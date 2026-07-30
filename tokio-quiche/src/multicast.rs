// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Multicast client/server integration for tokio-quiche.
//!
//! This module keeps multicast socket ownership outside core [`quiche`] while
//! still integrating with the multicast draft's unicast control plane. It is
//! currently IPv4-only on the multicast data path and emits explicit
//! placeholders for IPv6-specific behavior.

mod bounded_queue;
mod event_stream;
mod server_stream;

pub use bounded_queue::RetainedQueueConfigError;
pub use bounded_queue::RetainedQueueLimits;
pub use bounded_queue::RetainedQueueStats;
pub use event_stream::ClientEventStream;
pub use event_stream::EventQueueConfigError;
pub use event_stream::EventQueueLimits;
pub use event_stream::EventQueueStats;
pub use event_stream::EventStreamTerminal;
pub use event_stream::EventStreamTerminalReason;
pub use event_stream::ServerEventStream;
pub use server_stream::ServerStreamAttachment;
pub use server_stream::ServerStreamFrame;
pub use server_stream::ServerStreamPublication;
pub use server_stream::ServerStreamPublisher;
pub use server_stream::ServerStreamPublisherError;
pub use server_stream::ServerStreamPublisherLimits;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::fmt;
use std::future::pending;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::ops::Bound;
use std::sync::Arc;
use std::time::Duration;

use mcrx_core::Context as MulticastContext;
use mcrx_core::PacketWithMetadata;
use mcrx_core::SubscriptionConfig;
use mcrx_core::SubscriptionMetricsSnapshot;
use mcrx_core::TokioReceiveError;
use mcrx_core::TokioSubscription;
use mctx_core::MctxError;
use mctx_core::Publication;
use mctx_core::PublicationConfig;
use mctx_core::SendReport;
use tokio::select;
use tokio::time::sleep_until;
use tokio::time::Instant;
use tokio_util::task::AbortOnDropHandle;

use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

use self::bounded_queue::bounded_channel;
use self::bounded_queue::retained_queue_budget;
use self::bounded_queue::BoundedReceiver;
use self::bounded_queue::BoundedSender;
use self::bounded_queue::QueueSendError;
use self::bounded_queue::Queued;
use self::bounded_queue::RetainedDeque;
use self::bounded_queue::RetainedQueueBudget;
use self::bounded_queue::RetainedQueueObserver;
use self::bounded_queue::RetainedSize;
use self::event_stream::client_event_channel;
use self::event_stream::server_event_channel;
use self::event_stream::EventQueueObserver;
use self::event_stream::EventSendError;
use self::event_stream::ManagedEventSender;

pub use crate::settings::MulticastClientSettings as ClientSettings;

const STATE_REASON_UNSPECIFIED_OTHER: u64 = 0x0;
const STATE_REASON_PROTOCOL_ERROR: u64 = 0x3;
const STATE_REASON_UNSYNCHRONIZED_PROPERTIES: u64 = 0x5;
const STATE_REASON_LIMIT_VIOLATED: u64 = 0x16;
const SERVER_ACK_FRESHNESS_TIMEOUT_MULTIPLIER: u64 = 4;
const PUBLISH_RETRY_DELAY: Duration = Duration::from_millis(10);
const MIN_INGRESS_NOTIFICATION_RETAINED_BYTES: usize = 64;

fn fair_ready_channel_ids<T>(
    channels: &BTreeMap<Vec<u8>, T>, cursor: Option<&[u8]>, limit: usize,
    mut ready: impl FnMut(&T) -> bool,
) -> Vec<Vec<u8>> {
    if limit == 0 {
        return Vec::new();
    }

    let mut selected = Vec::with_capacity(limit.min(channels.len()));

    if let Some(cursor) = cursor {
        for (channel_id, channel) in
            channels.range((Bound::Excluded(cursor.to_vec()), Bound::Unbounded))
        {
            if ready(channel) {
                selected.push(channel_id.clone());
            }
            if selected.len() == limit {
                return selected;
            }
        }
        for (channel_id, channel) in channels.range(..=cursor.to_vec()) {
            if ready(channel) {
                selected.push(channel_id.clone());
            }
            if selected.len() == limit {
                break;
            }
        }
    } else {
        for (channel_id, channel) in channels {
            if ready(channel) {
                selected.push(channel_id.clone());
            }
            if selected.len() == limit {
                break;
            }
        }
    }

    selected
}

fn run_callback_work<E>(
    max_work: usize, cursor: &mut usize, class_count: usize,
    mut process_one: impl FnMut(usize) -> Result<bool, E>,
) -> Result<usize, E> {
    debug_assert!(class_count > 0);
    let mut work = 0;

    while work < max_work {
        let mut progressed = false;

        for _ in 0..class_count {
            let class = *cursor % class_count;
            *cursor = (class + 1) % class_count;

            if process_one(class)? {
                work += 1;
                progressed = true;
                break;
            }
        }

        if !progressed {
            break;
        }
    }

    Ok(work)
}

fn validate_client_settings(settings: &ClientSettings) -> quiche::Result<()> {
    settings.transport_params.encoded_len()?;
    quiche::multicast::Frame::Limits(quiche::multicast::Limits {
        sequence: 0,
        limits: settings.transport_params.limits.clone(),
        max_joined_count: settings.max_joined_channels,
    })
    .encoded_len()
    .map(|_| ())
}

fn validate_server_announce(
    announce: &quiche::multicast::Announce,
) -> quiche::Result<()> {
    announce.validate()?;
    std::time::Instant::now()
        .checked_add(server_ack_freshness_timeout(announce.max_ack_delay_ms))
        .ok_or(quiche::Error::InvalidState)?;

    Ok(())
}

/// Owned controller-command admission failure.
///
/// The rejected input is retained so callers can retry transient saturation
/// without cloning a secret-bearing or potentially large value.
#[derive(Debug)]
pub struct ControllerSendError<T> {
    kind: ControllerSendErrorKind,
    value: Box<T>,
}

impl<T> ControllerSendError<T> {
    fn invalid(value: T) -> Self {
        Self {
            kind: ControllerSendErrorKind::InvalidValue,
            value: Box::new(value),
        }
    }

    fn from_queue(error: QueueSendError<T>) -> Self {
        match error {
            QueueSendError::Full(value) => Self {
                kind: ControllerSendErrorKind::Full,
                value: Box::new(value),
            },

            QueueSendError::Oversized(value) => Self {
                kind: ControllerSendErrorKind::Oversized,
                value: Box::new(value),
            },

            QueueSendError::Closed(value) => Self {
                kind: ControllerSendErrorKind::Closed,
                value: Box::new(value),
            },
        }
    }

    /// Returns the failure category.
    pub fn kind(&self) -> ControllerSendErrorKind {
        self.kind
    }

    /// Returns the value that was not admitted.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Recovers ownership of the value that was not admitted.
    pub fn into_inner(self) -> T {
        *self.value
    }
}

impl<T> fmt::Display for ControllerSendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "multicast controller send failed: {}", self.kind)
    }
}

impl<T: fmt::Debug> std::error::Error for ControllerSendError<T> {}

/// Category reported by [`ControllerSendError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerSendErrorKind {
    /// The bounded command queue is temporarily full.
    Full,

    /// The command can never fit the configured retained-byte limit.
    Oversized,

    /// The connection runtime no longer accepts commands.
    Closed,

    /// One or more command fields cannot be represented on the wire.
    InvalidValue,
}

impl fmt::Display for ControllerSendErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::Full => "queue full",
            Self::Oversized => "command oversized",
            Self::Closed => "runtime closed",
            Self::InvalidValue => "invalid command value",
        };
        f.write_str(description)
    }
}

/// Channel ID and channel frames recovered from a rejected server send.
pub type ServerChannelPacket = (Vec<u8>, Vec<quiche::multicast::ChannelFrame>);

/// Owned admission error returned by [`ServerController::send_on_channel`].
pub type ServerChannelSendError = ControllerSendError<ServerChannelPacket>;

/// Local resource and work limits for one Tokio multicast connection wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeLimits {
    /// Required event and coalesced metric retention limits.
    pub events: EventQueueLimits,

    /// Controller command limits, including commands staged by the runtime.
    pub commands: RetainedQueueLimits,

    /// Client multicast socket ingress limits.
    pub ingress: RetainedQueueLimits,

    /// Encoded or shared publications awaiting connection-local processing.
    pub pending_publications: RetainedQueueLimits,

    /// Integrity frames awaiting unicast control delivery.
    pub pending_integrity: RetainedQueueLimits,

    /// Aggregate multicast work units processed by one driver callback.
    ///
    /// One unit is one successful scheduled work-class operation: one control
    /// frame handled; one ingress, controller, publisher, publication,
    /// integrity, or pending-control item transferred or handled; one
    /// standalone indexed receive-maintenance operation; or one coalesced ACK,
    /// delivery-metric update, or probe event forwarded. Processing one ingress
    /// packet or receive-side control includes its single core receive
    /// admission and never opens a nested work budget. Queue readiness scans
    /// and class attempts that perform no mutation are not charged. All ready
    /// work classes are selected round-robin under this one budget.
    pub max_work_per_call: usize,

    /// Delay before retrying a control frame rejected by the core send queue.
    pub control_retry_delay: Duration,

    /// Maximum continuous control-queue saturation before failing explicitly.
    pub control_backpressure_timeout: Duration,

    /// Maximum connection-lifetime multicast Channel IDs retained by a
    /// runtime, including retired-ID tombstones.
    pub max_tracked_channel_ids: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            events: EventQueueLimits::default(),
            commands: RetainedQueueLimits {
                max_items: 4096,
                max_retained_bytes: 64 * 1024 * 1024,
            },
            ingress: RetainedQueueLimits {
                max_items: 4096,
                max_retained_bytes: 64 * 1024 * 1024,
            },
            pending_publications: RetainedQueueLimits {
                max_items: 4096,
                max_retained_bytes: 64 * 1024 * 1024,
            },
            pending_integrity: RetainedQueueLimits {
                max_items: 8192,
                max_retained_bytes: 8 * 1024 * 1024,
            },
            max_work_per_call: 256,
            control_retry_delay: Duration::from_millis(1),
            control_backpressure_timeout: Duration::from_secs(30),
            max_tracked_channel_ids: 1024,
        }
    }
}

impl RuntimeLimits {
    fn validate(self) -> Result<Self, RuntimeLimitsError> {
        self.events.validate()?;
        self.commands.validate("multicast command")?;
        self.ingress.validate("multicast ingress")?;
        if self.ingress.max_retained_bytes <
            MIN_INGRESS_NOTIFICATION_RETAINED_BYTES
        {
            return Err(RuntimeLimitsError::IngressNotificationByteCapacity {
                minimum: MIN_INGRESS_NOTIFICATION_RETAINED_BYTES,
            });
        }
        self.pending_publications
            .validate("multicast pending publication")?;
        self.pending_integrity
            .validate("multicast pending integrity")?;
        if self.max_work_per_call == 0 {
            return Err(RuntimeLimitsError::ZeroWorkBudget);
        }
        if self.control_retry_delay.is_zero() {
            return Err(RuntimeLimitsError::ZeroControlRetryDelay);
        }
        if Instant::now()
            .checked_add(self.control_retry_delay)
            .is_none()
        {
            return Err(RuntimeLimitsError::UnrepresentableControlRetryDelay);
        }
        if self.control_backpressure_timeout.is_zero() {
            return Err(RuntimeLimitsError::ZeroControlBackpressureTimeout);
        }
        if Instant::now()
            .checked_add(self.control_backpressure_timeout)
            .is_none()
        {
            return Err(
                RuntimeLimitsError::UnrepresentableControlBackpressureTimeout,
            );
        }
        if self.max_tracked_channel_ids == 0 {
            return Err(RuntimeLimitsError::ZeroTrackedChannelIds);
        }

        Ok(self)
    }
}

/// Invalid Tokio multicast runtime limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeLimitsError {
    /// Event queue limits are invalid.
    #[error(transparent)]
    EventQueue(#[from] EventQueueConfigError),

    /// Another retained runtime queue has invalid limits.
    #[error(transparent)]
    RetainedQueue(#[from] RetainedQueueConfigError),

    /// Driver callbacks could never make queue progress.
    #[error("multicast runtime work budget must be greater than zero")]
    ZeroWorkBudget,

    /// Control queue retries could spin without yielding.
    #[error("multicast control retry delay must be greater than zero")]
    ZeroControlRetryDelay,

    /// The control retry deadline cannot be represented by Tokio's clock.
    #[error("multicast control retry delay cannot be represented")]
    UnrepresentableControlRetryDelay,

    /// Control queue saturation could never reach a terminal outcome.
    #[error("multicast control backpressure timeout must be greater than zero")]
    ZeroControlBackpressureTimeout,

    /// The control saturation deadline cannot be represented by Tokio's clock.
    #[error("multicast control backpressure timeout cannot be represented")]
    UnrepresentableControlBackpressureTimeout,

    /// No multicast Channel ID could ever be retained.
    #[error("multicast tracked Channel ID capacity must be greater than zero")]
    ZeroTrackedChannelIds,

    /// The ingress byte limit cannot retain a terminal overload notification.
    #[error("multicast ingress byte capacity must be at least {minimum} bytes")]
    IngressNotificationByteCapacity {
        /// Smallest safe retained-byte capacity.
        minimum: usize,
    },

    /// Multicast settings contain a value that cannot be encoded.
    #[error("invalid multicast settings: {0}")]
    InvalidMulticastSettings(quiche::Error),
}

/// Point-in-time retained queue counters for a multicast client runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientRuntimeQueueStats {
    /// Multicast socket ingress retained by tasks or runtime staging.
    pub ingress: RetainedQueueStats,

    /// Client control frames awaiting core QUIC queue admission.
    pub control: RetainedQueueStats,
}

/// Point-in-time retained queue counters for a multicast server runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerRuntimeQueueStats {
    /// Controller commands retained by the channel or runtime staging.
    pub commands: RetainedQueueStats,

    /// Connection-local publications awaiting recovery registration or send.
    pub pending_publications: RetainedQueueStats,

    /// Delayed and ready-to-send integrity frames.
    pub pending_integrity: RetainedQueueStats,
}

/// A point-in-time multicast receive metrics snapshot for one joined channel.
#[derive(Clone, Debug)]
pub struct ClientChannelMetricsSnapshot {
    /// Socket-level receive metrics from `mcrx-core`.
    pub socket: SubscriptionMetricsSnapshot,

    /// Decode and buffering metrics from `quiche`'s channel receiver.
    pub receive: quiche::multicast::ChannelReceiveMetricsSnapshot,
}

/// Events emitted by [`ClientDriver`].
#[derive(Debug)]
pub enum ClientEvent {
    /// A usable IPv4 multicast channel was announced by the server.
    Announce(quiche::multicast::Announce),

    /// The server announced an IPv6 multicast channel.
    ///
    /// The current integration keeps IPv6-specific multicast handling as a
    /// placeholder so it can be implemented later without reshaping the API.
    UnsupportedIpv6Announce(quiche::multicast::Announce),

    /// A local multicast state transition was reported back to the server.
    LocalState(quiche::multicast::State),

    /// Updated multicast receive metrics for a joined channel.
    MetricsUpdated {
        /// The QUIC multicast channel ID associated with the metrics.
        channel_id: Vec<u8>,

        /// The latest paired socket and decode metrics snapshot.
        metrics: ClientChannelMetricsSnapshot,
    },

    /// A multicast UDP packet was validated and decoded for a joined channel.
    Packet {
        /// The QUIC multicast channel ID associated with the packet.
        channel_id: Vec<u8>,

        /// The decoded QUIC multicast packet.
        packet: quiche::multicast::ChannelPacket,

        /// The original multicast datagram and its receive metadata.
        received: PacketWithMetadata,
    },

    /// A received multicast UDP packet could not be validated or decoded.
    DecodeError {
        /// The QUIC multicast channel ID associated with the packet.
        channel_id: Vec<u8>,

        /// The decode or validation failure reported by `quiche`.
        error: quiche::Error,

        /// The original multicast datagram and its receive metadata.
        packet: PacketWithMetadata,
    },

    /// A background multicast receive task failed.
    ReceiveError {
        /// The QUIC multicast channel ID whose receive path failed.
        channel_id: Vec<u8>,

        /// The underlying async receive error from `mcrx-core`.
        error: TokioReceiveError,
    },

    /// One multicast UDP packet exceeded the configured ingress item bound.
    IngressOverload {
        /// The QUIC multicast channel ID whose receive path was stopped.
        channel_id: Vec<u8>,

        /// Logical bytes the rejected ingress item would have retained.
        retained_bytes: usize,

        /// Configured retained-byte bound for multicast ingress.
        max_retained_bytes: usize,
    },
}

/// Handle for consuming multicast events produced by [`ClientDriver`].
pub struct ClientController {
    event_receiver: Option<ClientEventStream>,
    event_observer: EventQueueObserver<ClientEvent>,
    ingress_observer: RetainedQueueObserver,
    control_observer: RetainedQueueObserver,
}

impl ClientController {
    /// Returns the multicast event receiver if it has not been taken.
    pub fn event_receiver_mut(&mut self) -> Option<&mut ClientEventStream> {
        self.event_receiver.as_mut()
    }

    /// Takes ownership of the event receiver.
    ///
    /// A receiver can be taken only once. Later calls return `None` and do not
    /// create a replacement queue.
    pub fn take_event_receiver(&mut self) -> Option<ClientEventStream> {
        self.event_receiver.take()
    }

    /// Returns event queue counters without consuming the receiver.
    pub fn event_queue_stats(&self) -> EventQueueStats {
        self.event_observer.stats()
    }

    /// Returns retained runtime queue counters without consuming ingress.
    pub fn runtime_queue_stats(&self) -> ClientRuntimeQueueStats {
        ClientRuntimeQueueStats {
            ingress: self.ingress_observer.stats(),
            control: self.control_observer.stats(),
        }
    }
}

/// Wraps another [`ApplicationOverQuic`] with multicast client receive logic.
///
/// The wrapped application continues to own the regular QUIC and HTTP/3
/// behavior while this wrapper handles multicast control frames, joins IPv4
/// channels with `mcrx-core`, and forwards validated multicast packets via
/// [`ClientController`].
pub struct ClientDriver<A> {
    inner: A,
    runtime: ClientRuntime<McrxJoinBackend>,
}

impl<A> ClientDriver<A> {
    /// Creates a new multicast client wrapper and its controller.
    pub fn new(
        inner: A, settings: ClientSettings,
    ) -> Result<(Self, ClientController), RuntimeLimitsError> {
        Self::new_with_runtime_limits(inner, settings, RuntimeLimits::default())
    }

    /// Creates a multicast client wrapper with explicit event queue limits.
    pub fn new_with_event_queue_limits(
        inner: A, settings: ClientSettings, event_limits: EventQueueLimits,
    ) -> Result<(Self, ClientController), RuntimeLimitsError> {
        let limits = RuntimeLimits {
            events: event_limits,
            ..RuntimeLimits::default()
        };
        Self::new_with_runtime_limits(inner, settings, limits)
    }

    /// Creates a multicast client wrapper with explicit runtime limits.
    pub fn new_with_runtime_limits(
        inner: A, settings: ClientSettings, limits: RuntimeLimits,
    ) -> Result<(Self, ClientController), RuntimeLimitsError> {
        validate_client_settings(&settings)
            .map_err(RuntimeLimitsError::InvalidMulticastSettings)?;
        let limits = limits.validate()?;
        let (event_sender, event_receiver, event_observer) =
            client_event_channel(limits.events);

        let runtime = ClientRuntime::new(settings, event_sender, limits);
        let ingress_observer = runtime.ingress_observer.clone();
        let control_observer = runtime.pending_control.observer();
        Ok((Self { inner, runtime }, ClientController {
            event_receiver: Some(event_receiver),
            event_observer,
            ingress_observer,
            control_observer,
        }))
    }

    /// Returns a shared reference to the wrapped application.
    pub fn inner(&self) -> &A {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped application.
    pub fn inner_mut(&mut self) -> &mut A {
        &mut self.inner
    }

    /// Consumes the wrapper and returns the wrapped application.
    pub fn into_inner(self) -> A {
        self.inner
    }
}

impl<A: ApplicationOverQuic> ApplicationOverQuic for ClientDriver<A> {
    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection,
        handshake_info: &crate::quic::HandshakeInfo,
    ) -> QuicResult<()> {
        self.runtime.on_conn_established(qconn)?;
        self.inner.on_conn_established(qconn, handshake_info)
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        self.inner.buffer()
    }

    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if self.runtime.has_pending_work() {
            return Ok(());
        }

        if self.inner.should_act() {
            select! {
                res = self.inner.wait_for_data(qconn) => res,
                res = self.runtime.wait_for_ingress_or_key_expiry() => res,
            }
        } else {
            self.runtime.wait_for_ingress_or_key_expiry().await
        }
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.runtime.process_reads(qconn)?;

        if self.inner.should_act() {
            self.inner.process_reads(qconn)?;
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.runtime.process_writes(qconn)?;

        if self.inner.should_act() {
            self.inner.process_writes(qconn)?;
        }

        Ok(())
    }

    fn on_conn_close<M: crate::metrics::Metrics>(
        &mut self, qconn: &mut QuicheConnection, metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        self.runtime.clear();
        self.runtime.event_sender.finish();
        self.inner.on_conn_close(qconn, metrics, connection_result);
    }
}

#[derive(Debug, thiserror::Error)]
enum ClientError {
    #[error("multicast client wrapper only supports client connections")]
    ServerConnectionUnsupported,

    #[error("peer exceeded the advertised multicast Channel ID limit of {0}")]
    ChannelIdLimit(u64),

    #[error(
        "multicast runtime exhausted its connection-lifetime Channel ID limit of {0}"
    )]
    TrackedChannelIdLimit(usize),

    #[error("{0} multicast client control queue exhausted")]
    ControlQueueExhausted(&'static str),

    #[error("multicast client control queue made no progress for {0:?}")]
    ControlBackpressureTimeout(Duration),
}

enum ClientControlFrame {
    Limits {
        frame: quiche::multicast::Limits,
        commit: Option<quiche::multicast::Limits>,
    },
    State {
        frame: quiche::multicast::State,
        commit: Option<quiche::multicast::State>,
    },
}

struct PendingClientControl {
    frame: ClientControlFrame,
    blocked_since: Option<Instant>,
}

impl RetainedSize for PendingClientControl {
    fn retained_size(&self) -> usize {
        match &self.frame {
            ClientControlFrame::Limits { commit, .. } =>
                128_usize.saturating_add(commit.as_ref().map_or(0, |_| 128)),

            ClientControlFrame::State { frame, commit } => {
                let frame_size = frame
                    .channel_id
                    .len()
                    .saturating_add(frame.reason_phrase.len())
                    .saturating_add(128);
                frame_size.saturating_add(commit.as_ref().map_or(0, |frame| {
                    frame
                        .channel_id
                        .len()
                        .saturating_add(frame.reason_phrase.len())
                        .saturating_add(128)
                }))
            },
        }
    }
}

struct ClientRuntime<B: JoinBackend> {
    settings: ClientSettings,
    limits: RuntimeLimits,
    event_sender: ManagedEventSender<ClientEvent>,
    // Subscription tasks run outside the QUIC driver's immediate poll point,
    // so they hand off validated socket ingress through this channel. The
    // queue is drained on each driver tick and bounded in practice by the
    // number and lifetime of joined channels.
    ingress_sender: BoundedSender<IngressEvent>,
    ingress_receiver: BoundedReceiver<IngressEvent>,
    ingress_observer: RetainedQueueObserver,
    pending_ingress: VecDeque<Queued<IngressEvent>>,
    pending_control: RetainedDeque<PendingClientControl>,
    control_retry_deadline: Option<Instant>,
    control_read_pending: bool,
    channels: BTreeMap<Vec<u8>, Channel<B::Handle>>,
    receiver_maintenance_cursor: Option<Vec<u8>>,
    ack_flush_cursor: Option<Vec<u8>>,
    read_work_cursor: usize,
    write_work_cursor: usize,
    next_limits_sequence: u64,
    reserved_limits_sequence: u64,
    reserved_state_sequences: BTreeMap<Vec<u8>, u64>,
    backend: B,
    #[cfg(test)]
    callback_read_work_last_call: usize,
    #[cfg(test)]
    callback_write_work_last_call: usize,
}

impl ClientRuntime<McrxJoinBackend> {
    fn new(
        settings: ClientSettings, event_sender: ManagedEventSender<ClientEvent>,
        limits: RuntimeLimits,
    ) -> Self {
        Self::with_backend_and_limits(
            settings,
            event_sender,
            McrxJoinBackend,
            limits,
        )
    }
}

impl<B: JoinBackend> ClientRuntime<B> {
    #[cfg(test)]
    fn with_backend(
        settings: ClientSettings, event_sender: ManagedEventSender<ClientEvent>,
        backend: B,
    ) -> Self {
        Self::with_backend_and_limits(
            settings,
            event_sender,
            backend,
            RuntimeLimits::default(),
        )
    }

    fn with_backend_and_limits(
        settings: ClientSettings, event_sender: ManagedEventSender<ClientEvent>,
        backend: B, limits: RuntimeLimits,
    ) -> Self {
        let (ingress_sender, ingress_receiver, ingress_observer) =
            bounded_channel(limits.ingress);

        Self {
            settings,
            limits,
            event_sender,
            ingress_sender,
            ingress_receiver,
            ingress_observer,
            pending_ingress: VecDeque::new(),
            pending_control: RetainedDeque::new(limits.commands),
            control_retry_deadline: None,
            control_read_pending: false,
            channels: BTreeMap::new(),
            receiver_maintenance_cursor: None,
            ack_flush_cursor: None,
            read_work_cursor: 0,
            write_work_cursor: 0,
            next_limits_sequence: 0,
            reserved_limits_sequence: 0,
            reserved_state_sequences: BTreeMap::new(),
            backend,
            #[cfg(test)]
            callback_read_work_last_call: 0,
            #[cfg(test)]
            callback_write_work_last_call: 0,
        }
    }

    fn emit_event(&self, event: ClientEvent) -> QuicResult<()> {
        self.event_sender.try_send(event)?;
        Ok(())
    }

    fn clear(&mut self) {
        self.ingress_receiver.close();
        self.channels.clear();
        self.receiver_maintenance_cursor = None;
        self.ack_flush_cursor = None;
        self.read_work_cursor = 0;
        self.write_work_cursor = 0;
        self.pending_ingress.clear();
        self.pending_control.clear();
        self.control_retry_deadline = None;
        self.control_read_pending = false;
        self.reserved_state_sequences.clear();

        while self.ingress_receiver.try_recv().is_ok() {}
    }

    fn has_pending_work(&self) -> bool {
        self.control_read_pending ||
            self.ingress_observer.stats().retained_items > 0 ||
            !self.pending_ingress.is_empty() ||
            (!self.pending_control.is_empty() &&
                self.control_retry_deadline
                    .is_none_or(|deadline| deadline <= Instant::now())) ||
            self.channels.values().any(|channel| {
                channel.ack_state.has_pending_ack() ||
                    channel
                        .receive_state
                        .as_ref()
                        .is_some_and(|receiver| receiver.has_pending_work())
            })
    }

    async fn wait_for_ingress_or_key_expiry(&mut self) -> QuicResult<()> {
        let key_expiry = self
            .channels
            .values()
            .filter_map(|channel| {
                channel
                    .receive_state
                    .as_ref()
                    .and_then(|receiver| receiver.next_key_expiry())
            })
            .min()
            .map(Instant::from_std);
        let deadline = match (key_expiry, self.control_retry_deadline) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        };

        if let Some(deadline) = deadline {
            select! {
                event = self.ingress_receiver.recv() => {
                    self.queue_ingress_event(event).await
                },
                () = sleep_until(deadline) => Ok(()),
            }
        } else {
            let event = self.ingress_receiver.recv().await;
            self.queue_ingress_event(event).await
        }
    }

    async fn queue_ingress_event(
        &mut self, event: Option<Queued<IngressEvent>>,
    ) -> QuicResult<()> {
        match event {
            Some(event) => {
                self.pending_ingress.push_back(event);
                Ok(())
            },

            None => {
                #[allow(unreachable_code)]
                {
                    pending::<()>().await;
                    Ok(())
                }
            },
        }
    }

    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if qconn.is_server() {
            return Err(Box::new(ClientError::ServerConnectionUnsupported));
        }

        if self.peer_supports_multicast(qconn) {
            self.send_limits(qconn)?;
        }

        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.control_retry_deadline = None;
        let mut cursor = self.read_work_cursor;
        let work = run_callback_work(
            self.limits.max_work_per_call,
            &mut cursor,
            4,
            |class| match class {
                0 => self.process_one_receiver_maintenance(qconn),
                1 => Ok(self.transfer_one_ingress()),
                2 => self.process_one_ingress(qconn),
                3 => self.process_one_control_frame(qconn),
                _ => unreachable!("client read work class is in range"),
            },
        )?;
        self.read_work_cursor = cursor;
        self.control_read_pending = qconn.is_multicast_readable();

        #[cfg(test)]
        {
            self.callback_read_work_last_call = work;
        }

        debug_assert!(work <= self.limits.max_work_per_call);
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let mut cursor = self.write_work_cursor;
        let work = run_callback_work(
            self.limits.max_work_per_call,
            &mut cursor,
            5,
            |class| match class {
                0 => self.process_one_receiver_maintenance(qconn),
                1 => Ok(self.transfer_one_ingress()),
                2 => self.process_one_ingress(qconn),
                3 => self.flush_one_pending_control(qconn),
                4 => self.flush_one_pending_ack(qconn),
                _ => unreachable!("client write work class is in range"),
            },
        )?;
        self.write_work_cursor = cursor;

        #[cfg(test)]
        {
            self.callback_write_work_last_call = work;
        }

        debug_assert!(work <= self.limits.max_work_per_call);
        Ok(())
    }

    fn process_one_control_frame(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        match qconn.multicast_recv() {
            Ok(frame) => {
                self.handle_frame(qconn, frame)?;
                Ok(true)
            },

            Err(quiche::Error::Done) => {
                self.control_read_pending = false;
                Ok(false)
            },

            Err(err) => Err(err.into()),
        }
    }

    fn process_one_receiver_maintenance(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        let now = std::time::Instant::now();
        let Some(channel_id) = fair_ready_channel_ids(
            &self.channels,
            self.receiver_maintenance_cursor.as_deref(),
            1,
            |channel| {
                channel.receive_state.as_ref().is_some_and(|receiver| {
                    receiver.has_pending_work() ||
                        receiver
                            .next_key_expiry()
                            .is_some_and(|deadline| deadline <= now)
                })
            },
        )
        .pop() else {
            return Ok(false);
        };

        self.receiver_maintenance_cursor = Some(channel_id.clone());
        let result = self
            .channels
            .get_mut(&channel_id)
            .and_then(|channel| channel.receive_state.as_mut())
            .map(|receiver| receiver.maintain_with_budget(1, 1))
            .unwrap_or_else(|| {
                Ok(quiche::multicast::ChannelReceiveWorkBatch {
                    events: Vec::new(),
                    work_performed: 0,
                })
            });
        let result = result.map(|batch| batch.events);
        let Some(events) =
            self.resolve_receive_result(qconn, &channel_id, result)?
        else {
            self.emit_channel_metrics(&channel_id)?;
            return Ok(true);
        };

        for event in events {
            self.handle_channel_receive_event(qconn, channel_id.clone(), event)?;
        }

        self.emit_channel_metrics(&channel_id)?;
        Ok(true)
    }

    fn transfer_one_ingress(&mut self) -> bool {
        let Ok(event) = self.ingress_receiver.try_recv() else {
            return false;
        };
        self.pending_ingress.push_back(event);
        true
    }

    fn process_one_ingress(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        let Some(event) = self.pending_ingress.pop_front() else {
            return Ok(false);
        };

        match event.into_inner() {
            IngressEvent::Packet {
                channel_id,
                packet,
                socket_metrics,
            } => {
                self.handle_ingress_packet(
                    qconn,
                    channel_id,
                    socket_metrics,
                    packet,
                )?;
            },

            IngressEvent::ReceiveError {
                channel_id,
                error,
                socket_metrics,
            } =>
                if let Some(channel) = self.channels.get_mut(&channel_id) {
                    channel.last_subscription_metrics = Some(socket_metrics);
                    self.emit_channel_metrics(&channel_id)?;
                    self.emit_event(ClientEvent::ReceiveError {
                        channel_id,
                        error,
                    })?;
                },

            IngressEvent::Overload {
                channel_id,
                retained_bytes,
                max_retained_bytes,
            } => {
                let joined = if let Some(channel) =
                    self.channels.get_mut(&channel_id)
                {
                    let joined = channel.receive_handle.take().is_some();
                    channel.receive_state.take();
                    channel.ack_state = quiche::multicast::AckTracker::default();
                    channel.pending_leave = None;
                    channel.pending_retire_after = None;
                    channel.largest_authenticated_packet_number = None;
                    joined
                } else {
                    return Ok(true);
                };

                self.emit_event(ClientEvent::IngressOverload {
                    channel_id: channel_id.clone(),
                    retained_bytes,
                    max_retained_bytes,
                })?;
                if joined {
                    self.send_state(
                        qconn,
                        channel_id,
                        quiche::multicast::ChannelState::Left,
                        STATE_REASON_LIMIT_VIOLATED,
                        b"multicast ingress item exceeds local byte limit"
                            .to_vec(),
                    )?;
                }
            },
        }

        Ok(true)
    }

    fn handle_ingress_packet(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
        socket_metrics: SubscriptionMetricsSnapshot, packet: PacketWithMetadata,
    ) -> QuicResult<()> {
        {
            let Some(channel) = self.channels.get_mut(&channel_id) else {
                self.emit_event(ClientEvent::DecodeError {
                    channel_id,
                    error: quiche::Error::InvalidState,
                    packet,
                })?;
                return Ok(());
            };
            channel.last_subscription_metrics = Some(socket_metrics);

            Self::ensure_channel_decoder(channel);
        }

        let Some(receiver) = self
            .channels
            .get_mut(&channel_id)
            .and_then(|channel| channel.receive_state.as_mut())
        else {
            self.emit_event(ClientEvent::DecodeError {
                channel_id: channel_id.clone(),
                error: quiche::Error::InvalidState,
                packet,
            })?;
            self.emit_channel_metrics(&channel_id)?;
            return Ok(());
        };

        let payload = packet.packet.payload.clone();
        let result = receiver
            .recv_buf_with_budget(payload, packet, 1, 1)
            .map(|batch| batch.events);
        let Some(events) =
            self.resolve_receive_result(qconn, &channel_id, result)?
        else {
            self.emit_channel_metrics(&channel_id)?;
            return Ok(());
        };

        for event in events {
            self.handle_channel_receive_event(qconn, channel_id.clone(), event)?;
        }

        self.emit_channel_metrics(&channel_id)?;

        Ok(())
    }

    fn handle_channel_receive_event(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
        event: quiche::multicast::ChannelReceiveEvent<PacketWithMetadata>,
    ) -> QuicResult<()> {
        match event {
            quiche::multicast::ChannelReceiveEvent::Packet {
                packet,
                metadata,
            } => self.handle_channel_packet(qconn, channel_id, packet, metadata),

            quiche::multicast::ChannelReceiveEvent::Error { error, metadata } => {
                self.emit_event(ClientEvent::DecodeError {
                    channel_id,
                    error,
                    packet: metadata,
                })?;

                Ok(())
            },
        }
    }

    fn resolve_receive_result(
        &mut self, qconn: &mut QuicheConnection, channel_id: &[u8],
        result: quiche::Result<
            Vec<quiche::multicast::ChannelReceiveEvent<PacketWithMetadata>>,
        >,
    ) -> QuicResult<
        Option<Vec<quiche::multicast::ChannelReceiveEvent<PacketWithMetadata>>>,
    > {
        match result {
            Ok(events) => Ok(Some(events)),

            Err(error) => {
                let failure = self
                    .channels
                    .get(channel_id)
                    .and_then(|channel| channel.receive_state.as_ref())
                    .and_then(|receiver| receiver.terminal_failure());
                let Some(failure) = failure else {
                    return Err(error.into());
                };

                self.fail_receive_channel(qconn, channel_id, failure)?;
                Ok(None)
            },
        }
    }

    fn fail_receive_channel(
        &mut self, qconn: &mut QuicheConnection, channel_id: &[u8],
        failure: quiche::multicast::ChannelReceiveFailure,
    ) -> QuicResult<()> {
        let (reason_code, reason_phrase) = match failure {
            quiche::multicast::ChannelReceiveFailure::ConflictingIntegrity => (
                STATE_REASON_PROTOCOL_ERROR,
                b"conflicting multicast integrity".to_vec(),
            ),

            _ => (
                STATE_REASON_LIMIT_VIOLATED,
                b"multicast receive resource limit exceeded".to_vec(),
            ),
        };

        let joined = {
            let Some(channel) = self.channels.get_mut(channel_id) else {
                return Ok(());
            };
            channel.decoder_error = Some(reason_phrase.clone());
            channel.pending_leave = None;
            if let Some(mut key) = channel.key.take() {
                key.secret.fill(0);
            }
            channel.receive_handle.take().is_some()
        };

        if joined {
            self.send_state(
                qconn,
                channel_id.to_vec(),
                quiche::multicast::ChannelState::Left,
                reason_code,
                reason_phrase,
            )?;
        }

        Ok(())
    }

    fn handle_channel_packet(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
        packet: quiche::multicast::ChannelPacket, received: PacketWithMetadata,
    ) -> QuicResult<()> {
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return Ok(());
        };
        channel.ack_state.record_packet(packet.packet_number);
        {
            let channel = self
                .channels
                .get_mut(&channel_id)
                .expect("channel was checked above");
            channel.largest_authenticated_packet_number = Some(
                channel
                    .largest_authenticated_packet_number
                    .unwrap_or(packet.packet_number)
                    .max(packet.packet_number),
            );
        }

        for frame in &packet.frames {
            if let quiche::multicast::ChannelFrame::Multicast(frame) = frame {
                self.handle_frame(qconn, frame.clone())?;
            }
        }

        qconn.multicast_process_channel_packet_ref(&packet)?;

        self.emit_event(ClientEvent::Packet {
            channel_id: channel_id.clone(),
            packet,
            received,
        })?;

        self.settle_pending_transitions(qconn, &channel_id)
    }

    fn handle_frame(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Frame,
    ) -> QuicResult<()> {
        match &frame {
            quiche::multicast::Frame::Announce(frame) =>
                self.admit_peer_channel_id(&frame.channel_id, true)?,

            quiche::multicast::Frame::Key(frame) =>
                self.admit_peer_channel_id(&frame.channel_id, true)?,

            quiche::multicast::Frame::Integrity(frame) =>
                self.admit_peer_channel_id(&frame.channel_id, true)?,

            quiche::multicast::Frame::Retire(frame) =>
                self.admit_peer_channel_id(&frame.channel_id, false)?,

            _ => (),
        }

        match frame {
            quiche::multicast::Frame::Announce(frame) => {
                self.handle_announce(frame)?;
            },

            quiche::multicast::Frame::Key(frame) => {
                self.handle_key(qconn, frame)?;
            },

            quiche::multicast::Frame::Join(frame) => {
                self.handle_join(qconn, frame)?;
            },

            quiche::multicast::Frame::Leave(frame) => {
                self.handle_leave(qconn, frame)?;
            },

            quiche::multicast::Frame::Retire(frame) => {
                self.handle_retire(qconn, frame)?;
            },

            quiche::multicast::Frame::Integrity(frame) => {
                self.handle_integrity(qconn, frame)?;
            },

            quiche::multicast::Frame::Ack(..) |
            quiche::multicast::Frame::Limits(..) |
            quiche::multicast::Frame::State(..) => (),
        }

        Ok(())
    }

    fn admit_peer_channel_id(
        &mut self, channel_id: &[u8], counts_against_peer_limit: bool,
    ) -> QuicResult<()> {
        if self.channels.contains_key(channel_id) {
            return Ok(());
        }
        if self.channels.len() >= self.limits.max_tracked_channel_ids {
            return Err(Box::new(ClientError::TrackedChannelIdLimit(
                self.limits.max_tracked_channel_ids,
            )));
        }

        let peer_limit = self.settings.transport_params.limits.max_channel_ids;
        let active = self
            .channels
            .values()
            .filter(|channel| !channel.retired)
            .count() as u64;
        if counts_against_peer_limit && active >= peer_limit {
            return Err(Box::new(ClientError::ChannelIdLimit(peer_limit)));
        }

        self.channels
            .insert(channel_id.to_vec(), Channel::default());
        Ok(())
    }

    fn handle_announce(
        &mut self, frame: quiche::multicast::Announce,
    ) -> QuicResult<()> {
        let channel_id = frame.channel_id.clone();
        self.admit_peer_channel_id(&channel_id, true)?;
        let event = match (&frame.source, &frame.group) {
            (IpAddr::V4(..), IpAddr::V4(..)) =>
                ClientEvent::Announce(frame.clone()),

            (IpAddr::V6(..), IpAddr::V6(..)) =>
                ClientEvent::UnsupportedIpv6Announce(frame.clone()),

            _ => ClientEvent::UnsupportedIpv6Announce(frame.clone()),
        };

        let channel = self
            .channels
            .get_mut(&channel_id)
            .expect("announce admitted its Channel ID");
        if channel.retired {
            return Ok(());
        }
        channel.announce = Some(frame.clone());

        if let Some(receiver) = channel.receive_state.as_mut() {
            if receiver.update_announce(frame).is_err() {
                channel.decoder_error =
                    Some(b"unsupported multicast channel properties".to_vec());
                channel.receive_state = None;
            } else {
                channel.decoder_error = None;
            }
        } else {
            Self::ensure_channel_decoder(channel);
        }

        self.emit_event(event)
    }

    fn handle_key(
        &mut self, qconn: &mut QuicheConnection,
        mut frame: quiche::multicast::Key,
    ) -> QuicResult<()> {
        let channel_id = frame.channel_id.clone();
        self.admit_peer_channel_id(&channel_id, true)?;
        if self
            .channels
            .get(&channel_id)
            .is_some_and(|channel| channel.retired)
        {
            frame.secret.fill(0);
            return Ok(());
        }
        let result = {
            let channel = self
                .channels
                .get_mut(&channel_id)
                .expect("key admitted its Channel ID");

            Self::ensure_channel_decoder(channel);

            match channel.receive_state.as_mut() {
                Some(receiver) => receiver
                    .insert_key_with_budget(frame.clone(), 1, 1)
                    .map(|batch| batch.events),
                None => Ok(Vec::new()),
            }
        };
        let Some(events) =
            self.resolve_receive_result(qconn, &channel_id, result)?
        else {
            frame.secret.fill(0);
            self.emit_channel_metrics(&channel_id)?;
            return Ok(());
        };

        let channel = self
            .channels
            .get_mut(&channel_id)
            .expect("key admitted its Channel ID");
        let replace = channel
            .key
            .as_ref()
            .is_none_or(|current| frame.key_sequence > current.key_sequence);
        if replace {
            if let Some(mut old) = channel.key.replace(frame) {
                old.secret.fill(0);
            }
        } else {
            frame.secret.fill(0);
        }

        for event in events {
            self.handle_channel_receive_event(qconn, channel_id.clone(), event)?;
        }

        self.emit_channel_metrics(&channel_id)?;

        Ok(())
    }

    fn handle_integrity(
        &mut self, qconn: &mut QuicheConnection,
        frame: quiche::multicast::Integrity,
    ) -> QuicResult<()> {
        let channel_id = frame.channel_id.clone();
        self.admit_peer_channel_id(&channel_id, true)?;
        let result = {
            let channel = self
                .channels
                .get_mut(&channel_id)
                .expect("integrity admitted its Channel ID");

            Self::ensure_channel_decoder(channel);

            match channel.receive_state.as_mut() {
                Some(receiver) => receiver
                    .insert_integrity_with_budget(frame, 1, 1)
                    .map(|batch| batch.events),
                None => Ok(Vec::new()),
            }
        };
        let Some(events) =
            self.resolve_receive_result(qconn, &channel_id, result)?
        else {
            self.emit_channel_metrics(&channel_id)?;
            return Ok(());
        };

        for event in events {
            self.handle_channel_receive_event(qconn, channel_id.clone(), event)?;
        }

        self.emit_channel_metrics(&channel_id)?;

        Ok(())
    }

    fn handle_join(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Join,
    ) -> QuicResult<()> {
        let channel_id = frame.channel_id.clone();
        let is_new_channel = !self.channels.contains_key(&channel_id);

        if is_new_channel {
            if self.channels.len() >= self.limits.max_tracked_channel_ids {
                return Err(Box::new(ClientError::TrackedChannelIdLimit(
                    self.limits.max_tracked_channel_ids,
                )));
            }
            let active = self
                .channels
                .values()
                .filter(|channel| !channel.retired)
                .count() as u64;
            self.channels.insert(channel_id.clone(), Channel::default());
            if active >= self.settings.transport_params.limits.max_channel_ids {
                return self.decline_join(
                    qconn,
                    channel_id,
                    b"max channel ids exceeded".to_vec(),
                );
            }
        }

        {
            let channel = self.channels.entry(channel_id.clone()).or_default();
            if channel.retired ||
                channel
                    .highest_server_state_sequence
                    .is_some_and(|sequence| sequence > frame.mc_state_sequence)
            {
                return Ok(());
            }

            if channel
                .highest_server_state_sequence
                .is_none_or(|sequence| sequence < frame.mc_state_sequence)
            {
                channel.pending_leave = None;
            }
            channel.highest_server_state_sequence = Some(
                channel
                    .highest_server_state_sequence
                    .unwrap_or(frame.mc_state_sequence)
                    .max(frame.mc_state_sequence),
            );
        }

        let announce = self
            .channels
            .get(&channel_id)
            .and_then(|channel| channel.announce.clone());
        let decoder_error = self
            .channels
            .get(&channel_id)
            .and_then(|channel| channel.decoder_error.clone());
        let key_sequence = self
            .channels
            .get(&channel_id)
            .and_then(|channel| channel.key.as_ref())
            .map(|key| key.key_sequence);
        let state_sequence = self
            .channels
            .get(&channel_id)
            .map(|channel| channel.next_state_sequence)
            .unwrap_or_default();
        let already_joined = self
            .channels
            .get(&channel_id)
            .and_then(|channel| channel.receive_handle.as_ref())
            .is_some();

        if already_joined {
            return Ok(());
        }

        let Some(announce) = announce else {
            return self.decline_join(
                qconn,
                channel_id,
                b"missing multicast properties".to_vec(),
            );
        };

        let Some(key_sequence) = key_sequence else {
            return self.decline_join(
                qconn,
                channel_id,
                b"missing multicast properties".to_vec(),
            );
        };

        if frame.mc_limits_sequence > self.next_limits_sequence ||
            frame.mc_state_sequence > state_sequence ||
            frame.mc_key_sequence > key_sequence
        {
            return self.decline_join_with_reason(
                qconn,
                channel_id,
                STATE_REASON_UNSYNCHRONIZED_PROPERTIES,
                b"unsynchronized multicast properties".to_vec(),
            );
        }

        if let Some(reason_phrase) = decoder_error {
            return self.decline_join(qconn, channel_id, reason_phrase);
        }

        if self.joined_channel_count() >= self.settings.max_joined_channels {
            return self.decline_join(
                qconn,
                channel_id,
                b"max joined channels exceeded".to_vec(),
            );
        }

        if self
            .joined_rate_kibps()
            .saturating_add(announce.max_rate_kibps) >
            self.settings
                .transport_params
                .limits
                .max_aggregate_rate_kibps
        {
            return self.decline_join(
                qconn,
                channel_id,
                b"aggregate rate exceeded".to_vec(),
            );
        }

        let receive_handle = match self.join_channel(&channel_id, &announce) {
            Ok(handle) => handle,

            Err(err) => {
                return self.decline_join(qconn, channel_id, err.reason_phrase);
            },
        };

        {
            let channel = self.channels.entry(channel_id.clone()).or_default();
            channel.receive_handle = Some(receive_handle);
            channel.pending_leave = None;
        }

        self.send_state(
            qconn,
            channel_id,
            quiche::multicast::ChannelState::Joined,
            quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            Vec::new(),
        )
    }

    fn handle_leave(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Leave,
    ) -> QuicResult<()> {
        let channel_id = frame.channel_id;
        let should_leave = {
            let Some(channel) = self.channels.get_mut(&channel_id) else {
                return Ok(());
            };

            if channel.retired ||
                channel.receive_handle.is_none() ||
                channel
                    .highest_server_state_sequence
                    .is_some_and(|sequence| sequence > frame.mc_state_sequence)
            {
                return Ok(());
            }

            let newer_sequence = channel
                .highest_server_state_sequence
                .is_none_or(|sequence| sequence < frame.mc_state_sequence);
            channel.highest_server_state_sequence = Some(
                channel
                    .highest_server_state_sequence
                    .unwrap_or(frame.mc_state_sequence)
                    .max(frame.mc_state_sequence),
            );

            let pending = PendingLeave {
                state_sequence: frame.mc_state_sequence,
                after_packet_number: frame.after_packet_number,
            };
            channel.pending_leave = match channel.pending_leave {
                Some(existing) if !newer_sequence => Some(PendingLeave {
                    state_sequence: existing.state_sequence,
                    after_packet_number: existing
                        .after_packet_number
                        .max(pending.after_packet_number),
                }),

                _ => Some(pending),
            };

            let threshold = channel
                .pending_leave
                .expect("pending leave was set")
                .after_packet_number;
            threshold == 0 ||
                channel
                    .largest_authenticated_packet_number
                    .is_some_and(|packet_number| packet_number >= threshold)
        };

        if !should_leave {
            return Ok(());
        }

        self.execute_leave(qconn, channel_id)
    }

    fn handle_retire(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Retire,
    ) -> QuicResult<()> {
        let channel_id = frame.channel_id;
        self.admit_peer_channel_id(&channel_id, false)?;
        let should_retire = {
            let channel = self.channels.entry(channel_id.clone()).or_default();
            if channel.retired {
                return Ok(());
            }

            let effective_threshold = channel
                .pending_retire_after
                .unwrap_or(frame.after_packet_number)
                .max(frame.after_packet_number);
            let should_wait = frame.after_packet_number != 0 &&
                channel.receive_handle.is_some() &&
                channel.largest_authenticated_packet_number.is_some() &&
                channel.largest_authenticated_packet_number.is_none_or(
                    |packet_number| packet_number < effective_threshold,
                );

            if should_wait {
                channel.pending_retire_after = Some(effective_threshold);
                false
            } else {
                true
            }
        };

        if !should_retire {
            return Ok(());
        }

        self.execute_retire(qconn, channel_id)
    }

    fn execute_leave(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
    ) -> QuicResult<()> {
        let joined = {
            let Some(channel) = self.channels.get_mut(&channel_id) else {
                return Ok(());
            };
            channel.pending_leave = None;
            channel.receive_handle.take().is_some()
        };

        if !joined {
            return Ok(());
        }

        self.send_state(
            qconn,
            channel_id,
            quiche::multicast::ChannelState::Left,
            quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            Vec::new(),
        )
    }

    fn execute_retire(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
    ) -> QuicResult<()> {
        {
            let channel = self.channels.entry(channel_id.clone()).or_default();
            if channel.retired {
                return Ok(());
            }

            channel.receive_handle.take();
            channel.receive_state.take();
            channel.announce.take();
            channel.decoder_error = None;
            channel.pending_leave = None;
            channel.pending_retire_after = None;
            channel.highest_server_state_sequence = None;
            channel.largest_authenticated_packet_number = None;
            channel.ack_state = quiche::multicast::AckTracker::default();
            channel.retired = true;

            if let Some(mut key) = channel.key.take() {
                key.secret.fill(0);
            }
        }

        self.send_state(
            qconn,
            channel_id,
            quiche::multicast::ChannelState::Retired,
            quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            Vec::new(),
        )
    }

    fn settle_pending_transitions(
        &mut self, qconn: &mut QuicheConnection, channel_id: &[u8],
    ) -> QuicResult<()> {
        let Some(channel) = self.channels.get(channel_id) else {
            return Ok(());
        };
        let Some(packet_number) = channel.largest_authenticated_packet_number
        else {
            return Ok(());
        };
        let retire = channel
            .pending_retire_after
            .is_some_and(|threshold| packet_number >= threshold);
        let leave = channel
            .pending_leave
            .is_some_and(|pending| packet_number >= pending.after_packet_number);

        if retire {
            return self.execute_retire(qconn, channel_id.to_vec());
        }

        if leave {
            return self.execute_leave(qconn, channel_id.to_vec());
        }

        Ok(())
    }

    fn send_limits(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let sequence = self
            .reserved_limits_sequence
            .checked_add(1)
            .ok_or(quiche::Error::InvalidState)?;
        let frame = quiche::multicast::Limits {
            sequence,
            limits: self.settings.transport_params.limits.clone(),
            max_joined_count: self.settings.max_joined_channels,
        };
        quiche::multicast::Frame::Limits(frame.clone()).encoded_len()?;

        if !self.pending_control.is_empty() {
            self.queue_client_control(
                PendingClientControl {
                    frame: ClientControlFrame::Limits {
                        frame,
                        commit: None,
                    },
                    blocked_since: Some(Instant::now()),
                },
                "limits",
            )?;
            self.reserved_limits_sequence = sequence;
            return Ok(());
        }

        match qconn.multicast_try_send(quiche::multicast::Frame::Limits(frame)) {
            Ok(()) => {
                self.next_limits_sequence = sequence;
                self.reserved_limits_sequence = sequence;
            },

            Err(error)
                if error.kind() ==
                    quiche::multicast::ControlSendErrorKind::Full =>
            {
                let quiche::multicast::Frame::Limits(frame) = error.into_frame()
                else {
                    unreachable!("core returned another frame");
                };
                self.queue_client_control(
                    PendingClientControl {
                        frame: ClientControlFrame::Limits {
                            frame,
                            commit: None,
                        },
                        blocked_since: Some(Instant::now()),
                    },
                    "limits",
                )?;
                self.reserved_limits_sequence = sequence;
            },

            Err(error) => return Err(Box::new(error)),
        }

        Ok(())
    }

    fn send_state(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
        state: quiche::multicast::ChannelState, reason_code: u64,
        reason_phrase: Vec<u8>,
    ) -> QuicResult<()> {
        let Some(channel) = self.channels.get(&channel_id) else {
            return Err(quiche::Error::InvalidState.into());
        };
        let sequence = self
            .reserved_state_sequences
            .get(&channel_id)
            .copied()
            .unwrap_or(channel.next_state_sequence)
            .checked_add(1)
            .ok_or(quiche::Error::InvalidState)?;

        let frame = quiche::multicast::State {
            channel_id: channel_id.clone(),
            sequence,
            state,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code,
            reason_phrase,
        };
        quiche::multicast::Frame::State(frame.clone()).encoded_len()?;

        let commit = frame.clone();
        if !self.pending_control.is_empty() {
            self.queue_client_control(
                PendingClientControl {
                    frame: ClientControlFrame::State {
                        frame,
                        commit: Some(commit),
                    },
                    blocked_since: Some(Instant::now()),
                },
                "state",
            )?;
            self.reserved_state_sequences.insert(channel_id, sequence);
            return Ok(());
        }

        match qconn.multicast_try_send(quiche::multicast::Frame::State(frame)) {
            Ok(()) => {
                self.channels
                    .get_mut(&channel_id)
                    .expect("channel was checked above")
                    .next_state_sequence = sequence;
                qconn.multicast_process_local_state(commit.clone())?;
                self.emit_event(ClientEvent::LocalState(commit))?;
            },

            Err(error)
                if error.kind() ==
                    quiche::multicast::ControlSendErrorKind::Full =>
            {
                let quiche::multicast::Frame::State(frame) = error.into_frame()
                else {
                    unreachable!("core returned another frame");
                };
                self.queue_client_control(
                    PendingClientControl {
                        frame: ClientControlFrame::State {
                            frame,
                            commit: Some(commit),
                        },
                        blocked_since: Some(Instant::now()),
                    },
                    "state",
                )?;
                self.reserved_state_sequences.insert(channel_id, sequence);
            },

            Err(error) => return Err(Box::new(error)),
        }

        Ok(())
    }

    fn flush_one_pending_control(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.flush_pending_control_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    fn flush_pending_control_with_limit(
        &mut self, qconn: &mut QuicheConnection, max_work: usize,
    ) -> QuicResult<usize> {
        if self
            .control_retry_deadline
            .is_some_and(|deadline| deadline > Instant::now())
        {
            return Ok(0);
        }
        self.control_retry_deadline = None;
        let mut work = 0;

        for _ in 0..max_work {
            let Some(mut pending) = self.pending_control.pop_front() else {
                break;
            };
            work += 1;
            match pending.frame {
                ClientControlFrame::Limits { frame, commit } => {
                    let commit = commit.unwrap_or_else(|| frame.clone());
                    match qconn.multicast_try_send(
                        quiche::multicast::Frame::Limits(frame),
                    ) {
                        Ok(()) => {
                            self.next_limits_sequence = commit.sequence;
                        },

                        Err(error)
                            if error.kind() ==
                                quiche::multicast::ControlSendErrorKind::Full =>
                        {
                            let quiche::multicast::Frame::Limits(frame) =
                                error.into_frame()
                            else {
                                unreachable!("core returned another frame");
                            };
                            pending.frame = ClientControlFrame::Limits {
                                frame,
                                commit: Some(commit),
                            };
                            self.retry_client_control(pending)?;
                            break;
                        },

                        Err(error) => return Err(Box::new(error)),
                    }
                },

                ClientControlFrame::State { frame, commit } => {
                    let commit = commit.unwrap_or_else(|| frame.clone());
                    match qconn.multicast_try_send(
                        quiche::multicast::Frame::State(frame),
                    ) {
                        Ok(()) => {
                            let channel_id = commit.channel_id.clone();
                            let Some(channel) =
                                self.channels.get_mut(&channel_id)
                            else {
                                return Err(quiche::Error::InvalidState.into());
                            };
                            channel.next_state_sequence = commit.sequence;
                            if self
                                .reserved_state_sequences
                                .get(&channel_id)
                                .is_some_and(|sequence| {
                                    *sequence == commit.sequence
                                })
                            {
                                self.reserved_state_sequences.remove(&channel_id);
                            }
                            qconn
                                .multicast_process_local_state(commit.clone())?;
                            self.emit_event(ClientEvent::LocalState(commit))?;
                        },

                        Err(error)
                            if error.kind() ==
                                quiche::multicast::ControlSendErrorKind::Full =>
                        {
                            let quiche::multicast::Frame::State(frame) =
                                error.into_frame()
                            else {
                                unreachable!("core returned another frame");
                            };
                            pending.frame = ClientControlFrame::State {
                                frame,
                                commit: Some(commit),
                            };
                            self.retry_client_control(pending)?;
                            break;
                        },

                        Err(error) => return Err(Box::new(error)),
                    }
                },
            }
        }

        Ok(work)
    }

    fn queue_client_control(
        &mut self, pending: PendingClientControl, kind: &'static str,
    ) -> QuicResult<()> {
        let retry_deadline = if self.control_retry_deadline.is_none() {
            Some(
                Instant::now()
                    .checked_add(self.limits.control_retry_delay)
                    .ok_or(quiche::Error::InvalidState)?,
            )
        } else {
            None
        };
        self.pending_control.push_back(pending).map_err(|_| {
            Box::new(ClientError::ControlQueueExhausted(kind))
                as crate::result::BoxError
        })?;
        if let Some(retry_deadline) = retry_deadline {
            self.control_retry_deadline = Some(retry_deadline);
        }
        Ok(())
    }

    fn retry_client_control(
        &mut self, mut pending: PendingClientControl,
    ) -> QuicResult<()> {
        let now = Instant::now();
        let retry_deadline = now
            .checked_add(self.limits.control_retry_delay)
            .ok_or(quiche::Error::InvalidState)?;
        let blocked_since = *pending.blocked_since.get_or_insert(now);
        if now.saturating_duration_since(blocked_since) >=
            self.limits.control_backpressure_timeout
        {
            return Err(Box::new(ClientError::ControlBackpressureTimeout(
                self.limits.control_backpressure_timeout,
            )));
        }

        self.pending_control.push_front(pending).map_err(|_| {
            Box::new(ClientError::ControlQueueExhausted("retry"))
                as crate::result::BoxError
        })?;
        self.control_retry_deadline = Some(retry_deadline);
        Ok(())
    }

    fn decline_join(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
        reason_phrase: Vec<u8>,
    ) -> QuicResult<()> {
        self.decline_join_with_reason(
            qconn,
            channel_id,
            STATE_REASON_UNSPECIFIED_OTHER,
            reason_phrase,
        )
    }

    fn decline_join_with_reason(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
        reason_code: u64, reason_phrase: Vec<u8>,
    ) -> QuicResult<()> {
        {
            let channel = self.channels.entry(channel_id.clone()).or_default();
            channel.receive_handle.take();
            channel.pending_leave = None;
        }

        self.send_state(
            qconn,
            channel_id,
            quiche::multicast::ChannelState::DeclinedJoin,
            reason_code,
            reason_phrase,
        )
    }

    fn joined_channel_count(&self) -> u64 {
        self.channels
            .values()
            .filter(|channel| channel.receive_handle.is_some())
            .count() as u64
    }

    fn joined_rate_kibps(&self) -> u64 {
        self.channels
            .values()
            .filter(|channel| channel.receive_handle.is_some())
            .filter_map(|channel| channel.announce.as_ref())
            .fold(0_u64, |total, announce| {
                total.saturating_add(announce.max_rate_kibps)
            })
    }

    fn join_channel(
        &mut self, channel_id: &[u8], announce: &quiche::multicast::Announce,
    ) -> Result<B::Handle, JoinError> {
        match self.channel_socket_config(announce)? {
            ChannelSocketConfig::Ipv4 {
                source,
                group,
                udp_port,
                interface,
            } => self.backend.join_ipv4(
                channel_id,
                source,
                group,
                udp_port,
                interface,
                self.ingress_sender.clone(),
            ),

            ChannelSocketConfig::Ipv6Placeholder => Err(JoinError {
                reason_phrase: b"ipv6 multicast not yet supported".to_vec(),
            }),
        }
    }

    fn channel_socket_config(
        &self, announce: &quiche::multicast::Announce,
    ) -> Result<ChannelSocketConfig, JoinError> {
        match (&announce.source, &announce.group) {
            (IpAddr::V4(source), IpAddr::V4(group)) => {
                if !self.settings.transport_params.limits.ipv4_channels_allowed {
                    return Err(JoinError {
                        reason_phrase: b"ipv4 multicast disabled".to_vec(),
                    });
                }

                Ok(ChannelSocketConfig::Ipv4 {
                    source: *source,
                    group: *group,
                    udp_port: announce.udp_port,
                    interface: self.settings.ipv4_interface,
                })
            },

            (IpAddr::V6(_), IpAddr::V6(_)) =>
                Ok(ChannelSocketConfig::Ipv6Placeholder),

            _ => Err(JoinError {
                reason_phrase: b"mixed-family multicast announce".to_vec(),
            }),
        }
    }

    fn peer_supports_multicast(&self, qconn: &QuicheConnection) -> bool {
        qconn
            .peer_transport_params()
            .map(|params| params.multicast_server_support)
            .unwrap_or(false)
    }

    fn flush_one_pending_ack(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        let Some(channel_id) = fair_ready_channel_ids(
            &self.channels,
            self.ack_flush_cursor.as_deref(),
            1,
            |channel| channel.ack_state.has_pending_ack(),
        )
        .pop() else {
            return Ok(false);
        };
        self.ack_flush_cursor = Some(channel_id.clone());
        let frame = self
            .channels
            .get(&channel_id)
            .and_then(|channel| channel.ack_state.pending_ack(&channel_id))
            .expect("selected channel has a pending ACK");

        match qconn.multicast_try_send(quiche::multicast::Frame::Ack(frame)) {
            Ok(()) => {
                self.channels
                    .get_mut(&channel_id)
                    .expect("selected channel still exists")
                    .ack_state
                    .mark_sent();
            },

            Err(error)
                if error.kind() ==
                    quiche::multicast::ControlSendErrorKind::Full =>
                (),

            Err(error) => return Err(Box::new(error)),
        }

        Ok(true)
    }

    fn emit_channel_metrics(&self, channel_id: &[u8]) -> QuicResult<()> {
        let Some(channel) = self.channels.get(channel_id) else {
            return Ok(());
        };
        let Some(receive_state) = channel.receive_state.as_ref() else {
            return Ok(());
        };
        let Some(socket) = channel.last_subscription_metrics.clone() else {
            return Ok(());
        };

        self.emit_event(ClientEvent::MetricsUpdated {
            channel_id: channel_id.to_vec(),
            metrics: ClientChannelMetricsSnapshot {
                socket,
                receive: receive_state.metrics_snapshot(),
            },
        })
    }

    fn ensure_channel_decoder(channel: &mut Channel<B::Handle>) {
        if channel.retired ||
            channel.receive_state.is_some() ||
            channel.decoder_error.is_some()
        {
            return;
        }

        let Some(announce) = channel.announce.clone() else {
            return;
        };

        let mut receiver =
            match quiche::multicast::ChannelReceiveState::new(announce) {
                Ok(receiver) => receiver,

                Err(..) => {
                    channel.decoder_error = Some(
                        b"unsupported multicast channel properties".to_vec(),
                    );
                    return;
                },
            };

        if let Some(key) = channel.key.clone() {
            match receiver.insert_key_with_budget(key, 1, 1) {
                Ok(..) => (),

                Err(..) => {
                    channel.decoder_error = Some(
                        b"unsupported multicast channel properties".to_vec(),
                    );
                    return;
                },
            }
        }

        channel.receive_state = Some(receiver);
    }
}

struct Channel<H> {
    announce: Option<quiche::multicast::Announce>,
    key: Option<quiche::multicast::Key>,
    decoder_error: Option<Vec<u8>>,
    last_subscription_metrics: Option<SubscriptionMetricsSnapshot>,
    receive_state:
        Option<quiche::multicast::ChannelReceiveState<PacketWithMetadata>>,
    ack_state: quiche::multicast::AckTracker,
    next_state_sequence: u64,
    highest_server_state_sequence: Option<u64>,
    largest_authenticated_packet_number: Option<u64>,
    pending_leave: Option<PendingLeave>,
    pending_retire_after: Option<u64>,
    retired: bool,
    receive_handle: Option<H>,
}

impl<H> Default for Channel<H> {
    fn default() -> Self {
        Self {
            announce: None,
            key: None,
            decoder_error: None,
            last_subscription_metrics: None,
            receive_state: None,
            ack_state: quiche::multicast::AckTracker::default(),
            next_state_sequence: 0,
            highest_server_state_sequence: None,
            largest_authenticated_packet_number: None,
            pending_leave: None,
            pending_retire_after: None,
            retired: false,
            receive_handle: None,
        }
    }
}

impl<H> Drop for Channel<H> {
    fn drop(&mut self) {
        if let Some(key) = self.key.as_mut() {
            key.secret.fill(0);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingLeave {
    state_sequence: u64,
    after_packet_number: u64,
}

#[derive(Debug)]
enum ChannelSocketConfig {
    Ipv4 {
        source: Ipv4Addr,
        group: Ipv4Addr,
        udp_port: u16,
        interface: Option<Ipv4Addr>,
    },

    Ipv6Placeholder,
}

#[derive(Debug)]
struct JoinError {
    reason_phrase: Vec<u8>,
}

#[derive(Debug)]
enum IngressEvent {
    Packet {
        channel_id: Vec<u8>,
        socket_metrics: SubscriptionMetricsSnapshot,
        packet: PacketWithMetadata,
    },

    ReceiveError {
        channel_id: Vec<u8>,
        socket_metrics: SubscriptionMetricsSnapshot,
        error: TokioReceiveError,
    },

    Overload {
        channel_id: Vec<u8>,
        retained_bytes: usize,
        max_retained_bytes: usize,
    },
}

impl RetainedSize for IngressEvent {
    fn retained_size(&self) -> usize {
        match self {
            Self::Packet {
                channel_id, packet, ..
            } => channel_id
                .len()
                .saturating_add(packet.packet.payload.len())
                .saturating_add(256),

            Self::ReceiveError { channel_id, .. } =>
                channel_id.len().saturating_add(256),

            Self::Overload { channel_id, .. } =>
                channel_id.len().saturating_add(32),
        }
    }
}

trait JoinBackend {
    type Handle;

    fn join_ipv4(
        &mut self, channel_id: &[u8], source: Ipv4Addr, group: Ipv4Addr,
        udp_port: u16, interface: Option<Ipv4Addr>,
        ingress_sender: BoundedSender<IngressEvent>,
    ) -> Result<Self::Handle, JoinError>;
}

#[derive(Debug)]
struct McrxJoinBackend;

impl McrxJoinBackend {
    fn join_error(err: impl std::fmt::Display) -> JoinError {
        JoinError {
            reason_phrase: format!("mcrx join failed: {err}").into_bytes(),
        }
    }
}

impl JoinBackend for McrxJoinBackend {
    type Handle = AbortOnDropHandle<()>;

    fn join_ipv4(
        &mut self, channel_id: &[u8], source: Ipv4Addr, group: Ipv4Addr,
        udp_port: u16, interface: Option<Ipv4Addr>,
        ingress_sender: BoundedSender<IngressEvent>,
    ) -> Result<Self::Handle, JoinError> {
        let mut config = SubscriptionConfig::ssm(group, source, udp_port);
        config.interface = interface.map(IpAddr::V4);

        let mut context = MulticastContext::new();
        let subscription_id = context
            .add_subscription(config)
            .map_err(McrxJoinBackend::join_error)?;
        context
            .join_subscription(subscription_id)
            .map_err(McrxJoinBackend::join_error)?;

        let subscription =
            context
                .take_subscription(subscription_id)
                .ok_or(JoinError {
                    reason_phrase: b"mcrx join failed: missing subscription"
                        .to_vec(),
                })?;
        let mut subscription = TokioSubscription::new(subscription)
            .map_err(McrxJoinBackend::join_error)?;

        let channel_id = channel_id.to_vec();
        let task = tokio::spawn(async move {
            loop {
                match subscription.recv_with_metadata().await {
                    Ok(packet) => {
                        let socket_metrics =
                            subscription.subscription().metrics_snapshot();
                        let event = IngressEvent::Packet {
                            channel_id: channel_id.clone(),
                            socket_metrics,
                            packet,
                        };
                        let retained_bytes = event.retained_size();
                        match ingress_sender.send(event).await {
                            Ok(()) => (),

                            Err(QueueSendError::Oversized(..)) => {
                                let _ = ingress_sender
                                    .send(IngressEvent::Overload {
                                        channel_id: channel_id.clone(),
                                        retained_bytes,
                                        max_retained_bytes: ingress_sender
                                            .limits()
                                            .max_retained_bytes,
                                    })
                                    .await;
                                break;
                            },

                            Err(QueueSendError::Closed(..)) => break,

                            Err(QueueSendError::Full(..)) => unreachable!(
                                "asynchronous ingress send waits for capacity"
                            ),
                        }
                    },

                    Err(error) => {
                        let socket_metrics =
                            subscription.subscription().metrics_snapshot();
                        let _ = ingress_sender
                            .send(IngressEvent::ReceiveError {
                                channel_id: channel_id.clone(),
                                socket_metrics,
                                error,
                            })
                            .await;
                        break;
                    },
                }
            }
        });

        Ok(AbortOnDropHandle::new(task))
    }
}

/// Bounded batching for integrity generated by [`ServerStreamPublisher`].
///
/// This does not alter externally relayed `MC_INTEGRITY` frames. A value of one
/// for `max_packet_hashes` or a zero `max_delay` preserves immediate delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamIntegrityBatchingSettings {
    /// Maximum number of contiguous packet hashes in one `MC_INTEGRITY` frame.
    pub max_packet_hashes: u64,

    /// Maximum time the first packet hash may wait for more contiguous hashes.
    pub max_delay: Duration,
}

impl Default for StreamIntegrityBatchingSettings {
    fn default() -> Self {
        Self {
            max_packet_hashes: 1,
            max_delay: Duration::ZERO,
        }
    }
}

/// Server-side multicast settings for one connection wrapper.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerControlSettings {
    /// Whether configured control frames should be sent automatically or only
    /// when driven explicitly through [`ServerControlController`].
    pub mode: ServerControlMode,

    /// The multicast channels this server may announce and manage through the
    /// QUIC control connection.
    pub channels: Vec<ServerControlChannelConfig>,

    /// Batching policy for stream-publication integrity frames.
    pub stream_integrity_batching: StreamIntegrityBatchingSettings,
}

/// Automatic or manual sequencing for multicast control frames.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServerControlMode {
    /// Send initial announces and keys automatically, then emit joins when the
    /// peer advertises `MC_LIMITS`.
    #[default]
    Automatic,

    /// Keep channel state locally but only send control frames when the
    /// application explicitly requests them.
    Manual,
}

/// Control-plane configuration for one multicast channel.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerControlChannelConfig {
    /// The announced multicast channel properties.
    pub announce: quiche::multicast::Announce,

    /// The active multicast payload-protection key for the channel.
    pub key: quiche::multicast::Key,
}

impl fmt::Debug for ServerControlChannelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerControlChannelConfig")
            .field("announce", &self.announce)
            .field("key", &self.key)
            .finish()
    }
}

impl ServerControlChannelConfig {
    fn validate(&self) -> quiche::Result<()> {
        validate_server_announce(&self.announce)?;
        self.key.validate()?;

        if self.announce.channel_id != self.key.channel_id {
            return Err(quiche::Error::InvalidState);
        }

        Ok(())
    }
}

impl ServerControlSettings {
    fn validate(&self) -> quiche::Result<()> {
        for channel in &self.channels {
            channel.validate()?;
        }

        quiche::multicast::Integrity {
            channel_id: vec![1],
            packet_number_start: 0,
            packet_hash_count: Some(
                self.stream_integrity_batching.max_packet_hashes,
            ),
            packet_hashes: Vec::new(),
        }
        .validate()?;
        Instant::now()
            .checked_add(self.stream_integrity_batching.max_delay)
            .ok_or(quiche::Error::InvalidState)?;

        Ok(())
    }
}

/// Server-side multicast settings for one publication-owning connection
/// wrapper.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerSettings {
    /// The multicast channels this server may announce and publish.
    pub channels: Vec<ServerChannelConfig>,
}

/// Configuration for one multicast channel served by [`ServerDriver`].
#[derive(Clone, PartialEq, Eq)]
pub struct ServerChannelConfig {
    /// The multicast channel ID carried in the draft control frames.
    pub channel_id: Vec<u8>,

    /// The multicast sender socket configuration used by `mctx-core`.
    pub publication: PublicationConfig,

    /// The header protection algorithm from the TLS cipher suite registry.
    pub header_protection_algorithm: u16,

    /// The secret used for multicast short-header protection.
    pub header_secret: Vec<u8>,

    /// The AEAD algorithm from the TLS cipher suite registry.
    pub aead_algorithm: u16,

    /// The packet integrity hash algorithm.
    pub integrity_hash_algorithm: u16,

    /// The maximum multicast payload rate for the channel, in Kibps.
    pub max_rate_kibps: u64,

    /// The maximum delay before sending `MC_ACK`, in milliseconds.
    pub max_ack_delay_ms: u64,

    /// The key sequence number announced to receivers.
    pub key_sequence: u64,

    /// The first packet number protected by `secret`.
    pub from_packet_number: u64,

    /// The multicast payload protection secret.
    pub secret: Vec<u8>,
}

impl fmt::Debug for ServerChannelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerChannelConfig")
            .field("channel_id", &self.channel_id)
            .field("publication", &self.publication)
            .field(
                "header_protection_algorithm",
                &self.header_protection_algorithm,
            )
            .field(
                "header_secret",
                &format_args!("<redacted:{} bytes>", self.header_secret.len()),
            )
            .field("aead_algorithm", &self.aead_algorithm)
            .field("integrity_hash_algorithm", &self.integrity_hash_algorithm)
            .field("max_rate_kibps", &self.max_rate_kibps)
            .field("max_ack_delay_ms", &self.max_ack_delay_ms)
            .field("key_sequence", &self.key_sequence)
            .field("from_packet_number", &self.from_packet_number)
            .field(
                "secret",
                &format_args!("<redacted:{} bytes>", self.secret.len()),
            )
            .finish()
    }
}

impl Drop for ServerChannelConfig {
    fn drop(&mut self) {
        self.header_secret.fill(0);
        self.secret.fill(0);
    }
}

impl ServerChannelConfig {
    fn validate(&self) -> quiche::Result<()> {
        let source = match self.publication.group {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };
        let announce = quiche::multicast::Announce {
            channel_id: self.channel_id.clone(),
            source,
            group: self.publication.group,
            udp_port: self.publication.dst_port,
            header_protection_algorithm: self.header_protection_algorithm,
            header_secret: self.header_secret.clone(),
            aead_algorithm: self.aead_algorithm,
            integrity_hash_algorithm: self.integrity_hash_algorithm,
            max_rate_kibps: self.max_rate_kibps,
            max_ack_delay_ms: self.max_ack_delay_ms,
        };
        validate_server_announce(&announce)?;
        self.key_frame().validate()
    }

    fn control_channel_from(
        &self, source: Ipv4Addr, group: Ipv4Addr, udp_port: u16,
    ) -> Result<ServerControlChannelConfig, MctxError> {
        Ok(ServerControlChannelConfig {
            announce: self.announce_from(source, group, udp_port)?,
            key: self.key_frame(),
        })
    }

    fn announce_from(
        &self, source: Ipv4Addr, group: Ipv4Addr, udp_port: u16,
    ) -> Result<quiche::multicast::Announce, MctxError> {
        Ok(quiche::multicast::Announce {
            channel_id: self.channel_id.clone(),
            source: IpAddr::V4(source),
            group: IpAddr::V4(group),
            udp_port,
            header_protection_algorithm: self.header_protection_algorithm,
            header_secret: self.header_secret.clone(),
            aead_algorithm: self.aead_algorithm,
            integrity_hash_algorithm: self.integrity_hash_algorithm,
            max_rate_kibps: self.max_rate_kibps,
            max_ack_delay_ms: self.max_ack_delay_ms,
        })
    }

    fn key_frame(&self) -> quiche::multicast::Key {
        quiche::multicast::Key {
            channel_id: self.channel_id.clone(),
            key_sequence: self.key_sequence,
            from_packet_number: self.from_packet_number,
            secret: self.secret.clone(),
        }
    }
}

impl ServerSettings {
    fn validate(&self) -> quiche::Result<()> {
        for channel in &self.channels {
            channel.validate()?;
        }

        Ok(())
    }
}

/// Events emitted by [`ServerDriver`].
#[derive(Debug)]
pub enum ServerEvent {
    /// The client advertised updated multicast limits.
    ClientLimits(quiche::multicast::Limits),

    /// The client reported multicast channel state.
    ClientState(quiche::multicast::State),

    /// The client acknowledged multicast packet ranges.
    ClientAck(quiche::multicast::Ack),

    /// The connection-local multicast path changed viability state.
    ///
    /// This includes probing, successful ACK validation, ACK-freshness
    /// timeout, join failure, leave, and retirement transitions.
    ProbeStatusChanged(quiche::multicast::ProbeEvent),

    /// A multicast packet was successfully published on a channel.
    Published {
        /// The QUIC multicast channel ID associated with the packet.
        channel_id: Vec<u8>,

        /// The multicast channel packet number carried on the wire.
        packet_number: u64,

        /// The send report returned by `mctx-core`.
        report: SendReport,
    },

    /// The server could not encode a multicast packet command.
    EncodeError {
        /// The QUIC multicast channel ID associated with the failed command.
        channel_id: Vec<u8>,

        /// The core multicast encoding error reported by `quiche`.
        error: quiche::Error,
    },

    /// The server could not publish an encoded multicast packet.
    PublishError {
        /// The QUIC multicast channel ID associated with the failed publish.
        channel_id: Vec<u8>,

        /// The underlying multicast sender error from `mctx-core`.
        error: MctxError,
    },
}

enum PendingClientAckAction {
    Ack(quiche::multicast::Ack),
    Reset,
}

#[derive(Default)]
struct ServerEventCoalescer {
    pending_client_acks: BTreeMap<Vec<u8>, VecDeque<PendingClientAckAction>>,
    last_client_acks: BTreeMap<Vec<u8>, quiche::multicast::Ack>,
    last_probe_events: BTreeMap<Vec<u8>, quiche::multicast::ProbeEvent>,
    ack_flush_cursor: Option<Vec<u8>>,
}

impl ServerEventCoalescer {
    fn has_pending_client_acks(&self) -> bool {
        self.pending_client_acks
            .values()
            .any(|pending| !pending.is_empty())
    }

    fn queue_client_ack(
        &mut self, event_sender: &ManagedEventSender<ServerEvent>,
        frame: quiche::multicast::Ack,
    ) {
        let pending = self
            .pending_client_acks
            .entry(frame.channel_id.clone())
            .or_default();
        let matches_pending = pending.back().is_some_and(|previous| {
            matches!(
                previous,
                PendingClientAckAction::Ack(previous) if previous == &frame
            )
        });
        let matches_delivered = pending.is_empty() &&
            self.last_client_acks
                .get(&frame.channel_id)
                .is_some_and(|previous| previous == &frame);
        if matches_pending || matches_delivered {
            event_sender.record_identical_coalesced();
            return;
        }
        pending.push_back(PendingClientAckAction::Ack(frame));
    }

    fn flush_client_acks(
        &mut self, event_sender: &ManagedEventSender<ServerEvent>,
        max_work: usize,
    ) -> Result<usize, EventSendError> {
        let mut work = 0;
        while work < max_work {
            if !self.flush_one_client_ack(event_sender)? {
                break;
            }
            work += 1;
        }

        Ok(work)
    }

    fn flush_one_client_ack(
        &mut self, event_sender: &ManagedEventSender<ServerEvent>,
    ) -> Result<bool, EventSendError> {
        let Some(channel_id) = fair_ready_channel_ids(
            &self.pending_client_acks,
            self.ack_flush_cursor.as_deref(),
            1,
            |pending| !pending.is_empty(),
        )
        .pop() else {
            return Ok(false);
        };
        self.ack_flush_cursor = Some(channel_id.clone());
        let action = self
            .pending_client_acks
            .get_mut(&channel_id)
            .and_then(VecDeque::pop_front)
            .expect("selected channel has pending ACK work");
        if self
            .pending_client_acks
            .get(&channel_id)
            .is_some_and(VecDeque::is_empty)
        {
            self.pending_client_acks.remove(&channel_id);
        }

        match action {
            PendingClientAckAction::Ack(frame) => {
                self.last_client_acks.insert(channel_id, frame.clone());
                event_sender.try_send(ServerEvent::ClientAck(frame))?;
            },

            PendingClientAckAction::Reset => {
                self.last_client_acks.remove(&channel_id);
            },
        }

        Ok(true)
    }

    fn reset_channel(&mut self, channel_id: &[u8]) {
        let pending = self
            .pending_client_acks
            .entry(channel_id.to_vec())
            .or_default();
        if !matches!(pending.back(), Some(PendingClientAckAction::Reset)) {
            pending.push_back(PendingClientAckAction::Reset);
        }
        self.last_client_acks.remove(channel_id);
        self.last_probe_events.remove(channel_id);
    }

    fn forward_probe_event(
        &mut self, event_sender: &ManagedEventSender<ServerEvent>,
        event: quiche::multicast::ProbeEvent,
    ) -> Result<(), EventSendError> {
        if self
            .last_probe_events
            .get(&event.channel_id)
            .is_some_and(|previous| previous == &event)
        {
            event_sender.record_identical_coalesced();
            return Ok(());
        }

        self.last_probe_events
            .insert(event.channel_id.clone(), event.clone());
        event_sender.try_send(ServerEvent::ProbeStatusChanged(event))
    }

    fn clear(&mut self) {
        self.pending_client_acks.clear();
        self.last_client_acks.clear();
        self.last_probe_events.clear();
        self.ack_flush_cursor = None;
    }
}

/// Handle for consuming multicast control events and relaying integrity from
/// an external multicast sender.
pub struct ServerControlController {
    command_sender: BoundedSender<ServerControlCommand>,
    command_observer: RetainedQueueObserver,
    pending_publication_observer: RetainedQueueObserver,
    pending_integrity_observer: RetainedQueueObserver,
    event_receiver: Option<ServerEventStream>,
    event_observer: EventQueueObserver<ServerEvent>,
}

impl ServerControlController {
    /// Stores or updates one channel definition.
    ///
    /// In automatic mode this also sends `MC_ANNOUNCE` and `MC_KEY`
    /// immediately once the client connection is ready, and it will emit
    /// `MC_JOIN` automatically if the peer has already sent `MC_LIMITS`.
    pub fn upsert_channel(
        &self, config: ServerControlChannelConfig,
    ) -> Result<(), ControllerSendError<ServerControlChannelConfig>> {
        if config.validate().is_err() {
            return Err(ControllerSendError::invalid(config));
        }

        self.command_sender
            .try_send(ServerControlCommand::UpsertChannel { config })
            .map_err(|error| {
                ControllerSendError::from_queue(error.map(|command| {
                    let ServerControlCommand::UpsertChannel { config } = command
                    else {
                        unreachable!("upsert command changed while queued");
                    };
                    config
                }))
            })
    }

    /// Queues one `MC_ANNOUNCE` frame for explicit transmission.
    pub fn send_announce(
        &self, frame: quiche::multicast::Announce,
    ) -> Result<(), ControllerSendError<quiche::multicast::Announce>> {
        if validate_server_announce(&frame).is_err() {
            return Err(ControllerSendError::invalid(frame));
        }

        self.command_sender
            .try_send(ServerControlCommand::SendAnnounce {
                frame,
                cached: None,
            })
            .map_err(|error| {
                ControllerSendError::from_queue(error.map(|command| {
                    let ServerControlCommand::SendAnnounce { frame, .. } =
                        command
                    else {
                        unreachable!("announce command changed while queued");
                    };
                    frame
                }))
            })
    }

    /// Queues one `MC_KEY` frame for explicit transmission.
    pub fn send_key(
        &self, frame: quiche::multicast::Key,
    ) -> Result<(), ControllerSendError<quiche::multicast::Key>> {
        if frame.validate().is_err() {
            return Err(ControllerSendError::invalid(frame));
        }

        self.command_sender
            .try_send(ServerControlCommand::SendKey {
                frame,
                cached: None,
            })
            .map_err(|error| {
                ControllerSendError::from_queue(error.map(|command| {
                    let ServerControlCommand::SendKey { frame, .. } = command
                    else {
                        unreachable!("key command changed while queued");
                    };
                    frame
                }))
            })
    }

    /// Queues one explicit `MC_JOIN` frame.
    pub fn send_join(
        &self, frame: quiche::multicast::Join,
    ) -> Result<(), ControllerSendError<quiche::multicast::Join>> {
        if frame.validate().is_err() {
            return Err(ControllerSendError::invalid(frame));
        }

        self.command_sender
            .try_send(ServerControlCommand::SendJoin { frame })
            .map_err(|error| {
                ControllerSendError::from_queue(error.map(|command| {
                    let ServerControlCommand::SendJoin { frame } = command else {
                        unreachable!("join command changed while queued");
                    };
                    frame
                }))
            })
    }

    /// Queues one externally generated `MC_INTEGRITY` frame for relay on the
    /// client-facing QUIC control connection.
    pub fn send_integrity(
        &self, frame: quiche::multicast::Integrity,
    ) -> Result<(), ControllerSendError<quiche::multicast::Integrity>> {
        if frame.validate().is_err() {
            return Err(ControllerSendError::invalid(frame));
        }

        self.command_sender
            .try_send(ServerControlCommand::RelayIntegrity { frame })
            .map_err(|error| {
                ControllerSendError::from_queue(error.map(|command| {
                    let ServerControlCommand::RelayIntegrity { frame } = command
                    else {
                        unreachable!("integrity command changed while queued");
                    };
                    frame
                }))
            })
    }

    /// Returns the multicast event receiver if it has not been taken.
    pub fn event_receiver_mut(&mut self) -> Option<&mut ServerEventStream> {
        self.event_receiver.as_mut()
    }

    /// Takes ownership of the event receiver.
    ///
    /// A receiver can be taken only once. Later calls return `None` and do not
    /// create a replacement queue.
    pub fn take_event_receiver(&mut self) -> Option<ServerEventStream> {
        self.event_receiver.take()
    }

    /// Returns event queue counters without consuming the receiver.
    pub fn event_queue_stats(&self) -> EventQueueStats {
        self.event_observer.stats()
    }

    /// Returns command queue counters without consuming commands.
    pub fn command_queue_stats(&self) -> RetainedQueueStats {
        self.command_observer.stats()
    }

    /// Returns all retained runtime queue counters.
    pub fn runtime_queue_stats(&self) -> ServerRuntimeQueueStats {
        ServerRuntimeQueueStats {
            commands: self.command_observer.stats(),
            pending_publications: self.pending_publication_observer.stats(),
            pending_integrity: self.pending_integrity_observer.stats(),
        }
    }
}

/// Wraps another [`ApplicationOverQuic`] with multicast control-plane logic
/// only.
///
/// The wrapped application continues to own the regular QUIC and HTTP/3
/// behavior while this wrapper announces configured multicast channels, reacts
/// to client `MC_LIMITS` / `MC_STATE` / `MC_ACK` frames, and relays externally
/// generated `MC_INTEGRITY` frames. It does not assume this QUIC endpoint owns
/// multicast publication itself.
pub struct ServerControlDriver<A> {
    inner: A,
    runtime: ServerControlRuntime,
}

impl<A> ServerControlDriver<A> {
    /// Creates a new control-only multicast server wrapper and its
    /// controller.
    pub fn new(
        inner: A, settings: ServerControlSettings,
    ) -> Result<(Self, ServerControlController), RuntimeLimitsError> {
        Self::new_with_runtime_limits(inner, settings, RuntimeLimits::default())
    }

    /// Creates a control-only server wrapper with explicit event queue limits.
    pub fn new_with_event_queue_limits(
        inner: A, settings: ServerControlSettings, event_limits: EventQueueLimits,
    ) -> Result<(Self, ServerControlController), RuntimeLimitsError> {
        let limits = RuntimeLimits {
            events: event_limits,
            ..RuntimeLimits::default()
        };
        Self::new_with_runtime_limits(inner, settings, limits)
    }

    /// Creates a control-only server wrapper with explicit runtime limits.
    pub fn new_with_runtime_limits(
        inner: A, settings: ServerControlSettings, limits: RuntimeLimits,
    ) -> Result<(Self, ServerControlController), RuntimeLimitsError> {
        settings
            .validate()
            .map_err(RuntimeLimitsError::InvalidMulticastSettings)?;
        let limits = limits.validate()?;
        let (command_sender, command_receiver, command_observer) =
            bounded_channel(limits.commands);
        let (event_sender, event_receiver, event_observer) =
            server_event_channel(limits.events);
        let runtime = ServerControlRuntime::with_limits(
            settings,
            event_sender,
            command_receiver,
            limits,
        );
        let pending_publication_observer =
            runtime.pending_stream_publications.observer();
        let pending_integrity_observer = runtime.pending_integrities.observer();

        Ok((Self { inner, runtime }, ServerControlController {
            command_sender,
            command_observer,
            pending_publication_observer,
            pending_integrity_observer,
            event_receiver: Some(event_receiver),
            event_observer,
        }))
    }

    /// Returns a shared reference to the wrapped application.
    pub fn inner(&self) -> &A {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped application.
    pub fn inner_mut(&mut self) -> &mut A {
        &mut self.inner
    }

    /// Consumes the wrapper and returns the wrapped application.
    pub fn into_inner(self) -> A {
        self.inner
    }
}

impl<A: ApplicationOverQuic> ApplicationOverQuic for ServerControlDriver<A> {
    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection,
        handshake_info: &crate::quic::HandshakeInfo,
    ) -> QuicResult<()> {
        self.runtime.on_conn_established(qconn)?;
        let result = self.inner.on_conn_established(qconn, handshake_info);
        self.runtime.probe_read_pending = qconn.is_multicast_probe_readable();
        result
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        self.inner.buffer()
    }

    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if self.runtime.has_pending_work() ||
            qconn.is_multicast_probe_readable() ||
            qconn.is_multicast_stream_delivery_metrics_readable()
        {
            return Ok(());
        }

        if self.inner.should_act() {
            select! {
                res = self.inner.wait_for_data(qconn) => res,
                res = self.runtime.wait_for_work() => res,
            }
        } else {
            self.runtime.wait_for_work().await
        }
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.runtime.process_reads(qconn)?;

        let result = if self.inner.should_act() {
            self.inner.process_reads(qconn)
        } else {
            Ok(())
        };
        self.runtime.probe_read_pending = qconn.is_multicast_probe_readable();
        result
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        if self.inner.should_act() {
            self.inner.process_writes(qconn)?;
        }

        // The application owns any connection-specific stream prefix. Let it
        // create that prefix before shared publisher ranges are registered at
        // their exact offsets.
        self.runtime.process_writes(qconn)
    }

    fn on_conn_close<M: crate::metrics::Metrics>(
        &mut self, qconn: &mut QuicheConnection, metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        self.runtime.on_conn_close(qconn);
        self.inner.on_conn_close(qconn, metrics, connection_result);
    }
}

/// Handle for consuming multicast events and publishing packets.
pub struct ServerController {
    command_sender: BoundedSender<ServerCommand>,
    command_observer: RetainedQueueObserver,
    pending_publication_observer: RetainedQueueObserver,
    pending_integrity_observer: RetainedQueueObserver,
    event_receiver: Option<ServerEventStream>,
    event_observer: EventQueueObserver<ServerEvent>,
}

impl ServerController {
    /// Queues one multicast packet for the given channel.
    pub fn send_on_channel(
        &self, channel_id: Vec<u8>, frames: Vec<quiche::multicast::ChannelFrame>,
    ) -> Result<(), ServerChannelSendError> {
        if quiche::multicast::validate_channel_id(&channel_id).is_err() ||
            frames.iter().any(|frame| frame.encoded_len().is_err())
        {
            return Err(ControllerSendError::invalid((channel_id, frames)));
        }

        self.command_sender
            .try_send(ServerCommand::Send { channel_id, frames })
            .map_err(|error| {
                ControllerSendError::from_queue(error.map(|command| {
                    let ServerCommand::Send { channel_id, frames } = command
                    else {
                        unreachable!("send command changed while queued");
                    };
                    (channel_id, frames)
                }))
            })
    }

    /// Queues one externally generated `MC_INTEGRITY` frame for relay on the
    /// client-facing QUIC control connection.
    pub fn send_integrity(
        &self, frame: quiche::multicast::Integrity,
    ) -> Result<(), ControllerSendError<quiche::multicast::Integrity>> {
        if frame.validate().is_err() {
            return Err(ControllerSendError::invalid(frame));
        }

        self.command_sender
            .try_send(ServerCommand::RelayIntegrity { frame })
            .map_err(|error| {
                ControllerSendError::from_queue(error.map(|command| {
                    let ServerCommand::RelayIntegrity { frame } = command else {
                        unreachable!("integrity command changed while queued");
                    };
                    frame
                }))
            })
    }

    /// Returns the multicast event receiver if it has not been taken.
    pub fn event_receiver_mut(&mut self) -> Option<&mut ServerEventStream> {
        self.event_receiver.as_mut()
    }

    /// Takes ownership of the event receiver.
    ///
    /// A receiver can be taken only once. Later calls return `None` and do not
    /// create a replacement queue.
    pub fn take_event_receiver(&mut self) -> Option<ServerEventStream> {
        self.event_receiver.take()
    }

    /// Returns event queue counters without consuming the receiver.
    pub fn event_queue_stats(&self) -> EventQueueStats {
        self.event_observer.stats()
    }

    /// Returns command queue counters without consuming commands.
    pub fn command_queue_stats(&self) -> RetainedQueueStats {
        self.command_observer.stats()
    }

    /// Returns all retained runtime queue counters.
    pub fn runtime_queue_stats(&self) -> ServerRuntimeQueueStats {
        ServerRuntimeQueueStats {
            commands: self.command_observer.stats(),
            pending_publications: self.pending_publication_observer.stats(),
            pending_integrity: self.pending_integrity_observer.stats(),
        }
    }
}

/// Wraps another [`ApplicationOverQuic`] with multicast server send logic.
///
/// The wrapped application continues to own the regular QUIC and HTTP/3
/// behavior while this wrapper announces configured multicast channels, reacts
/// to client `MC_LIMITS` / `MC_STATE` frames, and publishes encoded multicast
/// packets via `mctx-core`.
pub struct ServerDriver<A> {
    inner: A,
    runtime: ServerRuntime<MctxPublishBackend>,
}

impl<A> ServerDriver<A> {
    /// Creates a new multicast server wrapper and its controller.
    pub fn new(
        inner: A, settings: ServerSettings,
    ) -> Result<(Self, ServerController), RuntimeLimitsError> {
        Self::new_with_runtime_limits(inner, settings, RuntimeLimits::default())
    }

    /// Creates a multicast server wrapper with explicit event queue limits.
    pub fn new_with_event_queue_limits(
        inner: A, settings: ServerSettings, event_limits: EventQueueLimits,
    ) -> Result<(Self, ServerController), RuntimeLimitsError> {
        let limits = RuntimeLimits {
            events: event_limits,
            ..RuntimeLimits::default()
        };
        Self::new_with_runtime_limits(inner, settings, limits)
    }

    /// Creates a multicast server wrapper with explicit runtime limits.
    pub fn new_with_runtime_limits(
        inner: A, settings: ServerSettings, limits: RuntimeLimits,
    ) -> Result<(Self, ServerController), RuntimeLimitsError> {
        settings
            .validate()
            .map_err(RuntimeLimitsError::InvalidMulticastSettings)?;
        let limits = limits.validate()?;
        let (command_sender, command_receiver, command_observer) =
            bounded_channel(limits.commands);
        let (event_sender, event_receiver, event_observer) =
            server_event_channel(limits.events);
        let runtime =
            ServerRuntime::new(settings, event_sender, command_receiver, limits);
        let pending_publication_observer =
            runtime.pending_publications.observer();
        let pending_integrity_observer = runtime.pending_integrities.observer();

        Ok((Self { inner, runtime }, ServerController {
            command_sender,
            command_observer,
            pending_publication_observer,
            pending_integrity_observer,
            event_receiver: Some(event_receiver),
            event_observer,
        }))
    }

    /// Returns a shared reference to the wrapped application.
    pub fn inner(&self) -> &A {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped application.
    pub fn inner_mut(&mut self) -> &mut A {
        &mut self.inner
    }

    /// Consumes the wrapper and returns the wrapped application.
    pub fn into_inner(self) -> A {
        self.inner
    }
}

impl<A: ApplicationOverQuic> ApplicationOverQuic for ServerDriver<A> {
    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection,
        handshake_info: &crate::quic::HandshakeInfo,
    ) -> QuicResult<()> {
        self.runtime.on_conn_established(qconn)?;
        self.inner.on_conn_established(qconn, handshake_info)
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        self.inner.buffer()
    }

    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if self.runtime.has_pending_work() {
            return Ok(());
        }

        if self.inner.should_act() {
            select! {
                res = self.inner.wait_for_data(qconn) => res,
                res = self.runtime.wait_for_work() => res,
            }
        } else {
            self.runtime.wait_for_work().await
        }
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.runtime.process_reads(qconn)?;

        if self.inner.should_act() {
            self.inner.process_reads(qconn)?;
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.runtime.process_writes(qconn)?;

        if self.inner.should_act() {
            self.inner.process_writes(qconn)?;
        }

        Ok(())
    }

    fn on_conn_close<M: crate::metrics::Metrics>(
        &mut self, qconn: &mut QuicheConnection, metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        self.runtime.clear();
        self.runtime.event_sender.finish();
        self.inner.on_conn_close(qconn, metrics, connection_result);
    }
}

#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error("multicast server wrapper only supports server connections")]
    ClientConnectionUnsupported,

    #[error("multicast publication failed: {0}")]
    Publication(#[from] MctxError),

    #[error("{0} multicast runtime queue exhausted")]
    RuntimeQueueExhausted(&'static str),

    #[error("multicast control queue made no progress for {0:?}")]
    ControlBackpressureTimeout(Duration),

    #[error(
        "multicast runtime exhausted its connection-lifetime Channel ID limit of {0}"
    )]
    TrackedChannelIdLimit(usize),
}

#[derive(Debug)]
enum ServerControlCommand {
    UpsertChannel {
        config: ServerControlChannelConfig,
    },
    SendAnnounce {
        frame: quiche::multicast::Announce,
        cached: Option<quiche::multicast::Announce>,
    },
    SendKey {
        frame: quiche::multicast::Key,
        cached: Option<quiche::multicast::Key>,
    },
    SendJoin {
        frame: quiche::multicast::Join,
    },
    SendLeave {
        frame: quiche::multicast::Leave,
    },
    AutomaticAnnounce {
        announce: Option<quiche::multicast::Announce>,
        key: quiche::multicast::Key,
        generation: u64,
    },
    RelayIntegrity {
        frame: quiche::multicast::Integrity,
    },
    AttachStreamPublisher {
        config: ServerControlChannelConfig,
        reordering_threshold: u64,
        max_stream_id: Option<u64>,
        delivery_metrics:
            Arc<server_stream::ServerStreamDeliveryMetricsAccumulator>,
        publication_queue: Arc<server_stream::ServerStreamPublisherQueue>,
    },
    StreamPublisherQueueReady {
        publication_queue: Arc<server_stream::ServerStreamPublisherQueue>,
    },
    DetachStreamPublisher {
        publication_queue: Arc<server_stream::ServerStreamPublisherQueue>,
    },
    StreamPublication {
        publication: Arc<server_stream::CommittedServerStreamPublication>,
    },
    StreamPublisherKey {
        frame: quiche::multicast::Key,
        cached: Option<quiche::multicast::Key>,
    },
    StreamPublisherMaxStreamId {
        channel_id: Vec<u8>,
        max_stream_id: u64,
    },
    StreamPublisherRetire {
        frame: quiche::multicast::Retire,
    },
    RetireForLimits {
        channel_id: Vec<u8>,
        generation: u64,
    },
}

impl RetainedSize for ServerControlCommand {
    fn retained_size(&self) -> usize {
        match self {
            Self::UpsertChannel { config } |
            Self::AttachStreamPublisher { config, .. } =>
                control_config_retained_size(config).saturating_add(256),

            Self::SendAnnounce { frame, cached } => announce_retained_size(frame)
                .saturating_add(cached.as_ref().map_or(0, announce_retained_size))
                .saturating_add(128),

            Self::SendKey { frame, cached } => key_retained_size(frame)
                .saturating_add(cached.as_ref().map_or(0, key_retained_size))
                .saturating_add(128),

            Self::StreamPublisherKey { frame, cached } =>
                key_retained_size(frame)
                    .saturating_add(cached.as_ref().map_or(0, key_retained_size))
                    .saturating_add(128),

            Self::SendJoin { frame } =>
                frame.channel_id.len().saturating_add(128),

            Self::SendLeave { frame } =>
                frame.channel_id.len().saturating_add(128),

            Self::AutomaticAnnounce { announce, key, .. } => announce
                .as_ref()
                .map_or(0, announce_retained_size)
                .saturating_add(key_retained_size(key))
                .saturating_add(192),

            Self::RelayIntegrity { frame } =>
                integrity_retained_size(frame).saturating_add(128),

            Self::StreamPublication { publication } => publication
                .frame
                .data
                .len()
                .saturating_add(integrity_retained_size(&publication.integrity))
                .saturating_add(256),

            Self::StreamPublisherMaxStreamId { channel_id, .. } =>
                channel_id.len().saturating_add(128),

            Self::StreamPublisherRetire { frame } =>
                frame.channel_id.len().saturating_add(128),

            Self::RetireForLimits { channel_id, .. } =>
                channel_id.len().saturating_add(128),

            Self::StreamPublisherQueueReady { .. } |
            Self::DetachStreamPublisher { .. } => 128,
        }
    }
}

impl ServerControlCommand {
    fn channel_id(&self) -> &[u8] {
        match self {
            Self::UpsertChannel { config } |
            Self::AttachStreamPublisher { config, .. } =>
                &config.announce.channel_id,

            Self::SendAnnounce { frame, .. } => &frame.channel_id,

            Self::SendKey { frame, .. } |
            Self::StreamPublisherKey { frame, .. } => &frame.channel_id,

            Self::SendJoin { frame } => &frame.channel_id,

            Self::SendLeave { frame } => &frame.channel_id,

            Self::AutomaticAnnounce { announce, key, .. } => announce
                .as_ref()
                .map_or(key.channel_id.as_slice(), |frame| {
                    frame.channel_id.as_slice()
                }),

            Self::RelayIntegrity { frame } => &frame.channel_id,

            Self::StreamPublisherQueueReady { publication_queue } |
            Self::DetachStreamPublisher { publication_queue } =>
                publication_queue.channel_id(),

            Self::StreamPublication { publication } =>
                &publication.integrity.channel_id,

            Self::StreamPublisherMaxStreamId { channel_id, .. } => channel_id,

            Self::StreamPublisherRetire { frame } => &frame.channel_id,

            Self::RetireForLimits { channel_id, .. } => channel_id,
        }
    }
}

struct PendingServerControlCommand {
    command: Queued<ServerControlCommand>,
    deferred_barrier: bool,
    blocked_since: Option<Instant>,
}

enum ControlSendOutcome {
    Sent,
    Full(quiche::multicast::Frame),
}

impl PendingServerControlCommand {
    fn regular(command: Queued<ServerControlCommand>) -> Self {
        Self {
            command,
            deferred_barrier: false,
            blocked_since: None,
        }
    }

    fn record_full(&mut self, now: Instant) {
        self.blocked_since.get_or_insert(now);
    }

    fn made_progress(&mut self) {
        self.blocked_since = None;
    }
}

impl RetainedSize for quiche::multicast::Integrity {
    fn retained_size(&self) -> usize {
        integrity_retained_size(self)
    }
}

impl RetainedSize for Arc<server_stream::CommittedServerStreamPublication> {
    fn retained_size(&self) -> usize {
        self.frame
            .data
            .len()
            .saturating_add(integrity_retained_size(&self.integrity))
            .saturating_add(128)
    }
}

fn announce_retained_size(frame: &quiche::multicast::Announce) -> usize {
    frame
        .channel_id
        .len()
        .saturating_add(frame.header_secret.len())
        .saturating_add(128)
}

fn key_retained_size(frame: &quiche::multicast::Key) -> usize {
    frame
        .channel_id
        .len()
        .saturating_add(frame.secret.len())
        .saturating_add(96)
}

fn integrity_retained_size(frame: &quiche::multicast::Integrity) -> usize {
    frame
        .channel_id
        .len()
        .saturating_add(frame.packet_hashes.len())
        .saturating_add(96)
}

fn control_config_retained_size(config: &ServerControlChannelConfig) -> usize {
    announce_retained_size(&config.announce)
        .saturating_add(key_retained_size(&config.key))
}

#[derive(Default)]
struct ServerControlChannel {
    announce: Option<quiche::multicast::Announce>,
    key: Option<quiche::multicast::Key>,
    announce_sent: bool,
    announce_pending: bool,
    join_sent: bool,
    join_pending: bool,
    leave_pending: bool,
    join_blocked_by_client: bool,
    stream_publisher: bool,
    max_stream_id: Option<u64>,
    largest_stream_packet_number: Option<u64>,
    stream_delivery_metrics: Option<ConnectionStreamDeliveryMetrics>,
    stream_publication_queue:
        Option<Arc<server_stream::ServerStreamPublisherQueue>>,
    last_client_state_sequence: u64,
    retired: bool,
    retirement_pending: bool,
    generation: u64,
}

struct ConnectionStreamDeliveryMetrics {
    accumulator: Arc<server_stream::ServerStreamDeliveryMetricsAccumulator>,
    baseline: quiche::multicast::StreamDeliveryMetricsSnapshot,
}

struct PendingStreamIntegrityBatch {
    frame: quiche::multicast::Integrity,
    hash_len: usize,
    deadline: Instant,
}

impl RetainedSize for PendingStreamIntegrityBatch {
    fn retained_size(&self) -> usize {
        integrity_retained_size(&self.frame).saturating_add(64)
    }
}

struct PendingIntegrityFrames {
    queues: BTreeMap<Vec<u8>, VecDeque<Queued<quiche::multicast::Integrity>>>,
    ready: VecDeque<Vec<u8>>,
    ready_set: BTreeSet<Vec<u8>>,
    budget: RetainedQueueBudget<quiche::multicast::Integrity>,
    observer: RetainedQueueObserver,
}

impl PendingIntegrityFrames {
    fn new(limits: RetainedQueueLimits) -> Self {
        let (budget, observer) = retained_queue_budget(limits);
        Self {
            queues: BTreeMap::new(),
            ready: VecDeque::new(),
            ready_set: BTreeSet::new(),
            budget,
            observer,
        }
    }

    fn push_back(
        &mut self, frame: quiche::multicast::Integrity,
    ) -> Result<(), quiche::multicast::Integrity> {
        self.push(frame, false)
    }

    fn push_front(
        &mut self, frame: quiche::multicast::Integrity,
    ) -> Result<(), quiche::multicast::Integrity> {
        self.push(frame, true)
    }

    fn push(
        &mut self, frame: quiche::multicast::Integrity, front: bool,
    ) -> Result<(), quiche::multicast::Integrity> {
        let frame = self
            .budget
            .wrap(frame)
            .map_err(|error| error.into_inner())?;
        let channel_id = frame.as_ref().channel_id.clone();
        let queue = self.queues.entry(channel_id.clone()).or_default();
        if front {
            queue.push_front(frame);
        } else {
            queue.push_back(frame);
        }
        self.schedule(channel_id);
        Ok(())
    }

    fn pop_next(&mut self) -> Option<quiche::multicast::Integrity> {
        while let Some(channel_id) = self.ready.pop_front() {
            self.ready_set.remove(&channel_id);
            if let Some(frame) = self.pop_channel_inner(&channel_id) {
                return Some(frame);
            }
        }

        None
    }

    #[cfg(test)]
    fn pop_front(&mut self) -> Option<quiche::multicast::Integrity> {
        self.pop_next()
    }

    fn pop_channel_inner(
        &mut self, channel_id: &[u8],
    ) -> Option<quiche::multicast::Integrity> {
        let (frame, empty) = {
            let queue = self.queues.get_mut(channel_id)?;
            let frame = queue.pop_front()?;
            (frame, queue.is_empty())
        };
        if empty {
            self.queues.remove(channel_id);
        } else {
            self.schedule(channel_id.to_vec());
        }
        Some(frame.into_inner())
    }

    fn schedule(&mut self, channel_id: Vec<u8>) {
        if self.ready_set.insert(channel_id.clone()) {
            self.ready.push_back(channel_id);
        }
    }

    fn contains_channel(&self, channel_id: &[u8]) -> bool {
        self.queues.contains_key(channel_id)
    }

    fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    fn clear(&mut self) {
        self.queues.clear();
        self.ready.clear();
        self.ready_set.clear();
    }

    fn observer(&self) -> RetainedQueueObserver {
        self.observer.clone()
    }

    fn batch_budget(&self) -> RetainedQueueBudget<PendingStreamIntegrityBatch> {
        self.budget.cast()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PendingStreamKey {
    channel_id: Vec<u8>,
    stream_id: u64,
}

struct PendingStreamPublications {
    queues: BTreeMap<
        PendingStreamKey,
        VecDeque<Queued<Arc<server_stream::CommittedServerStreamPublication>>>,
    >,
    ready: VecDeque<PendingStreamKey>,
    ready_set: BTreeSet<PendingStreamKey>,
    blocked: BTreeSet<PendingStreamKey>,
    budget:
        RetainedQueueBudget<Arc<server_stream::CommittedServerStreamPublication>>,
    observer: RetainedQueueObserver,
}

impl PendingStreamPublications {
    fn new(limits: RetainedQueueLimits) -> Self {
        let (budget, observer) = retained_queue_budget(limits);
        Self {
            queues: BTreeMap::new(),
            ready: VecDeque::new(),
            ready_set: BTreeSet::new(),
            blocked: BTreeSet::new(),
            budget,
            observer,
        }
    }

    fn push(
        &mut self,
        publication: Arc<server_stream::CommittedServerStreamPublication>,
    ) -> Result<(), ()> {
        let publication = self.budget.wrap(publication).map_err(|_| ())?;
        let key = PendingStreamKey {
            channel_id: publication.as_ref().integrity.channel_id.clone(),
            stream_id: publication.as_ref().frame.stream_id,
        };
        self.queues
            .entry(key.clone())
            .or_default()
            .push_back(publication);
        self.schedule(key);
        Ok(())
    }

    fn schedule(&mut self, key: PendingStreamKey) {
        if self.ready_set.insert(key.clone()) {
            self.ready.push_back(key);
        }
    }

    fn begin_pass(&mut self) {
        self.blocked.clear();
    }

    fn next_ready(&mut self) -> Option<PendingStreamKey> {
        let candidates = self.ready.len();
        for _ in 0..candidates {
            let key = self.ready.pop_front()?;
            self.ready_set.remove(&key);
            if self.blocked.contains(&key) {
                self.schedule(key);
                continue;
            }

            return Some(key);
        }

        None
    }

    fn front(
        &self, key: &PendingStreamKey,
    ) -> Option<&Arc<server_stream::CommittedServerStreamPublication>> {
        self.queues
            .get(key)
            .and_then(|queue| queue.front())
            .map(Queued::as_ref)
    }

    fn complete_front(&mut self, key: PendingStreamKey) {
        let mut remove_queue = false;
        if let Some(queue) = self.queues.get_mut(&key) {
            queue.pop_front();
            remove_queue = queue.is_empty();
        }

        if remove_queue {
            self.queues.remove(&key);
            self.blocked.remove(&key);
        } else {
            self.schedule(key);
        }
    }

    fn block(&mut self, key: PendingStreamKey) {
        self.blocked.insert(key.clone());
        self.schedule(key);
    }

    fn contains_channel(&self, channel_id: &[u8]) -> bool {
        self.queues
            .keys()
            .any(|key| key.channel_id.as_slice() == channel_id)
    }

    fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.observer.stats().retained_items
    }

    fn is_retry_blocked(&self) -> bool {
        !self.queues.is_empty() && self.blocked.len() == self.queues.len()
    }

    fn clear(&mut self) {
        self.queues.clear();
        self.ready.clear();
        self.ready_set.clear();
        self.blocked.clear();
    }

    fn observer(&self) -> RetainedQueueObserver {
        self.observer.clone()
    }
}

struct ServerControlRuntime {
    settings: ServerControlSettings,
    limits: RuntimeLimits,
    event_sender: ManagedEventSender<ServerEvent>,
    command_receiver: BoundedReceiver<ServerControlCommand>,
    command_budget: RetainedQueueBudget<ServerControlCommand>,
    pending_commands: VecDeque<PendingServerControlCommand>,
    blocked_command_channels: BTreeSet<Vec<u8>>,
    pending_stream_publications: PendingStreamPublications,
    pending_integrities: PendingIntegrityFrames,
    pending_stream_integrity_batches:
        BTreeMap<Vec<u8>, Queued<PendingStreamIntegrityBatch>>,
    pending_stream_integrity_batch_budget:
        RetainedQueueBudget<PendingStreamIntegrityBatch>,
    control_read_pending: bool,
    probe_read_pending: bool,
    integrity_retry_blocked: bool,
    control_retry_deadline: Option<Instant>,
    channels: BTreeMap<Vec<u8>, ServerControlChannel>,
    publisher_stage_cursor: Option<Vec<u8>>,
    integrity_stage_cursor: Option<Vec<u8>>,
    stream_metric_fold_cursor: Option<Vec<u8>>,
    read_work_cursor: usize,
    write_work_cursor: usize,
    last_client_limits: Option<quiche::multicast::Limits>,
    event_coalescer: ServerEventCoalescer,
    #[cfg(test)]
    stream_delivery_metric_fold_attempts: u64,
    #[cfg(test)]
    stream_publication_registrations: u64,
    #[cfg(test)]
    callback_read_work_last_call: usize,
    #[cfg(test)]
    callback_write_work_last_call: usize,
}

impl ServerControlRuntime {
    #[cfg(test)]
    fn new(
        settings: ServerControlSettings,
        event_sender: ManagedEventSender<ServerEvent>,
        command_receiver: BoundedReceiver<ServerControlCommand>,
    ) -> Self {
        Self::with_limits(
            settings,
            event_sender,
            command_receiver,
            RuntimeLimits::default(),
        )
    }

    fn with_limits(
        settings: ServerControlSettings,
        event_sender: ManagedEventSender<ServerEvent>,
        command_receiver: BoundedReceiver<ServerControlCommand>,
        limits: RuntimeLimits,
    ) -> Self {
        let command_budget = command_receiver.budget();
        let pending_integrities =
            PendingIntegrityFrames::new(limits.pending_integrity);
        let pending_stream_integrity_batch_budget =
            pending_integrities.batch_budget();
        Self {
            settings,
            limits,
            event_sender,
            command_receiver,
            command_budget,
            pending_commands: VecDeque::new(),
            blocked_command_channels: BTreeSet::new(),
            pending_stream_publications: PendingStreamPublications::new(
                limits.pending_publications,
            ),
            pending_integrities,
            pending_stream_integrity_batches: BTreeMap::new(),
            pending_stream_integrity_batch_budget,
            control_read_pending: false,
            probe_read_pending: false,
            integrity_retry_blocked: false,
            control_retry_deadline: None,
            channels: BTreeMap::new(),
            publisher_stage_cursor: None,
            integrity_stage_cursor: None,
            stream_metric_fold_cursor: None,
            read_work_cursor: 0,
            write_work_cursor: 0,
            last_client_limits: None,
            event_coalescer: ServerEventCoalescer::default(),
            #[cfg(test)]
            stream_delivery_metric_fold_attempts: 0,
            #[cfg(test)]
            stream_publication_registrations: 0,
            #[cfg(test)]
            callback_read_work_last_call: 0,
            #[cfg(test)]
            callback_write_work_last_call: 0,
        }
    }

    fn clear(&mut self) {
        self.command_receiver.close();
        for channel in self.channels.values_mut() {
            if let Some(queue) = channel.stream_publication_queue.take() {
                queue.close();
            }
        }
        self.pending_commands.clear();
        self.blocked_command_channels.clear();
        self.pending_stream_publications.clear();
        self.pending_integrities.clear();
        self.pending_stream_integrity_batches.clear();
        self.control_read_pending = false;
        self.probe_read_pending = false;
        self.integrity_retry_blocked = false;
        self.control_retry_deadline = None;
        self.channels.clear();
        self.publisher_stage_cursor = None;
        self.integrity_stage_cursor = None;
        self.stream_metric_fold_cursor = None;
        self.read_work_cursor = 0;
        self.write_work_cursor = 0;
        self.last_client_limits = None;
        self.event_coalescer.clear();

        while self.command_receiver.try_recv().is_ok() {}
    }

    fn on_conn_close(&mut self, qconn: &QuicheConnection) {
        self.fold_final_stream_delivery_metrics(qconn);
        self.clear();
        self.event_sender.finish();
    }

    fn has_pending_work(&self) -> bool {
        let now = Instant::now();
        let control_retry_ready = self
            .control_retry_deadline
            .is_none_or(|deadline| deadline <= now);
        let runnable_command = self.pending_commands.iter().any(|pending| {
            if !self
                .blocked_command_channels
                .contains(pending.command.as_ref().channel_id())
            {
                return true;
            }

            pending.deferred_barrier &&
                (pending.blocked_since.is_none() || control_retry_ready)
        });
        let unblocked_publication = !self.pending_stream_publications.is_empty() &&
            !self.pending_stream_publications.is_retry_blocked();
        let integrity_deadline_elapsed = self
            .next_stream_integrity_deadline()
            .is_some_and(|deadline| deadline <= now);
        let publisher_queue_pending =
            self.channels.iter().any(|(channel_id, channel)| {
                !self.blocked_command_channels.contains(channel_id) &&
                    channel
                        .stream_publication_queue
                        .as_ref()
                        .is_some_and(|queue| queue.has_pending())
            });

        self.control_read_pending ||
            self.probe_read_pending ||
            self.event_coalescer.has_pending_client_acks() ||
            runnable_command ||
            unblocked_publication ||
            publisher_queue_pending ||
            (!self.pending_integrities.is_empty() &&
                !self.integrity_retry_blocked) ||
            integrity_deadline_elapsed
    }

    async fn wait_for_work(&mut self) -> QuicResult<()> {
        if let Some(deadline) = self.next_runtime_deadline() {
            select! {
                command = self.command_receiver.recv() => {
                    match command {
                        Some(command) => {
                            self.pending_commands.push_back(
                                PendingServerControlCommand::regular(command),
                            );
                            Ok(())
                        },

                        None => {
                            sleep_until(deadline).await;
                            Ok(())
                        },
                    }
                },

                _ = sleep_until(deadline) => Ok(()),
            }
        } else {
            match self.command_receiver.recv().await {
                Some(command) => {
                    self.pending_commands
                        .push_back(PendingServerControlCommand::regular(command));
                    Ok(())
                },

                None => {
                    #[allow(unreachable_code)]
                    {
                        pending::<()>().await;
                        Ok(())
                    }
                },
            }
        }
    }

    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if !qconn.is_server() {
            return Err(Box::new(ServerError::ClientConnectionUnsupported));
        }

        self.initialize_channels(qconn)?;
        if self.pending_commands.iter().all(|pending| {
            match pending.command.as_ref() {
                ServerControlCommand::AutomaticAnnounce { .. } |
                ServerControlCommand::SendJoin { .. } => true,

                ServerControlCommand::SendLeave { frame } => self
                    .channels
                    .get(&frame.channel_id)
                    .is_none_or(|channel| !channel.stream_publisher),

                _ => false,
            }
        }) {
            self.handle_pending_commands(qconn)?;
        }
        self.probe_read_pending = qconn.is_multicast_probe_readable();

        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.control_retry_deadline = None;
        self.integrity_retry_blocked = false;
        self.pending_stream_publications.begin_pass();
        let now = Instant::now();
        let mut cursor = self.read_work_cursor;
        let work = run_callback_work(
            self.limits.max_work_per_call,
            &mut cursor,
            10,
            |class| match class {
                0 => self.process_one_control_frame(qconn),
                1 => self
                    .event_coalescer
                    .flush_client_acks(&self.event_sender, 1)
                    .map(|work| work > 0)
                    .map_err(Into::into),
                2 => Ok(self.transfer_one_server_control_command()),
                3 => self.stage_one_stream_publisher_queue_item(),
                4 => self.handle_one_pending_command(qconn),
                5 => self.flush_one_pending_stream_publication(qconn),
                6 => self.stage_one_due_stream_integrity(now),
                7 => self.flush_one_pending_integrity(qconn),
                8 => Ok(self.fold_one_dirty_stream_delivery_metric(qconn)),
                9 => self.forward_one_probe_event(qconn),
                _ => unreachable!("server-control read work class is in range"),
            },
        )?;
        self.read_work_cursor = cursor;
        self.control_read_pending = qconn.is_multicast_readable();
        self.probe_read_pending = qconn.is_multicast_probe_readable();

        #[cfg(test)]
        {
            self.callback_read_work_last_call = work;
        }

        debug_assert!(work <= self.limits.max_work_per_call);
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.pending_stream_publications.begin_pass();
        if self
            .control_retry_deadline
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            self.control_retry_deadline = None;
        }
        let now = Instant::now();
        let mut cursor = self.write_work_cursor;
        let work = run_callback_work(
            self.limits.max_work_per_call,
            &mut cursor,
            8,
            |class| match class {
                0 => Ok(self.transfer_one_server_control_command()),
                1 => self.stage_one_stream_publisher_queue_item(),
                2 => self.handle_one_pending_command(qconn),
                3 => self.flush_one_pending_stream_publication(qconn),
                4 => self.stage_one_due_stream_integrity(now),
                5 => self.flush_one_pending_integrity(qconn),
                6 => Ok(self.fold_one_dirty_stream_delivery_metric(qconn)),
                7 => self.forward_one_probe_event(qconn),
                _ => unreachable!("server-control write work class is in range"),
            },
        )?;
        self.write_work_cursor = cursor;
        self.probe_read_pending = qconn.is_multicast_probe_readable();

        #[cfg(test)]
        {
            self.callback_write_work_last_call = work;
        }

        debug_assert!(work <= self.limits.max_work_per_call);
        Ok(())
    }

    fn transfer_one_server_control_command(&mut self) -> bool {
        let Ok(command) = self.command_receiver.try_recv() else {
            return false;
        };
        self.pending_commands
            .push_back(PendingServerControlCommand::regular(command));
        true
    }

    fn process_one_control_frame(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        match qconn.multicast_recv() {
            Ok(frame) => {
                self.handle_frame(qconn, frame)?;
                Ok(true)
            },

            Err(quiche::Error::Done) => {
                self.control_read_pending = false;
                Ok(false)
            },

            Err(err) => Err(err.into()),
        }
    }

    fn fold_stream_delivery_metrics_snapshot(
        &mut self, channel_id: &[u8],
        snapshot: quiche::multicast::StreamDeliveryMetricsSnapshot,
    ) {
        #[cfg(test)]
        if self
            .channels
            .get(channel_id)
            .is_some_and(|channel| channel.stream_delivery_metrics.is_some())
        {
            self.stream_delivery_metric_fold_attempts =
                self.stream_delivery_metric_fold_attempts.saturating_add(1);
        }

        let Some(metrics) = self
            .channels
            .get_mut(channel_id)
            .and_then(|channel| channel.stream_delivery_metrics.as_mut())
        else {
            return;
        };

        metrics.accumulator.add(
            quiche::multicast::StreamDeliveryMetricsDelta::between(
                metrics.baseline,
                snapshot,
            ),
        );
        metrics.baseline = snapshot;
    }

    fn fold_one_dirty_stream_delivery_metric(
        &mut self, qconn: &mut QuicheConnection,
    ) -> bool {
        let Some((channel_id, snapshot)) = qconn
            .multicast_stream_take_next_delivery_metric_update(
                self.stream_metric_fold_cursor.as_deref(),
            )
        else {
            return false;
        };
        self.stream_metric_fold_cursor = Some(channel_id.clone());
        self.fold_stream_delivery_metrics_snapshot(&channel_id, snapshot);
        true
    }

    fn fold_final_stream_delivery_metrics(&mut self, qconn: &QuicheConnection) {
        for (channel_id, channel) in &mut self.channels {
            let Some(metrics) = channel.stream_delivery_metrics.as_mut() else {
                continue;
            };
            #[cfg(test)]
            {
                self.stream_delivery_metric_fold_attempts =
                    self.stream_delivery_metric_fold_attempts.saturating_add(1);
            }
            let snapshot =
                qconn.multicast_stream_delivery_metrics_snapshot(channel_id);
            metrics.accumulator.add(
                quiche::multicast::StreamDeliveryMetricsDelta::between(
                    metrics.baseline,
                    snapshot,
                ),
            );
            metrics.baseline = snapshot;
        }
    }

    fn stop_stream_publisher(
        &mut self, qconn: &mut QuicheConnection, channel_id: &[u8],
    ) -> QuicResult<()> {
        if let Some(snapshot) = qconn.multicast_stream_stop_channel(channel_id)? {
            self.fold_stream_delivery_metrics_snapshot(channel_id, snapshot);
        }

        if let Some(channel) = self.channels.get_mut(channel_id) {
            channel.stream_publisher = false;
            channel.stream_delivery_metrics = None;
            if let Some(queue) = channel.stream_publication_queue.take() {
                queue.close();
            }
        }

        Ok(())
    }

    fn forward_one_probe_event(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        match qconn.multicast_probe_recv() {
            Ok(event) => {
                self.event_coalescer
                    .forward_probe_event(&self.event_sender, event)?;
                Ok(true)
            },

            Err(quiche::Error::Done) => {
                self.probe_read_pending = false;
                Ok(false)
            },

            Err(err) => Err(err.into()),
        }
    }

    fn initialize_channels(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        let auto_send = self.settings.mode == ServerControlMode::Automatic &&
            self.peer_supports_multicast(qconn);
        let channels = self.settings.channels.clone();

        for config in channels {
            self.upsert_channel_config(qconn, config, auto_send, true)?;
        }

        Ok(())
    }

    fn handle_frame(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Frame,
    ) -> QuicResult<()> {
        match frame {
            quiche::multicast::Frame::Limits(frame) => {
                self.handle_limits(qconn, frame)?;
            },

            quiche::multicast::Frame::State(frame) => {
                let retired =
                    frame.state == quiche::multicast::ChannelState::Retired;
                if let Some(channel) = self.channels.get_mut(&frame.channel_id) {
                    channel.last_client_state_sequence = frame.sequence;
                    match frame.state {
                        quiche::multicast::ChannelState::Joined => {
                            channel.leave_pending = false;
                            channel.join_blocked_by_client = false;
                        },

                        quiche::multicast::ChannelState::DeclinedJoin |
                        quiche::multicast::ChannelState::Left => {
                            channel.join_sent = false;
                            channel.join_pending = false;
                            channel.leave_pending = false;
                            channel.join_blocked_by_client = true;
                        },

                        quiche::multicast::ChannelState::Retired => {
                            channel.announce_sent = false;
                            channel.announce_pending = false;
                            channel.join_sent = false;
                            channel.join_pending = false;
                            channel.leave_pending = false;
                            channel.join_blocked_by_client = true;
                            channel.retired = true;
                            channel.retirement_pending = false;
                        },
                    }
                }
                if retired {
                    self.event_coalescer.reset_channel(&frame.channel_id);
                }
                self.event_sender
                    .try_send(ServerEvent::ClientState(frame))?;
            },

            quiche::multicast::Frame::Ack(frame) => {
                if self.channels.contains_key(&frame.channel_id) {
                    qconn.multicast_process_peer_ack(frame.clone())?;
                    self.event_coalescer
                        .queue_client_ack(&self.event_sender, frame);
                } else {
                    self.event_sender.try_send(ServerEvent::ClientAck(frame))?;
                }
            },

            quiche::multicast::Frame::Announce(..) |
            quiche::multicast::Frame::Key(..) |
            quiche::multicast::Frame::Join(..) |
            quiche::multicast::Frame::Leave(..) |
            quiche::multicast::Frame::Integrity(..) |
            quiche::multicast::Frame::Retire(..) => (),
        }

        Ok(())
    }

    fn handle_limits(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Limits,
    ) -> QuicResult<()> {
        if self
            .last_client_limits
            .as_ref()
            .is_some_and(|current| frame.sequence <= current.sequence)
        {
            return Ok(());
        }

        self.last_client_limits = Some(frame.clone());
        self.event_sender
            .try_send(ServerEvent::ClientLimits(frame))?;

        if self.settings.mode != ServerControlMode::Automatic {
            return Ok(());
        }

        for channel in self.channels.values_mut() {
            if !channel.retired && !channel.retirement_pending {
                channel.join_blocked_by_client = false;
            }
        }

        self.enforce_client_channel_id_limit(qconn)?;
        self.enforce_client_join_limits(qconn)?;

        let channel_ids = self.channels.keys().cloned().collect::<Vec<_>>();

        for channel_id in channel_ids {
            self.maybe_auto_announce_channel(qconn, &channel_id)?;
            self.maybe_auto_join_channel(qconn, &channel_id)?;
        }

        Ok(())
    }

    fn enforce_client_channel_id_limit(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        let Some(max_channel_ids) = self
            .last_client_limits
            .as_ref()
            .map(|limits| limits.limits.max_channel_ids)
        else {
            return Ok(());
        };
        let announced = self
            .channels
            .iter()
            .filter(|(_, channel)| channel.announce_sent)
            .map(|(channel_id, _)| channel_id.clone())
            .collect::<Vec<_>>();
        let retained_count =
            usize::try_from(max_channel_ids).unwrap_or(usize::MAX);

        for channel_id in announced.into_iter().skip(retained_count) {
            self.retire_channel_for_limits(qconn, &channel_id)?;
        }

        Ok(())
    }

    fn retire_channel_for_limits(
        &mut self, _qconn: &mut QuicheConnection, channel_id: &[u8],
    ) -> QuicResult<()> {
        let Some(channel) = self.channels.get_mut(channel_id) else {
            return Ok(());
        };
        if channel.retired || channel.retirement_pending {
            return Ok(());
        }

        channel.join_blocked_by_client = true;
        channel.retirement_pending = true;
        let publication_queue = channel.stream_publication_queue.clone();
        let generation = channel.generation;

        if let Some(publication_queue) = publication_queue {
            publication_queue.seal();
            publication_queue.claim_detach();
        }

        self.queue_command_back(ServerControlCommand::RetireForLimits {
            channel_id: channel_id.to_vec(),
            generation,
        })
    }

    fn enforce_client_join_limits(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        let Some(limits) = self.last_client_limits.clone() else {
            return Ok(());
        };
        let joined = self
            .channels
            .iter()
            .filter(|(_, channel)| {
                channel.join_sent && !channel.retirement_pending
            })
            .map(|(channel_id, _)| channel_id.clone())
            .collect::<Vec<_>>();
        let mut retained_count = 0_u64;
        let mut retained_rate = 0_u64;

        for channel_id in joined {
            let Some(channel) = self.channels.get(&channel_id) else {
                continue;
            };
            let Some(announce) = channel.announce.as_ref() else {
                continue;
            };
            let stream_limit_ok = !channel.stream_publisher ||
                channel.max_stream_id.is_some_and(|stream_id| {
                    Self::stream_id_within_peer_limit(qconn, stream_id)
                });
            let permitted = Self::announce_matches_client_capabilities(
                qconn,
                &limits.limits,
                announce,
            ) && stream_limit_ok &&
                retained_count < limits.max_joined_count &&
                retained_count < limits.limits.max_channel_ids &&
                retained_rate.saturating_add(announce.max_rate_kibps) <=
                    limits.limits.max_aggregate_rate_kibps;

            if permitted {
                retained_count = retained_count.saturating_add(1);
                retained_rate =
                    retained_rate.saturating_add(announce.max_rate_kibps);
                continue;
            }

            let after_packet_number =
                channel.largest_stream_packet_number.unwrap_or(0);
            self.leave_channel(qconn, &channel_id, after_packet_number)?;
        }

        Ok(())
    }

    fn handle_pending_commands(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        self.handle_pending_commands_with_limit(
            qconn,
            self.limits.max_work_per_call,
        )
        .map(|_| ())
    }

    fn handle_one_pending_command(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.handle_pending_commands_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    fn handle_pending_commands_with_limit(
        &mut self, qconn: &mut QuicheConnection, max_work: usize,
    ) -> QuicResult<usize> {
        let mut work = 0;
        for _ in 0..max_work {
            let Some(mut pending) = self.pending_commands.pop_front() else {
                break;
            };
            work += 1;
            let channel_id = pending.command.as_ref().channel_id().to_vec();
            let channel_blocked =
                self.blocked_command_channels.contains(&channel_id);
            let retry_waiting = channel_blocked &&
                pending.deferred_barrier &&
                pending.blocked_since.is_some() &&
                self.control_retry_deadline
                    .is_some_and(|deadline| deadline > Instant::now());
            if (channel_blocked && !pending.deferred_barrier) || retry_waiting {
                self.pending_commands.push_back(pending);
                continue;
            }
            if pending.deferred_barrier {
                self.blocked_command_channels.remove(&channel_id);
            }

            let command = pending.command.take();
            match command {
                ServerControlCommand::UpsertChannel { config } => {
                    let auto_send = self.settings.mode ==
                        ServerControlMode::Automatic &&
                        self.peer_supports_multicast(qconn);
                    self.upsert_channel_config(qconn, config, auto_send, true)?;
                },

                ServerControlCommand::SendAnnounce { frame, cached } => {
                    self.ensure_channel_capacity(&frame.channel_id)?;
                    let cached = cached.unwrap_or_else(|| frame.clone());
                    match Self::try_send_control(
                        qconn,
                        quiche::multicast::Frame::Announce(frame),
                    )? {
                        ControlSendOutcome::Sent => (),

                        ControlSendOutcome::Full(
                            quiche::multicast::Frame::Announce(frame),
                        ) => {
                            self.retry_control_command(
                                pending,
                                ServerControlCommand::SendAnnounce {
                                    frame,
                                    cached: Some(cached),
                                },
                            )?;
                            break;
                        },

                        ControlSendOutcome::Full(_) =>
                            unreachable!("core returned another frame"),
                    }
                    if self.channels.contains_key(&cached.channel_id) ||
                        qconn
                            .multicast_probe_status(&cached.channel_id)
                            .is_some()
                    {
                        self.event_coalescer.reset_channel(&cached.channel_id);
                        qconn.multicast_probe_reset(&cached.channel_id)?;
                    }
                    Self::set_default_dgram_channel_if_unset(
                        qconn,
                        &cached.channel_id,
                    )?;
                    Self::set_ack_timeout(
                        qconn,
                        &cached.channel_id,
                        cached.max_ack_delay_ms,
                    )?;
                    let channel = self
                        .channels
                        .entry(cached.channel_id.clone())
                        .or_default();
                    channel.announce = Some(cached);
                    channel.announce_sent = true;
                    channel.announce_pending = false;
                    channel.join_sent = false;
                    channel.join_pending = false;
                    channel.leave_pending = false;
                },

                ServerControlCommand::SendKey { frame, cached } => {
                    self.ensure_channel_capacity(&frame.channel_id)?;
                    if !self.prepare_channel_barrier(qconn, &frame.channel_id)? {
                        self.defer_pending_barrier(
                            pending,
                            ServerControlCommand::SendKey { frame, cached },
                        );
                        continue;
                    }
                    let cached = cached.unwrap_or_else(|| frame.clone());
                    match Self::try_send_control(
                        qconn,
                        quiche::multicast::Frame::Key(frame),
                    )? {
                        ControlSendOutcome::Sent => (),

                        ControlSendOutcome::Full(
                            quiche::multicast::Frame::Key(frame),
                        ) => {
                            self.retry_control_command(
                                pending,
                                ServerControlCommand::SendKey {
                                    frame,
                                    cached: Some(cached),
                                },
                            )?;
                            break;
                        },

                        ControlSendOutcome::Full(_) =>
                            unreachable!("core returned another frame"),
                    }
                    Self::set_default_dgram_channel_if_unset(
                        qconn,
                        &cached.channel_id,
                    )?;
                    let channel = self
                        .channels
                        .entry(cached.channel_id.clone())
                        .or_default();
                    channel.key = Some(cached);
                },

                ServerControlCommand::SendJoin { frame } => {
                    self.ensure_channel_capacity(&frame.channel_id)?;
                    let channel_id = frame.channel_id.clone();
                    match Self::try_send_control(
                        qconn,
                        quiche::multicast::Frame::Join(frame),
                    )? {
                        ControlSendOutcome::Sent => (),

                        ControlSendOutcome::Full(
                            quiche::multicast::Frame::Join(frame),
                        ) => {
                            self.retry_control_command(
                                pending,
                                ServerControlCommand::SendJoin { frame },
                            )?;
                            break;
                        },

                        ControlSendOutcome::Full(_) =>
                            unreachable!("core returned another frame"),
                    }
                    self.event_coalescer.reset_channel(&channel_id);
                    qconn.multicast_probe_reset(&channel_id)?;
                    Self::set_default_dgram_channel_if_unset(qconn, &channel_id)?;
                    let channel = self.channels.entry(channel_id).or_default();
                    channel.join_sent = true;
                    channel.join_pending = false;
                    channel.join_blocked_by_client = false;
                },

                ServerControlCommand::SendLeave { frame } => {
                    if !self.prepare_channel_barrier(qconn, &frame.channel_id)? {
                        self.defer_pending_barrier(
                            pending,
                            ServerControlCommand::SendLeave { frame },
                        );
                        continue;
                    }

                    let channel_id = frame.channel_id.clone();
                    let state_sequence = frame.mc_state_sequence;
                    if self.peer_supports_multicast(qconn) {
                        match Self::try_send_control(
                            qconn,
                            quiche::multicast::Frame::Leave(frame),
                        )? {
                            ControlSendOutcome::Sent => (),

                            ControlSendOutcome::Full(
                                quiche::multicast::Frame::Leave(frame),
                            ) => {
                                self.retry_control_command(
                                    pending,
                                    ServerControlCommand::SendLeave { frame },
                                )?;
                                break;
                            },

                            ControlSendOutcome::Full(_) =>
                                unreachable!("core returned another frame"),
                        }
                    }

                    let Some(channel) = self.channels.get_mut(&channel_id) else {
                        continue;
                    };
                    channel.join_sent = false;
                    channel.join_pending = false;
                    channel.leave_pending = false;
                    qconn
                        .multicast_process_local_state(quiche::multicast::State {
                        channel_id,
                        sequence: state_sequence,
                        state: quiche::multicast::ChannelState::Left,
                        reason_scope:
                            quiche::multicast::StateReasonScope::Transport,
                        reason_code:
                            quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                        reason_phrase: Vec::new(),
                    })?;
                },

                ServerControlCommand::AutomaticAnnounce {
                    announce,
                    key,
                    generation,
                } => {
                    let channel_id = key.channel_id.clone();
                    if !self.channels.get(&channel_id).is_some_and(|channel| {
                        channel.generation == generation &&
                            !channel.retired &&
                            !channel.retirement_pending
                    }) {
                        continue;
                    }

                    if let Some(announce) = announce {
                        match Self::try_send_control(
                            qconn,
                            quiche::multicast::Frame::Announce(announce),
                        )? {
                            ControlSendOutcome::Sent => {
                                self.defer_pending_barrier(
                                    pending,
                                    ServerControlCommand::AutomaticAnnounce {
                                        announce: None,
                                        key,
                                        generation,
                                    },
                                );
                                continue;
                            },

                            ControlSendOutcome::Full(
                                quiche::multicast::Frame::Announce(announce),
                            ) => {
                                self.retry_control_command(
                                    pending,
                                    ServerControlCommand::AutomaticAnnounce {
                                        announce: Some(announce),
                                        key,
                                        generation,
                                    },
                                )?;
                                break;
                            },

                            ControlSendOutcome::Full(_) =>
                                unreachable!("core returned another frame"),
                        }
                    }

                    match Self::try_send_control(
                        qconn,
                        quiche::multicast::Frame::Key(key),
                    )? {
                        ControlSendOutcome::Sent => (),

                        ControlSendOutcome::Full(
                            quiche::multicast::Frame::Key(key),
                        ) => {
                            self.retry_control_command(
                                pending,
                                ServerControlCommand::AutomaticAnnounce {
                                    announce: None,
                                    key,
                                    generation,
                                },
                            )?;
                            break;
                        },

                        ControlSendOutcome::Full(_) =>
                            unreachable!("core returned another frame"),
                    }

                    let channel = self
                        .channels
                        .get_mut(&channel_id)
                        .expect("automatic channel was checked above");
                    channel.announce_sent = true;
                    channel.announce_pending = false;
                    drop(pending);
                    self.maybe_auto_join_channel(qconn, &channel_id)?;
                },

                ServerControlCommand::RelayIntegrity { frame } => {
                    self.queue_integrity(frame)?;
                },

                ServerControlCommand::AttachStreamPublisher {
                    config,
                    reordering_threshold,
                    max_stream_id,
                    delivery_metrics,
                    publication_queue,
                } => {
                    let channel_id = config.announce.channel_id.clone();
                    if self.channels.get(&channel_id).is_some_and(|channel| {
                        channel.stream_delivery_metrics.is_some()
                    }) {
                        return Err(quiche::Error::InvalidState.into());
                    }

                    qconn.multicast_set_stream_recovery_reordering_threshold(
                        &channel_id,
                        reordering_threshold,
                    )?;

                    let auto_send = self.settings.mode ==
                        ServerControlMode::Automatic &&
                        self.peer_supports_multicast(qconn);
                    self.upsert_channel_config(qconn, config, false, false)?;

                    let channel = self
                        .channels
                        .get_mut(&channel_id)
                        .ok_or(Box::new(quiche::Error::InvalidState)
                            as Box<dyn std::error::Error + Send + Sync>)?;
                    channel.stream_publisher = true;
                    channel.max_stream_id = max_stream_id;
                    channel.stream_delivery_metrics =
                        Some(ConnectionStreamDeliveryMetrics {
                            accumulator: delivery_metrics,
                            baseline: qconn
                                .multicast_stream_delivery_metrics_snapshot(
                                    &channel_id,
                                ),
                        });
                    channel.stream_publication_queue =
                        Some(Arc::clone(&publication_queue));

                    self.coalesce_attached_publisher_ready(&publication_queue);
                    if auto_send {
                        self.maybe_auto_announce_channel(qconn, &channel_id)?;
                        self.maybe_auto_join_channel(qconn, &channel_id)?;
                    }
                },

                ServerControlCommand::StreamPublisherQueueReady {
                    publication_queue,
                } => {
                    let channel_id = publication_queue.channel_id();
                    let is_current = self
                        .channels
                        .get(channel_id)
                        .and_then(|channel| {
                            channel.stream_publication_queue.as_ref()
                        })
                        .is_some_and(|current| {
                            Arc::ptr_eq(current, &publication_queue)
                        });
                    if !is_current {
                        continue;
                    }
                },

                ServerControlCommand::DetachStreamPublisher {
                    publication_queue,
                } => {
                    let channel_id = publication_queue.channel_id();
                    let is_current = self
                        .channels
                        .get(channel_id)
                        .and_then(|channel| {
                            channel.stream_publication_queue.as_ref()
                        })
                        .is_some_and(|current| {
                            Arc::ptr_eq(current, &publication_queue)
                        });
                    if !is_current {
                        continue;
                    }

                    if publication_queue.has_items() {
                        pending.command.restore(
                            ServerControlCommand::DetachStreamPublisher {
                                publication_queue: Arc::clone(&publication_queue),
                            },
                        );
                        self.pending_commands.push_front(pending);
                        break;
                    }

                    if !self.prepare_channel_barrier(qconn, channel_id)? {
                        self.defer_pending_barrier(
                            pending,
                            ServerControlCommand::DetachStreamPublisher {
                                publication_queue,
                            },
                        );
                        continue;
                    }

                    self.event_coalescer.reset_channel(channel_id);
                    qconn.multicast_probe_reset(channel_id)?;
                    self.stop_stream_publisher(qconn, channel_id)?;
                },

                ServerControlCommand::StreamPublication { publication } => {
                    let channel_id = publication.integrity.channel_id.clone();
                    let exceeds_stream_limit = {
                        let Some(channel) = self.channels.get_mut(&channel_id)
                        else {
                            return Err(quiche::Error::InvalidState.into());
                        };

                        channel.max_stream_id =
                            Some(channel.max_stream_id.map_or(
                                publication.frame.stream_id,
                                |current| {
                                    current.max(publication.frame.stream_id)
                                },
                            ));
                        channel.largest_stream_packet_number =
                            Some(publication.packet_number);
                        channel.join_sent &&
                            !Self::stream_id_within_peer_limit(
                                qconn,
                                publication.frame.stream_id,
                            )
                    };

                    if exceeds_stream_limit {
                        self.leave_channel(
                            qconn,
                            &channel_id,
                            publication.packet_number.saturating_sub(1),
                        )?;
                    }

                    self.pending_stream_publications.push(publication).map_err(
                        |()| {
                            Box::new(ServerError::RuntimeQueueExhausted(
                                "stream publication",
                            ))
                                as crate::result::BoxError
                        },
                    )?;

                    if self.settings.mode == ServerControlMode::Automatic {
                        self.maybe_auto_join_channel(qconn, &channel_id)?;
                    }
                },

                ServerControlCommand::StreamPublisherKey { frame, cached } => {
                    if !self.prepare_channel_barrier(qconn, &frame.channel_id)? {
                        self.defer_pending_barrier(
                            pending,
                            ServerControlCommand::StreamPublisherKey {
                                frame,
                                cached,
                            },
                        );
                        continue;
                    }
                    let channel_id = frame.channel_id.clone();
                    let should_send =
                        self.channels.get(&channel_id).is_some_and(|channel| {
                            channel.announce_sent &&
                                !channel.retired &&
                                self.peer_supports_multicast(qconn)
                        });
                    let cached = cached.unwrap_or_else(|| frame.clone());
                    if should_send {
                        match Self::try_send_control(
                            qconn,
                            quiche::multicast::Frame::Key(frame),
                        )? {
                            ControlSendOutcome::Sent => (),

                            ControlSendOutcome::Full(
                                quiche::multicast::Frame::Key(frame),
                            ) => {
                                self.retry_control_command(
                                    pending,
                                    ServerControlCommand::StreamPublisherKey {
                                        frame,
                                        cached: Some(cached),
                                    },
                                )?;
                                break;
                            },

                            ControlSendOutcome::Full(_) =>
                                unreachable!("core returned another frame"),
                        }
                    }

                    let Some(channel) = self.channels.get_mut(&channel_id) else {
                        return Err(quiche::Error::InvalidState.into());
                    };
                    channel.key = Some(cached);
                },

                ServerControlCommand::StreamPublisherMaxStreamId {
                    channel_id,
                    max_stream_id,
                } => {
                    let (exceeds_stream_limit, after_packet_number) = {
                        let Some(channel) = self.channels.get_mut(&channel_id)
                        else {
                            return Err(quiche::Error::InvalidState.into());
                        };
                        channel.max_stream_id = Some(
                            channel
                                .max_stream_id
                                .map_or(max_stream_id, |current| {
                                    current.max(max_stream_id)
                                }),
                        );
                        (
                            channel.join_sent &&
                                !Self::stream_id_within_peer_limit(
                                    qconn,
                                    max_stream_id,
                                ),
                            channel.largest_stream_packet_number.unwrap_or(0),
                        )
                    };

                    if exceeds_stream_limit {
                        self.leave_channel(
                            qconn,
                            &channel_id,
                            after_packet_number,
                        )?;
                    } else if self.settings.mode == ServerControlMode::Automatic {
                        self.maybe_auto_join_channel(qconn, &channel_id)?;
                    }
                },

                ServerControlCommand::StreamPublisherRetire { frame } => {
                    if !self.prepare_channel_barrier(qconn, &frame.channel_id)? {
                        self.defer_pending_barrier(
                            pending,
                            ServerControlCommand::StreamPublisherRetire { frame },
                        );
                        continue;
                    }
                    let channel_id = frame.channel_id.clone();
                    if self.peer_supports_multicast(qconn) {
                        match Self::try_send_control(
                            qconn,
                            quiche::multicast::Frame::Retire(frame),
                        )? {
                            ControlSendOutcome::Sent => (),

                            ControlSendOutcome::Full(
                                quiche::multicast::Frame::Retire(frame),
                            ) => {
                                self.retry_control_command(
                                    pending,
                                    ServerControlCommand::StreamPublisherRetire {
                                        frame,
                                    },
                                )?;
                                break;
                            },

                            ControlSendOutcome::Full(_) =>
                                unreachable!("core returned another frame"),
                        }
                    }
                    self.event_coalescer.reset_channel(&channel_id);

                    let Some(channel) = self.channels.get_mut(&channel_id) else {
                        return Err(quiche::Error::InvalidState.into());
                    };
                    channel.retired = true;
                    channel.announce_sent = false;
                    channel.announce_pending = false;
                    channel.join_sent = false;
                    channel.join_pending = false;
                    channel.join_blocked_by_client = true;
                    channel.retirement_pending = false;

                    qconn
                        .multicast_process_local_state(quiche::multicast::State {
                        channel_id: channel_id.clone(),
                        sequence: 0,
                        state: quiche::multicast::ChannelState::Retired,
                        reason_scope:
                            quiche::multicast::StateReasonScope::Transport,
                        reason_code:
                            quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                        reason_phrase: Vec::new(),
                    })?;
                    self.stop_stream_publisher(qconn, &channel_id)?;
                },

                ServerControlCommand::RetireForLimits {
                    channel_id,
                    generation,
                } => {
                    if !self.channels.get(&channel_id).is_some_and(|channel| {
                        channel.retirement_pending &&
                            channel.generation == generation
                    }) {
                        continue;
                    }
                    if !self.prepare_channel_barrier(qconn, &channel_id)? {
                        self.defer_pending_barrier(
                            pending,
                            ServerControlCommand::RetireForLimits {
                                channel_id,
                                generation,
                            },
                        );
                        continue;
                    }

                    if !self.finish_limit_retirement(
                        qconn,
                        &channel_id,
                        generation,
                    )? {
                        self.retry_control_command(
                            pending,
                            ServerControlCommand::RetireForLimits {
                                channel_id,
                                generation,
                            },
                        )?;
                        break;
                    }
                },
            }
        }

        Ok(work)
    }

    fn coalesce_attached_publisher_ready(
        &mut self,
        publication_queue: &Arc<server_stream::ServerStreamPublisherQueue>,
    ) {
        let Ok(command) = self.command_receiver.try_recv() else {
            return;
        };
        let redundant = matches!(
            command.as_ref(),
            ServerControlCommand::StreamPublisherQueueReady {
                publication_queue: queued,
            } if Arc::ptr_eq(queued, publication_queue)
        );
        if !redundant {
            self.pending_commands
                .push_back(PendingServerControlCommand::regular(command));
        }
    }

    fn stream_publisher_item_command(
        channel_id: &[u8], item: server_stream::ServerStreamPublisherQueueItem,
    ) -> ServerControlCommand {
        match item {
            server_stream::ServerStreamPublisherQueueItem::Publication(
                publication,
            ) => ServerControlCommand::StreamPublication { publication },

            server_stream::ServerStreamPublisherQueueItem::Key(frame) =>
                ServerControlCommand::StreamPublisherKey {
                    frame,
                    cached: None,
                },

            server_stream::ServerStreamPublisherQueueItem::MaxStreamId(
                max_stream_id,
            ) => ServerControlCommand::StreamPublisherMaxStreamId {
                channel_id: channel_id.to_vec(),
                max_stream_id,
            },

            server_stream::ServerStreamPublisherQueueItem::Retire(frame) =>
                ServerControlCommand::StreamPublisherRetire { frame },
        }
    }

    fn stream_publisher_command_item(
        command: ServerControlCommand,
    ) -> server_stream::ServerStreamPublisherQueueItem {
        match command {
            ServerControlCommand::StreamPublication { publication } =>
                server_stream::ServerStreamPublisherQueueItem::Publication(
                    publication,
                ),

            ServerControlCommand::StreamPublisherKey {
                frame,
                cached: None,
            } => server_stream::ServerStreamPublisherQueueItem::Key(frame),

            ServerControlCommand::StreamPublisherMaxStreamId {
                max_stream_id,
                ..
            } => server_stream::ServerStreamPublisherQueueItem::MaxStreamId(
                max_stream_id,
            ),

            ServerControlCommand::StreamPublisherRetire { frame } =>
                server_stream::ServerStreamPublisherQueueItem::Retire(frame),

            _ => unreachable!("only unstaged publisher commands are restored"),
        }
    }

    fn stage_stream_publisher_queue_items(
        &mut self,
        publication_queue: &Arc<server_stream::ServerStreamPublisherQueue>,
        max_items: usize,
    ) -> QuicResult<usize> {
        let command_budget = self.command_budget.clone();
        let channel_id = publication_queue.channel_id().to_vec();
        let staged = publication_queue.stage_up_to(max_items, |mut items| {
            let mut commands = VecDeque::new();
            let mut unconsumed = VecDeque::new();
            let mut structural_error = false;
            let mut inspected = 0_usize;

            while let Some(item) = items.pop_front() {
                inspected = inspected.saturating_add(1);
                let command =
                    Self::stream_publisher_item_command(&channel_id, item);
                match command_budget.wrap(command) {
                    Ok(command) => commands.push_back(command),

                    Err(QueueSendError::Full(command)) => {
                        unconsumed.push_back(
                            Self::stream_publisher_command_item(command),
                        );
                        unconsumed.append(&mut items);
                        break;
                    },

                    Err(
                        QueueSendError::Oversized(command) |
                        QueueSendError::Closed(command),
                    ) => {
                        unconsumed.push_back(
                            Self::stream_publisher_command_item(command),
                        );
                        unconsumed.append(&mut items);
                        structural_error = true;
                        break;
                    },
                }
            }

            ((commands, structural_error, inspected), unconsumed)
        });

        let Some((mut commands, structural_error, inspected)) = staged else {
            return Ok(0);
        };
        while let Some(command) = commands.pop_back() {
            self.pending_commands
                .push_front(PendingServerControlCommand::regular(command));
        }

        if structural_error {
            return Err(Box::new(ServerError::RuntimeQueueExhausted(
                "publisher command",
            )));
        }

        Ok(inspected)
    }

    fn stage_one_stream_publisher_queue_item(&mut self) -> QuicResult<bool> {
        self.stage_pending_stream_publisher_queues_with_limit(1)
            .map(|work| work > 0)
    }

    fn stage_pending_stream_publisher_queues_with_limit(
        &mut self, max_work: usize,
    ) -> QuicResult<usize> {
        let staged_channels = self
            .pending_commands
            .iter()
            .filter_map(|pending| match pending.command.as_ref() {
                ServerControlCommand::StreamPublication { publication } =>
                    Some(publication.integrity.channel_id.clone()),

                ServerControlCommand::StreamPublisherKey { frame, .. } =>
                    Some(frame.channel_id.clone()),

                ServerControlCommand::StreamPublisherRetire { frame } =>
                    Some(frame.channel_id.clone()),

                ServerControlCommand::StreamPublisherMaxStreamId {
                    channel_id,
                    ..
                } => Some(channel_id.clone()),

                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let channel_ids = fair_ready_channel_ids(
            &self.channels,
            self.publisher_stage_cursor.as_deref(),
            max_work,
            |channel| {
                channel
                    .stream_publication_queue
                    .as_ref()
                    .is_some_and(|queue| {
                        queue.has_pending() &&
                            !staged_channels.contains(queue.channel_id()) &&
                            !self
                                .blocked_command_channels
                                .contains(queue.channel_id())
                    })
            },
        );
        let channel_count = channel_ids.len();
        let base_quota = if channel_count == 0 {
            0
        } else {
            max_work / channel_count
        };
        let extra_quota = if channel_count == 0 {
            0
        } else {
            max_work % channel_count
        };
        let mut work_performed = 0_usize;

        for (index, channel_id) in channel_ids.into_iter().enumerate() {
            let quota = base_quota + usize::from(index < extra_quota);
            self.publisher_stage_cursor = Some(channel_id.clone());
            let Some(queue) = self
                .channels
                .get(&channel_id)
                .and_then(|channel| channel.stream_publication_queue.clone())
            else {
                continue;
            };
            work_performed = work_performed.saturating_add(
                self.stage_stream_publisher_queue(&queue, quota)?,
            );
        }

        debug_assert!(work_performed <= max_work);
        Ok(work_performed)
    }

    fn stage_stream_publisher_queue(
        &mut self,
        publication_queue: &Arc<server_stream::ServerStreamPublisherQueue>,
        max_work: usize,
    ) -> QuicResult<usize> {
        let channel_id = publication_queue.channel_id();
        let is_current = self
            .channels
            .get(channel_id)
            .and_then(|channel| channel.stream_publication_queue.as_ref())
            .is_some_and(|current| Arc::ptr_eq(current, publication_queue));
        if !is_current {
            return Ok(0);
        }

        let mut work =
            self.stage_stream_publisher_queue_items(publication_queue, max_work)?;
        if work < max_work &&
            !publication_queue.has_items() &&
            publication_queue.claim_detach()
        {
            if let Err(error) = self.queue_command_front(
                ServerControlCommand::DetachStreamPublisher {
                    publication_queue: Arc::clone(publication_queue),
                },
            ) {
                publication_queue.release_detach_claim();
                return Err(error);
            }
            work = work.saturating_add(1);
        }

        Ok(work)
    }

    fn queue_command_front(
        &mut self, command: ServerControlCommand,
    ) -> QuicResult<()> {
        let command = self.command_budget.wrap(command).map_err(|_| {
            Box::new(ServerError::RuntimeQueueExhausted("command"))
                as crate::result::BoxError
        })?;
        self.pending_commands
            .push_front(PendingServerControlCommand::regular(command));
        Ok(())
    }

    fn queue_command_back(
        &mut self, command: ServerControlCommand,
    ) -> QuicResult<()> {
        let command = self.command_budget.wrap(command).map_err(|_| {
            Box::new(ServerError::RuntimeQueueExhausted("command"))
                as crate::result::BoxError
        })?;
        self.pending_commands
            .push_back(PendingServerControlCommand::regular(command));
        Ok(())
    }

    fn try_send_control(
        qconn: &mut QuicheConnection, frame: quiche::multicast::Frame,
    ) -> QuicResult<ControlSendOutcome> {
        match qconn.multicast_try_send(frame) {
            Ok(()) => Ok(ControlSendOutcome::Sent),

            Err(error)
                if error.kind() ==
                    quiche::multicast::ControlSendErrorKind::Full =>
                Ok(ControlSendOutcome::Full(error.into_frame())),

            Err(error) => Err(Box::new(error)),
        }
    }

    fn retry_control_command(
        &mut self, mut pending: PendingServerControlCommand,
        command: ServerControlCommand,
    ) -> QuicResult<()> {
        let now = Instant::now();
        let deadline = now
            .checked_add(self.limits.control_retry_delay)
            .ok_or(quiche::Error::InvalidState)?;
        pending.record_full(now);
        if pending.blocked_since.is_some_and(|blocked_since| {
            now.saturating_duration_since(blocked_since) >=
                self.limits.control_backpressure_timeout
        }) {
            return Err(Box::new(ServerError::ControlBackpressureTimeout(
                self.limits.control_backpressure_timeout,
            )));
        }

        let channel_id = command.channel_id().to_vec();
        pending.command.restore(command);
        pending.deferred_barrier = true;
        self.blocked_command_channels.insert(channel_id);
        self.pending_commands.push_back(pending);

        self.control_retry_deadline = Some(
            self.control_retry_deadline
                .map_or(deadline, |current| current.min(deadline)),
        );
        Ok(())
    }

    fn defer_pending_barrier(
        &mut self, mut pending: PendingServerControlCommand,
        command: ServerControlCommand,
    ) {
        let channel_id = command.channel_id().to_vec();
        pending.command.restore(command);
        pending.deferred_barrier = true;
        pending.made_progress();
        self.blocked_command_channels.insert(channel_id);
        self.pending_commands.push_back(pending);
    }

    fn upsert_channel_config(
        &mut self, qconn: &mut QuicheConnection,
        config: ServerControlChannelConfig, auto_send: bool,
        set_default_dgram_channel: bool,
    ) -> QuicResult<()> {
        config.validate()?;

        let channel_id = config.announce.channel_id.clone();
        self.ensure_channel_capacity(&channel_id)?;
        if self.channels.contains_key(&channel_id) ||
            qconn.multicast_probe_status(&channel_id).is_some()
        {
            self.event_coalescer.reset_channel(&channel_id);
            qconn.multicast_probe_reset(&channel_id)?;
        }
        if set_default_dgram_channel {
            Self::set_default_dgram_channel_if_unset(qconn, &channel_id)?;
        }
        Self::set_ack_timeout(
            qconn,
            &channel_id,
            config.announce.max_ack_delay_ms,
        )?;
        let channel = self.channels.entry(channel_id.clone()).or_default();
        channel.announce = Some(config.announce.clone());
        channel.key = Some(config.key.clone());
        channel.announce_sent = false;
        channel.announce_pending = false;
        channel.join_sent = false;
        channel.join_pending = false;
        channel.leave_pending = false;
        channel.join_blocked_by_client = false;
        channel.retired = false;
        channel.retirement_pending = false;
        channel.generation = channel.generation.saturating_add(1);

        if !auto_send {
            return Ok(());
        }

        self.maybe_auto_announce_channel(qconn, &channel_id)?;
        self.maybe_auto_join_channel(qconn, &channel_id)
    }

    fn ensure_channel_capacity(&self, channel_id: &[u8]) -> QuicResult<()> {
        if !self.channels.contains_key(channel_id) &&
            self.channels.len() >= self.limits.max_tracked_channel_ids
        {
            return Err(Box::new(ServerError::TrackedChannelIdLimit(
                self.limits.max_tracked_channel_ids,
            )));
        }

        Ok(())
    }

    fn maybe_auto_announce_channel(
        &mut self, qconn: &mut QuicheConnection, channel_id: &[u8],
    ) -> QuicResult<()> {
        if self.settings.mode != ServerControlMode::Automatic ||
            !self.peer_supports_multicast(qconn)
        {
            return Ok(());
        }

        let Some(channel) = self.channels.get(channel_id) else {
            return Ok(());
        };
        if channel.announce_sent ||
            channel.announce_pending ||
            channel.retired ||
            channel.retirement_pending
        {
            return Ok(());
        }
        let (Some(announce), Some(key)) =
            (channel.announce.as_ref(), channel.key.as_ref())
        else {
            return Ok(());
        };
        if !self.channel_can_be_announced(qconn, channel_id, announce) {
            return Ok(());
        }

        let command = ServerControlCommand::AutomaticAnnounce {
            announce: Some(announce.clone()),
            key: key.clone(),
            generation: channel.generation,
        };
        self.queue_command_back(command)?;
        self.channels
            .get_mut(channel_id)
            .expect("channel was checked above")
            .announce_pending = true;

        Ok(())
    }

    fn maybe_auto_join_channel(
        &mut self, qconn: &mut QuicheConnection, channel_id: &[u8],
    ) -> QuicResult<()> {
        if self.settings.mode != ServerControlMode::Automatic {
            return Ok(());
        }

        let Some(limits) = self.last_client_limits.as_ref() else {
            return Ok(());
        };

        let sequence = limits.sequence;

        let Some(channel) = self.channels.get(channel_id) else {
            return Ok(());
        };

        if !channel.announce_sent ||
            channel.join_sent ||
            channel.join_pending ||
            channel.join_blocked_by_client ||
            channel.retired ||
            channel.retirement_pending
        {
            return Ok(());
        }

        let (Some(announce), Some(key)) =
            (channel.announce.as_ref(), channel.key.as_ref())
        else {
            return Ok(());
        };

        if !self.channel_fits_client_limits(qconn, channel_id, announce) {
            return Ok(());
        }

        let join = quiche::multicast::Join {
            channel_id: announce.channel_id.clone(),
            mc_limits_sequence: sequence,
            mc_state_sequence: channel.last_client_state_sequence,
            mc_key_sequence: key.key_sequence,
        };

        self.queue_command_back(ServerControlCommand::SendJoin { frame: join })?;
        self.channels
            .get_mut(channel_id)
            .expect("channel was checked above")
            .join_pending = true;

        Ok(())
    }

    fn channel_fits_client_limits(
        &self, qconn: &QuicheConnection, channel_id: &[u8],
        announce: &quiche::multicast::Announce,
    ) -> bool {
        let Some(limits) = self.last_client_limits.as_ref() else {
            return false;
        };
        if !Self::announce_matches_client_capabilities(
            qconn,
            &limits.limits,
            announce,
        ) {
            return false;
        }

        let joined_count = self
            .channels
            .iter()
            .filter(|(id, channel)| {
                id.as_slice() != channel_id && channel.join_sent
            })
            .count() as u64;
        if joined_count >= limits.max_joined_count ||
            joined_count >= limits.limits.max_channel_ids
        {
            return false;
        }

        let joined_rate = self
            .channels
            .iter()
            .filter(|(id, channel)| {
                id.as_slice() != channel_id && channel.join_sent
            })
            .filter_map(|(_, channel)| channel.announce.as_ref())
            .fold(0_u64, |total, joined| {
                total.saturating_add(joined.max_rate_kibps)
            });
        if joined_rate.saturating_add(announce.max_rate_kibps) >
            limits.limits.max_aggregate_rate_kibps
        {
            return false;
        }

        let channel = self
            .channels
            .get(channel_id)
            .expect("channel was checked by caller");
        if channel.stream_publisher {
            let Some(max_stream_id) = channel.max_stream_id else {
                return false;
            };

            if !Self::stream_id_within_peer_limit(qconn, max_stream_id) {
                return false;
            }
        }

        true
    }

    fn channel_can_be_announced(
        &self, qconn: &QuicheConnection, channel_id: &[u8],
        announce: &quiche::multicast::Announce,
    ) -> bool {
        let Some(peer) = qconn
            .peer_transport_params()
            .and_then(|params| params.multicast_client_params.as_ref())
        else {
            return false;
        };
        let active_limits = self
            .last_client_limits
            .as_ref()
            .map_or(&peer.limits, |limits| &limits.limits);

        if !Self::announce_matches_client_capabilities(
            qconn,
            active_limits,
            announce,
        ) {
            return false;
        }

        let announced_count = self
            .channels
            .iter()
            .filter(|(id, channel)| {
                id.as_slice() != channel_id && channel.announce_sent
            })
            .count() as u64;

        announced_count < active_limits.max_channel_ids
    }

    fn announce_matches_client_capabilities(
        qconn: &QuicheConnection, limits: &quiche::multicast::ClientLimits,
        announce: &quiche::multicast::Announce,
    ) -> bool {
        let Some(peer) = qconn
            .peer_transport_params()
            .and_then(|params| params.multicast_client_params.as_ref())
        else {
            return false;
        };

        let family_allowed = match (&announce.source, &announce.group) {
            (IpAddr::V4(_), IpAddr::V4(_)) => limits.ipv4_channels_allowed,
            (IpAddr::V6(_), IpAddr::V6(_)) => limits.ipv6_channels_allowed,
            _ => false,
        };

        family_allowed &&
            peer.hash_algorithms
                .contains(&announce.integrity_hash_algorithm) &&
            peer.encryption_algorithms
                .contains(&announce.header_protection_algorithm) &&
            peer.encryption_algorithms
                .contains(&announce.aead_algorithm)
    }

    fn stream_id_within_peer_limit(
        qconn: &QuicheConnection, stream_id: u64,
    ) -> bool {
        stream_id >> 2 < qconn.peer_max_streams_uni()
    }

    fn leave_channel(
        &mut self, _qconn: &mut QuicheConnection, channel_id: &[u8],
        after_packet_number: u64,
    ) -> QuicResult<()> {
        let Some(channel) = self.channels.get(channel_id) else {
            return Ok(());
        };
        if !channel.join_sent || channel.leave_pending {
            return Ok(());
        }

        let state_sequence = channel.last_client_state_sequence;
        self.queue_command_back(ServerControlCommand::SendLeave {
            frame: quiche::multicast::Leave {
                channel_id: channel_id.to_vec(),
                mc_state_sequence: state_sequence,
                after_packet_number,
            },
        })?;
        self.channels
            .get_mut(channel_id)
            .expect("channel was checked above")
            .leave_pending = true;

        Ok(())
    }

    fn flush_one_pending_stream_publication(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.flush_pending_stream_publications_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    fn flush_pending_stream_publications_with_limit(
        &mut self, qconn: &mut QuicheConnection, max_work: usize,
    ) -> QuicResult<usize> {
        let mut work = 0;
        for _ in 0..max_work {
            let Some(key) = self.pending_stream_publications.next_ready() else {
                break;
            };
            self.flush_pending_stream_publication(qconn, key)?;
            work += 1;
        }

        Ok(work)
    }

    fn flush_pending_stream_publication(
        &mut self, qconn: &mut QuicheConnection, key: PendingStreamKey,
    ) -> QuicResult<()> {
        let publication = self
            .pending_stream_publications
            .front(&key)
            .cloned()
            .expect("scheduled stream queue is non-empty");
        let channel_id = &publication.integrity.channel_id;
        let frame = &publication.frame;

        match qconn.multicast_stream_send_buf(
            channel_id,
            publication.packet_number,
            frame.stream_id,
            frame.offset,
            frame.data.clone(),
            frame.fin,
        ) {
            Ok(()) => {
                #[cfg(test)]
                {
                    self.stream_publication_registrations =
                        self.stream_publication_registrations.saturating_add(1);
                }
                if self.peer_supports_multicast(qconn) &&
                    self.channels.get(channel_id).is_some_and(|channel| {
                        channel.announce_sent &&
                            channel.join_sent &&
                            !channel.retired
                    })
                {
                    self.queue_stream_integrity(
                        publication.integrity.clone(),
                        Instant::now(),
                    )?;
                }
                self.pending_stream_publications.complete_front(key);
            },

            Err(quiche::Error::Done | quiche::Error::StreamLimit) => {
                self.pending_stream_publications.block(key);
            },

            // A terminal stream cannot accept this connection's registration.
            // Other publisher attachments retain and process their own copy,
            // so discarding it here lets detach finish.
            Err(
                quiche::Error::InvalidStreamState(_) |
                quiche::Error::StreamStopped(_),
            ) => self.pending_stream_publications.complete_front(key),

            Err(error) => return Err(error.into()),
        }

        Ok(())
    }

    fn queue_stream_integrity(
        &mut self, frame: quiche::multicast::Integrity, now: Instant,
    ) -> QuicResult<()> {
        let batching = self.settings.stream_integrity_batching;
        if batching.max_packet_hashes <= 1 || batching.max_delay.is_zero() {
            return self.queue_integrity(frame);
        }
        let deadline = now
            .checked_add(batching.max_delay)
            .ok_or(quiche::Error::InvalidState)?;

        let Some((frame_count, frame_hash_len)) =
            Self::integrity_hash_shape(&frame)
        else {
            return self.queue_integrity(frame);
        };
        let channel_id = frame.channel_id.clone();

        if let Some(pending) =
            self.pending_stream_integrity_batches.remove(&channel_id)
        {
            let mut pending = pending.into_inner();
            let pending_count = pending
                .frame
                .packet_hash_count
                .expect("batched integrity always has an explicit count");
            let combined_count = pending_count.checked_add(frame_count);
            let is_contiguous =
                pending.frame.packet_number_start.checked_add(pending_count) ==
                    Some(frame.packet_number_start);
            let can_append = pending.hash_len == frame_hash_len &&
                is_contiguous &&
                combined_count
                    .is_some_and(|count| count <= batching.max_packet_hashes);

            if can_append {
                let combined_count = combined_count
                    .expect("appendable integrity count cannot overflow");
                pending.frame.packet_hash_count = Some(combined_count);
                pending.frame.packet_hashes.extend(frame.packet_hashes);

                if combined_count == batching.max_packet_hashes {
                    self.queue_integrity(pending.frame)?;
                } else {
                    self.store_stream_integrity_batch(channel_id, pending)?;
                }
                return Ok(());
            }

            self.queue_integrity(pending.frame)?;
        }

        if frame_count >= batching.max_packet_hashes {
            return self.queue_integrity(frame);
        }

        self.store_stream_integrity_batch(
            channel_id,
            PendingStreamIntegrityBatch {
                frame,
                hash_len: frame_hash_len,
                deadline,
            },
        )
    }

    fn integrity_hash_shape(
        frame: &quiche::multicast::Integrity,
    ) -> Option<(u64, usize)> {
        let count = frame.packet_hash_count?;
        let count_usize = usize::try_from(count).ok()?;
        if count_usize == 0 ||
            frame.packet_hashes.is_empty() ||
            frame.packet_hashes.len() % count_usize != 0
        {
            return None;
        }

        Some((count, frame.packet_hashes.len() / count_usize))
    }

    fn next_stream_integrity_deadline(&self) -> Option<Instant> {
        self.pending_stream_integrity_batches
            .values()
            .map(|pending| pending.as_ref().deadline)
            .min()
    }

    fn next_runtime_deadline(&self) -> Option<Instant> {
        match (
            self.next_stream_integrity_deadline(),
            self.control_retry_deadline,
        ) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }

    fn stage_one_due_stream_integrity(
        &mut self, now: Instant,
    ) -> QuicResult<bool> {
        self.stage_due_stream_integrities_with_limit(now, 1)
            .map(|work| work > 0)
    }

    fn stage_due_stream_integrities_with_limit(
        &mut self, now: Instant, max_work: usize,
    ) -> QuicResult<usize> {
        let due_channels = fair_ready_channel_ids(
            &self.pending_stream_integrity_batches,
            self.integrity_stage_cursor.as_deref(),
            max_work,
            |pending| pending.as_ref().deadline <= now,
        );
        let mut work = 0;

        for channel_id in due_channels {
            self.integrity_stage_cursor = Some(channel_id.clone());
            self.flush_stream_integrity_batch(&channel_id)?;
            work += 1;
        }

        Ok(work)
    }

    fn flush_stream_integrity_batch(
        &mut self, channel_id: &[u8],
    ) -> QuicResult<()> {
        if let Some(pending) =
            self.pending_stream_integrity_batches.remove(channel_id)
        {
            self.queue_integrity(pending.into_inner().frame)?;
        }

        Ok(())
    }

    fn store_stream_integrity_batch(
        &mut self, channel_id: Vec<u8>, pending: PendingStreamIntegrityBatch,
    ) -> QuicResult<()> {
        let pending = self
            .pending_stream_integrity_batch_budget
            .wrap(pending)
            .map_err(|_| {
                Box::new(ServerError::RuntimeQueueExhausted("integrity"))
                    as crate::result::BoxError
            })?;
        self.pending_stream_integrity_batches
            .insert(channel_id, pending);
        Ok(())
    }

    fn queue_integrity(
        &mut self, frame: quiche::multicast::Integrity,
    ) -> QuicResult<()> {
        self.pending_integrities.push_back(frame).map_err(|_| {
            Box::new(ServerError::RuntimeQueueExhausted("integrity"))
                as crate::result::BoxError
        })
    }

    fn flush_one_pending_integrity(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.flush_pending_integrities_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    fn flush_pending_integrities_with_limit(
        &mut self, qconn: &mut QuicheConnection, max_work: usize,
    ) -> QuicResult<usize> {
        let mut work = 0;
        for _ in 0..max_work {
            let Some(frame) = self.pending_integrities.pop_next() else {
                break;
            };
            work += 1;
            if let Err(error) = qconn
                .multicast_try_send(quiche::multicast::Frame::Integrity(frame))
            {
                if error.kind() != quiche::multicast::ControlSendErrorKind::Full {
                    return Err(Box::new(error));
                }
                let quiche::multicast::Frame::Integrity(frame) =
                    error.into_frame()
                else {
                    unreachable!("core returned another frame");
                };
                self.pending_integrities.push_front(frame).map_err(|_| {
                    Box::new(ServerError::RuntimeQueueExhausted("integrity"))
                        as crate::result::BoxError
                })?;
                self.integrity_retry_blocked = true;
                break;
            }
        }

        Ok(work)
    }

    fn prepare_channel_barrier(
        &mut self, _qconn: &mut QuicheConnection, channel_id: &[u8],
    ) -> QuicResult<bool> {
        if self
            .pending_stream_publications
            .contains_channel(channel_id)
        {
            return Ok(false);
        }

        if self
            .pending_stream_integrity_batches
            .contains_key(channel_id)
        {
            self.flush_stream_integrity_batch(channel_id)?;
            return Ok(false);
        }

        Ok(!self.pending_integrities.contains_channel(channel_id))
    }

    fn finish_limit_retirement(
        &mut self, qconn: &mut QuicheConnection, channel_id: &[u8],
        generation: u64,
    ) -> QuicResult<bool> {
        if !self.channels.get(channel_id).is_some_and(|channel| {
            channel.retirement_pending && channel.generation == generation
        }) {
            return Ok(true);
        }

        let Some(channel) = self.channels.get(channel_id) else {
            return Ok(true);
        };
        let after_packet_number =
            channel.largest_stream_packet_number.unwrap_or(0);
        let sequence = channel.last_client_state_sequence;

        if self.peer_supports_multicast(qconn) {
            let retire = quiche::multicast::Retire {
                channel_id: channel_id.to_vec(),
                after_packet_number,
            };
            match Self::try_send_control(
                qconn,
                quiche::multicast::Frame::Retire(retire),
            )? {
                ControlSendOutcome::Sent => (),
                ControlSendOutcome::Full(_) => return Ok(false),
            }
        }

        self.event_coalescer.reset_channel(channel_id);

        let Some(channel) = self.channels.get_mut(channel_id) else {
            return Ok(true);
        };
        channel.announce_sent = false;
        channel.announce_pending = false;
        channel.join_sent = false;
        channel.join_pending = false;
        channel.leave_pending = false;
        channel.join_blocked_by_client = true;
        channel.retired = true;
        channel.retirement_pending = false;

        qconn.multicast_process_local_state(quiche::multicast::State {
            channel_id: channel_id.to_vec(),
            sequence,
            state: quiche::multicast::ChannelState::Retired,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: Vec::new(),
        })?;
        self.stop_stream_publisher(qconn, channel_id)?;
        Ok(true)
    }

    fn peer_supports_multicast(&self, qconn: &QuicheConnection) -> bool {
        qconn
            .peer_transport_params()
            .and_then(|params| params.multicast_client_params.as_ref())
            .is_some()
    }

    fn set_default_dgram_channel_if_unset(
        qconn: &mut QuicheConnection, channel_id: &[u8],
    ) -> QuicResult<()> {
        if qconn.multicast_default_dgram_channel().is_none() {
            qconn
                .multicast_set_default_dgram_channel(Some(channel_id.to_vec()))?;
        }

        Ok(())
    }

    fn set_ack_timeout(
        qconn: &mut QuicheConnection, channel_id: &[u8], max_ack_delay_ms: u64,
    ) -> QuicResult<()> {
        qconn.multicast_set_ack_timeout(
            channel_id,
            Some(server_ack_freshness_timeout(max_ack_delay_ms)),
        )?;

        Ok(())
    }
}

#[derive(Debug)]
enum ServerCommand {
    Send {
        channel_id: Vec<u8>,
        frames: Vec<quiche::multicast::ChannelFrame>,
    },

    RelayIntegrity {
        frame: quiche::multicast::Integrity,
    },
}

impl RetainedSize for ServerCommand {
    fn retained_size(&self) -> usize {
        match self {
            Self::Send { channel_id, frames } => frames.iter().fold(
                channel_id.len().saturating_add(128),
                |total, frame| {
                    let frame_size = match frame {
                        quiche::multicast::ChannelFrame::Stream {
                            data, ..
                        } |
                        quiche::multicast::ChannelFrame::Datagram { data } =>
                            data.len().saturating_add(64),

                        quiche::multicast::ChannelFrame::Multicast(frame) =>
                            match frame {
                                quiche::multicast::Frame::Announce(frame) =>
                                    announce_retained_size(frame),

                                quiche::multicast::Frame::Key(frame) =>
                                    key_retained_size(frame),

                                quiche::multicast::Frame::Integrity(frame) =>
                                    integrity_retained_size(frame),

                                _ => 128,
                            },

                        _ => 64,
                    };
                    total.saturating_add(frame_size)
                },
            ),

            Self::RelayIntegrity { frame } => integrity_retained_size(frame),
        }
    }
}

#[derive(Debug)]
enum ServerPendingControl {
    AnnounceAndKey {
        announce: Option<quiche::multicast::Announce>,
        key: quiche::multicast::Key,
    },
    Join(quiche::multicast::Join),
}

impl RetainedSize for ServerPendingControl {
    fn retained_size(&self) -> usize {
        match self {
            Self::AnnounceAndKey { announce, key } => announce
                .as_ref()
                .map_or(0, announce_retained_size)
                .saturating_add(key_retained_size(key)),

            Self::Join(frame) => frame.channel_id.len().saturating_add(64),
        }
    }
}

struct PendingServerControl {
    command: Queued<ServerPendingControl>,
    blocked_since: Option<Instant>,
}

#[derive(Debug)]
struct PendingPublication {
    channel_id: Vec<u8>,
    packet: Vec<u8>,
    packet_number: u64,
    integrity: quiche::multicast::Integrity,
}

impl RetainedSize for PendingPublication {
    fn retained_size(&self) -> usize {
        self.channel_id
            .len()
            .saturating_add(self.packet.len())
            .saturating_add(integrity_retained_size(&self.integrity))
            .saturating_add(128)
    }
}

struct ServerRuntime<B: PublishBackend> {
    settings: ServerSettings,
    limits: RuntimeLimits,
    event_sender: ManagedEventSender<ServerEvent>,
    command_receiver: BoundedReceiver<ServerCommand>,
    control_budget: RetainedQueueBudget<ServerPendingControl>,
    pending_commands: VecDeque<Queued<ServerCommand>>,
    pending_controls: VecDeque<PendingServerControl>,
    pending_publications: RetainedDeque<PendingPublication>,
    pending_integrities: RetainedDeque<quiche::multicast::Integrity>,
    control_retry_deadline: Option<Instant>,
    publish_retry_deadline: Option<Instant>,
    integrity_retry_blocked: bool,
    channels: BTreeMap<Vec<u8>, ServerChannel<B::Publication>>,
    backend: B,
    event_coalescer: ServerEventCoalescer,
    control_read_pending: bool,
    read_work_cursor: usize,
    write_work_cursor: usize,
    #[cfg(test)]
    callback_read_work_last_call: usize,
    #[cfg(test)]
    callback_write_work_last_call: usize,
}

impl ServerRuntime<MctxPublishBackend> {
    fn new(
        settings: ServerSettings, event_sender: ManagedEventSender<ServerEvent>,
        command_receiver: BoundedReceiver<ServerCommand>, limits: RuntimeLimits,
    ) -> Self {
        Self::with_backend_and_limits(
            settings,
            event_sender,
            command_receiver,
            MctxPublishBackend,
            limits,
        )
    }
}

impl<B: PublishBackend> ServerRuntime<B> {
    #[cfg(test)]
    fn with_backend(
        settings: ServerSettings, event_sender: ManagedEventSender<ServerEvent>,
        command_receiver: BoundedReceiver<ServerCommand>, backend: B,
    ) -> Self {
        Self::with_backend_and_limits(
            settings,
            event_sender,
            command_receiver,
            backend,
            RuntimeLimits::default(),
        )
    }

    fn with_backend_and_limits(
        settings: ServerSettings, event_sender: ManagedEventSender<ServerEvent>,
        command_receiver: BoundedReceiver<ServerCommand>, backend: B,
        limits: RuntimeLimits,
    ) -> Self {
        let control_budget = command_receiver.budget().cast();
        Self {
            settings,
            limits,
            event_sender,
            command_receiver,
            control_budget,
            pending_commands: VecDeque::new(),
            pending_controls: VecDeque::new(),
            pending_publications: RetainedDeque::new(limits.pending_publications),
            pending_integrities: RetainedDeque::new(limits.pending_integrity),
            control_retry_deadline: None,
            publish_retry_deadline: None,
            integrity_retry_blocked: false,
            channels: BTreeMap::new(),
            backend,
            event_coalescer: ServerEventCoalescer::default(),
            control_read_pending: false,
            read_work_cursor: 0,
            write_work_cursor: 0,
            #[cfg(test)]
            callback_read_work_last_call: 0,
            #[cfg(test)]
            callback_write_work_last_call: 0,
        }
    }

    fn clear(&mut self) {
        self.command_receiver.close();
        self.pending_commands.clear();
        self.pending_controls.clear();
        self.pending_publications.clear();
        self.pending_integrities.clear();
        self.control_retry_deadline = None;
        self.publish_retry_deadline = None;
        self.integrity_retry_blocked = false;
        self.channels.clear();
        self.event_coalescer.clear();
        self.control_read_pending = false;
        self.read_work_cursor = 0;
        self.write_work_cursor = 0;

        while self.command_receiver.try_recv().is_ok() {}
    }

    fn has_pending_work(&self) -> bool {
        let publication_ready = !self.pending_publications.is_empty() &&
            self.publish_retry_deadline
                .is_none_or(|deadline| deadline <= Instant::now());
        self.control_read_pending ||
            self.event_coalescer.has_pending_client_acks() ||
            !self.pending_commands.is_empty() ||
            (!self.pending_controls.is_empty() &&
                self.control_retry_deadline
                    .is_none_or(|deadline| deadline <= Instant::now())) ||
            publication_ready ||
            (!self.pending_integrities.is_empty() &&
                !self.integrity_retry_blocked)
    }

    async fn wait_for_work(&mut self) -> QuicResult<()> {
        let deadline =
            match (self.control_retry_deadline, self.publish_retry_deadline) {
                (Some(control), Some(publication)) =>
                    Some(control.min(publication)),
                (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
                (None, None) => None,
            };
        if let Some(deadline) = deadline {
            select! {
                command = self.command_receiver.recv() => {
                    match command {
                        Some(command) => {
                            self.pending_commands.push_back(command);
                            Ok(())
                        },

                        None => {
                            #[allow(unreachable_code)]
                            {
                                pending::<()>().await;
                                Ok(())
                            }
                        },
                    }
                },

                _ = sleep_until(deadline) => Ok(()),
            }
        } else {
            match self.command_receiver.recv().await {
                Some(command) => {
                    self.pending_commands.push_back(command);
                    Ok(())
                },

                None => {
                    #[allow(unreachable_code)]
                    {
                        pending::<()>().await;
                        Ok(())
                    }
                },
            }
        }
    }

    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if !qconn.is_server() {
            return Err(Box::new(ServerError::ClientConnectionUnsupported));
        }

        if self.peer_supports_multicast(qconn) {
            self.initialize_channels(qconn)?;
            self.flush_pending_controls(qconn)?;
        }

        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let mut cursor = self.read_work_cursor;
        let work = run_callback_work(
            self.limits.max_work_per_call,
            &mut cursor,
            3,
            |class| match class {
                0 => self.process_one_control_frame(qconn),
                1 => self
                    .event_coalescer
                    .flush_client_acks(&self.event_sender, 1)
                    .map(|work| work > 0)
                    .map_err(Into::into),
                2 => self.flush_one_pending_server_control(qconn),
                _ => unreachable!("server read work class is in range"),
            },
        )?;
        self.read_work_cursor = cursor;
        self.control_read_pending = qconn.is_multicast_readable();

        #[cfg(test)]
        {
            self.callback_read_work_last_call = work;
        }

        debug_assert!(work <= self.limits.max_work_per_call);
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.integrity_retry_blocked = false;
        let mut cursor = self.write_work_cursor;
        let work = run_callback_work(
            self.limits.max_work_per_call,
            &mut cursor,
            5,
            |class| match class {
                0 => Ok(self.transfer_one_server_command()),
                1 => self.flush_one_pending_server_control(qconn),
                2 => self.encode_one_pending_command(qconn),
                3 => self.flush_one_pending_publication(),
                4 => self.flush_one_pending_server_integrity(qconn),
                _ => unreachable!("server write work class is in range"),
            },
        )?;
        self.write_work_cursor = cursor;

        #[cfg(test)]
        {
            self.callback_write_work_last_call = work;
        }

        debug_assert!(work <= self.limits.max_work_per_call);
        Ok(())
    }

    fn transfer_one_server_command(&mut self) -> bool {
        let Ok(command) = self.command_receiver.try_recv() else {
            return false;
        };
        self.pending_commands.push_back(command);
        true
    }

    fn process_one_control_frame(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        match qconn.multicast_recv() {
            Ok(frame) => {
                self.handle_frame(qconn, frame)?;
                Ok(true)
            },

            Err(quiche::Error::Done) => {
                self.control_read_pending = false;
                Ok(false)
            },

            Err(err) => Err(err.into()),
        }
    }

    fn initialize_channels(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if !self.channels.is_empty() {
            return Ok(());
        }

        for index in 0..self.settings.channels.len() {
            let channel_id = self.settings.channels[index].channel_id.clone();
            if !self.channels.contains_key(&channel_id) &&
                self.channels.len() >= self.limits.max_tracked_channel_ids
            {
                return Err(Box::new(ServerError::TrackedChannelIdLimit(
                    self.limits.max_tracked_channel_ids,
                )));
            }

            let (channel_id, max_ack_delay_ms, publication, control, send_state) = {
                let config = &self.settings.channels[index];
                let publication = self.backend.open(&config.publication)?;
                let (source, group, udp_port) =
                    self.backend.announce_tuple(&publication)?;
                let control =
                    config.control_channel_from(source, group, udp_port)?;
                let send_state = quiche::multicast::ChannelSendState::new(
                    control.announce.clone(),
                    control.key.clone(),
                )?;
                (
                    config.channel_id.clone(),
                    config.max_ack_delay_ms,
                    publication,
                    control,
                    send_state,
                )
            };

            if qconn.multicast_default_dgram_channel().is_none() {
                qconn.multicast_set_default_dgram_channel(Some(
                    channel_id.clone(),
                ))?;
            }
            qconn.multicast_set_ack_timeout(
                &channel_id,
                Some(server_ack_freshness_timeout(max_ack_delay_ms)),
            )?;

            self.queue_server_control(ServerPendingControl::AnnounceAndKey {
                announce: Some(control.announce),
                key: control.key,
            })?;

            self.channels.insert(channel_id, ServerChannel {
                publication,
                send_state,
                join_sent: false,
                join_pending: false,
            });
        }

        Ok(())
    }

    fn handle_frame(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Frame,
    ) -> QuicResult<()> {
        match frame {
            quiche::multicast::Frame::Limits(frame) => {
                self.handle_limits(qconn, frame)?;
            },

            quiche::multicast::Frame::State(frame) => {
                if frame.state == quiche::multicast::ChannelState::Retired {
                    self.event_coalescer.reset_channel(&frame.channel_id);
                }
                self.event_sender
                    .try_send(ServerEvent::ClientState(frame))?;
            },

            quiche::multicast::Frame::Ack(frame) => {
                if let Some(channel) = self.channels.get_mut(&frame.channel_id) {
                    channel.send_state.on_ack(&frame)?;
                    qconn.multicast_process_peer_ack(frame.clone())?;
                    self.event_coalescer
                        .queue_client_ack(&self.event_sender, frame);
                } else {
                    self.event_sender.try_send(ServerEvent::ClientAck(frame))?;
                }
            },

            quiche::multicast::Frame::Announce(..) |
            quiche::multicast::Frame::Key(..) |
            quiche::multicast::Frame::Join(..) |
            quiche::multicast::Frame::Leave(..) |
            quiche::multicast::Frame::Integrity(..) |
            quiche::multicast::Frame::Retire(..) => (),
        }

        Ok(())
    }

    fn handle_limits(
        &mut self, _qconn: &mut QuicheConnection,
        frame: quiche::multicast::Limits,
    ) -> QuicResult<()> {
        let sequence = frame.sequence;
        self.event_sender
            .try_send(ServerEvent::ClientLimits(frame))?;

        let channel_ids: Vec<Vec<u8>> = self.channels.keys().cloned().collect();
        for channel_id in channel_ids {
            let Some(channel) = self.channels.get(&channel_id) else {
                continue;
            };
            if channel.join_sent || channel.join_pending {
                continue;
            }

            let frame = quiche::multicast::Join {
                channel_id: channel.send_state.announce().channel_id.clone(),
                mc_limits_sequence: sequence,
                mc_state_sequence: 0,
                mc_key_sequence: channel.send_state.key().key_sequence,
            };
            self.queue_server_control(ServerPendingControl::Join(frame))?;
            self.channels
                .get_mut(&channel_id)
                .expect("channel was collected above")
                .join_pending = true;
        }

        Ok(())
    }

    fn queue_server_control(
        &mut self, command: ServerPendingControl,
    ) -> QuicResult<()> {
        let command = self.control_budget.wrap(command).map_err(|_| {
            Box::new(ServerError::RuntimeQueueExhausted("control"))
                as crate::result::BoxError
        })?;
        self.pending_controls.push_back(PendingServerControl {
            command,
            blocked_since: None,
        });
        Ok(())
    }

    fn flush_pending_controls(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        self.flush_pending_controls_with_limit(
            qconn,
            self.limits.max_work_per_call,
        )
        .map(|_| ())
    }

    fn flush_one_pending_server_control(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.flush_pending_controls_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    fn flush_pending_controls_with_limit(
        &mut self, qconn: &mut QuicheConnection, max_work: usize,
    ) -> QuicResult<usize> {
        if self
            .control_retry_deadline
            .is_some_and(|deadline| deadline > Instant::now())
        {
            return Ok(0);
        }
        self.control_retry_deadline = None;
        let mut work = 0;

        for _ in 0..max_work {
            let Some(mut pending) = self.pending_controls.pop_front() else {
                break;
            };
            work += 1;
            let command = pending.command.take();

            match command {
                ServerPendingControl::AnnounceAndKey {
                    announce: Some(announce),
                    key,
                } => match qconn.multicast_try_send(
                    quiche::multicast::Frame::Announce(announce),
                ) {
                    Ok(()) => {
                        pending.command.restore(
                            ServerPendingControl::AnnounceAndKey {
                                announce: None,
                                key,
                            },
                        );
                        pending.blocked_since = None;
                        self.pending_controls.push_front(pending);
                    },

                    Err(error)
                        if error.kind() ==
                            quiche::multicast::ControlSendErrorKind::Full =>
                    {
                        let quiche::multicast::Frame::Announce(announce) =
                            error.into_frame()
                        else {
                            unreachable!("core returned another frame");
                        };
                        pending.command.restore(
                            ServerPendingControl::AnnounceAndKey {
                                announce: Some(announce),
                                key,
                            },
                        );
                        self.retry_server_control(pending)?;
                        break;
                    },

                    Err(error) => return Err(Box::new(error)),
                },

                ServerPendingControl::AnnounceAndKey {
                    announce: None,
                    key,
                } => match qconn
                    .multicast_try_send(quiche::multicast::Frame::Key(key))
                {
                    Ok(()) => (),

                    Err(error)
                        if error.kind() ==
                            quiche::multicast::ControlSendErrorKind::Full =>
                    {
                        let quiche::multicast::Frame::Key(key) =
                            error.into_frame()
                        else {
                            unreachable!("core returned another frame");
                        };
                        pending.command.restore(
                            ServerPendingControl::AnnounceAndKey {
                                announce: None,
                                key,
                            },
                        );
                        self.retry_server_control(pending)?;
                        break;
                    },

                    Err(error) => return Err(Box::new(error)),
                },

                ServerPendingControl::Join(frame) => {
                    let channel_id = frame.channel_id.clone();
                    match qconn
                        .multicast_try_send(quiche::multicast::Frame::Join(frame))
                    {
                        Ok(()) => {
                            if let Some(channel) =
                                self.channels.get_mut(&channel_id)
                            {
                                channel.join_sent = true;
                                channel.join_pending = false;
                            }
                        },

                        Err(error)
                            if error.kind() ==
                                quiche::multicast::ControlSendErrorKind::Full =>
                        {
                            let quiche::multicast::Frame::Join(frame) =
                                error.into_frame()
                            else {
                                unreachable!("core returned another frame");
                            };
                            pending
                                .command
                                .restore(ServerPendingControl::Join(frame));
                            self.retry_server_control(pending)?;
                            break;
                        },

                        Err(error) => return Err(Box::new(error)),
                    }
                },
            }
        }

        Ok(work)
    }

    fn retry_server_control(
        &mut self, mut pending: PendingServerControl,
    ) -> QuicResult<()> {
        let now = Instant::now();
        let retry_deadline = now
            .checked_add(self.limits.control_retry_delay)
            .ok_or(quiche::Error::InvalidState)?;
        let blocked_since = *pending.blocked_since.get_or_insert(now);
        if now.saturating_duration_since(blocked_since) >=
            self.limits.control_backpressure_timeout
        {
            return Err(Box::new(ServerError::ControlBackpressureTimeout(
                self.limits.control_backpressure_timeout,
            )));
        }

        self.pending_controls.push_front(pending);
        self.control_retry_deadline = Some(retry_deadline);
        Ok(())
    }

    fn encode_one_pending_command(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        if !self.pending_controls.is_empty() {
            return Ok(false);
        }

        self.encode_pending_commands_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    fn encode_pending_commands_with_limit(
        &mut self, qconn: &mut QuicheConnection, max_work: usize,
    ) -> QuicResult<usize> {
        let mut work = 0;
        for _ in 0..max_work {
            let Some(command) = self.pending_commands.pop_front() else {
                break;
            };
            work += 1;
            match command.into_inner() {
                ServerCommand::Send { channel_id, frames } => {
                    let Some(channel) = self.channels.get_mut(&channel_id) else {
                        self.event_sender.try_send(ServerEvent::EncodeError {
                            channel_id,
                            error: quiche::Error::InvalidState,
                        })?;
                        continue;
                    };

                    for frame in &frames {
                        let quiche::multicast::ChannelFrame::Datagram { data } =
                            frame
                        else {
                            continue;
                        };

                        // DATAGRAM fallback is best-effort, matching the QUIC
                        // DATAGRAM API. Multicast publication and integrity
                        // relay still proceed even if the unicast queue is full.
                        let _ = qconn.multicast_dgram_send(&channel_id, data);
                    }

                    let packet_len = match channel.send_state.packet_len(&frames)
                    {
                        Ok(packet_len) => packet_len,

                        Err(error) => {
                            self.event_sender.try_send(
                                ServerEvent::EncodeError { channel_id, error },
                            )?;
                            continue;
                        },
                    };
                    let mut packet = vec![0; packet_len];

                    match channel.send_state.write_packet(&frames, &mut packet) {
                        Ok(output) => {
                            debug_assert_eq!(output.packet_len, packet_len);
                            packet.truncate(output.packet_len);
                            self.queue_publication(PendingPublication {
                                channel_id,
                                packet,
                                packet_number: output.packet_number,
                                integrity: output.integrity,
                            })?;
                        },

                        Err(error) => {
                            self.event_sender.try_send(
                                ServerEvent::EncodeError { channel_id, error },
                            )?;
                        },
                    }
                },

                ServerCommand::RelayIntegrity { frame } => {
                    self.queue_integrity(frame)?;
                },
            }
        }

        Ok(work)
    }

    fn flush_one_pending_publication(&mut self) -> QuicResult<bool> {
        self.flush_pending_publications_with_limit(1)
            .map(|work| work > 0)
    }

    fn flush_pending_publications_with_limit(
        &mut self, max_work: usize,
    ) -> QuicResult<usize> {
        if self
            .publish_retry_deadline
            .is_some_and(|deadline| deadline > Instant::now())
        {
            return Ok(0);
        }

        let mut work = 0;
        for _ in 0..max_work {
            let Some(pending) = self.pending_publications.pop_front() else {
                break;
            };
            work += 1;
            let Some(channel) = self.channels.get(&pending.channel_id) else {
                self.event_sender.try_send(ServerEvent::EncodeError {
                    channel_id: pending.channel_id,
                    error: quiche::Error::InvalidState,
                })?;
                continue;
            };

            match self.backend.send(&channel.publication, &pending.packet) {
                Ok(report) => {
                    self.queue_integrity(pending.integrity)?;
                    self.event_sender.try_send(ServerEvent::Published {
                        channel_id: pending.channel_id,
                        packet_number: pending.packet_number,
                        report,
                    })?;
                },

                Err(error) if publish_would_block(&error) => {
                    let retry_deadline = Instant::now()
                        .checked_add(PUBLISH_RETRY_DELAY)
                        .ok_or(quiche::Error::InvalidState)?;
                    self.pending_publications.push_front(pending).map_err(
                        |_| {
                            Box::new(ServerError::RuntimeQueueExhausted(
                                "publication",
                            ))
                                as crate::result::BoxError
                        },
                    )?;
                    self.publish_retry_deadline = Some(retry_deadline);
                    return Ok(work);
                },

                Err(error) => {
                    self.event_sender.try_send(ServerEvent::PublishError {
                        channel_id: pending.channel_id,
                        error,
                    })?;
                },
            }
        }

        if self.pending_publications.is_empty() {
            self.publish_retry_deadline = None;
        }

        Ok(work)
    }

    fn queue_publication(
        &mut self, pending: PendingPublication,
    ) -> QuicResult<()> {
        self.pending_publications.push_back(pending).map_err(|_| {
            Box::new(ServerError::RuntimeQueueExhausted("publication"))
                as crate::result::BoxError
        })
    }

    fn queue_integrity(
        &mut self, frame: quiche::multicast::Integrity,
    ) -> QuicResult<()> {
        self.pending_integrities.push_back(frame).map_err(|_| {
            Box::new(ServerError::RuntimeQueueExhausted("integrity"))
                as crate::result::BoxError
        })
    }

    fn flush_one_pending_server_integrity(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.flush_pending_integrities_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    fn flush_pending_integrities_with_limit(
        &mut self, qconn: &mut QuicheConnection, max_work: usize,
    ) -> QuicResult<usize> {
        let mut work = 0;
        for _ in 0..max_work {
            let Some(frame) = self.pending_integrities.pop_front() else {
                break;
            };
            work += 1;
            if let Err(error) = qconn
                .multicast_try_send(quiche::multicast::Frame::Integrity(frame))
            {
                if error.kind() != quiche::multicast::ControlSendErrorKind::Full {
                    return Err(Box::new(error));
                }
                let quiche::multicast::Frame::Integrity(frame) =
                    error.into_frame()
                else {
                    unreachable!("core returned another frame");
                };
                self.pending_integrities.push_front(frame).map_err(|_| {
                    Box::new(ServerError::RuntimeQueueExhausted("integrity"))
                        as crate::result::BoxError
                })?;
                self.integrity_retry_blocked = true;
                break;
            }
        }

        Ok(work)
    }

    fn peer_supports_multicast(&self, qconn: &QuicheConnection) -> bool {
        qconn
            .peer_transport_params()
            .and_then(|params| params.multicast_client_params.as_ref())
            .is_some()
    }
}

struct ServerChannel<P> {
    publication: P,
    send_state: quiche::multicast::ChannelSendState,
    join_sent: bool,
    join_pending: bool,
}

trait PublishBackend {
    type Publication;

    fn open(
        &mut self, config: &PublicationConfig,
    ) -> Result<Self::Publication, MctxError>;

    fn announce_tuple(
        &self, publication: &Self::Publication,
    ) -> Result<(Ipv4Addr, Ipv4Addr, u16), MctxError>;

    fn send(
        &self, publication: &Self::Publication, payload: &[u8],
    ) -> Result<SendReport, MctxError>;
}

struct MctxPublishBackend;

impl PublishBackend for MctxPublishBackend {
    type Publication = Publication;

    fn open(
        &mut self, config: &PublicationConfig,
    ) -> Result<Self::Publication, MctxError> {
        mctx_core::Publication::new(mctx_core::PublicationId(0), config.clone())
    }

    fn announce_tuple(
        &self, publication: &Self::Publication,
    ) -> Result<(Ipv4Addr, Ipv4Addr, u16), MctxError> {
        match publication.announce_tuple()? {
            (IpAddr::V4(source), IpAddr::V4(group), udp_port) =>
                Ok((source, group, udp_port)),

            _ => Err(MctxError::OutgoingInterfaceFamilyMismatch),
        }
    }

    fn send(
        &self, publication: &Self::Publication, payload: &[u8],
    ) -> Result<SendReport, MctxError> {
        publication.send(payload)
    }
}

fn publish_would_block(error: &MctxError) -> bool {
    matches!(error, MctxError::SendFailed(err) if err.kind() == std::io::ErrorKind::WouldBlock)
}

fn server_ack_freshness_timeout(max_ack_delay_ms: u64) -> Duration {
    Duration::from_millis(
        max_ack_delay_ms.saturating_mul(SERVER_ACK_FRESHNESS_TIMEOUT_MULTIPLIER),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Wake;
    use std::task::Waker;

    use bytes::Bytes;

    use crate::buf_factory::BufFactory;

    type Pipe = quiche::test_utils::Pipe<BufFactory>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct JoinRequest {
        channel_id: Vec<u8>,
        source: Ipv4Addr,
        group: Ipv4Addr,
        udp_port: u16,
        interface: Option<Ipv4Addr>,
    }

    #[derive(Clone, Debug, Default)]
    struct FakeJoinBackend {
        joins: Arc<Mutex<Vec<JoinRequest>>>,
    }

    #[derive(Debug)]
    struct FakeHandle;

    impl JoinBackend for FakeJoinBackend {
        type Handle = FakeHandle;

        fn join_ipv4(
            &mut self, channel_id: &[u8], source: Ipv4Addr, group: Ipv4Addr,
            udp_port: u16, interface: Option<Ipv4Addr>,
            _ingress_sender: BoundedSender<IngressEvent>,
        ) -> Result<Self::Handle, JoinError> {
            self.joins.lock().unwrap().push(JoinRequest {
                channel_id: channel_id.to_vec(),
                source,
                group,
                udp_port,
                interface,
            });

            Ok(FakeHandle)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct PublishRecord {
        source: Ipv4Addr,
        group: Ipv4Addr,
        udp_port: u16,
        payload: Vec<u8>,
    }

    #[derive(Clone, Debug, Default)]
    struct FakePublishBackend {
        sent: Arc<Mutex<Vec<PublishRecord>>>,
    }

    #[derive(Clone, Debug)]
    struct FakePublication {
        source: Ipv4Addr,
        group: Ipv4Addr,
        udp_port: u16,
    }

    impl PublishBackend for FakePublishBackend {
        type Publication = FakePublication;

        fn open(
            &mut self, config: &PublicationConfig,
        ) -> Result<Self::Publication, MctxError> {
            Ok(FakePublication {
                source: match config.source_addr {
                    Some(IpAddr::V4(source)) => source,
                    _ => Ipv4Addr::new(10, 0, 0, 1),
                },
                group: match config.group {
                    IpAddr::V4(group) => group,
                    IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                },
                udp_port: config.dst_port,
            })
        }

        fn announce_tuple(
            &self, publication: &Self::Publication,
        ) -> Result<(Ipv4Addr, Ipv4Addr, u16), MctxError> {
            Ok((publication.source, publication.group, publication.udp_port))
        }

        fn send(
            &self, publication: &Self::Publication, payload: &[u8],
        ) -> Result<SendReport, MctxError> {
            self.sent.lock().unwrap().push(PublishRecord {
                source: publication.source,
                group: publication.group,
                udp_port: publication.udp_port,
                payload: payload.to_vec(),
            });

            Ok(SendReport {
                publication_id: mctx_core::PublicationId(0),
                destination: std::net::SocketAddr::V4(
                    std::net::SocketAddrV4::new(
                        publication.group,
                        publication.udp_port,
                    ),
                ),
                local_addr: Some(std::net::SocketAddr::V4(
                    std::net::SocketAddrV4::new(publication.source, 0),
                )),
                source_addr: Some(IpAddr::V4(publication.source)),
                bytes_sent: payload.len(),
            })
        }
    }

    fn test_transport_params() -> quiche::multicast::ClientTransportParams {
        quiche::multicast::ClientTransportParams {
            limits: quiche::multicast::ClientLimits {
                ipv6_channels_allowed: false,
                ipv4_channels_allowed: true,
                max_aggregate_rate_kibps: 8192,
                max_channel_ids: 16,
            },
            hash_algorithms: vec![1],
            encryption_algorithms: vec![0x1301],
        }
    }

    fn test_settings() -> ClientSettings {
        ClientSettings {
            transport_params: test_transport_params(),
            max_joined_channels: 4,
            ipv4_interface: None,
            ipv6_interface: None,
        }
    }

    fn test_pipe(settings: &ClientSettings) -> Pipe {
        test_pipe_with_server_control_queue(settings, 1024, 2 * 1024 * 1024)
    }

    fn test_pipe_with_server_control_queue(
        settings: &ClientSettings, max_frames: usize, max_bytes: usize,
    ) -> Pipe {
        let mut client_config =
            quiche::test_utils::Pipe::default_config("cubic").unwrap();
        client_config.enable_dgram(true, 10, 10);
        client_config
            .set_multicast_client_params(Some(settings.transport_params.clone()))
            .unwrap();

        let mut server_config =
            quiche::test_utils::Pipe::default_config("cubic").unwrap();
        server_config.enable_dgram(true, 10, 10);
        server_config.enable_multicast_server_support(true);
        server_config.set_multicast_send_queue_limits(max_frames, max_bytes);

        let mut pipe = Pipe::with_client_and_server_config_and_buf(
            &mut client_config,
            &mut server_config,
        )
        .unwrap();
        pipe.handshake().unwrap();

        pipe
    }

    fn test_stream_pipe(settings: &ClientSettings) -> Pipe {
        test_stream_pipe_with_max_streams_uni(settings, 3)
    }

    fn test_stream_pipe_with_max_streams_uni(
        settings: &ClientSettings, max_streams_uni: u64,
    ) -> Pipe {
        test_stream_pipe_with_flow_control(settings, max_streams_uni, 4096)
    }

    fn test_stream_pipe_with_flow_control(
        settings: &ClientSettings, max_streams_uni: u64, max_data: u64,
    ) -> Pipe {
        let mut client_config =
            quiche::test_utils::Pipe::default_config("cubic").unwrap();
        client_config.enable_dgram(true, 10, 10);
        client_config.set_initial_max_data(max_data);
        client_config.set_initial_max_stream_data_uni(max_data);
        client_config.set_initial_max_streams_uni(max_streams_uni);
        client_config
            .set_multicast_client_params(Some(settings.transport_params.clone()))
            .unwrap();

        let mut server_config =
            quiche::test_utils::Pipe::default_config("cubic").unwrap();
        server_config.enable_dgram(true, 10, 10);
        server_config.enable_multicast_server_support(true);
        server_config.set_initial_max_data(max_data);
        server_config.set_initial_max_stream_data_uni(max_data);

        let mut pipe = Pipe::with_client_and_server_config_and_buf(
            &mut client_config,
            &mut server_config,
        )
        .unwrap();
        pipe.handshake().unwrap();

        pipe
    }

    fn test_ipv4_announce() -> quiche::multicast::Announce {
        quiche::multicast::Announce {
            channel_id: vec![1, 2, 3, 4],
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            udp_port: 4444,
            header_protection_algorithm: 0x1301,
            header_secret: vec![0xaa; 16],
            aead_algorithm: 0x1301,
            integrity_hash_algorithm: 1,
            max_rate_kibps: 1024,
            max_ack_delay_ms: 25,
        }
    }

    fn test_ipv6_announce() -> quiche::multicast::Announce {
        quiche::multicast::Announce {
            channel_id: vec![7, 8, 9, 0],
            source: IpAddr::V6("2001:db8::1".parse().unwrap()),
            group: IpAddr::V6("ff3e::8000:1".parse().unwrap()),
            udp_port: 5555,
            header_protection_algorithm: 0x1301,
            header_secret: vec![0xbb; 16],
            aead_algorithm: 0x1301,
            integrity_hash_algorithm: 1,
            max_rate_kibps: 2048,
            max_ack_delay_ms: 25,
        }
    }

    fn test_key(channel_id: &[u8]) -> quiche::multicast::Key {
        quiche::multicast::Key {
            channel_id: channel_id.to_vec(),
            key_sequence: 1,
            from_packet_number: 0,
            secret: vec![0xcc; 16],
        }
    }

    fn test_limits() -> quiche::multicast::Limits {
        quiche::multicast::Limits {
            sequence: 1,
            limits: test_transport_params().limits,
            max_joined_count: 4,
        }
    }

    fn test_server_settings() -> ServerSettings {
        ServerSettings {
            channels: vec![ServerChannelConfig {
                channel_id: vec![1, 2, 3, 4],
                publication: PublicationConfig::new(
                    Ipv4Addr::new(232, 1, 2, 3),
                    4444,
                )
                .with_source_addr(Ipv4Addr::new(10, 0, 0, 1)),
                header_protection_algorithm: 0x1301,
                header_secret: vec![0xaa; 16],
                aead_algorithm: 0x1301,
                integrity_hash_algorithm: 1,
                max_rate_kibps: 1024,
                max_ack_delay_ms: 25,
                key_sequence: 1,
                from_packet_number: 0,
                secret: vec![0xcc; 16],
            }],
        }
    }

    fn test_server_control_settings() -> ServerControlSettings {
        ServerControlSettings {
            mode: ServerControlMode::Automatic,
            channels: vec![ServerControlChannelConfig {
                announce: test_ipv4_announce(),
                key: test_key(&[1, 2, 3, 4]),
            }],
            stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
        }
    }

    fn test_client_event_channel() -> (
        ManagedEventSender<ClientEvent>,
        ClientEventStream,
        EventQueueObserver<ClientEvent>,
    ) {
        client_event_channel(EventQueueLimits::default())
    }

    fn test_server_event_channel() -> (
        ManagedEventSender<ServerEvent>,
        ServerEventStream,
        EventQueueObserver<ServerEvent>,
    ) {
        server_event_channel(EventQueueLimits::default())
    }

    #[test]
    fn client_maintenance_budget_is_aggregate_and_fair() {
        const CHANNELS: usize = 300;
        const BUDGET: usize = 32;

        let mut settings = test_settings();
        settings.transport_params.limits.max_channel_ids = CHANNELS as u64;
        settings.max_joined_channels = CHANNELS as u64;
        let (event_sender, _events, _) = test_client_event_channel();
        let limits = RuntimeLimits {
            max_work_per_call: BUDGET,
            ..RuntimeLimits::default()
        };
        let mut runtime = ClientRuntime::with_backend_and_limits(
            settings.clone(),
            event_sender,
            FakeJoinBackend::default(),
            limits,
        );

        for index in 0..CHANNELS {
            let channel_id = (index as u32).to_be_bytes().to_vec();
            let mut announce = test_ipv4_announce();
            announce.channel_id = channel_id.clone();
            let mut receiver = quiche::multicast::ChannelReceiveState::<
                PacketWithMetadata,
            >::new(announce.clone())
            .unwrap();
            receiver
                .insert_integrity(quiche::multicast::Integrity {
                    channel_id: channel_id.clone(),
                    packet_number_start: 0,
                    packet_hash_count: Some(257),
                    packet_hashes: vec![0; 257 * 32],
                })
                .unwrap();
            assert!(receiver.has_pending_work());

            let mut channel = Channel::default();
            channel.announce = Some(announce);
            channel.receive_state = Some(receiver);
            runtime.channels.insert(channel_id, channel);
        }

        let mut pipe = test_pipe(&settings);
        let max_passes = (CHANNELS * 4).div_ceil(BUDGET);
        let mut passes = 0;
        while runtime.channels.values().any(|channel| {
            channel
                .receive_state
                .as_ref()
                .is_some_and(|receiver| receiver.has_pending_work())
        }) {
            runtime.process_reads(&mut pipe.client).unwrap();
            passes += 1;
            assert!(
                runtime.callback_read_work_last_call <= BUDGET,
                "one complete callback exceeded the aggregate work budget"
            );
            assert!(passes <= max_passes, "maintenance failed to converge");
        }

        assert!(runtime.channels.values().all(|channel| {
            !channel.receive_state.as_ref().unwrap().has_pending_work()
        }));
        assert_eq!(
            runtime.receiver_maintenance_cursor,
            Some(((CHANNELS - 1) as u32).to_be_bytes().to_vec())
        );
    }

    #[test]
    fn client_callbacks_share_one_budget_across_adversarial_phase_backlog() {
        let (mut runtime, mut pipe, _events, announce) = joined_client_runtime();
        let channel_id = announce.channel_id.clone();
        runtime.limits.max_work_per_call = 4;
        runtime.read_work_cursor = 0;

        runtime
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .receive_state
            .as_mut()
            .unwrap()
            .insert_integrity_with_budget(
                quiche::multicast::Integrity {
                    channel_id: channel_id.clone(),
                    packet_number_start: 100,
                    packet_hash_count: Some(2),
                    packet_hashes: vec![0; 64],
                },
                1,
                1,
            )
            .unwrap();
        runtime
            .ingress_sender
            .try_send(IngressEvent::Overload {
                channel_id: vec![9],
                retained_bytes: 1,
                max_retained_bytes: 1,
            })
            .unwrap();
        assert!(runtime.transfer_one_ingress());
        runtime
            .ingress_sender
            .try_send(IngressEvent::Overload {
                channel_id: vec![8],
                retained_bytes: 1,
                max_retained_bytes: 1,
            })
            .unwrap();

        let mut key = test_key(&channel_id);
        key.key_sequence = 2;
        key.from_packet_number = 100;
        pipe.server
            .multicast_send(quiche::multicast::Frame::Key(key))
            .unwrap();
        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        let work_before = runtime.channels[&channel_id]
            .receive_state
            .as_ref()
            .unwrap()
            .metrics_snapshot()
            .work_performed;
        assert_eq!(runtime.pending_ingress.len(), 1);
        assert_eq!(runtime.ingress_observer.stats().retained_items, 2);
        assert_eq!(pipe.client.multicast_recv_queue_len(), 1);

        runtime.process_reads(&mut pipe.client).unwrap();

        assert_eq!(runtime.callback_read_work_last_call, 4);
        assert!(
            runtime.channels[&channel_id]
                .receive_state
                .as_ref()
                .unwrap()
                .metrics_snapshot()
                .work_performed >
                work_before
        );
        assert_eq!(runtime.pending_ingress.len(), 1);
        assert_eq!(runtime.ingress_observer.stats().retained_items, 1);
        assert_eq!(pipe.client.multicast_recv_queue_len(), 0);

        for _ in 0..16 {
            if !runtime.has_pending_work() && !pipe.client.is_multicast_readable()
            {
                break;
            }
            runtime.process_reads(&mut pipe.client).unwrap();
            assert!(runtime.callback_read_work_last_call <= 4);
        }
        assert!(!runtime.has_pending_work());
        assert!(!pipe.client.is_multicast_readable());

        let (mut runtime, mut pipe, _events, announce) = joined_client_runtime();
        let channel_id = announce.channel_id.clone();
        runtime.limits.max_work_per_call = 5;
        runtime.write_work_cursor = 0;
        runtime
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .receive_state
            .as_mut()
            .unwrap()
            .insert_integrity_with_budget(
                quiche::multicast::Integrity {
                    channel_id: channel_id.clone(),
                    packet_number_start: 200,
                    packet_hash_count: Some(2),
                    packet_hashes: vec![0; 64],
                },
                1,
                1,
            )
            .unwrap();
        runtime
            .ingress_sender
            .try_send(IngressEvent::Overload {
                channel_id: vec![9],
                retained_bytes: 1,
                max_retained_bytes: 1,
            })
            .unwrap();
        assert!(runtime.transfer_one_ingress());
        runtime
            .ingress_sender
            .try_send(IngressEvent::Overload {
                channel_id: vec![8],
                retained_bytes: 1,
                max_retained_bytes: 1,
            })
            .unwrap();
        assert!(runtime
            .pending_control
            .push_back(PendingClientControl {
                frame: ClientControlFrame::Limits {
                    frame: test_limits(),
                    commit: Some(test_limits()),
                },
                blocked_since: None,
            })
            .is_ok());
        runtime
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .ack_state
            .record_packet(1);

        runtime.process_writes(&mut pipe.client).unwrap();

        assert_eq!(runtime.callback_write_work_last_call, 5);
        assert_eq!(runtime.pending_ingress.len(), 1);
        assert_eq!(runtime.ingress_observer.stats().retained_items, 1);
        assert!(runtime.pending_control.is_empty());
        assert!(!runtime.channels[&channel_id].ack_state.has_pending_ack());
    }

    fn seed_server_control_callback_backlog(
        runtime: &mut ServerControlRuntime,
        command_sender: &BoundedSender<ServerControlCommand>, pipe: &mut Pipe,
    ) {
        let publisher_channel_id = vec![2];
        let publisher_queue =
            Arc::new(server_stream::ServerStreamPublisherQueue::new(
                publisher_channel_id.clone(),
                server_stream::ServerStreamPublisherLimits::default(),
            ));
        publisher_queue.seal();
        runtime
            .channels
            .insert(publisher_channel_id, ServerControlChannel {
                stream_publisher: true,
                stream_publication_queue: Some(publisher_queue),
                ..ServerControlChannel::default()
            });

        let mut pending_announce = test_ipv4_announce();
        pending_announce.channel_id = vec![8];
        runtime
            .queue_command_back(ServerControlCommand::SendAnnounce {
                frame: pending_announce,
                cached: None,
            })
            .unwrap();
        let mut incoming_announce = test_ipv4_announce();
        incoming_announce.channel_id = vec![9];
        assert!(command_sender
            .try_send(ServerControlCommand::SendAnnounce {
                frame: incoming_announce,
                cached: None,
            })
            .is_ok());

        assert_eq!(pipe.server.stream_send(3, b"p", false), Ok(1));
        let publication_channel_id = vec![3];
        runtime
            .channels
            .entry(publication_channel_id.clone())
            .or_default();
        runtime
            .pending_stream_publications
            .push(Arc::new(server_stream::CommittedServerStreamPublication {
                packet_number: 0,
                integrity: quiche::multicast::Integrity {
                    channel_id: publication_channel_id,
                    packet_number_start: 0,
                    packet_hash_count: Some(1),
                    packet_hashes: vec![0xaa; 32],
                },
                frame: ServerStreamFrame {
                    stream_id: 3,
                    offset: 1,
                    fin: false,
                    data: Bytes::from_static(b"x"),
                },
            }))
            .unwrap();

        let due_channel_id = vec![5];
        runtime
            .store_stream_integrity_batch(
                due_channel_id.clone(),
                PendingStreamIntegrityBatch {
                    frame: quiche::multicast::Integrity {
                        channel_id: due_channel_id,
                        packet_number_start: 0,
                        packet_hash_count: Some(1),
                        packet_hashes: vec![0xbb; 32],
                    },
                    hash_len: 32,
                    deadline: Instant::now(),
                },
            )
            .unwrap();
        let mut pending_integrity = test_stream_integrity(0, 0xcc);
        pending_integrity.channel_id = vec![6];
        runtime.queue_integrity(pending_integrity).unwrap();

        assert_eq!(pipe.server.stream_send(7, b"p", false), Ok(1));
        pipe.server
            .multicast_stream_send(&[4], 0, 7, 1, b"m", false)
            .unwrap();
        pipe.server
            .multicast_probe_start(&[7], Duration::from_secs(1))
            .unwrap();
    }

    fn server_control_callback_backlog_drained(
        runtime: &ServerControlRuntime, pipe: &Pipe,
    ) -> bool {
        !runtime.has_pending_work() &&
            !pipe.server.is_multicast_stream_delivery_metrics_readable() &&
            !pipe.server.is_multicast_probe_readable() &&
            !pipe.server.is_multicast_readable()
    }

    #[test]
    fn server_control_callbacks_share_one_budget_across_adversarial_backlog() {
        let limits = RuntimeLimits {
            max_work_per_call: 8,
            ..RuntimeLimits::default()
        };
        let (command_sender, command_receiver, _command_observer) =
            bounded_channel(limits.commands);
        let (event_sender, _events, _) = test_server_event_channel();
        let mut runtime = ServerControlRuntime::with_limits(
            ServerControlSettings::default(),
            event_sender,
            command_receiver,
            limits,
        );
        let mut pipe = test_stream_pipe(&test_settings());
        runtime.on_conn_established(&mut pipe.server).unwrap();
        seed_server_control_callback_backlog(
            &mut runtime,
            &command_sender,
            &mut pipe,
        );

        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(runtime.callback_write_work_last_call, 8);
        assert!(runtime.command_receiver.try_recv().is_err());
        assert!(runtime.pending_stream_integrity_batches.is_empty());
        assert_eq!(pipe.server.multicast_probe_queue_len(), 1);

        for _ in 0..64 {
            if server_control_callback_backlog_drained(&runtime, &pipe) {
                break;
            }
            runtime.process_reads(&mut pipe.server).unwrap();
            assert!(runtime.callback_read_work_last_call <= 8);
            runtime.process_writes(&mut pipe.server).unwrap();
            assert!(runtime.callback_write_work_last_call <= 8);
        }
        assert!(server_control_callback_backlog_drained(&runtime, &pipe));

        let limits = RuntimeLimits {
            max_work_per_call: 10,
            ..RuntimeLimits::default()
        };
        let (command_sender, command_receiver, _command_observer) =
            bounded_channel(limits.commands);
        let (event_sender, _events, _) = test_server_event_channel();
        let mut runtime = ServerControlRuntime::with_limits(
            ServerControlSettings::default(),
            event_sender,
            command_receiver,
            limits,
        );
        let mut pipe = test_stream_pipe(&test_settings());
        runtime.on_conn_established(&mut pipe.server).unwrap();
        seed_server_control_callback_backlog(
            &mut runtime,
            &command_sender,
            &mut pipe,
        );
        runtime.event_coalescer.queue_client_ack(
            &runtime.event_sender,
            quiche::multicast::Ack {
                channel_id: vec![10],
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            },
        );
        pipe.client
            .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
            .unwrap();
        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        runtime.process_reads(&mut pipe.server).unwrap();

        assert_eq!(runtime.callback_read_work_last_call, 10);
        assert!(runtime.command_receiver.try_recv().is_err());
        assert!(runtime
            .event_coalescer
            .last_client_acks
            .contains_key(&[10][..]));
        assert_eq!(
            runtime
                .event_coalescer
                .pending_client_acks
                .values()
                .map(VecDeque::len)
                .sum::<usize>(),
            1
        );
        assert!(runtime.pending_stream_integrity_batches.is_empty());
        assert_eq!(pipe.server.multicast_probe_queue_len(), 1);

        for _ in 0..64 {
            if server_control_callback_backlog_drained(&runtime, &pipe) {
                break;
            }
            runtime.process_writes(&mut pipe.server).unwrap();
            assert!(runtime.callback_write_work_last_call <= 10);
            runtime.process_reads(&mut pipe.server).unwrap();
            assert!(runtime.callback_read_work_last_call <= 10);
        }
        assert!(server_control_callback_backlog_drained(&runtime, &pipe));
    }

    #[derive(Default)]
    enum ProbeTestAction {
        #[default]
        None,
        Start(Vec<u8>),
        Drain,
    }

    #[derive(Default)]
    struct ProbeReadinessTestApp {
        established_action: ProbeTestAction,
        read_action: ProbeTestAction,
        output: Vec<u8>,
    }

    impl ProbeReadinessTestApp {
        fn apply_action(
            action: &mut ProbeTestAction, qconn: &mut QuicheConnection,
        ) -> QuicResult<()> {
            match std::mem::take(action) {
                ProbeTestAction::None => {},

                ProbeTestAction::Start(channel_id) => {
                    qconn.multicast_probe_start(
                        &channel_id,
                        Duration::from_secs(1),
                    )?;
                },

                ProbeTestAction::Drain => loop {
                    match qconn.multicast_probe_recv() {
                        Ok(_) => {},
                        Err(quiche::Error::Done) => break,
                        Err(error) => return Err(error.into()),
                    }
                },
            }

            Ok(())
        }
    }

    impl ApplicationOverQuic for ProbeReadinessTestApp {
        fn on_conn_established(
            &mut self, qconn: &mut QuicheConnection,
            _handshake_info: &crate::quic::HandshakeInfo,
        ) -> QuicResult<()> {
            Self::apply_action(&mut self.established_action, qconn)
        }

        fn should_act(&self) -> bool {
            true
        }

        fn buffer(&mut self) -> &mut [u8] {
            &mut self.output
        }

        fn wait_for_data(
            &mut self, _qconn: &mut QuicheConnection,
        ) -> impl Future<Output = QuicResult<()>> + Send {
            pending()
        }

        fn process_reads(
            &mut self, qconn: &mut QuicheConnection,
        ) -> QuicResult<()> {
            Self::apply_action(&mut self.read_action, qconn)
        }

        fn process_writes(
            &mut self, _qconn: &mut QuicheConnection,
        ) -> QuicResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn server_control_driver_resyncs_inner_probe_creation() {
        const BUDGET: usize = 1;

        let app = ProbeReadinessTestApp {
            established_action: ProbeTestAction::Start(vec![1]),
            ..ProbeReadinessTestApp::default()
        };
        let limits = RuntimeLimits {
            max_work_per_call: BUDGET,
            ..RuntimeLimits::default()
        };
        let (mut driver, _controller) =
            ServerControlDriver::new_with_runtime_limits(
                app,
                ServerControlSettings::default(),
                limits,
            )
            .unwrap();
        let mut pipe = test_pipe(&test_settings());
        let handshake_info =
            crate::quic::HandshakeInfo::new(std::time::Instant::now(), None);

        driver
            .on_conn_established(&mut pipe.server, &handshake_info)
            .unwrap();

        assert!(pipe.server.is_multicast_probe_readable());
        assert!(driver.runtime.probe_read_pending);
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_millis(1),
                driver.wait_for_data(&mut pipe.server)
            )
            .await,
            Ok(Ok(()))
        ));

        driver.process_writes(&mut pipe.server).unwrap();
        assert_eq!(driver.runtime.callback_write_work_last_call, BUDGET);
        assert!(!pipe.server.is_multicast_probe_readable());
        assert!(!driver.runtime.probe_read_pending);

        driver.inner_mut().read_action = ProbeTestAction::Start(vec![2]);
        driver.process_reads(&mut pipe.server).unwrap();

        assert_eq!(driver.runtime.callback_read_work_last_call, 0);
        assert!(pipe.server.is_multicast_probe_readable());
        assert!(driver.runtime.probe_read_pending);
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_millis(1),
                driver.wait_for_data(&mut pipe.server)
            )
            .await,
            Ok(Ok(()))
        ));

        driver.process_writes(&mut pipe.server).unwrap();
        assert!(driver.runtime.callback_write_work_last_call <= BUDGET);
        assert!(!driver.runtime.probe_read_pending);

        pipe.server
            .multicast_probe_start(&[3], Duration::from_secs(1))
            .unwrap();
        assert!(!driver.runtime.probe_read_pending);
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_millis(1),
                driver.wait_for_data(&mut pipe.server)
            )
            .await,
            Ok(Ok(()))
        ));
    }

    #[tokio::test]
    async fn server_control_driver_clears_probe_readiness_after_inner_drain() {
        const BUDGET: usize = 1;

        let app = ProbeReadinessTestApp {
            read_action: ProbeTestAction::Drain,
            ..ProbeReadinessTestApp::default()
        };
        let limits = RuntimeLimits {
            max_work_per_call: BUDGET,
            ..RuntimeLimits::default()
        };
        let (mut driver, _controller) =
            ServerControlDriver::new_with_runtime_limits(
                app,
                ServerControlSettings::default(),
                limits,
            )
            .unwrap();
        let mut pipe = test_pipe(&test_settings());
        let handshake_info =
            crate::quic::HandshakeInfo::new(std::time::Instant::now(), None);
        driver
            .on_conn_established(&mut pipe.server, &handshake_info)
            .unwrap();

        pipe.server
            .multicast_probe_start(&[1], Duration::from_secs(1))
            .unwrap();
        pipe.client
            .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
            .unwrap();
        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        driver.process_reads(&mut pipe.server).unwrap();

        assert_eq!(driver.runtime.callback_read_work_last_call, BUDGET);
        assert_eq!(pipe.server.multicast_probe_queue_len(), 0);
        assert!(!driver.runtime.probe_read_pending);
        assert!(!driver.runtime.has_pending_work());
        assert!(tokio::time::timeout(
            Duration::from_millis(1),
            driver.wait_for_data(&mut pipe.server)
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn server_control_probe_backlog_keeps_wait_path_runnable() {
        const BUDGET: usize = 2;
        const PROBE_EVENTS: u8 = 5;

        let limits = RuntimeLimits {
            max_work_per_call: BUDGET,
            ..RuntimeLimits::default()
        };
        let (_command_sender, command_receiver, _command_observer) =
            bounded_channel(limits.commands);
        let (event_sender, mut events, _) = test_server_event_channel();
        let mut runtime = ServerControlRuntime::with_limits(
            ServerControlSettings::default(),
            event_sender,
            command_receiver,
            limits,
        );
        let mut pipe = test_pipe(&test_settings());
        runtime.on_conn_established(&mut pipe.server).unwrap();

        for channel_id in 1..=PROBE_EVENTS {
            pipe.server
                .multicast_probe_start(&[channel_id], Duration::from_secs(1))
                .unwrap();
        }
        assert!(!runtime.probe_read_pending);
        assert_eq!(
            pipe.server.multicast_probe_queue_len(),
            usize::from(PROBE_EVENTS)
        );

        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(runtime.callback_write_work_last_call, BUDGET);
        assert_eq!(
            pipe.server.multicast_probe_queue_len(),
            usize::from(PROBE_EVENTS) - BUDGET
        );
        assert!(runtime.probe_read_pending);
        assert!(runtime.has_pending_work());

        let wait = async {
            if runtime.has_pending_work() {
                Ok(())
            } else {
                runtime.wait_for_work().await
            }
        };
        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(1), wait).await,
            Ok(Ok(()))
        ));

        while pipe.server.is_multicast_probe_readable() {
            runtime.process_writes(&mut pipe.server).unwrap();
            assert!(runtime.callback_write_work_last_call <= BUDGET);
        }
        assert_eq!(pipe.server.multicast_probe_queue_len(), 0);
        assert!(!runtime.probe_read_pending);
        assert!(!runtime.has_pending_work());

        let mut delivered = 0;
        while let Ok(event) = events.try_recv() {
            if matches!(event, ServerEvent::ProbeStatusChanged(_)) {
                delivered += 1;
            }
        }
        assert_eq!(delivered, usize::from(PROBE_EVENTS));
    }

    fn publishing_server_runtime(
        max_work_per_call: usize,
    ) -> (
        ServerRuntime<FakePublishBackend>,
        BoundedSender<ServerCommand>,
        ServerEventStream,
        Pipe,
    ) {
        let limits = RuntimeLimits {
            max_work_per_call,
            ..RuntimeLimits::default()
        };
        let (command_sender, command_receiver, _) =
            bounded_channel(limits.commands);
        let (event_sender, events, _) = test_server_event_channel();
        let mut runtime = ServerRuntime::with_backend_and_limits(
            test_server_settings(),
            event_sender,
            command_receiver,
            FakePublishBackend::default(),
            limits,
        );
        let mut pipe = test_pipe(&test_settings());
        runtime.on_conn_established(&mut pipe.server).unwrap();

        (runtime, command_sender, events, pipe)
    }

    #[test]
    fn publishing_server_callbacks_share_one_budget_across_adversarial_backlog() {
        let (mut runtime, command_sender, _events, mut pipe) =
            publishing_server_runtime(5);
        let channel_id = vec![1, 2, 3, 4];
        let mut first_integrity = test_stream_integrity(10, 0xaa);
        first_integrity.channel_id = channel_id.clone();
        assert!(command_sender
            .try_send(ServerCommand::RelayIntegrity {
                frame: first_integrity,
            })
            .is_ok());
        assert!(runtime.transfer_one_server_command());
        let mut second_integrity = test_stream_integrity(11, 0xbb);
        second_integrity.channel_id = channel_id.clone();
        assert!(command_sender
            .try_send(ServerCommand::RelayIntegrity {
                frame: second_integrity,
            })
            .is_ok());
        runtime
            .queue_server_control(ServerPendingControl::Join(
                quiche::multicast::Join {
                    channel_id: channel_id.clone(),
                    mc_limits_sequence: 0,
                    mc_state_sequence: 0,
                    mc_key_sequence: 1,
                },
            ))
            .unwrap();
        let mut publication_integrity = test_stream_integrity(12, 0xcc);
        publication_integrity.channel_id = channel_id.clone();
        runtime
            .queue_publication(PendingPublication {
                channel_id: channel_id.clone(),
                packet: vec![1, 2, 3],
                packet_number: 12,
                integrity: publication_integrity,
            })
            .unwrap();
        let mut pending_integrity = test_stream_integrity(13, 0xdd);
        pending_integrity.channel_id = channel_id.clone();
        runtime.queue_integrity(pending_integrity).unwrap();

        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(runtime.callback_write_work_last_call, 5);
        assert!(runtime.command_receiver.try_recv().is_err());
        for _ in 0..32 {
            if !runtime.has_pending_work() {
                break;
            }
            runtime.process_writes(&mut pipe.server).unwrap();
            assert!(runtime.callback_write_work_last_call <= 5);
        }
        assert!(!runtime.has_pending_work());

        let (mut runtime, _command_sender, _events, mut pipe) =
            publishing_server_runtime(3);
        runtime.event_coalescer.queue_client_ack(
            &runtime.event_sender,
            quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            },
        );
        runtime
            .queue_server_control(ServerPendingControl::Join(
                quiche::multicast::Join {
                    channel_id: channel_id.clone(),
                    mc_limits_sequence: 0,
                    mc_state_sequence: 0,
                    mc_key_sequence: 1,
                },
            ))
            .unwrap();
        pipe.client
            .multicast_send(quiche::multicast::Frame::State(
                quiche::multicast::State {
                    channel_id,
                    sequence: 1,
                    state: quiche::multicast::ChannelState::DeclinedJoin,
                    reason_scope: quiche::multicast::StateReasonScope::Transport,
                    reason_code: STATE_REASON_UNSPECIFIED_OTHER,
                    reason_phrase: Vec::new(),
                },
            ))
            .unwrap();
        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        runtime.process_reads(&mut pipe.server).unwrap();

        assert_eq!(runtime.callback_read_work_last_call, 3);
        assert!(!runtime.event_coalescer.has_pending_client_acks());
        assert!(runtime.pending_controls.is_empty());
        assert!(!pipe.server.is_multicast_readable());
    }

    #[test]
    fn publisher_staging_budget_is_aggregate_and_fair() {
        const CHANNELS: usize = 300;
        const BUDGET: usize = 32;

        let limits = RuntimeLimits {
            max_work_per_call: BUDGET,
            ..RuntimeLimits::default()
        };
        let (_command_sender, command_receiver, _) =
            bounded_channel(limits.commands);
        let (event_sender, _events, _) = test_server_event_channel();
        let mut runtime = ServerControlRuntime::with_limits(
            ServerControlSettings::default(),
            event_sender,
            command_receiver,
            limits,
        );

        for index in 0..CHANNELS {
            let channel_id = (index as u32).to_be_bytes().to_vec();
            let queue = Arc::new(server_stream::ServerStreamPublisherQueue::new(
                channel_id.clone(),
                server_stream::ServerStreamPublisherLimits::default(),
            ));
            queue.seal();
            runtime.channels.insert(channel_id, ServerControlChannel {
                stream_publication_queue: Some(queue),
                ..ServerControlChannel::default()
            });
        }

        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let max_passes = (CHANNELS * 4).div_ceil(BUDGET);
        let mut passes = 0;
        while runtime.channels.values().any(|channel| {
            channel
                .stream_publication_queue
                .as_ref()
                .is_some_and(|queue| queue.has_pending())
        }) {
            runtime.process_writes(&mut pipe.server).unwrap();
            passes += 1;
            assert!(
                runtime.callback_write_work_last_call <= BUDGET,
                "one complete callback exceeded the aggregate work budget"
            );
            assert!(passes <= max_passes, "publisher staging starved");
        }

        assert!(runtime.channels.values().all(|channel| {
            channel.stream_publication_queue.is_none() ||
                !channel
                    .stream_publication_queue
                    .as_ref()
                    .unwrap()
                    .has_pending()
        }));
        assert!(runtime.publisher_stage_cursor.is_some());
    }

    #[test]
    #[ignore = "release-mode aggregate scheduler scaling probe"]
    fn aggregate_scheduler_scaling_release_probe() {
        const BUDGET: usize = 256;

        for active_channels in [1_usize, 128, 1024] {
            let mut settings = test_settings();
            settings.transport_params.limits.max_channel_ids =
                active_channels as u64;
            settings.max_joined_channels = active_channels as u64;
            let (event_sender, _events, _) = test_client_event_channel();
            let limits = RuntimeLimits {
                max_work_per_call: BUDGET,
                ..RuntimeLimits::default()
            };
            let mut runtime = ClientRuntime::with_backend_and_limits(
                settings.clone(),
                event_sender,
                FakeJoinBackend::default(),
                limits,
            );

            for index in 0..active_channels {
                let channel_id = (index as u32).to_be_bytes().to_vec();
                let mut announce = test_ipv4_announce();
                announce.channel_id = channel_id.clone();
                let receiver_limits = quiche::multicast::ChannelReceiveLimits {
                    max_work_per_call: 1,
                    ..quiche::multicast::ChannelReceiveLimits::default()
                };
                let mut receiver = quiche::multicast::ChannelReceiveState::<
                    PacketWithMetadata,
                >::with_limits(
                    announce.clone(), receiver_limits
                )
                .unwrap();
                receiver
                    .insert_integrity(quiche::multicast::Integrity {
                        channel_id: channel_id.clone(),
                        packet_number_start: 0,
                        packet_hash_count: Some(2),
                        packet_hashes: vec![0; 2 * 32],
                    })
                    .unwrap();
                let mut channel = Channel::default();
                channel.announce = Some(announce);
                channel.receive_state = Some(receiver);
                runtime.channels.insert(channel_id, channel);
            }

            let mut pipe = test_pipe(&settings);
            let started = Instant::now();
            let mut calls = 0_usize;
            let mut peak_work = 0_usize;
            while runtime.channels.values().any(|channel| {
                channel
                    .receive_state
                    .as_ref()
                    .is_some_and(|receiver| receiver.has_pending_work())
            }) {
                runtime.process_reads(&mut pipe.client).unwrap();
                calls += 1;
                peak_work = peak_work.max(runtime.callback_read_work_last_call);
                assert!(runtime.callback_read_work_last_call <= BUDGET);
            }
            let elapsed = started.elapsed();
            println!(
                "client_process_reads active={active_channels} calls={calls} \
                 total_us={} per_call_us={} peak_work={peak_work}",
                elapsed.as_micros(),
                elapsed.as_micros() / calls.max(1) as u128,
            );

            let (_command_sender, command_receiver, _) =
                bounded_channel(limits.commands);
            let (event_sender, _events, _) = test_server_event_channel();
            let mut runtime = ServerControlRuntime::with_limits(
                ServerControlSettings::default(),
                event_sender,
                command_receiver,
                limits,
            );
            for index in 0..active_channels {
                let channel_id = (index as u32).to_be_bytes().to_vec();
                let queue =
                    Arc::new(server_stream::ServerStreamPublisherQueue::new(
                        channel_id.clone(),
                        server_stream::ServerStreamPublisherLimits::default(),
                    ));
                queue.seal();
                runtime.channels.insert(channel_id, ServerControlChannel {
                    stream_publication_queue: Some(queue),
                    ..ServerControlChannel::default()
                });
            }

            let started = Instant::now();
            let mut calls = 0_usize;
            let mut peak_work = 0_usize;
            while !runtime.pending_commands.is_empty() ||
                runtime.channels.values().any(|channel| {
                    channel
                        .stream_publication_queue
                        .as_ref()
                        .is_some_and(|queue| queue.has_pending())
                })
            {
                runtime.process_writes(&mut pipe.server).unwrap();
                calls += 1;
                peak_work = peak_work.max(runtime.callback_write_work_last_call);
                assert!(runtime.callback_write_work_last_call <= BUDGET);
            }
            let elapsed = started.elapsed();
            println!(
                "server_process_writes active={active_channels} calls={calls} \
                 total_us={} per_call_us={} peak_work={peak_work}",
                elapsed.as_micros(),
                elapsed.as_micros() / calls.max(1) as u128,
            );
        }
    }

    #[test]
    fn tokio_settings_and_explicit_controls_validate_before_admission() {
        let invalid = 1 << 62;

        assert!(Instant::now().checked_add(Duration::MAX).is_none());
        let runtime_limits = RuntimeLimits {
            control_retry_delay: Duration::MAX,
            ..RuntimeLimits::default()
        };
        assert!(matches!(
            ClientDriver::new_with_runtime_limits(
                (),
                test_settings(),
                runtime_limits,
            ),
            Err(RuntimeLimitsError::UnrepresentableControlRetryDelay)
        ));
        let runtime_limits = RuntimeLimits {
            control_backpressure_timeout: Duration::MAX,
            ..RuntimeLimits::default()
        };
        assert!(matches!(
            ClientDriver::new_with_runtime_limits(
                (),
                test_settings(),
                runtime_limits,
            ),
            Err(RuntimeLimitsError::UnrepresentableControlBackpressureTimeout)
        ));

        let mut client_settings = test_settings();
        client_settings.transport_params.limits.max_channel_ids = invalid;
        assert!(matches!(
            ClientDriver::new((), client_settings),
            Err(RuntimeLimitsError::InvalidMulticastSettings(
                quiche::Error::InvalidTransportParam
            ))
        ));
        let mut client_settings = test_settings();
        client_settings.max_joined_channels = invalid;
        assert!(matches!(
            ClientDriver::new((), client_settings),
            Err(RuntimeLimitsError::InvalidMulticastSettings(
                quiche::Error::InvalidFrame
            ))
        ));

        let mut control_settings = test_server_control_settings();
        control_settings.channels[0].announce.channel_id = Vec::new();
        assert!(matches!(
            ServerControlDriver::new((), control_settings),
            Err(RuntimeLimitsError::InvalidMulticastSettings(
                quiche::Error::InvalidFrame
            ))
        ));
        let mut control_settings = test_server_control_settings();
        control_settings.stream_integrity_batching.max_packet_hashes = invalid;
        assert!(matches!(
            ServerControlDriver::new((), control_settings),
            Err(RuntimeLimitsError::InvalidMulticastSettings(
                quiche::Error::InvalidFrame
            ))
        ));
        let mut control_settings = test_server_control_settings();
        control_settings.stream_integrity_batching.max_delay = Duration::MAX;
        assert!(matches!(
            ServerControlDriver::new((), control_settings),
            Err(RuntimeLimitsError::InvalidMulticastSettings(
                quiche::Error::InvalidState
            ))
        ));
        let mut control_settings = test_server_control_settings();
        control_settings.channels[0].announce.max_ack_delay_ms = invalid;
        assert!(matches!(
            ServerControlDriver::new((), control_settings),
            Err(RuntimeLimitsError::InvalidMulticastSettings(
                quiche::Error::InvalidFrame
            ))
        ));
        let mut server_settings = test_server_settings();
        server_settings.channels[0].max_rate_kibps = invalid;
        assert!(matches!(
            ServerDriver::new((), server_settings),
            Err(RuntimeLimitsError::InvalidMulticastSettings(
                quiche::Error::InvalidFrame
            ))
        ));

        let (_driver, controller) =
            ServerControlDriver::new((), ServerControlSettings::default())
                .unwrap();
        let mut announce = test_ipv4_announce();
        announce.channel_id = vec![0; 21];
        assert_eq!(
            controller.send_announce(announce).unwrap_err().kind(),
            ControllerSendErrorKind::InvalidValue
        );
        let mut announce = test_ipv4_announce();
        announce.max_ack_delay_ms = invalid;
        assert_eq!(
            controller.send_announce(announce).unwrap_err().kind(),
            ControllerSendErrorKind::InvalidValue
        );
        let mut key = test_key(&[1]);
        key.key_sequence = invalid;
        assert_eq!(
            controller.send_key(key).unwrap_err().kind(),
            ControllerSendErrorKind::InvalidValue
        );
        assert_eq!(
            controller
                .send_join(quiche::multicast::Join {
                    channel_id: vec![1],
                    mc_limits_sequence: invalid,
                    mc_state_sequence: 0,
                    mc_key_sequence: 0,
                })
                .unwrap_err()
                .kind(),
            ControllerSendErrorKind::InvalidValue
        );
        assert_eq!(
            controller
                .send_integrity(quiche::multicast::Integrity {
                    channel_id: vec![1],
                    packet_number_start: invalid,
                    packet_hash_count: Some(1),
                    packet_hashes: vec![0; 32],
                })
                .unwrap_err()
                .kind(),
            ControllerSendErrorKind::InvalidValue
        );
        let mut config = test_server_control_settings().channels.remove(0);
        config.key.channel_id = vec![2];
        assert_eq!(
            controller.upsert_channel(config).unwrap_err().kind(),
            ControllerSendErrorKind::InvalidValue
        );
        assert_eq!(controller.command_queue_stats().retained_items, 0);

        controller
            .send_join(quiche::multicast::Join {
                channel_id: vec![1],
                mc_limits_sequence: 0,
                mc_state_sequence: 0,
                mc_key_sequence: 0,
            })
            .unwrap();
        assert_eq!(controller.command_queue_stats().retained_items, 1);

        let (_driver, publisher_controller) =
            ServerDriver::new((), ServerSettings::default()).unwrap();
        assert_eq!(
            publisher_controller
                .send_on_channel(vec![1], vec![
                    quiche::multicast::ChannelFrame::Stream {
                        stream_id: 3,
                        offset: invalid,
                        fin: false,
                        data: Vec::new(),
                    }
                ],)
                .unwrap_err()
                .kind(),
            ControllerSendErrorKind::InvalidValue
        );
        assert_eq!(publisher_controller.command_queue_stats().retained_items, 0);
        publisher_controller
            .send_on_channel(vec![1], vec![
                quiche::multicast::ChannelFrame::Datagram { data: vec![1] },
            ])
            .unwrap();
        assert_eq!(publisher_controller.command_queue_stats().retained_items, 1);
    }

    #[test]
    fn stream_declaration_validates_before_publisher_mutation() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();

        assert!(matches!(
            publisher.declare_stream((1 << 62) | 3),
            Err(ServerStreamPublisherError::Encode(
                quiche::Error::InvalidFrame
            ))
        ));
        publisher.declare_stream(3).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(runtime.channels[&[1, 2, 3, 4][..]].max_stream_id, Some(3));
    }

    fn test_server_control_command_channel() -> (
        BoundedSender<ServerControlCommand>,
        BoundedReceiver<ServerControlCommand>,
        RetainedQueueObserver,
    ) {
        bounded_channel(RuntimeLimits::default().commands)
    }

    fn test_server_command_channel() -> (
        BoundedSender<ServerCommand>,
        BoundedReceiver<ServerCommand>,
        RetainedQueueObserver,
    ) {
        bounded_channel(RuntimeLimits::default().commands)
    }

    fn test_retained_queue_observer() -> RetainedQueueObserver {
        retained_queue_budget::<quiche::multicast::Integrity>(
            RuntimeLimits::default().pending_integrity,
        )
        .1
    }

    #[test]
    fn controller_event_receivers_can_be_taken_only_once() {
        let (_client_sender, client_receiver, client_observer) =
            test_client_event_channel();
        let mut client = ClientController {
            event_receiver: Some(client_receiver),
            event_observer: client_observer,
            ingress_observer: test_retained_queue_observer(),
            control_observer: test_retained_queue_observer(),
        };
        assert!(client.event_receiver_mut().is_some());
        let client_receiver = client.take_event_receiver().unwrap();
        assert!(client.take_event_receiver().is_none());
        assert!(client.event_receiver_mut().is_none());
        drop(client_receiver);
        assert_eq!(
            client
                .event_queue_stats()
                .terminal
                .map(|terminal| terminal.reason),
            Some(EventStreamTerminalReason::ReceiverDropped)
        );

        let (command_sender, _command_receiver, command_observer) =
            test_server_control_command_channel();
        let (_server_sender, server_receiver, server_observer) =
            test_server_event_channel();
        let mut server = ServerControlController {
            command_sender,
            command_observer,
            pending_publication_observer: test_retained_queue_observer(),
            pending_integrity_observer: test_retained_queue_observer(),
            event_receiver: Some(server_receiver),
            event_observer: server_observer,
        };
        assert!(server.take_event_receiver().is_some());
        assert!(server.take_event_receiver().is_none());
    }

    #[test]
    fn server_controller_command_queue_saturates_without_blocking() {
        let limits = RuntimeLimits {
            commands: RetainedQueueLimits {
                max_items: 1,
                max_retained_bytes: 4096,
            },
            ..RuntimeLimits::default()
        };
        let (_driver, controller) = ServerControlDriver::new_with_runtime_limits(
            (),
            ServerControlSettings::default(),
            limits,
        )
        .unwrap();

        controller.send_announce(test_ipv4_announce()).unwrap();
        let rejected = test_ipv4_announce();
        let error = controller.send_announce(rejected.clone()).unwrap_err();
        assert_eq!(error.kind(), ControllerSendErrorKind::Full);
        assert_eq!(error.into_inner(), rejected);

        let stats = controller.runtime_queue_stats().commands;
        assert_eq!(stats.retained_items, 1);
        assert!(stats.retained_bytes <= stats.max_retained_bytes);
        assert_eq!(stats.peak_retained_items, 1);
        assert_eq!(stats.saturations_total, 1);
    }

    #[test]
    fn server_controller_returns_owned_oversized_and_closed_commands() {
        let oversized_limits = RuntimeLimits {
            commands: RetainedQueueLimits {
                max_items: 1,
                max_retained_bytes: 1,
            },
            ..RuntimeLimits::default()
        };
        let (_driver, controller) = ServerControlDriver::new_with_runtime_limits(
            (),
            ServerControlSettings::default(),
            oversized_limits,
        )
        .unwrap();
        let key = test_key(&[1, 2, 3, 4]);
        let error = controller.send_key(key.clone()).unwrap_err();
        assert_eq!(error.kind(), ControllerSendErrorKind::Oversized);
        assert_eq!(error.into_inner(), key);

        let (driver, controller) =
            ServerControlDriver::new((), ServerControlSettings::default())
                .unwrap();
        drop(driver);
        let integrity = test_stream_integrity(1, 0xaa);
        let error = controller.send_integrity(integrity.clone()).unwrap_err();
        assert_eq!(error.kind(), ControllerSendErrorKind::Closed);
        assert_eq!(error.into_inner(), integrity);
    }

    #[test]
    fn runtime_limits_reserve_space_for_ingress_overload_notification() {
        let limits = RuntimeLimits {
            ingress: RetainedQueueLimits {
                max_items: 1,
                max_retained_bytes: MIN_INGRESS_NOTIFICATION_RETAINED_BYTES - 1,
            },
            ..RuntimeLimits::default()
        };

        assert_eq!(
            limits.validate(),
            Err(RuntimeLimitsError::IngressNotificationByteCapacity {
                minimum: MIN_INGRESS_NOTIFICATION_RETAINED_BYTES,
            })
        );
    }

    #[test]
    fn client_control_sequence_exhaustion_does_not_reserve_or_queue() {
        let settings = test_settings();
        let (event_sender, _events, _) = test_client_event_channel();
        let mut runtime = ClientRuntime::with_backend(
            settings.clone(),
            event_sender,
            FakeJoinBackend::default(),
        );
        let mut pipe = test_pipe(&settings);
        let max_varint = (1 << 62) - 1;

        runtime.reserved_limits_sequence = max_varint;
        assert!(runtime.send_limits(&mut pipe.client).is_err());
        assert_eq!(runtime.reserved_limits_sequence, max_varint);
        assert!(runtime.pending_control.is_empty());

        let channel_id = vec![1, 2, 3, 4];
        let mut channel = Channel::default();
        channel.next_state_sequence = max_varint;
        runtime.channels.insert(channel_id.clone(), channel);
        assert!(runtime
            .send_state(
                &mut pipe.client,
                channel_id.clone(),
                quiche::multicast::ChannelState::Left,
                STATE_REASON_UNSPECIFIED_OTHER,
                Vec::new(),
            )
            .is_err());
        assert_eq!(
            runtime.channels[&channel_id].next_state_sequence,
            max_varint
        );
        assert!(!runtime.reserved_state_sequences.contains_key(&channel_id));
        assert!(runtime.pending_control.is_empty());
    }

    #[test]
    fn server_secret_bearing_config_debug_output_is_redacted() {
        let mut announce = test_ipv4_announce();
        announce.header_secret = vec![0xde, 0xad, 0xbe, 0xef];
        let mut key = test_key(&[1, 2, 3, 4]);
        key.secret = vec![0xca, 0xfe, 0xba, 0xbe];
        let control = ServerControlChannelConfig { announce, key };
        let control_debug = format!("{control:?}");
        assert!(control_debug.contains("<redacted:4 bytes>"));
        assert!(!control_debug.contains("[222, 173, 190, 239]"));
        assert!(!control_debug.contains("[202, 254, 186, 190]"));

        let mut publication = test_server_settings()
            .channels
            .first()
            .expect("test server has one channel")
            .clone();
        publication.header_secret = vec![0x11, 0x22, 0x33, 0x44];
        publication.secret = vec![0x55, 0x66, 0x77, 0x88];
        let publication_debug = format!("{publication:?}");
        assert!(publication_debug.matches("<redacted:4 bytes>").count() >= 2);
        assert!(!publication_debug.contains("[17, 34, 51, 68]"));
        assert!(!publication_debug.contains("[85, 102, 119, 136]"));
    }

    fn assert_next_local_state(
        event_receiver: &mut ClientEventStream,
        expected: quiche::multicast::ChannelState,
    ) {
        loop {
            match event_receiver.try_recv() {
                Ok(ClientEvent::LocalState(frame)) => {
                    assert_eq!(frame.state, expected);
                    return;
                },

                Ok(ClientEvent::MetricsUpdated { .. }) => continue,

                other => panic!("expected local state, got {other:?}"),
            }
        }
    }

    fn joined_client_runtime() -> (
        ClientRuntime<FakeJoinBackend>,
        Pipe,
        ClientEventStream,
        quiche::multicast::Announce,
    ) {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let (event_sender, mut event_receiver, _event_observer) =
            test_client_event_channel();
        let mut runtime = ClientRuntime::with_backend(
            settings,
            event_sender,
            FakeJoinBackend::default(),
        );
        let announce = test_ipv4_announce();

        runtime.handle_announce(announce.clone()).unwrap();
        runtime
            .handle_key(&mut pipe.client, test_key(&announce.channel_id))
            .unwrap();
        runtime
            .handle_join(&mut pipe.client, quiche::multicast::Join {
                channel_id: announce.channel_id.clone(),
                mc_limits_sequence: 0,
                mc_state_sequence: 0,
                mc_key_sequence: 1,
            })
            .unwrap();
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ClientEvent::Announce(frame)) if frame == announce
        ));
        assert_next_local_state(
            &mut event_receiver,
            quiche::multicast::ChannelState::Joined,
        );
        while event_receiver.try_recv().is_ok() {}

        (runtime, pipe, event_receiver, announce)
    }

    #[test]
    fn client_ingress_overload_releases_join_and_reports_fallback() {
        let (mut runtime, mut pipe, mut events, announce) =
            joined_client_runtime();
        let retained_bytes = 4096;
        let max_retained_bytes = 1024;

        runtime
            .ingress_sender
            .try_send(IngressEvent::Overload {
                channel_id: announce.channel_id.clone(),
                retained_bytes,
                max_retained_bytes,
            })
            .unwrap();
        assert!(runtime.transfer_one_ingress());
        assert!(runtime.process_one_ingress(&mut pipe.client).unwrap());

        let channel = &runtime.channels[&announce.channel_id];
        assert!(channel.receive_handle.is_none());
        assert!(channel.receive_state.is_none());
        assert_eq!(channel.ack_state, quiche::multicast::AckTracker::default());

        assert!(matches!(
            events.try_recv(),
            Ok(ClientEvent::IngressOverload {
                channel_id,
                retained_bytes: 4096,
                max_retained_bytes: 1024,
            }) if channel_id == announce.channel_id
        ));
        assert_next_local_state(
            &mut events,
            quiche::multicast::ChannelState::Left,
        );
    }

    #[test]
    fn client_control_retry_preserves_state_sequence_order() {
        let settings = test_settings();
        let mut client_config =
            quiche::test_utils::Pipe::default_config("cubic").unwrap();
        client_config
            .set_multicast_client_params(Some(settings.transport_params.clone()))
            .unwrap();
        client_config.set_multicast_send_queue_limits(1, 4096);
        let mut server_config =
            quiche::test_utils::Pipe::default_config("cubic").unwrap();
        server_config.enable_multicast_server_support(true);
        let mut pipe = Pipe::with_client_and_server_config_and_buf(
            &mut client_config,
            &mut server_config,
        )
        .unwrap();
        pipe.handshake().unwrap();

        let (event_sender, mut events, _event_observer) =
            test_client_event_channel();
        let mut runtime = ClientRuntime::with_backend(
            settings,
            event_sender,
            FakeJoinBackend::default(),
        );
        runtime.on_conn_established(&mut pipe.client).unwrap();
        let channel_id = vec![1, 2, 3, 4];
        runtime
            .channels
            .insert(channel_id.clone(), Channel::default());

        runtime
            .send_state(
                &mut pipe.client,
                channel_id.clone(),
                quiche::multicast::ChannelState::Joined,
                quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                b"first".to_vec(),
            )
            .unwrap();
        runtime
            .send_state(
                &mut pipe.client,
                channel_id.clone(),
                quiche::multicast::ChannelState::Left,
                quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                b"second".to_vec(),
            )
            .unwrap();
        assert_eq!(runtime.pending_control.observer().stats().retained_items, 2);
        assert_eq!(runtime.channels[&channel_id].next_state_sequence, 0);
        assert_eq!(runtime.reserved_state_sequences[&channel_id], 2);

        pipe.advance().unwrap();
        runtime.process_reads(&mut pipe.client).unwrap();
        assert!(runtime.flush_one_pending_control(&mut pipe.client).unwrap());
        assert_eq!(runtime.channels[&channel_id].next_state_sequence, 1);
        assert_eq!(runtime.pending_control.observer().stats().retained_items, 1);

        pipe.advance().unwrap();
        runtime.process_reads(&mut pipe.client).unwrap();
        assert!(runtime.flush_one_pending_control(&mut pipe.client).unwrap());
        assert_eq!(runtime.channels[&channel_id].next_state_sequence, 2);
        assert!(runtime.pending_control.is_empty());

        let first = events.try_recv().unwrap();
        let second = events.try_recv().unwrap();
        assert!(matches!(
            first,
            ClientEvent::LocalState(frame)
                if frame.sequence == 1 &&
                    frame.state == quiche::multicast::ChannelState::Joined
        ));
        assert!(matches!(
            second,
            ClientEvent::LocalState(frame)
                if frame.sequence == 2 &&
                    frame.state == quiche::multicast::ChannelState::Left
        ));

        pipe.advance().unwrap();
        assert!(matches!(
            pipe.server.multicast_recv(),
            Ok(quiche::multicast::Frame::Limits(_))
        ));
        assert!(matches!(
            pipe.server.multicast_recv(),
            Ok(quiche::multicast::Frame::State(frame)) if frame.sequence == 1
        ));
        assert!(matches!(
            pipe.server.multicast_recv(),
            Ok(quiche::multicast::Frame::State(frame)) if frame.sequence == 2
        ));
    }

    #[test]
    fn client_runtime_bounds_unique_channel_ids_across_retirement() {
        let settings = test_settings();
        let (event_sender, _events, _event_observer) =
            test_client_event_channel();
        let limits = RuntimeLimits {
            max_tracked_channel_ids: 2,
            ..RuntimeLimits::default()
        };
        let mut runtime = ClientRuntime::with_backend_and_limits(
            settings,
            event_sender,
            FakeJoinBackend::default(),
            limits,
        );

        for id in [1_u8, 2] {
            let mut announce = test_ipv4_announce();
            announce.channel_id = vec![id];
            runtime.handle_announce(announce).unwrap();
        }
        assert_eq!(runtime.channels.len(), 2);

        runtime.channels.get_mut(&[1][..]).unwrap().retired = true;
        let mut rejected = test_ipv4_announce();
        rejected.channel_id = vec![3];
        assert!(matches!(
            runtime.handle_announce(rejected),
            Err(error) if error.to_string().contains(
                "connection-lifetime Channel ID limit"
            )
        ));
        assert_eq!(runtime.channels.len(), 2);
        assert_eq!(runtime.channels.keys().map(Vec::len).sum::<usize>(), 2);
    }

    #[test]
    fn server_runtime_bounds_ids_and_unknown_acks_do_not_allocate() {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, _events, _event_observer) =
            test_server_event_channel();
        let limits = RuntimeLimits {
            max_tracked_channel_ids: 2,
            ..RuntimeLimits::default()
        };
        let mut runtime = ServerControlRuntime::with_limits(
            ServerControlSettings {
                mode: ServerControlMode::Manual,
                channels: Vec::new(),
                stream_integrity_batching:
                    StreamIntegrityBatchingSettings::default(),
            },
            event_sender,
            command_receiver,
            limits,
        );
        runtime.on_conn_established(&mut pipe.server).unwrap();

        for id in [1_u8, 2] {
            let mut config = test_stream_control_config();
            config.announce.channel_id = vec![id];
            config.key.channel_id = vec![id];
            runtime
                .upsert_channel_config(&mut pipe.server, config, false, false)
                .unwrap();
        }
        assert_eq!(runtime.channels.len(), 2);

        for id in 10_u16..110 {
            runtime
                .handle_frame(
                    &mut pipe.server,
                    quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                        channel_id: id.to_be_bytes().to_vec(),
                        largest_acknowledged: 0,
                        ack_delay: 0,
                        first_ack_range: 0,
                        ack_ranges: Vec::new(),
                        ecn_counts: None,
                    }),
                )
                .unwrap();
        }
        assert_eq!(runtime.channels.len(), 2);
        assert!(runtime.event_coalescer.pending_client_acks.is_empty());
        assert!(runtime.event_coalescer.last_client_acks.is_empty());
        assert!(runtime.event_coalescer.last_probe_events.is_empty());

        let mut rejected = test_stream_control_config();
        rejected.announce.channel_id = vec![3];
        rejected.key.channel_id = vec![3];
        assert!(runtime
            .upsert_channel_config(&mut pipe.server, rejected, false, false)
            .is_err());
        assert_eq!(runtime.channels.len(), 2);
    }

    fn assert_client_receives_dgram(pipe: &mut Pipe, expected: &[u8]) {
        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        let mut out = [0; 128];
        assert_eq!(pipe.client.dgram_recv(&mut out), Ok(expected.len()));
        assert_eq!(&out[..expected.len()], expected);
        assert_eq!(pipe.client.dgram_recv(&mut out), Err(quiche::Error::Done));
    }

    fn test_stream_control_config() -> ServerControlChannelConfig {
        ServerControlChannelConfig {
            announce: test_ipv4_announce(),
            key: test_key(&[1, 2, 3, 4]),
        }
    }

    fn test_stream_control_runtime(
    ) -> (ServerControlRuntime, ServerControlController) {
        test_stream_control_runtime_with_integrity_batching(
            StreamIntegrityBatchingSettings::default(),
        )
    }

    fn test_stream_control_runtime_with_integrity_batching(
        stream_integrity_batching: StreamIntegrityBatchingSettings,
    ) -> (ServerControlRuntime, ServerControlController) {
        let (command_sender, command_receiver, command_observer) =
            test_server_control_command_channel();
        let (event_sender, event_receiver, event_observer) =
            test_server_event_channel();

        (
            ServerControlRuntime::new(
                ServerControlSettings {
                    mode: ServerControlMode::Automatic,
                    channels: Vec::new(),
                    stream_integrity_batching,
                },
                event_sender,
                command_receiver,
            ),
            ServerControlController {
                command_sender,
                command_observer,
                pending_publication_observer: test_retained_queue_observer(),
                pending_integrity_observer: test_retained_queue_observer(),
                event_receiver: Some(event_receiver),
                event_observer,
            },
        )
    }

    fn test_manual_control_runtime_with_small_core_queue() -> (
        ServerControlRuntime,
        BoundedSender<ServerControlCommand>,
        RetainedQueueObserver,
        ServerEventStream,
        Pipe,
    ) {
        let settings = test_settings();
        let pipe = test_pipe_with_server_control_queue(&settings, 1, 4096);
        let (command_sender, command_receiver, command_observer) =
            test_server_control_command_channel();
        let (event_sender, event_receiver, _event_observer) =
            test_server_event_channel();
        let mut control_settings = test_server_control_settings();
        control_settings.mode = ServerControlMode::Manual;
        let mut runtime = ServerControlRuntime::new(
            control_settings,
            event_sender,
            command_receiver,
        );
        let mut pipe = pipe;
        runtime.on_conn_established(&mut pipe.server).unwrap();

        (
            runtime,
            command_sender,
            command_observer,
            event_receiver,
            pipe,
        )
    }

    fn test_stream_integrity(
        packet_number: u64, hash_byte: u8,
    ) -> quiche::multicast::Integrity {
        quiche::multicast::Integrity {
            channel_id: vec![1, 2, 3, 4],
            packet_number_start: packet_number,
            packet_hash_count: Some(1),
            packet_hashes: vec![hash_byte; 32],
        }
    }

    fn send_webtransport_stream_prefix(
        pipe: &mut Pipe, stream_id: u64, session_id: u64,
    ) {
        let mut prefix = [0; 10];
        prefix[..2].copy_from_slice(&[0x40, 0x54]);
        prefix[2..].copy_from_slice(&session_id.to_be_bytes());

        assert_eq!(
            pipe.server.stream_send(stream_id, &prefix, false),
            Ok(prefix.len())
        );
        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        let mut out = [0; 16];
        assert_eq!(
            pipe.client.stream_recv(stream_id, &mut out),
            Ok((prefix.len(), false))
        );
        assert_eq!(&out[..prefix.len()], &prefix);
    }

    fn deliver_server_flight(pipe: &mut Pipe) {
        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();
    }

    fn send_client_control(
        pipe: &mut Pipe, runtime: &mut ServerControlRuntime,
        frame: quiche::multicast::Frame,
    ) {
        pipe.client.multicast_send(frame).unwrap();
        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
        runtime.process_reads(&mut pipe.server).unwrap();
    }

    struct StreamProfileConnection {
        pipe: Pipe,
        runtime: ServerControlRuntime,
        controller: ServerControlController,
        _attachment: ServerStreamAttachment,
    }

    #[derive(Default)]
    struct StreamProfileWakeCounter {
        wakes: AtomicU64,
    }

    impl Wake for StreamProfileWakeCounter {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn setup_stream_profile_connections(
        settings: &ClientSettings, publisher: &ServerStreamPublisher,
        channel_id: &[u8], stream_id: u64, client_count: usize,
        batching: StreamIntegrityBatchingSettings,
    ) -> Vec<StreamProfileConnection> {
        let mut connections = Vec::with_capacity(client_count);

        for client_id in 0..client_count {
            let mut pipe =
                test_stream_pipe_with_flow_control(settings, 3, 512 * 1024);
            let (mut runtime, controller) =
                test_stream_control_runtime_with_integrity_batching(batching);
            runtime.on_conn_established(&mut pipe.server).unwrap();
            send_webtransport_stream_prefix(
                &mut pipe,
                stream_id,
                client_id as u64,
            );
            let attachment = publisher.attach(&controller).unwrap();
            runtime.process_writes(&mut pipe.server).unwrap();

            send_client_control(
                &mut pipe,
                &mut runtime,
                quiche::multicast::Frame::Limits(test_limits()),
            );
            send_client_control(
                &mut pipe,
                &mut runtime,
                quiche::multicast::Frame::State(quiche::multicast::State {
                    channel_id: channel_id.to_vec(),
                    sequence: 1,
                    state: quiche::multicast::ChannelState::Joined,
                    reason_scope: quiche::multicast::StateReasonScope::Transport,
                    reason_code:
                        quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                    reason_phrase: Vec::new(),
                }),
            );

            connections.push(StreamProfileConnection {
                pipe,
                runtime,
                controller,
                _attachment: attachment,
            });
        }

        connections
    }

    fn publish_profile_burst(
        publisher: &ServerStreamPublisher,
        connections: &mut [StreamProfileConnection], stream_id: u64,
        start_offset: u64, range_count: usize, payload: &Bytes, finish: bool,
    ) -> (u64, u64) {
        const PROFILE_PUBLISH_BATCH: usize = 128;
        let mut offset = start_offset;
        let mut wake_count = 0_u64;

        for batch_start in (0..range_count).step_by(PROFILE_PUBLISH_BATCH) {
            let batch_len = PROFILE_PUBLISH_BATCH.min(range_count - batch_start);
            let wake_counter = Arc::new(StreamProfileWakeCounter::default());
            let waker = Waker::from(Arc::clone(&wake_counter));
            let mut context = Context::from_waker(&waker);
            let mut waiters = connections
                .iter_mut()
                .map(|connection| Box::pin(connection.runtime.wait_for_work()))
                .collect::<Vec<_>>();

            for waiter in &mut waiters {
                assert!(matches!(
                    waiter.as_mut().poll(&mut context),
                    Poll::Pending
                ));
            }

            for batch_index in 0..batch_len {
                let range_index = batch_start + batch_index;
                let range_fin = finish && range_index + 1 == range_count;
                let publication = publisher
                    .prepare_stream_buf(
                        stream_id,
                        offset,
                        range_fin,
                        payload.clone(),
                    )
                    .unwrap();
                assert!(!publication.packet().is_empty());
                publisher.commit(publication).unwrap();
                offset += payload.len() as u64;
            }

            wake_count = wake_count
                .saturating_add(wake_counter.wakes.load(Ordering::Relaxed));
            drop(waiters);

            for connection in &mut *connections {
                let max_passes = batch_len
                    .div_ceil(connection.runtime.limits.max_work_per_call)
                    .saturating_add(4);
                for _ in 0..max_passes {
                    connection
                        .runtime
                        .process_writes(&mut connection.pipe.server)
                        .unwrap();

                    let publisher_commands =
                        connection.runtime.pending_commands.iter().any(
                            |pending| {
                                matches!(
                                pending.command.as_ref(),
                                ServerControlCommand::StreamPublisherQueueReady {
                                    ..
                                } |
                                ServerControlCommand::DetachStreamPublisher {
                                    ..
                                } |
                                ServerControlCommand::StreamPublication {
                                    ..
                                } |
                                ServerControlCommand::StreamPublisherKey {
                                    ..
                                } |
                                ServerControlCommand::StreamPublisherMaxStreamId {
                                    ..
                                } |
                                ServerControlCommand::StreamPublisherRetire {
                                    ..
                                }
                            )
                            },
                        );
                    let attachment_items =
                        connection.runtime.channels.values().any(|channel| {
                            channel
                                .stream_publication_queue
                                .as_ref()
                                .is_some_and(|queue| queue.has_items())
                        });
                    if !publisher_commands &&
                        !attachment_items &&
                        connection
                            .runtime
                            .pending_stream_publications
                            .is_empty()
                    {
                        break;
                    }
                }

                assert!(!connection.runtime.pending_commands.iter().any(
                    |pending| {
                        matches!(
                            pending.command.as_ref(),
                            ServerControlCommand::StreamPublisherQueueReady {
                                ..
                            } |
                                ServerControlCommand::StreamPublication { .. }
                        )
                    }
                ));
                assert!(!connection.runtime.channels.values().any(|channel| {
                    channel
                        .stream_publication_queue
                        .as_ref()
                        .is_some_and(|queue| queue.has_items())
                }));
                assert!(connection
                    .runtime
                    .pending_stream_publications
                    .is_empty());
            }
        }

        (offset, wake_count)
    }

    fn assert_no_queued_join(qconn: &mut QuicheConnection) {
        loop {
            match qconn.multicast_recv() {
                Ok(quiche::multicast::Frame::Join(frame)) => {
                    panic!("unexpected MC_JOIN: {frame:?}");
                },

                Ok(_) => (),

                Err(quiche::Error::Done) => return,

                Err(error) =>
                    panic!("unexpected multicast receive error: {error:?}"),
            }
        }
    }

    #[test]
    fn server_stream_publisher_encodes_shared_stream_packet() {
        let config = test_stream_control_config();
        let publisher = ServerStreamPublisher::new(config.clone()).unwrap();
        publisher.declare_stream(3).unwrap();

        let publication = publisher
            .prepare_stream(3, 10, true, b"shared stream body")
            .unwrap();
        assert_eq!(publication.packet_number(), 0);
        assert_eq!(publication.frame().offset, 10);

        let mut receiver =
            quiche::multicast::ChannelReceiveState::new(config.announce).unwrap();
        receiver.insert_key(config.key).unwrap();
        assert!(receiver
            .insert_integrity(publication.integrity().clone())
            .unwrap()
            .is_empty());

        let events = receiver.recv(publication.packet(), ()).unwrap();
        assert!(matches!(
            &events[0],
            quiche::multicast::ChannelReceiveEvent::Packet { packet, .. }
                if packet.frames == vec![quiche::multicast::ChannelFrame::Stream {
                    stream_id: 3,
                    offset: 10,
                    fin: true,
                    data: b"shared stream body".to_vec(),
                }]
        ));
    }

    #[test]
    fn server_stream_unresolved_publication_fail_stops_channel() {
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();

        drop(publisher.prepare_stream(3, 0, false, b"uncertain").unwrap());

        assert!(matches!(
            publisher.prepare_stream(3, 9, false, b"later"),
            Err(ServerStreamPublisherError::Retired)
        ));
    }

    #[test]
    fn server_stream_explicit_abandon_fail_stops_without_reuse() {
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();

        let publication = publisher
            .prepare_stream(3, 0, false, b"unpublished")
            .unwrap();
        publisher.abandon(publication).unwrap();

        assert!(matches!(
            publisher.prepare_stream(3, 11, false, b"later"),
            Err(ServerStreamPublisherError::Retired)
        ));
    }

    #[test]
    fn server_stream_foreign_resolution_retires_actual_publisher() {
        let first =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        let mut second_config = test_stream_control_config();
        second_config.announce.channel_id = vec![5, 6, 7, 8];
        second_config.key.channel_id = vec![5, 6, 7, 8];
        let second = ServerStreamPublisher::new(second_config).unwrap();
        first.declare_stream(3).unwrap();
        second.declare_stream(7).unwrap();

        let publication = first.prepare_stream(3, 0, false, b"foreign").unwrap();
        assert!(matches!(
            second.commit(publication),
            Err(ServerStreamPublisherError::UnknownPublication)
        ));
        assert!(matches!(
            first.prepare_stream(3, 7, false, b"later"),
            Err(ServerStreamPublisherError::Retired)
        ));
        assert!(second.prepare_stream(7, 0, false, b"healthy").is_ok());
    }

    #[test]
    fn server_stream_prepare_preflights_effective_payload_boundary() {
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        let maximum_payload = vec![0x5a; 16_383];
        let publication = publisher
            .prepare_stream(3, 0, true, &maximum_payload)
            .unwrap();
        assert_eq!(publication.packet_number(), 0);
        publisher.commit(publication).unwrap();
        assert_eq!(publisher.metrics_snapshot().unwrap().next_packet_number, 1);

        let rejected =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        assert!(matches!(
            rejected.prepare_stream(3, 0, false, &vec![0x5a; 16_384]),
            Err(ServerStreamPublisherError::Encode(
                quiche::Error::InvalidFrame
            ))
        ));
        assert_eq!(rejected.metrics_snapshot().unwrap().next_packet_number, 0);
        assert_eq!(rejected.next_stream_offset(3).unwrap(), None);

        let retry = rejected.prepare_stream(3, 0, true, b"retry").unwrap();
        assert_eq!(retry.packet_number(), 0);
        rejected.commit(retry).unwrap();
    }

    #[test]
    fn server_stream_publisher_bounds_active_and_completed_stream_state() {
        let limits = ServerStreamPublisherLimits {
            max_active_streams: 1,
            max_completed_stream_storage_units: 1,
            ..ServerStreamPublisherLimits::default()
        };
        let publisher = ServerStreamPublisher::with_limits(
            test_stream_control_config(),
            limits,
        )
        .unwrap();

        let active = publisher.prepare_stream(3, 0, false, b"a").unwrap();
        publisher.commit(active).unwrap();
        assert!(matches!(
            publisher.prepare_stream(7, 0, false, b"blocked"),
            Err(ServerStreamPublisherError::ActiveStreamLimit { limit: 1 })
        ));
        assert_eq!(publisher.metrics_snapshot().unwrap().next_packet_number, 1);
        assert_eq!(publisher.next_stream_offset(7).unwrap(), None);

        let finish = publisher.prepare_stream(3, 1, true, b"b").unwrap();
        publisher.commit(finish).unwrap();

        let sparse_stream_id = ((1024_u64 * 2) << 2) | 0x3;
        assert!(matches!(
            publisher.prepare_stream(sparse_stream_id, 0, true, b"sparse"),
            Err(ServerStreamPublisherError::CompletedStreamHistoryLimit {
                limit: 1
            })
        ));
        let profile = publisher.test_profile().unwrap();
        assert_eq!(profile.tracked_streams, 0);
        assert_eq!(profile.finished_streams, 1);
        assert_eq!(profile.finished_stream_storage_units, 1);
        assert_eq!(publisher.metrics_snapshot().unwrap().next_packet_number, 2);
    }

    #[test]
    fn server_stream_key_structural_boundary_is_transactional() {
        const ITEM_RESERVE: usize = 64 * 1024;

        let (_runtime, controller) = test_stream_control_runtime();
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        let channel_id = vec![1, 2, 3, 4];
        let exact_secret_len = ITEM_RESERVE - channel_id.len() - 64;
        publisher
            .update_key(quiche::multicast::Key {
                channel_id: channel_id.clone(),
                key_sequence: 2,
                from_packet_number: 0,
                secret: vec![0xdd; exact_secret_len],
            })
            .unwrap();
        assert_eq!(publisher.metrics_snapshot().unwrap().key_updates, 1);

        assert!(matches!(
            publisher.update_key(quiche::multicast::Key {
                channel_id: channel_id.clone(),
                key_sequence: 3,
                from_packet_number: 0,
                secret: vec![0xee; exact_secret_len + 1],
            }),
            Err(ServerStreamPublisherError::KeyTooLarge {
                retained_bytes,
                max_retained_bytes: ITEM_RESERVE,
            }) if retained_bytes == ITEM_RESERVE + 1
        ));
        assert_eq!(publisher.metrics_snapshot().unwrap().key_updates, 1);

        publisher
            .update_key(quiche::multicast::Key {
                channel_id,
                key_sequence: 3,
                from_packet_number: 0,
                secret: vec![0xff; 16],
            })
            .unwrap();
        assert_eq!(publisher.metrics_snapshot().unwrap().key_updates, 2);
    }

    #[test]
    fn server_stream_attachment_saturation_detaches_without_failing_commit() {
        let limits = ServerStreamPublisherLimits {
            max_attachment_queue_items: 2,
            max_attachment_queue_bytes: 128 * 1024,
            ..ServerStreamPublisherLimits::default()
        };
        let publisher = ServerStreamPublisher::with_limits(
            test_stream_control_config(),
            limits,
        )
        .unwrap();
        let (_runtime, controller) = test_stream_control_runtime();
        let _attachment = publisher.attach(&controller).unwrap();

        for (offset, fin) in [(0, false), (1, true)] {
            let publication =
                publisher.prepare_stream(3, offset, fin, b"x").unwrap();
            publisher.commit(publication).unwrap();
        }

        assert_eq!(publisher.attached_connections().unwrap(), 0);
        assert_eq!(publisher.metrics_snapshot().unwrap().next_packet_number, 2);
    }

    #[test]
    fn server_stream_attach_distinguishes_full_oversized_and_closed() {
        let full_limits = RuntimeLimits {
            commands: RetainedQueueLimits {
                max_items: 1,
                max_retained_bytes: 4096,
            },
            ..RuntimeLimits::default()
        };
        let (_full_driver, full_controller) =
            ServerControlDriver::new_with_runtime_limits(
                (),
                ServerControlSettings::default(),
                full_limits,
            )
            .unwrap();
        full_controller.send_announce(test_ipv4_announce()).unwrap();
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        assert!(matches!(
            publisher.attach(&full_controller),
            Err(ServerStreamPublisherError::ControllerQueueFull)
        ));

        let oversized_limits = RuntimeLimits {
            commands: RetainedQueueLimits {
                max_items: 4,
                max_retained_bytes: 256,
            },
            ..RuntimeLimits::default()
        };
        let (_oversized_driver, oversized_controller) =
            ServerControlDriver::new_with_runtime_limits(
                (),
                ServerControlSettings::default(),
                oversized_limits,
            )
            .unwrap();
        assert!(matches!(
            publisher.attach(&oversized_controller),
            Err(ServerStreamPublisherError::ControllerCommandTooLarge)
        ));

        let (closed_driver, closed_controller) =
            ServerControlDriver::new((), ServerControlSettings::default())
                .unwrap();
        drop(closed_driver);
        assert!(matches!(
            publisher.attach(&closed_controller),
            Err(ServerStreamPublisherError::ControllerClosed)
        ));
        assert_eq!(publisher.attached_connections().unwrap(), 0);
    }

    #[test]
    fn server_stream_publisher_queue_is_edge_triggered_and_ordered() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();

        let channel_id = vec![1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        let queue = Arc::clone(
            runtime.channels[&channel_id]
                .stream_publication_queue
                .as_ref()
                .unwrap(),
        );

        let first = publisher.prepare_stream(3, 0, false, b"first").unwrap();
        publisher.commit(first).unwrap();
        let rotated = quiche::multicast::Key {
            channel_id: channel_id.clone(),
            key_sequence: 2,
            from_packet_number: 1,
            secret: vec![0xdd; 16],
        };
        publisher.update_key(rotated.clone()).unwrap();
        let second = publisher.prepare_stream(3, 5, false, b"second").unwrap();
        publisher.commit(second).unwrap();

        let profile = publisher.test_profile().unwrap();
        assert_eq!(profile.publication_commands_sent, 1);
        let items = queue.drain().into_iter().collect::<Vec<_>>();
        assert!(matches!(
            &items[..],
            [
                server_stream::ServerStreamPublisherQueueItem::Publication(
                    first
                ),
                server_stream::ServerStreamPublisherQueueItem::Key(key),
                server_stream::ServerStreamPublisherQueueItem::Publication(
                    second
                ),
            ] if first.packet_number == 0 &&
                key == &rotated &&
                second.packet_number == 1
        ));
    }

    #[test]
    fn server_stream_publisher_stages_transactionally_under_command_pressure() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        send_webtransport_stream_prefix(&mut pipe, 3, 11);

        let limits = RuntimeLimits {
            commands: RetainedQueueLimits {
                max_items: 2,
                max_retained_bytes: 64 * 1024,
            },
            max_work_per_call: 1,
            ..RuntimeLimits::default()
        };
        let (command_sender, command_receiver, command_observer) =
            bounded_channel(limits.commands);
        let (event_sender, event_receiver, event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::with_limits(
            ServerControlSettings::default(),
            event_sender,
            command_receiver,
            limits,
        );
        let controller = ServerControlController {
            command_sender,
            command_observer: command_observer.clone(),
            pending_publication_observer: test_retained_queue_observer(),
            pending_integrity_observer: test_retained_queue_observer(),
            event_receiver: Some(event_receiver),
            event_observer,
        };
        runtime.on_conn_established(&mut pipe.server).unwrap();

        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        for offset in 10..13 {
            let publication =
                publisher.prepare_stream(3, offset, false, b"x").unwrap();
            publisher.commit(publication).unwrap();
        }

        for pass in 0..32 {
            if let Err(error) = runtime.process_writes(&mut pipe.server) {
                panic!(
                    "pass={pass} pending={} command_stats={:?} blocked={:?}: \
                     {error}",
                    runtime.pending_commands.len(),
                    command_observer.stats(),
                    runtime.blocked_command_channels,
                );
            }
            assert!(runtime.callback_write_work_last_call <= 1);
        }

        assert_eq!(runtime.stream_publication_registrations, 3);
        assert!(runtime.pending_stream_publications.is_empty());
        assert!(runtime.pending_commands.is_empty());
        assert!(!runtime.channels[&[1, 2, 3, 4][..]]
            .stream_publication_queue
            .as_ref()
            .unwrap()
            .has_items());
        let stats = command_observer.stats();
        assert!(stats.peak_retained_items <= stats.max_items);
        assert!(stats.peak_retained_bytes <= stats.max_retained_bytes);
    }

    #[test]
    fn server_stream_detach_releases_undrained_publications() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);

        let channel_id = vec![1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        for (offset, fin, data) in
            [(10, false, b"one".as_slice()), (13, true, b"two")]
        {
            let publication =
                publisher.prepare_stream(3, offset, fin, data).unwrap();
            publisher.commit(publication).unwrap();
        }
        assert_eq!(
            publisher.test_profile().unwrap().publication_commands_sent,
            1
        );

        drop(attachment);
        assert_eq!(publisher.attached_connections().unwrap(), 0);
        runtime.process_writes(&mut pipe.server).unwrap();

        assert!(runtime.pending_stream_publications.is_empty());
        assert_eq!(
            pipe.server.multicast_stream_recovery_pending(&channel_id),
            0
        );
        deliver_server_flight(&mut pipe);
        let mut out = [0; 16];
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((6, true)));
        assert_eq!(&out[..6], b"onetwo");
        assert_eq!(
            publisher.delivery_metrics_snapshot(),
            quiche::multicast::StreamDeliveryMetricsSnapshot {
                direct_fallback_ranges_total: 2,
                direct_fallback_bytes_total: 6,
                ..Default::default()
            }
        );
    }

    #[test]
    fn server_stream_detach_waits_for_blocked_committed_publication() {
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let past = publisher.prepare_stream(3, 10, false, b"past").unwrap();
        publisher.commit(past).unwrap();

        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);
        let attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let live = publisher.prepare_stream(3, 14, true, b"live").unwrap();
        publisher.commit(live).unwrap();
        drop(attachment);
        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(runtime.pending_stream_publications.len(), 1);
        assert!(runtime.pending_stream_publications.is_retry_blocked());
        assert!(runtime.channels[&[1, 2, 3, 4][..]].stream_publisher);

        assert_eq!(pipe.server.stream_send(3, b"past", false), Ok(4));
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.pending_stream_publications.is_empty());
        assert!(!runtime.channels[&[1, 2, 3, 4][..]].stream_publisher);
        deliver_server_flight(&mut pipe);

        let mut out = [0; 16];
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((8, true)));
        assert_eq!(&out[..8], b"pastlive");
    }

    #[test]
    fn server_stream_detach_waits_for_missing_webtransport_prefix() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();

        let channel_id = [1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let publication = publisher
            .prepare_stream(3, 10, true, b"after prefix")
            .unwrap();
        publisher.commit(publication).unwrap();
        drop(attachment);
        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(runtime.pending_stream_publications.len(), 1);
        assert!(runtime.pending_stream_publications.is_retry_blocked());
        assert!(runtime.channels[&channel_id[..]].stream_publisher);

        send_webtransport_stream_prefix(&mut pipe, 3, 11);
        runtime.process_writes(&mut pipe.server).unwrap();

        assert!(runtime.pending_stream_publications.is_empty());
        assert!(!runtime.pending_stream_publications.is_retry_blocked());
        assert!(!runtime.channels[&channel_id[..]].stream_publisher);
        deliver_server_flight(&mut pipe);

        let mut out = [0; 16];
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((12, true)));
        assert_eq!(&out[..12], b"after prefix");
    }

    #[test]
    fn server_stream_detach_discards_collected_stream_publication() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);

        let channel_id = [1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let publication =
            publisher.prepare_stream(3, 10, true, b"stale").unwrap();
        publisher.commit(publication).unwrap();

        assert_eq!(
            pipe.server.stream_send(3, b"ordinary", true),
            Ok(b"ordinary".len())
        );
        pipe.advance().unwrap();

        let mut out = [0; 16];
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((8, true)));
        assert_eq!(&out[..8], b"ordinary");
        assert_eq!(
            pipe.server.stream_capacity(3),
            Err(quiche::Error::InvalidStreamState(3))
        );

        drop(attachment);
        runtime.process_writes(&mut pipe.server).unwrap();

        assert!(runtime.pending_stream_publications.is_empty());
        assert!(!runtime.pending_stream_publications.is_retry_blocked());
        assert!(!runtime.channels[&channel_id[..]].stream_publisher);
        assert_eq!(
            pipe.server.multicast_stream_recovery_pending(&channel_id),
            0
        );
    }

    #[test]
    fn server_stream_reattach_requires_fresh_ack_before_cutover() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);

        let channel_id = vec![1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let old = publisher.prepare_stream(3, 10, false, b"old").unwrap();
        publisher.commit(old).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);
        let mut out = [0; 16];
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((3, false)));

        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );
        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::Viable)
        );

        drop(attachment);
        runtime.process_writes(&mut pipe.server).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::Probing)
        );

        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );
        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::Probing)
        );

        let new = publisher.prepare_stream(3, 13, false, b"new").unwrap();
        publisher.commit(new).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((3, false)));
        assert_eq!(&out[..3], b"new");

        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );
        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::Probing)
        );

        let end = publisher.prepare_stream(3, 16, true, b"end").unwrap();
        publisher.commit(end).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((3, true)));
        assert_eq!(&out[..3], b"end");

        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id,
                largest_acknowledged: 2,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );
        assert_eq!(
            pipe.server.multicast_probe_status(&[1, 2, 3, 4]),
            Some(quiche::multicast::ProbeStatus::Viable)
        );
    }

    fn structural_profile_percentile(
        sorted_nanos: &[u128], percentile: usize,
    ) -> u128 {
        let index = sorted_nanos
            .len()
            .saturating_sub(1)
            .saturating_mul(percentile) /
            100;
        sorted_nanos[index]
    }

    fn run_stream_attachment_structural_profile(client_count: usize) {
        const PUBLICATION_COUNT: usize = 32;
        const STREAM_ID: u64 = 3;

        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(STREAM_ID).unwrap();
        let mut attachments = Vec::with_capacity(client_count);

        for _ in 0..client_count {
            let (command_sender, command_receiver, command_observer) =
                test_server_control_command_channel();
            let (_event_sender, event_receiver, event_observer) =
                test_server_event_channel();
            let controller = ServerControlController {
                command_sender,
                command_observer: command_observer.clone(),
                pending_publication_observer: test_retained_queue_observer(),
                pending_integrity_observer: test_retained_queue_observer(),
                event_receiver: Some(event_receiver),
                event_observer,
            };
            let attachment = publisher.attach(&controller).unwrap();
            attachments.push((command_receiver, command_observer, attachment));
        }

        let payload = Bytes::from(vec![0x5a; 256]);
        let mut offset = 10_u64;
        let mut publication_nanos = Vec::with_capacity(PUBLICATION_COUNT);
        for index in 0..PUBLICATION_COUNT {
            let publication = publisher
                .prepare_stream_buf(
                    STREAM_ID,
                    offset,
                    index + 1 == PUBLICATION_COUNT,
                    payload.clone(),
                )
                .unwrap();
            let started = std::time::Instant::now();
            publisher.commit(publication).unwrap();
            publication_nanos.push(started.elapsed().as_nanos());
            offset = offset.saturating_add(payload.len() as u64);
        }
        publication_nanos.sort_unstable();

        let profile = publisher.test_profile().unwrap();
        let command_peak_items = attachments
            .iter()
            .map(|(_, observer, _)| observer.stats().peak_retained_items)
            .sum::<usize>();
        let command_peak_bytes = attachments
            .iter()
            .map(|(_, observer, _)| observer.stats().peak_retained_bytes)
            .sum::<usize>();

        assert_eq!(profile.attached_connections, client_count);
        assert_eq!(
            profile.attachment_queue_items,
            client_count * PUBLICATION_COUNT
        );
        assert!(
            profile.attachment_queue_bytes <=
                client_count *
                    ServerStreamPublisherLimits::default()
                        .max_attachment_queue_bytes
        );

        println!(
            concat!(
                "MCQUIC_ATTACHMENT_PROFILE clients={} publications={} ",
                "queue_items={} queue_bytes={} command_peak_items={} ",
                "command_peak_bytes={} p50_ns={} p95_ns={} p99_ns={} ",
                "worst_ns={} notifications={}"
            ),
            client_count,
            PUBLICATION_COUNT,
            profile.attachment_queue_items,
            profile.attachment_queue_bytes,
            command_peak_items,
            command_peak_bytes,
            structural_profile_percentile(&publication_nanos, 50),
            structural_profile_percentile(&publication_nanos, 95),
            structural_profile_percentile(&publication_nanos, 99),
            publication_nanos.last().copied().unwrap_or(0),
            profile.publication_commands_sent,
        );
    }

    #[test]
    #[ignore = "release-mode structural profile; run explicitly"]
    fn server_stream_publisher_profiles_one_and_ten_thousand_attachments() {
        run_stream_attachment_structural_profile(1_000);
        run_stream_attachment_structural_profile(10_000);
    }

    #[test]
    #[ignore = "deterministic performance profile; run explicitly"]
    fn server_stream_publisher_profiles_eighty_connections() {
        const CLIENT_COUNT: usize = 80;
        const RANGES_PER_PHASE: usize = 32;
        const STREAM_ID: u64 = 3;
        const WEBTRANSPORT_PREFIX_LEN: u64 = 10;

        let settings = test_settings();
        let config = test_stream_control_config();
        let channel_id = config.announce.channel_id.clone();
        let publisher = ServerStreamPublisher::new(config).unwrap();
        publisher.declare_stream(STREAM_ID).unwrap();

        let mut connections = setup_stream_profile_connections(
            &settings,
            &publisher,
            &channel_id,
            STREAM_ID,
            CLIENT_COUNT,
            StreamIntegrityBatchingSettings::default(),
        );

        let mut stream_offset = WEBTRANSPORT_PREFIX_LEN;
        let mut task_wakes = 0_u64;
        let payload = Bytes::from(vec![0x5a; 1024]);

        let (next_offset, wakes) = publish_profile_burst(
            &publisher,
            &mut connections,
            STREAM_ID,
            stream_offset,
            RANGES_PER_PHASE,
            &payload,
            false,
        );
        stream_offset = next_offset;
        task_wakes = task_wakes.saturating_add(wakes);

        for connection in &mut connections {
            send_client_control(
                &mut connection.pipe,
                &mut connection.runtime,
                quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                    channel_id: channel_id.clone(),
                    largest_acknowledged: RANGES_PER_PHASE as u64 - 1,
                    ack_delay: 0,
                    first_ack_range: 0,
                    ack_ranges: Vec::new(),
                    ecn_counts: None,
                }),
            );
        }

        let (next_offset, wakes) = publish_profile_burst(
            &publisher,
            &mut connections,
            STREAM_ID,
            stream_offset,
            RANGES_PER_PHASE,
            &payload,
            false,
        );
        stream_offset = next_offset;
        task_wakes = task_wakes.saturating_add(wakes);
        let peak_recovery_ranges = connections
            .iter()
            .map(|connection| {
                connection
                    .pipe
                    .server
                    .multicast_stream_recovery_pending(&channel_id)
            })
            .sum::<usize>();
        assert_eq!(peak_recovery_ranges, CLIENT_COUNT * RANGES_PER_PHASE);

        for connection in &mut connections {
            send_client_control(
                &mut connection.pipe,
                &mut connection.runtime,
                quiche::multicast::Frame::State(quiche::multicast::State {
                    channel_id: channel_id.clone(),
                    sequence: 2,
                    state: quiche::multicast::ChannelState::Left,
                    reason_scope: quiche::multicast::StateReasonScope::Transport,
                    reason_code:
                        quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                    reason_phrase: Vec::new(),
                }),
            );
        }

        let (_, wakes) = publish_profile_burst(
            &publisher,
            &mut connections,
            STREAM_ID,
            stream_offset,
            RANGES_PER_PHASE,
            &payload,
            true,
        );
        task_wakes = task_wakes.saturating_add(wakes);

        let final_recovery_ranges = connections
            .iter()
            .map(|connection| {
                connection
                    .pipe
                    .server
                    .multicast_stream_recovery_pending(&channel_id)
            })
            .sum::<usize>();
        assert_eq!(final_recovery_ranges, 0);

        let mut client_limits_events = 0_u64;
        let mut client_state_events = 0_u64;
        let mut client_ack_events = 0_u64;
        let mut probe_events = 0_u64;
        for connection in &mut connections {
            let event_receiver = connection
                .controller
                .event_receiver
                .as_mut()
                .expect("profile receiver is retained");
            while let Ok(event) = event_receiver.try_recv() {
                match event {
                    ServerEvent::ClientLimits(..) => client_limits_events += 1,

                    ServerEvent::ClientState(..) => client_state_events += 1,

                    ServerEvent::ClientAck(..) => client_ack_events += 1,

                    ServerEvent::ProbeStatusChanged(..) => probe_events += 1,

                    ServerEvent::Published { .. } |
                    ServerEvent::EncodeError { .. } |
                    ServerEvent::PublishError { .. } => (),
                }
            }
        }

        let metric_fold_attempts = connections
            .iter()
            .map(|connection| {
                connection.runtime.stream_delivery_metric_fold_attempts
            })
            .sum::<u64>();
        let publication_registrations = connections
            .iter()
            .map(|connection| connection.runtime.stream_publication_registrations)
            .sum::<u64>();
        let profile = publisher.test_profile().unwrap();
        let delivery = publisher.delivery_metrics_snapshot();

        assert_eq!(client_ack_events, CLIENT_COUNT as u64);
        assert_eq!(
            publication_registrations,
            (CLIENT_COUNT * RANGES_PER_PHASE * 3) as u64
        );
        assert_eq!(
            delivery.direct_fallback_ranges_total,
            (CLIENT_COUNT * RANGES_PER_PHASE * 2) as u64
        );
        assert_eq!(
            delivery.fallback_reentry_ranges_total,
            (CLIENT_COUNT * RANGES_PER_PHASE) as u64
        );
        assert_eq!(profile.tracked_streams, 0);
        assert_eq!(profile.finished_streams, 1);
        assert_eq!(profile.finished_stream_storage_units, 1);
        assert_eq!(profile.attached_connections, CLIENT_COUNT);
        assert!(
            profile.preparation_capacity_bytes <
                (RANGES_PER_PHASE * 3 * 2048) as u64
        );

        println!(
            concat!(
                "MCQUIC_PROFILE clients={} ranges_per_phase={} ",
                "publication_commands={} task_wakes={} ",
                "publication_registrations={} ",
                "preparation_capacity_bytes={} ack_events={} ",
                "probe_events={} limits_events={} state_events={} ",
                "metric_fold_attempts={} peak_recovery_ranges={} ",
                "final_recovery_ranges={} direct_ranges={} ",
                "gap_recovery_ranges={} reentry_ranges={} ",
                "publisher_tracked_streams={} ",
                "publisher_finished_streams={} ",
                "publisher_finished_stream_storage_units={}"
            ),
            CLIENT_COUNT,
            RANGES_PER_PHASE,
            profile.publication_commands_sent,
            task_wakes,
            publication_registrations,
            profile.preparation_capacity_bytes,
            client_ack_events,
            probe_events,
            client_limits_events,
            client_state_events,
            metric_fold_attempts,
            peak_recovery_ranges,
            final_recovery_ranges,
            delivery.direct_fallback_ranges_total,
            delivery.ack_gap_recovery_ranges_total,
            delivery.fallback_reentry_ranges_total,
            profile.tracked_streams,
            profile.finished_streams,
            profile.finished_stream_storage_units,
        );
    }

    #[tokio::test]
    #[ignore = "long established-connection performance profile"]
    async fn server_stream_publisher_profiles_established_connections() {
        const CLIENT_COUNT: usize = 80;
        const RANGES_PER_ROUND: usize = 4_096;
        const ROUND_COUNT: usize = 4;
        const STREAM_ID: u64 = 3;
        const WEBTRANSPORT_PREFIX_LEN: u64 = 10;

        let settings = test_settings();
        let config = test_stream_control_config();
        let channel_id = config.announce.channel_id.clone();
        let publisher = ServerStreamPublisher::new(config).unwrap();
        publisher.declare_stream(STREAM_ID).unwrap();
        let batching = StreamIntegrityBatchingSettings {
            max_packet_hashes: 16,
            max_delay: Duration::from_secs(1),
        };

        let mut connections = setup_stream_profile_connections(
            &settings,
            &publisher,
            &channel_id,
            STREAM_ID,
            CLIENT_COUNT,
            batching,
        );

        let payload = Bytes::from(vec![0x5a; 24]);
        let (mut stream_offset, _) = publish_profile_burst(
            &publisher,
            &mut connections,
            STREAM_ID,
            WEBTRANSPORT_PREFIX_LEN,
            1,
            &payload,
            false,
        );
        for connection in &mut connections {
            send_client_control(
                &mut connection.pipe,
                &mut connection.runtime,
                quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                    channel_id: channel_id.clone(),
                    largest_acknowledged: 0,
                    ack_delay: 0,
                    first_ack_range: 0,
                    ack_ranges: Vec::new(),
                    ecn_counts: None,
                }),
            );
        }

        let baseline_registrations = connections
            .iter()
            .map(|connection| connection.runtime.stream_publication_registrations)
            .sum::<u64>();
        let started = Instant::now();
        let mut task_wakes = 0_u64;
        let mut peak_recovery_ranges = 0_usize;

        for round in 0..ROUND_COUNT {
            let (next_offset, wakes) = publish_profile_burst(
                &publisher,
                &mut connections,
                STREAM_ID,
                stream_offset,
                RANGES_PER_ROUND,
                &payload,
                round + 1 == ROUND_COUNT,
            );
            stream_offset = next_offset;
            task_wakes = task_wakes.saturating_add(wakes);

            let recovery_ranges = connections
                .iter()
                .map(|connection| {
                    connection
                        .pipe
                        .server
                        .multicast_stream_recovery_pending(&channel_id)
                })
                .sum::<usize>();
            peak_recovery_ranges = peak_recovery_ranges.max(recovery_ranges);
            assert_eq!(recovery_ranges, CLIENT_COUNT * RANGES_PER_ROUND);

            let largest_acknowledged = ((round + 1) * RANGES_PER_ROUND) as u64;
            for connection in &mut connections {
                send_client_control(
                    &mut connection.pipe,
                    &mut connection.runtime,
                    quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                        channel_id: channel_id.clone(),
                        largest_acknowledged,
                        ack_delay: 0,
                        first_ack_range: RANGES_PER_ROUND as u64 - 1,
                        ack_ranges: Vec::new(),
                        ecn_counts: None,
                    }),
                );
            }
        }

        let elapsed = started.elapsed();
        let registrations = connections
            .iter()
            .map(|connection| connection.runtime.stream_publication_registrations)
            .sum::<u64>()
            .saturating_sub(baseline_registrations);
        let final_recovery_ranges = connections
            .iter()
            .map(|connection| {
                connection
                    .pipe
                    .server
                    .multicast_stream_recovery_pending(&channel_id)
            })
            .sum::<usize>();
        let profile = publisher.test_profile().unwrap();

        assert_eq!(
            registrations,
            (CLIENT_COUNT * RANGES_PER_ROUND * ROUND_COUNT) as u64
        );
        assert_eq!(final_recovery_ranges, 0);
        assert_eq!(profile.tracked_streams, 0);
        assert_eq!(profile.finished_streams, 1);

        println!(
            concat!(
                "MCQUIC_ESTABLISHED_PROFILE clients={} rounds={} ",
                "ranges_per_round={} registrations={} task_wakes={} ",
                "peak_recovery_ranges={} final_recovery_ranges={} ",
                "elapsed_us={} ns_per_registration={}"
            ),
            CLIENT_COUNT,
            ROUND_COUNT,
            RANGES_PER_ROUND,
            registrations,
            task_wakes,
            peak_recovery_ranges,
            final_recovery_ranges,
            elapsed.as_micros(),
            elapsed.as_nanos() / u128::from(registrations),
        );
    }

    #[test]
    fn server_stream_integrity_batches_contiguous_hashes_by_count() {
        let (mut runtime, _controller) =
            test_stream_control_runtime_with_integrity_batching(
                StreamIntegrityBatchingSettings {
                    max_packet_hashes: 3,
                    max_delay: Duration::from_millis(75),
                },
            );
        let now = Instant::now();

        runtime
            .queue_stream_integrity(test_stream_integrity(10, 0xaa), now)
            .unwrap();
        runtime
            .queue_stream_integrity(test_stream_integrity(11, 0xbb), now)
            .unwrap();
        assert!(runtime.pending_integrities.is_empty());
        assert_eq!(runtime.pending_stream_integrity_batches.len(), 1);

        runtime
            .queue_stream_integrity(test_stream_integrity(12, 0xcc), now)
            .unwrap();
        assert!(runtime.pending_stream_integrity_batches.is_empty());
        assert_eq!(
            runtime.pending_integrities.pop_front(),
            Some(quiche::multicast::Integrity {
                channel_id: vec![1, 2, 3, 4],
                packet_number_start: 10,
                packet_hash_count: Some(3),
                packet_hashes: [vec![0xaa; 32], vec![0xbb; 32], vec![0xcc; 32]]
                    .concat(),
            })
        );
    }

    #[test]
    fn server_stream_integrity_does_not_batch_across_packet_gaps() {
        let (mut runtime, _controller) =
            test_stream_control_runtime_with_integrity_batching(
                StreamIntegrityBatchingSettings {
                    max_packet_hashes: 3,
                    max_delay: Duration::from_millis(75),
                },
            );
        let now = Instant::now();
        let first = test_stream_integrity(10, 0xaa);
        let after_gap = test_stream_integrity(12, 0xcc);

        runtime.queue_stream_integrity(first.clone(), now).unwrap();
        runtime
            .queue_stream_integrity(after_gap.clone(), now)
            .unwrap();

        assert_eq!(runtime.pending_integrities.pop_front(), Some(first));
        assert_eq!(
            runtime.pending_stream_integrity_batches[&[1, 2, 3, 4][..]]
                .as_ref()
                .frame,
            after_gap
        );
    }

    #[test]
    fn server_stream_integrity_batches_share_bounded_send_budget() {
        let limits = RuntimeLimits {
            pending_integrity: RetainedQueueLimits {
                max_items: 2,
                max_retained_bytes: 1024,
            },
            ..RuntimeLimits::default()
        };
        let (_command_sender, command_receiver, _command_observer) =
            bounded_channel(limits.commands);
        let (event_sender, _event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::with_limits(
            ServerControlSettings {
                mode: ServerControlMode::Automatic,
                channels: Vec::new(),
                stream_integrity_batching: StreamIntegrityBatchingSettings {
                    max_packet_hashes: 3,
                    max_delay: Duration::from_millis(75),
                },
            },
            event_sender,
            command_receiver,
            limits,
        );

        let now = Instant::now();
        let first = test_stream_integrity(10, 0xaa);
        let mut second = test_stream_integrity(10, 0xbb);
        let mut rejected = test_stream_integrity(10, 0xcc);
        second.channel_id = vec![5, 6, 7, 8];
        rejected.channel_id = vec![9, 10, 11, 12];

        runtime.queue_stream_integrity(first.clone(), now).unwrap();
        runtime.queue_stream_integrity(second, now).unwrap();
        assert!(runtime.queue_stream_integrity(rejected, now).is_err());

        let observer = runtime.pending_integrities.observer();
        let stats = observer.stats();
        assert_eq!(stats.retained_items, 2);
        assert!(stats.retained_bytes <= stats.max_retained_bytes);
        assert_eq!(stats.saturations_total, 1);

        runtime
            .flush_stream_integrity_batch(&first.channel_id)
            .unwrap();
        assert_eq!(observer.stats().retained_items, 2);
        assert_eq!(runtime.pending_integrities.pop_front(), Some(first));
        assert_eq!(observer.stats().retained_items, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn server_stream_integrity_tail_wakes_at_max_delay() {
        let (mut runtime, _controller) =
            test_stream_control_runtime_with_integrity_batching(
                StreamIntegrityBatchingSettings {
                    max_packet_hashes: 3,
                    max_delay: Duration::from_millis(75),
                },
            );
        let integrity = test_stream_integrity(10, 0xaa);
        runtime
            .queue_stream_integrity(integrity.clone(), Instant::now())
            .unwrap();

        assert!(!runtime.has_pending_work());
        assert!(tokio::time::timeout(
            Duration::from_millis(74),
            runtime.wait_for_work()
        )
        .await
        .is_err());
        assert!(tokio::time::timeout(
            Duration::from_millis(2),
            runtime.wait_for_work()
        )
        .await
        .is_ok());
        assert!(runtime.has_pending_work());

        assert!(runtime
            .stage_one_due_stream_integrity(Instant::now())
            .unwrap());
        assert_eq!(runtime.pending_integrities.pop_front(), Some(integrity));
        assert!(runtime.pending_stream_integrity_batches.is_empty());
    }

    #[test]
    fn server_stream_publisher_fans_out_unicast_fallback_to_two_clients() {
        let settings = test_settings();
        let mut first = test_stream_pipe(&settings);
        let mut second = test_stream_pipe(&settings);
        let (mut first_runtime, first_controller) = test_stream_control_runtime();
        let (mut second_runtime, second_controller) =
            test_stream_control_runtime();
        first_runtime
            .on_conn_established(&mut first.server)
            .unwrap();
        second_runtime
            .on_conn_established(&mut second.server)
            .unwrap();
        send_webtransport_stream_prefix(&mut first, 3, 11);
        send_webtransport_stream_prefix(&mut second, 3, 22);

        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let first_attachment = publisher.attach(&first_controller).unwrap();
        let second_attachment = publisher.attach(&second_controller).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();

        let publication = publisher
            .prepare_stream(3, 10, false, b"one shared body")
            .unwrap();
        publisher.commit(publication).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();
        let channel_metrics = publisher.metrics_snapshot().unwrap();
        assert_eq!(
            publisher.delivery_metrics_snapshot(),
            quiche::multicast::StreamDeliveryMetricsSnapshot {
                direct_fallback_ranges_total: 2,
                direct_fallback_bytes_total: 30,
                ..Default::default()
            }
        );
        assert_eq!(publisher.metrics_snapshot().unwrap(), channel_metrics);
        deliver_server_flight(&mut first);
        deliver_server_flight(&mut second);

        let mut out = [0; 32];
        assert_eq!(first.client.stream_recv(3, &mut out), Ok((15, false)));
        assert_eq!(&out[..15], b"one shared body");
        assert_eq!(second.client.stream_recv(3, &mut out), Ok((15, false)));
        assert_eq!(&out[..15], b"one shared body");
        assert_eq!(publisher.attached_connections().unwrap(), 2);

        drop(first_attachment);
        drop(second_attachment);
        assert_eq!(publisher.attached_connections().unwrap(), 0);
        assert_eq!(
            publisher.delivery_metrics_snapshot(),
            quiche::multicast::StreamDeliveryMetricsSnapshot {
                direct_fallback_ranges_total: 2,
                direct_fallback_bytes_total: 30,
                ..Default::default()
            }
        );
    }

    #[test]
    fn server_stream_stalled_connection_does_not_block_healthy_connection() {
        let settings = test_settings();
        let mut stalled = test_stream_pipe(&settings);
        let mut healthy = test_stream_pipe(&settings);
        let (mut stalled_runtime, stalled_controller) =
            test_stream_control_runtime();
        let (mut healthy_runtime, healthy_controller) =
            test_stream_control_runtime();
        stalled_runtime
            .on_conn_established(&mut stalled.server)
            .unwrap();
        healthy_runtime
            .on_conn_established(&mut healthy.server)
            .unwrap();
        send_webtransport_stream_prefix(&mut healthy, 3, 22);

        let channel_id = vec![1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let _stalled_attachment = publisher.attach(&stalled_controller).unwrap();
        let _healthy_attachment = publisher.attach(&healthy_controller).unwrap();
        stalled_runtime.process_writes(&mut stalled.server).unwrap();
        healthy_runtime.process_writes(&mut healthy.server).unwrap();

        let publication = publisher
            .prepare_stream(3, 10, true, b"independent progress")
            .unwrap();
        publisher.commit(publication).unwrap();
        stalled_runtime.process_writes(&mut stalled.server).unwrap();
        healthy_runtime.process_writes(&mut healthy.server).unwrap();

        assert_eq!(
            stalled_runtime
                .pending_stream_publications
                .observer()
                .stats()
                .retained_items,
            1
        );
        assert_eq!(
            healthy_runtime
                .pending_stream_publications
                .observer()
                .stats()
                .retained_items,
            0
        );
        deliver_server_flight(&mut healthy);
        let mut out = [0; 32];
        assert_eq!(
            healthy.client.stream_recv(3, &mut out),
            Ok((b"independent progress".len(), true))
        );
        assert_eq!(
            &out[..b"independent progress".len()],
            b"independent progress"
        );

        send_webtransport_stream_prefix(&mut stalled, 3, 11);
        stalled_runtime.process_writes(&mut stalled.server).unwrap();
        assert_eq!(
            stalled
                .server
                .multicast_stream_recovery_pending(&channel_id),
            0
        );
        deliver_server_flight(&mut stalled);
        assert_eq!(
            stalled.client.stream_recv(3, &mut out),
            Ok((b"independent progress".len(), true))
        );
    }

    #[test]
    fn server_stream_publisher_attaches_directly_to_sparse_high_stream_id() {
        let settings = test_settings();
        let stream_ordinal = 1_000_003;
        let stream_id = (stream_ordinal << 2) | 0x3;
        let mut pipe =
            test_stream_pipe_with_max_streams_uni(&settings, stream_ordinal + 1);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(test_limits()),
        );
        send_webtransport_stream_prefix(&mut pipe, stream_id, 11);

        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        publisher.declare_stream(stream_id).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let publication = publisher
            .prepare_stream(stream_id, 10, true, b"direct high-id body")
            .unwrap();
        publisher.commit(publication).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);

        let mut out = [0; 32];
        assert_eq!(pipe.client.stream_recv(stream_id, &mut out), Ok((19, true)));
        assert_eq!(&out[..19], b"direct high-id body");
        assert_eq!(pipe.server.peer_streams_left_uni(), 0);
    }

    #[test]
    fn server_stream_ack_cuts_over_left_falls_back_and_later_rejoins() {
        let settings = test_settings();
        let mut first = test_stream_pipe(&settings);
        let mut second = test_stream_pipe(&settings);
        let (mut first_runtime, first_controller) = test_stream_control_runtime();
        let (mut second_runtime, second_controller) =
            test_stream_control_runtime();
        first_runtime
            .on_conn_established(&mut first.server)
            .unwrap();
        second_runtime
            .on_conn_established(&mut second.server)
            .unwrap();
        send_webtransport_stream_prefix(&mut first, 3, 11);
        send_webtransport_stream_prefix(&mut second, 3, 22);

        let channel_id = vec![1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let _first_attachment = publisher.attach(&first_controller).unwrap();
        let _second_attachment = publisher.attach(&second_controller).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();

        send_client_control(
            &mut first,
            &mut first_runtime,
            quiche::multicast::Frame::Limits(test_limits()),
        );
        deliver_server_flight(&mut first);
        send_client_control(
            &mut first,
            &mut first_runtime,
            quiche::multicast::Frame::State(quiche::multicast::State {
                channel_id: channel_id.clone(),
                sequence: 1,
                state: quiche::multicast::ChannelState::Joined,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                reason_phrase: Vec::new(),
            }),
        );

        let baseline =
            publisher.prepare_stream(3, 10, false, b"baseline").unwrap();
        publisher.commit(baseline).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();
        deliver_server_flight(&mut first);
        deliver_server_flight(&mut second);

        let mut out = [0; 64];
        assert_eq!(first.client.stream_recv(3, &mut out), Ok((8, false)));
        assert_eq!(&out[..8], b"baseline");
        assert_eq!(second.client.stream_recv(3, &mut out), Ok((8, false)));
        assert_eq!(&out[..8], b"baseline");

        send_client_control(
            &mut first,
            &mut first_runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );
        assert_eq!(
            first.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::Viable),
            "work={} readable={} queued={} channel_present={}",
            first_runtime.callback_read_work_last_call,
            first.server.is_multicast_readable(),
            first.server.multicast_recv_queue_len(),
            first_runtime.channels.contains_key(&channel_id),
        );

        let multicast_only = publisher
            .prepare_stream(3, 18, false, b"green-gap")
            .unwrap();
        publisher.commit(multicast_only).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();
        deliver_server_flight(&mut first);
        deliver_server_flight(&mut second);

        assert_eq!(
            first.client.stream_recv(3, &mut out),
            Err(quiche::Error::Done)
        );
        assert_eq!(second.client.stream_recv(3, &mut out), Ok((9, false)));
        assert_eq!(&out[..9], b"green-gap");
        assert_eq!(
            first.server.multicast_stream_recovery_pending(&channel_id),
            1
        );
        assert_eq!(
            publisher.delivery_metrics_snapshot(),
            quiche::multicast::StreamDeliveryMetricsSnapshot {
                direct_fallback_ranges_total: 3,
                direct_fallback_bytes_total: 25,
                ..Default::default()
            }
        );

        send_client_control(
            &mut first,
            &mut first_runtime,
            quiche::multicast::Frame::State(quiche::multicast::State {
                channel_id: channel_id.clone(),
                sequence: 2,
                state: quiche::multicast::ChannelState::Left,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                reason_phrase: Vec::new(),
            }),
        );

        let fallback =
            publisher.prepare_stream(3, 27, true, b"fallback").unwrap();
        publisher.commit(fallback).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();
        deliver_server_flight(&mut first);
        deliver_server_flight(&mut second);

        assert_eq!(first.client.stream_recv(3, &mut out), Ok((17, true)));
        assert_eq!(&out[..17], b"green-gapfallback");
        assert_eq!(second.client.stream_recv(3, &mut out), Ok((8, true)));
        assert_eq!(&out[..8], b"fallback");
        assert_eq!(
            first.server.multicast_stream_recovery_pending(&channel_id),
            0
        );

        send_webtransport_stream_prefix(&mut first, 7, 11);
        send_webtransport_stream_prefix(&mut second, 7, 22);
        publisher.declare_stream(7).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();
        let mut renewed_limits = test_limits();
        renewed_limits.sequence = 2;
        send_client_control(
            &mut first,
            &mut first_runtime,
            quiche::multicast::Frame::Limits(renewed_limits),
        );
        deliver_server_flight(&mut first);
        send_client_control(
            &mut first,
            &mut first_runtime,
            quiche::multicast::Frame::State(quiche::multicast::State {
                channel_id: channel_id.clone(),
                sequence: 3,
                state: quiche::multicast::ChannelState::Joined,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                reason_phrase: Vec::new(),
            }),
        );

        let rejoin_probe = publisher
            .prepare_stream(7, 10, false, b"rejoin-probe")
            .unwrap();
        publisher.commit(rejoin_probe).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();
        deliver_server_flight(&mut first);
        deliver_server_flight(&mut second);
        assert_eq!(first.client.stream_recv(7, &mut out), Ok((12, false)));
        assert_eq!(&out[..12], b"rejoin-probe");
        assert_eq!(second.client.stream_recv(7, &mut out), Ok((12, false)));
        assert_eq!(&out[..12], b"rejoin-probe");

        send_client_control(
            &mut first,
            &mut first_runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 3,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );
        assert_eq!(
            first.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::Viable)
        );

        let multicast_again = publisher
            .prepare_stream(7, 22, true, b"green-again")
            .unwrap();
        publisher.commit(multicast_again).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();
        deliver_server_flight(&mut first);
        deliver_server_flight(&mut second);
        assert_eq!(
            first.client.stream_recv(7, &mut out),
            Err(quiche::Error::Done)
        );
        assert_eq!(second.client.stream_recv(7, &mut out), Ok((11, true)));
        assert_eq!(&out[..11], b"green-again");
    }

    #[test]
    fn server_stream_publisher_aggregates_exact_ack_gap_recovery() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);

        let channel_id = vec![1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.set_reordering_threshold(1).unwrap();
        publisher.declare_stream(3).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let baseline = publisher.prepare_stream(3, 10, false, b"a").unwrap();
        publisher.commit(baseline).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );

        for (offset, data, fin) in [
            (11, &b"one"[..], false),
            (14, &b"two"[..], false),
            (17, &b"three"[..], true),
        ] {
            let publication =
                publisher.prepare_stream(3, offset, fin, data).unwrap();
            publisher.commit(publication).unwrap();
        }
        runtime.process_writes(&mut pipe.server).unwrap();

        let ack = quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 3,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Ack(ack.clone()),
        );
        let after_recovery = publisher.delivery_metrics_snapshot();
        assert_eq!(
            after_recovery,
            quiche::multicast::StreamDeliveryMetricsSnapshot {
                direct_fallback_ranges_total: 1,
                direct_fallback_bytes_total: 1,
                ack_gap_recovery_ranges_total: 2,
                ack_gap_recovery_bytes_total: 6,
                ..Default::default()
            }
        );

        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Ack(ack),
        );
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id,
                largest_acknowledged: 2,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );
        assert_eq!(publisher.delivery_metrics_snapshot(), after_recovery);
    }

    #[test]
    fn server_stream_timeout_and_close_fold_retained_backlog_once() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);

        let channel_id = vec![1, 2, 3, 4];
        let mut config = test_stream_control_config();
        config.announce.max_ack_delay_ms = 0;
        let publisher = ServerStreamPublisher::new(config).unwrap();
        publisher.declare_stream(3).unwrap();
        let attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let baseline = publisher.prepare_stream(3, 10, false, b"a").unwrap();
        publisher.commit(baseline).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );

        let held = publisher.prepare_stream(3, 11, true, b"timeout").unwrap();
        publisher.commit(held).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        pipe.server.on_timeout();
        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::TimedOut)
        );

        runtime.on_conn_close(&pipe.server);
        let after_close = publisher.delivery_metrics_snapshot();
        assert_eq!(
            after_close,
            quiche::multicast::StreamDeliveryMetricsSnapshot {
                direct_fallback_ranges_total: 1,
                direct_fallback_bytes_total: 1,
                fallback_reentry_ranges_total: 1,
                fallback_reentry_bytes_total: 7,
                ..Default::default()
            }
        );
        runtime.on_conn_close(&pipe.server);
        drop(attachment);
        assert_eq!(publisher.delivery_metrics_snapshot(), after_close);
    }

    #[test]
    fn server_stream_retirement_folds_retained_backlog_once() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);

        let channel_id = vec![1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let baseline = publisher.prepare_stream(3, 10, false, b"a").unwrap();
        publisher.commit(baseline).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );

        let retained = publisher.prepare_stream(3, 11, true, b"retired").unwrap();
        publisher.commit(retained).unwrap();
        publisher
            .retire(quiche::multicast::Retire {
                channel_id,
                after_packet_number: 1,
            })
            .unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let after_retirement = publisher.delivery_metrics_snapshot();
        assert_eq!(
            after_retirement,
            quiche::multicast::StreamDeliveryMetricsSnapshot {
                direct_fallback_ranges_total: 1,
                direct_fallback_bytes_total: 1,
                fallback_reentry_ranges_total: 1,
                fallback_reentry_bytes_total: 7,
                ..Default::default()
            }
        );
        runtime.process_writes(&mut pipe.server).unwrap();
        runtime.on_conn_close(&pipe.server);
        assert_eq!(publisher.delivery_metrics_snapshot(), after_retirement);
    }

    #[test]
    fn server_stream_publishers_keep_channel_metrics_isolated() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);
        send_webtransport_stream_prefix(&mut pipe, 7, 22);

        let first =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        let mut second_config = test_stream_control_config();
        second_config.announce.channel_id = vec![5, 6, 7, 8];
        second_config.key.channel_id = vec![5, 6, 7, 8];
        let second = ServerStreamPublisher::new(second_config).unwrap();
        first.declare_stream(3).unwrap();
        second.declare_stream(7).unwrap();
        let _first_attachment = first.attach(&controller).unwrap();
        let _second_attachment = second.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let first_publication =
            first.prepare_stream(3, 10, true, b"first").unwrap();
        first.commit(first_publication).unwrap();
        let second_publication =
            second.prepare_stream(7, 10, true, b"second").unwrap();
        second.commit(second_publication).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(
            first.delivery_metrics_snapshot(),
            quiche::multicast::StreamDeliveryMetricsSnapshot {
                direct_fallback_ranges_total: 1,
                direct_fallback_bytes_total: 5,
                ..Default::default()
            }
        );
        assert_eq!(
            second.delivery_metrics_snapshot(),
            quiche::multicast::StreamDeliveryMetricsSnapshot {
                direct_fallback_ranges_total: 1,
                direct_fallback_bytes_total: 6,
                ..Default::default()
            }
        );
    }

    #[test]
    fn server_stream_reset_and_attachment_teardown_are_connection_local() {
        let settings = test_settings();
        let mut first = test_stream_pipe(&settings);
        let mut second = test_stream_pipe(&settings);
        let (mut first_runtime, first_controller) = test_stream_control_runtime();
        let (mut second_runtime, second_controller) =
            test_stream_control_runtime();
        first_runtime
            .on_conn_established(&mut first.server)
            .unwrap();
        second_runtime
            .on_conn_established(&mut second.server)
            .unwrap();
        send_webtransport_stream_prefix(&mut first, 3, 11);
        send_webtransport_stream_prefix(&mut second, 3, 22);

        let channel_id = vec![1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let first_attachment = publisher.attach(&first_controller).unwrap();
        let second_attachment = publisher.attach(&second_controller).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();

        let baseline = publisher.prepare_stream(3, 10, false, b"base").unwrap();
        publisher.commit(baseline).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();
        deliver_server_flight(&mut first);
        deliver_server_flight(&mut second);

        let mut out = [0; 32];
        assert_eq!(first.client.stream_recv(3, &mut out), Ok((4, false)));
        assert_eq!(second.client.stream_recv(3, &mut out), Ok((4, false)));

        send_client_control(
            &mut first,
            &mut first_runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );

        let held = publisher.prepare_stream(3, 14, false, b"held").unwrap();
        publisher.commit(held).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();
        assert_eq!(
            first.server.multicast_stream_recovery_pending(&channel_id),
            1
        );

        first
            .server
            .stream_shutdown(3, quiche::Shutdown::Write, 42)
            .unwrap();
        assert_eq!(
            first.server.multicast_stream_recovery_pending(&channel_id),
            0
        );
        deliver_server_flight(&mut first);
        deliver_server_flight(&mut second);
        assert_eq!(
            first.client.stream_recv(3, &mut out),
            Err(quiche::Error::StreamReset(42))
        );
        assert_eq!(second.client.stream_recv(3, &mut out), Ok((4, false)));
        assert_eq!(&out[..4], b"held");

        drop(first_attachment);
        assert_eq!(publisher.attached_connections().unwrap(), 1);
        let remaining = publisher.prepare_stream(3, 18, true, b"other").unwrap();
        publisher.commit(remaining).unwrap();
        first_runtime.process_writes(&mut first.server).unwrap();
        second_runtime.process_writes(&mut second.server).unwrap();
        deliver_server_flight(&mut second);
        assert_eq!(second.client.stream_recv(3, &mut out), Ok((5, true)));
        assert_eq!(&out[..5], b"other");

        drop(second_attachment);
        assert_eq!(publisher.attached_connections().unwrap(), 0);
    }

    #[test]
    fn server_stream_fallback_survives_mc_limits_that_forbid_joining() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);

        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let mut limits = test_limits();
        limits.max_joined_count = 0;
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(limits),
        );
        deliver_server_flight(&mut pipe);
        assert_no_queued_join(&mut pipe.client);

        let publication = publisher
            .prepare_stream(3, 10, true, b"fallback only")
            .unwrap();
        publisher.commit(publication).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);

        let mut out = [0; 32];
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((13, true)));
        assert_eq!(&out[..13], b"fallback only");
    }

    #[test]
    fn server_stream_auto_join_waits_for_quic_stream_credit() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        let max_streams_uni = pipe.server.peer_max_streams_uni();
        let blocked_stream_id = (max_streams_uni << 2) | 0x3;

        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(test_limits()),
        );

        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(blocked_stream_id).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);

        assert_no_queued_join(&mut pipe.client);
        assert!(!runtime.channels[&[1, 2, 3, 4][..]].join_sent);

        let publication = publisher
            .prepare_stream(blocked_stream_id, 0, false, b"wait for credit")
            .unwrap();
        publisher.commit(publication).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(runtime.pending_stream_publications.len(), 1);
        assert!(runtime.pending_stream_publications.is_retry_blocked());
        assert_eq!(pipe.server.multicast_send_queue_len(), 0);
        assert_eq!(
            publisher.delivery_metrics_snapshot(),
            quiche::multicast::StreamDeliveryMetricsSnapshot::default()
        );
    }

    #[test]
    fn server_stream_publisher_relays_key_rotation_and_retirement() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();

        let channel_id = vec![1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);
        while pipe.client.multicast_recv().is_ok() {}

        assert!(matches!(
            publisher.update_key(quiche::multicast::Key {
                channel_id: channel_id.clone(),
                key_sequence: 2,
                from_packet_number: 5,
                secret: vec![0xdd; 16],
            }),
            Err(ServerStreamPublisherError::InvalidState)
        ));
        let rotated = quiche::multicast::Key {
            channel_id: channel_id.clone(),
            key_sequence: 2,
            from_packet_number: 0,
            secret: vec![0xdd; 16],
        };
        publisher.update_key(rotated.clone()).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);
        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Key(rotated))
        );

        let retire = quiche::multicast::Retire {
            channel_id: channel_id.clone(),
            after_packet_number: 0,
        };
        publisher.retire(retire.clone()).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);
        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Retire(retire))
        );
        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::Retired)
        );
        assert!(matches!(
            publisher.prepare_stream(3, 0, false, b"retired"),
            Err(ServerStreamPublisherError::Retired)
        ));
    }

    #[test]
    fn server_stream_barriers_do_not_wait_for_another_blocked_channel() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 7, 22);

        let blocked_channel = vec![1, 2, 3, 4];
        let healthy_channel = vec![5, 6, 7, 8];
        let blocked =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        let mut healthy_config = test_stream_control_config();
        healthy_config.announce.channel_id = healthy_channel.clone();
        healthy_config.key.channel_id = healthy_channel.clone();
        let healthy = ServerStreamPublisher::new(healthy_config).unwrap();
        blocked.declare_stream(3).unwrap();
        healthy.declare_stream(7).unwrap();
        let _blocked_attachment = blocked.attach(&controller).unwrap();
        let _healthy_attachment = healthy.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);
        while pipe.client.multicast_recv().is_ok() {}

        let blocked_publication = blocked
            .prepare_stream(3, 10, false, b"missing prefix")
            .unwrap();
        blocked.commit(blocked_publication).unwrap();
        let healthy_publication = healthy
            .prepare_stream(7, 10, true, b"healthy channel")
            .unwrap();
        healthy.commit(healthy_publication).unwrap();
        healthy
            .retire(quiche::multicast::Retire {
                channel_id: healthy_channel.clone(),
                after_packet_number: 0,
            })
            .unwrap();

        runtime.process_writes(&mut pipe.server).unwrap();

        assert!(runtime
            .pending_stream_publications
            .contains_channel(&blocked_channel));
        assert!(!runtime
            .pending_stream_publications
            .contains_channel(&healthy_channel));
        assert!(runtime.channels[&healthy_channel[..]].retired);
        assert!(!runtime.channels[&healthy_channel[..]].stream_publisher);

        deliver_server_flight(&mut pipe);
        let mut out = [0; 32];
        assert_eq!(
            pipe.client.stream_recv(7, &mut out),
            Ok((b"healthy channel".len(), true))
        );
        assert_eq!(&out[..b"healthy channel".len()], b"healthy channel");
    }

    #[test]
    fn server_stream_integrity_precedes_following_key_barrier() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);

        let channel_id = vec![1, 2, 3, 4];
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);
        while pipe.client.multicast_recv().is_ok() {}

        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(test_limits()),
        );
        deliver_server_flight(&mut pipe);
        while pipe.client.multicast_recv().is_ok() {}

        let publication = publisher
            .prepare_stream(3, 10, false, b"before rotation")
            .unwrap();
        let integrity = publication.integrity().clone();
        publisher.commit(publication).unwrap();
        let rotated = quiche::multicast::Key {
            channel_id,
            key_sequence: 2,
            from_packet_number: 1,
            secret: vec![0xdd; 16],
        };
        publisher.update_key(rotated.clone()).unwrap();

        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);

        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Integrity(integrity))
        );
        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Key(rotated))
        );
    }

    #[test]
    fn server_stream_publisher_compacts_finished_streams_and_rejects_reuse() {
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();

        for sequence in 0..100 {
            let stream_id = (sequence << 2) | 0x3;
            let publication = publisher
                .prepare_stream(stream_id, 10, true, b"finished")
                .unwrap();
            publisher.commit(publication).unwrap();
        }

        let profile = publisher.test_profile().unwrap();
        assert_eq!(profile.tracked_streams, 0);
        assert_eq!(profile.finished_streams, 100);
        assert_eq!(profile.finished_stream_storage_units, 1);
        assert_eq!(publisher.next_stream_offset(3).unwrap(), None);
        assert!(matches!(
            publisher.prepare_stream(3, 10, false, b"reuse"),
            Err(ServerStreamPublisherError::StreamFinished { stream_id: 3 })
        ));
    }

    #[test]
    fn server_stream_late_attachment_waits_for_unicast_catch_up() {
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let past = publisher.prepare_stream(3, 10, false, b"past").unwrap();
        publisher.commit(past).unwrap();
        assert_eq!(publisher.next_stream_offset(3).unwrap(), Some(14));

        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);
        let _attachment = publisher.attach(&controller).unwrap();

        let live = publisher.prepare_stream(3, 14, true, b"live").unwrap();
        publisher.commit(live).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        assert_eq!(runtime.pending_stream_publications.len(), 1);
        assert!(runtime.pending_stream_publications.is_retry_blocked());

        assert_eq!(pipe.server.stream_send(3, b"past", false), Ok(4));
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.pending_stream_publications.is_empty());
        deliver_server_flight(&mut pipe);

        let mut out = [0; 16];
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((8, true)));
        assert_eq!(&out[..8], b"pastlive");
    }

    #[test]
    fn server_stream_retirement_waits_for_prior_recovery_registration() {
        let publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        publisher.declare_stream(3).unwrap();
        let past = publisher.prepare_stream(3, 10, false, b"past").unwrap();
        publisher.commit(past).unwrap();

        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let (mut runtime, controller) = test_stream_control_runtime();
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, 3, 11);
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(test_limits()),
        );
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);
        while pipe.client.multicast_recv().is_ok() {}
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::State(quiche::multicast::State {
                channel_id: vec![1, 2, 3, 4],
                sequence: 1,
                state: quiche::multicast::ChannelState::Joined,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                reason_phrase: Vec::new(),
            }),
        );

        let live = publisher.prepare_stream(3, 14, true, b"live").unwrap();
        publisher.commit(live).unwrap();
        publisher
            .retire(quiche::multicast::Retire {
                channel_id: vec![1, 2, 3, 4],
                after_packet_number: 1,
            })
            .unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(runtime.pending_stream_publications.len(), 1);
        assert!(!runtime.channels[&[1, 2, 3, 4][..]].retired);
        assert!(runtime.pending_stream_publications.is_retry_blocked());

        assert_eq!(pipe.server.stream_send(3, b"past", false), Ok(4));
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);

        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Integrity(_))
        ));
        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Retire(_))
        ));
        let mut out = [0; 16];
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((8, true)));
        assert_eq!(&out[..8], b"pastlive");
    }

    #[test]
    fn server_control_retries_atomic_announce_key_after_prolonged_full_queue() {
        let settings = test_settings();
        let mut pipe = test_pipe_with_server_control_queue(&settings, 1, 4096);
        let (_command_sender, command_receiver, command_observer) =
            test_server_control_command_channel();
        let (event_sender, _event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::with_limits(
            test_server_control_settings(),
            event_sender,
            command_receiver,
            RuntimeLimits::default(),
        );

        runtime.on_conn_established(&mut pipe.server).unwrap();
        assert_eq!(pipe.server.multicast_send_queue_len(), 1);
        assert_eq!(runtime.pending_commands.len(), 1);
        assert!(!runtime.channels[&[1, 2, 3, 4][..]].announce_sent);

        for _ in 0..32 {
            runtime.process_reads(&mut pipe.server).unwrap();
            runtime.process_writes(&mut pipe.server).unwrap();
            assert_eq!(pipe.server.multicast_send_queue_len(), 1);
            assert_eq!(runtime.pending_commands.len(), 1);
            assert_eq!(command_observer.stats().retained_items, 1);
            assert!(!runtime.channels[&[1, 2, 3, 4][..]].announce_sent);
        }

        pipe.advance().unwrap();
        runtime.process_reads(&mut pipe.server).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.pending_commands.is_empty());
        assert_eq!(command_observer.stats().retained_items, 0);
        assert!(runtime.channels[&[1, 2, 3, 4][..]].announce_sent);

        pipe.advance().unwrap();
        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Announce(_))
        ));
        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Key(_))
        ));
        assert_eq!(pipe.client.multicast_recv(), Err(quiche::Error::Done));
    }

    #[tokio::test(start_paused = true)]
    async fn server_control_blocked_publisher_waits_for_retry_deadline() {
        let settings = test_settings();
        let mut pipe = test_pipe_with_server_control_queue(&settings, 1, 4096);
        let limits = RuntimeLimits {
            max_work_per_call: 16,
            control_retry_delay: Duration::from_millis(100),
            ..RuntimeLimits::default()
        };
        let control_settings = ServerControlSettings {
            mode: ServerControlMode::Manual,
            channels: Vec::new(),
            stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
        };
        let (driver, controller) = ServerControlDriver::new_with_runtime_limits(
            (),
            control_settings,
            limits,
        )
        .unwrap();
        let mut runtime = driver.runtime;
        runtime.on_conn_established(&mut pipe.server).unwrap();

        let blocked_channel_id = vec![1, 2, 3, 4];
        let healthy_channel_id = vec![5, 6, 7, 8];
        let blocked_publisher =
            ServerStreamPublisher::new(test_stream_control_config()).unwrap();
        let mut healthy_config = test_stream_control_config();
        healthy_config.announce.channel_id = healthy_channel_id.clone();
        healthy_config.key.channel_id = healthy_channel_id.clone();
        let healthy_publisher =
            ServerStreamPublisher::new(healthy_config).unwrap();
        let _blocked_attachment = blocked_publisher.attach(&controller).unwrap();
        let _healthy_attachment = healthy_publisher.attach(&controller).unwrap();

        for _ in 0..8 {
            runtime.process_writes(&mut pipe.server).unwrap();
            if runtime.pending_commands.is_empty() &&
                runtime.command_receiver.try_recv().is_err()
            {
                break;
            }
        }
        assert!(runtime.channels[&blocked_channel_id].stream_publisher);
        assert!(runtime.channels[&healthy_channel_id].stream_publisher);

        let mut filler = test_ipv4_announce();
        filler.channel_id = vec![9];
        pipe.server
            .multicast_send(quiche::multicast::Frame::Announce(filler))
            .unwrap();
        assert_eq!(pipe.server.multicast_send_queue_len(), 1);
        controller.send_key(test_key(&blocked_channel_id)).unwrap();

        for _ in 0..8 {
            runtime.process_writes(&mut pipe.server).unwrap();
            if runtime
                .blocked_command_channels
                .contains(&blocked_channel_id)
            {
                break;
            }
        }
        assert!(runtime
            .blocked_command_channels
            .contains(&blocked_channel_id));
        let retry_deadline = runtime.control_retry_deadline.unwrap();
        assert!(retry_deadline > Instant::now());

        blocked_publisher.declare_stream(3).unwrap();
        healthy_publisher.declare_stream(7).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        let blocked_queue = runtime.channels[&blocked_channel_id]
            .stream_publication_queue
            .as_ref()
            .unwrap();
        let healthy_queue = runtime.channels[&healthy_channel_id]
            .stream_publication_queue
            .as_ref()
            .unwrap();
        assert!(blocked_queue.has_pending());
        assert!(!healthy_queue.has_pending());
        assert_eq!(runtime.channels[&healthy_channel_id].max_stream_id, Some(7));
        assert_eq!(runtime.channels[&blocked_channel_id].max_stream_id, None);
        assert!(runtime.command_receiver.try_recv().is_err());
        assert!(!runtime.has_pending_work());
        assert_eq!(runtime.next_runtime_deadline(), Some(retry_deadline));

        pipe.advance().unwrap();
        assert_eq!(pipe.server.multicast_send_queue_len(), 0);
        assert!(tokio::time::timeout(
            Duration::from_millis(99),
            runtime.wait_for_work()
        )
        .await
        .is_err());
        assert!(tokio::time::timeout(
            Duration::from_millis(2),
            runtime.wait_for_work()
        )
        .await
        .is_ok());
        assert!(runtime.has_pending_work());

        for _ in 0..8 {
            runtime.process_writes(&mut pipe.server).unwrap();
            if !runtime.channels[&blocked_channel_id]
                .stream_publication_queue
                .as_ref()
                .unwrap()
                .has_pending() &&
                runtime.pending_commands.is_empty()
            {
                break;
            }
        }
        assert!(!runtime
            .blocked_command_channels
            .contains(&blocked_channel_id));
        assert!(!runtime.channels[&blocked_channel_id]
            .stream_publication_queue
            .as_ref()
            .unwrap()
            .has_pending());
        assert_eq!(runtime.channels[&blocked_channel_id].max_stream_id, Some(3));
        assert_eq!(runtime.channels[&healthy_channel_id].max_stream_id, Some(7));
    }

    #[test]
    fn server_control_deferred_barrier_remains_runnable_with_one_work_item() {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, _event_receiver, _event_observer) =
            test_server_event_channel();
        let limits = RuntimeLimits {
            max_work_per_call: 1,
            ..RuntimeLimits::default()
        };
        let mut runtime = ServerControlRuntime::with_limits(
            test_server_control_settings(),
            event_sender,
            command_receiver,
            limits,
        );

        runtime.on_conn_established(&mut pipe.server).unwrap();
        assert_eq!(runtime.pending_commands.len(), 1);
        assert!(runtime.pending_commands[0].deferred_barrier);
        assert!(runtime.has_pending_work());
        assert!(!runtime.channels[&[1, 2, 3, 4][..]].announce_sent);

        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.pending_commands.is_empty());
        assert!(runtime.channels[&[1, 2, 3, 4][..]].announce_sent);

        pipe.advance().unwrap();
        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Announce(_))
        ));
        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Key(_))
        ));
    }

    #[test]
    fn server_control_retries_integrity_without_loss_or_duplication() {
        let (mut runtime, _command_sender, _command_observer, _events, mut pipe) =
            test_manual_control_runtime_with_small_core_queue();
        let announce = quiche::multicast::Frame::Announce(test_ipv4_announce());
        pipe.server.multicast_try_send(announce.clone()).unwrap();
        let integrity = test_stream_integrity(9, 0xdd);
        runtime.queue_integrity(integrity.clone()).unwrap();
        let integrity_observer = runtime.pending_integrities.observer();

        for _ in 0..16 {
            runtime.process_reads(&mut pipe.server).unwrap();
            runtime.process_writes(&mut pipe.server).unwrap();
            assert_eq!(integrity_observer.stats().retained_items, 1);
            assert_eq!(pipe.server.multicast_send_queue_len(), 1);
        }

        pipe.advance().unwrap();
        runtime.process_reads(&mut pipe.server).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.pending_integrities.is_empty());
        assert_eq!(integrity_observer.stats().retained_items, 0);

        pipe.advance().unwrap();
        assert_eq!(pipe.client.multicast_recv(), Ok(announce));
        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Integrity(integrity))
        );
        assert_eq!(pipe.client.multicast_recv(), Err(quiche::Error::Done));
    }

    #[test]
    fn server_control_commits_leave_only_after_queue_admission() {
        let (mut runtime, _command_sender, command_observer, _events, mut pipe) =
            test_manual_control_runtime_with_small_core_queue();
        let channel_id = vec![1, 2, 3, 4];
        let announce = quiche::multicast::Frame::Announce(test_ipv4_announce());
        pipe.server.multicast_try_send(announce.clone()).unwrap();
        {
            let channel = runtime.channels.get_mut(&channel_id).unwrap();
            channel.join_sent = true;
            channel.last_client_state_sequence = 7;
        }

        runtime
            .leave_channel(&mut pipe.server, &channel_id, 11)
            .unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.channels[&channel_id].join_sent);
        assert!(runtime.channels[&channel_id].leave_pending);
        assert_eq!(runtime.pending_commands.len(), 1);
        assert_eq!(command_observer.stats().retained_items, 1);

        pipe.advance().unwrap();
        runtime.process_reads(&mut pipe.server).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(!runtime.channels[&channel_id].join_sent);
        assert!(!runtime.channels[&channel_id].leave_pending);
        assert!(runtime.pending_commands.is_empty());
        assert_eq!(command_observer.stats().retained_items, 0);

        pipe.advance().unwrap();
        assert_eq!(pipe.client.multicast_recv(), Ok(announce));
        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Leave(quiche::multicast::Leave {
                channel_id,
                mc_state_sequence: 7,
                after_packet_number: 11,
            }))
        );
    }

    #[test]
    fn server_control_commits_retire_only_after_queue_admission() {
        let (mut runtime, _command_sender, command_observer, _events, mut pipe) =
            test_manual_control_runtime_with_small_core_queue();
        let channel_id = vec![1, 2, 3, 4];
        let announce = quiche::multicast::Frame::Announce(test_ipv4_announce());
        pipe.server.multicast_try_send(announce.clone()).unwrap();
        let retire = quiche::multicast::Retire {
            channel_id: channel_id.clone(),
            after_packet_number: 0,
        };
        runtime
            .queue_command_back(ServerControlCommand::StreamPublisherRetire {
                frame: retire.clone(),
            })
            .unwrap();
        runtime
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .retirement_pending = true;

        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(!runtime.channels[&channel_id].retired);
        assert!(runtime.channels[&channel_id].retirement_pending);
        assert_eq!(runtime.pending_commands.len(), 1);
        assert_eq!(command_observer.stats().retained_items, 1);

        pipe.advance().unwrap();
        runtime.process_reads(&mut pipe.server).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.channels[&channel_id].retired);
        assert!(!runtime.channels[&channel_id].retirement_pending);
        assert!(runtime.pending_commands.is_empty());
        assert_eq!(command_observer.stats().retained_items, 0);

        pipe.advance().unwrap();
        assert_eq!(pipe.client.multicast_recv(), Ok(announce));
        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Retire(retire))
        );
    }

    #[test]
    fn server_control_teardown_releases_blocked_secret_command() {
        let (mut runtime, command_sender, command_observer, _events, mut pipe) =
            test_manual_control_runtime_with_small_core_queue();
        pipe.server
            .multicast_try_send(quiche::multicast::Frame::Announce(
                test_ipv4_announce(),
            ))
            .unwrap();
        let mut key = test_key(&[1, 2, 3, 4]);
        key.key_sequence = 2;
        command_sender
            .try_send(ServerControlCommand::SendKey {
                frame: key,
                cached: None,
            })
            .unwrap();

        runtime.process_writes(&mut pipe.server).unwrap();
        assert_eq!(runtime.pending_commands.len(), 1);
        assert_eq!(command_observer.stats().retained_items, 1);

        runtime.clear();
        assert!(runtime.pending_commands.is_empty());
        assert!(runtime.channels.is_empty());
        assert_eq!(command_observer.stats().retained_items, 0);
    }

    #[test]
    fn server_control_announce_waits_for_allowed_address_family() {
        let mut settings = test_settings();
        settings.transport_params.limits.ipv4_channels_allowed = false;
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, _event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::new(
            test_server_control_settings(),
            event_sender,
            command_receiver,
        );
        runtime.on_conn_established(&mut pipe.server).unwrap();

        assert_eq!(pipe.server.multicast_send_queue_len(), 0);
        assert!(!runtime.channels[&[1, 2, 3, 4][..]].announce_sent);

        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(test_limits()),
        );
        deliver_server_flight(&mut pipe);

        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Announce(_))
        ));
        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Key(_))
        ));
        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Join(_))
        ));
    }

    #[test]
    fn server_control_reduced_limits_leave_joined_channel() {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, _event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::new(
            test_server_control_settings(),
            event_sender,
            command_receiver,
        );
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(test_limits()),
        );
        deliver_server_flight(&mut pipe);
        while pipe.client.multicast_recv().is_ok() {}

        let mut reduced = test_limits();
        reduced.sequence = 2;
        reduced.max_joined_count = 0;
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(reduced),
        );
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);

        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Leave(quiche::multicast::Leave {
                channel_id,
                ..
            })) if channel_id == vec![1, 2, 3, 4]
        ));
        assert!(!runtime.channels[&[1, 2, 3, 4][..]].join_sent);
        assert_eq!(
            pipe.server.multicast_probe_status(&[1, 2, 3, 4]),
            Some(quiche::multicast::ProbeStatus::Left)
        );
    }

    #[test]
    fn server_control_limit_retirement_drains_stream_barriers_first() {
        let settings = test_settings();
        let mut pipe = test_stream_pipe(&settings);
        let channel_id = vec![5, 6, 7, 8];
        let mut second_config = test_stream_control_config();
        second_config.announce.channel_id = channel_id.clone();
        second_config.key.channel_id = channel_id.clone();
        let server_settings = ServerControlSettings {
            mode: ServerControlMode::Automatic,
            channels: vec![test_stream_control_config(), second_config.clone()],
            stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
        };
        let (command_sender, command_receiver, command_observer) =
            test_server_control_command_channel();
        let (event_sender, event_receiver, event_observer) =
            test_server_event_channel();
        let controller = ServerControlController {
            command_sender,
            command_observer,
            pending_publication_observer: test_retained_queue_observer(),
            pending_integrity_observer: test_retained_queue_observer(),
            event_receiver: Some(event_receiver),
            event_observer,
        };
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );
        runtime.on_conn_established(&mut pipe.server).unwrap();

        let publisher = ServerStreamPublisher::new(second_config).unwrap();
        publisher.declare_stream(3).unwrap();
        let _attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(test_limits()),
        );
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);
        while pipe.client.multicast_recv().is_ok() {}
        send_webtransport_stream_prefix(&mut pipe, 3, 11);

        let first = publisher.prepare_stream(3, 10, false, b"a").unwrap();
        publisher.commit(first).unwrap();
        let second = publisher.prepare_stream(3, 11, true, b"b").unwrap();
        publisher.commit(second).unwrap();

        let mut reduced = test_limits();
        reduced.sequence = 2;
        reduced.limits.max_channel_ids = 1;
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(reduced),
        );
        if !runtime.channels[&channel_id].retired {
            assert!(runtime.channels[&channel_id].retirement_pending);
            runtime.process_writes(&mut pipe.server).unwrap();
        }
        assert!(runtime.channels[&channel_id].retired);
        deliver_server_flight(&mut pipe);

        let mut out = [0; 8];
        assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((2, true)));
        assert_eq!(&out[..2], b"ab");
        for packet_number_start in 0..=1 {
            assert!(matches!(
                pipe.client.multicast_recv(),
                Ok(quiche::multicast::Frame::Integrity(
                    quiche::multicast::Integrity {
                        channel_id: ref integrity_channel,
                        packet_number_start: actual,
                        packet_hash_count: Some(1),
                        ..
                    }
                )) if integrity_channel == &channel_id &&
                    actual == packet_number_start
            ));
        }
        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Retire(
                quiche::multicast::Retire {
                    channel_id,
                    after_packet_number: 1,
                }
            ))
        );
    }

    #[test]
    fn server_control_reduced_channel_id_limit_retires_excess_state() {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let mut second_announce = test_ipv4_announce();
        second_announce.channel_id = vec![5, 6, 7, 8];
        let server_settings = ServerControlSettings {
            mode: ServerControlMode::Automatic,
            channels: vec![
                test_stream_control_config(),
                ServerControlChannelConfig {
                    announce: second_announce,
                    key: test_key(&[5, 6, 7, 8]),
                },
            ],
            stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
        };
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, _event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(test_limits()),
        );
        deliver_server_flight(&mut pipe);
        while pipe.client.multicast_recv().is_ok() {}

        let mut reduced = test_limits();
        reduced.sequence = 2;
        reduced.limits.max_channel_ids = 1;
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(reduced),
        );
        runtime.process_writes(&mut pipe.server).unwrap();
        deliver_server_flight(&mut pipe);

        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Retire(
                quiche::multicast::Retire {
                    channel_id: vec![5, 6, 7, 8],
                    after_packet_number: 0,
                }
            ))
        );
        assert!(runtime.channels[&[5, 6, 7, 8][..]].retired);
        assert_eq!(
            pipe.server.multicast_probe_status(&[5, 6, 7, 8]),
            Some(quiche::multicast::ProbeStatus::Retired)
        );
    }

    #[test]
    fn runtime_sends_initial_limits() {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let (event_sender, _event_receiver, _event_observer) =
            test_client_event_channel();
        let mut runtime = ClientRuntime::with_backend(
            settings.clone(),
            event_sender,
            FakeJoinBackend::default(),
        );

        runtime.on_conn_established(&mut pipe.client).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        assert_eq!(
            pipe.server.multicast_recv(),
            Ok(quiche::multicast::Frame::Limits(
                quiche::multicast::Limits {
                    sequence: 1,
                    limits: settings.transport_params.limits,
                    max_joined_count: settings.max_joined_channels,
                }
            ))
        );
    }

    #[test]
    fn runtime_joins_ipv4_channel() {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let backend = FakeJoinBackend::default();
        let recorded = Arc::clone(&backend.joins);
        let (event_sender, mut event_receiver, _event_observer) =
            test_client_event_channel();
        let mut runtime =
            ClientRuntime::with_backend(settings, event_sender, backend);
        let announce = test_ipv4_announce();

        pipe.server
            .multicast_send(quiche::multicast::Frame::Announce(announce.clone()))
            .unwrap();
        pipe.server
            .multicast_send(quiche::multicast::Frame::Key(test_key(
                &announce.channel_id,
            )))
            .unwrap();
        pipe.server
            .multicast_send(quiche::multicast::Frame::Join(
                quiche::multicast::Join {
                    channel_id: announce.channel_id.clone(),
                    mc_limits_sequence: 0,
                    mc_state_sequence: 0,
                    mc_key_sequence: 1,
                },
            ))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        runtime.process_reads(&mut pipe.client).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        assert_eq!(
            pipe.server.multicast_recv(),
            Ok(quiche::multicast::Frame::State(quiche::multicast::State {
                channel_id: announce.channel_id.clone(),
                sequence: 1,
                state: quiche::multicast::ChannelState::Joined,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                reason_phrase: Vec::new(),
            }))
        );

        assert_eq!(recorded.lock().unwrap().as_slice(), &[JoinRequest {
            channel_id: announce.channel_id.clone(),
            source: Ipv4Addr::new(10, 0, 0, 1),
            group: Ipv4Addr::new(232, 1, 2, 3),
            udp_port: 4444,
            interface: None,
        }]);

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ClientEvent::Announce(frame)) if frame == announce
        ));
        assert_next_local_state(
            &mut event_receiver,
            quiche::multicast::ChannelState::Joined,
        );
    }

    #[test]
    fn runtime_delays_leave_until_authenticated_packet_threshold() {
        let (mut runtime, mut pipe, mut events, announce) =
            joined_client_runtime();
        let channel_id = announce.channel_id.clone();

        runtime
            .handle_leave(&mut pipe.client, quiche::multicast::Leave {
                channel_id: channel_id.clone(),
                mc_state_sequence: 0,
                after_packet_number: 10,
            })
            .unwrap();
        assert!(runtime.channels[&channel_id].receive_handle.is_some());
        assert_eq!(
            runtime.channels[&channel_id].pending_leave,
            Some(PendingLeave {
                state_sequence: 0,
                after_packet_number: 10,
            })
        );
        assert!(events.try_recv().is_err());

        runtime
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .largest_authenticated_packet_number = Some(9);
        runtime
            .settle_pending_transitions(&mut pipe.client, &channel_id)
            .unwrap();
        assert!(runtime.channels[&channel_id].receive_handle.is_some());
        assert!(events.try_recv().is_err());

        runtime
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .largest_authenticated_packet_number = Some(10);
        runtime
            .settle_pending_transitions(&mut pipe.client, &channel_id)
            .unwrap();
        assert!(runtime.channels[&channel_id].receive_handle.is_none());
        assert_eq!(runtime.channels[&channel_id].pending_leave, None);
        assert_next_local_state(
            &mut events,
            quiche::multicast::ChannelState::Left,
        );
    }

    #[test]
    fn runtime_leave_is_idempotent_and_newer_join_cancels_pending_leave() {
        let (mut runtime, mut pipe, mut events, announce) =
            joined_client_runtime();
        let channel_id = announce.channel_id.clone();

        for threshold in [10, 10, 12] {
            runtime
                .handle_leave(&mut pipe.client, quiche::multicast::Leave {
                    channel_id: channel_id.clone(),
                    mc_state_sequence: 0,
                    after_packet_number: threshold,
                })
                .unwrap();
        }
        assert_eq!(
            runtime.channels[&channel_id].pending_leave,
            Some(PendingLeave {
                state_sequence: 0,
                after_packet_number: 12,
            })
        );

        runtime
            .handle_join(&mut pipe.client, quiche::multicast::Join {
                channel_id: channel_id.clone(),
                mc_limits_sequence: 0,
                mc_state_sequence: 1,
                mc_key_sequence: 1,
            })
            .unwrap();
        assert_eq!(runtime.channels[&channel_id].pending_leave, None);

        runtime
            .handle_leave(&mut pipe.client, quiche::multicast::Leave {
                channel_id: channel_id.clone(),
                mc_state_sequence: 0,
                after_packet_number: 0,
            })
            .unwrap();
        assert!(runtime.channels[&channel_id].receive_handle.is_some());
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn runtime_pending_leave_is_bounded_and_cleared_on_decline_and_teardown() {
        let (mut runtime, mut pipe, mut events, announce) =
            joined_client_runtime();
        let channel_id = announce.channel_id.clone();

        runtime
            .handle_leave(&mut pipe.client, quiche::multicast::Leave {
                channel_id: channel_id.clone(),
                mc_state_sequence: 0,
                after_packet_number: u64::MAX,
            })
            .unwrap();
        assert!(runtime.channels[&channel_id].pending_leave.is_some());

        runtime
            .decline_join(
                &mut pipe.client,
                channel_id.clone(),
                b"test join failure".to_vec(),
            )
            .unwrap();
        assert_eq!(runtime.channels[&channel_id].pending_leave, None);
        assert!(runtime.channels[&channel_id].receive_handle.is_none());
        assert_next_local_state(
            &mut events,
            quiche::multicast::ChannelState::DeclinedJoin,
        );

        runtime.clear();
        assert!(runtime.channels.is_empty());
    }

    #[test]
    fn runtime_delays_retire_and_coalesces_thresholds_safely() {
        let (mut runtime, mut pipe, mut events, announce) =
            joined_client_runtime();
        let channel_id = announce.channel_id.clone();
        runtime
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .largest_authenticated_packet_number = Some(5);

        for threshold in [10, 10, 12] {
            runtime
                .handle_retire(&mut pipe.client, quiche::multicast::Retire {
                    channel_id: channel_id.clone(),
                    after_packet_number: threshold,
                })
                .unwrap();
        }
        assert_eq!(runtime.channels[&channel_id].pending_retire_after, Some(12));
        assert!(runtime.channels[&channel_id].receive_handle.is_some());
        assert!(events.try_recv().is_err());

        runtime
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .largest_authenticated_packet_number = Some(10);
        runtime
            .settle_pending_transitions(&mut pipe.client, &channel_id)
            .unwrap();
        assert!(!runtime.channels[&channel_id].retired);
        assert!(events.try_recv().is_err());

        runtime
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .largest_authenticated_packet_number = Some(12);
        runtime
            .settle_pending_transitions(&mut pipe.client, &channel_id)
            .unwrap();
        let channel = &runtime.channels[&channel_id];
        assert!(channel.retired);
        assert!(channel.receive_handle.is_none());
        assert!(channel.receive_state.is_none());
        assert!(channel.announce.is_none());
        assert!(channel.key.is_none());
        assert_next_local_state(
            &mut events,
            quiche::multicast::ChannelState::Retired,
        );

        runtime
            .handle_retire(&mut pipe.client, quiche::multicast::Retire {
                channel_id,
                after_packet_number: 0,
            })
            .unwrap();
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn runtime_retires_immediately_without_joined_data_or_after_leave() {
        let (mut runtime, mut pipe, mut events, announce) =
            joined_client_runtime();
        let channel_id = announce.channel_id.clone();

        runtime
            .handle_retire(&mut pipe.client, quiche::multicast::Retire {
                channel_id: channel_id.clone(),
                after_packet_number: 100,
            })
            .unwrap();
        assert!(runtime.channels[&channel_id].retired);
        assert_next_local_state(
            &mut events,
            quiche::multicast::ChannelState::Retired,
        );

        let (mut runtime, mut pipe, mut events, announce) =
            joined_client_runtime();
        let channel_id = announce.channel_id.clone();
        runtime
            .execute_leave(&mut pipe.client, channel_id.clone())
            .unwrap();
        assert_next_local_state(
            &mut events,
            quiche::multicast::ChannelState::Left,
        );
        runtime
            .handle_retire(&mut pipe.client, quiche::multicast::Retire {
                channel_id: channel_id.clone(),
                after_packet_number: 100,
            })
            .unwrap();
        assert!(runtime.channels[&channel_id].retired);
        assert_next_local_state(
            &mut events,
            quiche::multicast::ChannelState::Retired,
        );
    }

    #[test]
    fn runtime_conflicting_integrity_fails_only_the_multicast_channel() {
        let (mut runtime, mut pipe, mut events, announce) =
            joined_client_runtime();
        let channel_id = announce.channel_id.clone();
        let integrity = quiche::multicast::Integrity {
            channel_id: channel_id.clone(),
            packet_number_start: 0,
            packet_hash_count: Some(1),
            packet_hashes: vec![0xaa; 32],
        };

        runtime
            .handle_integrity(&mut pipe.client, integrity.clone())
            .unwrap();
        let mut conflicting = integrity;
        conflicting.packet_hashes[0] ^= 0xff;
        runtime
            .handle_integrity(&mut pipe.client, conflicting)
            .unwrap();
        for _ in 0..4 {
            if runtime.channels[&channel_id]
                .receive_state
                .as_ref()
                .is_some_and(|receiver| {
                    receiver.terminal_failure().is_some() ||
                        !receiver.has_pending_work()
                })
            {
                break;
            }
            runtime
                .process_one_receiver_maintenance(&mut pipe.client)
                .unwrap();
        }

        let channel = &runtime.channels[&channel_id];
        assert!(channel.receive_handle.is_none());
        assert!(channel.key.is_none());
        assert_eq!(
            channel.receive_state.as_ref().unwrap().terminal_failure(),
            Some(quiche::multicast::ChannelReceiveFailure::ConflictingIntegrity)
        );
        assert!(!pipe.client.is_closed());

        loop {
            match events.try_recv() {
                Ok(ClientEvent::LocalState(state)) => {
                    assert_eq!(
                        state.state,
                        quiche::multicast::ChannelState::Left
                    );
                    assert_eq!(state.reason_code, STATE_REASON_PROTOCOL_ERROR);
                    break;
                },

                Ok(ClientEvent::MetricsUpdated { .. }) => continue,

                other => panic!("expected failed-channel state, got {other:?}"),
            }
        }
    }

    #[test]
    fn runtime_receive_limit_failure_uses_limit_violated_reason() {
        let (mut runtime, mut pipe, mut events, announce) =
            joined_client_runtime();
        let channel_id = announce.channel_id.clone();
        let limits = quiche::multicast::ChannelReceiveLimits {
            max_pending_integrity_entries: 1,
            ..quiche::multicast::ChannelReceiveLimits::default()
        };
        runtime.channels.get_mut(&channel_id).unwrap().receive_state = Some(
            quiche::multicast::ChannelReceiveState::with_limits(announce, limits)
                .unwrap(),
        );

        runtime
            .handle_integrity(&mut pipe.client, quiche::multicast::Integrity {
                channel_id: channel_id.clone(),
                packet_number_start: 0,
                packet_hash_count: Some(2),
                packet_hashes: vec![0xaa; 64],
            })
            .unwrap();
        assert!(!pipe.client.is_closed());

        loop {
            match events.try_recv() {
                Ok(ClientEvent::LocalState(state)) => {
                    assert_eq!(
                        state.state,
                        quiche::multicast::ChannelState::Left
                    );
                    assert_eq!(state.reason_code, STATE_REASON_LIMIT_VIOLATED);
                    break;
                },

                Ok(ClientEvent::MetricsUpdated { .. }) => continue,

                other => panic!("expected failed-channel state, got {other:?}"),
            }
        }
    }

    #[test]
    fn runtime_declines_ipv6_channel_with_placeholder_event() {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let backend = FakeJoinBackend::default();
        let recorded = Arc::clone(&backend.joins);
        let (event_sender, mut event_receiver, _event_observer) =
            test_client_event_channel();
        let mut runtime =
            ClientRuntime::with_backend(settings, event_sender, backend);
        let announce = test_ipv6_announce();

        pipe.server
            .multicast_send(quiche::multicast::Frame::Announce(announce.clone()))
            .unwrap();
        pipe.server
            .multicast_send(quiche::multicast::Frame::Key(test_key(
                &announce.channel_id,
            )))
            .unwrap();
        pipe.server
            .multicast_send(quiche::multicast::Frame::Join(
                quiche::multicast::Join {
                    channel_id: announce.channel_id.clone(),
                    mc_limits_sequence: 0,
                    mc_state_sequence: 0,
                    mc_key_sequence: 1,
                },
            ))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        runtime.process_reads(&mut pipe.client).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        assert_eq!(
            pipe.server.multicast_recv(),
            Ok(quiche::multicast::Frame::State(quiche::multicast::State {
                channel_id: announce.channel_id.clone(),
                sequence: 1,
                state: quiche::multicast::ChannelState::DeclinedJoin,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: STATE_REASON_UNSPECIFIED_OTHER,
                reason_phrase: b"ipv6 multicast not yet supported".to_vec(),
            }))
        );

        assert!(recorded.lock().unwrap().is_empty());
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ClientEvent::UnsupportedIpv6Announce(frame)) if frame == announce
        ));
        assert_next_local_state(
            &mut event_receiver,
            quiche::multicast::ChannelState::DeclinedJoin,
        );
    }

    #[test]
    fn runtime_declines_join_for_missing_key_sequence() {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let backend = FakeJoinBackend::default();
        let recorded = Arc::clone(&backend.joins);
        let (event_sender, mut event_receiver, _event_observer) =
            test_client_event_channel();
        let mut runtime =
            ClientRuntime::with_backend(settings, event_sender, backend);
        let announce = test_ipv4_announce();

        pipe.server
            .multicast_send(quiche::multicast::Frame::Announce(announce.clone()))
            .unwrap();
        pipe.server
            .multicast_send(quiche::multicast::Frame::Key(test_key(
                &announce.channel_id,
            )))
            .unwrap();
        pipe.server
            .multicast_send(quiche::multicast::Frame::Join(
                quiche::multicast::Join {
                    channel_id: announce.channel_id.clone(),
                    mc_limits_sequence: 0,
                    mc_state_sequence: 0,
                    mc_key_sequence: 2,
                },
            ))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        runtime.process_reads(&mut pipe.client).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        assert_eq!(
            pipe.server.multicast_recv(),
            Ok(quiche::multicast::Frame::State(quiche::multicast::State {
                channel_id: announce.channel_id.clone(),
                sequence: 1,
                state: quiche::multicast::ChannelState::DeclinedJoin,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: STATE_REASON_UNSYNCHRONIZED_PROPERTIES,
                reason_phrase: b"unsynchronized multicast properties".to_vec(),
            }))
        );

        assert!(recorded.lock().unwrap().is_empty());
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ClientEvent::Announce(frame)) if frame == announce
        ));
        assert_next_local_state(
            &mut event_receiver,
            quiche::multicast::ChannelState::DeclinedJoin,
        );
    }

    #[test]
    fn server_runtime_announces_and_joins_after_limits() {
        let settings = test_settings();
        let server_settings = test_server_settings();
        let mut pipe = test_pipe(&settings);
        let backend = FakePublishBackend::default();
        let (_command_sender, command_receiver, _command_observer) =
            test_server_command_channel();
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerRuntime::with_backend(
            server_settings,
            event_sender,
            command_receiver,
            backend,
        );

        runtime.on_conn_established(&mut pipe.server).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        let announce = match pipe.client.multicast_recv() {
            Ok(quiche::multicast::Frame::Announce(frame)) => frame,
            other => panic!("expected announce, got {other:?}"),
        };
        let key = match pipe.client.multicast_recv() {
            Ok(quiche::multicast::Frame::Key(frame)) => frame,
            other => panic!("expected key, got {other:?}"),
        };

        assert_eq!(announce, test_ipv4_announce());
        assert_eq!(key, test_key(&announce.channel_id));

        pipe.client
            .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        runtime.process_reads(&mut pipe.server).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Join(quiche::multicast::Join {
                channel_id: announce.channel_id.clone(),
                mc_limits_sequence: 1,
                mc_state_sequence: 0,
                mc_key_sequence: 1,
            }))
        );
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientLimits(frame))
                if frame.sequence == 1 &&
                    frame.limits == test_transport_params().limits
        ));
    }

    #[test]
    fn server_control_runtime_announces_and_joins_after_limits() {
        let settings = test_settings();
        let server_settings = test_server_control_settings();
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );

        runtime.on_conn_established(&mut pipe.server).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        let announce = match pipe.client.multicast_recv() {
            Ok(quiche::multicast::Frame::Announce(frame)) => frame,
            other => panic!("expected announce, got {other:?}"),
        };
        let key = match pipe.client.multicast_recv() {
            Ok(quiche::multicast::Frame::Key(frame)) => frame,
            other => panic!("expected key, got {other:?}"),
        };

        assert_eq!(announce, test_ipv4_announce());
        assert_eq!(key, test_key(&announce.channel_id));

        pipe.client
            .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        runtime.process_reads(&mut pipe.server).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Join(quiche::multicast::Join {
                channel_id: announce.channel_id.clone(),
                mc_limits_sequence: 1,
                mc_state_sequence: 0,
                mc_key_sequence: 1,
            }))
        );
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientLimits(frame))
                if frame.sequence == 1 &&
                    frame.limits == test_transport_params().limits
        ));
    }

    #[test]
    fn server_control_runtime_installs_default_dgram_fallback_channel() {
        let settings = test_settings();
        let server_settings = test_server_control_settings();
        let channel_id = server_settings.channels[0].announce.channel_id.clone();
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, _event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );

        runtime.on_conn_established(&mut pipe.server).unwrap();

        assert_eq!(
            pipe.server.multicast_default_dgram_channel(),
            Some(channel_id.as_slice())
        );

        pipe.server.dgram_send(b"default-fallback").unwrap();
        assert_client_receives_dgram(&mut pipe, b"default-fallback");

        pipe.server
            .multicast_process_peer_ack(quiche::multicast::Ack {
                channel_id,
                largest_acknowledged: 1,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            })
            .unwrap();
        pipe.server.dgram_send(b"do-not-duplicate").unwrap();
        assert_eq!(pipe.server.dgram_send_queue_len(), 0);
    }

    #[test]
    fn server_control_runtime_ack_timeout_reenters_dgram_fallback() {
        let settings = test_settings();
        let mut server_settings = test_server_control_settings();
        server_settings.channels[0].announce.max_ack_delay_ms = 0;
        let channel_id = server_settings.channels[0].announce.channel_id.clone();
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );

        runtime.on_conn_established(&mut pipe.server).unwrap();

        pipe.client
            .multicast_send(quiche::multicast::Frame::Ack(
                quiche::multicast::Ack {
                    channel_id: channel_id.clone(),
                    largest_acknowledged: 1,
                    ack_delay: 0,
                    first_ack_range: 0,
                    ack_ranges: Vec::new(),
                    ecn_counts: None,
                },
            ))
            .unwrap();
        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
        runtime.process_reads(&mut pipe.server).unwrap();

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(frame)) if frame.channel_id == channel_id
        ));
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ProbeStatusChanged(quiche::multicast::ProbeEvent {
                channel_id: event_channel,
                status: quiche::multicast::ProbeStatus::Viable,
                ..
            })) if event_channel == channel_id
        ));

        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::Viable)
        );

        pipe.server.on_timeout();
        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::TimedOut)
        );
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ProbeStatusChanged(quiche::multicast::ProbeEvent {
                channel_id: event_channel,
                status: quiche::multicast::ProbeStatus::TimedOut,
                ..
            })) if event_channel == channel_id
        ));

        pipe.server.dgram_send(b"fallback-after-stall").unwrap();
        assert_client_receives_dgram(&mut pipe, b"fallback-after-stall");
    }

    #[test]
    fn server_control_runtime_join_without_first_ack_times_out() {
        let settings = test_settings();
        let mut server_settings = test_server_control_settings();
        server_settings.channels[0].announce.max_ack_delay_ms = 0;
        let channel_id = server_settings.channels[0].announce.channel_id.clone();
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );

        runtime.on_conn_established(&mut pipe.server).unwrap();
        pipe.client
            .multicast_send(quiche::multicast::Frame::State(
                quiche::multicast::State {
                    channel_id: channel_id.clone(),
                    sequence: 1,
                    state: quiche::multicast::ChannelState::Joined,
                    reason_scope: quiche::multicast::StateReasonScope::Transport,
                    reason_code:
                        quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                    reason_phrase: Vec::new(),
                },
            ))
            .unwrap();
        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
        runtime.process_reads(&mut pipe.server).unwrap();

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientState(frame)) if frame.channel_id == channel_id
        ));
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ProbeStatusChanged(quiche::multicast::ProbeEvent {
                channel_id: event_channel,
                status: quiche::multicast::ProbeStatus::Probing,
                ..
            })) if event_channel == channel_id
        ));
        pipe.server.on_timeout();
        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::TimedOut)
        );
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ProbeStatusChanged(quiche::multicast::ProbeEvent {
                channel_id: event_channel,
                status: quiche::multicast::ProbeStatus::TimedOut,
                ..
            })) if event_channel == channel_id
        ));
    }

    #[test]
    fn server_runtime_emits_client_ack() {
        let settings = test_settings();
        let server_settings = test_server_settings();
        let mut pipe = test_pipe(&settings);
        let backend = FakePublishBackend::default();
        let (_command_sender, command_receiver, _command_observer) =
            test_server_command_channel();
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerRuntime::with_backend(
            server_settings,
            event_sender,
            command_receiver,
            backend,
        );
        let ack = quiche::multicast::Ack {
            channel_id: vec![1, 2, 3, 4],
            largest_acknowledged: 7,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: vec![quiche::multicast::AckRange {
                gap: 1,
                ack_range_length: 1,
            }],
            ecn_counts: None,
        };

        runtime.on_conn_established(&mut pipe.server).unwrap();
        let mut out = [0; 256];
        let channel = runtime.channels.get_mut(&ack.channel_id).unwrap();

        for _ in 0..8 {
            channel
                .send_state
                .write_packet(&[quiche::multicast::ChannelFrame::Ping], &mut out)
                .unwrap();
        }

        pipe.client
            .multicast_send(quiche::multicast::Frame::Ack(ack.clone()))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        runtime.process_reads(&mut pipe.server).unwrap();

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(frame)) if frame == ack
        ));
        assert_eq!(
            pipe.server.multicast_probe_status(&[1, 2, 3, 4]),
            Some(quiche::multicast::ProbeStatus::Viable)
        );
        assert_eq!(
            pipe.server.multicast_probe_recv(),
            Ok(quiche::multicast::ProbeEvent {
                channel_id: vec![1, 2, 3, 4],
                status: quiche::multicast::ProbeStatus::Viable,
                reason_scope: None,
                reason_code: None,
                reason_phrase: Vec::new(),
            })
        );
        let metrics = runtime
            .channels
            .get([1, 2, 3, 4].as_slice())
            .unwrap()
            .send_state
            .metrics_snapshot();
        assert_eq!(metrics.ack_frames_processed, 1);
        assert_eq!(metrics.ack_blocks_processed, 2);
        assert_eq!(metrics.acked_packets_reported, 3);
        assert_eq!(metrics.ack_errors, 0);
        assert_eq!(metrics.largest_acknowledged, Some(7));
    }

    #[test]
    fn server_runtime_processes_unique_acks_and_deduplicates_notifications() {
        let settings = test_settings();
        let server_settings = test_server_settings();
        let mut pipe = test_pipe(&settings);
        let backend = FakePublishBackend::default();
        let (_command_sender, command_receiver, _command_observer) =
            test_server_command_channel();
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerRuntime::with_backend(
            server_settings,
            event_sender,
            command_receiver,
            backend,
        );
        let ack = |largest_acknowledged| quiche::multicast::Ack {
            channel_id: vec![1, 2, 3, 4],
            largest_acknowledged,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };

        runtime.on_conn_established(&mut pipe.server).unwrap();
        let mut out = [0; 256];
        let channel = runtime.channels.get_mut(&[1, 2, 3, 4][..]).unwrap();
        for _ in 0..8 {
            channel
                .send_state
                .write_packet(&[quiche::multicast::ChannelFrame::Ping], &mut out)
                .unwrap();
        }

        for frame in [ack(5), ack(5), ack(7)] {
            pipe.client
                .multicast_send(quiche::multicast::Frame::Ack(frame))
                .unwrap();
        }
        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
        runtime.process_reads(&mut pipe.server).unwrap();

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(frame))
                if frame.largest_acknowledged == 5
        ));
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(frame))
                if frame.largest_acknowledged == 7
        ));
        assert!(event_receiver.try_recv().is_err());

        pipe.client
            .multicast_send(quiche::multicast::Frame::Ack(ack(7)))
            .unwrap();
        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
        runtime.process_reads(&mut pipe.server).unwrap();
        assert!(event_receiver.try_recv().is_err());

        let metrics = runtime
            .channels
            .get([1, 2, 3, 4].as_slice())
            .unwrap()
            .send_state
            .metrics_snapshot();
        // The reliable core handoff safely coalesces the exact duplicate ACK
        // before the runtime sees it. Distinct range updates are retained.
        assert_eq!(metrics.ack_frames_processed, 3);
        assert_eq!(metrics.largest_acknowledged, Some(7));
    }

    #[test]
    fn server_event_coalescer_preserves_same_largest_ack_with_new_ranges() {
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut coalescer = ServerEventCoalescer::default();
        let first = quiche::multicast::Ack {
            channel_id: vec![1, 2, 3, 4],
            largest_acknowledged: 7,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };
        let mut fills_lower_range = first.clone();
        fills_lower_range
            .ack_ranges
            .push(quiche::multicast::AckRange {
                gap: 1,
                ack_range_length: 0,
            });

        coalescer.queue_client_ack(&event_sender, first.clone());
        coalescer.queue_client_ack(&event_sender, fills_lower_range.clone());
        coalescer
            .flush_client_acks(&event_sender, usize::MAX)
            .unwrap();

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(received)) if received == first
        ));
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(received))
                if received == fills_lower_range
        ));
        assert!(event_receiver.try_recv().is_err());
    }

    #[test]
    fn server_event_coalescer_resets_ack_and_probe_history_per_generation() {
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut coalescer = ServerEventCoalescer::default();
        let ack = quiche::multicast::Ack {
            channel_id: vec![1, 2, 3, 4],
            largest_acknowledged: 7,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };
        let probe = quiche::multicast::ProbeEvent {
            channel_id: ack.channel_id.clone(),
            status: quiche::multicast::ProbeStatus::Probing,
            reason_scope: None,
            reason_code: None,
            reason_phrase: Vec::new(),
        };

        coalescer.queue_client_ack(&event_sender, ack.clone());
        coalescer
            .flush_client_acks(&event_sender, usize::MAX)
            .unwrap();
        coalescer
            .forward_probe_event(&event_sender, probe.clone())
            .unwrap();
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(received)) if received == ack
        ));
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ProbeStatusChanged(received)) if received == probe
        ));

        coalescer.queue_client_ack(&event_sender, ack.clone());
        coalescer
            .forward_probe_event(&event_sender, probe.clone())
            .unwrap();
        assert!(event_receiver.try_recv().is_err());

        coalescer.reset_channel(&ack.channel_id);
        coalescer.queue_client_ack(&event_sender, ack.clone());
        coalescer
            .flush_client_acks(&event_sender, usize::MAX)
            .unwrap();
        coalescer
            .forward_probe_event(&event_sender, probe.clone())
            .unwrap();
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(received)) if received == ack
        ));
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ProbeStatusChanged(received)) if received == probe
        ));
    }

    #[test]
    fn server_event_coalescer_suppresses_identical_probe_events() {
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut coalescer = ServerEventCoalescer::default();
        let event = quiche::multicast::ProbeEvent {
            channel_id: vec![1, 2, 3, 4],
            status: quiche::multicast::ProbeStatus::Probing,
            reason_scope: Some(quiche::multicast::StateReasonScope::Transport),
            reason_code: Some(
                quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            ),
            reason_phrase: Vec::new(),
        };

        coalescer
            .forward_probe_event(&event_sender, event.clone())
            .unwrap();
        coalescer
            .forward_probe_event(&event_sender, event.clone())
            .unwrap();

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ProbeStatusChanged(received)) if received == event
        ));
        assert!(event_receiver.try_recv().is_err());

        let mut changed = event;
        changed.reason_phrase = b"path changed".to_vec();
        coalescer
            .forward_probe_event(&event_sender, changed.clone())
            .unwrap();
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ProbeStatusChanged(received))
                if received == changed
        ));
    }

    #[test]
    fn server_runtime_does_not_probe_unknown_ack() {
        let settings = test_settings();
        let server_settings = test_server_settings();
        let mut pipe = test_pipe(&settings);
        let backend = FakePublishBackend::default();
        let (_command_sender, command_receiver, _command_observer) =
            test_server_command_channel();
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerRuntime::with_backend(
            server_settings,
            event_sender,
            command_receiver,
            backend,
        );
        let ack = quiche::multicast::Ack {
            channel_id: vec![9, 9, 9, 9],
            largest_acknowledged: 3,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };

        runtime.on_conn_established(&mut pipe.server).unwrap();

        pipe.client
            .multicast_send(quiche::multicast::Frame::Ack(ack.clone()))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        runtime.process_reads(&mut pipe.server).unwrap();

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(frame)) if frame == ack
        ));
        assert_eq!(pipe.server.multicast_probe_status(&ack.channel_id), None);
        assert_eq!(pipe.server.multicast_probe_recv(), Err(quiche::Error::Done));
    }

    #[test]
    fn server_control_runtime_relays_external_integrity() {
        let settings = test_settings();
        let server_settings = test_server_control_settings();
        let mut pipe = test_pipe(&settings);
        let (command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, _event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );
        let integrity = quiche::multicast::Integrity {
            channel_id: vec![1, 2, 3, 4],
            packet_number_start: 11,
            packet_hash_count: Some(1),
            packet_hashes: vec![0xaa; 32],
        };

        runtime.on_conn_established(&mut pipe.server).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        let _ = pipe.client.multicast_recv().unwrap();
        let _ = pipe.client.multicast_recv().unwrap();

        command_sender
            .try_send(ServerControlCommand::RelayIntegrity {
                frame: integrity.clone(),
            })
            .unwrap();

        runtime.process_writes(&mut pipe.server).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Integrity(integrity))
        );
    }

    #[test]
    fn server_control_runtime_upserts_channel_after_limits() {
        let settings = test_settings();
        let server_settings = ServerControlSettings {
            mode: ServerControlMode::Automatic,
            channels: Vec::new(),
            stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
        };
        let mut pipe = test_pipe(&settings);
        let (command_sender, command_receiver, command_observer) =
            test_server_control_command_channel();
        let (event_sender, mut event_receiver, event_observer) =
            test_server_event_channel();
        let mut controller = ServerControlController {
            command_sender,
            command_observer,
            pending_publication_observer: test_retained_queue_observer(),
            pending_integrity_observer: test_retained_queue_observer(),
            event_receiver: None,
            event_observer,
        };
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );
        let config = ServerControlChannelConfig {
            announce: test_ipv4_announce(),
            key: test_key(&[1, 2, 3, 4]),
        };

        runtime.on_conn_established(&mut pipe.server).unwrap();

        pipe.client
            .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        runtime.process_reads(&mut pipe.server).unwrap();
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientLimits(frame))
                if frame.sequence == 1 &&
                    frame.limits == test_transport_params().limits
        ));

        controller.upsert_channel(config).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        assert_eq!(
            pipe.server.multicast_default_dgram_channel(),
            Some(&[1, 2, 3, 4][..])
        );

        pipe.server.dgram_send(b"upsert-fallback").unwrap();
        assert_client_receives_dgram(&mut pipe, b"upsert-fallback");

        let announce = match pipe.client.multicast_recv() {
            Ok(quiche::multicast::Frame::Announce(frame)) => frame,
            other => panic!("expected announce, got {other:?}"),
        };
        let key = match pipe.client.multicast_recv() {
            Ok(quiche::multicast::Frame::Key(frame)) => frame,
            other => panic!("expected key, got {other:?}"),
        };
        let join = match pipe.client.multicast_recv() {
            Ok(quiche::multicast::Frame::Join(frame)) => frame,
            other => panic!("expected join, got {other:?}"),
        };

        assert_eq!(announce, test_ipv4_announce());
        assert_eq!(key, test_key(&[1, 2, 3, 4]));
        assert_eq!(join, quiche::multicast::Join {
            channel_id: vec![1, 2, 3, 4],
            mc_limits_sequence: 1,
            mc_state_sequence: 0,
            mc_key_sequence: 1,
        });

        let _ = controller.take_event_receiver();
    }

    #[test]
    fn server_control_runtime_manual_mode_allows_explicit_sequencing() {
        let settings = test_settings();
        let server_settings = ServerControlSettings {
            mode: ServerControlMode::Manual,
            channels: Vec::new(),
            stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
        };
        let mut pipe = test_pipe(&settings);
        let (command_sender, command_receiver, command_observer) =
            test_server_control_command_channel();
        let (event_sender, mut event_receiver, event_observer) =
            test_server_event_channel();
        let controller = ServerControlController {
            command_sender,
            command_observer,
            pending_publication_observer: test_retained_queue_observer(),
            pending_integrity_observer: test_retained_queue_observer(),
            event_receiver: None,
            event_observer,
        };
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );
        let announce = test_ipv4_announce();
        let key = test_key(&announce.channel_id);
        let join = quiche::multicast::Join {
            channel_id: announce.channel_id.clone(),
            mc_limits_sequence: 1,
            mc_state_sequence: 0,
            mc_key_sequence: key.key_sequence,
        };

        runtime.on_conn_established(&mut pipe.server).unwrap();
        if let Ok(flight) = quiche::test_utils::emit_flight(&mut pipe.server) {
            quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();
        }
        assert_eq!(pipe.client.multicast_recv(), Err(quiche::Error::Done));

        pipe.client
            .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        runtime.process_reads(&mut pipe.server).unwrap();
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientLimits(frame))
                if frame.sequence == 1 &&
                    frame.limits == test_transport_params().limits
        ));
        if let Ok(flight) = quiche::test_utils::emit_flight(&mut pipe.server) {
            quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();
        }
        assert_eq!(pipe.client.multicast_recv(), Err(quiche::Error::Done));

        controller.send_announce(announce.clone()).unwrap();
        controller.send_key(key.clone()).unwrap();
        controller.send_join(join.clone()).unwrap();

        runtime.process_writes(&mut pipe.server).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Announce(announce))
        );
        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Key(key))
        );
        assert_eq!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Join(join))
        );
    }

    #[test]
    fn server_control_runtime_emits_client_state_and_ack() {
        let settings = test_settings();
        let server_settings = test_server_control_settings();
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );
        let state = quiche::multicast::State {
            channel_id: vec![1, 2, 3, 4],
            sequence: 1,
            state: quiche::multicast::ChannelState::Joined,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: Vec::new(),
        };
        let ack = quiche::multicast::Ack {
            channel_id: vec![1, 2, 3, 4],
            largest_acknowledged: 3,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };

        runtime.on_conn_established(&mut pipe.server).unwrap();

        pipe.client
            .multicast_send(quiche::multicast::Frame::State(state.clone()))
            .unwrap();
        pipe.client
            .multicast_send(quiche::multicast::Frame::Ack(ack.clone()))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        runtime.process_reads(&mut pipe.server).unwrap();

        let mut saw_state = false;
        let mut saw_ack = false;
        for _ in 0..8 {
            match event_receiver.try_recv() {
                Ok(ServerEvent::ClientState(frame)) if frame == state => {
                    assert!(!saw_ack);
                    saw_state = true;
                },

                Ok(ServerEvent::ClientAck(frame)) if frame == ack => {
                    assert!(saw_state);
                    saw_ack = true;
                },

                Ok(ServerEvent::ProbeStatusChanged(..)) => (),
                Ok(other) => panic!("unexpected server event: {other:?}"),
                Err(_) => break,
            }
        }
        assert!(saw_state);
        assert!(saw_ack);
        assert_eq!(
            pipe.server.multicast_probe_status(&[1, 2, 3, 4]),
            Some(quiche::multicast::ProbeStatus::Viable)
        );
    }

    #[test]
    fn server_control_runtime_does_not_probe_unknown_ack() {
        let settings = test_settings();
        let server_settings = ServerControlSettings {
            mode: ServerControlMode::Manual,
            channels: Vec::new(),
            stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
        };
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver, _command_observer) =
            test_server_control_command_channel();
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerControlRuntime::new(
            server_settings,
            event_sender,
            command_receiver,
        );
        let ack = quiche::multicast::Ack {
            channel_id: vec![9, 9, 9, 9],
            largest_acknowledged: 3,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };

        runtime.on_conn_established(&mut pipe.server).unwrap();

        pipe.client
            .multicast_send(quiche::multicast::Frame::Ack(ack.clone()))
            .unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        runtime.process_reads(&mut pipe.server).unwrap();

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(frame)) if frame == ack
        ));
        assert_eq!(pipe.server.multicast_probe_status(&ack.channel_id), None);
        assert_eq!(pipe.server.multicast_probe_recv(), Err(quiche::Error::Done));
    }

    #[test]
    fn server_runtime_publishes_encoded_channel_packet() {
        let settings = test_settings();
        let server_settings = test_server_settings();
        let channel_id = server_settings.channels[0].channel_id.clone();
        let mut pipe = test_pipe(&settings);
        let backend = FakePublishBackend::default();
        let published = Arc::clone(&backend.sent);
        let (command_sender, command_receiver, _command_observer) =
            test_server_command_channel();
        let (event_sender, mut event_receiver, _event_observer) =
            test_server_event_channel();
        let mut runtime = ServerRuntime::with_backend(
            server_settings,
            event_sender,
            command_receiver,
            backend,
        );

        runtime.on_conn_established(&mut pipe.server).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        let announce = match pipe.client.multicast_recv() {
            Ok(quiche::multicast::Frame::Announce(frame)) => frame,
            other => panic!("expected announce, got {other:?}"),
        };
        let key = match pipe.client.multicast_recv() {
            Ok(quiche::multicast::Frame::Key(frame)) => frame,
            other => panic!("expected key, got {other:?}"),
        };

        command_sender
            .try_send(ServerCommand::Send {
                channel_id: channel_id.clone(),
                frames: vec![quiche::multicast::ChannelFrame::Datagram {
                    data: b"hello multicast".to_vec(),
                }],
            })
            .unwrap();

        runtime.process_writes(&mut pipe.server).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

        let integrity = match pipe.client.multicast_recv() {
            Ok(quiche::multicast::Frame::Integrity(frame)) => frame,
            other => panic!("expected integrity, got {other:?}"),
        };
        let packet = published.lock().unwrap()[0].clone();
        let mut receiver =
            quiche::multicast::ChannelReceiveState::new(announce).unwrap();

        receiver.insert_key(key).unwrap();
        assert!(receiver.insert_integrity(integrity).unwrap().is_empty());

        let events = receiver.recv(&packet.payload, ()).unwrap();

        assert!(matches!(
            &events[0],
            quiche::multicast::ChannelReceiveEvent::Packet {
                packet,
                metadata: (),
            } if packet.channel_id == channel_id &&
                packet.frames == vec![quiche::multicast::ChannelFrame::Datagram {
                    data: b"hello multicast".to_vec(),
                }]
        ));
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::Published {
                channel_id: published_channel,
                packet_number: 0,
                report,
            }) if published_channel == channel_id &&
                report.bytes_sent == packet.payload.len()
        ));
    }

    #[test]
    fn channel_ack_state_encodes_non_contiguous_ranges() {
        let mut ack_state = quiche::multicast::AckTracker::default();

        for packet_number in [0, 2, 3, 6] {
            ack_state.record_packet(packet_number);
        }

        let ack = ack_state.pending_ack(&[1, 2, 3, 4]).unwrap();

        assert_eq!(ack.channel_id, vec![1, 2, 3, 4]);
        assert_eq!(ack.largest_acknowledged, 6);
        assert_eq!(ack.ack_delay, 0);
        assert_eq!(ack.first_ack_range, 0);
        assert_eq!(ack.ack_ranges, vec![
            quiche::multicast::AckRange {
                gap: 1,
                ack_range_length: 1,
            },
            quiche::multicast::AckRange {
                gap: 0,
                ack_range_length: 0,
            },
        ]);
        assert_eq!(ack.ecn_counts, None);

        ack_state.mark_sent();
        assert_eq!(ack_state.pending_ack(&[1, 2, 3, 4]), None);
    }

    #[test]
    fn runtime_flushes_pending_mc_ack() {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let backend = FakeJoinBackend::default();
        let (event_sender, _event_receiver, _event_observer) =
            test_client_event_channel();
        let mut runtime =
            ClientRuntime::with_backend(settings, event_sender, backend);
        let announce = test_ipv4_announce();

        runtime
            .channels
            .entry(announce.channel_id.clone())
            .or_default()
            .ack_state
            .record_packet(7);
        assert!(runtime.flush_one_pending_ack(&mut pipe.client).unwrap());

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        assert_eq!(
            pipe.server.multicast_recv(),
            Ok(quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: announce.channel_id.clone(),
                largest_acknowledged: 7,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }))
        );
    }
}
