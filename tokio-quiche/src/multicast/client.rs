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

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::future::pending;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::time::Duration;

use mcrx_core::Context as MulticastContext;
use mcrx_core::PacketWithMetadata;
use mcrx_core::SubscriptionConfig;
use mcrx_core::SubscriptionMetricsSnapshot;
use mcrx_core::TokioReceiveError;
use mcrx_core::TokioSubscription;
use tokio::select;
use tokio::time::sleep_until;
use tokio::time::Instant;
use tokio_util::task::AbortOnDropHandle;

use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

use super::bounded_queue::bounded_channel;
use super::bounded_queue::BoundedReceiver;
use super::bounded_queue::BoundedSender;
use super::bounded_queue::QueueSendError;
use super::bounded_queue::Queued;
use super::bounded_queue::RetainedDeque;
use super::bounded_queue::RetainedQueueObserver;
use super::bounded_queue::RetainedSize;
use super::event_stream::client_event_channel;
use super::event_stream::ClientEventStream;
use super::event_stream::EventQueueLimits;
use super::event_stream::EventQueueObserver;
use super::event_stream::EventQueueStats;
use super::event_stream::ManagedEventSender;
use super::runtime::fair_ready_channel_ids;
use super::runtime::run_callback_work;
use super::runtime::validate_client_settings;
use super::runtime::STATE_REASON_LIMIT_VIOLATED;
use super::runtime::STATE_REASON_PROTOCOL_ERROR;
use super::runtime::STATE_REASON_UNSPECIFIED_OTHER;
use super::runtime::STATE_REASON_UNSYNCHRONIZED_PROPERTIES;
use super::ClientRuntimeQueueStats;
use super::ClientSettings;
use super::RuntimeLimits;
use super::RuntimeLimitsError;

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
    pub(super) event_receiver: Option<ClientEventStream>,
    pub(super) event_observer: EventQueueObserver<ClientEvent>,
    pub(super) ingress_observer: RetainedQueueObserver,
    pub(super) control_observer: RetainedQueueObserver,
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

pub(super) enum ClientControlFrame {
    Limits {
        frame: quiche::multicast::Limits,
        commit: Option<quiche::multicast::Limits>,
    },
    State {
        frame: quiche::multicast::State,
        commit: Option<quiche::multicast::State>,
    },
}

pub(super) struct PendingClientControl {
    pub(super) frame: ClientControlFrame,
    pub(super) blocked_since: Option<Instant>,
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

pub(super) struct ClientRuntime<B: JoinBackend> {
    pub(super) settings: ClientSettings,
    pub(super) limits: RuntimeLimits,
    pub(super) event_sender: ManagedEventSender<ClientEvent>,
    // Subscription tasks run outside the QUIC driver's immediate poll point,
    // so they hand off validated socket ingress through this channel. The
    // queue is drained on each driver tick and bounded in practice by the
    // number and lifetime of joined channels.
    pub(super) ingress_sender: BoundedSender<IngressEvent>,
    pub(super) ingress_receiver: BoundedReceiver<IngressEvent>,
    pub(super) ingress_observer: RetainedQueueObserver,
    pub(super) pending_ingress: VecDeque<Queued<IngressEvent>>,
    pub(super) pending_control: RetainedDeque<PendingClientControl>,
    pub(super) control_retry_deadline: Option<Instant>,
    pub(super) control_read_pending: bool,
    pub(super) channels: BTreeMap<Vec<u8>, Channel<B::Handle>>,
    pub(super) receiver_maintenance_cursor: Option<Vec<u8>>,
    pub(super) ack_flush_cursor: Option<Vec<u8>>,
    pub(super) read_work_cursor: usize,
    pub(super) write_work_cursor: usize,
    pub(super) next_limits_sequence: u64,
    pub(super) reserved_limits_sequence: u64,
    pub(super) reserved_state_sequences: BTreeMap<Vec<u8>, u64>,
    pub(super) backend: B,
    #[cfg(test)]
    pub(super) callback_read_work_last_call: usize,
    #[cfg(test)]
    pub(super) callback_write_work_last_call: usize,
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
    pub(super) fn with_backend(
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

    pub(super) fn with_backend_and_limits(
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

    pub(super) fn emit_event(&self, event: ClientEvent) -> QuicResult<()> {
        self.event_sender.try_send(event)?;
        Ok(())
    }

    pub(super) fn clear(&mut self) {
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

    pub(super) fn has_pending_work(&self) -> bool {
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

    pub(super) async fn wait_for_ingress_or_key_expiry(
        &mut self,
    ) -> QuicResult<()> {
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

    pub(super) async fn queue_ingress_event(
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

    pub(super) fn on_conn_established(
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

    pub(super) fn process_reads(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
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

    pub(super) fn process_writes(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
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

    pub(super) fn process_one_control_frame(
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

    pub(super) fn process_one_receiver_maintenance(
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

    pub(super) fn transfer_one_ingress(&mut self) -> bool {
        let Ok(event) = self.ingress_receiver.try_recv() else {
            return false;
        };
        self.pending_ingress.push_back(event);
        true
    }

    pub(super) fn process_one_ingress(
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

    pub(super) fn handle_ingress_packet(
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

    pub(super) fn handle_channel_receive_event(
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

    pub(super) fn resolve_receive_result(
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

    pub(super) fn fail_receive_channel(
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

    pub(super) fn handle_channel_packet(
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

    pub(super) fn handle_frame(
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

    pub(super) fn admit_peer_channel_id(
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

    pub(super) fn handle_announce(
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

    pub(super) fn handle_key(
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

    pub(super) fn handle_integrity(
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

    pub(super) fn handle_join(
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

    pub(super) fn handle_leave(
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

    pub(super) fn handle_retire(
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

    pub(super) fn execute_leave(
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

    pub(super) fn execute_retire(
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

    pub(super) fn settle_pending_transitions(
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

    pub(super) fn send_limits(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
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

    pub(super) fn send_state(
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

    pub(super) fn flush_one_pending_control(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.flush_pending_control_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    pub(super) fn flush_pending_control_with_limit(
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

    pub(super) fn queue_client_control(
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

    pub(super) fn retry_client_control(
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

    pub(super) fn decline_join(
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

    pub(super) fn decline_join_with_reason(
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

    pub(super) fn joined_channel_count(&self) -> u64 {
        self.channels
            .values()
            .filter(|channel| channel.receive_handle.is_some())
            .count() as u64
    }

    pub(super) fn joined_rate_kibps(&self) -> u64 {
        self.channels
            .values()
            .filter(|channel| channel.receive_handle.is_some())
            .filter_map(|channel| channel.announce.as_ref())
            .fold(0_u64, |total, announce| {
                total.saturating_add(announce.max_rate_kibps)
            })
    }

    pub(super) fn join_channel(
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

    pub(super) fn channel_socket_config(
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

    pub(super) fn peer_supports_multicast(
        &self, qconn: &QuicheConnection,
    ) -> bool {
        qconn
            .peer_transport_params()
            .map(|params| params.multicast_server_support)
            .unwrap_or(false)
    }

    pub(super) fn flush_one_pending_ack(
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

    pub(super) fn emit_channel_metrics(
        &self, channel_id: &[u8],
    ) -> QuicResult<()> {
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

    pub(super) fn ensure_channel_decoder(channel: &mut Channel<B::Handle>) {
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

pub(super) struct Channel<H> {
    pub(super) announce: Option<quiche::multicast::Announce>,
    pub(super) key: Option<quiche::multicast::Key>,
    pub(super) decoder_error: Option<Vec<u8>>,
    pub(super) last_subscription_metrics: Option<SubscriptionMetricsSnapshot>,
    pub(super) receive_state:
        Option<quiche::multicast::ChannelReceiveState<PacketWithMetadata>>,
    pub(super) ack_state: quiche::multicast::AckTracker,
    pub(super) next_state_sequence: u64,
    pub(super) highest_server_state_sequence: Option<u64>,
    pub(super) largest_authenticated_packet_number: Option<u64>,
    pub(super) pending_leave: Option<PendingLeave>,
    pub(super) pending_retire_after: Option<u64>,
    pub(super) retired: bool,
    pub(super) receive_handle: Option<H>,
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
pub(super) struct PendingLeave {
    pub(super) state_sequence: u64,
    pub(super) after_packet_number: u64,
}

#[derive(Debug)]
pub(super) enum ChannelSocketConfig {
    Ipv4 {
        source: Ipv4Addr,
        group: Ipv4Addr,
        udp_port: u16,
        interface: Option<Ipv4Addr>,
    },

    Ipv6Placeholder,
}

#[derive(Debug)]
pub(super) struct JoinError {
    pub(super) reason_phrase: Vec<u8>,
}

#[derive(Debug)]
pub(super) enum IngressEvent {
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

pub(super) trait JoinBackend {
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
