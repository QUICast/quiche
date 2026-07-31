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
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::future::pending;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::select;
use tokio::time::sleep_until;
use tokio::time::Instant;

use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

use super::bounded_queue::bounded_channel;
use super::bounded_queue::retained_queue_budget;
use super::bounded_queue::BoundedReceiver;
use super::bounded_queue::BoundedSender;
use super::bounded_queue::QueueSendError;
use super::bounded_queue::Queued;
use super::bounded_queue::RetainedQueueBudget;
use super::bounded_queue::RetainedQueueLimits;
use super::bounded_queue::RetainedQueueObserver;
use super::bounded_queue::RetainedQueueStats;
use super::bounded_queue::RetainedSize;
use super::event_stream::server_event_channel;
use super::event_stream::EventQueueLimits;
use super::event_stream::EventQueueObserver;
use super::event_stream::EventQueueStats;
use super::event_stream::ManagedEventSender;
use super::event_stream::ServerEventStream;
use super::runtime::fair_ready_channel_ids;
use super::runtime::run_callback_work;
use super::runtime::server_ack_freshness_timeout;
use super::runtime::validate_server_announce;
use super::server::announce_retained_size;
use super::server::control_config_retained_size;
use super::server::integrity_retained_size;
use super::server::key_retained_size;
use super::server::ServerControlChannelConfig;
use super::server::ServerControlMode;
use super::server::ServerControlSettings;
use super::server::ServerError;
use super::server::ServerEvent;
use super::server::ServerEventCoalescer;
use super::server_stream;
use super::ControllerSendError;
use super::RuntimeLimits;
use super::RuntimeLimitsError;
use super::ServerRuntimeQueueStats;

/// Handle for consuming multicast control events and relaying integrity from
/// an external multicast sender.
pub struct ServerControlController {
    pub(super) command_sender: BoundedSender<ServerControlCommand>,
    pub(super) command_observer: RetainedQueueObserver,
    pub(super) pending_publication_observer: RetainedQueueObserver,
    pub(super) pending_integrity_observer: RetainedQueueObserver,
    pub(super) event_receiver: Option<ServerEventStream>,
    pub(super) event_observer: EventQueueObserver<ServerEvent>,
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
    pub(super) runtime: ServerControlRuntime,
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
#[derive(Debug)]
pub(super) enum ServerControlCommand {
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

pub(super) struct PendingServerControlCommand {
    pub(super) command: Queued<ServerControlCommand>,
    pub(super) deferred_barrier: bool,
    pub(super) blocked_since: Option<Instant>,
}

pub(super) enum ControlSendOutcome {
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

#[derive(Default)]
pub(super) struct ServerControlChannel {
    pub(super) announce: Option<quiche::multicast::Announce>,
    pub(super) key: Option<quiche::multicast::Key>,
    pub(super) announce_sent: bool,
    pub(super) announce_pending: bool,
    pub(super) join_sent: bool,
    pub(super) join_pending: bool,
    pub(super) leave_pending: bool,
    pub(super) join_blocked_by_client: bool,
    pub(super) stream_publisher: bool,
    pub(super) max_stream_id: Option<u64>,
    pub(super) largest_stream_packet_number: Option<u64>,
    pub(super) stream_delivery_metrics: Option<ConnectionStreamDeliveryMetrics>,
    pub(super) stream_publication_queue:
        Option<Arc<server_stream::ServerStreamPublisherQueue>>,
    pub(super) last_client_state_sequence: u64,
    pub(super) retired: bool,
    pub(super) retirement_pending: bool,
    pub(super) generation: u64,
}

pub(super) struct ConnectionStreamDeliveryMetrics {
    accumulator: Arc<server_stream::ServerStreamDeliveryMetricsAccumulator>,
    baseline: quiche::multicast::StreamDeliveryMetricsSnapshot,
}

pub(super) struct PendingStreamIntegrityBatch {
    pub(super) frame: quiche::multicast::Integrity,
    pub(super) hash_len: usize,
    pub(super) deadline: Instant,
}

impl RetainedSize for PendingStreamIntegrityBatch {
    fn retained_size(&self) -> usize {
        integrity_retained_size(&self.frame).saturating_add(64)
    }
}

pub(super) struct PendingIntegrityFrames {
    queues: BTreeMap<Vec<u8>, VecDeque<Queued<quiche::multicast::Integrity>>>,
    ready: VecDeque<Vec<u8>>,
    ready_set: BTreeSet<Vec<u8>>,
    budget: RetainedQueueBudget<quiche::multicast::Integrity>,
    observer: RetainedQueueObserver,
}

impl PendingIntegrityFrames {
    pub(super) fn new(limits: RetainedQueueLimits) -> Self {
        let (budget, observer) = retained_queue_budget(limits);
        Self {
            queues: BTreeMap::new(),
            ready: VecDeque::new(),
            ready_set: BTreeSet::new(),
            budget,
            observer,
        }
    }

    pub(super) fn push_back(
        &mut self, frame: quiche::multicast::Integrity,
    ) -> Result<(), quiche::multicast::Integrity> {
        self.push(frame, false)
    }

    pub(super) fn push_front(
        &mut self, frame: quiche::multicast::Integrity,
    ) -> Result<(), quiche::multicast::Integrity> {
        self.push(frame, true)
    }

    pub(super) fn push(
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

    pub(super) fn pop_next(&mut self) -> Option<quiche::multicast::Integrity> {
        while let Some(channel_id) = self.ready.pop_front() {
            self.ready_set.remove(&channel_id);
            if let Some(frame) = self.pop_channel_inner(&channel_id) {
                return Some(frame);
            }
        }

        None
    }

    #[cfg(test)]
    pub(super) fn pop_front(&mut self) -> Option<quiche::multicast::Integrity> {
        self.pop_next()
    }

    pub(super) fn pop_channel_inner(
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

    pub(super) fn schedule(&mut self, channel_id: Vec<u8>) {
        if self.ready_set.insert(channel_id.clone()) {
            self.ready.push_back(channel_id);
        }
    }

    pub(super) fn contains_channel(&self, channel_id: &[u8]) -> bool {
        self.queues.contains_key(channel_id)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    pub(super) fn clear(&mut self) {
        self.queues.clear();
        self.ready.clear();
        self.ready_set.clear();
    }

    pub(super) fn observer(&self) -> RetainedQueueObserver {
        self.observer.clone()
    }

    pub(super) fn batch_budget(
        &self,
    ) -> RetainedQueueBudget<PendingStreamIntegrityBatch> {
        self.budget.cast()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PendingStreamKey {
    channel_id: Vec<u8>,
    stream_id: u64,
}

pub(super) struct PendingStreamPublications {
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
    pub(super) fn new(limits: RetainedQueueLimits) -> Self {
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

    pub(super) fn push(
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

    pub(super) fn schedule(&mut self, key: PendingStreamKey) {
        if self.ready_set.insert(key.clone()) {
            self.ready.push_back(key);
        }
    }

    pub(super) fn begin_pass(&mut self) {
        self.blocked.clear();
    }

    pub(super) fn next_ready(&mut self) -> Option<PendingStreamKey> {
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

    pub(super) fn front(
        &self, key: &PendingStreamKey,
    ) -> Option<&Arc<server_stream::CommittedServerStreamPublication>> {
        self.queues
            .get(key)
            .and_then(|queue| queue.front())
            .map(Queued::as_ref)
    }

    pub(super) fn complete_front(&mut self, key: PendingStreamKey) {
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

    pub(super) fn block(&mut self, key: PendingStreamKey) {
        self.blocked.insert(key.clone());
        self.schedule(key);
    }

    pub(super) fn contains_channel(&self, channel_id: &[u8]) -> bool {
        self.queues
            .keys()
            .any(|key| key.channel_id.as_slice() == channel_id)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.observer.stats().retained_items
    }

    pub(super) fn is_retry_blocked(&self) -> bool {
        !self.queues.is_empty() && self.blocked.len() == self.queues.len()
    }

    pub(super) fn clear(&mut self) {
        self.queues.clear();
        self.ready.clear();
        self.ready_set.clear();
        self.blocked.clear();
    }

    pub(super) fn observer(&self) -> RetainedQueueObserver {
        self.observer.clone()
    }
}

pub(super) struct ServerControlRuntime {
    pub(super) settings: ServerControlSettings,
    pub(super) limits: RuntimeLimits,
    pub(super) event_sender: ManagedEventSender<ServerEvent>,
    pub(super) command_receiver: BoundedReceiver<ServerControlCommand>,
    pub(super) command_budget: RetainedQueueBudget<ServerControlCommand>,
    pub(super) pending_commands: VecDeque<PendingServerControlCommand>,
    pub(super) blocked_command_channels: BTreeSet<Vec<u8>>,
    pub(super) pending_stream_publications: PendingStreamPublications,
    pub(super) pending_integrities: PendingIntegrityFrames,
    pub(super) pending_stream_integrity_batches:
        BTreeMap<Vec<u8>, Queued<PendingStreamIntegrityBatch>>,
    pub(super) pending_stream_integrity_batch_budget:
        RetainedQueueBudget<PendingStreamIntegrityBatch>,
    pub(super) control_read_pending: bool,
    pub(super) probe_read_pending: bool,
    pub(super) integrity_retry_blocked: bool,
    pub(super) control_retry_deadline: Option<Instant>,
    pub(super) channels: BTreeMap<Vec<u8>, ServerControlChannel>,
    pub(super) publisher_stage_cursor: Option<Vec<u8>>,
    pub(super) integrity_stage_cursor: Option<Vec<u8>>,
    pub(super) stream_metric_fold_cursor: Option<Vec<u8>>,
    pub(super) read_work_cursor: usize,
    pub(super) write_work_cursor: usize,
    pub(super) last_client_limits: Option<quiche::multicast::Limits>,
    pub(super) event_coalescer: ServerEventCoalescer,
    #[cfg(test)]
    pub(super) stream_delivery_metric_fold_attempts: u64,
    #[cfg(test)]
    pub(super) stream_publication_registrations: u64,
    #[cfg(test)]
    pub(super) callback_read_work_last_call: usize,
    #[cfg(test)]
    pub(super) callback_write_work_last_call: usize,
}

impl ServerControlRuntime {
    #[cfg(test)]
    pub(super) fn new(
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

    pub(super) fn with_limits(
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

    pub(super) fn clear(&mut self) {
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

    pub(super) fn on_conn_close(&mut self, qconn: &QuicheConnection) {
        self.fold_final_stream_delivery_metrics(qconn);
        self.clear();
        self.event_sender.finish();
    }

    pub(super) fn has_pending_work(&self) -> bool {
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

    pub(super) async fn wait_for_work(&mut self) -> QuicResult<()> {
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

    pub(super) fn on_conn_established(
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

    pub(super) fn process_reads(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
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

    pub(super) fn process_writes(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
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

    pub(super) fn transfer_one_server_control_command(&mut self) -> bool {
        let Ok(command) = self.command_receiver.try_recv() else {
            return false;
        };
        self.pending_commands
            .push_back(PendingServerControlCommand::regular(command));
        true
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

    pub(super) fn fold_stream_delivery_metrics_snapshot(
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

    pub(super) fn fold_one_dirty_stream_delivery_metric(
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

    pub(super) fn fold_final_stream_delivery_metrics(
        &mut self, qconn: &QuicheConnection,
    ) {
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

    pub(super) fn stop_stream_publisher(
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

    pub(super) fn forward_one_probe_event(
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

    pub(super) fn initialize_channels(
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

    pub(super) fn handle_frame(
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

    pub(super) fn handle_limits(
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

    pub(super) fn enforce_client_channel_id_limit(
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

    pub(super) fn retire_channel_for_limits(
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

    pub(super) fn enforce_client_join_limits(
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

    pub(super) fn handle_pending_commands(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        self.handle_pending_commands_with_limit(
            qconn,
            self.limits.max_work_per_call,
        )
        .map(|_| ())
    }

    pub(super) fn handle_one_pending_command(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.handle_pending_commands_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    pub(super) fn handle_pending_commands_with_limit(
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

    pub(super) fn coalesce_attached_publisher_ready(
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

    pub(super) fn stream_publisher_item_command(
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

    pub(super) fn stream_publisher_command_item(
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

    pub(super) fn stage_stream_publisher_queue_items(
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

    pub(super) fn stage_one_stream_publisher_queue_item(
        &mut self,
    ) -> QuicResult<bool> {
        self.stage_pending_stream_publisher_queues_with_limit(1)
            .map(|work| work > 0)
    }

    pub(super) fn stage_pending_stream_publisher_queues_with_limit(
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

    pub(super) fn stage_stream_publisher_queue(
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

    pub(super) fn queue_command_front(
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

    pub(super) fn queue_command_back(
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

    pub(super) fn try_send_control(
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

    pub(super) fn retry_control_command(
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

    pub(super) fn defer_pending_barrier(
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

    pub(super) fn upsert_channel_config(
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

    pub(super) fn ensure_channel_capacity(
        &self, channel_id: &[u8],
    ) -> QuicResult<()> {
        if !self.channels.contains_key(channel_id) &&
            self.channels.len() >= self.limits.max_tracked_channel_ids
        {
            return Err(Box::new(ServerError::TrackedChannelIdLimit(
                self.limits.max_tracked_channel_ids,
            )));
        }

        Ok(())
    }

    pub(super) fn maybe_auto_announce_channel(
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

    pub(super) fn maybe_auto_join_channel(
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

    pub(super) fn channel_fits_client_limits(
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

    pub(super) fn channel_can_be_announced(
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

    pub(super) fn announce_matches_client_capabilities(
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

    pub(super) fn stream_id_within_peer_limit(
        qconn: &QuicheConnection, stream_id: u64,
    ) -> bool {
        stream_id >> 2 < qconn.peer_max_streams_uni()
    }

    pub(super) fn leave_channel(
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

    pub(super) fn flush_one_pending_stream_publication(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.flush_pending_stream_publications_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    pub(super) fn flush_pending_stream_publications_with_limit(
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

    pub(super) fn flush_pending_stream_publication(
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

    pub(super) fn queue_stream_integrity(
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

    pub(super) fn integrity_hash_shape(
        frame: &quiche::multicast::Integrity,
    ) -> Option<(u64, usize)> {
        let count = frame.packet_hash_count?;
        let count_usize = usize::try_from(count).ok()?;
        if count_usize == 0 ||
            frame.packet_hashes.is_empty() ||
            !frame.packet_hashes.len().is_multiple_of(count_usize)
        {
            return None;
        }

        Some((count, frame.packet_hashes.len() / count_usize))
    }

    pub(super) fn next_stream_integrity_deadline(&self) -> Option<Instant> {
        self.pending_stream_integrity_batches
            .values()
            .map(|pending| pending.as_ref().deadline)
            .min()
    }

    pub(super) fn next_runtime_deadline(&self) -> Option<Instant> {
        match (
            self.next_stream_integrity_deadline(),
            self.control_retry_deadline,
        ) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }

    pub(super) fn stage_one_due_stream_integrity(
        &mut self, now: Instant,
    ) -> QuicResult<bool> {
        self.stage_due_stream_integrities_with_limit(now, 1)
            .map(|work| work > 0)
    }

    pub(super) fn stage_due_stream_integrities_with_limit(
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

    pub(super) fn flush_stream_integrity_batch(
        &mut self, channel_id: &[u8],
    ) -> QuicResult<()> {
        if let Some(pending) =
            self.pending_stream_integrity_batches.remove(channel_id)
        {
            self.queue_integrity(pending.into_inner().frame)?;
        }

        Ok(())
    }

    pub(super) fn store_stream_integrity_batch(
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

    pub(super) fn queue_integrity(
        &mut self, frame: quiche::multicast::Integrity,
    ) -> QuicResult<()> {
        self.pending_integrities.push_back(frame).map_err(|_| {
            Box::new(ServerError::RuntimeQueueExhausted("integrity"))
                as crate::result::BoxError
        })
    }

    pub(super) fn flush_one_pending_integrity(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.flush_pending_integrities_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    pub(super) fn flush_pending_integrities_with_limit(
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

    pub(super) fn prepare_channel_barrier(
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

    pub(super) fn finish_limit_retirement(
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

    pub(super) fn peer_supports_multicast(
        &self, qconn: &QuicheConnection,
    ) -> bool {
        qconn
            .peer_transport_params()
            .and_then(|params| params.multicast_client_params.as_ref())
            .is_some()
    }

    pub(super) fn set_default_dgram_channel_if_unset(
        qconn: &mut QuicheConnection, channel_id: &[u8],
    ) -> QuicResult<()> {
        if qconn.multicast_default_dgram_channel().is_none() {
            qconn
                .multicast_set_default_dgram_channel(Some(channel_id.to_vec()))?;
        }

        Ok(())
    }

    pub(super) fn set_ack_timeout(
        qconn: &mut QuicheConnection, channel_id: &[u8], max_ack_delay_ms: u64,
    ) -> QuicResult<()> {
        qconn.multicast_set_ack_timeout(
            channel_id,
            Some(server_ack_freshness_timeout(max_ack_delay_ms)),
        )?;

        Ok(())
    }
}
