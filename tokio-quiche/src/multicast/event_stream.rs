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
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;

use futures::stream::FusedStream;
use futures::task::AtomicWaker;
use futures::Stream;
use mcrx_core::PacketWithMetadata;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

use super::ClientEvent;
use super::ServerEvent;

/// Item and logical-byte bounds for one multicast event stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventQueueLimits {
    /// Maximum admitted required events and coalesced metric slots.
    pub max_events: usize,

    /// Maximum logical bytes retained by admitted events.
    pub max_retained_bytes: usize,
}

impl Default for EventQueueLimits {
    fn default() -> Self {
        Self {
            max_events: 4096,
            max_retained_bytes: 64 * 1024 * 1024,
        }
    }
}

impl EventQueueLimits {
    pub(super) fn validate(self) -> Result<Self, EventQueueConfigError> {
        if self.max_events == 0 {
            return Err(EventQueueConfigError::ZeroEventCapacity);
        }
        if self.max_retained_bytes == 0 {
            return Err(EventQueueConfigError::ZeroByteCapacity);
        }

        Ok(self)
    }
}

/// Invalid managed multicast event queue configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EventQueueConfigError {
    /// Required events could never be admitted.
    #[error("multicast event queue capacity must be greater than zero")]
    ZeroEventCapacity,

    /// Events with nonzero retained size could never be admitted.
    #[error("multicast event queue byte capacity must be greater than zero")]
    ZeroByteCapacity,
}

/// Why a managed multicast event stream terminated abnormally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventStreamTerminalReason {
    /// The configured event-entry bound was exhausted.
    EventCapacityExhausted,

    /// The configured retained-byte bound was exhausted.
    ByteCapacityExhausted,

    /// The consumer explicitly closed the receiver.
    ReceiverClosed,

    /// The consumer dropped the receiver before normal runtime completion.
    ReceiverDropped,

    /// The event sequence number space was exhausted.
    SequenceExhausted,
}

/// Terminal state retained independently from the bounded event queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventStreamTerminal {
    /// The deterministic terminal reason.
    pub reason: EventStreamTerminalReason,

    /// Kind of required event that could not be admitted, when applicable.
    pub rejected_event_kind: Option<&'static str>,
}

/// Point-in-time counters for a managed multicast event stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventQueueStats {
    /// Configured maximum admitted entries.
    pub max_events: usize,

    /// Configured maximum retained logical bytes.
    pub max_retained_bytes: usize,

    /// Entries currently retained by the queue or metric slots.
    pub retained_events: usize,

    /// Logical bytes currently retained by events.
    pub retained_bytes: usize,

    /// Peak retained entries.
    pub peak_retained_events: usize,

    /// Peak retained logical bytes.
    pub peak_retained_bytes: usize,

    /// Events or metric slots admitted since creation.
    pub admitted_events_total: u64,

    /// Logical bytes admitted since creation.
    pub admitted_bytes_total: u64,

    /// Events delivered to the consumer.
    pub delivered_events_total: u64,

    /// Metric snapshots folded into an existing latest-only slot.
    pub metrics_coalesced_total: u64,

    /// Metric snapshots omitted or evicted to preserve required-event capacity.
    pub metrics_dropped_total: u64,

    /// Identical diagnostics suppressed by a semantic coalescer.
    pub identical_diagnostics_coalesced_total: u64,

    /// Admission attempts rejected by an item or byte bound.
    pub queue_saturations_total: u64,

    /// Streams terminated because required delivery could not be admitted.
    pub terminal_overloads_total: u64,

    /// Events discarded only because the receiver itself was dropped.
    pub receiver_drop_events_total: u64,

    /// Current terminal state, if any.
    pub terminal: Option<EventStreamTerminal>,

    /// Whether the producer completed normally.
    pub runtime_finished: bool,
}

#[derive(Clone, Copy)]
pub(super) struct EventProperties {
    retained_bytes: usize,
    kind: &'static str,
}

pub(super) trait ManagedEvent: Send + 'static {
    fn properties(&self) -> EventProperties;

    fn metric_channel_owned(&self) -> Option<Vec<u8>>;
}

impl ManagedEvent for ClientEvent {
    fn properties(&self) -> EventProperties {
        let (retained_bytes, kind) = match self {
            Self::Announce(frame) => (
                frame
                    .channel_id
                    .len()
                    .saturating_add(frame.header_secret.len())
                    .saturating_add(96),
                "announce",
            ),

            Self::UnsupportedIpv6Announce(frame) => (
                frame
                    .channel_id
                    .len()
                    .saturating_add(frame.header_secret.len())
                    .saturating_add(96),
                "unsupported_ipv6_announce",
            ),

            Self::LocalState(frame) => (
                frame
                    .channel_id
                    .len()
                    .saturating_add(frame.reason_phrase.len())
                    .saturating_add(64),
                "local_state",
            ),

            Self::MetricsUpdated { channel_id, .. } => (
                channel_id.len().saturating_add(std::mem::size_of_val(self)),
                "metrics",
            ),

            Self::Packet {
                channel_id,
                packet,
                received,
            } => (
                channel_id
                    .len()
                    .saturating_add(channel_packet_retained_bytes(packet))
                    .saturating_add(received_packet_retained_bytes(received))
                    .saturating_add(128),
                "packet",
            ),

            Self::DecodeError {
                channel_id, packet, ..
            } => (
                channel_id
                    .len()
                    .saturating_add(received_packet_retained_bytes(packet))
                    .saturating_add(128),
                "decode_error",
            ),

            Self::ReceiveError { channel_id, .. } =>
                (channel_id.len().saturating_add(128), "receive_error"),

            Self::IngressOverload { channel_id, .. } =>
                (channel_id.len().saturating_add(64), "ingress_overload"),
        };

        EventProperties {
            retained_bytes,
            kind,
        }
    }

    fn metric_channel_owned(&self) -> Option<Vec<u8>> {
        match self {
            Self::MetricsUpdated { channel_id, .. } => Some(channel_id.clone()),
            _ => None,
        }
    }
}

impl ManagedEvent for ServerEvent {
    fn properties(&self) -> EventProperties {
        let (retained_bytes, kind) = match self {
            Self::ClientLimits(..) => (64, "client_limits"),

            Self::ClientState(frame) => (
                frame
                    .channel_id
                    .len()
                    .saturating_add(frame.reason_phrase.len())
                    .saturating_add(64),
                "client_state",
            ),

            Self::ClientAck(frame) => (
                frame
                    .channel_id
                    .len()
                    .saturating_add(frame.ack_ranges.len().saturating_mul(16))
                    .saturating_add(64),
                "client_ack",
            ),

            Self::ProbeStatusChanged(event) => (
                event
                    .channel_id
                    .len()
                    .saturating_add(event.reason_phrase.len())
                    .saturating_add(64),
                "probe_status",
            ),

            Self::Published { channel_id, .. } =>
                (channel_id.len().saturating_add(128), "published"),

            Self::EncodeError { channel_id, .. } =>
                (channel_id.len().saturating_add(128), "encode_error"),

            Self::PublishError { channel_id, .. } =>
                (channel_id.len().saturating_add(128), "publish_error"),
        };

        EventProperties {
            retained_bytes,
            kind,
        }
    }

    fn metric_channel_owned(&self) -> Option<Vec<u8>> {
        None
    }
}

fn channel_packet_retained_bytes(
    packet: &quiche::multicast::ChannelPacket,
) -> usize {
    packet.frames.iter().fold(
        packet.channel_id.len().saturating_add(64),
        |total, frame| {
            let frame_bytes = match frame {
                quiche::multicast::ChannelFrame::Stream { data, .. } |
                quiche::multicast::ChannelFrame::Datagram { data } =>
                    data.len().saturating_add(48),

                quiche::multicast::ChannelFrame::Multicast(frame) =>
                    match frame {
                        quiche::multicast::Frame::Announce(frame) => frame
                            .channel_id
                            .len()
                            .saturating_add(frame.header_secret.len())
                            .saturating_add(96),

                        quiche::multicast::Frame::Key(frame) => frame
                            .channel_id
                            .len()
                            .saturating_add(frame.secret.len())
                            .saturating_add(48),

                        quiche::multicast::Frame::Integrity(frame) => frame
                            .channel_id
                            .len()
                            .saturating_add(frame.packet_hashes.len())
                            .saturating_add(48),

                        _ => 96,
                    },

                _ => 48,
            };
            total.saturating_add(frame_bytes)
        },
    )
}

fn received_packet_retained_bytes(packet: &PacketWithMetadata) -> usize {
    packet.packet.payload.len().saturating_add(128)
}

struct QueuedEvent<E> {
    sequence: u64,
    retained_bytes: usize,
    event: E,
}

struct EventQueueState<E> {
    next_sequence: u64,
    metric_epoch: u64,
    coalesced: BTreeMap<u64, QueuedEvent<E>>,
    active_metrics: BTreeMap<Vec<u8>, (u64, u64)>,
    retained_events: usize,
    retained_bytes: usize,
    peak_retained_events: usize,
    peak_retained_bytes: usize,
    admitted_events_total: u64,
    admitted_bytes_total: u64,
    delivered_events_total: u64,
    metrics_coalesced_total: u64,
    metrics_dropped_total: u64,
    identical_diagnostics_coalesced_total: u64,
    queue_saturations_total: u64,
    terminal_overloads_total: u64,
    receiver_drop_events_total: u64,
    terminal: Option<EventStreamTerminal>,
    receiver_closed: bool,
    receiver_dropped: bool,
    runtime_finished: bool,
}

impl<E> Default for EventQueueState<E> {
    fn default() -> Self {
        Self {
            next_sequence: 0,
            metric_epoch: 0,
            coalesced: BTreeMap::new(),
            active_metrics: BTreeMap::new(),
            retained_events: 0,
            retained_bytes: 0,
            peak_retained_events: 0,
            peak_retained_bytes: 0,
            admitted_events_total: 0,
            admitted_bytes_total: 0,
            delivered_events_total: 0,
            metrics_coalesced_total: 0,
            metrics_dropped_total: 0,
            identical_diagnostics_coalesced_total: 0,
            queue_saturations_total: 0,
            terminal_overloads_total: 0,
            receiver_drop_events_total: 0,
            terminal: None,
            receiver_closed: false,
            receiver_dropped: false,
            runtime_finished: false,
        }
    }
}

struct EventQueueShared<E> {
    state: Mutex<EventQueueState<E>>,
    limits: EventQueueLimits,
    waker: AtomicWaker,
}

impl<E> EventQueueShared<E> {
    fn stats(&self) -> EventQueueStats {
        let state = self.state.lock().expect("event queue mutex poisoned");
        EventQueueStats {
            max_events: self.limits.max_events,
            max_retained_bytes: self.limits.max_retained_bytes,
            retained_events: state.retained_events,
            retained_bytes: state.retained_bytes,
            peak_retained_events: state.peak_retained_events,
            peak_retained_bytes: state.peak_retained_bytes,
            admitted_events_total: state.admitted_events_total,
            admitted_bytes_total: state.admitted_bytes_total,
            delivered_events_total: state.delivered_events_total,
            metrics_coalesced_total: state.metrics_coalesced_total,
            metrics_dropped_total: state.metrics_dropped_total,
            identical_diagnostics_coalesced_total: state
                .identical_diagnostics_coalesced_total,
            queue_saturations_total: state.queue_saturations_total,
            terminal_overloads_total: state.terminal_overloads_total,
            receiver_drop_events_total: state.receiver_drop_events_total,
            terminal: state.terminal.clone(),
            runtime_finished: state.runtime_finished,
        }
    }
}

pub(super) struct EventQueueObserver<E> {
    shared: Arc<EventQueueShared<E>>,
}

impl<E> Clone for EventQueueObserver<E> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<E> EventQueueObserver<E> {
    pub(super) fn stats(&self) -> EventQueueStats {
        self.shared.stats()
    }
}

pub(super) struct ManagedEventSender<E> {
    sender: mpsc::Sender<QueuedEvent<E>>,
    shared: Arc<EventQueueShared<E>>,
}

impl<E> Clone for ManagedEventSender<E> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            shared: Arc::clone(&self.shared),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum EventSendError {
    #[error("multicast event stream terminated: {0:?}")]
    Terminal(EventStreamTerminal),

    #[error("multicast event stream runtime has finished")]
    Finished,
}

impl<E: ManagedEvent> ManagedEventSender<E> {
    pub(super) fn try_send(&self, event: E) -> Result<(), EventSendError> {
        let properties = event.properties();
        let metric_channel = event.metric_channel_owned();
        let mut state = self.shared.state.lock().expect("event queue poisoned");

        if state.runtime_finished {
            return Err(EventSendError::Finished);
        }
        if let Some(terminal) = state.terminal.clone() {
            return Err(EventSendError::Terminal(terminal));
        }
        if state.receiver_closed || state.receiver_dropped {
            let terminal = EventStreamTerminal {
                reason: if state.receiver_dropped {
                    EventStreamTerminalReason::ReceiverDropped
                } else {
                    EventStreamTerminalReason::ReceiverClosed
                },
                rejected_event_kind: Some(properties.kind),
            };
            state.terminal.get_or_insert_with(|| terminal.clone());
            return Err(EventSendError::Terminal(terminal));
        }

        if let Some(channel_id) = metric_channel {
            if let Some((epoch, sequence)) =
                state.active_metrics.get(&channel_id).copied()
            {
                if epoch == state.metric_epoch {
                    let old_bytes = state
                        .coalesced
                        .get(&sequence)
                        .map_or(0, |queued| queued.retained_bytes);
                    let retained_bytes = state
                        .retained_bytes
                        .saturating_sub(old_bytes)
                        .saturating_add(properties.retained_bytes);
                    if retained_bytes > self.shared.limits.max_retained_bytes {
                        record_metric_drop(&mut state);
                        drop(state);
                        return Ok(());
                    }

                    let queued = state
                        .coalesced
                        .get_mut(&sequence)
                        .expect("active metric sequence is retained");
                    queued.event = event;
                    queued.retained_bytes = properties.retained_bytes;
                    state.retained_bytes = retained_bytes;
                    state.peak_retained_bytes =
                        state.peak_retained_bytes.max(retained_bytes);
                    state.metrics_coalesced_total =
                        state.metrics_coalesced_total.saturating_add(1);
                    drop(state);
                    self.shared.waker.wake();
                    return Ok(());
                }
            }

            let sequence = match reserve_metric_event(
                &mut state,
                self.shared.limits,
                properties,
            ) {
                Ok(Some(sequence)) => sequence,
                Ok(None) => {
                    drop(state);
                    return Ok(());
                },
                Err(error) => {
                    drop(state);
                    self.shared.waker.wake();
                    return Err(error);
                },
            };
            state.coalesced.insert(sequence, QueuedEvent {
                sequence,
                retained_bytes: properties.retained_bytes,
                event,
            });
            let metric_epoch = state.metric_epoch;
            state
                .active_metrics
                .insert(channel_id, (metric_epoch, sequence));
            drop(state);
            self.shared.waker.wake();
            return Ok(());
        }

        state.metric_epoch = state.metric_epoch.saturating_add(1);
        make_room_for_required(
            &mut state,
            self.shared.limits,
            properties.retained_bytes,
        );
        let sequence =
            match reserve_event(&mut state, self.shared.limits, properties) {
                Ok(sequence) => sequence,
                Err(error) => {
                    drop(state);
                    self.shared.waker.wake();
                    return Err(error);
                },
            };
        let queued = QueuedEvent {
            sequence,
            retained_bytes: properties.retained_bytes,
            event,
        };

        match self.sender.try_send(queued) {
            Ok(()) => Ok(()),

            Err(mpsc::error::TrySendError::Full(queued)) => {
                rollback_reservation(&mut state, queued.retained_bytes);
                let terminal = terminate_for_capacity(
                    &mut state,
                    EventStreamTerminalReason::EventCapacityExhausted,
                    properties.kind,
                );
                drop(state);
                self.shared.waker.wake();
                Err(EventSendError::Terminal(terminal))
            },

            Err(mpsc::error::TrySendError::Closed(queued)) => {
                rollback_reservation(&mut state, queued.retained_bytes);
                let terminal = EventStreamTerminal {
                    reason: EventStreamTerminalReason::ReceiverClosed,
                    rejected_event_kind: Some(properties.kind),
                };
                state.terminal.get_or_insert_with(|| terminal.clone());
                drop(state);
                self.shared.waker.wake();
                Err(EventSendError::Terminal(terminal))
            },
        }
    }

    pub(super) fn record_identical_coalesced(&self) {
        let mut state = self.shared.state.lock().expect("event queue poisoned");
        if state.runtime_finished {
            return;
        }
        state.identical_diagnostics_coalesced_total = state
            .identical_diagnostics_coalesced_total
            .saturating_add(1);
    }

    pub(super) fn finish(&self) {
        let mut state = self.shared.state.lock().expect("event queue poisoned");
        state.runtime_finished = true;
        drop(state);
        self.shared.waker.wake();
    }
}

fn reserve_event<E>(
    state: &mut EventQueueState<E>, limits: EventQueueLimits,
    properties: EventProperties,
) -> Result<u64, EventSendError> {
    if state.retained_events >= limits.max_events {
        let terminal = terminate_for_capacity(
            state,
            EventStreamTerminalReason::EventCapacityExhausted,
            properties.kind,
        );
        return Err(EventSendError::Terminal(terminal));
    }
    if state
        .retained_bytes
        .saturating_add(properties.retained_bytes) >
        limits.max_retained_bytes
    {
        let terminal = terminate_for_capacity(
            state,
            EventStreamTerminalReason::ByteCapacityExhausted,
            properties.kind,
        );
        return Err(EventSendError::Terminal(terminal));
    }
    let Some(sequence) = state.next_sequence.checked_add(1) else {
        let terminal = EventStreamTerminal {
            reason: EventStreamTerminalReason::SequenceExhausted,
            rejected_event_kind: Some(properties.kind),
        };
        state.terminal = Some(terminal.clone());
        state.terminal_overloads_total =
            state.terminal_overloads_total.saturating_add(1);
        return Err(EventSendError::Terminal(terminal));
    };
    let assigned = state.next_sequence;
    state.next_sequence = sequence;
    state.retained_events = state.retained_events.saturating_add(1);
    state.retained_bytes = state
        .retained_bytes
        .saturating_add(properties.retained_bytes);
    state.peak_retained_events =
        state.peak_retained_events.max(state.retained_events);
    state.peak_retained_bytes =
        state.peak_retained_bytes.max(state.retained_bytes);
    state.admitted_events_total = state.admitted_events_total.saturating_add(1);
    state.admitted_bytes_total = state
        .admitted_bytes_total
        .saturating_add(properties.retained_bytes as u64);

    Ok(assigned)
}

fn reserve_metric_event<E>(
    state: &mut EventQueueState<E>, limits: EventQueueLimits,
    properties: EventProperties,
) -> Result<Option<u64>, EventSendError> {
    if state.retained_events >= limits.max_events ||
        state
            .retained_bytes
            .saturating_add(properties.retained_bytes) >
            limits.max_retained_bytes
    {
        record_metric_drop(state);
        return Ok(None);
    }

    reserve_event(state, limits, properties).map(Some)
}

fn make_room_for_required<E>(
    state: &mut EventQueueState<E>, limits: EventQueueLimits,
    required_bytes: usize,
) {
    while !state.coalesced.is_empty() &&
        (state.retained_events >= limits.max_events ||
            state.retained_bytes.saturating_add(required_bytes) >
                limits.max_retained_bytes)
    {
        let sequence = *state
            .coalesced
            .first_key_value()
            .expect("coalesced queue is not empty")
            .0;
        let queued = state
            .coalesced
            .remove(&sequence)
            .expect("coalesced sequence exists");
        state
            .active_metrics
            .retain(|_, (_, active_sequence)| *active_sequence != sequence);
        state.retained_events = state.retained_events.saturating_sub(1);
        state.retained_bytes =
            state.retained_bytes.saturating_sub(queued.retained_bytes);
        record_metric_drop(state);
    }
}

fn record_metric_drop<E>(state: &mut EventQueueState<E>) {
    state.metrics_dropped_total = state.metrics_dropped_total.saturating_add(1);
    state.queue_saturations_total =
        state.queue_saturations_total.saturating_add(1);
}

fn rollback_reservation<E>(
    state: &mut EventQueueState<E>, retained_bytes: usize,
) {
    state.retained_events = state.retained_events.saturating_sub(1);
    state.retained_bytes = state.retained_bytes.saturating_sub(retained_bytes);
    state.admitted_events_total = state.admitted_events_total.saturating_sub(1);
    state.admitted_bytes_total = state
        .admitted_bytes_total
        .saturating_sub(retained_bytes as u64);
}

fn terminate_for_capacity<E>(
    state: &mut EventQueueState<E>, reason: EventStreamTerminalReason,
    event_kind: &'static str,
) -> EventStreamTerminal {
    let terminal = EventStreamTerminal {
        reason,
        rejected_event_kind: Some(event_kind),
    };
    state.terminal.get_or_insert_with(|| terminal.clone());
    state.queue_saturations_total =
        state.queue_saturations_total.saturating_add(1);
    state.terminal_overloads_total =
        state.terminal_overloads_total.saturating_add(1);
    terminal
}

struct ManagedEventStream<E> {
    receiver: mpsc::Receiver<QueuedEvent<E>>,
    shared: Arc<EventQueueShared<E>>,
    buffered: Option<QueuedEvent<E>>,
    channel_closed: bool,
    terminated: bool,
    dropped: bool,
}

impl<E: ManagedEvent> ManagedEventStream<E> {
    async fn recv(&mut self) -> Option<E> {
        poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    fn try_recv(&mut self) -> Result<E, TryRecvError> {
        if self.terminated {
            return Err(TryRecvError::Disconnected);
        }

        if self.buffered.is_none() {
            match self.receiver.try_recv() {
                Ok(event) => self.buffered = Some(event),
                Err(TryRecvError::Disconnected) => self.channel_closed = true,
                Err(TryRecvError::Empty) => (),
            }
        }

        if let Some(event) = self.take_lowest_sequence() {
            return Ok(event);
        }

        if self.is_finished() {
            self.terminated = true;
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    fn close(&mut self) {
        self.receiver.close();
        let mut state = self.shared.state.lock().expect("event queue poisoned");
        state.receiver_closed = true;
        state.terminal.get_or_insert(EventStreamTerminal {
            reason: EventStreamTerminalReason::ReceiverClosed,
            rejected_event_kind: None,
        });
        drop(state);
        self.shared.waker.wake();
    }

    fn stats(&self) -> EventQueueStats {
        self.shared.stats()
    }

    fn terminal(&self) -> Option<EventStreamTerminal> {
        self.shared.stats().terminal
    }

    fn take_lowest_sequence(&mut self) -> Option<E> {
        let mut state = self.shared.state.lock().expect("event queue poisoned");
        let coalesced_sequence =
            state.coalesced.first_key_value().map(|(k, _)| *k);
        let buffered_sequence =
            self.buffered.as_ref().map(|event| event.sequence);

        let queued = match (buffered_sequence, coalesced_sequence) {
            (Some(buffered), Some(coalesced)) if buffered <= coalesced =>
                self.buffered.take(),

            (Some(_), Some(coalesced)) => state.coalesced.remove(&coalesced),

            (Some(_), None) => self.buffered.take(),

            (None, Some(coalesced)) => state.coalesced.remove(&coalesced),

            (None, None) => None,
        }?;

        state
            .active_metrics
            .retain(|_, (_, sequence)| *sequence != queued.sequence);
        state.retained_events = state.retained_events.saturating_sub(1);
        state.retained_bytes =
            state.retained_bytes.saturating_sub(queued.retained_bytes);
        state.delivered_events_total =
            state.delivered_events_total.saturating_add(1);

        Some(queued.event)
    }

    fn is_finished(&self) -> bool {
        let state = self.shared.state.lock().expect("event queue poisoned");
        let no_retained = state.retained_events == 0 && self.buffered.is_none();
        no_retained &&
            (state.runtime_finished ||
                state.terminal.is_some() ||
                state.receiver_closed ||
                state.receiver_dropped ||
                self.channel_closed)
    }

    fn poll_next_event(&mut self, cx: &mut Context<'_>) -> Poll<Option<E>> {
        if self.terminated {
            return Poll::Ready(None);
        }

        self.shared.waker.register(cx.waker());

        if self.buffered.is_none() && !self.channel_closed {
            match Pin::new(&mut self.receiver).poll_recv(cx) {
                Poll::Ready(Some(event)) => self.buffered = Some(event),
                Poll::Ready(None) => self.channel_closed = true,
                Poll::Pending => (),
            }
        }

        if let Some(event) = self.take_lowest_sequence() {
            return Poll::Ready(Some(event));
        }
        if self.is_finished() {
            self.terminated = true;
            return Poll::Ready(None);
        }

        // Close the race between registering and observing terminal/metric
        // state changed by a producer.
        self.shared.waker.register(cx.waker());
        if self.is_finished() {
            self.terminated = true;
            return Poll::Ready(None);
        }
        if self
            .shared
            .state
            .lock()
            .expect("event queue poisoned")
            .coalesced
            .is_empty()
        {
            Poll::Pending
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

impl<E: ManagedEvent> Stream for ManagedEventStream<E> {
    type Item = E;

    fn poll_next(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_next_event(cx)
    }
}

impl<E: ManagedEvent> FusedStream for ManagedEventStream<E> {
    fn is_terminated(&self) -> bool {
        self.terminated
    }
}

impl<E> Unpin for ManagedEventStream<E> {}

impl<E> Drop for ManagedEventStream<E> {
    fn drop(&mut self) {
        if self.dropped {
            return;
        }
        self.dropped = true;
        self.receiver.close();

        let mut state = self.shared.state.lock().expect("event queue poisoned");
        if !state.runtime_finished && !state.receiver_closed {
            state.receiver_dropped = true;
            state.terminal.get_or_insert(EventStreamTerminal {
                reason: EventStreamTerminalReason::ReceiverDropped,
                rejected_event_kind: None,
            });
        }
        state.receiver_drop_events_total = state
            .receiver_drop_events_total
            .saturating_add(state.retained_events as u64);
        state.retained_events = 0;
        state.retained_bytes = 0;
        state.coalesced.clear();
        state.active_metrics.clear();
        drop(state);
        self.shared.waker.wake();
    }
}

fn managed_event_channel<E: ManagedEvent>(
    limits: EventQueueLimits,
) -> (
    ManagedEventSender<E>,
    ManagedEventStream<E>,
    EventQueueObserver<E>,
) {
    debug_assert!(limits.validate().is_ok());
    let (sender, receiver) = mpsc::channel(limits.max_events);
    let shared = Arc::new(EventQueueShared {
        state: Mutex::new(EventQueueState::default()),
        limits,
        waker: AtomicWaker::new(),
    });

    (
        ManagedEventSender {
            sender,
            shared: Arc::clone(&shared),
        },
        ManagedEventStream {
            receiver,
            shared: Arc::clone(&shared),
            buffered: None,
            channel_closed: false,
            terminated: false,
            dropped: false,
        },
        EventQueueObserver { shared },
    )
}

/// Managed bounded event stream returned by the multicast client controller.
pub struct ClientEventStream {
    inner: ManagedEventStream<ClientEvent>,
}

impl ClientEventStream {
    /// Receives the next event, or `None` after normal or terminal completion.
    pub async fn recv(&mut self) -> Option<ClientEvent> {
        self.inner.recv().await
    }

    /// Attempts to receive an event without waiting.
    pub fn try_recv(&mut self) -> Result<ClientEvent, TryRecvError> {
        self.inner.try_recv()
    }

    /// Stops accepting new events while allowing admitted events to drain.
    pub fn close(&mut self) {
        self.inner.close();
    }

    /// Returns queue counters without consuming an event.
    pub fn stats(&self) -> EventQueueStats {
        self.inner.stats()
    }

    /// Returns the terminal reason, if the stream ended abnormally.
    pub fn terminal(&self) -> Option<EventStreamTerminal> {
        self.inner.terminal()
    }
}

impl Stream for ClientEventStream {
    type Item = ClientEvent;

    fn poll_next(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }
}

impl FusedStream for ClientEventStream {
    fn is_terminated(&self) -> bool {
        self.inner.is_terminated()
    }
}

/// Managed bounded event stream returned by multicast server controllers.
pub struct ServerEventStream {
    inner: ManagedEventStream<ServerEvent>,
}

impl ServerEventStream {
    /// Receives the next event, or `None` after normal or terminal completion.
    pub async fn recv(&mut self) -> Option<ServerEvent> {
        self.inner.recv().await
    }

    /// Attempts to receive an event without waiting.
    pub fn try_recv(&mut self) -> Result<ServerEvent, TryRecvError> {
        self.inner.try_recv()
    }

    /// Stops accepting new events while allowing admitted events to drain.
    pub fn close(&mut self) {
        self.inner.close();
    }

    /// Returns queue counters without consuming an event.
    pub fn stats(&self) -> EventQueueStats {
        self.inner.stats()
    }

    /// Returns the terminal reason, if the stream ended abnormally.
    pub fn terminal(&self) -> Option<EventStreamTerminal> {
        self.inner.terminal()
    }
}

impl Stream for ServerEventStream {
    type Item = ServerEvent;

    fn poll_next(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }
}

impl FusedStream for ServerEventStream {
    fn is_terminated(&self) -> bool {
        self.inner.is_terminated()
    }
}

pub(super) fn client_event_channel(
    limits: EventQueueLimits,
) -> (
    ManagedEventSender<ClientEvent>,
    ClientEventStream,
    EventQueueObserver<ClientEvent>,
) {
    let (sender, inner, observer) = managed_event_channel(limits);
    (sender, ClientEventStream { inner }, observer)
}

pub(super) fn server_event_channel(
    limits: EventQueueLimits,
) -> (
    ManagedEventSender<ServerEvent>,
    ServerEventStream,
    EventQueueObserver<ServerEvent>,
) {
    let (sender, inner, observer) = managed_event_channel(limits);
    (sender, ServerEventStream { inner }, observer)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use std::time::SystemTime;

    use super::*;
    use crate::multicast::ClientChannelMetricsSnapshot;
    use mcrx_core::SubscriptionMetricsSnapshot;

    fn limits_event(sequence: u64) -> ServerEvent {
        ServerEvent::ClientLimits(quiche::multicast::Limits {
            sequence,
            limits: quiche::multicast::ClientLimits::default(),
            max_joined_count: 1,
        })
    }

    fn announce_event(channel_id: &[u8]) -> ClientEvent {
        ClientEvent::Announce(quiche::multicast::Announce {
            channel_id: channel_id.to_vec(),
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            udp_port: 4444,
            header_protection_algorithm: 0x1301,
            header_secret: vec![0xaa; 16],
            aead_algorithm: 0x1301,
            integrity_hash_algorithm: 1,
            max_rate_kibps: 1024,
            max_ack_delay_ms: 25,
        })
    }

    fn metric_event(channel_id: &[u8], recv_calls: u64) -> ClientEvent {
        ClientEvent::MetricsUpdated {
            channel_id: channel_id.to_vec(),
            metrics: ClientChannelMetricsSnapshot {
                socket: SubscriptionMetricsSnapshot {
                    packets_received: recv_calls,
                    bytes_received: 0,
                    would_block_count: 0,
                    receive_errors: 0,
                    join_count: 0,
                    leave_count: 0,
                    last_payload_len: None,
                    last_source: None,
                    last_receive_at: None,
                    captured_at: SystemTime::UNIX_EPOCH,
                },
                receive: quiche::multicast::ChannelReceiveMetricsSnapshot {
                    recv_calls,
                    ..Default::default()
                },
            },
        }
    }

    #[test]
    fn limits_reject_zero_capacities() {
        assert_eq!(
            EventQueueLimits {
                max_events: 0,
                max_retained_bytes: 1,
            }
            .validate(),
            Err(EventQueueConfigError::ZeroEventCapacity)
        );
        assert_eq!(
            EventQueueLimits {
                max_events: 1,
                max_retained_bytes: 0,
            }
            .validate(),
            Err(EventQueueConfigError::ZeroByteCapacity)
        );
    }

    #[tokio::test]
    async fn never_polled_consumer_terminates_deterministically_when_full() {
        let (sender, mut receiver, observer) =
            server_event_channel(EventQueueLimits {
                max_events: 2,
                max_retained_bytes: 1024,
            });

        sender.try_send(limits_event(1)).unwrap();
        sender.try_send(limits_event(2)).unwrap();
        assert!(matches!(
            sender.try_send(limits_event(3)),
            Err(EventSendError::Terminal(EventStreamTerminal {
                reason: EventStreamTerminalReason::EventCapacityExhausted,
                rejected_event_kind: Some("client_limits"),
            }))
        ));

        let stats = observer.stats();
        assert_eq!(stats.retained_events, 2);
        assert!(stats.retained_bytes <= stats.max_retained_bytes);
        assert_eq!(stats.queue_saturations_total, 1);
        assert_eq!(stats.terminal_overloads_total, 1);

        assert!(matches!(
            receiver.recv().await,
            Some(ServerEvent::ClientLimits(frame)) if frame.sequence == 1
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(ServerEvent::ClientLimits(frame)) if frame.sequence == 2
        ));
        assert!(receiver.recv().await.is_none());
        assert_eq!(
            receiver.terminal().map(|terminal| terminal.reason),
            Some(EventStreamTerminalReason::EventCapacityExhausted)
        );
    }

    #[test]
    fn lifecycle_events_split_metric_epochs_and_metrics_remain_latest_only() {
        let (sender, mut receiver, observer) =
            client_event_channel(EventQueueLimits {
                max_events: 4,
                max_retained_bytes: 4096,
            });

        sender.try_send(metric_event(&[1], 1)).unwrap();
        sender.try_send(announce_event(&[1])).unwrap();
        sender.try_send(metric_event(&[1], 2)).unwrap();
        sender.try_send(metric_event(&[1], 3)).unwrap();

        assert!(matches!(
            receiver.try_recv(),
            Ok(ClientEvent::MetricsUpdated { metrics, .. })
                if metrics.receive.recv_calls == 1
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(ClientEvent::Announce(frame)) if frame.channel_id == vec![1]
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(ClientEvent::MetricsUpdated { metrics, .. })
                if metrics.receive.recv_calls == 3
        ));
        assert_eq!(observer.stats().metrics_coalesced_total, 1);
    }

    #[test]
    fn required_event_evicts_metrics_instead_of_overloading_runtime() {
        let (sender, mut receiver, observer) =
            client_event_channel(EventQueueLimits {
                max_events: 1,
                max_retained_bytes: 4096,
            });

        sender.try_send(metric_event(&[1], 1)).unwrap();
        sender.try_send(announce_event(&[1])).unwrap();

        assert!(matches!(
            receiver.try_recv(),
            Ok(ClientEvent::Announce(frame)) if frame.channel_id == vec![1]
        ));
        let stats = observer.stats();
        assert_eq!(stats.metrics_dropped_total, 1);
        assert_eq!(stats.queue_saturations_total, 1);
        assert_eq!(stats.terminal, None);
    }

    #[test]
    fn receiver_drop_releases_accounting_and_retains_terminal_reason() {
        let (sender, receiver, observer) =
            server_event_channel(EventQueueLimits {
                max_events: 2,
                max_retained_bytes: 1024,
            });
        sender.try_send(limits_event(1)).unwrap();

        drop(receiver);

        assert!(matches!(
            sender.try_send(limits_event(2)),
            Err(EventSendError::Terminal(EventStreamTerminal {
                reason: EventStreamTerminalReason::ReceiverDropped,
                ..
            }))
        ));
        let stats = observer.stats();
        assert_eq!(stats.retained_events, 0);
        assert_eq!(stats.retained_bytes, 0);
        assert_eq!(stats.receiver_drop_events_total, 1);
        assert_eq!(
            stats.terminal.map(|terminal| terminal.reason),
            Some(EventStreamTerminalReason::ReceiverDropped)
        );
    }

    #[tokio::test]
    async fn shutdown_while_full_drains_without_deadlock() {
        let (sender, mut receiver, observer) =
            server_event_channel(EventQueueLimits {
                max_events: 2,
                max_retained_bytes: 1024,
            });
        sender.try_send(limits_event(1)).unwrap();
        sender.try_send(limits_event(2)).unwrap();
        sender.finish();

        let drained = tokio::time::timeout(Duration::from_secs(1), async {
            let mut sequences = Vec::new();
            while let Some(ServerEvent::ClientLimits(frame)) =
                receiver.recv().await
            {
                sequences.push(frame.sequence);
            }
            sequences
        })
        .await
        .expect("full queue shutdown must not deadlock");

        assert_eq!(drained, vec![1, 2]);
        assert!(observer.stats().runtime_finished);
    }

    #[test]
    fn finish_rejects_required_events_from_every_sender_clone() {
        let (sender, mut receiver, observer) =
            server_event_channel(EventQueueLimits {
                max_events: 4,
                max_retained_bytes: 4096,
            });
        let clone = sender.clone();
        sender.try_send(limits_event(1)).unwrap();
        sender.finish();
        let finished_stats = observer.stats();

        assert_eq!(
            sender.try_send(limits_event(2)),
            Err(EventSendError::Finished)
        );
        assert_eq!(
            clone.try_send(limits_event(3)),
            Err(EventSendError::Finished)
        );
        clone.record_identical_coalesced();
        assert_eq!(observer.stats(), finished_stats);

        assert!(matches!(
            receiver.try_recv(),
            Ok(ServerEvent::ClientLimits(frame)) if frame.sequence == 1
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(TryRecvError::Disconnected)
        ));
        assert!(receiver.is_terminated());
        assert!(matches!(
            receiver.try_recv(),
            Err(TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn finish_rejects_coalesced_metrics_without_changing_accounting() {
        let (sender, mut receiver, observer) =
            client_event_channel(EventQueueLimits {
                max_events: 2,
                max_retained_bytes: 4096,
            });
        sender.try_send(metric_event(&[1], 1)).unwrap();
        sender.finish();
        let finished_stats = observer.stats();

        assert_eq!(
            sender.try_send(metric_event(&[1], 2)),
            Err(EventSendError::Finished)
        );
        assert_eq!(observer.stats(), finished_stats);
        assert!(matches!(
            receiver.try_recv(),
            Ok(ClientEvent::MetricsUpdated { metrics, .. })
                if metrics.receive.recv_calls == 1
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn finish_and_close_race_remains_fused_and_bounded() {
        let (sender, mut receiver, observer) =
            server_event_channel(EventQueueLimits {
                max_events: 2,
                max_retained_bytes: 1024,
            });
        sender.try_send(limits_event(1)).unwrap();
        let finishing_sender = sender.clone();

        std::thread::scope(|scope| {
            let finish = scope.spawn(move || finishing_sender.finish());
            receiver.close();
            finish.join().unwrap();
        });

        assert_eq!(
            sender.try_send(limits_event(2)),
            Err(EventSendError::Finished)
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(ServerEvent::ClientLimits(frame)) if frame.sequence == 1
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(TryRecvError::Disconnected)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(TryRecvError::Disconnected)
        ));
        assert!(receiver.is_terminated());
        let stats = observer.stats();
        assert!(stats.retained_events <= stats.max_events);
        assert!(stats.retained_bytes <= stats.max_retained_bytes);
    }

    #[test]
    fn stalled_connection_does_not_affect_another_connection() {
        let (stalled_sender, _stalled_receiver, stalled_observer) =
            server_event_channel(EventQueueLimits {
                max_events: 1,
                max_retained_bytes: 1024,
            });
        let (healthy_sender, mut healthy_receiver, healthy_observer) =
            server_event_channel(EventQueueLimits {
                max_events: 1,
                max_retained_bytes: 1024,
            });

        stalled_sender.try_send(limits_event(1)).unwrap();
        assert!(stalled_sender.try_send(limits_event(2)).is_err());

        healthy_sender.try_send(limits_event(7)).unwrap();
        assert!(matches!(
            healthy_receiver.try_recv(),
            Ok(ServerEvent::ClientLimits(frame)) if frame.sequence == 7
        ));
        assert_eq!(stalled_observer.stats().terminal_overloads_total, 1);
        assert_eq!(healthy_observer.stats().terminal_overloads_total, 0);
    }

    #[test]
    fn sustained_required_delivery_never_exceeds_configured_bounds() {
        let limits = EventQueueLimits {
            max_events: 32,
            max_retained_bytes: 32 * 64,
        };
        let (sender, _receiver, observer) = server_event_channel(limits);

        for sequence in 0..10_000 {
            let _ = sender.try_send(limits_event(sequence));
        }

        let stats = observer.stats();
        assert!(stats.retained_events <= limits.max_events);
        assert!(stats.retained_bytes <= limits.max_retained_bytes);
        assert_eq!(stats.terminal_overloads_total, 1);
    }
}
