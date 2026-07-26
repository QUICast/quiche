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
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;

use bytes::Bytes;
use tokio::sync::mpsc::UnboundedSender;

use super::ServerControlChannelConfig;
use super::ServerControlCommand;
use super::ServerControlController;

const MAX_STREAM_OFFSET: u64 = 1 << 62;

static NEXT_PUBLISHER_ID: AtomicU64 = AtomicU64::new(1);

/// One shared STREAM frame carried by an MCQUIC channel packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerStreamFrame {
    /// The server-initiated unidirectional QUIC stream ID.
    pub stream_id: u64,

    /// The absolute byte offset of this range within the QUIC stream.
    pub offset: u64,

    /// Whether this range carries the stream's FIN marker.
    pub fin: bool,

    /// The shared stream bytes.
    pub data: Bytes,
}

/// One encrypted channel packet prepared for publication by the application.
///
/// The application sends [`ServerStreamPublication::packet()`] through its own
/// multicast publisher, then passes this value to
/// [`ServerStreamPublisher::commit()`]. Committing relays integrity and the
/// retained recovery range to every attached connection.
#[derive(Clone, Debug)]
#[must_use = "a prepared multicast packet must be published and committed"]
pub struct ServerStreamPublication {
    publisher_id: u64,
    token: u64,
    packet_number: u64,
    key_sequence: u64,
    key_phase: bool,
    packet: Bytes,
    integrity: quiche::multicast::Integrity,
    frame: ServerStreamFrame,
}

impl ServerStreamPublication {
    /// Returns the multicast channel packet number.
    pub fn packet_number(&self) -> u64 {
        self.packet_number
    }

    /// Returns the key sequence used to encrypt the channel packet.
    pub fn key_sequence(&self) -> u64 {
        self.key_sequence
    }

    /// Returns the channel packet's key phase bit.
    pub fn key_phase(&self) -> bool {
        self.key_phase
    }

    /// Returns the encrypted channel packet bytes to publish over multicast.
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Returns the matching integrity frame.
    pub fn integrity(&self) -> &quiche::multicast::Integrity {
        &self.integrity
    }

    /// Returns the STREAM frame represented by this publication.
    pub fn frame(&self) -> &ServerStreamFrame {
        &self.frame
    }
}

/// Errors produced by [`ServerStreamPublisher`].
#[derive(Debug, thiserror::Error)]
pub enum ServerStreamPublisherError {
    /// The channel configuration or requested operation is invalid.
    #[error("invalid multicast stream publisher state")]
    InvalidState,

    /// The stream ID is not a server-initiated unidirectional stream.
    #[error("stream {stream_id} is not server-initiated unidirectional")]
    InvalidStreamId {
        /// The rejected QUIC stream ID.
        stream_id: u64,
    },

    /// The new frame does not begin at the stream's next shared offset.
    #[error(
        "non-contiguous multicast stream offset for stream {stream_id}: expected {expected}, got {actual}"
    )]
    NonContiguousOffset {
        /// The affected QUIC stream ID.
        stream_id: u64,

        /// The next expected stream offset.
        expected: u64,

        /// The supplied stream offset.
        actual: u64,
    },

    /// The stream already carried FIN.
    #[error("multicast stream {stream_id} is already finished")]
    StreamFinished {
        /// The affected QUIC stream ID.
        stream_id: u64,
    },

    /// A prepared publication must be committed before another is encoded.
    #[error("a multicast stream publication is still awaiting commit")]
    PublicationPending,

    /// The publication did not originate from this publisher or is stale.
    #[error("unknown or stale multicast stream publication")]
    UnknownPublication,

    /// The channel has been retired and cannot publish more packets.
    #[error("the multicast stream channel is retired")]
    Retired,

    /// The target control driver is already closed.
    #[error("the multicast control driver is closed")]
    ControllerClosed,

    /// Shared publisher state was poisoned by a panic while locked.
    #[error("multicast stream publisher state is poisoned")]
    StatePoisoned,

    /// Core channel-packet encoding failed.
    #[error("multicast stream packet encoding failed: {0}")]
    Encode(#[from] quiche::Error),
}

/// A shared, socket-free MCQUIC STREAM packet publisher.
///
/// One publisher owns the channel packet number and key state shared by all
/// receivers. Each attached [`super::ServerControlDriver`] retains independent
/// `MC_LIMITS`, `MC_STATE`, `MC_ACK`, fallback, and ordinary QUIC stream state.
/// The publisher only encodes packets and fans out committed metadata; the
/// application remains responsible for multicast socket I/O.
#[derive(Clone)]
pub struct ServerStreamPublisher {
    inner: Arc<Mutex<ServerStreamPublisherInner>>,
    delivery_metrics: Arc<ServerStreamDeliveryMetricsAccumulator>,
}

impl ServerStreamPublisher {
    /// Creates a shared publisher for one multicast channel.
    pub fn new(
        channel: ServerControlChannelConfig,
    ) -> Result<Self, ServerStreamPublisherError> {
        channel
            .validate()
            .map_err(|_| ServerStreamPublisherError::InvalidState)?;
        let send_state = quiche::multicast::ChannelSendState::new(
            channel.announce.clone(),
            channel.key.clone(),
        )?;

        Ok(Self {
            inner: Arc::new(Mutex::new(ServerStreamPublisherInner {
                publisher_id: NEXT_PUBLISHER_ID.fetch_add(1, Ordering::Relaxed),
                channel,
                send_state,
                streams: BTreeMap::new(),
                subscribers: BTreeMap::new(),
                next_subscriber_id: 0,
                pending_token: None,
                max_stream_id: None,
                reordering_threshold:
                    quiche::multicast::DEFAULT_STREAM_RECOVERY_REORDERING_THRESHOLD,
                retired: false,
                #[cfg(test)]
                profile: ServerStreamPublisherTestProfile::default(),
            })),
            delivery_metrics: Arc::new(
                ServerStreamDeliveryMetricsAccumulator::default(),
            ),
        })
    }

    /// Sets the ACK reordering threshold copied to subsequently attached
    /// connections.
    pub fn set_reordering_threshold(
        &self, threshold: u64,
    ) -> Result<(), ServerStreamPublisherError> {
        if threshold == 0 {
            return Err(ServerStreamPublisherError::InvalidState);
        }

        let mut inner = self.lock()?;
        if !inner.subscribers.is_empty() {
            return Err(ServerStreamPublisherError::InvalidState);
        }
        inner.reordering_threshold = threshold;

        Ok(())
    }

    /// Attaches one client-facing control driver to this shared publisher.
    ///
    /// The returned guard detaches the connection when dropped. In automatic
    /// control mode, attachment upserts the channel and allows the existing
    /// `MC_ANNOUNCE` / `MC_KEY` / `MC_JOIN` sequence to run for that client.
    pub fn attach(
        &self, controller: &ServerControlController,
    ) -> Result<ServerStreamAttachment, ServerStreamPublisherError> {
        let mut inner = self.lock()?;

        if inner.retired {
            return Err(ServerStreamPublisherError::Retired);
        }

        if inner.subscribers.values().any(|subscriber| {
            subscriber
                .command_sender
                .same_channel(&controller.command_sender)
        }) {
            return Err(ServerStreamPublisherError::InvalidState);
        }

        let subscriber_id = inner.next_subscriber_id;
        inner.next_subscriber_id = inner.next_subscriber_id.saturating_add(1);
        let publication_queue = Arc::new(ServerStreamPublisherQueue::new(
            inner.channel.announce.channel_id.clone(),
        ));

        controller
            .command_sender
            .send(ServerControlCommand::AttachStreamPublisher {
                config: inner.channel.clone(),
                reordering_threshold: inner.reordering_threshold,
                max_stream_id: inner.max_stream_id,
                delivery_metrics: Arc::clone(&self.delivery_metrics),
                publication_queue: Arc::clone(&publication_queue),
            })
            .map_err(|_| ServerStreamPublisherError::ControllerClosed)?;

        inner
            .subscribers
            .insert(subscriber_id, PublisherSubscriber {
                command_sender: controller.command_sender.clone(),
                publication_queue: Arc::clone(&publication_queue),
            });

        Ok(ServerStreamAttachment {
            publisher: Arc::downgrade(&self.inner),
            subscriber_id,
            command_sender: controller.command_sender.clone(),
            publication_queue,
        })
    }

    /// Declares a server-initiated unidirectional stream carried by this
    /// channel.
    ///
    /// Applications should declare each stream before publishing its first
    /// packet. Attached automatic control drivers use the largest declared
    /// stream ID to avoid sending `MC_JOIN` beyond a client's QUIC
    /// `MAX_STREAMS_UNI` limit.
    pub fn declare_stream(
        &self, stream_id: u64,
    ) -> Result<(), ServerStreamPublisherError> {
        if stream_id & 0x3 != 0x3 {
            return Err(ServerStreamPublisherError::InvalidStreamId {
                stream_id,
            });
        }

        let mut inner = self.lock()?;
        if inner.retired {
            return Err(ServerStreamPublisherError::Retired);
        }

        if inner
            .max_stream_id
            .is_some_and(|current| current >= stream_id)
        {
            return Ok(());
        }

        inner.max_stream_id = Some(stream_id);
        inner.fanout(ServerStreamPublisherQueueItem::MaxStreamId(stream_id));

        Ok(())
    }

    /// Returns the next shared offset expected for `stream_id`.
    ///
    /// A newly attached connection can use this to finish any connection-local
    /// unicast catch-up before it begins consuming committed shared ranges.
    pub fn next_stream_offset(
        &self, stream_id: u64,
    ) -> Result<Option<u64>, ServerStreamPublisherError> {
        Ok(self
            .lock()?
            .streams
            .get(&stream_id)
            .map(|stream| stream.next_offset))
    }

    /// Encodes one STREAM frame and returns a packet ready for external
    /// multicast publication.
    ///
    /// This slice-based helper copies `data` once into shared storage. Use
    /// [`ServerStreamPublisher::prepare_stream_buf()`] when the application
    /// already owns a [`Bytes`] value.
    pub fn prepare_stream(
        &self, stream_id: u64, offset: u64, fin: bool, data: &[u8],
    ) -> Result<ServerStreamPublication, ServerStreamPublisherError> {
        self.prepare_stream_buf(
            stream_id,
            offset,
            fin,
            Bytes::copy_from_slice(data),
        )
    }

    /// Encodes one owned STREAM frame and returns a packet ready for external
    /// multicast publication.
    pub fn prepare_stream_buf(
        &self, stream_id: u64, offset: u64, fin: bool, data: Bytes,
    ) -> Result<ServerStreamPublication, ServerStreamPublisherError> {
        if stream_id & 0x3 != 0x3 {
            return Err(ServerStreamPublisherError::InvalidStreamId {
                stream_id,
            });
        }

        let end = offset
            .checked_add(data.len() as u64)
            .filter(|end| *end < MAX_STREAM_OFFSET)
            .ok_or(ServerStreamPublisherError::InvalidState)?;
        let mut inner = self.lock()?;

        if inner.retired {
            return Err(ServerStreamPublisherError::Retired);
        }

        if inner.pending_token.is_some() {
            return Err(ServerStreamPublisherError::PublicationPending);
        }

        if let Some(stream) = inner.streams.get(&stream_id) {
            if stream.finished {
                return Err(ServerStreamPublisherError::StreamFinished {
                    stream_id,
                });
            }

            if stream.next_offset != offset {
                return Err(ServerStreamPublisherError::NonContiguousOffset {
                    stream_id,
                    expected: stream.next_offset,
                    actual: offset,
                });
            }
        }

        let frame = ServerStreamFrame {
            stream_id,
            offset,
            fin,
            data,
        };
        let packet_len = inner.send_state.stream_packet_len(
            stream_id,
            offset,
            frame.data.len(),
        )?;
        let mut packet = vec![0; packet_len];
        #[cfg(test)]
        {
            inner.profile.preparation_capacity_bytes = inner
                .profile
                .preparation_capacity_bytes
                .saturating_add(packet.capacity() as u64);
        }
        let output = inner.send_state.write_stream_packet(
            stream_id,
            offset,
            fin,
            &frame.data,
            &mut packet,
        )?;
        debug_assert_eq!(output.packet_len, packet_len);
        packet.truncate(output.packet_len);

        inner.streams.insert(stream_id, PublisherStreamState {
            next_offset: end,
            finished: fin,
        });
        inner.max_stream_id = Some(
            inner
                .max_stream_id
                .map_or(stream_id, |current| current.max(stream_id)),
        );
        let token = output.packet_number;
        inner.pending_token = Some(token);

        Ok(ServerStreamPublication {
            publisher_id: inner.publisher_id,
            token,
            packet_number: output.packet_number,
            key_sequence: output.key_sequence,
            key_phase: output.key_phase,
            packet: Bytes::from(packet),
            integrity: output.integrity,
            frame,
        })
    }

    /// Commits a packet after the application has published its encrypted
    /// bytes.
    ///
    /// Commit relays the matching `MC_INTEGRITY` frame and retained STREAM
    /// range to every attached connection. A prepared packet must be
    /// retried until it is published and committed; preparing another
    /// packet first is rejected so the channel packet number space cannot
    /// develop a silent gap.
    pub fn commit(
        &self, publication: ServerStreamPublication,
    ) -> Result<(), ServerStreamPublisherError> {
        let mut inner = self.lock()?;

        if publication.publisher_id != inner.publisher_id ||
            inner.pending_token != Some(publication.token)
        {
            return Err(ServerStreamPublisherError::UnknownPublication);
        }

        inner.pending_token = None;
        let publication = Arc::new(CommittedServerStreamPublication {
            packet_number: publication.packet_number,
            integrity: publication.integrity,
            frame: publication.frame,
        });

        let commands_sent = inner
            .fanout(ServerStreamPublisherQueueItem::Publication(publication));
        #[cfg(test)]
        {
            inner.profile.publication_commands_sent = inner
                .profile
                .publication_commands_sent
                .saturating_add(commands_sent);
        }

        Ok(())
    }

    /// Rotates the multicast payload key and relays the new `MC_KEY` to every
    /// attached connection.
    pub fn update_key(
        &self, key: quiche::multicast::Key,
    ) -> Result<(), ServerStreamPublisherError> {
        let mut inner = self.lock()?;

        if inner.retired {
            return Err(ServerStreamPublisherError::Retired);
        }

        if inner.pending_token.is_some() {
            return Err(ServerStreamPublisherError::PublicationPending);
        }

        if key.from_packet_number != inner.send_state.next_packet_number() &&
            &key != inner.send_state.key()
        {
            return Err(ServerStreamPublisherError::InvalidState);
        }

        inner.send_state.update_key(key.clone())?;
        inner.channel.key = key.clone();
        inner.fanout(ServerStreamPublisherQueueItem::Key(key));

        Ok(())
    }

    /// Retires the channel and relays `MC_RETIRE` to every attached connection.
    pub fn retire(
        &self, frame: quiche::multicast::Retire,
    ) -> Result<(), ServerStreamPublisherError> {
        let mut inner = self.lock()?;

        if inner.retired {
            return Err(ServerStreamPublisherError::Retired);
        }

        if frame.channel_id != inner.channel.announce.channel_id ||
            (frame.after_packet_number != 0 &&
                frame.after_packet_number >=
                    inner.send_state.next_packet_number()) ||
            inner.pending_token.is_some()
        {
            return Err(ServerStreamPublisherError::InvalidState);
        }

        inner.retired = true;
        inner.fanout(ServerStreamPublisherQueueItem::Retire(frame));

        Ok(())
    }

    /// Returns the current channel send metrics.
    pub fn metrics_snapshot(
        &self,
    ) -> Result<
        quiche::multicast::ChannelSendMetricsSnapshot,
        ServerStreamPublisherError,
    > {
        Ok(self.lock()?.send_state.metrics_snapshot())
    }

    /// Returns cumulative ordinary-QUIC delivery metrics aggregated across
    /// every connection attached during this publisher's lifetime.
    ///
    /// These counters measure unique STREAM payload scheduled for direct
    /// fallback or recovery. They do not measure retransmissions, framing,
    /// encryption, control traffic, or socket egress. Collection is an O(1),
    /// allocation-free atomic snapshot.
    pub fn delivery_metrics_snapshot(
        &self,
    ) -> quiche::multicast::StreamDeliveryMetricsSnapshot {
        self.delivery_metrics.snapshot()
    }

    /// Returns the number of currently attached client connections.
    pub fn attached_connections(
        &self,
    ) -> Result<usize, ServerStreamPublisherError> {
        let mut inner = self.lock()?;
        inner
            .subscribers
            .retain(|_, subscriber| !subscriber.publication_queue.is_closed());
        Ok(inner.subscribers.len())
    }

    #[cfg(test)]
    pub(super) fn test_profile(
        &self,
    ) -> Result<ServerStreamPublisherTestProfile, ServerStreamPublisherError>
    {
        let inner = self.lock()?;
        let mut profile = inner.profile;
        profile.tracked_streams = inner.streams.len();
        profile.finished_streams = inner
            .streams
            .values()
            .filter(|stream| stream.finished)
            .count();
        profile.attached_connections = inner.subscribers.len();

        Ok(profile)
    }

    fn lock(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, ServerStreamPublisherInner>,
        ServerStreamPublisherError,
    > {
        self.inner
            .lock()
            .map_err(|_| ServerStreamPublisherError::StatePoisoned)
    }
}

/// Guard representing one connection attached to a shared stream publisher.
///
/// Dropping the guard stops future publications from being fanned out to that
/// connection. Already committed ranges remain owned by the connection until
/// they are acknowledged, recovered, reset, or torn down.
#[must_use = "dropping the attachment immediately detaches the connection"]
pub struct ServerStreamAttachment {
    publisher: Weak<Mutex<ServerStreamPublisherInner>>,
    subscriber_id: u64,
    command_sender: UnboundedSender<ServerControlCommand>,
    publication_queue: Arc<ServerStreamPublisherQueue>,
}

impl Drop for ServerStreamAttachment {
    fn drop(&mut self) {
        self.publication_queue.close();

        if let Some(publisher) = self.publisher.upgrade() {
            if let Ok(mut inner) = publisher.lock() {
                inner.subscribers.remove(&self.subscriber_id);
            };
        }

        let _ = self.command_sender.send(
            ServerControlCommand::DetachStreamPublisher {
                publication_queue: Arc::clone(&self.publication_queue),
            },
        );
    }
}

#[derive(Clone, Copy, Debug)]
struct PublisherStreamState {
    next_offset: u64,
    finished: bool,
}

struct ServerStreamPublisherInner {
    publisher_id: u64,
    channel: ServerControlChannelConfig,
    send_state: quiche::multicast::ChannelSendState,
    streams: BTreeMap<u64, PublisherStreamState>,
    subscribers: BTreeMap<u64, PublisherSubscriber>,
    next_subscriber_id: u64,
    pending_token: Option<u64>,
    max_stream_id: Option<u64>,
    reordering_threshold: u64,
    retired: bool,
    #[cfg(test)]
    profile: ServerStreamPublisherTestProfile,
}

impl ServerStreamPublisherInner {
    fn fanout(&mut self, item: ServerStreamPublisherQueueItem) -> u64 {
        let mut notifications_sent = 0_u64;

        self.subscribers.retain(|_, subscriber| {
            match subscriber.publication_queue.push(item.clone()) {
                QueuePushResult::AlreadyDirty => true,

                QueuePushResult::Notify => {
                    let sent = subscriber
                        .command_sender
                        .send(ServerControlCommand::StreamPublisherQueueReady {
                            publication_queue: Arc::clone(
                                &subscriber.publication_queue,
                            ),
                        })
                        .is_ok();
                    if sent {
                        notifications_sent = notifications_sent.saturating_add(1);
                    } else {
                        subscriber.publication_queue.close();
                    }
                    sent
                },

                QueuePushResult::Closed => false,
            }
        });

        notifications_sent
    }
}

struct PublisherSubscriber {
    command_sender: UnboundedSender<ServerControlCommand>,
    publication_queue: Arc<ServerStreamPublisherQueue>,
}

#[derive(Clone, Debug)]
pub(super) enum ServerStreamPublisherQueueItem {
    Publication(Arc<CommittedServerStreamPublication>),
    Key(quiche::multicast::Key),
    MaxStreamId(u64),
    Retire(quiche::multicast::Retire),
}

#[derive(Debug)]
pub(super) struct ServerStreamPublisherQueue {
    channel_id: Vec<u8>,
    state: Mutex<ServerStreamPublisherQueueState>,
}

impl ServerStreamPublisherQueue {
    fn new(channel_id: Vec<u8>) -> Self {
        Self {
            channel_id,
            state: Mutex::new(ServerStreamPublisherQueueState::default()),
        }
    }

    pub(super) fn channel_id(&self) -> &[u8] {
        &self.channel_id
    }

    fn push(&self, item: ServerStreamPublisherQueueItem) -> QueuePushResult {
        let Ok(mut state) = self.state.lock() else {
            return QueuePushResult::Closed;
        };
        if state.closed {
            return QueuePushResult::Closed;
        }

        state.items.push_back(item);
        if state.dirty {
            QueuePushResult::AlreadyDirty
        } else {
            state.dirty = true;
            QueuePushResult::Notify
        }
    }

    pub(super) fn drain(&self) -> VecDeque<ServerStreamPublisherQueueItem> {
        let Ok(mut state) = self.state.lock() else {
            return VecDeque::new();
        };
        if state.closed {
            return VecDeque::new();
        }

        state.dirty = false;
        std::mem::take(&mut state.items)
    }

    pub(super) fn close(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.items.clear();
        state.dirty = false;
        state.closed = true;
    }

    fn is_closed(&self) -> bool {
        self.state.lock().map_or(true, |state| state.closed)
    }
}

#[derive(Debug, Default)]
struct ServerStreamPublisherQueueState {
    items: VecDeque<ServerStreamPublisherQueueItem>,
    dirty: bool,
    closed: bool,
}

enum QueuePushResult {
    AlreadyDirty,
    Notify,
    Closed,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ServerStreamPublisherTestProfile {
    pub(super) preparation_capacity_bytes: u64,
    pub(super) publication_commands_sent: u64,
    pub(super) tracked_streams: usize,
    pub(super) finished_streams: usize,
    pub(super) attached_connections: usize,
}

#[derive(Debug, Default)]
pub(super) struct ServerStreamDeliveryMetricsAccumulator {
    direct_fallback_ranges_total: AtomicU64,
    direct_fallback_bytes_total: AtomicU64,
    ack_gap_recovery_ranges_total: AtomicU64,
    ack_gap_recovery_bytes_total: AtomicU64,
    fallback_reentry_ranges_total: AtomicU64,
    fallback_reentry_bytes_total: AtomicU64,
}

impl ServerStreamDeliveryMetricsAccumulator {
    pub(super) fn add(
        &self, delta: quiche::multicast::StreamDeliveryMetricsDelta,
    ) {
        atomic_saturating_add(
            &self.direct_fallback_ranges_total,
            delta.direct_fallback_ranges_total,
        );
        atomic_saturating_add(
            &self.direct_fallback_bytes_total,
            delta.direct_fallback_bytes_total,
        );
        atomic_saturating_add(
            &self.ack_gap_recovery_ranges_total,
            delta.ack_gap_recovery_ranges_total,
        );
        atomic_saturating_add(
            &self.ack_gap_recovery_bytes_total,
            delta.ack_gap_recovery_bytes_total,
        );
        atomic_saturating_add(
            &self.fallback_reentry_ranges_total,
            delta.fallback_reentry_ranges_total,
        );
        atomic_saturating_add(
            &self.fallback_reentry_bytes_total,
            delta.fallback_reentry_bytes_total,
        );
    }

    fn snapshot(&self) -> quiche::multicast::StreamDeliveryMetricsSnapshot {
        quiche::multicast::StreamDeliveryMetricsSnapshot {
            direct_fallback_ranges_total: self
                .direct_fallback_ranges_total
                .load(Ordering::Relaxed),
            direct_fallback_bytes_total: self
                .direct_fallback_bytes_total
                .load(Ordering::Relaxed),
            ack_gap_recovery_ranges_total: self
                .ack_gap_recovery_ranges_total
                .load(Ordering::Relaxed),
            ack_gap_recovery_bytes_total: self
                .ack_gap_recovery_bytes_total
                .load(Ordering::Relaxed),
            fallback_reentry_ranges_total: self
                .fallback_reentry_ranges_total
                .load(Ordering::Relaxed),
            fallback_reentry_bytes_total: self
                .fallback_reentry_bytes_total
                .load(Ordering::Relaxed),
        }
    }
}

fn atomic_saturating_add(counter: &AtomicU64, value: u64) {
    if value == 0 {
        return;
    }

    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(value))
        })
        .expect("saturating update always returns a value");
}

#[derive(Debug)]
pub(super) struct CommittedServerStreamPublication {
    pub(super) packet_number: u64,
    pub(super) integrity: quiche::multicast::Integrity,
    pub(super) frame: ServerStreamFrame,
}
