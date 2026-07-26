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

mod server_stream;

pub use server_stream::ServerStreamAttachment;
pub use server_stream::ServerStreamFrame;
pub use server_stream::ServerStreamPublication;
pub use server_stream::ServerStreamPublisher;
pub use server_stream::ServerStreamPublisherError;

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::future::pending;
use std::net::IpAddr;
use std::net::Ipv4Addr;
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
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep_until;
use tokio::time::Instant;
use tokio_util::task::AbortOnDropHandle;

use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

pub use crate::settings::MulticastClientSettings as ClientSettings;

const STATE_REASON_UNSPECIFIED_OTHER: u64 = 0x0;
const STATE_REASON_UNSYNCHRONIZED_PROPERTIES: u64 = 0x5;
const SERVER_ACK_FRESHNESS_TIMEOUT_MULTIPLIER: u64 = 4;
const PUBLISH_RETRY_DELAY: Duration = Duration::from_millis(10);
const CHANNEL_PACKET_BUFFER_LEN: usize = 64 * 1024;

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
}

/// Event receiver for [`ClientDriver`].
pub type ClientEventStream = UnboundedReceiver<ClientEvent>;

/// Handle for consuming multicast events produced by [`ClientDriver`].
pub struct ClientController {
    event_receiver: ClientEventStream,
}

impl ClientController {
    /// Returns the underlying multicast event receiver.
    pub fn event_receiver_mut(&mut self) -> &mut ClientEventStream {
        &mut self.event_receiver
    }

    /// Consumes the controller and returns its event receiver.
    pub fn take_event_receiver(&mut self) -> ClientEventStream {
        std::mem::replace(&mut self.event_receiver, mpsc::unbounded_channel().1)
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
    pub fn new(inner: A, settings: ClientSettings) -> (Self, ClientController) {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        (
            Self {
                inner,
                runtime: ClientRuntime::new(settings, event_sender),
            },
            ClientController { event_receiver },
        )
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
        if self.runtime.has_pending_ingress() {
            return Ok(());
        }

        if self.inner.should_act() {
            select! {
                res = self.inner.wait_for_data(qconn) => res,
                res = self.runtime.wait_for_ingress() => res,
            }
        } else {
            self.runtime.wait_for_ingress().await
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
        self.runtime.process_ingress(qconn)?;
        self.runtime.flush_pending_acks(qconn)?;

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
        self.inner.on_conn_close(qconn, metrics, connection_result);
    }
}

#[derive(Debug, thiserror::Error)]
enum ClientError {
    #[error("multicast client wrapper only supports client connections")]
    ServerConnectionUnsupported,
}

struct ClientRuntime<B: JoinBackend> {
    settings: ClientSettings,
    event_sender: UnboundedSender<ClientEvent>,
    // Subscription tasks run outside the QUIC driver's immediate poll point,
    // so they hand off validated socket ingress through this channel. The
    // queue is drained on each driver tick and bounded in practice by the
    // number and lifetime of joined channels.
    ingress_sender: UnboundedSender<IngressEvent>,
    ingress_receiver: UnboundedReceiver<IngressEvent>,
    pending_ingress: VecDeque<IngressEvent>,
    channels: BTreeMap<Vec<u8>, Channel<B::Handle>>,
    next_limits_sequence: u64,
    backend: B,
}

impl ClientRuntime<McrxJoinBackend> {
    fn new(
        settings: ClientSettings, event_sender: UnboundedSender<ClientEvent>,
    ) -> Self {
        Self::with_backend(settings, event_sender, McrxJoinBackend)
    }
}

impl<B: JoinBackend> ClientRuntime<B> {
    fn with_backend(
        settings: ClientSettings, event_sender: UnboundedSender<ClientEvent>,
        backend: B,
    ) -> Self {
        let (ingress_sender, ingress_receiver) = mpsc::unbounded_channel();

        Self {
            settings,
            event_sender,
            ingress_sender,
            ingress_receiver,
            pending_ingress: VecDeque::new(),
            channels: BTreeMap::new(),
            next_limits_sequence: 0,
            backend,
        }
    }

    fn clear(&mut self) {
        self.channels.clear();
        self.pending_ingress.clear();

        while self.ingress_receiver.try_recv().is_ok() {}
    }

    fn has_pending_ingress(&self) -> bool {
        !self.pending_ingress.is_empty()
    }

    async fn wait_for_ingress(&mut self) -> QuicResult<()> {
        match self.ingress_receiver.recv().await {
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
        loop {
            let mut progressed = self.process_ingress(qconn)?;

            loop {
                match qconn.multicast_recv() {
                    Ok(frame) => {
                        progressed = true;
                        self.handle_frame(qconn, frame)?;
                    },

                    Err(quiche::Error::Done) => break,

                    Err(err) => return Err(err.into()),
                }
            }

            if !progressed {
                return Ok(());
            }
        }
    }

    fn process_ingress(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        while let Ok(event) = self.ingress_receiver.try_recv() {
            self.pending_ingress.push_back(event);
        }

        let mut progressed = false;

        while let Some(event) = self.pending_ingress.pop_front() {
            progressed = true;

            match event {
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
                } => {
                    self.channels
                        .entry(channel_id.clone())
                        .or_default()
                        .last_subscription_metrics = Some(socket_metrics);
                    self.emit_channel_metrics(&channel_id);
                    let _ = self
                        .event_sender
                        .send(ClientEvent::ReceiveError { channel_id, error });
                },
            }
        }

        Ok(progressed)
    }

    fn handle_ingress_packet(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
        socket_metrics: SubscriptionMetricsSnapshot, packet: PacketWithMetadata,
    ) -> QuicResult<()> {
        {
            let channel = self.channels.entry(channel_id.clone()).or_default();
            channel.last_subscription_metrics = Some(socket_metrics);

            Self::ensure_channel_decoder(channel);
        }

        let Some(receiver) = self
            .channels
            .get_mut(&channel_id)
            .and_then(|channel| channel.receive_state.as_mut())
        else {
            let _ = self.event_sender.send(ClientEvent::DecodeError {
                channel_id: channel_id.clone(),
                error: quiche::Error::InvalidState,
                packet,
            });
            self.emit_channel_metrics(&channel_id);
            return Ok(());
        };

        let payload = packet.packet.payload().to_vec();
        let events = receiver.recv(&payload, packet)?;

        for event in events {
            self.handle_channel_receive_event(qconn, channel_id.clone(), event)?;
        }

        self.emit_channel_metrics(&channel_id);

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
                let _ = self.event_sender.send(ClientEvent::DecodeError {
                    channel_id,
                    error,
                    packet: metadata,
                });

                Ok(())
            },
        }
    }

    fn handle_channel_packet(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
        packet: quiche::multicast::ChannelPacket, received: PacketWithMetadata,
    ) -> QuicResult<()> {
        self.channels
            .entry(channel_id.clone())
            .or_default()
            .ack_state
            .record_packet(packet.packet_number);

        for frame in &packet.frames {
            if let quiche::multicast::ChannelFrame::Multicast(frame) = frame {
                self.handle_frame(qconn, frame.clone())?;
            }
        }

        qconn.multicast_process_channel_packet(packet.clone())?;

        let _ = self.event_sender.send(ClientEvent::Packet {
            channel_id,
            packet,
            received,
        });

        Ok(())
    }

    fn handle_frame(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Frame,
    ) -> QuicResult<()> {
        match frame {
            quiche::multicast::Frame::Announce(frame) => {
                self.handle_announce(frame);
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

    fn handle_announce(&mut self, frame: quiche::multicast::Announce) {
        let channel_id = frame.channel_id.clone();
        let event = match (&frame.source, &frame.group) {
            (IpAddr::V4(..), IpAddr::V4(..)) =>
                ClientEvent::Announce(frame.clone()),

            (IpAddr::V6(..), IpAddr::V6(..)) =>
                ClientEvent::UnsupportedIpv6Announce(frame.clone()),

            _ => ClientEvent::UnsupportedIpv6Announce(frame.clone()),
        };

        let channel = self.channels.entry(channel_id).or_default();
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

        let _ = self.event_sender.send(event);
    }

    fn handle_key(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Key,
    ) -> QuicResult<()> {
        let channel_id = frame.channel_id.clone();
        let events = {
            let channel = self.channels.entry(channel_id.clone()).or_default();
            channel.key = Some(frame.clone());

            Self::ensure_channel_decoder(channel);

            match channel.receive_state.as_mut() {
                Some(receiver) => receiver.insert_key(frame)?,
                None => Vec::new(),
            }
        };

        for event in events {
            self.handle_channel_receive_event(qconn, channel_id.clone(), event)?;
        }

        self.emit_channel_metrics(&channel_id);

        Ok(())
    }

    fn handle_integrity(
        &mut self, qconn: &mut QuicheConnection,
        frame: quiche::multicast::Integrity,
    ) -> QuicResult<()> {
        let channel_id = frame.channel_id.clone();
        let events = {
            let channel = self.channels.entry(channel_id.clone()).or_default();

            Self::ensure_channel_decoder(channel);

            match channel.receive_state.as_mut() {
                Some(receiver) => receiver.insert_integrity(frame)?,
                None => Vec::new(),
            }
        };

        for event in events {
            self.handle_channel_receive_event(qconn, channel_id.clone(), event)?;
        }

        self.emit_channel_metrics(&channel_id);

        Ok(())
    }

    fn handle_join(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Join,
    ) -> QuicResult<()> {
        let channel_id = frame.channel_id.clone();
        let is_new_channel = !self.channels.contains_key(&channel_id);

        if is_new_channel &&
            self.channels.len() >=
                self.settings.transport_params.limits.max_channel_ids
                    as usize
        {
            return self.decline_join(
                qconn,
                channel_id,
                b"max channel ids exceeded".to_vec(),
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

        self.channels
            .entry(channel_id.clone())
            .or_default()
            .receive_handle = Some(receive_handle);

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
        let joined = self
            .channels
            .get_mut(&frame.channel_id)
            .and_then(|channel| channel.receive_handle.take())
            .is_some();

        if !joined {
            return Ok(());
        }

        self.send_state(
            qconn,
            frame.channel_id,
            quiche::multicast::ChannelState::Left,
            quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            Vec::new(),
        )
    }

    fn handle_retire(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Retire,
    ) -> QuicResult<()> {
        let Some(channel) = self.channels.get_mut(&frame.channel_id) else {
            return Ok(());
        };

        channel.receive_handle.take();

        self.send_state(
            qconn,
            frame.channel_id,
            quiche::multicast::ChannelState::Retired,
            quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            Vec::new(),
        )
    }

    fn send_limits(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.next_limits_sequence += 1;

        qconn.multicast_send(quiche::multicast::Frame::Limits(
            quiche::multicast::Limits {
                sequence: self.next_limits_sequence,
                limits: self.settings.transport_params.limits.clone(),
                max_joined_count: self.settings.max_joined_channels,
            },
        ))?;

        Ok(())
    }

    fn send_state(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
        state: quiche::multicast::ChannelState, reason_code: u64,
        reason_phrase: Vec<u8>,
    ) -> QuicResult<()> {
        let sequence = {
            let channel = self.channels.entry(channel_id.clone()).or_default();
            channel.next_state_sequence += 1;
            channel.next_state_sequence
        };

        let frame = quiche::multicast::State {
            channel_id,
            sequence,
            state,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code,
            reason_phrase,
        };

        qconn.multicast_send(quiche::multicast::Frame::State(frame.clone()))?;
        qconn.multicast_process_local_state(frame.clone())?;

        let _ = self.event_sender.send(ClientEvent::LocalState(frame));

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

    fn flush_pending_acks(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        let pending = self
            .channels
            .iter()
            .filter_map(|(channel_id, channel)| {
                channel
                    .ack_state
                    .pending_ack(channel_id)
                    .map(|frame| (channel_id.clone(), frame))
            })
            .collect::<Vec<_>>();

        for (channel_id, frame) in pending {
            match qconn.multicast_send(quiche::multicast::Frame::Ack(frame)) {
                Ok(()) => (),

                Err(quiche::Error::Done) => break,

                Err(err) => return Err(err.into()),
            }

            if let Some(channel) = self.channels.get_mut(&channel_id) {
                channel.ack_state.mark_sent();
            }
        }

        Ok(())
    }

    fn emit_channel_metrics(&self, channel_id: &[u8]) {
        let Some(channel) = self.channels.get(channel_id) else {
            return;
        };
        let Some(receive_state) = channel.receive_state.as_ref() else {
            return;
        };
        let Some(socket) = channel.last_subscription_metrics.clone() else {
            return;
        };

        let _ = self.event_sender.send(ClientEvent::MetricsUpdated {
            channel_id: channel_id.to_vec(),
            metrics: ClientChannelMetricsSnapshot {
                socket,
                receive: receive_state.metrics_snapshot(),
            },
        });
    }

    fn ensure_channel_decoder(channel: &mut Channel<B::Handle>) {
        if channel.receive_state.is_some() || channel.decoder_error.is_some() {
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
            match receiver.insert_key(key) {
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
            receive_handle: None,
        }
    }
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
}

trait JoinBackend {
    type Handle;

    fn join_ipv4(
        &mut self, channel_id: &[u8], source: Ipv4Addr, group: Ipv4Addr,
        udp_port: u16, interface: Option<Ipv4Addr>,
        ingress_sender: UnboundedSender<IngressEvent>,
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
        ingress_sender: UnboundedSender<IngressEvent>,
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
                        let _ = ingress_sender.send(IngressEvent::Packet {
                            channel_id: channel_id.clone(),
                            socket_metrics,
                            packet,
                        });
                    },

                    Err(error) => {
                        let socket_metrics =
                            subscription.subscription().metrics_snapshot();
                        let _ = ingress_sender.send(IngressEvent::ReceiveError {
                            channel_id: channel_id.clone(),
                            socket_metrics,
                            error,
                        });
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerControlChannelConfig {
    /// The announced multicast channel properties.
    pub announce: quiche::multicast::Announce,

    /// The active multicast payload-protection key for the channel.
    pub key: quiche::multicast::Key,
}

impl ServerControlChannelConfig {
    fn validate(&self) -> QuicResult<()> {
        if self.announce.channel_id != self.key.channel_id {
            return Err(Box::new(quiche::Error::InvalidState));
        }

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
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl ServerChannelConfig {
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

/// Event receiver for [`ServerDriver`].
pub type ServerEventStream = UnboundedReceiver<ServerEvent>;

#[derive(Default)]
struct ServerEventCoalescer {
    pending_client_acks: BTreeMap<Vec<u8>, quiche::multicast::Ack>,
    last_client_ack_largest: BTreeMap<Vec<u8>, u64>,
    last_probe_events: BTreeMap<Vec<u8>, quiche::multicast::ProbeEvent>,
}

impl ServerEventCoalescer {
    fn queue_client_ack(&mut self, frame: quiche::multicast::Ack) {
        if self
            .last_client_ack_largest
            .get(&frame.channel_id)
            .is_some_and(|largest| frame.largest_acknowledged <= *largest)
        {
            return;
        }

        match self.pending_client_acks.entry(frame.channel_id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(frame);
            },

            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if frame.largest_acknowledged > entry.get().largest_acknowledged {
                    entry.insert(frame);
                }
            },
        }
    }

    fn flush_client_acks(&mut self, event_sender: &UnboundedSender<ServerEvent>) {
        for (channel_id, frame) in std::mem::take(&mut self.pending_client_acks) {
            self.last_client_ack_largest
                .insert(channel_id, frame.largest_acknowledged);
            let _ = event_sender.send(ServerEvent::ClientAck(frame));
        }
    }

    fn forward_probe_event(
        &mut self, event_sender: &UnboundedSender<ServerEvent>,
        event: quiche::multicast::ProbeEvent,
    ) {
        if self
            .last_probe_events
            .get(&event.channel_id)
            .is_some_and(|previous| previous == &event)
        {
            return;
        }

        self.last_probe_events
            .insert(event.channel_id.clone(), event.clone());
        let _ = event_sender.send(ServerEvent::ProbeStatusChanged(event));
    }

    fn clear(&mut self) {
        self.pending_client_acks.clear();
        self.last_client_ack_largest.clear();
        self.last_probe_events.clear();
    }
}

/// Handle for consuming multicast control events and relaying integrity from
/// an external multicast sender.
pub struct ServerControlController {
    command_sender: UnboundedSender<ServerControlCommand>,
    event_receiver: ServerEventStream,
}

impl ServerControlController {
    /// Stores or updates one channel definition.
    ///
    /// In automatic mode this also sends `MC_ANNOUNCE` and `MC_KEY`
    /// immediately once the client connection is ready, and it will emit
    /// `MC_JOIN` automatically if the peer has already sent `MC_LIMITS`.
    pub fn upsert_channel(
        &self, config: ServerControlChannelConfig,
    ) -> Result<(), mpsc::error::SendError<()>> {
        self.command_sender
            .send(ServerControlCommand::UpsertChannel { config })
            .map_err(|_| mpsc::error::SendError(()))
    }

    /// Queues one `MC_ANNOUNCE` frame for explicit transmission.
    pub fn send_announce(
        &self, frame: quiche::multicast::Announce,
    ) -> Result<(), mpsc::error::SendError<()>> {
        self.command_sender
            .send(ServerControlCommand::SendAnnounce { frame })
            .map_err(|_| mpsc::error::SendError(()))
    }

    /// Queues one `MC_KEY` frame for explicit transmission.
    pub fn send_key(
        &self, frame: quiche::multicast::Key,
    ) -> Result<(), mpsc::error::SendError<()>> {
        self.command_sender
            .send(ServerControlCommand::SendKey { frame })
            .map_err(|_| mpsc::error::SendError(()))
    }

    /// Queues one explicit `MC_JOIN` frame.
    pub fn send_join(
        &self, frame: quiche::multicast::Join,
    ) -> Result<(), mpsc::error::SendError<()>> {
        self.command_sender
            .send(ServerControlCommand::SendJoin { frame })
            .map_err(|_| mpsc::error::SendError(()))
    }

    /// Queues one externally generated `MC_INTEGRITY` frame for relay on the
    /// client-facing QUIC control connection.
    pub fn send_integrity(
        &self, frame: quiche::multicast::Integrity,
    ) -> Result<(), mpsc::error::SendError<()>> {
        self.command_sender
            .send(ServerControlCommand::RelayIntegrity { frame })
            .map_err(|_| mpsc::error::SendError(()))
    }

    /// Returns the underlying multicast event receiver.
    pub fn event_receiver_mut(&mut self) -> &mut ServerEventStream {
        &mut self.event_receiver
    }

    /// Consumes the controller and returns its event receiver.
    pub fn take_event_receiver(&mut self) -> ServerEventStream {
        std::mem::replace(&mut self.event_receiver, mpsc::unbounded_channel().1)
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
    ) -> (Self, ServerControlController) {
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        (
            Self {
                inner,
                runtime: ServerControlRuntime::new(
                    settings,
                    event_sender,
                    command_receiver,
                ),
            },
            ServerControlController {
                command_sender,
                event_receiver,
            },
        )
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
    command_sender: UnboundedSender<ServerCommand>,
    event_receiver: ServerEventStream,
}

impl ServerController {
    /// Queues one multicast packet for the given channel.
    pub fn send_on_channel(
        &self, channel_id: Vec<u8>, frames: Vec<quiche::multicast::ChannelFrame>,
    ) -> Result<(), mpsc::error::SendError<()>> {
        self.command_sender
            .send(ServerCommand::Send { channel_id, frames })
            .map_err(|_| mpsc::error::SendError(()))
    }

    /// Queues one externally generated `MC_INTEGRITY` frame for relay on the
    /// client-facing QUIC control connection.
    pub fn send_integrity(
        &self, frame: quiche::multicast::Integrity,
    ) -> Result<(), mpsc::error::SendError<()>> {
        self.command_sender
            .send(ServerCommand::RelayIntegrity { frame })
            .map_err(|_| mpsc::error::SendError(()))
    }

    /// Returns the underlying multicast event receiver.
    pub fn event_receiver_mut(&mut self) -> &mut ServerEventStream {
        &mut self.event_receiver
    }

    /// Consumes the controller and returns its event receiver.
    pub fn take_event_receiver(&mut self) -> ServerEventStream {
        std::mem::replace(&mut self.event_receiver, mpsc::unbounded_channel().1)
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
    pub fn new(inner: A, settings: ServerSettings) -> (Self, ServerController) {
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        (
            Self {
                inner,
                runtime: ServerRuntime::new(
                    settings,
                    event_sender,
                    command_receiver,
                ),
            },
            ServerController {
                command_sender,
                event_receiver,
            },
        )
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
        self.inner.on_conn_close(qconn, metrics, connection_result);
    }
}

#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error("multicast server wrapper only supports server connections")]
    ClientConnectionUnsupported,

    #[error("multicast publication failed: {0}")]
    Publication(#[from] MctxError),
}

#[derive(Debug)]
enum ServerControlCommand {
    UpsertChannel {
        config: ServerControlChannelConfig,
    },
    SendAnnounce {
        frame: quiche::multicast::Announce,
    },
    SendKey {
        frame: quiche::multicast::Key,
    },
    SendJoin {
        frame: quiche::multicast::Join,
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
    },
    StreamPublisherMaxStreamId {
        channel_id: Vec<u8>,
        max_stream_id: u64,
    },
    StreamPublisherRetire {
        frame: quiche::multicast::Retire,
    },
}

#[derive(Default)]
struct ServerControlChannel {
    announce: Option<quiche::multicast::Announce>,
    key: Option<quiche::multicast::Key>,
    announce_sent: bool,
    join_sent: bool,
    join_blocked_by_client: bool,
    stream_publisher: bool,
    max_stream_id: Option<u64>,
    largest_stream_packet_number: Option<u64>,
    stream_delivery_metrics: Option<ConnectionStreamDeliveryMetrics>,
    stream_publication_queue:
        Option<Arc<server_stream::ServerStreamPublisherQueue>>,
    last_client_state_sequence: u64,
    retired: bool,
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

struct ServerControlRuntime {
    settings: ServerControlSettings,
    event_sender: UnboundedSender<ServerEvent>,
    command_receiver: UnboundedReceiver<ServerControlCommand>,
    pending_commands: VecDeque<ServerControlCommand>,
    pending_stream_publications:
        VecDeque<Arc<server_stream::CommittedServerStreamPublication>>,
    stream_retry_blocked: bool,
    pending_integrities: VecDeque<quiche::multicast::Integrity>,
    pending_stream_integrity_batches:
        BTreeMap<Vec<u8>, PendingStreamIntegrityBatch>,
    channels: BTreeMap<Vec<u8>, ServerControlChannel>,
    last_client_limits: Option<quiche::multicast::Limits>,
    event_coalescer: ServerEventCoalescer,
    #[cfg(test)]
    stream_delivery_metric_fold_attempts: u64,
}

impl ServerControlRuntime {
    fn new(
        settings: ServerControlSettings,
        event_sender: UnboundedSender<ServerEvent>,
        command_receiver: UnboundedReceiver<ServerControlCommand>,
    ) -> Self {
        Self {
            settings,
            event_sender,
            command_receiver,
            pending_commands: VecDeque::new(),
            pending_stream_publications: VecDeque::new(),
            stream_retry_blocked: false,
            pending_integrities: VecDeque::new(),
            pending_stream_integrity_batches: BTreeMap::new(),
            channels: BTreeMap::new(),
            last_client_limits: None,
            event_coalescer: ServerEventCoalescer::default(),
            #[cfg(test)]
            stream_delivery_metric_fold_attempts: 0,
        }
    }

    fn clear(&mut self) {
        for channel in self.channels.values_mut() {
            if let Some(queue) = channel.stream_publication_queue.take() {
                queue.close();
            }
        }
        self.pending_commands.clear();
        self.pending_stream_publications.clear();
        self.stream_retry_blocked = false;
        self.pending_integrities.clear();
        self.pending_stream_integrity_batches.clear();
        self.channels.clear();
        self.last_client_limits = None;
        self.event_coalescer.clear();

        while self.command_receiver.try_recv().is_ok() {}
    }

    fn on_conn_close(&mut self, qconn: &QuicheConnection) {
        self.fold_all_stream_delivery_metrics(qconn);
        self.clear();
    }

    fn has_pending_work(&self) -> bool {
        let unblocked_stream_work = (!self.pending_commands.is_empty() ||
            !self.pending_stream_publications.is_empty()) &&
            !self.stream_retry_blocked;
        let integrity_deadline_elapsed = self
            .next_stream_integrity_deadline()
            .is_some_and(|deadline| deadline <= Instant::now());

        unblocked_stream_work ||
            !self.pending_integrities.is_empty() ||
            integrity_deadline_elapsed
    }

    async fn wait_for_work(&mut self) -> QuicResult<()> {
        if let Some(deadline) = self.next_stream_integrity_deadline() {
            select! {
                command = self.command_receiver.recv() => {
                    match command {
                        Some(command) => {
                            self.pending_commands.push_back(command);
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

        self.initialize_channels(qconn)?;

        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let result: QuicResult<()> = loop {
            match qconn.multicast_recv() {
                Ok(frame) =>
                    if let Err(error) = self.handle_frame(qconn, frame) {
                        break Err(error);
                    },

                Err(quiche::Error::Done) => break Ok(()),

                Err(err) => break Err(err.into()),
            }
        };

        self.event_coalescer.flush_client_acks(&self.event_sender);
        result?;
        self.fold_all_stream_delivery_metrics(qconn);
        self.forward_probe_events(qconn)
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        // Connection timers run outside this wrapper. Fold first so timeout
        // fallback releases are retained before processing new commands.
        self.fold_all_stream_delivery_metrics(qconn);

        while let Ok(command) = self.command_receiver.try_recv() {
            self.pending_commands.push_back(command);
        }

        self.stream_retry_blocked = false;
        self.handle_pending_commands(qconn)?;
        if !self.stream_retry_blocked {
            self.flush_pending_stream_publications(qconn)?;
        }
        self.stage_due_stream_integrities(Instant::now());
        self.flush_pending_integrities(qconn)?;
        self.fold_all_stream_delivery_metrics(qconn);
        self.forward_probe_events(qconn)
    }

    fn fold_stream_delivery_metrics(
        &mut self, qconn: &QuicheConnection, channel_id: &[u8],
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

        let snapshot =
            qconn.multicast_stream_delivery_metrics_snapshot(channel_id);
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

    fn fold_all_stream_delivery_metrics(&mut self, qconn: &QuicheConnection) {
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

    fn forward_probe_events(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        loop {
            match qconn.multicast_probe_recv() {
                Ok(event) => {
                    self.event_coalescer
                        .forward_probe_event(&self.event_sender, event);
                },

                Err(quiche::Error::Done) => return Ok(()),

                Err(err) => return Err(err.into()),
            }
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
                let channel_id = frame.channel_id.clone();
                if let Some(channel) = self.channels.get_mut(&frame.channel_id) {
                    channel.last_client_state_sequence = frame.sequence;
                    match frame.state {
                        quiche::multicast::ChannelState::Joined => {
                            channel.join_blocked_by_client = false;
                        },

                        quiche::multicast::ChannelState::DeclinedJoin |
                        quiche::multicast::ChannelState::Left => {
                            channel.join_sent = false;
                            channel.join_blocked_by_client = true;
                        },

                        quiche::multicast::ChannelState::Retired => {
                            channel.announce_sent = false;
                            channel.join_sent = false;
                            channel.join_blocked_by_client = true;
                            channel.retired = true;
                        },
                    }
                }
                self.fold_stream_delivery_metrics(qconn, &channel_id);
                let _ = self.event_sender.send(ServerEvent::ClientState(frame));
            },

            quiche::multicast::Frame::Ack(frame) => {
                if self.channels.contains_key(&frame.channel_id) {
                    qconn.multicast_process_peer_ack(frame.clone())?;
                    self.fold_stream_delivery_metrics(qconn, &frame.channel_id);
                }
                self.event_coalescer.queue_client_ack(frame);
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
        let _ = self.event_sender.send(ServerEvent::ClientLimits(frame));

        if self.settings.mode != ServerControlMode::Automatic {
            return Ok(());
        }

        for channel in self.channels.values_mut() {
            if !channel.retired {
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
        &mut self, qconn: &mut QuicheConnection, channel_id: &[u8],
    ) -> QuicResult<()> {
        let Some(channel) = self.channels.get_mut(channel_id) else {
            return Ok(());
        };
        channel.announce_sent = false;
        channel.join_sent = false;
        channel.join_blocked_by_client = true;
        channel.retired = true;
        let after_packet_number =
            channel.largest_stream_packet_number.unwrap_or(0);

        qconn.multicast_process_local_state(quiche::multicast::State {
            channel_id: channel_id.to_vec(),
            sequence: channel.last_client_state_sequence,
            state: quiche::multicast::ChannelState::Retired,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: Vec::new(),
        })?;
        self.fold_stream_delivery_metrics(qconn, channel_id);
        qconn.multicast_send(quiche::multicast::Frame::Retire(
            quiche::multicast::Retire {
                channel_id: channel_id.to_vec(),
                after_packet_number,
            },
        ))?;

        Ok(())
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
            .filter(|(_, channel)| channel.join_sent)
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
        while let Some(command) = self.pending_commands.pop_front() {
            match command {
                ServerControlCommand::UpsertChannel { config } => {
                    let auto_send = self.settings.mode ==
                        ServerControlMode::Automatic &&
                        self.peer_supports_multicast(qconn);
                    self.upsert_channel_config(qconn, config, auto_send, true)?;
                },

                ServerControlCommand::SendAnnounce { frame } => {
                    Self::set_default_dgram_channel_if_unset(
                        qconn,
                        &frame.channel_id,
                    )?;
                    Self::set_ack_timeout(
                        qconn,
                        &frame.channel_id,
                        frame.max_ack_delay_ms,
                    )?;
                    let channel = self
                        .channels
                        .entry(frame.channel_id.clone())
                        .or_default();
                    channel.announce = Some(frame.clone());
                    channel.announce_sent = true;
                    channel.join_sent = false;
                    qconn.multicast_send(quiche::multicast::Frame::Announce(
                        frame,
                    ))?;
                },

                ServerControlCommand::SendKey { frame } => {
                    Self::set_default_dgram_channel_if_unset(
                        qconn,
                        &frame.channel_id,
                    )?;
                    let channel = self
                        .channels
                        .entry(frame.channel_id.clone())
                        .or_default();
                    channel.key = Some(frame.clone());
                    qconn.multicast_send(quiche::multicast::Frame::Key(frame))?;
                },

                ServerControlCommand::SendJoin { frame } => {
                    Self::set_default_dgram_channel_if_unset(
                        qconn,
                        &frame.channel_id,
                    )?;
                    let channel = self
                        .channels
                        .entry(frame.channel_id.clone())
                        .or_default();
                    channel.join_sent = true;
                    channel.join_blocked_by_client = false;
                    qconn
                        .multicast_send(quiche::multicast::Frame::Join(frame))?;
                },

                ServerControlCommand::RelayIntegrity { frame } => {
                    self.pending_integrities.push_back(frame);
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

                    let mut items = publication_queue.drain();
                    while let Some(item) = items.pop_back() {
                        let command = match item {
                            server_stream::ServerStreamPublisherQueueItem::Publication(
                                publication,
                            ) => ServerControlCommand::StreamPublication {
                                publication,
                            },

                            server_stream::ServerStreamPublisherQueueItem::Key(
                                frame,
                            ) => ServerControlCommand::StreamPublisherKey {
                                frame,
                            },

                            server_stream::ServerStreamPublisherQueueItem::MaxStreamId(
                                max_stream_id,
                            ) => ServerControlCommand::StreamPublisherMaxStreamId {
                                channel_id: channel_id.to_vec(),
                                max_stream_id,
                            },

                            server_stream::ServerStreamPublisherQueueItem::Retire(
                                frame,
                            ) => ServerControlCommand::StreamPublisherRetire {
                                frame,
                            },
                        };
                        self.pending_commands.push_front(command);
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

                    self.fold_stream_delivery_metrics(qconn, channel_id);
                    self.pending_stream_publications.retain(|publication| {
                        publication.integrity.channel_id != channel_id
                    });
                    if let Some(channel) = self.channels.get_mut(channel_id) {
                        channel.stream_publisher = false;
                        channel.stream_delivery_metrics = None;
                        channel.stream_publication_queue = None;
                    }
                    self.stream_retry_blocked = false;
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

                    self.pending_stream_publications.push_back(publication);

                    if self.settings.mode == ServerControlMode::Automatic {
                        self.maybe_auto_join_channel(qconn, &channel_id)?;
                    }
                },

                ServerControlCommand::StreamPublisherKey { frame } => {
                    let Some(channel) = self.channels.get_mut(&frame.channel_id)
                    else {
                        return Err(quiche::Error::InvalidState.into());
                    };
                    channel.key = Some(frame.clone());

                    if channel.announce_sent &&
                        !channel.retired &&
                        self.peer_supports_multicast(qconn)
                    {
                        qconn.multicast_send(quiche::multicast::Frame::Key(
                            frame,
                        ))?;
                    }
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
                    self.flush_pending_stream_publications(qconn)?;
                    if !self.pending_stream_publications.is_empty() {
                        self.pending_commands.push_front(
                            ServerControlCommand::StreamPublisherRetire { frame },
                        );
                        self.stream_retry_blocked = true;
                        return Ok(());
                    }
                    self.flush_stream_integrity_batch(&frame.channel_id);
                    self.flush_pending_integrities(qconn)?;

                    let Some(channel) = self.channels.get_mut(&frame.channel_id)
                    else {
                        return Err(quiche::Error::InvalidState.into());
                    };
                    channel.retired = true;
                    channel.announce_sent = false;
                    channel.join_sent = false;
                    channel.join_blocked_by_client = true;

                    qconn
                        .multicast_process_local_state(quiche::multicast::State {
                        channel_id: frame.channel_id.clone(),
                        sequence: 0,
                        state: quiche::multicast::ChannelState::Retired,
                        reason_scope:
                            quiche::multicast::StateReasonScope::Transport,
                        reason_code:
                            quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                        reason_phrase: Vec::new(),
                    })?;
                    self.fold_stream_delivery_metrics(qconn, &frame.channel_id);

                    if self.peer_supports_multicast(qconn) {
                        qconn.multicast_send(
                            quiche::multicast::Frame::Retire(frame),
                        )?;
                    }
                },
            }
        }

        Ok(())
    }

    fn upsert_channel_config(
        &mut self, qconn: &mut QuicheConnection,
        config: ServerControlChannelConfig, auto_send: bool,
        set_default_dgram_channel: bool,
    ) -> QuicResult<()> {
        config.validate()?;

        let channel_id = config.announce.channel_id.clone();
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
        channel.join_sent = false;
        channel.join_blocked_by_client = false;
        channel.retired = false;

        if !auto_send {
            return Ok(());
        }

        self.maybe_auto_announce_channel(qconn, &channel_id)?;
        self.maybe_auto_join_channel(qconn, &channel_id)
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
        if channel.announce_sent || channel.retired {
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

        let announce = announce.clone();
        let key = key.clone();
        qconn.multicast_send(quiche::multicast::Frame::Announce(announce))?;
        qconn.multicast_send(quiche::multicast::Frame::Key(key))?;
        self.channels
            .get_mut(channel_id)
            .expect("channel was checked above")
            .announce_sent = true;

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
            channel.join_blocked_by_client ||
            channel.retired
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

        qconn.multicast_send(quiche::multicast::Frame::Join(join))?;
        self.channels
            .get_mut(channel_id)
            .expect("channel was checked above")
            .join_sent = true;

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
        &mut self, qconn: &mut QuicheConnection, channel_id: &[u8],
        after_packet_number: u64,
    ) -> QuicResult<()> {
        let Some(channel) = self.channels.get_mut(channel_id) else {
            return Ok(());
        };
        if !channel.join_sent {
            return Ok(());
        }

        let state_sequence = channel.last_client_state_sequence;
        channel.join_sent = false;
        qconn.multicast_process_local_state(quiche::multicast::State {
            channel_id: channel_id.to_vec(),
            sequence: state_sequence,
            state: quiche::multicast::ChannelState::Left,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: Vec::new(),
        })?;
        self.fold_stream_delivery_metrics(qconn, channel_id);

        if self.peer_supports_multicast(qconn) {
            qconn.multicast_send(quiche::multicast::Frame::Leave(
                quiche::multicast::Leave {
                    channel_id: channel_id.to_vec(),
                    mc_state_sequence: state_sequence,
                    after_packet_number,
                },
            ))?;
        }

        Ok(())
    }

    fn flush_pending_stream_publications(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        while let Some(publication) = self.pending_stream_publications.pop_front()
        {
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
                    self.fold_stream_delivery_metrics(qconn, channel_id);
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
                        );
                    }
                },

                Err(
                    quiche::Error::Done |
                    quiche::Error::StreamLimit |
                    quiche::Error::InvalidStreamState(_),
                ) => {
                    self.pending_stream_publications.push_front(publication);
                    self.stream_retry_blocked = true;
                    break;
                },

                Err(quiche::Error::StreamStopped(_)) => (),

                Err(error) => return Err(error.into()),
            }
        }

        Ok(())
    }

    fn queue_stream_integrity(
        &mut self, frame: quiche::multicast::Integrity, now: Instant,
    ) {
        let batching = self.settings.stream_integrity_batching;
        if batching.max_packet_hashes <= 1 || batching.max_delay.is_zero() {
            self.pending_integrities.push_back(frame);
            return;
        }

        let Some((frame_count, frame_hash_len)) =
            Self::integrity_hash_shape(&frame)
        else {
            self.pending_integrities.push_back(frame);
            return;
        };
        let channel_id = frame.channel_id.clone();

        if let Some(mut pending) =
            self.pending_stream_integrity_batches.remove(&channel_id)
        {
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
                    self.pending_integrities.push_back(pending.frame);
                } else {
                    self.pending_stream_integrity_batches
                        .insert(channel_id, pending);
                }
                return;
            }

            self.pending_integrities.push_back(pending.frame);
        }

        if frame_count >= batching.max_packet_hashes {
            self.pending_integrities.push_back(frame);
            return;
        }

        let deadline = now.checked_add(batching.max_delay).unwrap_or(now);
        self.pending_stream_integrity_batches.insert(
            channel_id,
            PendingStreamIntegrityBatch {
                frame,
                hash_len: frame_hash_len,
                deadline,
            },
        );
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
            .map(|pending| pending.deadline)
            .min()
    }

    fn stage_due_stream_integrities(&mut self, now: Instant) {
        let due_channels = self
            .pending_stream_integrity_batches
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(channel_id, _)| channel_id.clone())
            .collect::<Vec<_>>();

        for channel_id in due_channels {
            self.flush_stream_integrity_batch(&channel_id);
        }
    }

    fn flush_stream_integrity_batch(&mut self, channel_id: &[u8]) {
        if let Some(pending) =
            self.pending_stream_integrity_batches.remove(channel_id)
        {
            self.pending_integrities.push_back(pending.frame);
        }
    }

    fn flush_pending_integrities(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        while let Some(frame) = self.pending_integrities.pop_front() {
            qconn.multicast_send(quiche::multicast::Frame::Integrity(frame))?;
        }

        Ok(())
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

#[derive(Debug)]
struct PendingPublication {
    channel_id: Vec<u8>,
    packet: Vec<u8>,
    packet_number: u64,
    integrity: quiche::multicast::Integrity,
}

struct ServerRuntime<B: PublishBackend> {
    settings: ServerSettings,
    event_sender: UnboundedSender<ServerEvent>,
    command_receiver: UnboundedReceiver<ServerCommand>,
    pending_commands: VecDeque<ServerCommand>,
    pending_publications: VecDeque<PendingPublication>,
    pending_integrities: VecDeque<quiche::multicast::Integrity>,
    publish_retry_deadline: Option<Instant>,
    channels: BTreeMap<Vec<u8>, ServerChannel<B::Publication>>,
    backend: B,
    event_coalescer: ServerEventCoalescer,
}

impl ServerRuntime<MctxPublishBackend> {
    fn new(
        settings: ServerSettings, event_sender: UnboundedSender<ServerEvent>,
        command_receiver: UnboundedReceiver<ServerCommand>,
    ) -> Self {
        Self::with_backend(
            settings,
            event_sender,
            command_receiver,
            MctxPublishBackend,
        )
    }
}

impl<B: PublishBackend> ServerRuntime<B> {
    fn with_backend(
        settings: ServerSettings, event_sender: UnboundedSender<ServerEvent>,
        command_receiver: UnboundedReceiver<ServerCommand>, backend: B,
    ) -> Self {
        Self {
            settings,
            event_sender,
            command_receiver,
            pending_commands: VecDeque::new(),
            pending_publications: VecDeque::new(),
            pending_integrities: VecDeque::new(),
            publish_retry_deadline: None,
            channels: BTreeMap::new(),
            backend,
            event_coalescer: ServerEventCoalescer::default(),
        }
    }

    fn clear(&mut self) {
        self.pending_commands.clear();
        self.pending_publications.clear();
        self.pending_integrities.clear();
        self.publish_retry_deadline = None;
        self.channels.clear();
        self.event_coalescer.clear();

        while self.command_receiver.try_recv().is_ok() {}
    }

    fn has_pending_work(&self) -> bool {
        !self.pending_commands.is_empty() ||
            !self.pending_publications.is_empty() ||
            !self.pending_integrities.is_empty()
    }

    async fn wait_for_work(&mut self) -> QuicResult<()> {
        if let Some(deadline) = self.publish_retry_deadline.take() {
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
        }

        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let result: QuicResult<()> = loop {
            match qconn.multicast_recv() {
                Ok(frame) =>
                    if let Err(error) = self.handle_frame(qconn, frame) {
                        break Err(error);
                    },

                Err(quiche::Error::Done) => break Ok(()),

                Err(err) => break Err(err.into()),
            }
        };

        self.event_coalescer.flush_client_acks(&self.event_sender);
        result
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        while let Ok(command) = self.command_receiver.try_recv() {
            self.pending_commands.push_back(command);
        }

        self.encode_pending_commands(qconn);
        self.flush_pending_publications()?;
        self.flush_pending_integrities(qconn)?;

        Ok(())
    }

    fn initialize_channels(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if !self.channels.is_empty() {
            return Ok(());
        }

        for config in &self.settings.channels {
            if qconn.multicast_default_dgram_channel().is_none() {
                qconn.multicast_set_default_dgram_channel(Some(
                    config.channel_id.clone(),
                ))?;
            }
            qconn.multicast_set_ack_timeout(
                &config.channel_id,
                Some(server_ack_freshness_timeout(config.max_ack_delay_ms)),
            )?;

            let publication = self.backend.open(&config.publication)?;
            let (source, group, udp_port) =
                self.backend.announce_tuple(&publication)?;
            let control = config.control_channel_from(source, group, udp_port)?;
            let send_state = quiche::multicast::ChannelSendState::new(
                control.announce.clone(),
                control.key.clone(),
            )?;

            qconn.multicast_send(quiche::multicast::Frame::Announce(
                control.announce,
            ))?;
            qconn.multicast_send(quiche::multicast::Frame::Key(control.key))?;

            self.channels
                .insert(config.channel_id.clone(), ServerChannel {
                    publication,
                    send_state,
                    join_sent: false,
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
                let _ = self.event_sender.send(ServerEvent::ClientState(frame));
            },

            quiche::multicast::Frame::Ack(frame) => {
                if let Some(channel) = self.channels.get_mut(&frame.channel_id) {
                    channel.send_state.on_ack(&frame)?;
                    qconn.multicast_process_peer_ack(frame.clone())?;
                }

                self.event_coalescer.queue_client_ack(frame);
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
        let sequence = frame.sequence;
        let _ = self.event_sender.send(ServerEvent::ClientLimits(frame));

        for channel in self.channels.values_mut() {
            if channel.join_sent {
                continue;
            }

            qconn.multicast_send(quiche::multicast::Frame::Join(
                quiche::multicast::Join {
                    channel_id: channel.send_state.announce().channel_id.clone(),
                    mc_limits_sequence: sequence,
                    mc_state_sequence: 0,
                    mc_key_sequence: channel.send_state.key().key_sequence,
                },
            ))?;
            channel.join_sent = true;
        }

        Ok(())
    }

    fn encode_pending_commands(&mut self, qconn: &mut QuicheConnection) {
        while let Some(command) = self.pending_commands.pop_front() {
            match command {
                ServerCommand::Send { channel_id, frames } => {
                    let Some(channel) = self.channels.get_mut(&channel_id) else {
                        let _ =
                            self.event_sender.send(ServerEvent::EncodeError {
                                channel_id,
                                error: quiche::Error::InvalidState,
                            });
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

                    let mut packet = vec![0; CHANNEL_PACKET_BUFFER_LEN];

                    match channel.send_state.write_packet(&frames, &mut packet) {
                        Ok(output) => {
                            packet.truncate(output.packet_len);
                            self.pending_publications.push_back(
                                PendingPublication {
                                    channel_id,
                                    packet,
                                    packet_number: output.packet_number,
                                    integrity: output.integrity,
                                },
                            );
                        },

                        Err(error) => {
                            let _ = self.event_sender.send(
                                ServerEvent::EncodeError { channel_id, error },
                            );
                        },
                    }
                },

                ServerCommand::RelayIntegrity { frame } => {
                    self.pending_integrities.push_back(frame);
                },
            }
        }
    }

    fn flush_pending_publications(&mut self) -> QuicResult<()> {
        while let Some(pending) = self.pending_publications.pop_front() {
            let Some(channel) = self.channels.get(&pending.channel_id) else {
                let _ = self.event_sender.send(ServerEvent::EncodeError {
                    channel_id: pending.channel_id,
                    error: quiche::Error::InvalidState,
                });
                continue;
            };

            match self.backend.send(&channel.publication, &pending.packet) {
                Ok(report) => {
                    self.pending_integrities.push_back(pending.integrity);
                    let _ = self.event_sender.send(ServerEvent::Published {
                        channel_id: pending.channel_id,
                        packet_number: pending.packet_number,
                        report,
                    });
                },

                Err(error) if publish_would_block(&error) => {
                    self.pending_publications.push_front(pending);
                    self.publish_retry_deadline =
                        Some(Instant::now() + PUBLISH_RETRY_DELAY);
                    return Ok(());
                },

                Err(error) => {
                    let _ = self.event_sender.send(ServerEvent::PublishError {
                        channel_id: pending.channel_id,
                        error,
                    });
                },
            }
        }

        self.publish_retry_deadline = None;

        Ok(())
    }

    fn flush_pending_integrities(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        while let Some(frame) = self.pending_integrities.pop_front() {
            qconn.multicast_send(quiche::multicast::Frame::Integrity(frame))?;
        }

        Ok(())
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
            _ingress_sender: UnboundedSender<IngressEvent>,
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
        let mut client_config =
            quiche::test_utils::Pipe::default_config("cubic").unwrap();
        client_config.enable_dgram(true, 10, 10);
        client_config
            .set_multicast_client_params(Some(settings.transport_params.clone()));

        let mut server_config =
            quiche::test_utils::Pipe::default_config("cubic").unwrap();
        server_config.enable_dgram(true, 10, 10);
        server_config.enable_multicast_server_support(true);

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
            .set_multicast_client_params(Some(settings.transport_params.clone()));

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

    fn assert_next_local_state(
        event_receiver: &mut UnboundedReceiver<ClientEvent>,
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
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

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
                event_receiver,
            },
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

    fn publish_profile_burst(
        publisher: &ServerStreamPublisher,
        connections: &mut [StreamProfileConnection], stream_id: u64,
        start_offset: u64, range_count: usize, finish: bool,
    ) -> (u64, u64) {
        let wake_counter = Arc::new(StreamProfileWakeCounter::default());
        let waker = Waker::from(Arc::clone(&wake_counter));
        let mut context = Context::from_waker(&waker);
        let mut waiters = connections
            .iter_mut()
            .map(|connection| Box::pin(connection.runtime.wait_for_work()))
            .collect::<Vec<_>>();

        for waiter in &mut waiters {
            assert!(matches!(waiter.as_mut().poll(&mut context), Poll::Pending));
        }

        let payload = Bytes::from(vec![0x5a; 1024]);
        let mut offset = start_offset;
        for range_index in 0..range_count {
            let range_fin = finish && range_index + 1 == range_count;
            let publication = publisher
                .prepare_stream_buf(stream_id, offset, range_fin, payload.clone())
                .unwrap();
            assert!(!publication.packet().is_empty());
            publisher.commit(publication).unwrap();
            offset += payload.len() as u64;
        }

        let wake_count = wake_counter.wakes.load(Ordering::Relaxed);
        drop(waiters);
        for connection in connections {
            connection
                .runtime
                .process_writes(&mut connection.pipe.server)
                .unwrap();
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

        for (offset, data) in [(10, b"one".as_slice()), (13, b"two")] {
            let publication =
                publisher.prepare_stream(3, offset, false, data).unwrap();
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
        assert_eq!(
            publisher.delivery_metrics_snapshot(),
            quiche::multicast::StreamDeliveryMetricsSnapshot::default()
        );
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

        let mut connections = Vec::with_capacity(CLIENT_COUNT);
        for client_id in 0..CLIENT_COUNT {
            let mut pipe =
                test_stream_pipe_with_flow_control(&settings, 3, 512 * 1024);
            let (mut runtime, controller) = test_stream_control_runtime();
            runtime.on_conn_established(&mut pipe.server).unwrap();
            send_webtransport_stream_prefix(
                &mut pipe,
                STREAM_ID,
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
                    channel_id: channel_id.clone(),
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

        let mut stream_offset = WEBTRANSPORT_PREFIX_LEN;
        let mut task_wakes = 0_u64;

        let (next_offset, wakes) = publish_profile_burst(
            &publisher,
            &mut connections,
            STREAM_ID,
            stream_offset,
            RANGES_PER_PHASE,
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
            while let Ok(event) = connection.controller.event_receiver.try_recv()
            {
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
        let profile = publisher.test_profile().unwrap();
        let delivery = publisher.delivery_metrics_snapshot();

        assert_eq!(client_ack_events, CLIENT_COUNT as u64);
        assert_eq!(
            delivery.direct_fallback_ranges_total,
            (CLIENT_COUNT * RANGES_PER_PHASE * 2) as u64
        );
        assert_eq!(
            delivery.fallback_reentry_ranges_total,
            (CLIENT_COUNT * RANGES_PER_PHASE) as u64
        );
        assert_eq!(profile.tracked_streams, 1);
        assert_eq!(profile.finished_streams, 1);
        assert_eq!(profile.attached_connections, CLIENT_COUNT);

        println!(
            concat!(
                "MCQUIC_PROFILE clients={} ranges_per_phase={} ",
                "publication_commands={} task_wakes={} ",
                "preparation_capacity_bytes={} ack_events={} ",
                "probe_events={} limits_events={} state_events={} ",
                "metric_fold_attempts={} peak_recovery_ranges={} ",
                "final_recovery_ranges={} direct_ranges={} ",
                "gap_recovery_ranges={} reentry_ranges={} ",
                "publisher_tracked_streams={} ",
                "publisher_finished_streams={}"
            ),
            CLIENT_COUNT,
            RANGES_PER_PHASE,
            profile.publication_commands_sent,
            task_wakes,
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

        runtime.queue_stream_integrity(test_stream_integrity(10, 0xaa), now);
        runtime.queue_stream_integrity(test_stream_integrity(11, 0xbb), now);
        assert!(runtime.pending_integrities.is_empty());
        assert_eq!(runtime.pending_stream_integrity_batches.len(), 1);

        runtime.queue_stream_integrity(test_stream_integrity(12, 0xcc), now);
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

        runtime.queue_stream_integrity(first.clone(), now);
        runtime.queue_stream_integrity(after_gap.clone(), now);

        assert_eq!(runtime.pending_integrities.pop_front(), Some(first));
        assert_eq!(
            runtime.pending_stream_integrity_batches[&[1, 2, 3, 4][..]].frame,
            after_gap
        );
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
        runtime.queue_stream_integrity(integrity.clone(), Instant::now());

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

        runtime.stage_due_stream_integrities(Instant::now());
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
            Some(quiche::multicast::ProbeStatus::Viable)
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
        assert!(runtime.stream_retry_blocked);
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
        assert_eq!(runtime.pending_stream_publications.len(), 1);
        assert!(runtime.stream_retry_blocked);

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
        assert!(runtime.stream_retry_blocked);

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
    fn server_control_announce_waits_for_allowed_address_family() {
        let mut settings = test_settings();
        settings.transport_params.limits.ipv4_channels_allowed = false;
        let mut pipe = test_pipe(&settings);
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
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
        let (event_sender, _) = mpsc::unbounded_channel();
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
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
    fn runtime_declines_ipv6_channel_with_placeholder_event() {
        let settings = test_settings();
        let mut pipe = test_pipe(&settings);
        let backend = FakeJoinBackend::default();
        let recorded = Arc::clone(&backend.joins);
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
                channel_id: announce.channel_id,
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
                channel_id: announce.channel_id,
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
    fn server_runtime_processes_all_acks_and_coalesces_notifications() {
        let settings = test_settings();
        let server_settings = test_server_settings();
        let mut pipe = test_pipe(&settings);
        let backend = FakePublishBackend::default();
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
        assert_eq!(metrics.ack_frames_processed, 4);
        assert_eq!(metrics.largest_acknowledged, Some(7));
    }

    #[test]
    fn server_event_coalescer_suppresses_identical_probe_events() {
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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

        coalescer.forward_probe_event(&event_sender, event.clone());
        coalescer.forward_probe_event(&event_sender, event.clone());

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ProbeStatusChanged(received)) if received == event
        ));
        assert!(event_receiver.try_recv().is_err());

        let mut changed = event;
        changed.reason_phrase = b"path changed".to_vec();
        coalescer.forward_probe_event(&event_sender, changed.clone());
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
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
            .send(ServerControlCommand::RelayIntegrity {
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
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let mut controller = ServerControlController {
            command_sender,
            event_receiver: mpsc::unbounded_channel().1,
        };
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let controller = ServerControlController {
            command_sender,
            event_receiver: mpsc::unbounded_channel().1,
        };
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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

        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientState(frame)) if frame == state
        ));
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ServerEvent::ClientAck(frame)) if frame == ack
        ));
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
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
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
            .send(ServerCommand::Send {
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
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
        let mut runtime =
            ClientRuntime::with_backend(settings, event_sender, backend);
        let announce = test_ipv4_announce();

        runtime
            .channels
            .entry(announce.channel_id.clone())
            .or_default()
            .ack_state
            .record_packet(7);
        runtime.flush_pending_acks(&mut pipe.client).unwrap();

        let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
        quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

        assert_eq!(
            pipe.server.multicast_recv(),
            Ok(quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: announce.channel_id,
                largest_acknowledged: 7,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }))
        );
    }
}
