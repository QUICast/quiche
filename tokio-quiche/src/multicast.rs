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

/// Server-side multicast settings for one connection wrapper.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerControlSettings {
    /// Whether configured control frames should be sent automatically or only
    /// when driven explicitly through [`ServerControlController`].
    pub mode: ServerControlMode,

    /// The multicast channels this server may announce and manage through the
    /// QUIC control connection.
    pub channels: Vec<ServerControlChannelConfig>,
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
    UpsertChannel { config: ServerControlChannelConfig },
    SendAnnounce { frame: quiche::multicast::Announce },
    SendKey { frame: quiche::multicast::Key },
    SendJoin { frame: quiche::multicast::Join },
    RelayIntegrity { frame: quiche::multicast::Integrity },
}

#[derive(Default)]
struct ServerControlChannel {
    announce: Option<quiche::multicast::Announce>,
    key: Option<quiche::multicast::Key>,
    join_sent: bool,
}

struct ServerControlRuntime {
    settings: ServerControlSettings,
    event_sender: UnboundedSender<ServerEvent>,
    command_receiver: UnboundedReceiver<ServerControlCommand>,
    pending_commands: VecDeque<ServerControlCommand>,
    pending_integrities: VecDeque<quiche::multicast::Integrity>,
    channels: BTreeMap<Vec<u8>, ServerControlChannel>,
    last_client_limits_sequence: Option<u64>,
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
            pending_integrities: VecDeque::new(),
            channels: BTreeMap::new(),
            last_client_limits_sequence: None,
        }
    }

    fn clear(&mut self) {
        self.pending_commands.clear();
        self.pending_integrities.clear();
        self.channels.clear();
        self.last_client_limits_sequence = None;

        while self.command_receiver.try_recv().is_ok() {}
    }

    fn has_pending_work(&self) -> bool {
        !self.pending_commands.is_empty() || !self.pending_integrities.is_empty()
    }

    async fn wait_for_work(&mut self) -> QuicResult<()> {
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
        loop {
            match qconn.multicast_recv() {
                Ok(frame) => self.handle_frame(qconn, frame)?,

                Err(quiche::Error::Done) => return Ok(()),

                Err(err) => return Err(err.into()),
            }
        }
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        while let Ok(command) = self.command_receiver.try_recv() {
            self.pending_commands.push_back(command);
        }

        self.handle_pending_commands(qconn)?;
        self.flush_pending_integrities(qconn)
    }

    fn initialize_channels(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        let auto_send = self.settings.mode == ServerControlMode::Automatic &&
            self.peer_supports_multicast(qconn);
        let channels = self.settings.channels.clone();

        for config in channels {
            self.upsert_channel_config(qconn, config, auto_send)?;
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
                if self.channels.contains_key(&frame.channel_id) {
                    qconn.multicast_process_peer_ack(frame.clone())?;
                }
                let _ = self.event_sender.send(ServerEvent::ClientAck(frame));
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
        self.last_client_limits_sequence = Some(frame.sequence);
        let _ = self.event_sender.send(ServerEvent::ClientLimits(frame));

        if self.settings.mode != ServerControlMode::Automatic {
            return Ok(());
        }

        let channel_ids = self.channels.keys().cloned().collect::<Vec<_>>();

        for channel_id in channel_ids {
            self.maybe_auto_join_channel(qconn, &channel_id)?;
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
                    self.upsert_channel_config(qconn, config, auto_send)?;
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
                    qconn
                        .multicast_send(quiche::multicast::Frame::Join(frame))?;
                },

                ServerControlCommand::RelayIntegrity { frame } => {
                    self.pending_integrities.push_back(frame);
                },
            }
        }

        Ok(())
    }

    fn upsert_channel_config(
        &mut self, qconn: &mut QuicheConnection,
        config: ServerControlChannelConfig, auto_send: bool,
    ) -> QuicResult<()> {
        config.validate()?;

        let channel_id = config.announce.channel_id.clone();
        Self::set_default_dgram_channel_if_unset(qconn, &channel_id)?;
        Self::set_ack_timeout(
            qconn,
            &channel_id,
            config.announce.max_ack_delay_ms,
        )?;
        let channel = self.channels.entry(channel_id.clone()).or_default();
        channel.announce = Some(config.announce.clone());
        channel.key = Some(config.key.clone());
        channel.join_sent = false;

        if !auto_send {
            return Ok(());
        }

        qconn.multicast_send(quiche::multicast::Frame::Announce(
            config.announce,
        ))?;
        qconn.multicast_send(quiche::multicast::Frame::Key(config.key))?;
        self.maybe_auto_join_channel(qconn, &channel_id)
    }

    fn maybe_auto_join_channel(
        &mut self, qconn: &mut QuicheConnection, channel_id: &[u8],
    ) -> QuicResult<()> {
        if self.settings.mode != ServerControlMode::Automatic {
            return Ok(());
        }

        let Some(sequence) = self.last_client_limits_sequence else {
            return Ok(());
        };

        let Some(channel) = self.channels.get_mut(channel_id) else {
            return Ok(());
        };

        if channel.join_sent {
            return Ok(());
        }

        let (Some(announce), Some(key)) =
            (channel.announce.as_ref(), channel.key.as_ref())
        else {
            return Ok(());
        };

        qconn.multicast_send(quiche::multicast::Frame::Join(
            quiche::multicast::Join {
                channel_id: announce.channel_id.clone(),
                mc_limits_sequence: sequence,
                mc_state_sequence: 0,
                mc_key_sequence: key.key_sequence,
            },
        ))?;
        channel.join_sent = true;

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
        }
    }

    fn clear(&mut self) {
        self.pending_commands.clear();
        self.pending_publications.clear();
        self.pending_integrities.clear();
        self.publish_retry_deadline = None;
        self.channels.clear();

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
        loop {
            match qconn.multicast_recv() {
                Ok(frame) => self.handle_frame(qconn, frame)?,

                Err(quiche::Error::Done) => return Ok(()),

                Err(err) => return Err(err.into()),
            }
        }
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
                }

                qconn.multicast_process_peer_ack(frame.clone())?;

                let _ = self.event_sender.send(ServerEvent::ClientAck(frame));
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
                    if !self.channels.contains_key(&channel_id) {
                        let _ =
                            self.event_sender.send(ServerEvent::EncodeError {
                                channel_id,
                                error: quiche::Error::InvalidState,
                            });
                        continue;
                    }

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

                    let mut packet = vec![0; 64 * 1024];
                    let channel = self
                        .channels
                        .get_mut(&channel_id)
                        .expect("channel existence checked above");

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
    use std::sync::Arc;
    use std::sync::Mutex;

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
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
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

        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::Viable)
        );

        pipe.server.on_timeout();

        assert_eq!(
            pipe.server.multicast_probe_status(&channel_id),
            Some(quiche::multicast::ProbeStatus::TimedOut)
        );

        pipe.server.dgram_send(b"fallback-after-stall").unwrap();
        assert_client_receives_dgram(&mut pipe, b"fallback-after-stall");
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
