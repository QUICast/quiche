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

//! Client-side multicast receive integration for tokio-quiche.
//!
//! This module keeps multicast socket ownership outside core [`quiche`] while
//! still integrating with the multicast draft's unicast control plane. It is
//! currently IPv4-only on the data path and emits explicit placeholder events
//! for IPv6 multicast announcements.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::future::pending;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use mcrx_core::Context as MulticastContext;
use mcrx_core::PacketWithMetadata;
use mcrx_core::SubscriptionConfig;
use mcrx_core::TokioReceiveError;
use mcrx_core::TokioSubscription;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::task::AbortOnDropHandle;

use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

pub use crate::settings::MulticastClientSettings as ClientSettings;

const STATE_REASON_UNSPECIFIED_OTHER: u64 = 0x0;

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

    fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> impl std::future::Future<Output = QuicResult<()>> + Send {
        async move {
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
                IngressEvent::Packet { channel_id, packet } => {
                    self.handle_ingress_packet(qconn, channel_id, packet)?;
                },

                IngressEvent::ReceiveError { channel_id, error } => {
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
        packet: PacketWithMetadata,
    ) -> QuicResult<()> {
        let events = {
            let channel = self.channels.entry(channel_id.clone()).or_default();

            Self::ensure_channel_decoder(channel);

            let Some(receiver) = channel.receive_state.as_mut() else {
                let _ = self.event_sender.send(ClientEvent::DecodeError {
                    channel_id,
                    error: quiche::Error::InvalidState,
                    packet,
                });

                return Ok(());
            };

            let payload = packet.packet.payload().to_vec();
            receiver.recv(&payload, packet)?
        };

        for event in events {
            self.handle_channel_receive_event(qconn, channel_id.clone(), event)?;
        }

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
        for frame in &packet.frames {
            if let quiche::multicast::ChannelFrame::Multicast(frame) = frame {
                self.handle_frame(qconn, frame.clone())?;
            }
        }

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
        let has_key = self
            .channels
            .get(&channel_id)
            .and_then(|channel| channel.key.as_ref())
            .is_some();
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

        if !has_key {
            return self.decline_join(
                qconn,
                channel_id,
                b"missing multicast properties".to_vec(),
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

        let _ = self.event_sender.send(ClientEvent::LocalState(frame));

        Ok(())
    }

    fn decline_join(
        &mut self, qconn: &mut QuicheConnection, channel_id: Vec<u8>,
        reason_phrase: Vec<u8>,
    ) -> QuicResult<()> {
        self.send_state(
            qconn,
            channel_id,
            quiche::multicast::ChannelState::DeclinedJoin,
            STATE_REASON_UNSPECIFIED_OTHER,
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
    receive_state:
        Option<quiche::multicast::ChannelReceiveState<PacketWithMetadata>>,
    next_state_sequence: u64,
    receive_handle: Option<H>,
}

impl<H> Default for Channel<H> {
    fn default() -> Self {
        Self {
            announce: None,
            key: None,
            decoder_error: None,
            receive_state: None,
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
        packet: PacketWithMetadata,
    },

    ReceiveError {
        channel_id: Vec<u8>,
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
        config.interface = interface;

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
        let subscription = TokioSubscription::new(subscription)
            .map_err(McrxJoinBackend::join_error)?;

        let channel_id = channel_id.to_vec();
        let task = tokio::spawn(async move {
            loop {
                match subscription.recv_with_metadata().await {
                    Ok(packet) => {
                        let _ = ingress_sender.send(IngressEvent::Packet {
                            channel_id: channel_id.clone(),
                            packet,
                        });
                    },

                    Err(error) => {
                        let _ = ingress_sender.send(IngressEvent::ReceiveError {
                            channel_id: channel_id.clone(),
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
        client_config
            .set_multicast_client_params(Some(settings.transport_params.clone()));

        let mut server_config =
            quiche::test_utils::Pipe::default_config("cubic").unwrap();
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
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ClientEvent::LocalState(frame))
                if frame.state == quiche::multicast::ChannelState::Joined
        ));
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
        assert!(matches!(
            event_receiver.try_recv(),
            Ok(ClientEvent::LocalState(frame))
                if frame.state == quiche::multicast::ChannelState::DeclinedJoin
        ));
    }
}
