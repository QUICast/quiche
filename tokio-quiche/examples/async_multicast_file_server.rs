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

#[cfg(not(feature = "multicast"))]
fn main() {
    eprintln!(
        "async_multicast_file_server requires the `multicast` feature.\n\
         Run it with: cargo run -p tokio-quiche --example \
         async_multicast_file_server --features multicast -- --address \
         127.0.0.1:5757 --file ./README.md"
    );
    std::process::exit(1);
}

#[cfg(feature = "multicast")]
#[path = "support/multicast_file.rs"]
mod multicast_file;

#[cfg(feature = "multicast")]
use std::collections::VecDeque;
#[cfg(feature = "multicast")]
use std::future::pending;
#[cfg(feature = "multicast")]
use std::io::ErrorKind;
#[cfg(feature = "multicast")]
use std::net::Ipv4Addr;
#[cfg(feature = "multicast")]
use std::path::PathBuf;
#[cfg(feature = "multicast")]
use std::sync::atomic::AtomicU64;
#[cfg(feature = "multicast")]
use std::sync::atomic::AtomicUsize;
#[cfg(feature = "multicast")]
use std::sync::atomic::Ordering;
#[cfg(feature = "multicast")]
use std::sync::Arc;
#[cfg(feature = "multicast")]
use std::time::Duration;
#[cfg(feature = "multicast")]
use std::time::Instant;

#[cfg(feature = "multicast")]
use anyhow::Context;
#[cfg(feature = "multicast")]
use clap::Parser;
#[cfg(feature = "multicast")]
use futures::stream::StreamExt;
#[cfg(feature = "multicast")]
use mctx_core::MctxError;
#[cfg(feature = "multicast")]
use mctx_core::Publication;
#[cfg(feature = "multicast")]
use mctx_core::PublicationConfig;
#[cfg(feature = "multicast")]
use mctx_core::PublicationId;
#[cfg(feature = "multicast")]
use mctx_core::PublicationMetricsSnapshot;
#[cfg(feature = "multicast")]
use tokio::net::UdpSocket;
#[cfg(feature = "multicast")]
use tokio::sync::broadcast;
#[cfg(feature = "multicast")]
use tokio::time::interval;
#[cfg(feature = "multicast")]
use tokio::time::MissedTickBehavior;
#[cfg(feature = "multicast")]
use tokio_quiche::listen;
#[cfg(feature = "multicast")]
use tokio_quiche::metrics::DefaultMetrics;
#[cfg(feature = "multicast")]
use tokio_quiche::quic::HandshakeInfo;
#[cfg(feature = "multicast")]
use tokio_quiche::quic::QuicheConnection;
#[cfg(feature = "multicast")]
use tokio_quiche::settings::CertificateKind;
#[cfg(feature = "multicast")]
use tokio_quiche::settings::Hooks;
#[cfg(feature = "multicast")]
use tokio_quiche::settings::QuicSettings;
#[cfg(feature = "multicast")]
use tokio_quiche::settings::TlsCertificatePaths;
#[cfg(feature = "multicast")]
use tokio_quiche::ApplicationOverQuic;
#[cfg(feature = "multicast")]
use tokio_quiche::ConnectionParams;
#[cfg(feature = "multicast")]
use tokio_quiche::QuicResult;

#[cfg(feature = "multicast")]
use crate::multicast_file::describe_hash_algorithm;
#[cfg(feature = "multicast")]
use crate::multicast_file::hash_algorithm_output_len;
#[cfg(feature = "multicast")]
use crate::multicast_file::parse_hash_algorithm_id;
#[cfg(feature = "multicast")]
use crate::multicast_file::LoopingTransfer;
#[cfg(feature = "multicast")]
use crate::multicast_file::PreparedTransfer;
#[cfg(feature = "multicast")]
use crate::multicast_file::DEFAULT_ENCRYPTION_ALGORITHM;
#[cfg(feature = "multicast")]
use crate::multicast_file::DEFAULT_HASH_ALGORITHM_NAME;
#[cfg(feature = "multicast")]
use crate::multicast_file::DEFAULT_HEADER_SECRET;
#[cfg(feature = "multicast")]
use crate::multicast_file::DEFAULT_PAYLOAD_SECRET;
#[cfg(feature = "multicast")]
use crate::multicast_file::FILE_CHANNEL_ID;

#[cfg(feature = "multicast")]
const DEFAULT_KEY_SEQUENCE: u64 = 1;
#[cfg(feature = "multicast")]
const DEFAULT_FROM_PACKET_NUMBER: u64 = 0;
#[cfg(feature = "multicast")]
const DEFAULT_MAX_RATE_KIBPS: u64 = 1024;
#[cfg(feature = "multicast")]
const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;
#[cfg(feature = "multicast")]
const INTEGRITY_BROADCAST_CAPACITY: usize = 2048;
#[cfg(feature = "multicast")]
const PACKET_LOG_INTERVAL: u64 = 128;
#[cfg(feature = "multicast")]
const CHANNEL_PACKET_BUFFER_LEN: usize = 64 * 1024;

#[cfg(feature = "multicast")]
#[derive(Parser, Debug)]
#[command(
    about = "Looped multicast file sender over tokio-quiche draft multicast",
    version
)]
struct Args {
    /// The address for the QUIC control server to listen on.
    #[arg(short, long)]
    address: String,

    /// The file to loop forever over the multicast channel.
    #[arg(long)]
    file: PathBuf,

    /// Path for the TLS certificate.
    #[arg(long, default_value_t = default_cert_path())]
    tls_cert_path: String,

    /// Path for the TLS private key.
    #[arg(long, default_value_t = default_private_key_path())]
    tls_private_key_path: String,

    /// The multicast group to publish on.
    #[arg(long, default_value_t = Ipv4Addr::new(232, 1, 2, 3))]
    multicast_group: Ipv4Addr,

    /// The multicast UDP destination port.
    #[arg(long, default_value_t = 4444)]
    multicast_port: u16,

    /// The IPv4 source address to announce and bind for multicast sends.
    #[arg(long, default_value_t = Ipv4Addr::LOCALHOST)]
    multicast_source: Ipv4Addr,

    /// The IPv4 multicast egress interface.
    #[arg(long, default_value_t = Ipv4Addr::LOCALHOST)]
    multicast_interface: Ipv4Addr,

    /// Application payload bytes per multicast chunk datagram.
    #[arg(long, default_value_t = 1024)]
    chunk_payload_bytes: usize,

    /// Maximum number of chunk packets between manifest packets.
    #[arg(long, default_value_t = 32)]
    manifest_interval_packets: u32,

    /// Milliseconds between multicast packets.
    #[arg(long, default_value_t = 20)]
    publish_interval_ms: u64,

    /// Multicast integrity hash algorithm to announce and use.
    #[arg(long, default_value = DEFAULT_HASH_ALGORITHM_NAME)]
    integrity_hash_algorithm: String,

    /// Number of packet hashes to aggregate into one `MC_INTEGRITY` frame.
    #[arg(long, default_value_t = 1)]
    integrity_hashes_per_frame: usize,

    /// Seconds between multicast publisher metrics summaries. Set to `0` to
    /// disable.
    #[arg(long, default_value_t = 5)]
    metrics_interval_secs: u64,
}

#[cfg(feature = "multicast")]
#[derive(Clone)]
struct SharedControlChannel {
    announce: quiche::multicast::Announce,
    key: quiche::multicast::Key,
    integrity_hash_len: usize,
    integrity_sender: broadcast::Sender<quiche::multicast::Integrity>,
    metrics: Arc<ControlFanoutMetrics>,
}

#[cfg(feature = "multicast")]
impl SharedControlChannel {
    fn subscribe(&self) -> broadcast::Receiver<quiche::multicast::Integrity> {
        self.integrity_sender.subscribe()
    }
}

#[cfg(feature = "multicast")]
#[derive(Default)]
struct ControlFanoutMetrics {
    connected_clients: AtomicUsize,
    joined_clients: AtomicUsize,
    total_connections: AtomicU64,
    total_join_events: AtomicU64,
    total_leave_events: AtomicU64,
    client_ack_frames: AtomicU64,
    client_ack_ranges: AtomicU64,
    client_acked_packets: AtomicU64,
    client_largest_acked_packet: AtomicU64,
    integrity_frames_published: AtomicU64,
    integrity_hashes_published: AtomicU64,
    integrity_hash_bytes_published: AtomicU64,
    integrity_frames_unicast_sent: AtomicU64,
    integrity_hashes_unicast_sent: AtomicU64,
    integrity_hash_bytes_unicast_sent: AtomicU64,
    integrity_send_blocked: AtomicU64,
    integrity_send_errors: AtomicU64,
    integrity_receiver_lagged_events: AtomicU64,
    integrity_receiver_lagged_messages: AtomicU64,
    max_pending_integrities: AtomicUsize,
}

#[cfg(feature = "multicast")]
#[derive(Clone, Copy, Debug, Default)]
struct ControlFanoutMetricsSnapshot {
    connected_clients: usize,
    joined_clients: usize,
    total_connections: u64,
    total_join_events: u64,
    total_leave_events: u64,
    client_ack_frames: u64,
    client_ack_ranges: u64,
    client_acked_packets: u64,
    client_largest_acked_packet: u64,
    integrity_frames_published: u64,
    integrity_hashes_published: u64,
    integrity_hash_bytes_published: u64,
    integrity_frames_unicast_sent: u64,
    integrity_hashes_unicast_sent: u64,
    integrity_hash_bytes_unicast_sent: u64,
    integrity_send_blocked: u64,
    integrity_send_errors: u64,
    integrity_receiver_lagged_events: u64,
    integrity_receiver_lagged_messages: u64,
    max_pending_integrities: usize,
}

#[cfg(feature = "multicast")]
#[derive(Clone, Copy, Debug, Default)]
struct ControlFanoutMetricsDelta {
    total_connections: u64,
    total_join_events: u64,
    total_leave_events: u64,
    client_ack_frames: u64,
    client_ack_ranges: u64,
    client_acked_packets: u64,
    integrity_frames_published: u64,
    integrity_hashes_published: u64,
    integrity_hash_bytes_published: u64,
    integrity_frames_unicast_sent: u64,
    integrity_hashes_unicast_sent: u64,
    integrity_hash_bytes_unicast_sent: u64,
    integrity_send_blocked: u64,
    integrity_send_errors: u64,
    integrity_receiver_lagged_events: u64,
    integrity_receiver_lagged_messages: u64,
}

#[cfg(feature = "multicast")]
impl ControlFanoutMetrics {
    fn snapshot(&self) -> ControlFanoutMetricsSnapshot {
        ControlFanoutMetricsSnapshot {
            connected_clients: self.connected_clients.load(Ordering::Relaxed),
            joined_clients: self.joined_clients.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            total_join_events: self.total_join_events.load(Ordering::Relaxed),
            total_leave_events: self.total_leave_events.load(Ordering::Relaxed),
            client_ack_frames: self.client_ack_frames.load(Ordering::Relaxed),
            client_ack_ranges: self.client_ack_ranges.load(Ordering::Relaxed),
            client_acked_packets: self
                .client_acked_packets
                .load(Ordering::Relaxed),
            client_largest_acked_packet: self
                .client_largest_acked_packet
                .load(Ordering::Relaxed),
            integrity_frames_published: self
                .integrity_frames_published
                .load(Ordering::Relaxed),
            integrity_hashes_published: self
                .integrity_hashes_published
                .load(Ordering::Relaxed),
            integrity_hash_bytes_published: self
                .integrity_hash_bytes_published
                .load(Ordering::Relaxed),
            integrity_frames_unicast_sent: self
                .integrity_frames_unicast_sent
                .load(Ordering::Relaxed),
            integrity_hashes_unicast_sent: self
                .integrity_hashes_unicast_sent
                .load(Ordering::Relaxed),
            integrity_hash_bytes_unicast_sent: self
                .integrity_hash_bytes_unicast_sent
                .load(Ordering::Relaxed),
            integrity_send_blocked: self
                .integrity_send_blocked
                .load(Ordering::Relaxed),
            integrity_send_errors: self
                .integrity_send_errors
                .load(Ordering::Relaxed),
            integrity_receiver_lagged_events: self
                .integrity_receiver_lagged_events
                .load(Ordering::Relaxed),
            integrity_receiver_lagged_messages: self
                .integrity_receiver_lagged_messages
                .load(Ordering::Relaxed),
            max_pending_integrities: self
                .max_pending_integrities
                .load(Ordering::Relaxed),
        }
    }

    fn on_control_connected(&self) {
        self.connected_clients.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    fn on_control_disconnected(&self) {
        self.connected_clients.fetch_sub(1, Ordering::Relaxed);
    }

    fn on_joined(&self) {
        self.joined_clients.fetch_add(1, Ordering::Relaxed);
        self.total_join_events.fetch_add(1, Ordering::Relaxed);
    }

    fn on_left(&self) {
        self.joined_clients.fetch_sub(1, Ordering::Relaxed);
        self.total_leave_events.fetch_add(1, Ordering::Relaxed);
    }

    fn on_client_ack(&self, ack: &quiche::multicast::Ack) {
        self.client_ack_frames.fetch_add(1, Ordering::Relaxed);
        self.client_ack_ranges
            .fetch_add(ack.ack_ranges.len() as u64, Ordering::Relaxed);
        self.client_acked_packets.fetch_add(
            ack.first_ack_range.saturating_add(1) +
                ack.ack_ranges
                    .iter()
                    .map(|range| range.ack_range_length.saturating_add(1))
                    .sum::<u64>(),
            Ordering::Relaxed,
        );
        self.client_largest_acked_packet
            .fetch_max(ack.largest_acknowledged, Ordering::Relaxed);
    }

    fn on_integrity_published(
        &self, integrity: &quiche::multicast::Integrity, hash_len: usize,
    ) {
        self.integrity_frames_published
            .fetch_add(1, Ordering::Relaxed);
        self.integrity_hashes_published.fetch_add(
            integrity_hash_count(integrity, hash_len),
            Ordering::Relaxed,
        );
        self.integrity_hash_bytes_published
            .fetch_add(integrity.packet_hashes.len() as u64, Ordering::Relaxed);
    }

    fn on_integrity_unicast_sent(
        &self, integrity: &quiche::multicast::Integrity, hash_len: usize,
    ) {
        self.integrity_frames_unicast_sent
            .fetch_add(1, Ordering::Relaxed);
        self.integrity_hashes_unicast_sent.fetch_add(
            integrity_hash_count(integrity, hash_len),
            Ordering::Relaxed,
        );
        self.integrity_hash_bytes_unicast_sent
            .fetch_add(integrity.packet_hashes.len() as u64, Ordering::Relaxed);
    }

    fn on_integrity_send_blocked(&self) {
        self.integrity_send_blocked.fetch_add(1, Ordering::Relaxed);
    }

    fn on_integrity_send_error(&self) {
        self.integrity_send_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn on_integrity_receiver_lagged(&self, skipped: u64) {
        self.integrity_receiver_lagged_events
            .fetch_add(1, Ordering::Relaxed);
        self.integrity_receiver_lagged_messages
            .fetch_add(skipped, Ordering::Relaxed);
    }

    fn observe_pending_integrities(&self, pending: usize) {
        self.max_pending_integrities
            .fetch_max(pending, Ordering::Relaxed);
    }
}

#[cfg(feature = "multicast")]
impl ControlFanoutMetricsDelta {
    fn between(
        before: ControlFanoutMetricsSnapshot, after: ControlFanoutMetricsSnapshot,
    ) -> Self {
        Self {
            total_connections: after
                .total_connections
                .saturating_sub(before.total_connections),
            total_join_events: after
                .total_join_events
                .saturating_sub(before.total_join_events),
            total_leave_events: after
                .total_leave_events
                .saturating_sub(before.total_leave_events),
            client_ack_frames: after
                .client_ack_frames
                .saturating_sub(before.client_ack_frames),
            client_ack_ranges: after
                .client_ack_ranges
                .saturating_sub(before.client_ack_ranges),
            client_acked_packets: after
                .client_acked_packets
                .saturating_sub(before.client_acked_packets),
            integrity_frames_published: after
                .integrity_frames_published
                .saturating_sub(before.integrity_frames_published),
            integrity_hashes_published: after
                .integrity_hashes_published
                .saturating_sub(before.integrity_hashes_published),
            integrity_hash_bytes_published: after
                .integrity_hash_bytes_published
                .saturating_sub(before.integrity_hash_bytes_published),
            integrity_frames_unicast_sent: after
                .integrity_frames_unicast_sent
                .saturating_sub(before.integrity_frames_unicast_sent),
            integrity_hashes_unicast_sent: after
                .integrity_hashes_unicast_sent
                .saturating_sub(before.integrity_hashes_unicast_sent),
            integrity_hash_bytes_unicast_sent: after
                .integrity_hash_bytes_unicast_sent
                .saturating_sub(before.integrity_hash_bytes_unicast_sent),
            integrity_send_blocked: after
                .integrity_send_blocked
                .saturating_sub(before.integrity_send_blocked),
            integrity_send_errors: after
                .integrity_send_errors
                .saturating_sub(before.integrity_send_errors),
            integrity_receiver_lagged_events: after
                .integrity_receiver_lagged_events
                .saturating_sub(before.integrity_receiver_lagged_events),
            integrity_receiver_lagged_messages: after
                .integrity_receiver_lagged_messages
                .saturating_sub(before.integrity_receiver_lagged_messages),
        }
    }
}

#[cfg(feature = "multicast")]
struct IntegrityFrameBatcher {
    hash_len: usize,
    max_hashes_per_frame: usize,
    pending: Option<quiche::multicast::Integrity>,
}

#[cfg(feature = "multicast")]
impl IntegrityFrameBatcher {
    fn new(hash_len: usize, max_hashes_per_frame: usize) -> anyhow::Result<Self> {
        if max_hashes_per_frame == 0 {
            anyhow::bail!("integrity hashes per frame must be greater than zero");
        }

        Ok(Self {
            hash_len,
            max_hashes_per_frame,
            pending: None,
        })
    }

    fn push(
        &mut self, mut integrity: quiche::multicast::Integrity,
    ) -> anyhow::Result<Vec<quiche::multicast::Integrity>> {
        let mut ready = Vec::with_capacity(2);
        let incoming_hashes =
            integrity_hash_count_checked(&integrity, self.hash_len)?;
        integrity.packet_hash_count = Some(incoming_hashes as u64);

        if let Some(pending) = self.pending.as_mut() {
            let pending_hashes =
                integrity_hash_count_checked(pending, self.hash_len)?;
            let pending_end = pending
                .packet_number_start
                .saturating_add(pending_hashes as u64);

            if pending.channel_id == integrity.channel_id &&
                pending_end == integrity.packet_number_start &&
                pending_hashes + incoming_hashes <= self.max_hashes_per_frame
            {
                pending
                    .packet_hashes
                    .extend_from_slice(&integrity.packet_hashes);
                pending.packet_hash_count =
                    Some((pending_hashes + incoming_hashes) as u64);

                if pending_hashes + incoming_hashes == self.max_hashes_per_frame {
                    if let Some(pending) = self.pending.take() {
                        ready.push(pending);
                    }
                }

                return Ok(ready);
            }

            if let Some(pending) = self.pending.take() {
                ready.push(pending);
            }
        }

        if incoming_hashes >= self.max_hashes_per_frame {
            ready.push(integrity);
        } else {
            self.pending = Some(integrity);
        }

        Ok(ready)
    }
}

#[cfg(feature = "multicast")]
struct FileControlApp {
    shared: Arc<SharedControlChannel>,
    integrity_receiver: broadcast::Receiver<quiche::multicast::Integrity>,
    pending_integrities: VecDeque<quiche::multicast::Integrity>,
    connected: bool,
    multicast_enabled: bool,
    join_sent: bool,
    joined: bool,
    out: Vec<u8>,
}

#[cfg(feature = "multicast")]
impl FileControlApp {
    fn new(shared: Arc<SharedControlChannel>) -> Self {
        Self {
            integrity_receiver: shared.subscribe(),
            shared,
            pending_integrities: VecDeque::new(),
            connected: false,
            multicast_enabled: false,
            join_sent: false,
            joined: false,
            out: vec![0; CHANNEL_PACKET_BUFFER_LEN],
        }
    }

    fn peer_supports_multicast(qconn: &QuicheConnection) -> bool {
        qconn
            .peer_transport_params()
            .and_then(|params| params.multicast_client_params.as_ref())
            .is_some()
    }

    fn handle_frame(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Frame,
    ) -> QuicResult<()> {
        match frame {
            quiche::multicast::Frame::Limits(frame) =>
                self.handle_limits(qconn, frame)?,

            quiche::multicast::Frame::State(frame) => {
                self.handle_state(frame);
            },

            quiche::multicast::Frame::Ack(frame) => {
                self.shared.metrics.on_client_ack(&frame);
                println!(
                    "client ack: channel={} largest={} delay={} ranges={}",
                    format_channel_id(&frame.channel_id),
                    frame.largest_acknowledged,
                    frame.ack_delay,
                    frame.ack_ranges.len(),
                );
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
        println!(
            "client limits: sequence={} max_joined={} ipv4_allowed={} \
             aggregate_rate={}KiBps",
            frame.sequence,
            frame.max_joined_count,
            frame.limits.ipv4_channels_allowed,
            frame.limits.max_aggregate_rate_kibps,
        );

        if self.join_sent {
            return Ok(());
        }

        qconn.multicast_send(quiche::multicast::Frame::Join(
            quiche::multicast::Join {
                channel_id: self.shared.announce.channel_id.clone(),
                mc_limits_sequence: frame.sequence,
                mc_state_sequence: 0,
                mc_key_sequence: self.shared.key.key_sequence,
            },
        ))?;
        self.join_sent = true;

        Ok(())
    }

    fn handle_state(&mut self, frame: quiche::multicast::State) {
        println!(
            "client state: channel={} sequence={} state={:?} reason_scope={:?} \
             reason_code={} phrase={}",
            format_channel_id(&frame.channel_id),
            frame.sequence,
            frame.state,
            frame.reason_scope,
            frame.reason_code,
            String::from_utf8_lossy(&frame.reason_phrase),
        );

        let was_joined = self.joined;
        let is_joined =
            matches!(frame.state, quiche::multicast::ChannelState::Joined);

        if is_joined && !self.joined {
            self.integrity_receiver = self.shared.subscribe();
            self.pending_integrities.clear();
        } else if !is_joined {
            self.pending_integrities.clear();
        }

        self.joined = is_joined;

        if is_joined && !was_joined {
            self.shared.metrics.on_joined();
        } else if !is_joined && was_joined {
            self.shared.metrics.on_left();
        }
    }

    fn drain_integrities(&mut self) {
        loop {
            match self.integrity_receiver.try_recv() {
                Ok(integrity) => self.pending_integrities.push_back(integrity),

                Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                    self.shared.metrics.on_integrity_receiver_lagged(skipped);
                    continue;
                },

                Err(broadcast::error::TryRecvError::Empty) |
                Err(broadcast::error::TryRecvError::Closed) => return,
            }
        }
    }
}

#[cfg(feature = "multicast")]
impl ApplicationOverQuic for FileControlApp {
    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection, _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.shared.metrics.on_control_connected();
        self.connected = true;
        self.multicast_enabled = Self::peer_supports_multicast(qconn);
        self.join_sent = false;
        self.joined = false;
        self.pending_integrities.clear();
        self.integrity_receiver = self.shared.subscribe();

        if !self.multicast_enabled {
            println!("peer connected without multicast negotiation");
            return Ok(());
        }

        qconn.multicast_send(quiche::multicast::Frame::Announce(
            self.shared.announce.clone(),
        ))?;
        qconn.multicast_send(quiche::multicast::Frame::Key(
            self.shared.key.clone(),
        ))?;

        println!(
            "multicast control established: channel={}",
            format_channel_id(&self.shared.announce.channel_id),
        );

        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.out
    }

    async fn wait_for_data(
        &mut self, _qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if !self.pending_integrities.is_empty() {
            return Ok(());
        }

        if !self.multicast_enabled || !self.joined {
            #[allow(unreachable_code)]
            {
                let _ = pending::<QuicResult<()>>().await;
                Ok(())
            }
        } else {
            loop {
                match self.integrity_receiver.recv().await {
                    Ok(integrity) => {
                        self.pending_integrities.push_back(integrity);
                        return Ok(());
                    },

                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        self.shared.metrics.on_integrity_receiver_lagged(skipped);
                        continue;
                    },

                    Err(broadcast::error::RecvError::Closed) => {
                        #[allow(unreachable_code)]
                        {
                            let _ = pending::<QuicResult<()>>().await;
                            return Ok(());
                        }
                    },
                }
            }
        }
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
        if !self.multicast_enabled || !self.joined {
            return Ok(());
        }

        self.drain_integrities();
        self.shared
            .metrics
            .observe_pending_integrities(self.pending_integrities.len());

        while let Some(integrity) = self.pending_integrities.pop_front() {
            match qconn.multicast_send(quiche::multicast::Frame::Integrity(
                integrity.clone(),
            )) {
                Ok(()) => self.shared.metrics.on_integrity_unicast_sent(
                    &integrity,
                    self.shared.integrity_hash_len,
                ),

                Err(quiche::Error::Done) => {
                    self.shared.metrics.on_integrity_send_blocked();
                    self.pending_integrities.push_front(integrity);
                    break;
                },

                Err(err) => {
                    self.shared.metrics.on_integrity_send_error();
                    return Err(err.into());
                },
            }
        }

        Ok(())
    }

    fn on_conn_close<M: tokio_quiche::metrics::Metrics>(
        &mut self, qconn: &mut QuicheConnection, _metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        self.pending_integrities.clear();
        if self.connected {
            self.shared.metrics.on_control_disconnected();
        }
        self.connected = false;
        if self.joined {
            self.shared.metrics.on_left();
        }
        self.joined = false;
        self.join_sent = false;
        let stats = qconn.stats();
        println!(
            "control connection closed: result={} detail={:?} local_error={:?} \
             peer_error={:?} sent={} recv={} lost={} retrans={} sent_bytes={} \
             recv_bytes={}",
            if connection_result.is_ok() {
                "ok"
            } else {
                "error"
            },
            connection_result,
            qconn.local_error(),
            qconn.peer_error(),
            stats.sent,
            stats.recv,
            stats.lost,
            stats.retrans,
            stats.sent_bytes,
            stats.recv_bytes,
        );
    }
}

#[cfg(feature = "multicast")]
#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(feature = "multicast")]
async fn run() -> anyhow::Result<()> {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::parse();
    let integrity_hash_algorithm =
        parse_hash_algorithm_id(&args.integrity_hash_algorithm)?;
    let integrity_hash_len = hash_algorithm_output_len(integrity_hash_algorithm)?;
    let transfer =
        PreparedTransfer::from_path(&args.file, args.chunk_payload_bytes)
            .with_context(|| {
                format!("failed to prepare {}", args.file.display())
            })?;
    let transfer = Arc::new(transfer);
    let publish_interval = Duration::from_millis(args.publish_interval_ms);

    let publication_config =
        PublicationConfig::new(args.multicast_group, args.multicast_port)
            .with_source_addr(args.multicast_source)
            .with_interface(args.multicast_interface)
            .with_loopback(true);
    let publication = Publication::new(PublicationId(1), publication_config)
        .context("failed to create multicast publication socket")?;
    let (source, group, udp_port) = publication
        .announce_tuple()
        .context("failed to derive multicast announce tuple")?;
    let announce = quiche::multicast::Announce {
        channel_id: FILE_CHANNEL_ID.to_vec(),
        source,
        group,
        udp_port,
        header_protection_algorithm: DEFAULT_ENCRYPTION_ALGORITHM,
        header_secret: DEFAULT_HEADER_SECRET.to_vec(),
        aead_algorithm: DEFAULT_ENCRYPTION_ALGORITHM,
        integrity_hash_algorithm,
        max_rate_kibps: DEFAULT_MAX_RATE_KIBPS,
        max_ack_delay_ms: DEFAULT_MAX_ACK_DELAY_MS,
    };
    let key = quiche::multicast::Key {
        channel_id: FILE_CHANNEL_ID.to_vec(),
        key_sequence: DEFAULT_KEY_SEQUENCE,
        from_packet_number: DEFAULT_FROM_PACKET_NUMBER,
        secret: DEFAULT_PAYLOAD_SECRET.to_vec(),
    };
    let send_state =
        quiche::multicast::ChannelSendState::new(announce.clone(), key.clone())
            .map_err(|error| {
            anyhow::anyhow!(
                "failed to initialize multicast send state: {error:?}"
            )
        })?;
    let (integrity_sender, _) = broadcast::channel(INTEGRITY_BROADCAST_CAPACITY);
    let control_metrics = Arc::new(ControlFanoutMetrics::default());
    let shared = Arc::new(SharedControlChannel {
        announce,
        key,
        integrity_hash_len,
        integrity_sender,
        metrics: control_metrics,
    });

    println!(
        "prepared transfer: file={} bytes={} chunks={} chunk_payload={} \
         manifest_every={} packets",
        transfer.manifest().file_name,
        transfer.manifest().file_len,
        transfer.manifest().total_chunks,
        transfer.manifest().chunk_payload_len,
        args.manifest_interval_packets,
    );
    println!(
        "shared multicast channel: channel={} source={} group={} port={} \
         interval={}ms hash={} hash_len={}B hashes_per_integrity={}",
        format_channel_id(&shared.announce.channel_id),
        source,
        group,
        udp_port,
        args.publish_interval_ms,
        describe_hash_algorithm(shared.announce.integrity_hash_algorithm),
        integrity_hash_len,
        args.integrity_hashes_per_frame,
    );

    let publisher_shared = Arc::clone(&shared);
    let publisher_transfer = Arc::clone(&transfer);
    let publish_config = PublishLoopConfig {
        publish_interval,
        metrics_interval_secs: args.metrics_interval_secs,
        manifest_interval_packets: args.manifest_interval_packets,
        integrity_hashes_per_frame: args.integrity_hashes_per_frame,
    };
    tokio::spawn(async move {
        if let Err(err) = publish_loop(
            publication,
            send_state,
            publisher_shared,
            publisher_transfer,
            publish_config,
        )
        .await
        {
            eprintln!("shared multicast publisher stopped: {err:#}");
        }
    });

    let socket = UdpSocket::bind(&args.address)
        .await
        .with_context(|| format!("failed to bind {}", args.address))?;

    let mut quic_settings = QuicSettings::default();
    quic_settings.multicast_server_support = true;
    quic_settings.max_idle_timeout = Some(Duration::from_secs(300));

    let mut listeners = listen(
        [socket],
        ConnectionParams::new_server(
            quic_settings,
            TlsCertificatePaths {
                cert: &args.tls_cert_path,
                private_key: &args.tls_private_key_path,
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        ),
        DefaultMetrics,
    )
    .context("failed to create QUIC listener")?;

    let accepted_connection_stream = &mut listeners[0];
    while let Some(conn_res) = accepted_connection_stream.next().await {
        let conn = conn_res.context("failed to accept QUIC connection")?;
        let app = FileControlApp::new(Arc::clone(&shared));
        conn.start(app);
    }

    Ok(())
}

#[cfg(feature = "multicast")]
struct PublishLoopConfig {
    publish_interval: Duration,
    metrics_interval_secs: u64,
    manifest_interval_packets: u32,
    integrity_hashes_per_frame: usize,
}

#[cfg(feature = "multicast")]
async fn publish_loop(
    publication: Publication,
    mut send_state: quiche::multicast::ChannelSendState,
    shared: Arc<SharedControlChannel>, transfer: Arc<PreparedTransfer>,
    config: PublishLoopConfig,
) -> anyhow::Result<()> {
    let mut looping = LoopingTransfer::new(
        (*transfer).clone(),
        config.manifest_interval_packets,
    )?;
    let mut integrity_batcher = IntegrityFrameBatcher::new(
        shared.integrity_hash_len,
        config.integrity_hashes_per_frame,
    )?;
    let mut ticker = interval(config.publish_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let metrics_interval = (config.metrics_interval_secs != 0)
        .then(|| Duration::from_secs(config.metrics_interval_secs));
    let mut last_metrics_at = Instant::now();
    let mut previous_publication_metrics = publication.metrics_snapshot();
    let mut previous_send_metrics = send_state.metrics_snapshot();
    let mut previous_control_metrics = shared.metrics.snapshot();

    let mut packet_buf = vec![0; CHANNEL_PACKET_BUFFER_LEN];
    let mut sent_packets = 0u64;

    loop {
        ticker.tick().await;

        let datagram = looping.next_datagram();
        let output = send_state
            .write_packet(
                &[quiche::multicast::ChannelFrame::Datagram { data: datagram }],
                &mut packet_buf,
            )
            .map_err(|error| {
                anyhow::anyhow!("failed to encode multicast packet: {error:?}")
            })?;

        match publication.send(&packet_buf[..output.packet_len]) {
            Ok(report) => {
                for integrity in integrity_batcher.push(output.integrity)? {
                    shared.metrics.on_integrity_published(
                        &integrity,
                        shared.integrity_hash_len,
                    );
                    let _ = shared.integrity_sender.send(integrity);
                }
                sent_packets += 1;

                if sent_packets == 1 || sent_packets % PACKET_LOG_INTERVAL == 0 {
                    println!(
                        "shared publisher progress: packets_sent={} last_pn={} \
                         bytes={} source={:?} destination={}",
                        sent_packets,
                        output.packet_number,
                        report.bytes_sent,
                        report.source_addr,
                        report.destination,
                    );
                }
            },

            Err(error) if publish_would_block(&error) => (),

            Err(error) => return Err(anyhow::Error::new(error)),
        }

        if let Some(metrics_interval) = metrics_interval {
            if last_metrics_at.elapsed() >= metrics_interval {
                print_publisher_metrics(
                    &send_state,
                    &publication,
                    &shared.metrics,
                    &mut previous_send_metrics,
                    &mut previous_publication_metrics,
                    &mut previous_control_metrics,
                );
                last_metrics_at = Instant::now();
            }
        }
    }
}

#[cfg(feature = "multicast")]
fn publish_would_block(error: &MctxError) -> bool {
    matches!(
        error,
        MctxError::SendFailed(error) if error.kind() == ErrorKind::WouldBlock
    )
}

#[cfg(feature = "multicast")]
fn integrity_hash_count(
    integrity: &quiche::multicast::Integrity, hash_len: usize,
) -> u64 {
    integrity
        .packet_hash_count
        .unwrap_or_else(|| (integrity.packet_hashes.len() / hash_len) as u64)
}

#[cfg(feature = "multicast")]
fn integrity_hash_count_checked(
    integrity: &quiche::multicast::Integrity, hash_len: usize,
) -> anyhow::Result<usize> {
    let hash_count = integrity_hash_count(integrity, hash_len);

    if hash_count == 0 {
        anyhow::bail!("integrity frame must carry at least one packet hash");
    }

    let expected_len = usize::try_from(hash_count)
        .ok()
        .and_then(|count| count.checked_mul(hash_len))
        .context("integrity frame hash count is too large")?;

    if integrity.packet_hashes.len() != expected_len {
        anyhow::bail!(
            "integrity frame hash payload length {} does not match {} hashes \
             of {} bytes",
            integrity.packet_hashes.len(),
            hash_count,
            hash_len
        );
    }

    Ok(expected_len / hash_len)
}

#[cfg(feature = "multicast")]
fn format_channel_id(id: &[u8]) -> String {
    let mut out = String::with_capacity(id.len() * 2);
    for byte in id {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }

    out
}

#[cfg(feature = "multicast")]
fn print_publisher_metrics(
    send_state: &quiche::multicast::ChannelSendState, publication: &Publication,
    control_metrics: &ControlFanoutMetrics,
    previous_send_metrics: &mut quiche::multicast::ChannelSendMetricsSnapshot,
    previous_publication_metrics: &mut PublicationMetricsSnapshot,
    previous_control_metrics: &mut ControlFanoutMetricsSnapshot,
) {
    let current_send_metrics = send_state.metrics_snapshot();
    let current_publication_metrics = publication.metrics_snapshot();
    let current_control_metrics = control_metrics.snapshot();
    let send_delta = quiche::multicast::ChannelSendMetricsDelta::between(
        *previous_send_metrics,
        current_send_metrics,
    );
    let publication_delta = current_publication_metrics
        .delta_since(previous_publication_metrics)
        .expect("publication metrics snapshots should be monotonic");
    let control_delta = ControlFanoutMetricsDelta::between(
        *previous_control_metrics,
        current_control_metrics,
    );

    *previous_send_metrics = current_send_metrics;
    *previous_publication_metrics = current_publication_metrics;
    *previous_control_metrics = current_control_metrics;

    println!(
        "[metrics] tx encoded_pkts={} encoded_bytes={} encoded_frames={} \
         send_calls={} wire_pkts={} wire_bytes={} send_errors={} \
         ack_frames={} ack_blocks={} acked_pkts={} ack_errors={} \
         largest_acked={:?} next_pn={}",
        send_delta.packets_encoded,
        send_delta.bytes_encoded,
        send_delta.frames_encoded,
        publication_delta.send_calls,
        publication_delta.packets_sent,
        publication_delta.bytes_sent,
        publication_delta.send_errors,
        send_delta.ack_frames_processed,
        send_delta.ack_blocks_processed,
        send_delta.acked_packets_reported,
        send_delta.ack_errors,
        current_send_metrics.largest_acknowledged,
        send_delta.next_packet_number,
    );
    println!(
        "[metrics] ctrl connected={} joined={} accepted={} join_events={} \
         leave_events={} ack_frames={} ack_ranges={} acked_pkts={} \
         max_largest_ack={} published_int_frames={} published_hashes={} \
         published_hash_bytes={} unicast_int_frames={} unicast_hashes={} \
         unicast_hash_bytes={} send_blocked={} send_errors={} lag_events={} \
         lagged_msgs={} max_pending={}",
        current_control_metrics.connected_clients,
        current_control_metrics.joined_clients,
        control_delta.total_connections,
        control_delta.total_join_events,
        control_delta.total_leave_events,
        control_delta.client_ack_frames,
        control_delta.client_ack_ranges,
        control_delta.client_acked_packets,
        current_control_metrics.client_largest_acked_packet,
        control_delta.integrity_frames_published,
        control_delta.integrity_hashes_published,
        control_delta.integrity_hash_bytes_published,
        control_delta.integrity_frames_unicast_sent,
        control_delta.integrity_hashes_unicast_sent,
        control_delta.integrity_hash_bytes_unicast_sent,
        control_delta.integrity_send_blocked,
        control_delta.integrity_send_errors,
        control_delta.integrity_receiver_lagged_events,
        control_delta.integrity_receiver_lagged_messages,
        current_control_metrics.max_pending_integrities,
    );
}

#[cfg(feature = "multicast")]
fn default_cert_path() -> String {
    path_relative_to_manifest_dir("examples/cert.crt")
}

#[cfg(feature = "multicast")]
fn default_private_key_path() -> String {
    path_relative_to_manifest_dir("examples/cert.key")
}

#[cfg(feature = "multicast")]
fn path_relative_to_manifest_dir(path: &str) -> String {
    std::fs::canonicalize({
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
    })
    .unwrap()
    .to_string_lossy()
    .into_owned()
}
