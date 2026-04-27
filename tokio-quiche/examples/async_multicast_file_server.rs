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

#![cfg_attr(not(feature = "multicast"), allow(dead_code))]

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
mod multicast_file;

#[cfg(feature = "multicast")]
use std::collections::VecDeque;
#[cfg(feature = "multicast")]
use std::future::pending;
#[cfg(feature = "multicast")]
use std::future::Future;
#[cfg(feature = "multicast")]
use std::io::ErrorKind;
#[cfg(feature = "multicast")]
use std::net::IpAddr;
#[cfg(feature = "multicast")]
use std::net::Ipv4Addr;
#[cfg(feature = "multicast")]
use std::path::PathBuf;
#[cfg(feature = "multicast")]
use std::sync::Arc;
#[cfg(feature = "multicast")]
use std::time::Duration;

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
use crate::multicast_file::LoopingTransfer;
#[cfg(feature = "multicast")]
use crate::multicast_file::PreparedTransfer;
#[cfg(feature = "multicast")]
use crate::multicast_file::DEFAULT_ENCRYPTION_ALGORITHM;
#[cfg(feature = "multicast")]
use crate::multicast_file::DEFAULT_HASH_ALGORITHM;
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
}

#[cfg(feature = "multicast")]
#[derive(Clone)]
struct SharedControlChannel {
    announce: quiche::multicast::Announce,
    key: quiche::multicast::Key,
    integrity_sender: broadcast::Sender<quiche::multicast::Integrity>,
}

#[cfg(feature = "multicast")]
impl SharedControlChannel {
    fn subscribe(&self) -> broadcast::Receiver<quiche::multicast::Integrity> {
        self.integrity_sender.subscribe()
    }
}

#[cfg(feature = "multicast")]
struct FileControlApp {
    shared: Arc<SharedControlChannel>,
    integrity_receiver: broadcast::Receiver<quiche::multicast::Integrity>,
    pending_integrities: VecDeque<quiche::multicast::Integrity>,
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
            multicast_enabled: false,
            join_sent: false,
            joined: false,
            out: vec![0; 64 * 1024],
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

        let is_joined =
            matches!(frame.state, quiche::multicast::ChannelState::Joined);

        if is_joined && !self.joined {
            self.integrity_receiver = self.shared.subscribe();
            self.pending_integrities.clear();
        } else if !is_joined {
            self.pending_integrities.clear();
        }

        self.joined = is_joined;
    }

    fn drain_integrities(&mut self) {
        loop {
            match self.integrity_receiver.try_recv() {
                Ok(integrity) => self.pending_integrities.push_back(integrity),

                Err(broadcast::error::TryRecvError::Lagged(..)) => continue,

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

    fn wait_for_data(
        &mut self, _qconn: &mut QuicheConnection,
    ) -> impl Future<Output = QuicResult<()>> + Send {
        async move {
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

                        Err(broadcast::error::RecvError::Lagged(..)) => continue,

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

        while let Some(integrity) = self.pending_integrities.pop_front() {
            qconn
                .multicast_send(quiche::multicast::Frame::Integrity(integrity))?;
        }

        Ok(())
    }

    fn on_conn_close<M: tokio_quiche::metrics::Metrics>(
        &mut self, _qconn: &mut QuicheConnection, _metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        self.pending_integrities.clear();
        self.joined = false;
        self.join_sent = false;
        println!(
            "control connection closed: result={}",
            if connection_result.is_ok() {
                "ok"
            } else {
                "error"
            },
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
        source: IpAddr::V4(source),
        group: IpAddr::V4(group),
        udp_port,
        header_protection_algorithm: DEFAULT_ENCRYPTION_ALGORITHM,
        header_secret: DEFAULT_HEADER_SECRET.to_vec(),
        aead_algorithm: DEFAULT_ENCRYPTION_ALGORITHM,
        integrity_hash_algorithm: DEFAULT_HASH_ALGORITHM,
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
    let shared = Arc::new(SharedControlChannel {
        announce,
        key,
        integrity_sender,
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
         interval={}ms",
        format_channel_id(&shared.announce.channel_id),
        source,
        group,
        udp_port,
        args.publish_interval_ms,
    );

    let publisher_shared = Arc::clone(&shared);
    let publisher_transfer = Arc::clone(&transfer);
    tokio::spawn(async move {
        if let Err(err) = publish_loop(
            publication,
            send_state,
            publisher_shared,
            publisher_transfer,
            publish_interval,
            args.manifest_interval_packets,
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
async fn publish_loop(
    publication: Publication,
    mut send_state: quiche::multicast::ChannelSendState,
    shared: Arc<SharedControlChannel>, transfer: Arc<PreparedTransfer>,
    publish_interval: Duration, manifest_interval_packets: u32,
) -> anyhow::Result<()> {
    let mut looping =
        LoopingTransfer::new((*transfer).clone(), manifest_interval_packets)?;
    let mut ticker = interval(publish_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut packet_buf = vec![0; 64 * 1024];
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
                let _ = shared.integrity_sender.send(output.integrity);
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

            Err(error) if publish_would_block(&error) => continue,

            Err(error) => return Err(anyhow::Error::new(error)),
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
fn format_channel_id(id: &[u8]) -> String {
    let mut out = String::with_capacity(id.len() * 2);
    for byte in id {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }

    out
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
