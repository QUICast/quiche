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
        "async_multicast_file_client requires the `multicast` feature.\n\
         Run it with: cargo run -p tokio-quiche --example \
         async_multicast_file_client --features multicast -- --connect-to \
         127.0.0.1:5757"
    );
    std::process::exit(1);
}

#[cfg(feature = "multicast")]
mod multicast_file;

#[cfg(feature = "multicast")]
use std::net::Ipv4Addr;
#[cfg(feature = "multicast")]
use std::net::SocketAddr;
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
use tokio::net::UdpSocket;
#[cfg(feature = "multicast")]
use tokio::select;
#[cfg(feature = "multicast")]
use tokio::time::sleep;
#[cfg(feature = "multicast")]
use tokio_quiche::multicast::ClientDriver as MulticastClientDriver;
#[cfg(feature = "multicast")]
use tokio_quiche::multicast::ClientEvent;
#[cfg(feature = "multicast")]
use tokio_quiche::multicast::ClientSettings as MulticastClientSettings;
#[cfg(feature = "multicast")]
use tokio_quiche::quic::connect_with_config;
#[cfg(feature = "multicast")]
use tokio_quiche::settings::Hooks;
#[cfg(feature = "multicast")]
use tokio_quiche::settings::QuicSettings;
#[cfg(feature = "multicast")]
use tokio_quiche::socket::Socket;
#[cfg(feature = "multicast")]
use tokio_quiche::ConnectionParams;

#[cfg(feature = "multicast")]
use crate::multicast_file::decode_file_packet;
#[cfg(feature = "multicast")]
use crate::multicast_file::FileReceiver;
#[cfg(feature = "multicast")]
use crate::multicast_file::IdleApp;
#[cfg(feature = "multicast")]
use crate::multicast_file::ReceiveUpdate;
#[cfg(feature = "multicast")]
use crate::multicast_file::DEFAULT_ENCRYPTION_ALGORITHM;
#[cfg(feature = "multicast")]
use crate::multicast_file::DEFAULT_HASH_ALGORITHM;
#[cfg(feature = "multicast")]
use crate::multicast_file::FILE_CHANNEL_ID;

#[cfg(feature = "multicast")]
#[derive(Parser, Debug)]
#[command(
    about = "Receives a looped multicast file over tokio-quiche draft multicast",
    version
)]
struct Args {
    /// The UDP address of the QUIC control server.
    #[arg(long)]
    connect_to: SocketAddr,

    /// TLS server name / SNI to use for the QUIC connection.
    #[arg(long, default_value = "test.com")]
    server_name: String,

    /// The local UDP address to bind before connecting.
    #[arg(long)]
    bind: Option<SocketAddr>,

    /// Optional output file path. Defaults to the name from the manifest.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Whether to verify the server certificate.
    #[arg(long, default_value_t = false)]
    verify_peer: bool,

    /// Maximum run time before the example exits with a timeout.
    #[arg(long, default_value_t = 120)]
    max_run_secs: u64,

    /// QUIC idle timeout in seconds.
    #[arg(long, default_value_t = 300)]
    idle_timeout_secs: u64,

    /// Maximum number of joined multicast channels.
    #[arg(long, default_value_t = 4)]
    max_joined_channels: u64,

    /// Maximum aggregate IPv4 multicast receive rate in Kibps.
    #[arg(long, default_value_t = 8192)]
    max_aggregate_rate_kibps: u64,

    /// Maximum number of multicast channel IDs to track.
    #[arg(long, default_value_t = 16)]
    max_channel_ids: u64,

    /// Optional IPv4 interface address to join multicast groups on.
    #[arg(long)]
    multicast_interface: Option<Ipv4Addr>,

    /// Whether to forward quiche's internal logs into the logger.
    #[arg(long, default_value_t = false)]
    capture_quiche_logs: bool,
}

#[cfg(feature = "multicast")]
#[tokio::main(flavor = "current_thread")]
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
    let bind_addr = args
        .bind
        .unwrap_or_else(|| default_bind_addr(args.connect_to));

    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind UDP socket on {bind_addr}"))?;
    socket.connect(args.connect_to).await.with_context(|| {
        format!("failed to connect UDP socket to {}", args.connect_to)
    })?;

    #[cfg_attr(not(target_os = "linux"), expect(unused_mut))]
    let mut socket = Socket::<Arc<UdpSocket>, Arc<UdpSocket>>::from_udp(socket)?;

    #[cfg(target_os = "linux")]
    socket.apply_max_capabilities();

    let mut quic_settings = QuicSettings::default();
    quic_settings.capture_quiche_logs = args.capture_quiche_logs;
    quic_settings.max_idle_timeout =
        Some(Duration::from_secs(args.idle_timeout_secs));
    quic_settings.verify_peer = args.verify_peer;

    let multicast_settings = build_multicast_settings(&args);
    let mut params =
        ConnectionParams::new_client(quic_settings, None, Hooks::default());
    params.multicast_client = Some(multicast_settings.clone());

    let (driver, mut controller) =
        MulticastClientDriver::new(IdleApp::new(), multicast_settings);
    let conn =
        connect_with_config(socket, Some(&args.server_name), &params, driver)
            .await
            .map_err(|err| {
                anyhow::anyhow!("failed to establish QUIC connection: {err}")
            })?;

    println!(
        "connected over QUIC: local={} peer={} scid={}",
        conn.local_addr(),
        conn.peer_addr(),
        format_channel_id(conn.scid().as_ref()),
    );

    let mut receiver = FileReceiver::default();
    let mut last_reported_pct = None;
    let mut events = controller.take_event_receiver();
    let timeout = sleep(Duration::from_secs(args.max_run_secs));
    tokio::pin!(timeout);

    loop {
        select! {
            _ = &mut timeout => {
                anyhow::bail!(
                    "timed out after {}s before receiving the full file",
                    args.max_run_secs
                );
            },

            event = events.recv() => {
                let Some(event) = event else {
                    anyhow::bail!("multicast event stream closed");
                };

                match event {
                    ClientEvent::Announce(frame) => {
                        println!(
                            "multicast announce: channel={} source={} group={} \
                             port={} rate={}KiBps ack_delay={}ms",
                            format_channel_id(&frame.channel_id),
                            frame.source,
                            frame.group,
                            frame.udp_port,
                            frame.max_rate_kibps,
                            frame.max_ack_delay_ms,
                        );
                    },

                    ClientEvent::UnsupportedIpv6Announce(frame) => {
                        println!(
                            "ignoring IPv6 announce for channel {}: source={} \
                             group={}",
                            format_channel_id(&frame.channel_id),
                            frame.source,
                            frame.group,
                        );
                    },

                    ClientEvent::LocalState(frame) => {
                        println!(
                            "multicast local state: channel={} sequence={} \
                             state={:?} reason_scope={:?} reason_code={} \
                             phrase={}",
                            format_channel_id(&frame.channel_id),
                            frame.sequence,
                            frame.state,
                            frame.reason_scope,
                            frame.reason_code,
                            String::from_utf8_lossy(&frame.reason_phrase),
                        );
                    },

                    ClientEvent::Packet {
                        channel_id,
                        packet,
                        received: _,
                    } => {
                        if channel_id != FILE_CHANNEL_ID {
                            continue;
                        }

                        for frame in packet.frames {
                            let quiche::multicast::ChannelFrame::Datagram { data } = frame else {
                                continue;
                            };

                            let Some(file_packet) = decode_file_packet(&data)
                                .map_err(anyhow::Error::msg)?
                            else {
                                continue;
                            };

                            match receiver
                                .apply(file_packet)
                                .map_err(anyhow::Error::msg)?
                            {
                                ReceiveUpdate::Ignored => (),

                                ReceiveUpdate::Manifest(manifest) => {
                                    println!(
                                        "file manifest: transfer={} name={} \
                                         bytes={} chunks={} chunk_payload={}",
                                        manifest.transfer_id,
                                        manifest.file_name,
                                        manifest.file_len,
                                        manifest.total_chunks,
                                        manifest.chunk_payload_len,
                                    );
                                },

                                ReceiveUpdate::ChunkStored {
                                    received_chunks,
                                    total_chunks,
                                    ..
                                } => {
                                    let pct = if total_chunks == 0 {
                                        100
                                    } else {
                                        (received_chunks * 100) / total_chunks
                                    };

                                    if last_reported_pct != Some(pct) &&
                                        (pct == 100 || pct >= last_reported_pct.unwrap_or(0) + 10)
                                    {
                                        println!(
                                            "progress: {received_chunks}/{total_chunks} \
                                             chunks ({pct}%)"
                                        );
                                        last_reported_pct = Some(pct);
                                    }
                                },

                                ReceiveUpdate::Complete(file) => {
                                    let output = args.output.clone().unwrap_or_else(|| {
                                        PathBuf::from(&file.manifest.file_name)
                                    });
                                    std::fs::write(&output, &file.bytes).with_context(|| {
                                        format!("failed to write {}", output.display())
                                    })?;

                                    println!(
                                        "file complete: transfer={} bytes={} saved_to={}",
                                        file.manifest.transfer_id,
                                        file.bytes.len(),
                                        output.display(),
                                    );
                                    return Ok(());
                                },
                            }
                        }
                    },

                    ClientEvent::DecodeError {
                        channel_id,
                        error,
                        packet: _,
                    } => {
                        eprintln!(
                            "multicast decode error on channel {}: {error:?}",
                            format_channel_id(&channel_id),
                        );
                    },

                    ClientEvent::ReceiveError {
                        channel_id,
                        error,
                    } => {
                        eprintln!(
                            "multicast receive error on channel {}: {error}",
                            format_channel_id(&channel_id),
                        );
                    },
                }
            },
        }
    }
}

#[cfg(feature = "multicast")]
fn build_multicast_settings(args: &Args) -> MulticastClientSettings {
    MulticastClientSettings {
        transport_params: quiche::multicast::ClientTransportParams {
            limits: quiche::multicast::ClientLimits {
                ipv6_channels_allowed: false,
                ipv4_channels_allowed: true,
                max_aggregate_rate_kibps: args.max_aggregate_rate_kibps,
                max_channel_ids: args.max_channel_ids,
            },
            hash_algorithms: vec![DEFAULT_HASH_ALGORITHM],
            encryption_algorithms: vec![DEFAULT_ENCRYPTION_ALGORITHM],
        },
        max_joined_channels: args.max_joined_channels,
        ipv4_interface: args.multicast_interface,
        ipv6_interface: None,
    }
}

#[cfg(feature = "multicast")]
fn default_bind_addr(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    }
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
