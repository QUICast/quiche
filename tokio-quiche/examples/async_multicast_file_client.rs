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
        "async_multicast_file_client requires the `multicast` feature.\n\
         Run it with: cargo run -p tokio-quiche --example \
         async_multicast_file_client --features multicast -- --connect-to \
         127.0.0.1:5757"
    );
    std::process::exit(1);
}

#[cfg(feature = "multicast")]
#[path = "support/heimdall_metrics.rs"]
mod heimdall_metrics;

#[cfg(feature = "multicast")]
#[path = "support/multicast_file.rs"]
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
use std::time::Instant;

#[cfg(feature = "multicast")]
use anyhow::Context;
#[cfg(feature = "multicast")]
use clap::Parser;
#[cfg(feature = "multicast")]
use heimdall_metrics::sample_receiver_metrics;
#[cfg(feature = "multicast")]
use heimdall_metrics::HeimdallJsonlMetadata;
#[cfg(feature = "multicast")]
use heimdall_metrics::HeimdallMetricsWriter;
#[cfg(feature = "multicast")]
use heimdall_metrics::ReceiverMetricSample;
#[cfg(feature = "multicast")]
use mcrx_core::SubscriptionMetricsSampler;
#[cfg(feature = "multicast")]
use tokio::net::UdpSocket;
#[cfg(feature = "multicast")]
use tokio::select;
#[cfg(feature = "multicast")]
use tokio::time::interval;
#[cfg(feature = "multicast")]
use tokio::time::sleep;
#[cfg(feature = "multicast")]
use tokio::time::MissedTickBehavior;
#[cfg(feature = "multicast")]
use tokio_quiche::multicast::ClientChannelMetricsSnapshot;
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
use crate::multicast_file::describe_hash_algorithm;
#[cfg(feature = "multicast")]
use crate::multicast_file::parse_hash_algorithm_id;
#[cfg(feature = "multicast")]
use crate::multicast_file::FileReceiver;
#[cfg(feature = "multicast")]
use crate::multicast_file::IdleApp;
#[cfg(feature = "multicast")]
use crate::multicast_file::ReceiveUpdate;
#[cfg(feature = "multicast")]
use crate::multicast_file::DEFAULT_ENCRYPTION_ALGORITHM;
#[cfg(feature = "multicast")]
use crate::multicast_file::DEFAULT_HASH_ALGORITHM_NAME;
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

    /// Supported multicast integrity hash algorithm to advertise.
    #[arg(long, default_value = DEFAULT_HASH_ALGORITHM_NAME)]
    integrity_hash_algorithm: String,

    /// Metadata-only hint for how many packet hashes the sender aggregates per
    /// `MC_INTEGRITY` frame.
    #[arg(long, default_value_t = 1)]
    integrity_hashes_per_frame: usize,

    /// Maximum number of multicast channel IDs to track.
    #[arg(long, default_value_t = 16)]
    max_channel_ids: u64,

    /// Optional IPv4 interface address to join multicast groups on.
    #[arg(long)]
    multicast_interface: Option<Ipv4Addr>,

    /// Whether to forward quiche's internal logs into the logger.
    #[arg(long, default_value_t = false)]
    capture_quiche_logs: bool,

    /// Seconds between multicast metrics summaries. Set to `0` to disable.
    #[arg(long, default_value_t = 5)]
    metrics_interval_secs: u64,

    /// Optional receiver metrics JSONL path for Heimdall ingestion.
    ///
    /// The network metrics use this exact path, and hardware metrics are
    /// written to a sibling `*_hardware.jsonl` file.
    #[arg(long)]
    heimdall_metrics_jsonl: Option<PathBuf>,
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

    let multicast_settings = build_multicast_settings(&args)?;
    let supported_hash_algorithm =
        multicast_settings.transport_params.hash_algorithms[0];
    let mut params =
        ConnectionParams::new_client(quic_settings, None, Hooks::default());
    params.multicast_client = Some(multicast_settings.clone());

    let (driver, mut controller) =
        MulticastClientDriver::new(IdleApp::new(), multicast_settings)?;
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
    println!(
        "multicast client hash support: {}",
        describe_hash_algorithm(supported_hash_algorithm),
    );

    let mut receiver = FileReceiver::default();
    let mut last_reported_pct = None;
    let mut latest_metrics: Option<(Vec<u8>, ClientChannelMetricsSnapshot)> =
        None;
    let mut heimdall_metrics_writer = args
        .heimdall_metrics_jsonl
        .clone()
        .map(|path| {
            HeimdallMetricsWriter::new(
                path,
                build_heimdall_metadata(&args, supported_hash_algorithm),
            )
        })
        .transpose()?;
    let mut previous_socket_metrics = SubscriptionMetricsSampler::new();
    let mut previous_receive_metrics = None;
    let mut last_metrics_at = Instant::now();
    let mut decode_errors_total = 0_u64;
    let mut last_decode_errors = 0_u64;
    let mut receive_errors_total = 0_u64;
    let mut last_receive_errors = 0_u64;
    let mut events = controller
        .take_event_receiver()
        .ok_or_else(|| anyhow::anyhow!("multicast event receiver was taken"))?;
    let emit_console_metrics = args.metrics_interval_secs > 0;
    let emit_heimdall_metrics = heimdall_metrics_writer.is_some();
    let metrics_tick_secs = if emit_console_metrics || emit_heimdall_metrics {
        args.metrics_interval_secs.max(1)
    } else {
        1
    };
    let mut metrics_tick = interval(Duration::from_secs(metrics_tick_secs));
    metrics_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    if emit_console_metrics || emit_heimdall_metrics {
        metrics_tick.tick().await;
    }
    let timeout = sleep(Duration::from_secs(args.max_run_secs));
    tokio::pin!(timeout);

    if let Some(writer) = heimdall_metrics_writer.as_ref() {
        println!(
            "heimdall metrics export: network={} hardware={} quiche={}",
            writer.network_path().display(),
            writer
                .hardware_path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<unsupported>".to_string()),
            writer.quiche_path().display(),
        );
    }

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

                    ClientEvent::MetricsUpdated { channel_id, metrics } => {
                        latest_metrics = Some((channel_id, metrics));
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
                        decode_errors_total =
                            decode_errors_total.saturating_add(1);
                        eprintln!(
                            "multicast decode error on channel {}: {error:?}",
                            format_channel_id(&channel_id),
                        );
                    },

                    ClientEvent::ReceiveError {
                        channel_id,
                        error,
                    } => {
                        receive_errors_total =
                            receive_errors_total.saturating_add(1);
                        eprintln!(
                            "multicast receive error on channel {}: {error}",
                            format_channel_id(&channel_id),
                        );
                    },

                    ClientEvent::IngressOverload {
                        channel_id,
                        retained_bytes,
                        max_retained_bytes,
                    } => {
                        receive_errors_total =
                            receive_errors_total.saturating_add(1);
                        eprintln!(
                            "multicast ingress overload on channel {}: \
                             item={}B limit={}B; channel returned to fallback",
                            format_channel_id(&channel_id),
                            retained_bytes,
                            max_retained_bytes,
                        );
                    },
                }
            },

            _ = metrics_tick.tick(), if emit_console_metrics || emit_heimdall_metrics => {
                let Some((channel_id, metrics)) = latest_metrics.as_ref() else {
                    continue;
                };
                let decode_errors =
                    decode_errors_total.saturating_sub(last_decode_errors);
                last_decode_errors = decode_errors_total;
                let receive_errors =
                    receive_errors_total.saturating_sub(last_receive_errors);
                last_receive_errors = receive_errors_total;
                let Some(sample) = sample_receiver_metrics(
                    metrics,
                    &mut previous_socket_metrics,
                    &mut previous_receive_metrics,
                    decode_errors,
                    receive_errors,
                ) else {
                    continue;
                };

                if emit_console_metrics {
                    let interval_secs = last_metrics_at.elapsed().as_secs_f64();
                    last_metrics_at = Instant::now();
                    print_metrics_summary(channel_id, &sample, interval_secs);
                }

                if let Some(writer) = heimdall_metrics_writer.as_mut() {
                    writer.write_receiver_sample(channel_id, &sample)?;
                }
            },
        }
    }
}

#[cfg(feature = "multicast")]
fn build_multicast_settings(
    args: &Args,
) -> anyhow::Result<MulticastClientSettings> {
    let hash_algorithm = parse_hash_algorithm_id(&args.integrity_hash_algorithm)?;

    Ok(MulticastClientSettings {
        transport_params: quiche::multicast::ClientTransportParams {
            limits: quiche::multicast::ClientLimits {
                ipv6_channels_allowed: false,
                ipv4_channels_allowed: true,
                max_aggregate_rate_kibps: args.max_aggregate_rate_kibps,
                max_channel_ids: args.max_channel_ids,
            },
            hash_algorithms: vec![hash_algorithm],
            encryption_algorithms: vec![DEFAULT_ENCRYPTION_ALGORITHM],
        },
        max_joined_channels: args.max_joined_channels,
        ipv4_interface: args.multicast_interface,
        ipv6_interface: None,
    })
}

#[cfg(feature = "multicast")]
fn build_heimdall_metadata(
    args: &Args, supported_hash_algorithm: u16,
) -> HeimdallJsonlMetadata {
    HeimdallJsonlMetadata {
        node_id: None,
        producer: "tokio-quiche/async_multicast_file_client",
        transport: "quic-multicast-draft-08".to_string(),
        role: "receiver".to_string(),
        connect_to: args.connect_to.to_string(),
        multicast_interface: args
            .multicast_interface
            .map(|addr| addr.to_string()),
        integrity_hash_algorithm: describe_hash_algorithm(
            supported_hash_algorithm,
        )
        .to_string(),
        integrity_hash_algorithm_id: supported_hash_algorithm,
        integrity_hashes_per_frame: args.integrity_hashes_per_frame,
        max_joined_channels: args.max_joined_channels,
        max_aggregate_rate_kibps: args.max_aggregate_rate_kibps,
        max_channel_ids: args.max_channel_ids,
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

#[cfg(feature = "multicast")]
fn print_metrics_summary(
    channel_id: &[u8], sample: &ReceiverMetricSample, interval_secs: f64,
) {
    println!(
        "[metrics] channel={} interval={:.2}s socket_rx_pps={:.1} \
         socket_rx_mbps={:.3} decode_rx_pps={:.1} decode_rx_mbps={:.3} \
         would_block={} socket_rx_errors={}",
        format_channel_id(channel_id),
        interval_secs,
        sample.socket_delta.packets_per_sec(),
        ((sample.socket_delta.bytes_per_sec() * 8.0) / 1_000_000.0),
        sample.receive_delta.recv_calls as f64 / interval_secs.max(f64::EPSILON),
        ((sample.receive_delta.recv_bytes as f64 * 8.0) / 1_000_000.0) /
            interval_secs.max(f64::EPSILON),
        sample.socket_delta.would_block_count,
        sample.socket_delta.receive_errors,
    );
    println!(
        "[metrics] delivered={} inline={} after_key={} after_integrity={} \
         pending={} wait_key={} wait_integrity={} last_src={} \
         last_payload={:?}",
        sample.receive_delta.packets_delivered,
        sample.receive_delta.packets_released_on_recv,
        sample.receive_delta.packets_released_on_key,
        sample.receive_delta.packets_released_on_integrity,
        sample.receive.pending_packets,
        sample.receive.waiting_for_key_packets,
        sample.receive.waiting_for_integrity_packets,
        sample
            .socket
            .last_source
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "-".to_string()),
        sample.socket.last_payload_len,
    );
    println!(
        "[metrics] task_rx_failures={} decode_errors={} dup_pkts={} \
         invalid_pkt={} invalid_frame={} integrity_mismatch={} decrypt={} \
         largest_pn={}",
        sample.receive_task_errors,
        sample.decode_errors,
        sample.receive_delta.duplicate_packets,
        sample.receive_delta.invalid_packet_errors,
        sample.receive_delta.invalid_frame_errors,
        sample.receive_delta.integrity_mismatch_errors,
        sample.receive_delta.decrypt_errors,
        sample.receive.largest_observed_packet_number,
    );
}
