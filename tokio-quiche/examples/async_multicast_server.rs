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
        "async_multicast_server requires the `multicast` feature.\n\
         Run it with: cargo run -p tokio-quiche --example \
         async_multicast_server --features multicast -- --address \
         127.0.0.1:5757"
    );
    std::process::exit(1);
}

#[cfg(feature = "multicast")]
#[path = "async_http3_server/body.rs"]
mod body;
#[cfg(feature = "multicast")]
#[path = "async_http3_server/server.rs"]
mod server;

#[cfg(feature = "multicast")]
use std::collections::BTreeSet;
#[cfg(feature = "multicast")]
use std::net::Ipv4Addr;
#[cfg(feature = "multicast")]
use std::time::Duration;

#[cfg(feature = "multicast")]
use clap::Parser;
#[cfg(feature = "multicast")]
use futures::stream::StreamExt;
#[cfg(feature = "multicast")]
use mctx_core::PublicationConfig;
#[cfg(feature = "multicast")]
use tokio::net::UdpSocket;
#[cfg(feature = "multicast")]
use tokio::select;
#[cfg(feature = "multicast")]
use tokio::time::interval;
#[cfg(feature = "multicast")]
use tokio_quiche::http3::settings::Http3Settings;
#[cfg(feature = "multicast")]
use tokio_quiche::listen;
#[cfg(feature = "multicast")]
use tokio_quiche::metrics::DefaultMetrics;
#[cfg(feature = "multicast")]
use tokio_quiche::multicast::ServerChannelConfig;
#[cfg(feature = "multicast")]
use tokio_quiche::multicast::ServerDriver as MulticastServerDriver;
#[cfg(feature = "multicast")]
use tokio_quiche::multicast::ServerEvent;
#[cfg(feature = "multicast")]
use tokio_quiche::multicast::ServerSettings as MulticastServerSettings;
#[cfg(feature = "multicast")]
use tokio_quiche::settings::CertificateKind;
#[cfg(feature = "multicast")]
use tokio_quiche::settings::Hooks;
#[cfg(feature = "multicast")]
use tokio_quiche::settings::QuicSettings;
#[cfg(feature = "multicast")]
use tokio_quiche::settings::TlsCertificatePaths;
#[cfg(feature = "multicast")]
use tokio_quiche::ConnectionParams;
#[cfg(feature = "multicast")]
use tokio_quiche::ServerH3Driver;

#[cfg(feature = "multicast")]
use crate::server::service_fn;
#[cfg(feature = "multicast")]
use crate::server::Server;

#[cfg(feature = "multicast")]
#[derive(Parser, Debug)]
#[command(
    about = "Async tokio-quiche HTTP/3 server with IPv4 multicast publishing",
    version
)]
struct Args {
    /// The address for the QUIC server to listen on.
    #[arg(short, long)]
    address: String,

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

    /// Milliseconds between multicast packets after the client joins.
    #[arg(long, default_value_t = 1000)]
    publish_interval_ms: u64,

    /// Payload prefix to send in multicast DATAGRAM frames.
    #[arg(long, default_value = "hello multicast")]
    publish_text: String,
}

#[cfg(feature = "multicast")]
#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::parse();
    let socket = UdpSocket::bind(&args.address)
        .await
        .expect("UDP socket should be bindable");

    let mut quic_settings = QuicSettings::default();
    quic_settings.multicast_server_support = true;

    let multicast_settings = build_multicast_settings(&args);
    let publish_interval = Duration::from_millis(args.publish_interval_ms);
    let publish_text = args.publish_text.clone();
    let channel_id = multicast_settings.channels[0].channel_id.clone();

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
    .expect("should be able to create a listener from a UDP socket");

    let accepted_connection_stream = &mut listeners[0];
    while let Some(conn_res) = accepted_connection_stream.next().await {
        match conn_res {
            Ok(conn) => {
                log::info!("received new connection!");
                let connection_channel_id = channel_id.clone();
                let connection_publish_text = publish_text.clone();

                let (h3_driver, mut h3_controller) =
                    ServerH3Driver::new(Http3Settings::default());
                let (driver, mut multicast_controller) =
                    MulticastServerDriver::new(
                        h3_driver,
                        multicast_settings.clone(),
                    );

                conn.start(driver);

                tokio::spawn(async move {
                    let mut server = Server::new(service_fn);
                    let mut h3_events = h3_controller.take_event_receiver();
                    let _ = server.serve_connection(&mut h3_events).await;
                });

                tokio::spawn(async move {
                    drive_multicast(
                        &mut multicast_controller,
                        connection_channel_id,
                        publish_interval,
                        connection_publish_text,
                    )
                    .await;
                });
            },

            Err(e) => {
                log::error!("could not create connection: {e:?}");
            },
        }
    }
}

#[cfg(feature = "multicast")]
fn build_multicast_settings(args: &Args) -> MulticastServerSettings {
    MulticastServerSettings {
        channels: vec![ServerChannelConfig {
            channel_id: vec![1, 2, 3, 4],
            publication: PublicationConfig::new(
                args.multicast_group,
                args.multicast_port,
            )
            .with_source_addr(args.multicast_source)
            .with_interface(args.multicast_interface)
            .with_loopback(true),
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

#[cfg(feature = "multicast")]
async fn drive_multicast(
    controller: &mut tokio_quiche::multicast::ServerController,
    channel_id: Vec<u8>, publish_interval: Duration, publish_text: String,
) {
    let mut events = controller.take_event_receiver();
    let mut joined_channels = BTreeSet::new();
    let mut ticker = interval(publish_interval);
    let mut counter = 0u64;

    loop {
        select! {
            event = events.recv() => {
                let Some(event) = event else {
                    return;
                };

                match event {
                    ServerEvent::ClientLimits(frame) => {
                        log::info!("client multicast limits: {:?}", frame);
                    },

                    ServerEvent::ClientState(frame) => {
                        log::info!("client multicast state: {:?}", frame);

                        if frame.channel_id == channel_id {
                            match frame.state {
                                quiche::multicast::ChannelState::Joined => {
                                    joined_channels.insert(channel_id.clone());
                                },

                                quiche::multicast::ChannelState::Left |
                                quiche::multicast::ChannelState::Retired |
                                quiche::multicast::ChannelState::DeclinedJoin => {
                                    joined_channels.remove(&channel_id);
                                },
                            }
                        }
                    },

                    ServerEvent::ClientAck(frame) => {
                        log::info!("client multicast ack: {:?}", frame);
                    },

                    ServerEvent::Published {
                        channel_id,
                        packet_number,
                        report,
                    } => {
                        log::info!(
                            "published multicast packet channel={:?} pn={} bytes={} source={:?} destination={}",
                            channel_id,
                            packet_number,
                            report.bytes_sent,
                            report.source_addr,
                            report.destination,
                        );
                    },

                    ServerEvent::EncodeError { channel_id, error } => {
                        log::error!(
                            "multicast encode error channel={:?}: {:?}",
                            channel_id,
                            error,
                        );
                    },

                    ServerEvent::PublishError { channel_id, error } => {
                        log::error!(
                            "multicast publish error channel={:?}: {:?}",
                            channel_id,
                            error,
                        );
                    },
                }
            },

            _ = ticker.tick(), if joined_channels.contains(&channel_id) => {
                let payload =
                    format!("{publish_text} #{counter}").into_bytes();
                counter += 1;

                if controller
                    .send_on_channel(
                        channel_id.clone(),
                        vec![quiche::multicast::ChannelFrame::Datagram {
                            data: payload,
                        }],
                    )
                    .is_err()
                {
                    return;
                }
            },
        }
    }
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
