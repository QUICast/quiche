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
        "async_multicast_client requires the `multicast` feature.\n\
         Run it with: cargo run -p tokio-quiche --example \
         async_multicast_client --features multicast -- <URL> --connect-to \
         <ADDR:PORT>"
    );
    std::process::exit(1);
}

#[cfg(feature = "multicast")]
use std::fmt::Write;
#[cfg(feature = "multicast")]
use std::net::IpAddr;
#[cfg(feature = "multicast")]
use std::net::Ipv4Addr;
#[cfg(feature = "multicast")]
use std::net::SocketAddr;
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
use tokio_quiche::http3::driver::ClientH3Event;
#[cfg(feature = "multicast")]
use tokio_quiche::http3::driver::H3Event;
#[cfg(feature = "multicast")]
use tokio_quiche::http3::driver::InboundFrame;
#[cfg(feature = "multicast")]
use tokio_quiche::http3::driver::NewClientRequest;
#[cfg(feature = "multicast")]
use tokio_quiche::http3::settings::Http3Settings;
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
use tokio_quiche::ClientH3Driver;
#[cfg(feature = "multicast")]
use tokio_quiche::ConnectionParams;
#[cfg(feature = "multicast")]
use url::Url;

#[cfg(feature = "multicast")]
const DEFAULT_HASH_ALGORITHM: u16 = 1;
#[cfg(feature = "multicast")]
const DEFAULT_ENCRYPTION_ALGORITHM: u16 = 0x1301;

#[cfg(feature = "multicast")]
#[derive(Parser, Debug)]
#[command(
    about = "Connects with tokio-quiche HTTP/3 plus IPv4 multicast reception",
    version
)]
struct Args {
    /// The request URL to send over HTTP/3.
    url: Url,

    /// The UDP address of the QUIC server.
    #[arg(long)]
    connect_to: SocketAddr,

    /// The local UDP address to bind before connecting.
    #[arg(long)]
    bind: Option<SocketAddr>,

    /// Whether to verify the server certificate.
    #[arg(long, default_value_t = false)]
    verify_peer: bool,

    /// How long to keep the example running after the connection starts.
    #[arg(long, default_value_t = 30)]
    run_for_secs: u64,

    /// QUIC idle timeout in seconds.
    #[arg(long, default_value_t = 30)]
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
    let host = args
        .url
        .host_str()
        .context("request URL must include a host")?
        .to_string();

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

    let (h3_driver, mut h3_controller) =
        ClientH3Driver::new(Http3Settings::default());
    let (driver, mut multicast_controller) =
        MulticastClientDriver::new(h3_driver, multicast_settings)?;

    let conn = connect_with_config(socket, Some(&host), &params, driver)
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
        "multicast support: ipv4_only=true max_joined_channels={}",
        args.max_joined_channels
    );

    h3_controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers: build_request_headers(&args.url)?,
            body_writer: None,
        })
        .map_err(|_| {
            anyhow::anyhow!("failed to send HTTP/3 request to driver")
        })?;

    let mut h3_events = h3_controller.take_event_receiver();
    let mut multicast_events = multicast_controller
        .take_event_receiver()
        .ok_or_else(|| anyhow::anyhow!("multicast event receiver was taken"))?;
    let timeout = sleep(Duration::from_secs(args.run_for_secs));
    tokio::pin!(timeout);

    loop {
        select! {
            event = h3_events.recv() => {
                let Some(event) = event else {
                    println!("http3 event stream closed");
                    break;
                };

                if handle_h3_event(event) {
                    break;
                }
            },

            event = multicast_events.recv() => {
                let Some(event) = event else {
                    println!("multicast event stream closed");
                    break;
                };

                handle_multicast_event(event);
            },

            _ = &mut timeout => {
                println!("run timeout reached after {}s", args.run_for_secs);
                break;
            },
        }
    }

    Ok(())
}

#[cfg(feature = "multicast")]
fn default_bind_addr(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) =>
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),

        SocketAddr::V6(_) =>
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
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
fn build_request_headers(url: &Url) -> anyhow::Result<Vec<quiche::h3::Header>> {
    let authority = url_authority(url)?;
    let path = url_path(url);

    Ok(vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(
            b"user-agent",
            b"tokio-quiche-async-multicast-client",
        ),
    ])
}

#[cfg(feature = "multicast")]
fn url_authority(url: &Url) -> anyhow::Result<String> {
    let host = url.host_str().context("request URL must include a host")?;

    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

#[cfg(feature = "multicast")]
fn url_path(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

#[cfg(feature = "multicast")]
fn handle_h3_event(event: ClientH3Event) -> bool {
    match event {
        ClientH3Event::NewOutboundRequest {
            stream_id,
            request_id,
        } => {
            println!(
                "http3 request sent: request_id={request_id} stream_id={stream_id}"
            );
            false
        },

        ClientH3Event::Core(event) => handle_core_h3_event(event),
    }
}

#[cfg(feature = "multicast")]
fn handle_core_h3_event(event: H3Event) -> bool {
    match event {
        H3Event::IncomingSettings { settings } => {
            println!("http3 settings: {settings:?}");
            false
        },

        H3Event::IncomingHeaders(headers) => {
            let stream_id = headers.stream_id;
            let read_fin = headers.read_fin;

            println!(
                "http3 response headers on stream {stream_id}: {:?}",
                headers.headers
            );
            println!("http3 response read_fin={read_fin}");

            tokio::spawn(async move {
                drain_response_body(stream_id, headers.recv).await;
            });

            false
        },

        H3Event::BodyBytesReceived {
            stream_id,
            num_bytes,
            fin,
        } => {
            println!(
                "http3 body progress: stream={stream_id} bytes={num_bytes} fin={fin}"
            );
            false
        },

        H3Event::NewFlow { flow_id, .. } => {
            println!("http3 datagram flow created: flow_id={flow_id}");
            false
        },

        H3Event::ResetStream { stream_id } => {
            println!("http3 reset stream: stream_id={stream_id}");
            false
        },

        H3Event::StreamClosed { stream_id } => {
            println!("http3 stream closed: stream_id={stream_id}");
            false
        },

        H3Event::RawStreamData {
            stream_id,
            data,
            fin,
        } => {
            println!(
                "http3 raw stream data: stream={stream_id} bytes={} fin={fin}",
                data.len()
            );
            false
        },

        H3Event::WebTransportStreamData {
            session_id,
            stream_id,
            direction,
            data,
            fin,
        } => {
            println!(
                "http3 webtransport stream data: session={session_id} stream={stream_id} direction={direction:?} bytes={} fin={fin}",
                data.len()
            );
            false
        },

        H3Event::WebTransportDiagnostic(diagnostic) => {
            println!("http3 webtransport diagnostic: {diagnostic:?}");
            false
        },

        H3Event::ConnectionError(err) => {
            println!("http3 connection error: {err:?}");
            true
        },

        H3Event::ConnectionShutdown(reason) => {
            println!("http3 connection shutdown: {reason:?}");
            true
        },
    }
}

#[cfg(feature = "multicast")]
async fn drain_response_body(
    stream_id: u64, mut recv: tokio::sync::mpsc::Receiver<InboundFrame>,
) {
    while let Some(frame) = recv.recv().await {
        match frame {
            InboundFrame::Body(data, fin) => {
                println!(
                    "http3 body chunk: stream={stream_id} bytes={} fin={} data={}",
                    data.len(),
                    fin,
                    preview_text_or_hex(data.as_ref(), 64),
                );
            },

            InboundFrame::Datagram(data) => {
                println!(
                    "http3 datagram body: stream={stream_id} bytes={} data={}",
                    data.len(),
                    hex_prefix(data.as_ref(), 32),
                );
            },
        }
    }
}

#[cfg(feature = "multicast")]
fn handle_multicast_event(event: ClientEvent) {
    match event {
        ClientEvent::Announce(announce) => {
            println!(
                "multicast announce: channel={} source={} group={} port={} \
                 rate={}KiBps ack_delay={}ms",
                format_channel_id(&announce.channel_id),
                announce.source,
                announce.group,
                announce.udp_port,
                announce.max_rate_kibps,
                announce.max_ack_delay_ms,
            );
        },

        ClientEvent::UnsupportedIpv6Announce(announce) => {
            println!(
                "multicast announce skipped (ipv6 placeholder): channel={} \
                 source={} group={} port={}",
                format_channel_id(&announce.channel_id),
                announce.source,
                announce.group,
                announce.udp_port,
            );
        },

        ClientEvent::LocalState(state) => {
            println!(
                "multicast local state: channel={} sequence={} state={:?} \
                 reason_scope={:?} reason_code={} phrase={}",
                format_channel_id(&state.channel_id),
                state.sequence,
                state.state,
                state.reason_scope,
                state.reason_code,
                String::from_utf8_lossy(&state.reason_phrase),
            );
        },

        ClientEvent::MetricsUpdated {
            channel_id,
            metrics,
        } => {
            println!(
                "multicast metrics: channel={} socket_pkts={} socket_bytes={} \
                 recv_calls={} delivered={} pending={} wait_key={} \
                 wait_integrity={}",
                format_channel_id(&channel_id),
                metrics.socket.packets_received,
                metrics.socket.bytes_received,
                metrics.receive.recv_calls,
                metrics.receive.packets_delivered,
                metrics.receive.pending_packets,
                metrics.receive.waiting_for_key_packets,
                metrics.receive.waiting_for_integrity_packets,
            );
        },

        ClientEvent::Packet {
            channel_id,
            packet,
            received,
        } => {
            println!(
                "multicast packet: channel={} pn={} key_seq={} key_phase={} \
                 from={} group={} dst_port={} payload={}B metadata={:?}",
                format_channel_id(&channel_id),
                packet.packet_number,
                packet.key_sequence,
                packet.key_phase,
                received.packet.source,
                received.packet.group,
                received.packet.dst_port,
                received.packet.payload_len(),
                received.metadata,
            );

            for frame in &packet.frames {
                println!("  frame: {}", describe_channel_frame(frame));
            }
        },

        ClientEvent::DecodeError {
            channel_id,
            error,
            packet,
        } => {
            println!(
                "multicast decode error: channel={} error={error:?} from={} \
                 group={} dst_port={} payload={}B",
                format_channel_id(&channel_id),
                packet.packet.source,
                packet.packet.group,
                packet.packet.dst_port,
                packet.packet.payload_len(),
            );
        },

        ClientEvent::ReceiveError { channel_id, error } => {
            println!(
                "multicast receive error: channel={} error={error:?}",
                format_channel_id(&channel_id),
            );
        },

        ClientEvent::IngressOverload {
            channel_id,
            retained_bytes,
            max_retained_bytes,
        } => {
            println!(
                "multicast ingress overload: channel={} item={}B limit={}B; \
                 channel returned to fallback",
                format_channel_id(&channel_id),
                retained_bytes,
                max_retained_bytes,
            );
        },
    }
}

#[cfg(feature = "multicast")]
fn describe_channel_frame(frame: &quiche::multicast::ChannelFrame) -> String {
    match frame {
        quiche::multicast::ChannelFrame::Padding { len } => {
            format!("PADDING len={len}")
        },

        quiche::multicast::ChannelFrame::Ping => "PING".to_string(),

        quiche::multicast::ChannelFrame::ResetStream {
            stream_id,
            error_code,
            final_size,
        } => format!(
            "RESET_STREAM stream_id={stream_id} error_code={error_code} \
             final_size={final_size}"
        ),

        quiche::multicast::ChannelFrame::ResetStreamAt {
            stream_id,
            error_code,
            final_size,
            reliable_size,
        } => format!(
            "RESET_STREAM_AT stream_id={stream_id} error_code={error_code} \
             final_size={final_size} reliable_size={reliable_size}"
        ),

        quiche::multicast::ChannelFrame::Stream {
            stream_id,
            offset,
            fin,
            data,
        } => format!(
            "STREAM stream_id={stream_id} offset={offset} fin={fin} len={} \
             data={}",
            data.len(),
            preview_text_or_hex(data, 32),
        ),

        quiche::multicast::ChannelFrame::Datagram { data } =>
            format!("DATAGRAM len={} data={}", data.len(), hex_prefix(data, 32),),

        quiche::multicast::ChannelFrame::Multicast(frame) => {
            format!("MC frame={frame:?}")
        },
    }
}

#[cfg(feature = "multicast")]
fn format_channel_id(channel_id: &[u8]) -> String {
    hex_prefix(channel_id, usize::MAX)
}

#[cfg(feature = "multicast")]
fn preview_text_or_hex(data: &[u8], max_len: usize) -> String {
    if data.is_empty() {
        return "<empty>".to_string();
    }

    let capped = &data[..data.len().min(max_len)];

    match std::str::from_utf8(capped) {
        Ok(text) if capped.len() == data.len() => format!("{text:?}"),
        Ok(text) => format!("{text:?}..."),
        Err(_) => hex_prefix(data, max_len),
    }
}

#[cfg(feature = "multicast")]
fn hex_prefix(data: &[u8], max_len: usize) -> String {
    if data.is_empty() {
        return "<empty>".to_string();
    }

    let mut out = String::new();
    let take = data.len().min(max_len);

    for byte in &data[..take] {
        let _ = write!(&mut out, "{byte:02x}");
    }

    if take < data.len() {
        out.push_str("...");
    }

    out
}
