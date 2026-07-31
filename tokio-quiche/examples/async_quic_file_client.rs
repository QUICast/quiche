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

use std::future::pending;
use std::future::Future;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_quiche::quic::connect_with_config;
use tokio_quiche::quic::HandshakeInfo;
use tokio_quiche::quic::QuicConnectionStats;
use tokio_quiche::quic::QuicheConnection;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::socket::Socket;
use tokio_quiche::ApplicationOverQuic;
use tokio_quiche::ConnectionParams;
use tokio_quiche::QuicResult;

const REQUEST_STREAM_ID: u64 = 0;

#[derive(Parser, Debug)]
#[command(
    about = "Downloads a file over one raw QUIC stream from async_quic_file_server",
    version
)]
struct Args {
    /// The UDP address of the QUIC server.
    #[arg(long)]
    connect_to: SocketAddr,

    /// TLS server name / SNI to use for the QUIC connection.
    #[arg(long, default_value = "test.com")]
    server_name: String,

    /// The local UDP address to bind before connecting.
    #[arg(long)]
    bind: Option<SocketAddr>,

    /// The output file path.
    #[arg(long)]
    output: PathBuf,

    /// Optional JSON file path for QUIC transfer stats.
    #[arg(long)]
    stats_json: Option<PathBuf>,

    /// Whether to verify the server certificate.
    #[arg(long, default_value_t = false)]
    verify_peer: bool,

    /// QUIC idle timeout in seconds.
    #[arg(long, default_value_t = 30)]
    idle_timeout_secs: u64,

    /// Hard stop for the transfer.
    #[arg(long, default_value_t = 300)]
    max_run_secs: u64,

    /// Whether to forward quiche's internal logs into the logger.
    #[arg(long, default_value_t = false)]
    capture_quiche_logs: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

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

    let mut params =
        ConnectionParams::new_client(quic_settings, None, Hooks::default());
    params.settings.max_idle_timeout =
        Some(Duration::from_secs(args.idle_timeout_secs));

    let (done_tx, done_rx) = oneshot::channel();
    let app = FileClientApp::new(done_tx);
    let started_at = Instant::now();
    let conn = connect_with_config(socket, Some(&args.server_name), &params, app)
        .await
        .map_err(|err| {
            anyhow::anyhow!("failed to establish QUIC connection: {err}")
        })?;

    println!(
        "connected over QUIC: local={} peer={} scid={}",
        conn.local_addr(),
        conn.peer_addr(),
        format_cid(conn.scid().as_ref()),
    );

    let response_bytes = timeout(Duration::from_secs(args.max_run_secs), done_rx)
        .await
        .context("timed out waiting for QUIC file response")?
        .context("QUIC file transfer worker dropped completion signal")??;

    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create parent directory for {}",
                args.output.display()
            )
        })?;
    }

    std::fs::write(&args.output, &response_bytes)
        .with_context(|| format!("failed to write {}", args.output.display()))?;

    let elapsed = started_at.elapsed();
    let stats = conn.stats().lock().unwrap();

    println!(
        "file complete: bytes={} saved_to={} elapsed_ms={}",
        response_bytes.len(),
        args.output.display(),
        elapsed.as_millis(),
    );
    print_stats_summary(&stats);

    if let Some(stats_path) = args.stats_json.as_deref() {
        write_stats_json(stats_path, response_bytes.len(), elapsed, &stats)?;
        println!("wrote stats: {}", stats_path.display());
    }

    Ok(())
}

struct FileClientApp {
    request_sent: bool,
    response_complete: bool,
    response_bytes: Vec<u8>,
    done_tx: Option<oneshot::Sender<anyhow::Result<Vec<u8>>>>,
}

impl FileClientApp {
    fn new(done_tx: oneshot::Sender<anyhow::Result<Vec<u8>>>) -> Self {
        Self {
            request_sent: false,
            response_complete: false,
            response_bytes: Vec::new(),
            done_tx: Some(done_tx),
        }
    }

    fn complete(&mut self, result: anyhow::Result<Vec<u8>>) {
        if let Some(done_tx) = self.done_tx.take() {
            let _ = done_tx.send(result);
        }
    }
}

impl ApplicationOverQuic for FileClientApp {
    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection, handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        println!(
            "client connection established: trace_id={} handshake={:?}",
            qconn.trace_id(),
            handshake_info.elapsed(),
        );

        Ok(())
    }

    fn should_act(&self) -> bool {
        !self.response_complete
    }

    fn wait_for_data(
        &mut self, _qconn: &mut QuicheConnection,
    ) -> impl Future<Output = QuicResult<()>> + Send {
        pending::<QuicResult<()>>()
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let mut recv_buf = [0; 16 * 1024];

        for stream_id in qconn.readable() {
            loop {
                match qconn.stream_recv(stream_id, &mut recv_buf) {
                    Ok((read, fin)) => {
                        self.response_bytes.extend_from_slice(&recv_buf[..read]);

                        if fin {
                            self.response_complete = true;
                            let response_bytes =
                                std::mem::take(&mut self.response_bytes);
                            self.complete(Ok(response_bytes));
                            return Ok(());
                        }
                    },

                    Err(quiche::Error::Done) => break,

                    Err(err) => return Err(Box::new(err)),
                }
            }
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        if self.request_sent {
            return Ok(());
        }

        match qconn.stream_send(REQUEST_STREAM_ID, &[], true) {
            Ok(_) => {
                self.request_sent = true;
                println!("request sent on stream {REQUEST_STREAM_ID}");
                Ok(())
            },

            Err(quiche::Error::Done) => Ok(()),

            Err(err) => Err(Box::new(err)),
        }
    }

    fn on_conn_close<M: tokio_quiche::metrics::Metrics>(
        &mut self, qconn: &mut QuicheConnection, _metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        if !self.response_complete {
            self.complete(Err(anyhow::anyhow!(
                "connection closed before file transfer completed: \
                 detail={:?} local_error={:?} peer_error={:?}",
                connection_result,
                qconn.local_error(),
                qconn.peer_error(),
            )));
        }
    }
}

fn default_bind_addr(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) =>
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),

        SocketAddr::V6(_) =>
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn format_cid(cid: &[u8]) -> String {
    let mut out = String::with_capacity(cid.len() * 2);

    for byte in cid {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }

    out
}

fn print_stats_summary(stats: &QuicConnectionStats) {
    println!(
        "connection stats: sent={} recv={} lost={} retrans={} sent_bytes={} \
         recv_bytes={}",
        stats.stats.sent,
        stats.stats.recv,
        stats.stats.lost,
        stats.stats.retrans,
        stats.stats.sent_bytes,
        stats.stats.recv_bytes,
    );

    if let Some(path_stats) = stats.path_stats.as_ref() {
        println!(
            "path stats: rtt_us={} min_rtt_us={} max_rtt_us={} cwnd={} pmtu={} \
             delivery_rate={}",
            path_stats.rtt.as_micros(),
            path_stats
                .min_rtt
                .map(|value| value.as_micros())
                .unwrap_or_default(),
            path_stats
                .max_rtt
                .map(|value| value.as_micros())
                .unwrap_or_default(),
            path_stats.cwnd,
            path_stats.pmtu,
            path_stats.delivery_rate,
        );
    }
}

fn write_stats_json(
    path: &Path, received_bytes: usize, elapsed: Duration,
    stats: &QuicConnectionStats,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create stats directory {}", parent.display())
        })?;
    }

    let path_stats = stats.path_stats.as_ref();
    let json = format!(
        concat!(
            "{{",
            "\"received_file_bytes\":{},",
            "\"elapsed_ms\":{},",
            "\"packets_sent\":{},",
            "\"packets_recvd\":{},",
            "\"packets_lost\":{},",
            "\"packets_retrans\":{},",
            "\"bytes_sent\":{},",
            "\"bytes_recvd\":{},",
            "\"bytes_lost\":{},",
            "\"stream_retrans_bytes\":{},",
            "\"rtt_us\":{},",
            "\"min_rtt_us\":{},",
            "\"max_rtt_us\":{},",
            "\"rtt_var_us\":{},",
            "\"cwnd\":{},",
            "\"pmtu\":{},",
            "\"delivery_rate\":{}",
            "}}\n"
        ),
        received_bytes,
        elapsed.as_millis(),
        stats.stats.sent,
        stats.stats.recv,
        stats.stats.lost,
        stats.stats.retrans,
        stats.stats.sent_bytes,
        stats.stats.recv_bytes,
        stats.stats.lost_bytes,
        stats.stats.stream_retrans_bytes,
        path_stats
            .map(|value| value.rtt.as_micros() as u64)
            .unwrap_or_default(),
        path_stats
            .and_then(|value| value.min_rtt.map(|inner| inner.as_micros() as u64))
            .unwrap_or_default(),
        path_stats
            .and_then(|value| value.max_rtt.map(|inner| inner.as_micros() as u64))
            .unwrap_or_default(),
        path_stats
            .map(|value| value.rttvar.as_micros() as u64)
            .unwrap_or_default(),
        path_stats
            .map(|value| value.cwnd as u64)
            .unwrap_or_default(),
        path_stats
            .map(|value| value.pmtu as u64)
            .unwrap_or_default(),
        path_stats
            .map(|value| value.delivery_rate)
            .unwrap_or_default(),
    );

    std::fs::write(path, json)
        .with_context(|| format!("failed to write {}", path.display()))
}
