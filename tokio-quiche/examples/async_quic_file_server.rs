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
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use futures::stream::StreamExt;
use tokio::net::UdpSocket;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::HandshakeInfo;
use tokio_quiche::quic::QuicheConnection;
use tokio_quiche::settings::CertificateKind;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::ApplicationOverQuic;
use tokio_quiche::ConnectionParams;
use tokio_quiche::QuicResult;

const RESPONSE_CHUNK_LEN: usize = 16 * 1024;

#[derive(Parser, Debug)]
#[command(about = "Serves a file over one raw QUIC stream per client", version)]
struct Args {
    /// The address for the QUIC server to listen on.
    #[arg(short, long)]
    address: String,

    /// The file to serve to every connecting client.
    #[arg(long)]
    file: PathBuf,

    /// Path for the TLS certificate.
    #[arg(long, default_value_t = default_cert_path())]
    tls_cert_path: String,

    /// Path for the TLS private key.
    #[arg(long, default_value_t = default_private_key_path())]
    tls_private_key_path: String,

    /// Congestion control algorithm to use.
    #[arg(long, default_value = "cubic")]
    cc_algorithm: String,

    /// Initial congestion window size in packets.
    #[arg(long, default_value_t = 10)]
    initial_cwnd_packets: usize,

    /// Disable HyStart++ slow-start algorithm.
    #[arg(long, default_value_t = false)]
    disable_hystart: bool,

    /// Enable pacing of outgoing packets.
    #[arg(long, default_value_t = false)]
    enable_pacing: bool,

    /// Maximum pacing rate in bytes per second (0 = no limit).
    #[arg(long, default_value_t = 0)]
    max_pacing_rate: u64,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::parse();
    let file_bytes =
        Arc::<[u8]>::from(std::fs::read(&args.file).with_context(|| {
            format!("failed to read {}", args.file.display())
        })?);

    println!(
        "prepared transfer: file={} bytes={}",
        args.file.display(),
        file_bytes.len(),
    );

    let socket = UdpSocket::bind(&args.address)
        .await
        .with_context(|| format!("failed to bind {}", args.address))?;

    let mut quic_settings = QuicSettings::default();
    quic_settings.cc_algorithm = args.cc_algorithm.clone();
    quic_settings.initial_congestion_window_packets = args.initial_cwnd_packets;
    quic_settings.enable_hystart = !args.disable_hystart;
    quic_settings.enable_pacing = args.enable_pacing;
    quic_settings.max_pacing_rate =
        (args.max_pacing_rate > 0).then_some(args.max_pacing_rate);

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
        match conn_res {
            Ok(conn) => {
                println!(
                    "received new QUIC connection: local={} peer={}",
                    conn.local_addr(),
                    conn.peer_addr(),
                );

                conn.start(FileServerApp::new(Arc::clone(&file_bytes)));
            },

            Err(err) => {
                eprintln!("failed to accept QUIC connection: {err:?}");
            },
        }
    }

    Ok(())
}

struct FileServerApp {
    out: Vec<u8>,
    file_bytes: Arc<[u8]>,
    response_stream_id: Option<u64>,
    response_offset: usize,
    response_fin_sent: bool,
}

impl FileServerApp {
    fn new(file_bytes: Arc<[u8]>) -> Self {
        Self {
            out: vec![0; 64 * 1024],
            file_bytes,
            response_stream_id: None,
            response_offset: 0,
            response_fin_sent: false,
        }
    }
}

impl ApplicationOverQuic for FileServerApp {
    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection, handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        println!(
            "server connection established: trace_id={} handshake={:?}",
            qconn.trace_id(),
            handshake_info.elapsed(),
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
        pending::<QuicResult<()>>()
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let mut recv_buf = [0; 4096];

        for stream_id in qconn.readable() {
            loop {
                match qconn.stream_recv(stream_id, &mut recv_buf) {
                    Ok((_read, fin)) => {
                        if fin && self.response_stream_id.is_none() {
                            self.response_stream_id = Some(stream_id);
                            self.response_offset = 0;
                            self.response_fin_sent = false;

                            println!(
                                "received file request: stream_id={} bytes={}",
                                stream_id,
                                self.file_bytes.len(),
                            );
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
        let Some(stream_id) = self.response_stream_id else {
            return Ok(());
        };

        while self.response_offset < self.file_bytes.len() {
            let end = self
                .response_offset
                .saturating_add(RESPONSE_CHUNK_LEN)
                .min(self.file_bytes.len());
            let chunk = &self.file_bytes[self.response_offset..end];

            match qconn.stream_send(stream_id, chunk, false) {
                Ok(written) => {
                    self.response_offset =
                        self.response_offset.saturating_add(written);

                    if written == 0 {
                        break;
                    }
                },

                Err(quiche::Error::Done) => break,

                Err(err) => return Err(Box::new(err)),
            }
        }

        if self.response_offset == self.file_bytes.len() &&
            !self.response_fin_sent
        {
            match qconn.stream_send(stream_id, &[], true) {
                Ok(_) => {
                    self.response_fin_sent = true;
                    println!(
                        "file response finished: stream_id={} bytes={}",
                        stream_id,
                        self.file_bytes.len(),
                    );
                },

                Err(quiche::Error::Done) => (),

                Err(err) => return Err(Box::new(err)),
            }
        }

        Ok(())
    }

    fn on_conn_close<M: tokio_quiche::metrics::Metrics>(
        &mut self, qconn: &mut QuicheConnection, _metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        let stats = qconn.stats();
        println!(
            "server connection closed: result={} detail={:?} local_error={:?} \
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

fn default_cert_path() -> String {
    path_relative_to_manifest_dir("examples/cert.crt")
}

fn default_private_key_path() -> String {
    path_relative_to_manifest_dir("examples/cert.key")
}

fn path_relative_to_manifest_dir(path: &str) -> String {
    std::fs::canonicalize(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path),
    )
    .unwrap()
    .to_string_lossy()
    .into_owned()
}
