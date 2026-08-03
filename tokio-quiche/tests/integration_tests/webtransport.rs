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

use std::time::Duration;

use futures::StreamExt;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_quiche::http3::driver::BoundedClientWebTransportEvent;
use tokio_quiche::http3::driver::BoundedConnectHeaders;
use tokio_quiche::http3::driver::BoundedSelectedWebTransportController;
use tokio_quiche::http3::driver::BoundedSelectedWebTransportSettings;
use tokio_quiche::http3::driver::BoundedServerWebTransportEvent;
use tokio_quiche::http3::driver::WebTransportOpenStreamOutcome;
use tokio_quiche::http3::driver::WebTransportSessionEvent;
use tokio_quiche::http3::driver::WebTransportStreamDirection;
use tokio_quiche::http3::driver::WebTransportStreamReadOutcome;
use tokio_quiche::http3::driver::WebTransportStreamReadyOutcome;
use tokio_quiche::http3::driver::WebTransportStreamReceiveTerminal;
use tokio_quiche::http3::driver::WebTransportStreamReceiveTerminalRetirementOutcome;
use tokio_quiche::http3::driver::WebTransportStreamWriteLease;
use tokio_quiche::http3::driver::WebTransportStreamWriteLeaseOutcome;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::connect_with_config;
use tokio_quiche::quiche::h3::Header;
use tokio_quiche::settings::CertificateKind;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::socket::Socket;
use tokio_quiche::ClientH3Driver;
use tokio_quiche::ConnectionParams;
use tokio_quiche::ServerH3Driver;

use crate::fixtures::TEST_CERT_FILE;
use crate::fixtures::TEST_KEY_FILE;

#[derive(Debug)]
struct PayloadLease(Box<[u8]>);

impl PayloadLease {
    fn new(data: &[u8]) -> Self {
        Self(data.into())
    }
}

impl WebTransportStreamWriteLease for PayloadLease {
    type Error = std::convert::Infallible;

    fn payload_len(&self) -> usize {
        self.0.len()
    }

    fn retained_bytes(&self) -> usize {
        self.0.len()
    }

    fn as_slice(&mut self) -> Result<&[u8], Self::Error> {
        Ok(&self.0)
    }
}

fn connect_headers(
    limits: tokio_quiche::http3::driver::BoundedConnectHeaderLimits,
) -> BoundedConnectHeaders {
    BoundedConnectHeaders::copy_from(
        &[
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"webtransport-h3"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"localhost"),
            Header::new(b":path", b"/terminal"),
        ],
        limits,
    )
    .unwrap()
}

fn response_headers(
    limits: tokio_quiche::http3::driver::BoundedConnectHeaderLimits,
) -> BoundedConnectHeaders {
    BoundedConnectHeaders::copy_from(&[Header::new(b":status", b"200")], limits)
        .unwrap()
}

async fn write_complete(
    selected: &BoundedSelectedWebTransportController, session_id: u64,
    stream_id: u64, payload: &[u8], fin: bool,
) {
    match selected
        .write_stream_lease(
            session_id,
            stream_id,
            PayloadLease::new(payload),
            fin,
        )
        .await
    {
        WebTransportStreamWriteLeaseOutcome::Accepted {
            lease,
            accepted,
            complete,
            fin_accepted,
        } => {
            assert_eq!(lease.0.as_ref(), payload);
            assert_eq!(accepted, payload.len());
            assert!(complete);
            assert_eq!(fin_accepted, fin);
        },
        outcome => panic!("bounded stream write failed: {outcome:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_receive_terminal_udp_loopback() {
    timeout(Duration::from_secs(15), async {
        let settings = BoundedSelectedWebTransportSettings::default();
        let mut server_quic = QuicSettings::default();
        settings.apply_to_quic_settings(&mut server_quic);
        let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server_params = ConnectionParams::new_server(
            server_quic,
            TlsCertificatePaths {
                cert: TEST_CERT_FILE,
                private_key: TEST_KEY_FILE,
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        );
        let mut incoming =
            listen(vec![server_socket], server_params, DefaultMetrics)
                .unwrap()
                .remove(0);

        let (payload_queued, payload_ready) = oneshot::channel();
        let (payload_consumed, payload_done) = oneshot::channel();
        let (client_finished, client_done) = oneshot::channel();
        let server = tokio::spawn(async move {
            let initial = incoming.next().await.unwrap().unwrap();
            let (driver, mut controller) =
                ServerH3Driver::new_bounded_selected_webtransport(settings)
                    .unwrap();
            let _connection = initial.start(driver);

            let (session_id, mut responder) = loop {
                match controller.recv_event().await.unwrap() {
                    BoundedServerWebTransportEvent::ConnectRequested {
                        session_id,
                        responder,
                        ..
                    } => break (session_id, responder),
                    BoundedServerWebTransportEvent::ProfileViolation =>
                        panic!("bounded server profile violation"),
                    _ => {},
                }
            };
            assert!(controller.applied_profile().unwrap().is_some());
            responder
                .try_send_response(response_headers(
                    controller.connect_header_limits(),
                ))
                .unwrap();

            loop {
                match controller.recv_event().await.unwrap() {
                    BoundedServerWebTransportEvent::Session(
                        WebTransportSessionEvent::Accepted {
                            session_id: accepted,
                        },
                    ) if accepted == session_id => break,
                    BoundedServerWebTransportEvent::ProfileViolation =>
                        panic!("bounded server profile violation"),
                    _ => {},
                }
            }

            let selected = controller.selected();
            let stream_id =
                match selected.open_unidirectional_stream(session_id).await {
                    WebTransportOpenStreamOutcome::Opened { stream_id } =>
                        stream_id,
                    outcome => panic!("bounded stream open failed: {outcome:?}"),
                };
            write_complete(
                &selected,
                session_id,
                stream_id,
                b"final payload",
                false,
            )
            .await;
            payload_queued.send(()).unwrap();
            payload_done.await.unwrap();
            write_complete(&selected, session_id, stream_id, b"", true).await;
            client_done.await.unwrap();
            (session_id, stream_id)
        });

        let mut client_quic = QuicSettings::default();
        settings.apply_to_quic_settings(&mut client_quic);
        let client_params =
            ConnectionParams::new_client(client_quic, None, Hooks::default());
        let client_socket =
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_socket.connect(server_addr).await.unwrap();
        let socket = Socket::try_from(client_socket).unwrap();
        let (driver, mut controller) =
            ClientH3Driver::new_bounded_selected_webtransport(settings).unwrap();
        let _connection = connect_with_config(
            socket,
            Some("localhost"),
            &client_params,
            driver,
        )
        .await
        .unwrap();
        controller
            .try_connect(7, connect_headers(controller.connect_header_limits()))
            .unwrap();

        let mut session_id = None;
        let (selected_session, selected_stream) = loop {
            match controller.recv_event().await.unwrap() {
                BoundedClientWebTransportEvent::ConnectOpened {
                    session_id: opened,
                    ..
                } => session_id = Some(opened),
                BoundedClientWebTransportEvent::Session(
                    WebTransportSessionEvent::AssociatedStream {
                        session_id: selected_session,
                        stream_id,
                        direction: WebTransportStreamDirection::Uni,
                        ..
                    },
                ) => break (selected_session, stream_id),
                BoundedClientWebTransportEvent::ProfileViolation =>
                    panic!("bounded client profile violation"),
                _ => {},
            }
        };
        assert_eq!(session_id, Some(selected_session));
        assert!(controller.applied_profile().unwrap().is_some());
        payload_ready.await.unwrap();

        let selected = controller.selected();
        assert_eq!(
            selected
                .wait_stream_readable(selected_session, selected_stream)
                .await,
            WebTransportStreamReadyOutcome::Ready
        );
        assert_eq!(
            selected
                .read_stream(selected_session, selected_stream, 64)
                .await,
            WebTransportStreamReadOutcome::Data {
                data: bytes::Bytes::from_static(b"final payload"),
                fin: false,
            }
        );
        payload_consumed.send(()).unwrap();

        assert_eq!(
            selected
                .wait_stream_readable(selected_session, selected_stream)
                .await,
            WebTransportStreamReadyOutcome::Ready
        );
        let terminal = match selected
            .read_stream(selected_session, selected_stream, 64)
            .await
        {
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal,
            outcome => panic!("missing terminal receive lease: {outcome:?}"),
        };
        assert!(terminal.data().is_empty());
        assert_eq!(terminal.terminal(), WebTransportStreamReceiveTerminal::Fin);
        assert_eq!(
            selected
                .retire_stream_receive_terminal(
                    selected_session,
                    selected_stream,
                )
                .await,
            WebTransportStreamReceiveTerminalRetirementOutcome::OutstandingRead {
                session_id: selected_session,
                stream_id: selected_stream,
            }
        );
        drop(terminal);
        assert_eq!(
            selected
                .retire_stream_receive_terminal(
                    selected_session,
                    selected_stream,
                )
                .await,
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id: selected_session,
                stream_id: selected_stream,
            }
        );
        let stats = selected.retention_stats().await.unwrap();
        assert_eq!(stats.receive_terminal_observations, 0);
        assert_eq!(stats.receive_terminal_states, 0);
        assert_eq!(stats.receive_terminal_bytes, 0);
        client_finished.send(()).unwrap();

        assert_eq!(server.await.unwrap(), (selected_session, selected_stream));
    })
    .await
    .expect("bounded WebTransport UDP loopback timed out");
}
