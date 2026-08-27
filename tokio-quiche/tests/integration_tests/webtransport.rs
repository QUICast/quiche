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

use assert_matches::assert_matches;
use futures::StreamExt;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_quiche::http3::driver::BoundedClientWebTransportEvent;
use tokio_quiche::http3::driver::BoundedConnectHeaders;
use tokio_quiche::http3::driver::BoundedSelectedWebTransportController;
use tokio_quiche::http3::driver::BoundedSelectedWebTransportSettings;
use tokio_quiche::http3::driver::BoundedServerWebTransportEvent;
use tokio_quiche::http3::driver::WebTransportLiveConnectionSnapshotOutcome;
use tokio_quiche::http3::driver::WebTransportOpenStreamOutcome;
use tokio_quiche::http3::driver::WebTransportSessionCloseReason;
use tokio_quiche::http3::driver::WebTransportSessionEvent;
use tokio_quiche::http3::driver::WebTransportStreamDirection;
use tokio_quiche::http3::driver::WebTransportStreamReadOutcome;
use tokio_quiche::http3::driver::WebTransportStreamReadyOutcome;
use tokio_quiche::http3::driver::WebTransportStreamReceiveTerminal;
use tokio_quiche::http3::driver::WebTransportStreamReceiveTerminalRetirementOutcome;
use tokio_quiche::http3::driver::WebTransportStreamWriteLease;
use tokio_quiche::http3::driver::WebTransportStreamWriteLeaseOutcome;
use tokio_quiche::http3::driver::WebTransportTerminalRetentionOutcome;
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
use tokio_quiche::ConnectionOwnerDropHook;
use tokio_quiche::ConnectionParams;
use tokio_quiche::QuicResult;
use tokio_quiche::ServerH3Driver;

use crate::fixtures::TEST_CERT_FILE;
use crate::fixtures::TEST_KEY_FILE;

#[derive(Debug)]
struct PayloadLease {
    payload: Box<[u8]>,
    offset: usize,
}

const WT_SESSION_GONE: u64 = 0x170d_7b68;

#[derive(Clone, Copy, Debug, Default)]
struct PeerFacingCloseOrder {
    session_id: u64,
    stream_id: Option<u64>,
    armed: bool,
    read_turn: u64,
    connect_close_turn: Option<u64>,
    associated_teardown_turn: Option<u64>,
    violation: bool,
    response_fin_sent: bool,
}

#[derive(Default)]
struct PeerFacingCloseObservation {
    state: std::sync::Mutex<PeerFacingCloseOrder>,
    teardown: tokio::sync::Notify,
}

impl PeerFacingCloseObservation {
    fn lock(&self) -> std::sync::MutexGuard<'_, PeerFacingCloseOrder> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn configure(&self, session_id: u64, stream_id: u64) {
        let mut state = self.lock();
        state.session_id = session_id;
        state.stream_id = Some(stream_id);
    }

    fn arm(&self) {
        self.lock().armed = true;
    }

    fn begin_read_turn(&self) -> u64 {
        let mut state = self.lock();
        state.read_turn = state.read_turn.saturating_add(1);
        state.read_turn
    }

    fn observe_associated_teardown(
        &self, qconn: &mut tokio_quiche::quic::QuicheConnection, turn: u64,
    ) {
        let stream_id = {
            let state = self.lock();
            if !state.armed {
                return;
            }
            let Some(stream_id) = state.stream_id else {
                return;
            };
            stream_id
        };
        let stopped = matches!(
            qconn.stream_capacity(stream_id),
            Err(tokio_quiche::quiche::Error::StreamStopped(WT_SESSION_GONE))
        );
        let reset = matches!(
            qconn.stream_recv(stream_id, &mut [0; 1]),
            Err(tokio_quiche::quiche::Error::StreamReset(WT_SESSION_GONE))
        );
        if !stopped && !reset {
            return;
        }

        let mut state = self.lock();
        if state.associated_teardown_turn.is_some() {
            return;
        }
        state.associated_teardown_turn = Some(turn);
        state.violation = state
            .connect_close_turn
            .is_none_or(|close_turn| turn <= close_turn);
        drop(state);
        self.teardown.notify_waiters();
    }

    fn observe_connect_close(
        &self, qconn: &tokio_quiche::quic::QuicheConnection, turn: u64,
    ) {
        let session_id = {
            let state = self.lock();
            if !state.armed {
                return;
            }
            state.session_id
        };
        if !qconn.stream_finished(session_id) && !qconn.stream_closed(session_id)
        {
            return;
        }
        self.lock().connect_close_turn.get_or_insert(turn);
    }

    fn close_observed(&self) -> bool {
        self.lock().connect_close_turn.is_some()
    }

    fn take_response_fin(&self) -> Option<u64> {
        let mut state = self.lock();
        if state.connect_close_turn.is_none() || state.response_fin_sent {
            return None;
        }
        state.response_fin_sent = true;
        Some(state.session_id)
    }

    fn snapshot(&self) -> PeerFacingCloseOrder {
        *self.lock()
    }
}

struct PeerFacingOrderClientDriver {
    inner: ClientH3Driver,
    observation: std::sync::Arc<PeerFacingCloseObservation>,
}

impl tokio_quiche::ApplicationOverQuic for PeerFacingOrderClientDriver {
    fn connection_owner_drop_hook(&self) -> Option<ConnectionOwnerDropHook> {
        self.inner.connection_owner_drop_hook()
    }

    fn on_conn_established(
        &mut self, qconn: &mut tokio_quiche::quic::QuicheConnection,
        handshake_info: &tokio_quiche::quic::HandshakeInfo,
    ) -> QuicResult<()> {
        self.inner.on_conn_established(qconn, handshake_info)
    }

    fn should_act(&self) -> bool {
        self.inner.should_act()
    }

    async fn wait_for_data(
        &mut self, qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> QuicResult<()> {
        if self.observation.close_observed() {
            std::future::pending().await
        } else {
            self.inner.wait_for_data(qconn).await
        }
    }

    fn process_reads(
        &mut self, qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> QuicResult<()> {
        let turn = self.observation.begin_read_turn();
        self.observation.observe_associated_teardown(qconn, turn);
        let result = self.inner.process_reads(qconn);
        self.observation.observe_connect_close(qconn, turn);
        result
    }

    fn process_writes(
        &mut self, qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> QuicResult<()> {
        let Some(session_id) = self.observation.take_response_fin() else {
            if self.observation.close_observed() {
                return Ok(());
            }
            return self.inner.process_writes(qconn);
        };
        match qconn.stream_send(session_id, &[], true) {
            Ok(_) | Err(tokio_quiche::quiche::Error::Done) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn on_conn_close<M: tokio_quiche::metrics::Metrics>(
        &mut self, qconn: &mut tokio_quiche::quic::QuicheConnection, metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        self.inner.on_conn_close(qconn, metrics, connection_result);
    }
}

struct GracefulCloseClientDriver {
    inner: ClientH3Driver,
    close: watch::Receiver<bool>,
    close_sent: bool,
}

impl tokio_quiche::ApplicationOverQuic for GracefulCloseClientDriver {
    fn connection_owner_drop_hook(&self) -> Option<ConnectionOwnerDropHook> {
        self.inner.connection_owner_drop_hook()
    }

    fn on_conn_established(
        &mut self, qconn: &mut tokio_quiche::quic::QuicheConnection,
        handshake_info: &tokio_quiche::quic::HandshakeInfo,
    ) -> QuicResult<()> {
        self.inner.on_conn_established(qconn, handshake_info)
    }

    fn should_act(&self) -> bool {
        self.inner.should_act()
    }

    async fn wait_for_data(
        &mut self, qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> QuicResult<()> {
        if self.close_sent {
            return self.inner.wait_for_data(qconn).await;
        }
        if *self.close.borrow() {
            return Ok(());
        }
        tokio::select! {
            result = self.inner.wait_for_data(qconn) => result,
            changed = self.close.changed() => {
                let _ = changed;
                Ok(())
            },
        }
    }

    fn process_reads(
        &mut self, qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> QuicResult<()> {
        self.inner.process_reads(qconn)
    }

    fn process_writes(
        &mut self, qconn: &mut tokio_quiche::quic::QuicheConnection,
    ) -> QuicResult<()> {
        self.inner.process_writes(qconn)?;
        if !self.close_sent && *self.close.borrow_and_update() {
            self.close_sent = true;
            let _ = qconn.close(true, 0, b"terminal retention test");
        }
        Ok(())
    }

    fn on_conn_close<M: tokio_quiche::metrics::Metrics>(
        &mut self, qconn: &mut tokio_quiche::quic::QuicheConnection, metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        self.inner.on_conn_close(qconn, metrics, connection_result);
    }
}

impl PayloadLease {
    fn new(data: &[u8]) -> Self {
        Self {
            payload: data.into(),
            offset: 0,
        }
    }

    fn advance(&mut self, accepted: usize) {
        self.offset += accepted;
    }
}

impl WebTransportStreamWriteLease for PayloadLease {
    type Error = std::convert::Infallible;

    fn payload_len(&self) -> usize {
        self.payload.len() - self.offset
    }

    fn retained_bytes(&self) -> usize {
        self.payload.len()
    }

    fn as_slice(&mut self) -> Result<&[u8], Self::Error> {
        Ok(&self.payload[self.offset..])
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

fn assert_terminal_current_zero(
    stats: &tokio_quiche::http3::driver::WebTransportRetentionStats,
) {
    assert_eq!(stats.sessions, 0);
    assert_eq!(stats.associated_streams, 0);
    assert_eq!(stats.provisional_streams, 0);
    assert_eq!(stats.stream_open_waiters, 0);
    assert_eq!(stats.session_terminal_waiters, 0);
    assert_eq!(stats.waiters, 0);
    assert_eq!(stats.send_terminal_waiters, 0);
    assert_eq!(stats.send_terminal_states, 0);
    assert_eq!(stats.receive_terminal_observations, 0);
    assert_eq!(stats.receive_terminal_states, 0);
    assert_eq!(stats.receive_terminal_waiters, 0);
    assert_eq!(stats.receive_terminal_leases, 0);
    assert_eq!(stats.receive_terminal_bytes, 0);
    assert_eq!(stats.bounded_client_connect_owners, 0);
    assert_eq!(stats.metadata_index_entries, 0);
    assert_eq!(stats.pending_datagrams, 0);
    assert_eq!(stats.terminal_retention_waiters, 0);
    assert_eq!(stats.live_connection_snapshot_requests, 0);
    assert_eq!(stats.queued_commands, 0);
    assert_eq!(stats.write_leases, 0);
    assert_eq!(stats.write_lease_retained_bytes, 0);
    assert_eq!(stats.adapter_bytes_upper_bound(), 0);
    assert_eq!(stats.transport_queued_bytes(), 0);
}

async fn write_complete(
    selected: &BoundedSelectedWebTransportController, session_id: u64,
    stream_id: u64, payload: &[u8], fin: bool,
) {
    let mut lease = PayloadLease::new(payload);
    loop {
        match selected
            .write_stream_lease(session_id, stream_id, lease, fin)
            .await
        {
            WebTransportStreamWriteLeaseOutcome::Accepted {
                lease: mut returned,
                accepted,
                complete,
                fin_accepted,
            } => {
                assert_eq!(returned.payload.as_ref(), payload);
                assert!(accepted <= returned.payload_len());
                returned.advance(accepted);
                if complete {
                    assert_eq!(returned.offset, payload.len());
                    assert_eq!(fin_accepted, fin);
                    return;
                }
                assert!(accepted > 0);
                assert!(!fin_accepted);
                lease = returned;
            },
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease: returned,
                fin: returned_fin,
                reasons: blocked_reasons,
                retry,
            } => {
                assert_eq!(returned_fin, fin);
                match selected.wait_stream_writable(retry).await {
                    WebTransportStreamReadyOutcome::WriteTransportWake {
                        reasons,
                    } => assert_eq!(reasons, blocked_reasons),
                    WebTransportStreamReadyOutcome::Ready => {},
                    outcome => {
                        panic!("bounded stream retry failed: {outcome:?}")
                    },
                }
                lease = returned;
            },
            outcome => panic!("bounded stream write failed: {outcome:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_receive_terminal_udp_loopback() {
    timeout(Duration::from_secs(15), async {
        const TRAFFIC_CHUNK: &[u8] = &[0x5a; 4096];
        const TRAFFIC_CHUNKS: usize = 128;
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
            payload_queued.send(()).unwrap();
            let mut max_bytes_in_flight = 0;
            let mut previous_sequence = None;
            for _ in 0..TRAFFIC_CHUNKS {
                write_complete(
                    &selected,
                    session_id,
                    stream_id,
                    TRAFFIC_CHUNK,
                    false,
                )
                .await;
                let sample = match selected.live_connection_snapshot().await {
                    WebTransportLiveConnectionSnapshotOutcome::Sampled(
                        sample,
                    ) => sample,
                    outcome => panic!("live UDP snapshot failed: {outcome:?}"),
                };
                if let Some(previous_sequence) = previous_sequence {
                    assert!(sample.sample_sequence > previous_sequence);
                }
                previous_sequence = Some(sample.sample_sequence);
                max_bytes_in_flight =
                    max_bytes_in_flight.max(sample.bytes_in_flight);
            }
            assert!(
                max_bytes_in_flight > 0,
                "no live UDP sample observed bytes in flight",
            );
            payload_done.await.unwrap();
            write_complete(&selected, session_id, stream_id, b"", true).await;
            client_done.await.unwrap();
            (session_id, stream_id, max_bytes_in_flight)
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
        let mut received = 0;
        while received < TRAFFIC_CHUNK.len() * TRAFFIC_CHUNKS {
            assert_eq!(
                selected
                    .wait_stream_readable(selected_session, selected_stream)
                    .await,
                WebTransportStreamReadyOutcome::Ready
            );
            match selected
                .read_stream(selected_session, selected_stream, 64 * 1024)
                .await
            {
                WebTransportStreamReadOutcome::Data { data, fin: false } => {
                    assert!(data.iter().all(|byte| *byte == 0x5a));
                    received += data.len();
                },
                outcome => panic!("unexpected traffic read: {outcome:?}"),
            }
        }
        assert_eq!(received, TRAFFIC_CHUNK.len() * TRAFFIC_CHUNKS);
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

        let (server_session, server_stream, max_bytes_in_flight) =
            server.await.unwrap();
        assert_eq!(
            (server_session, server_stream),
            (selected_session, selected_stream)
        );
        assert!(max_bytes_in_flight > 0);
    })
    .await
    .expect("bounded WebTransport UDP loopback timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_established_graceful_close_returns_terminal_zero() {
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
        let (server_ready, ready) = oneshot::channel();

        let server = tokio::spawn(async move {
            let initial = incoming.next().await.unwrap().unwrap();
            let (driver, mut controller) =
                ServerH3Driver::new_bounded_selected_webtransport(settings)
                    .unwrap();
            let selected = controller.selected();
            let claim = selected.terminal_retention_claim();
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
            server_ready.send(()).unwrap();

            let stats = match selected.wait_terminal_retention(claim).await {
                WebTransportTerminalRetentionOutcome::Taken(stats) => stats,
                outcome => panic!("terminal accounting failed: {outcome:?}"),
            };
            assert_terminal_current_zero(&stats);
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
        let (close, close_rx) = watch::channel(false);
        let driver = GracefulCloseClientDriver {
            inner: driver,
            close: close_rx,
            close_sent: false,
        };
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
        loop {
            match controller.recv_event().await.unwrap() {
                BoundedClientWebTransportEvent::Session(
                    WebTransportSessionEvent::Accepted { .. },
                ) => break,
                BoundedClientWebTransportEvent::ProfileViolation =>
                    panic!("bounded client profile violation"),
                _ => {},
            }
        }
        ready.await.unwrap();
        close.send(true).unwrap();
        server.await.unwrap();
    })
    .await
    .expect("graceful terminal-retention UDP test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_local_close_udp_orders_connect_before_associated_teardown() {
    timeout(Duration::from_secs(15), async {
        const PAYLOAD: &[u8] = b"peer-facing close order";
        let settings = BoundedSelectedWebTransportSettings::default();
        let observation =
            std::sync::Arc::new(PeerFacingCloseObservation::default());
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

        let (stream_opened, stream_ready) = oneshot::channel();
        let (payload_consumed, payload_ready) = oneshot::channel();
        let (client_observed, client_done) = oneshot::channel();
        let server_observation = std::sync::Arc::clone(&observation);
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
                match selected.open_bidirectional_stream(session_id).await {
                    WebTransportOpenStreamOutcome::Opened { stream_id } =>
                        stream_id,
                    outcome => panic!("bounded stream open failed: {outcome:?}"),
                };
            server_observation.configure(session_id, stream_id);
            write_complete(&selected, session_id, stream_id, PAYLOAD, false)
                .await;
            stream_opened.send((session_id, stream_id)).unwrap();
            payload_ready.await.unwrap();

            controller
                .close_session(session_id, 31, "ordered UDP close".to_string())
                .unwrap();
            loop {
                match controller.recv_event().await.unwrap() {
                    BoundedServerWebTransportEvent::Session(
                        WebTransportSessionEvent::Terminated {
                            session_id: closed,
                            reason:
                                WebTransportSessionCloseReason::Local {
                                    error_code: 31,
                                    ref message,
                                },
                        },
                    ) if closed == session_id &&
                        message == "ordered UDP close" =>
                        break,
                    BoundedServerWebTransportEvent::ProfileViolation =>
                        panic!("bounded server profile violation"),
                    _ => {},
                }
            }
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
        let (inner, mut controller) =
            ClientH3Driver::new_bounded_selected_webtransport(settings).unwrap();
        let driver = PeerFacingOrderClientDriver {
            inner,
            observation: std::sync::Arc::clone(&observation),
        };
        let _connection = connect_with_config(
            socket,
            Some("localhost"),
            &client_params,
            driver,
        )
        .await
        .unwrap();
        controller
            .try_connect(8, connect_headers(controller.connect_header_limits()))
            .unwrap();

        let (expected_session, expected_stream) = stream_ready.await.unwrap();
        let (selected_session, selected_stream) = loop {
            match controller.recv_event().await.unwrap() {
                BoundedClientWebTransportEvent::Session(
                    WebTransportSessionEvent::AssociatedStream {
                        session_id,
                        stream_id,
                        direction: WebTransportStreamDirection::Bidi,
                        ..
                    },
                ) => break (session_id, stream_id),
                BoundedClientWebTransportEvent::ProfileViolation =>
                    panic!("bounded client profile violation"),
                _ => {},
            }
        };
        assert_eq!(
            (selected_session, selected_stream),
            (expected_session, expected_stream)
        );
        let selected = controller.selected();
        assert_eq!(
            selected
                .wait_stream_readable(selected_session, selected_stream)
                .await,
            WebTransportStreamReadyOutcome::Ready
        );
        assert_eq!(
            selected
                .read_stream(selected_session, selected_stream, 1024)
                .await,
            WebTransportStreamReadOutcome::Data {
                data: PAYLOAD.into(),
                fin: false,
            }
        );
        observation.arm();
        payload_consumed.send(()).unwrap();

        loop {
            match controller.recv_event().await.unwrap() {
                BoundedClientWebTransportEvent::Session(
                    WebTransportSessionEvent::Terminated {
                        session_id,
                        reason:
                            WebTransportSessionCloseReason::Peer {
                                error_code: 31,
                                ref message,
                            },
                    },
                ) if session_id == selected_session &&
                    message == "ordered UDP close" =>
                    break,
                BoundedClientWebTransportEvent::ProfileViolation =>
                    panic!("bounded client profile violation"),
                _ => {},
            }
        }
        loop {
            let state = observation.snapshot();
            if state.associated_teardown_turn.is_some() {
                break;
            }
            observation.teardown.notified().await;
        }
        let state = observation.snapshot();
        assert!(
            !state.violation,
            "associated teardown preceded CONNECT close"
        );
        assert_matches!(
            (state.connect_close_turn, state.associated_teardown_turn),
            (Some(close_turn), Some(teardown_turn)) if teardown_turn > close_turn
        );
        client_observed.send(()).unwrap();
        assert_eq!(server.await.unwrap(), (selected_session, selected_stream));
    })
    .await
    .expect("bounded WebTransport close-order UDP regression timed out");
}
