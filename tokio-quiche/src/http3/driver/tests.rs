use crate::http3::driver::client::ClientHooks;
use crate::http3::driver::server::ServerHooks;
use assert_matches::assert_matches;

use super::test_utils::*;
use super::*;

/// Tests for the body receive buffer sizing helper.
mod body_recv_buf_size {
    use super::*;

    #[test]
    fn zero_readable_uses_floor() {
        // Never build a zero-capacity buffer.
        assert_eq!(body_recv_buf_size(0), MIN_BODY_RECV_BUF_SIZE);
    }

    #[test]
    fn small_readable_uses_floor() {
        // A read below the floor is raised to the floor so a trickle of tiny
        // reads reuses one allocation instead of reallocating each time.
        assert_eq!(body_recv_buf_size(10), MIN_BODY_RECV_BUF_SIZE);
        assert_eq!(
            body_recv_buf_size(MIN_BODY_RECV_BUF_SIZE),
            MIN_BODY_RECV_BUF_SIZE
        );
    }

    #[test]
    fn readable_above_floor_tracks_size() {
        // Between the floor and the cap the buffer tracks the readable length.
        let readable = MIN_BODY_RECV_BUF_SIZE + 500;
        assert_eq!(body_recv_buf_size(readable), readable);
    }

    #[test]
    fn large_readable_caps_at_max() {
        assert_eq!(
            body_recv_buf_size(BufFactory::MAX_BUF_SIZE),
            BufFactory::MAX_BUF_SIZE
        );
        // Readable beyond MAX_BUF_SIZE is capped.
        assert_eq!(
            body_recv_buf_size(BufFactory::MAX_BUF_SIZE + 1),
            BufFactory::MAX_BUF_SIZE
        );
        assert_eq!(
            body_recv_buf_size(10 * BufFactory::MAX_BUF_SIZE),
            BufFactory::MAX_BUF_SIZE
        );
    }
}

/// Tests for connection close error metrics recorded by
/// [`H3Driver::on_conn_close`].
mod conn_close_metrics {
    use crate::ApplicationOverQuic as _;

    use super::*;

    /// Peer sends a QUIC-level CONNECTION_CLOSE and the work loop
    /// completes with Ok. Verifies the peer QUIC error counter is
    /// incremented.
    #[test]
    fn peer_quic_error_on_ok_result() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();

        // Peer (client) closes with a QUIC-level error
        helper
            .pipe
            .client
            .close(false, 0x1, b"internal error")
            .unwrap();
        helper.pipe.advance().unwrap();

        let metrics = TestMetrics::default();
        helper
            .driver
            .on_conn_close(&mut helper.pipe.server, &metrics, &Ok(()));

        assert_eq!(metrics.peer_quic.get(), 1);
        assert_eq!(metrics.peer_h3.get(), 0);
        assert_eq!(metrics.local_quic.get(), 0);
        assert_eq!(metrics.local_h3.get(), 0);
    }

    /// Peer sends an APPLICATION_CLOSE (H3-level) and the work loop
    /// completes with Ok. Verifies the peer H3 error counter is
    /// incremented.
    #[test]
    fn peer_h3_error_on_ok_result() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();

        // Peer (client) closes with an H3-level error (is_app = true)
        helper.pipe.client.close(true, 0x100, b"no error").unwrap();
        helper.pipe.advance().unwrap();

        let metrics = TestMetrics::default();
        helper
            .driver
            .on_conn_close(&mut helper.pipe.server, &metrics, &Ok(()));

        assert_eq!(metrics.peer_h3.get(), 1);
        assert_eq!(metrics.peer_quic.get(), 0);
        assert_eq!(metrics.local_quic.get(), 0);
        assert_eq!(metrics.local_h3.get(), 0);
    }

    /// Work loop returns an error and the local side has a QUIC-level
    /// error set. Verifies the local QUIC error counter is incremented.
    #[test]
    fn local_quic_error_on_err_result() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();

        // Local side (server) closes with a QUIC-level error
        helper
            .pipe
            .server
            .close(false, 0x1, b"internal error")
            .unwrap();

        let err: crate::QuicResult<()> =
            Err(H3ConnectionError::PostAcceptTimeout.into());
        let metrics = TestMetrics::default();
        helper
            .driver
            .on_conn_close(&mut helper.pipe.server, &metrics, &err);

        assert_eq!(metrics.local_quic.get(), 1);
        assert_eq!(metrics.local_h3.get(), 0);
        assert_eq!(metrics.peer_quic.get(), 0);
        assert_eq!(metrics.peer_h3.get(), 0);
    }
}

/// Tests that use an H3Driver for the client side. We mostly focus on testing
/// the driver's handling of stream state, and data, rather than H3 semantics.
/// Note that most of these tests could have just as easily been written for
/// the server side.
mod client_side_driver {
    use super::*;

    type DriverPipe = quiche::test_utils::Pipe<crate::buf_factory::BufFactory>;

    fn webtransport_settings() -> Http3Settings {
        Http3Settings {
            enable_webtransport: true,
            ..Default::default()
        }
    }

    fn webtransport_pipe() -> DriverPipe {
        let mut config = default_quiche_config();
        config.enable_dgram(true, 10, 10);
        config.enable_reset_stream_at(true);
        DriverPipe::with_config_and_buf(&mut config).unwrap()
    }

    fn webtransport_request_headers() -> Vec<h3::Header> {
        vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", b"quic.tech"),
            h3::Header::new(b":path", b"/wt"),
            h3::Header::new(b":protocol", b"webtransport-h3"),
        ]
    }

    fn webtransport_helper() -> DriverTestHelper<ClientHooks> {
        DriverTestHelper::<ClientHooks>::with_pipe_and_http3_settings(
            webtransport_pipe(),
            webtransport_settings(),
        )
        .unwrap()
    }

    fn start_webtransport_driver(helper: &mut DriverTestHelper<ClientHooks>) {
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();
    }

    fn expect_session_event(
        helper: &mut DriverTestHelper<ClientHooks>,
        expected: WebTransportSessionEvent,
    ) {
        assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::WebTransportSession(event) if event == expected
        );
    }

    fn open_pending_webtransport_session(
        helper: &mut DriverTestHelper<ClientHooks>, request_id: u64,
    ) -> (u64, OutboundFrameSender) {
        let (body_tx, mut body_rx) = tokio::sync::oneshot::channel();
        helper.driver_enqueue_request(
            request_id,
            webtransport_request_headers(),
            Some(body_tx),
        );
        assert_eq!(helper.process_commands().unwrap(), 1);
        expect_session_event(helper, WebTransportSessionEvent::Pending {
            session_id: 0,
        });
        let stream_id = assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id: actual_request_id,
            } if actual_request_id == request_id => stream_id
        );
        assert_eq!(stream_id, 0);
        let sender = body_rx.try_recv().unwrap();
        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_server_poll(),
            Ok((id, h3::Event::Headers { .. })) if id == stream_id
        );
        (stream_id, sender)
    }

    fn peer_response_status(
        helper: &mut DriverTestHelper<ClientHooks>, stream_id: u64, status: u16,
    ) {
        let status = status.to_string();
        let headers = vec![
            h3::Header::new(b":status", status.as_bytes()),
            h3::Header::new(b"server", b"quiche-test"),
        ];
        helper
            .peer
            .send_response(&mut helper.pipe.server, stream_id, &headers, false)
            .unwrap();
    }

    #[test]
    fn client_webtransport_admits_only_after_final_success_response() {
        let mut helper = webtransport_helper();
        start_webtransport_driver(&mut helper);
        let (stream_id, _body) =
            open_pending_webtransport_session(&mut helper, 7);

        peer_response_status(&mut helper, stream_id, 200);
        helper.advance_and_run_loop().unwrap();
        expect_session_event(&mut helper, WebTransportSessionEvent::Accepted {
            session_id: stream_id,
        });
        assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::Core(H3Event::IncomingHeaders(headers))
                if headers.stream_id == stream_id
        );
    }

    #[tokio::test]
    async fn client_selected_streams_use_role_correct_physical_ids() {
        let mut helper = webtransport_helper();
        start_webtransport_driver(&mut helper);
        let (session_id, _body) =
            open_pending_webtransport_session(&mut helper, 71);

        peer_response_status(&mut helper, session_id, 200);
        helper.advance_and_run_loop().unwrap();
        expect_session_event(&mut helper, WebTransportSessionEvent::Accepted {
            session_id,
        });
        assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::Core(H3Event::IncomingHeaders(headers))
                if headers.stream_id == session_id
        );

        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let open_controller = controller.clone();
        let open = tokio::spawn(async move {
            open_controller.open_bidirectional_stream(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let stream_id = assert_matches!(
            open.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        );
        assert_eq!(stream_id, 4);

        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.peer_server_poll(),
            Ok((stream_id, h3::Event::WebTransportStream {
                session_id,
                direction: h3::WebTransportStreamDirection::Bidirectional,
                prefix_len: 3,
            }))
        );

        let write_controller = controller.clone();
        let write = tokio::spawn(async move {
            write_controller
                .write_stream(
                    session_id,
                    stream_id,
                    Bytes::from_static(b"client payload"),
                    false,
                )
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            write.await.unwrap(),
            WebTransportStreamWriteOutcome::Accepted {
                accepted: 14,
                remaining: None,
                fin_accepted: false,
            }
        );
        helper.pipe.advance().unwrap();
        let mut payload = [0; 32];
        assert_eq!(
            helper.pipe.server.stream_recv(stream_id, &mut payload),
            Ok((14, false))
        );
        assert_eq!(&payload[..14], b"client payload");

        let uni_controller = controller.clone();
        let uni = tokio::spawn(async move {
            uni_controller.open_unidirectional_stream(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let uni_stream_id = assert_matches!(
            uni.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        );
        assert_eq!(uni_stream_id & 0x3, 2);

        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.peer_server_poll(),
            Ok((uni_stream_id, h3::Event::WebTransportStream {
                session_id,
                direction: h3::WebTransportStreamDirection::Unidirectional,
                prefix_len: 3,
            }))
        );

        let uni_write_controller = controller.clone();
        let uni_write = tokio::spawn(async move {
            uni_write_controller
                .write_stream(
                    session_id,
                    uni_stream_id,
                    Bytes::from_static(b"client uni payload"),
                    true,
                )
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            uni_write.await.unwrap(),
            WebTransportStreamWriteOutcome::Accepted {
                accepted: 18,
                remaining: None,
                fin_accepted: true,
            }
        );
        helper.pipe.advance().unwrap();
        let mut uni_payload = [0; 32];
        assert_eq!(
            helper
                .pipe
                .server
                .stream_recv(uni_stream_id, &mut uni_payload),
            Ok((18, true))
        );
        assert_eq!(&uni_payload[..18], b"client uni payload");
    }

    #[test]
    fn client_webtransport_rejects_non_successful_final_response() {
        let mut helper = webtransport_helper();
        start_webtransport_driver(&mut helper);
        let (stream_id, _body) =
            open_pending_webtransport_session(&mut helper, 8);

        peer_response_status(&mut helper, stream_id, 404);
        helper.advance_and_run_loop().unwrap();
        expect_session_event(&mut helper, WebTransportSessionEvent::Rejected {
            session_id: stream_id,
            status: 404,
        });
        assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::Core(H3Event::IncomingHeaders(headers))
                if headers.stream_id == stream_id
        );
    }

    #[test]
    fn client_webtransport_informational_response_does_not_admit() {
        let mut helper = webtransport_helper();
        start_webtransport_driver(&mut helper);
        let (stream_id, _body) =
            open_pending_webtransport_session(&mut helper, 12);

        peer_response_status(&mut helper, stream_id, 103);
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );

        let final_headers = vec![h3::Header::new(b":status", b"200")];
        helper
            .peer
            .send_additional_headers(
                &mut helper.pipe.server,
                stream_id,
                &final_headers,
                false,
                false,
            )
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_event(&mut helper, WebTransportSessionEvent::Accepted {
            session_id: stream_id,
        });
    }

    #[test]
    fn client_webtransport_buffers_associated_stream_until_response() {
        let mut helper = webtransport_helper();
        start_webtransport_driver(&mut helper);
        let (stream_id, _body) =
            open_pending_webtransport_session(&mut helper, 9);

        let data = [0x40, 0x41, 0x00, b'o', b'k'];
        helper.pipe.server.stream_send(1, &data, true).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );

        peer_response_status(&mut helper, stream_id, 200);
        helper.advance_and_run_loop().unwrap();
        expect_session_event(&mut helper, WebTransportSessionEvent::Accepted {
            session_id: stream_id,
        });
        assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::Core(H3Event::IncomingHeaders(_))
        );
        expect_session_event(
            &mut helper,
            WebTransportSessionEvent::AssociatedStream {
                session_id: stream_id,
                stream_id: 1,
                direction: WebTransportStreamDirection::Bidi,
                prefix_len: 3,
            },
        );

        let mut payload = [0; 8];
        let (len, fin) = helper.pipe.client.stream_recv(1, &mut payload).unwrap();
        assert_eq!(&payload[..len], b"ok");
        assert!(fin);
    }

    #[test]
    fn client_webtransport_waits_for_and_rejects_missing_peer_settings() {
        let peer_h3_config = h3::Config::new().unwrap();
        let mut helper =
            DriverTestHelper::<ClientHooks>::with_pipe_and_http3_configs(
                webtransport_pipe(),
                webtransport_settings(),
                peer_h3_config,
            )
            .unwrap();
        helper.complete_handshake().unwrap();
        helper.driver.settings_received_and_forwarded = false;

        let (body_tx, _body_rx) = tokio::sync::oneshot::channel();
        helper.driver_enqueue_request(
            10,
            webtransport_request_headers(),
            Some(body_tx),
        );
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );

        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingSettings { .. }
        );
        assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::WebTransportRequestRejected { request_id: 10 }
        );
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));
    }

    #[test]
    fn client_webtransport_settings_only_read_releases_queued_connect() {
        let mut helper = webtransport_helper();
        helper.complete_handshake().unwrap();
        helper.driver.settings_received_and_forwarded = false;

        let (body_tx, _body_rx) = tokio::sync::oneshot::channel();
        helper.driver_enqueue_request(
            13,
            webtransport_request_headers(),
            Some(body_tx),
        );
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );

        helper.pipe.advance().unwrap();
        helper
            .driver
            .process_reads(&mut helper.pipe.client)
            .unwrap();

        assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingSettings { .. }
        );
        assert_eq!(helper.process_commands().unwrap(), 1);
        expect_session_event(&mut helper, WebTransportSessionEvent::Pending {
            session_id: 0,
        });
        assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::NewOutboundRequest {
                stream_id: 0,
                request_id: 13,
            }
        );
    }

    #[test]
    fn client_webtransport_reset_after_admission_is_terminal() {
        let mut helper = webtransport_helper();
        start_webtransport_driver(&mut helper);
        let (stream_id, _body) =
            open_pending_webtransport_session(&mut helper, 11);
        peer_response_status(&mut helper, stream_id, 200);
        helper.advance_and_run_loop().unwrap();
        expect_session_event(&mut helper, WebTransportSessionEvent::Accepted {
            session_id: stream_id,
        });
        assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::Core(H3Event::IncomingHeaders(_))
        );

        helper
            .pipe
            .server
            .stream_shutdown(stream_id, quiche::Shutdown::Write, 0x61)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_event(&mut helper, WebTransportSessionEvent::Terminated {
            session_id: stream_id,
            reason: WebTransportSessionCloseReason::ConnectReset {
                error_code: 0x61,
            },
        });
    }

    #[test]
    fn client_fin_before_server_body() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();

        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        let to_server = resp.send.get_ref().unwrap().clone();
        let mut from_server = resp.recv;
        // client sends body
        to_server
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[1; 5]), false))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // server receives client body
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_server_recv_body_vec(0, 1024), Ok(vec![1; 5]));

        // client sends fin, server sends body and fin
        to_server
            .try_send(OutboundFrame::Body(Default::default(), true))
            .unwrap();
        helper.peer_server_send_body(0, &[2; 10], true).unwrap();

        // Server reads fin
        helper.advance_and_run_loop().unwrap();
        // TODO: the server sees an h3::Event::Data, but it's for an empty buffer.
        // Ideally, it wouldn't do that.
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Data)));
        // No data to be read
        assert_eq!(
            helper.peer_server_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Finished)));
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));
        helper.advance_and_run_loop().unwrap();

        // client receives the server body
        assert_matches!(from_server.try_recv(), Ok(InboundFrame::Body(buf, fin)) => {
            assert_eq!(buf.to_vec(), vec![2; 10]);
            // TODO: it would be nice if we could receive the fin here, but that's not
            // how quiche::h3 works. Instead we need another receive call on the channel
            assert!(!fin);
        });
        helper.work_loop_iter().unwrap();

        // FIXME: This is an edge case. We should not see a `Disconnected` error
        // here. The `from_server` / `InboudFrame` channel is set to 1 in tests.
        // What happens, is the driver reads the previous body frame, then it
        // sees an `Event::Finished` and calls `process_h3_fin`, which sets
        // `ctx.fin_recv`. Then it processes the pending write that sends the fin
        // from client to server. The driver now sees both ctx.fin_read &&
        // ctx.fin_sent and drops the context and thus the channel. Application
        // code (H3Body) is not affected by -- it treats a disconnected channel
        // like receiving a fin. It's a different question if it should treat it
        // as such

        // assert_matches!(from_server.try_recv(), Ok(InboundFrame::Body(buf,
        // fin)) => {
        //    assert_eq!(buf.into_inner().into_vec().len(), 0);
        //    assert!(fin);
        //});
        assert_matches!(from_server.try_recv(), Err(TryRecvError::Disconnected));
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    #[test]
    fn client_body_recv_buf() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request with fin
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), true)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        let mut from_server = resp.recv;

        // Set the buffer size
        helper.driver_set_body_buf_size(30);
        // Server sends an initial 10 byte body.
        helper.peer_server_send_body(0, &[2; 10], false).unwrap();
        helper.advance_and_run_loop().unwrap();
        // client receives the server body
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, vec![2; 10]);
        // another 10 bytes
        helper.peer_server_send_body(0, &[3; 10], false).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, vec![3; 10]);
        // another 10 bytes. That should have used the initial buffer.
        helper.peer_server_send_body(0, &[4; 10], false).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, vec![4; 10]);
        // another 10 bytes. Should transparently use a new buffer
        helper.peer_server_send_body(0, &[5; 10], true).unwrap();
        helper.advance_and_run_loop().unwrap();

        let (body, fin, _) = helper.driver_try_recv_body(&mut from_server);
        assert_eq!(body, vec![5; 10]);
        // client receives the server FIN
        assert!(fin);
        // client should have cleaned up the stream as both directions have closed
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    /// An idle connection (and a request/response that exchanges only
    /// headers) must never allocate the body receive buffer.
    #[test]
    fn client_body_recv_buf_not_allocated_when_idle() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // Idle: never received body bytes, so the buffer is not allocated.
        assert!(helper.driver.body_recv_buf.is_none());

        // Client sends a headers-only request (fin, no request body).
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), true)
            .unwrap();

        // Server reads the request and sends a headers-only response: `fin =
        // true` finishes the stream on its headers, so no body follows.
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, true).unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client receives the response headers; `read_fin` confirms the
        // response carried no body.
        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(resp.read_fin);

        // Only headers were exchanged, so the body receive buffer is still
        // not allocated.
        assert!(helper.driver.body_recv_buf.is_none());
    }

    /// The body receive buffer is lazily allocated on the first body read
    /// and released once the last stream is cleaned up.
    #[test]
    fn client_body_recv_buf_allocated_on_body_and_released_on_close() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), true)
            .unwrap();

        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();
        helper.advance_and_run_loop().unwrap();

        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        let mut from_server = resp.recv;

        // No body yet: the buffer is still unallocated.
        assert!(helper.driver.body_recv_buf.is_none());

        // Server sends a body chunk (not fin).
        helper.peer_server_send_body(0, &[7; 10], false).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, vec![7; 10]);

        // The body read lazily allocated the buffer at the floor
        // (`MIN_BODY_RECV_BUF_SIZE`) rather than a fixed 64 KiB, because the
        // readable length was below the floor. The buffer therefore tracks the
        // floor -- far below the 64 KiB a fixed allocation would use.
        assert!(helper.driver.body_recv_buf.is_some());
        let cap = helper
            .driver
            .body_recv_buf
            .as_ref()
            .unwrap()
            .get_ref()
            .capacity();
        assert!(
            cap <= MIN_BODY_RECV_BUF_SIZE,
            "body buffer should track the floor, not a fixed 64 KiB; cap = {cap}"
        );

        // Server finishes the stream.
        helper.peer_server_send_body(0, &[8; 10], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        let (body, fin, _) = helper.driver_try_recv_body(&mut from_server);
        assert_eq!(body, vec![8; 10]);
        assert!(fin);

        // Stream cleaned up on both-directions-close, buffer released.
        assert_eq!(helper.driver.stream_map.len(), 0);
        assert!(helper.driver.body_recv_buf.is_none());
    }

    /// A body larger than the receive buffer exercises the reallocation
    /// branch; the buffer stays allocated across reallocations and is
    /// released once the stream closes.
    #[test]
    fn client_body_recv_buf_reallocates_and_releases() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), true)
            .unwrap();

        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();
        helper.advance_and_run_loop().unwrap();

        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        let mut from_server = resp.recv;

        // Force a small receive buffer so it is smaller than the size we want
        // for each read, exercising the reallocation branch
        // (`*body_recv_buf = ...`).
        helper.driver_set_body_buf_size(20);

        // Send 40 bytes across four chunks, reallocating on the way.
        helper.peer_server_send_body(0, &[1; 10], false).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, vec![1; 10]);
        helper.peer_server_send_body(0, &[2; 10], false).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, vec![2; 10]);
        helper.peer_server_send_body(0, &[3; 10], false).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, vec![3; 10]);
        // Buffer remains allocated across reallocation.
        assert!(helper.driver.body_recv_buf.is_some());

        // Final chunk with fin.
        helper.peer_server_send_body(0, &[4; 10], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        let (body, fin, _) = helper.driver_try_recv_body(&mut from_server);
        assert_eq!(body, vec![4; 10]);
        assert!(fin);

        // Stream cleaned up, buffer released.
        assert_eq!(helper.driver.stream_map.len(), 0);
        assert!(helper.driver.body_recv_buf.is_none());
    }

    /// An exhausted receive buffer is released while its stream remains
    /// active, then allocated again for subsequent body data.
    #[test]
    fn client_body_recv_buf_releases_when_exhausted() {
        // Permit one full floor-sized body in a single H3 DATA frame.
        let mut config = default_quiche_config();
        let max_data = 2 * MIN_BODY_RECV_BUF_SIZE as u64;
        config.set_initial_max_data(max_data);
        config.set_initial_max_stream_data_bidi_local(max_data);
        config.set_initial_max_stream_data_bidi_remote(max_data);
        config.set_initial_max_stream_data_uni(max_data);
        let mut helper = DriverTestHelper::<ClientHooks>::with_pipe(
            quiche::test_utils::Pipe::with_config_and_buf(&mut config).unwrap(),
        )
        .unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), true)
            .unwrap();

        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();
        helper.advance_and_run_loop().unwrap();

        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        let mut from_server = resp.recv;

        let full_body = vec![1; MIN_BODY_RECV_BUF_SIZE];
        assert_eq!(
            helper.peer_server_send_body(0, &full_body, false),
            Ok(full_body.len())
        );
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, full_body);
        assert_eq!(helper.driver.stream_map.len(), 1);
        assert!(helper.driver.body_recv_buf.is_none());

        // The next body chunk allocates a fresh buffer.
        helper.peer_server_send_body(0, &[2; 10], false).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, vec![2; 10]);
        assert!(helper.driver.body_recv_buf.is_some());

        helper.peer_server_send_body(0, &[3; 10], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        let (body, fin, _) = helper.driver_try_recv_body(&mut from_server);
        assert_eq!(body, vec![3; 10]);
        assert!(fin);
        assert_eq!(helper.driver.stream_map.len(), 0);
        assert!(helper.driver.body_recv_buf.is_none());
    }

    /// Test that dropping the OutboundFrame channel causes the driver to
    /// send a RESET_STREAM frame to the peer.
    #[test]
    fn client_send_reset_stream_when_outbound_frame_channel_drops() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        const REQUEST_CANCELED_ERR: u64 =
            h3::WireErrorCode::RequestCancelled as u64;
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // The client uses H3Driver
        // client sends a request
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();

        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        // the stream is waiting on writes
        assert_eq!(helper.driver.waiting_streams.len(), 1);
        // take the InboundFrame receiver and stats
        let mut from_server = resp.recv;
        let audit_stats = resp.h3_audit_stats.clone();
        // ... and drop the outbound frame
        drop(resp.send);

        helper.advance_and_run_loop().unwrap();

        // server receives the reset
        assert_eq!(
            helper.peer_server_poll(),
            Ok((0, h3::Event::Reset(REQUEST_CANCELED_ERR)))
        );
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));

        helper.peer_server_send_body(0, &[2; 10], true).unwrap();
        helper.advance_and_run_loop().unwrap();

        // client receives the server body
        assert_matches!(from_server.try_recv(), Ok(InboundFrame::Body(buf, fin)) => {
            assert_eq!(buf.to_vec(), vec![2; 10]);
            // TODO: it would be nice if we could receive the fin here, but that's not
            // how quiche::h3 works. Instead we need another receive call on the channel
            assert!(!fin);
        });
        helper.work_loop_iter().unwrap();
        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 10);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
    }

    /// Test that dropping the OutboundFrame channel causes the driver to
    /// send a RESET_STREAM frame to the peer.
    #[test]
    fn client_send_reset_stream_when_outbound_frame_channel_drops_2() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        const REQUEST_CANCELED_ERR: u64 =
            h3::WireErrorCode::RequestCancelled as u64;
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // The client uses H3Driver
        // client sends a request
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers, body, and fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();
        helper.peer_server_send_body(0, &[2; 10], true).unwrap();

        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let mut resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        // take the InboundFrame receiver and stats
        let mut from_server = resp.recv;
        let audit_stats = resp.h3_audit_stats.clone();
        let (body, fin, _) = helper.driver_try_recv_body(&mut from_server);
        assert_eq!(body, vec![2; 10]);
        assert!(fin);
        helper.advance_and_run_loop().unwrap();

        // clsoe the channel.
        resp.send.close();

        helper.advance_and_run_loop().unwrap();

        // server receives the reset
        assert_eq!(
            helper.peer_server_poll(),
            Ok((0, h3::Event::Reset(REQUEST_CANCELED_ERR)))
        );
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));

        helper.advance_and_run_loop().unwrap();

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 10);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
    }

    /// Send data until the stream is no longer writable, then drop the
    /// OutboundFrame channel to trigger a RESET_STREAM
    #[test]
    fn client_send_reset_stream_with_full_stream() {
        let mut config = default_quiche_config();
        config.set_initial_max_stream_data_bidi_local(30);
        config.set_initial_max_stream_data_bidi_remote(30);
        let mut helper = DriverTestHelper::<ClientHooks>::with_pipe(
            quiche::test_utils::Pipe::with_config_and_buf(&mut config).unwrap(),
        )
        .unwrap();
        const REQUEST_CANCELED_ERR: u64 =
            h3::WireErrorCode::RequestCancelled as u64;
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // The client uses H3Driver
        // client sends a request
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers, and fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, true).unwrap();

        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(resp.read_fin);
        let audit_stats = resp.h3_audit_stats.clone();
        // send a body the to server, but not enough flow control for the full
        // body
        resp.send
            .get_ref()
            .unwrap()
            .try_send(OutboundFrame::Body(
                Bytes::copy_from_slice(&[23; 50]),
                false,
            ))
            .unwrap();
        assert_eq!(helper.driver.waiting_streams.len(), 1);
        // run `work_loop_iter()` to write the body into quiche
        helper.work_loop_iter().unwrap();
        // make sure we couldn't write the full body
        assert!(audit_stats.downstream_bytes_sent() < 50);
        let written = audit_stats.downstream_bytes_sent();
        // advance the pipe, the stream is writable again, but
        // don't advance the work_loop yet.
        helper.pipe.advance().unwrap();
        while helper.peer_server_poll().is_ok() {}
        assert_eq!(
            helper.peer_server_recv_body_vec(0, 1024).unwrap().len(),
            written as usize
        );
        helper.pipe.advance().unwrap();
        assert_eq!(helper.driver.waiting_streams.len(), 0);
        assert!(helper.driver.stream_map.get(&0).unwrap().recv.is_some());
        assert!(helper
            .driver
            .stream_map
            .get(&0)
            .unwrap()
            .queued_frame
            .is_some());

        // clsoe the channel.
        drop(resp.send);

        helper.work_loop_iter().unwrap();
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        helper.advance_and_run_loop().unwrap();

        // server receives the reset
        assert_eq!(
            helper.peer_server_poll(),
            Ok((0, h3::Event::Reset(REQUEST_CANCELED_ERR)))
        );
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));

        helper.advance_and_run_loop().unwrap();

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::None);
    }

    /// Test that dropping the OutboundFrame channel after we've send a fin
    /// is a no-op.
    #[test]
    fn client_drop_outbound_frame_channel_after_fin_no_reset() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // The client uses H3Driver
        // client sends a request
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers, body, and fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();

        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let mut resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        // take the InboundFrame receiver and stats
        let mut from_server = resp.recv;
        let audit_stats = resp.h3_audit_stats.clone();
        helper.advance_and_run_loop().unwrap();
        resp.send
            .get_ref()
            .unwrap()
            .try_send(OutboundFrame::Body(Default::default(), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // clsoe the channel.
        resp.send.close();

        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_server_send_body(0, &[42], true), Ok(1));
        helper.advance_and_run_loop().unwrap();

        // server receives the fin
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_server_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Finished)));
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));

        helper.advance_and_run_loop().unwrap();

        // client receives the body and fin
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_server);
        assert_eq!(body, &[42]);
        assert!(fin);

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 1);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
    }

    /// Verify that a GOAWAY received mid-stream does not kill in-flight
    /// request streams. The server sends GOAWAY with an ID above the
    /// active stream, indicating the stream was accepted. The client
    /// should continue receiving the remaining response body and
    /// complete the stream normally.
    #[test]
    fn client_receives_goaway_during_streaming_response() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client sends a request with fin (GET, no body).
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), true)
            .unwrap();
        assert_eq!(stream_id, 0);

        // Server sees the request and starts a streaming response.
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();
        helper.peer_server_send_body(0, &[1; 10], false).unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client receives response headers.
        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        let mut from_server = resp.recv;

        // Client receives first body chunk.
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, vec![1; 10]);

        // Server sends GOAWAY with id = stream_id + 4 (our stream was
        // accepted, but no future streams will be).
        helper
            .peer
            .send_goaway(&mut helper.pipe.server, stream_id + 4)
            .unwrap();
        // Server continues sending body data on the existing stream.
        helper.peer_server_send_body(0, &[2; 10], false).unwrap();

        // Advance — the driver handles GOAWAY gracefully and keeps
        // the connection alive.
        helper.advance_and_run_loop().unwrap();

        // Client should still receive the second body chunk.
        assert_eq!(helper.driver_try_recv_body(&mut from_server).0, vec![2; 10]);

        // Controller receives a GoAway event with the correct ID.
        // Drain any BodyBytesReceived notifications first — the
        // ordering between data and control stream events is not
        // guaranteed.
        loop {
            match helper.driver_recv_core_event().unwrap() {
                H3Event::GoAway { id } => {
                    assert_eq!(id, stream_id + 4);
                    break;
                },
                H3Event::BodyBytesReceived { .. } => continue,
                other => panic!("unexpected event: {other:?}"),
            }
        }

        // Server finishes the response.
        helper.peer_server_send_body(0, &[3; 10], true).unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client receives the final chunk.
        let (body, _fin, _err) = helper.driver_try_recv_body(&mut from_server);
        assert_eq!(body, vec![3; 10]);
    }
}

/// Tests that use an H3Driver for the server side. We mostly focus on testing
/// the driver's handling of stream state, and data, rather than H3 semantics.
/// Note that most of these tests could have just as easily been written for
/// the client side.
mod server_side_driver {

    use crate::ApplicationOverQuic as _;

    use super::*;

    const WEBTRANSPORT_BIDI_STREAM_TYPE: u64 = 0x41;
    const WEBTRANSPORT_UNI_STREAM_TYPE: u64 = 0x54;

    type DriverPipe = quiche::test_utils::Pipe<crate::buf_factory::BufFactory>;

    /// Server-side equivalent of
    /// [`client_side_driver::client_body_recv_buf_not_allocated_when_idle`]:
    /// `body_recv_buf` is `H3Driver` state shared by both `ClientHooks` and
    /// `ServerHooks`, so a headers-only request/response must not allocate it
    /// on the server either.
    #[test]
    fn server_body_recv_buf_not_allocated_when_idle() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // Idle: never received body bytes, so the buffer is not allocated.
        assert!(helper.driver.body_recv_buf.is_none());

        // Client sends a headers-only request (fin, no request body).
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), true)
            .unwrap();

        // Server reads the request; `read_fin` confirms it finished on its
        // headers and carries no body.
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers { incoming_headers, .. } => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(req.read_fin);

        // The server read only headers (no body), so the buffer stays
        // unallocated.
        assert!(helper.driver.body_recv_buf.is_none());

        // Server replies with a headers-only response: response headers
        // followed by an empty body with fin to complete the exchange. The
        // per-stream channel holds a single frame in debug builds
        // (`STREAM_CAPACITY`), so drain the headers before sending the fin.
        let to_client = req.send.get_ref().unwrap().clone();
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.work_loop_iter().unwrap();
        to_client
            .try_send(OutboundFrame::Body(Default::default(), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client receives the headers-only response.
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );

        // Still only headers were exchanged and the stream is closed, so the
        // body receive buffer was never allocated.
        assert!(helper.driver.body_recv_buf.is_none());
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    fn make_webtransport_request_headers() -> Vec<h3::Header> {
        vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", b"quic.tech"),
            h3::Header::new(b":path", b"/wt"),
            h3::Header::new(b":protocol", b"webtransport-h3"),
        ]
    }

    fn webtransport_settings() -> Http3Settings {
        Http3Settings {
            enable_webtransport: true,
            ..Default::default()
        }
    }

    fn webtransport_multicast_settings(channel_id: Vec<u8>) -> Http3Settings {
        Http3Settings {
            enable_extended_connect: true,
            multicast_datagram_channel_id: Some(channel_id),
            ..Default::default()
        }
    }

    fn dgram_enabled_pipe() -> DriverPipe {
        let mut config = default_quiche_config();
        config.enable_dgram(true, 10, 10);
        config.enable_reset_stream_at(true);
        quiche::test_utils::Pipe::with_config_and_buf(&mut config).unwrap()
    }

    fn backpressured_webtransport_pipe() -> DriverPipe {
        let mut config = default_quiche_config();
        config.set_initial_max_stream_data_bidi_local(64);
        config.enable_dgram(true, 10, 10);
        config.enable_reset_stream_at(true);
        quiche::test_utils::Pipe::with_config_and_buf(&mut config).unwrap()
    }

    fn prefix_backpressured_webtransport_pipe() -> DriverPipe {
        let mut client = default_quiche_config();
        client.set_initial_max_stream_data_bidi_remote(2);
        client.enable_dgram(true, 10, 10);
        client.enable_reset_stream_at(true);

        let mut server = default_quiche_config();
        server.enable_dgram(true, 10, 10);
        server.enable_reset_stream_at(true);

        quiche::test_utils::Pipe::with_client_and_server_config_and_buf(
            &mut client,
            &mut server,
        )
        .unwrap()
    }

    fn exact_prefix_capacity_webtransport_pipe() -> DriverPipe {
        let mut client = default_quiche_config();
        client.set_initial_max_stream_data_bidi_remote(3);
        client.enable_dgram(true, 10, 10);
        client.enable_reset_stream_at(true);

        let mut server = default_quiche_config();
        server.enable_dgram(true, 10, 10);
        server.enable_reset_stream_at(true);

        quiche::test_utils::Pipe::with_client_and_server_config_and_buf(
            &mut client,
            &mut server,
        )
        .unwrap()
    }

    fn single_server_bidi_webtransport_pipe() -> DriverPipe {
        let mut client = default_quiche_config();
        client.set_initial_max_streams_bidi(1);
        client.set_initial_max_stream_data_bidi_remote(3);
        client.enable_dgram(true, 10, 10);
        client.enable_reset_stream_at(true);

        let mut server = default_quiche_config();
        server.enable_dgram(true, 10, 10);
        server.enable_reset_stream_at(true);

        quiche::test_utils::Pipe::with_client_and_server_config_and_buf(
            &mut client,
            &mut server,
        )
        .unwrap()
    }

    fn webtransport_helper(
        settings: Http3Settings,
    ) -> DriverTestHelper<ServerHooks> {
        DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
            dgram_enabled_pipe(),
            settings,
        )
        .unwrap()
    }

    fn dgram_buf(data: &[u8]) -> datagram_socket::DgramBuffer {
        <crate::buf_factory::BufFactory as quiche::BufFactory>::dgram_buf_from_slice(
            data,
        )
    }

    fn multicast_ack(channel_id: &[u8]) -> quiche::multicast::Ack {
        quiche::multicast::Ack {
            channel_id: channel_id.to_vec(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }
    }

    fn assert_next_client_raw_h3_dgram(
        helper: &mut DriverTestHelper<ServerHooks>, expected_flow_id: u64,
        expected_payload: &[u8],
    ) {
        let mut buf = [0; 128];
        let len = helper.pipe.client.dgram_recv(&mut buf).unwrap();
        let mut dgram = octets::Octets::with_slice(&buf[..len]);

        assert_eq!(dgram.get_varint().unwrap(), expected_flow_id);
        assert_eq!(
            dgram.get_bytes(dgram.cap()).unwrap().to_vec(),
            expected_payload
        );
    }

    fn assert_client_raw_h3_dgram(
        helper: &mut DriverTestHelper<ServerHooks>, expected_flow_id: u64,
        expected_payload: &[u8],
    ) {
        assert_next_client_raw_h3_dgram(
            helper,
            expected_flow_id,
            expected_payload,
        );
        let mut buf = [0; 128];
        assert_eq!(
            helper.pipe.client.dgram_recv(&mut buf),
            Err(quiche::Error::Done)
        );
    }

    fn assert_client_no_raw_h3_dgram(helper: &mut DriverTestHelper<ServerHooks>) {
        let mut buf = [0; 128];
        assert_eq!(
            helper.pipe.client.dgram_recv(&mut buf),
            Err(quiche::Error::Done)
        );
    }

    fn encode_varint(value: u64, out: &mut Vec<u8>) {
        let mut buf = [0; 8];
        let off = {
            let mut b = octets::OctetsMut::with_slice(&mut buf);
            b.put_varint(value).unwrap();
            b.off()
        };
        out.extend_from_slice(&buf[..off]);
    }

    fn webtransport_stream_data(
        stream_type: u64, session_id: u64, payload: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        encode_varint(stream_type, &mut data);
        encode_varint(session_id, &mut data);
        data.extend_from_slice(payload);
        data
    }

    fn webtransport_close_capsule(error_code: u32, message: &str) -> Vec<u8> {
        let mut data = Vec::new();
        encode_varint(webtransport::WT_CLOSE_SESSION, &mut data);
        encode_varint((4 + message.len()) as u64, &mut data);
        data.extend_from_slice(&error_code.to_be_bytes());
        data.extend_from_slice(message.as_bytes());
        data
    }

    fn expect_session_pending(
        helper: &mut DriverTestHelper<ServerHooks>, stream_id: u64,
    ) {
        assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::WebTransportSession(WebTransportSessionEvent::Pending {
                session_id,
            }) if session_id == stream_id
        );
    }

    fn expect_session_accepted(
        helper: &mut DriverTestHelper<ServerHooks>, stream_id: u64,
    ) {
        assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::WebTransportSession(WebTransportSessionEvent::Accepted {
                session_id,
            }) if session_id == stream_id
        );
    }

    fn expect_session_rejected(
        helper: &mut DriverTestHelper<ServerHooks>, stream_id: u64, status: u16,
    ) {
        assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::WebTransportSession(WebTransportSessionEvent::Rejected {
                session_id,
                status: actual_status,
            }) if session_id == stream_id && actual_status == status
        );
    }

    fn expect_session_terminated(
        helper: &mut DriverTestHelper<ServerHooks>, stream_id: u64,
        expected_reason: WebTransportSessionCloseReason,
    ) {
        assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::WebTransportSession(
                WebTransportSessionEvent::Terminated {
                    session_id,
                    reason,
                }
            ) if session_id == stream_id && reason == expected_reason
        );
    }

    fn expect_associated_stream(
        helper: &mut DriverTestHelper<ServerHooks>, session_id: u64,
        stream_id: u64, direction: WebTransportStreamDirection,
        prefix_len: usize,
    ) {
        assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::WebTransportSession(
                WebTransportSessionEvent::AssociatedStream {
                    session_id: actual_session_id,
                    stream_id: actual_stream_id,
                    direction: actual_direction,
                    prefix_len: actual_prefix_len,
                }
            ) if actual_session_id == session_id &&
                actual_stream_id == stream_id &&
                actual_direction == direction &&
                actual_prefix_len == prefix_len
        );
    }

    fn assert_no_driver_event(helper: &mut DriverTestHelper<ServerHooks>) {
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
    }

    fn assert_no_webtransport_session_event(
        helper: &mut DriverTestHelper<ServerHooks>,
    ) {
        while let Ok(event) = helper.controller.event_receiver_mut().try_recv() {
            assert!(!matches!(
                event,
                ServerH3Event::Core(H3Event::WebTransportSession(_))
            ));
        }
    }

    fn open_datagram_flow(
        helper: &mut DriverTestHelper<ServerHooks>,
    ) -> OutboundFrameSender {
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        let headers = vec![
            h3::Header::new(b":method", b"CONNECT-UDP"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", b"quic.tech"),
            h3::Header::new(b":path", b"/"),
            h3::Header::new(b"datagram-flow-id", b"0"),
        ];
        helper.peer_client_send_request(headers, false).unwrap();
        helper.advance_and_run_loop().unwrap();

        let flow = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Core(H3Event::NewFlow { send, .. }) => send
        );
        assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers { .. }
        );
        flow
    }

    fn start_webtransport_driver(helper: &mut DriverTestHelper<ServerHooks>) {
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();
    }

    fn open_pending_webtransport_session(
        helper: &mut DriverTestHelper<ServerHooks>,
    ) -> (
        u64,
        tokio::sync::mpsc::Sender<OutboundFrame>,
        InboundFrameStream,
    ) {
        let stream_id = helper
            .peer_client_send_request(make_webtransport_request_headers(), false)
            .unwrap();

        helper.advance_and_run_loop().unwrap();
        expect_session_pending(helper, stream_id);
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers { incoming_headers, .. } => incoming_headers
        );
        assert_eq!(req.stream_id, stream_id);

        let to_client = req.send.get_ref().unwrap().clone();
        let from_client = req.recv;

        (stream_id, to_client, from_client)
    }

    fn send_response_status(
        to_client: &tokio::sync::mpsc::Sender<OutboundFrame>, status: u16,
    ) {
        let response_headers = vec![
            h3::Header::new(b":status", status.to_string().as_bytes()),
            h3::Header::new(b"server", b"quiche-test"),
        ];
        to_client
            .try_send(OutboundFrame::Headers(response_headers, None))
            .unwrap();
    }

    fn accept_pending_webtransport_session(
        helper: &mut DriverTestHelper<ServerHooks>, stream_id: u64,
        to_client: &tokio::sync::mpsc::Sender<OutboundFrame>,
    ) {
        send_response_status(to_client, 200);
        helper.advance_and_run_loop().unwrap();
        expect_session_accepted(helper, stream_id);
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::Headers { .. })) if id == stream_id
        );
    }

    fn accept_webtransport_session(
        helper: &mut DriverTestHelper<ServerHooks>,
    ) -> (tokio::sync::mpsc::Sender<OutboundFrame>, InboundFrameStream) {
        start_webtransport_driver(helper);
        let (stream_id, to_client, from_client) =
            open_pending_webtransport_session(helper);

        accept_pending_webtransport_session(helper, stream_id, &to_client);

        (to_client, from_client)
    }

    async fn open_server_webtransport_bidi(
        helper: &mut DriverTestHelper<ServerHooks>,
        controller: &WebTransportController, session_id: u64,
    ) -> u64 {
        let open_controller = controller.clone();
        let open = tokio::spawn(async move {
            open_controller.open_bidirectional_stream(session_id).await
        });
        tokio::task::yield_now().await;
        for _ in 0..4 {
            helper.work_loop_iter().unwrap();
            if open.is_finished() {
                break;
            }
        }
        assert_matches!(
            open.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        )
    }

    #[test]
    fn webtransport_connect_creates_pending_session() {
        let mut helper = webtransport_helper(webtransport_settings());
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        let stream_id = helper
            .peer_client_send_request(make_webtransport_request_headers(), false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        expect_session_pending(&mut helper, stream_id);
    }

    #[test]
    fn webtransport_response_header_flush_accepts_session() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);
    }

    #[tokio::test]
    async fn webtransport_selected_server_bidi_stream_uses_exact_quic_id() {
        let mut settings = webtransport_settings();
        settings.webtransport_max_stream_write_bytes = 16;
        let mut helper = webtransport_helper(settings);
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);

        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        assert_eq!(
            controller
                .write_stream(
                    session_id,
                    1,
                    Bytes::from_static(b"seventeen payload"),
                    true,
                )
                .await,
            WebTransportStreamWriteOutcome::TooLarge {
                max: 16,
                data: Bytes::from_static(b"seventeen payload"),
                fin: true,
            }
        );
        assert_eq!(
            helper.driver.webtransport_cmd_recv.as_ref().unwrap().len(),
            0
        );
        let open_controller = controller.clone();
        let open = tokio::spawn(async move {
            open_controller.open_bidirectional_stream(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();

        let stream_id = assert_matches!(
            open.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        );
        assert_eq!(stream_id, 1);

        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.peer_client_poll(),
            Ok((stream_id, h3::Event::WebTransportStream {
                session_id,
                direction: h3::WebTransportStreamDirection::Bidirectional,
                prefix_len: 3,
            }))
        );

        let write_controller = controller.clone();
        let write = tokio::spawn(async move {
            write_controller
                .write_stream(
                    session_id,
                    stream_id,
                    Bytes::from_static(b"selected payload"),
                    true,
                )
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            write.await.unwrap(),
            WebTransportStreamWriteOutcome::Accepted {
                accepted: 16,
                remaining: None,
                fin_accepted: true,
            }
        );

        let closed_controller = controller.clone();
        let closed = tokio::spawn(async move {
            closed_controller
                .write_stream(
                    session_id,
                    stream_id,
                    Bytes::from_static(b"after fin"),
                    false,
                )
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            closed.await.unwrap(),
            WebTransportStreamWriteOutcome::Closed {
                data: Bytes::from_static(b"after fin"),
                fin: false,
            }
        );

        helper.pipe.advance().unwrap();
        let mut payload = [0; 32];
        assert_eq!(
            helper.pipe.client.stream_recv(stream_id, &mut payload),
            Ok((16, true))
        );
        assert_eq!(&payload[..16], b"selected payload");
        assert!(helper.driver.flow_map.is_empty());
        assert!(!helper.driver.raw_streams.contains(&stream_id));
    }

    #[tokio::test]
    async fn webtransport_exact_stream_waits_are_level_triggered_and_terminal() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                exact_prefix_capacity_webtransport_pipe(),
                webtransport_settings(),
            )
            .unwrap();
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let stream_id =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;

        let read_controller = controller.clone();
        let readable = tokio::spawn(async move {
            read_controller
                .wait_stream_readable(session_id, stream_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!readable.is_finished());

        let duplicate_controller = controller.clone();
        let duplicate = tokio::spawn(async move {
            duplicate_controller
                .wait_stream_readable(session_id, stream_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            duplicate.await.unwrap(),
            WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            )
        );

        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { .. })) if id == stream_id
        );
        helper
            .pipe
            .client
            .stream_send(stream_id, b"ready", true)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            readable.await.unwrap(),
            WebTransportStreamReadyOutcome::Ready
        );

        let already_readable_controller = controller.clone();
        let already_readable = tokio::spawn(async move {
            already_readable_controller
                .wait_stream_readable(session_id, stream_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            already_readable.await.unwrap(),
            WebTransportStreamReadyOutcome::Ready
        );

        let selected_read = controller.clone();
        let read = tokio::spawn(async move {
            selected_read.read_stream(session_id, stream_id, 16).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(read.await.unwrap(), WebTransportStreamReadOutcome::Data {
            data: Bytes::from_static(b"ready"),
            fin: true,
        });

        let writable_stream =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        let writable_controller = controller.clone();
        let writable = tokio::spawn(async move {
            writable_controller
                .wait_stream_writable(session_id, writable_stream)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!writable.is_finished());

        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { .. }))
                if id == writable_stream
        );
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            writable.await.unwrap(),
            WebTransportStreamReadyOutcome::Ready
        );

        let reset_stream =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { .. })) if id == reset_stream
        );
        let reset_controller = controller.clone();
        let reset = tokio::spawn(async move {
            reset_controller
                .wait_stream_readable(session_id, reset_stream)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!reset.is_finished());

        let reset_wire = webtransport_error_to_http3(29);
        helper
            .pipe
            .client
            .stream_shutdown_at(reset_stream, reset_wire, 0)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(reset.await.unwrap(), WebTransportStreamReadyOutcome::Ready);

        let reset_read_controller = controller.clone();
        let reset_read = tokio::spawn(async move {
            reset_read_controller
                .read_stream(session_id, reset_stream, 16)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            reset_read.await.unwrap(),
            WebTransportStreamReadOutcome::Reset {
                wire_error_code: reset_wire,
                application_error_code: Some(29),
            }
        );

        let stopped_stream =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        let stopped_controller = controller.clone();
        let stopped = tokio::spawn(async move {
            stopped_controller
                .wait_stream_writable(session_id, stopped_stream)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!stopped.is_finished());

        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { .. })) if id == stopped_stream
        );
        helper
            .pipe
            .client
            .stream_shutdown(
                stopped_stream,
                quiche::Shutdown::Read,
                webtransport_error_to_http3(23),
            )
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            stopped.await.unwrap(),
            WebTransportStreamReadyOutcome::ResetRequired {
                wire_error_code: webtransport_error_to_http3(23),
                application_error_code: Some(23),
            }
        );

        let closing_controller = controller.clone();
        let closing = tokio::spawn(async move {
            closing_controller
                .wait_stream_readable(session_id, stopped_stream)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!closing.is_finished());
        helper
            .controller
            .close_webtransport_session(session_id, 7, "done".to_string())
            .unwrap();
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_eq!(
            closing.await.unwrap(),
            WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ClosingSession,
            )
        );
    }

    #[tokio::test]
    async fn webtransport_exact_stream_wait_wakes_once_on_connection_drop() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let stream_id =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;

        let wait_controller = controller.clone();
        let wait = tokio::spawn(async move {
            wait_controller
                .wait_stream_readable(session_id, stream_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!wait.is_finished());
        drop(helper);
        assert_eq!(
            wait.await.unwrap(),
            WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            )
        );
    }

    #[tokio::test]
    async fn webtransport_command_lane_nonblocking_admission_preserves_ownership()
    {
        let mut settings = webtransport_settings();
        settings.webtransport_command_capacity = 2;
        let mut helper = webtransport_helper(settings);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let oversized = vec![0xa5; datagram_socket::MAX_DATAGRAM_SIZE + 1];
        assert_matches!(
            controller.try_send_datagram(0, dgram_buf(&oversized)),
            Err(WebTransportDatagramSendOutcome::TooLarge {
                max: datagram_socket::MAX_DATAGRAM_SIZE,
                datagram,
            }) if datagram.as_slice() == oversized
        );

        let write = controller
            .try_write_stream(0, 1, Bytes::from_static(b"byte-exact-write"), true)
            .unwrap();
        let datagram = controller
            .try_send_datagram(0, dgram_buf(b"byte-exact-datagram"))
            .unwrap();
        assert_matches!(
            controller.try_write_stream(
                0,
                1,
                Bytes::from_static(b"queue-full"),
                false,
            ),
            Err(WebTransportStreamWriteOutcome::QueueFull { data, fin: false })
                if data == Bytes::from_static(b"queue-full")
        );

        helper.driver.close_webtransport_command_lane();
        assert_eq!(
            controller.datagram_stats().await,
            Err(WebTransportDatagramError::ConnectionClosed),
        );
        assert_eq!(
            write.outcome().await,
            WebTransportStreamWriteOutcome::Rejected {
                error: WebTransportSelectionError::ConnectionClosed,
                data: Bytes::from_static(b"byte-exact-write"),
                fin: true,
            }
        );
        assert_matches!(
            datagram.outcome().await,
            WebTransportDatagramSendOutcome::Rejected {
                error: WebTransportDatagramError::ConnectionClosed,
                datagram,
            } if datagram.as_slice() == b"byte-exact-datagram"
        );
    }

    #[tokio::test]
    async fn webtransport_zero_progress_cancellation_retires_every_stream_id() {
        let mut settings = webtransport_settings();
        settings.webtransport_max_session_work_per_callback = 1;
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                single_server_bidi_webtransport_pipe(),
                settings,
            )
            .unwrap();
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        for expected_stream_id in [1, 5, 9] {
            let open_controller = controller.clone();
            let open = tokio::spawn(async move {
                open_controller.open_bidirectional_stream(session_id).await
            });
            tokio::task::yield_now().await;
            helper.work_loop_iter().unwrap();
            assert_eq!(
                helper
                    .driver
                    .webtransport
                    .as_ref()
                    .unwrap()
                    .first_opening_stream_id(),
                Some(expected_stream_id),
            );
            open.abort();
            assert!(open.await.unwrap_err().is_cancelled());

            helper.work_loop_iter().unwrap();
            helper.pipe.advance().unwrap();
            assert_matches!(
                helper.peer_client_poll(),
                Ok((id, h3::Event::WebTransportStream { .. }))
                    if id == expected_stream_id
            );
            assert_eq!(
                helper.pipe.client.stream_capacity(expected_stream_id),
                Err(quiche::Error::StreamStopped(webtransport::WT_SESSION_GONE,)),
            );
            assert_eq!(
                helper
                    .pipe
                    .client
                    .stream_recv(expected_stream_id, &mut [0; 1]),
                Err(quiche::Error::StreamReset(webtransport::WT_SESSION_GONE)),
            );

            for _ in 0..16 {
                helper.pipe.advance().unwrap();
                helper.work_loop_iter().unwrap();
                if helper.pipe.server.peer_streams_left_bidi() == 1 {
                    break;
                }
            }
            assert_eq!(helper.pipe.server.peer_streams_left_bidi(), 1);
            assert!(!helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .owns_stream(expected_stream_id));
        }

        let stream_id =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        assert_eq!(stream_id, 13);
    }

    #[tokio::test]
    async fn webtransport_stream_limit_is_retryable_resource_outcome() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                single_server_bidi_webtransport_pipe(),
                webtransport_settings(),
            )
            .unwrap();
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        assert_eq!(
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await,
            1,
        );
        let blocked_controller = controller.clone();
        let blocked = tokio::spawn(async move {
            blocked_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            blocked.await.unwrap(),
            WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            ),
        );
    }

    #[tokio::test]
    async fn webtransport_inbound_and_local_opening_share_one_hard_cap() {
        let mut settings = webtransport_settings();
        settings.webtransport_max_pending_streams = 1;
        settings.webtransport_max_pending_streams_per_session = 1;
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                prefix_backpressured_webtransport_pipe(),
                settings,
            )
            .unwrap();
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let open_controller = controller.clone();
        let open = tokio::spawn(async move {
            open_controller.open_bidirectional_stream(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!open.is_finished());
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .first_opening_stream_id(),
            Some(1),
        );

        let optimistic = webtransport_stream_data(
            WEBTRANSPORT_BIDI_STREAM_TYPE,
            session_id + 8,
            b"overflow",
        );
        helper
            .pipe
            .client
            .stream_send(4, &optimistic, false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .pending_stream_count(),
            0,
        );
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.pipe.client.stream_capacity(4),
            Err(quiche::Error::StreamStopped(
                webtransport::WT_BUFFERED_STREAM_REJECTED,
            )),
        );

        open.abort();
        assert!(open.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn webtransport_commit_errors_retry_or_fail_stop_without_leaking() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        helper
            .driver
            .webtransport
            .as_mut()
            .unwrap()
            .inject_commit_error(h3::Error::StreamBlocked);
        let retried =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        assert_eq!(retried, 1);

        helper
            .driver
            .webtransport
            .as_mut()
            .unwrap()
            .inject_commit_error(h3::Error::IdError);
        let failed_controller = controller.clone();
        let failed = tokio::spawn(async move {
            failed_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            failed.await.unwrap(),
            WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::InternalFailure,
            )
        );
        assert!(!helper.driver.webtransport.as_ref().unwrap().owns_stream(5));

        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((1, h3::Event::WebTransportStream { .. }))
        );
        assert_matches!(
            helper.peer_client_poll(),
            Ok((5, h3::Event::WebTransportStream { .. }))
        );
        assert_eq!(
            helper.pipe.client.stream_recv(5, &mut [0; 1]),
            Err(quiche::Error::StreamReset(webtransport::WT_SESSION_GONE)),
        );
    }

    #[tokio::test]
    async fn webtransport_prefix_and_payload_retry_without_replay() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                prefix_backpressured_webtransport_pipe(),
                webtransport_settings(),
            )
            .unwrap();
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let open_controller = controller.clone();
        let open = tokio::spawn(async move {
            open_controller.open_bidirectional_stream(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!open.is_finished());

        let mut classified_stream = None;
        for _ in 0..16 {
            helper.pipe.advance().unwrap();
            match helper.peer_client_poll() {
                Ok((
                    stream_id,
                    h3::Event::WebTransportStream {
                        session_id: actual_session,
                        direction: h3::WebTransportStreamDirection::Bidirectional,
                        prefix_len: 3,
                    },
                )) if actual_session == session_id => {
                    classified_stream = Some(stream_id);
                    break;
                },
                Err(h3::Error::Done) => {},
                other => panic!("unexpected prefix event: {other:?}"),
            }
            helper.pipe.advance().unwrap();
            helper.work_loop_iter().unwrap();
        }
        let stream_id = classified_stream.unwrap_or_else(|| {
            panic!(
                "prefix did not complete; capacity={:?} open_finished={}",
                helper.pipe.server.stream_capacity(1),
                open.is_finished(),
            )
        });
        assert_eq!(open.await.unwrap(), WebTransportOpenStreamOutcome::Opened {
            stream_id
        });

        let payload: Vec<u8> = (0..128).map(|value| value as u8).collect();
        let mut remaining = Bytes::copy_from_slice(&payload);
        let mut received = Vec::new();
        let mut saw_partial = false;
        let mut saw_fin = false;

        for _ in 0..128 {
            if remaining.is_empty() && saw_fin {
                break;
            }
            let write_controller = controller.clone();
            let data = remaining;
            let write = tokio::spawn(async move {
                write_controller
                    .write_stream(session_id, stream_id, data, true)
                    .await
            });
            tokio::task::yield_now().await;
            helper.work_loop_iter().unwrap();
            remaining = match write.await.unwrap() {
                WebTransportStreamWriteOutcome::Accepted {
                    accepted,
                    remaining,
                    fin_accepted,
                } => {
                    saw_partial |= accepted != payload.len();
                    saw_fin |= fin_accepted;
                    remaining.unwrap_or_default()
                },
                WebTransportStreamWriteOutcome::Blocked { data, fin: true } =>
                    data,
                outcome => panic!("unexpected write outcome: {outcome:?}"),
            };

            helper.pipe.advance().unwrap();
            loop {
                let mut part = [0; 256];
                match helper.pipe.client.stream_recv(stream_id, &mut part) {
                    Ok((len, fin)) => {
                        received.extend_from_slice(&part[..len]);
                        saw_fin |= fin;
                    },
                    Err(quiche::Error::Done) => break,
                    other => panic!("unexpected selected read: {other:?}"),
                }
            }
            helper.pipe.advance().unwrap();
        }

        assert!(saw_partial);
        assert!(saw_fin);
        assert!(remaining.is_empty());
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn webtransport_blocked_prefix_does_not_starve_another_session() {
        let mut settings = webtransport_settings();
        settings.webtransport_max_session_work_per_callback = 2;
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                prefix_backpressured_webtransport_pipe(),
                settings,
            )
            .unwrap();
        start_webtransport_driver(&mut helper);
        let (blocked_session, blocked_response, _blocked_body) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(
            &mut helper,
            blocked_session,
            &blocked_response,
        );
        let (healthy_session, healthy_response, _healthy_body) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(
            &mut helper,
            healthy_session,
            &healthy_response,
        );

        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let blocked_controller = controller.clone();
        let blocked = tokio::spawn(async move {
            blocked_controller
                .open_bidirectional_stream(blocked_session)
                .await
        });
        let healthy_controller = controller.clone();
        let healthy = tokio::spawn(async move {
            healthy_controller
                .open_unidirectional_stream(healthy_session)
                .await
        });
        for _ in 0..8 {
            if helper.driver.webtransport_cmd_recv.as_ref().unwrap().len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            helper.driver.webtransport_cmd_recv.as_ref().unwrap().len(),
            2
        );

        let mut callbacks = 0;
        while !healthy.is_finished() && callbacks < 4 {
            helper.work_loop_iter().unwrap();
            callbacks += 1;
            tokio::task::yield_now().await;
        }
        assert!(healthy.is_finished());
        assert!(!blocked.is_finished());
        assert!(callbacks <= 3);

        let stream_id = assert_matches!(
            healthy.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        );
        assert_eq!(stream_id & 0x3, 3);
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.peer_client_poll(),
            Ok((stream_id, h3::Event::WebTransportStream {
                session_id: healthy_session,
                direction: h3::WebTransportStreamDirection::Unidirectional,
                prefix_len: 3,
            }))
        );

        blocked.abort();
        let _ = blocked.await;
    }

    #[tokio::test]
    async fn webtransport_selected_read_preserves_fin_and_reliable_reset() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let fin_stream_id = 4;
        let fin_bytes = webtransport_stream_data(
            h3::WEBTRANSPORT_BIDI_STREAM_SIGNAL,
            session_id,
            b"fin payload",
        );
        helper
            .pipe
            .client
            .stream_send(fin_stream_id, &fin_bytes, true)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_associated_stream(
            &mut helper,
            session_id,
            fin_stream_id,
            WebTransportStreamDirection::Bidi,
            3,
        );

        let read_controller = controller.clone();
        let read = tokio::spawn(async move {
            read_controller
                .read_stream(session_id, fin_stream_id, 64)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(read.await.unwrap(), WebTransportStreamReadOutcome::Data {
            data: Bytes::from_static(b"fin payload"),
            fin: true,
        });

        let reset_stream_id = 8;
        let reset_bytes = webtransport_stream_data(
            h3::WEBTRANSPORT_BIDI_STREAM_SIGNAL,
            session_id,
            b"keptlost",
        );
        helper
            .pipe
            .client
            .stream_send(reset_stream_id, &reset_bytes, false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_associated_stream(
            &mut helper,
            session_id,
            reset_stream_id,
            WebTransportStreamDirection::Bidi,
            3,
        );
        assert_eq!(helper.pipe.server.stream_readable_len(reset_stream_id), 8);

        let wire_error = webtransport_error_to_http3(77);
        helper
            .pipe
            .client
            .stream_shutdown_at(reset_stream_id, wire_error, 7)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.pipe.server.stream_readable_len(reset_stream_id), 4);

        let first_controller = controller.clone();
        let first = tokio::spawn(async move {
            first_controller
                .read_stream(session_id, reset_stream_id, 64)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(first.await.unwrap(), WebTransportStreamReadOutcome::Data {
            data: Bytes::from_static(b"kept"),
            fin: false,
        });

        let second_controller = controller.clone();
        let second = tokio::spawn(async move {
            second_controller
                .read_stream(session_id, reset_stream_id, 64)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            second.await.unwrap(),
            WebTransportStreamReadOutcome::Reset {
                wire_error_code: wire_error,
                application_error_code: Some(77),
            }
        );
    }

    #[tokio::test]
    async fn webtransport_selected_stream_propagates_stop_and_reset_codes() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let open_controller = controller.clone();
        let open = tokio::spawn(async move {
            open_controller.open_bidirectional_stream(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let stream_id = assert_matches!(
            open.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        );
        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { .. })) if id == stream_id
        );

        let stop_wire = webtransport_error_to_http3(19);
        helper
            .pipe
            .client
            .stream_shutdown(stream_id, quiche::Shutdown::Read, stop_wire)
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        let write_controller = controller.clone();
        let write = tokio::spawn(async move {
            write_controller
                .write_stream(
                    session_id,
                    stream_id,
                    Bytes::from_static(b"retained"),
                    false,
                )
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            write.await.unwrap(),
            WebTransportStreamWriteOutcome::ResetRequired {
                wire_error_code: stop_wire,
                application_error_code: Some(19),
                data: Bytes::from_static(b"retained"),
                fin: false,
            }
        );

        helper.pipe.advance().unwrap();

        let second_open_controller = controller.clone();
        let second_open = tokio::spawn(async move {
            second_open_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let reset_target = assert_matches!(
            second_open.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        );
        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { .. }))
                if id == reset_target
        );

        let reset_controller = controller.clone();
        let reset = tokio::spawn(async move {
            reset_controller
                .reset_stream(session_id, reset_target, 23)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            reset.await.unwrap(),
            WebTransportStreamControlOutcome::Applied
        );
        helper.pipe.advance().unwrap();
        let mut payload = [0; 8];
        assert_eq!(
            helper.pipe.client.stream_recv(reset_target, &mut payload),
            Err(quiche::Error::StreamReset(webtransport_error_to_http3(23)))
        );

        let incoming_stream_id = 4;
        let incoming = webtransport_stream_data(
            h3::WEBTRANSPORT_BIDI_STREAM_SIGNAL,
            session_id,
            b"incoming",
        );
        helper
            .pipe
            .client
            .stream_send(incoming_stream_id, &incoming, false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_associated_stream(
            &mut helper,
            session_id,
            incoming_stream_id,
            WebTransportStreamDirection::Bidi,
            3,
        );

        let stop_controller = controller.clone();
        let stop = tokio::spawn(async move {
            stop_controller
                .stop_stream(session_id, incoming_stream_id, 29)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            stop.await.unwrap(),
            WebTransportStreamControlOutcome::Applied
        );
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.pipe.client.stream_send(
                incoming_stream_id,
                b"after stop",
                false
            ),
            Err(quiche::Error::StreamStopped(webtransport_error_to_http3(
                29
            )))
        );
    }

    #[tokio::test]
    async fn webtransport_typed_datagrams_are_atomic_and_bypass_legacy_flows() {
        let mut settings = webtransport_settings();
        settings.webtransport_max_pending_datagrams = 1;
        settings.webtransport_max_pending_datagrams_per_session = 1;
        settings.webtransport_max_pending_datagram_bytes = 32;
        settings.webtransport_max_pending_datagram_bytes_per_session = 32;
        let mut helper = webtransport_helper(settings);
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let max_controller = controller.clone();
        let max = tokio::spawn(async move {
            max_controller.max_datagram_payload(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let max = max.await.unwrap().unwrap();
        assert_eq!(
            max + octets::varint_len(session_id / 4),
            helper.pipe.server.dgram_max_writable_len().unwrap()
        );

        let send_controller = controller.clone();
        let send = tokio::spawn(async move {
            send_controller
                .send_datagram(session_id, dgram_buf(b"native"))
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            send.await.unwrap(),
            WebTransportDatagramSendOutcome::Accepted
        );
        helper.pipe.advance().unwrap();
        assert_client_raw_h3_dgram(&mut helper, session_id / 4, b"native");
        assert!(helper.driver.flow_map.is_empty());
        assert_no_driver_event(&mut helper);

        let too_large_payload = vec![0xa5; max + 1];
        let too_large_controller = controller.clone();
        let too_large = tokio::spawn(async move {
            too_large_controller
                .send_datagram(
                    session_id,
                    dgram_buf(too_large_payload.as_slice()),
                )
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            too_large.await.unwrap(),
            WebTransportDatagramSendOutcome::TooLarge {
                max: actual_max,
                datagram,
            } if actual_max == max && datagram.as_slice().len() == max + 1
        );

        let boundary_controller = controller.clone();
        let boundary = tokio::spawn(async move {
            boundary_controller
                .send_datagram(session_id, dgram_buf(&vec![0x5a; max]))
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            boundary.await.unwrap(),
            WebTransportDatagramSendOutcome::Accepted
        );
        helper.pipe.advance().unwrap();
        let boundary = helper.pipe.client.dgram_recv_buf().unwrap();
        assert_eq!(boundary.as_slice()[0], 0);
        assert_eq!(boundary.as_slice().len(), max + 1);
        assert!(boundary.as_slice()[1..].iter().all(|byte| *byte == 0x5a));

        for _ in 0..10 {
            helper.pipe.server.dgram_send(b"fill").unwrap();
        }
        let blocked_controller = controller.clone();
        let blocked = tokio::spawn(async move {
            blocked_controller
                .send_datagram(session_id, dgram_buf(b"blocked"))
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            blocked.await.unwrap(),
            WebTransportDatagramSendOutcome::Blocked(datagram)
                if datagram.as_slice() == b"blocked"
        );
        helper.pipe.advance().unwrap();
        while helper.pipe.client.dgram_recv_buf().is_ok() {}

        for payload in [b"one".as_slice(), b"two", b"three"] {
            let mut wire = vec![0];
            wire.extend_from_slice(payload);
            helper.pipe.client.dgram_send(&wire).unwrap();
        }
        helper.advance_and_run_loop().unwrap();
        assert!(helper.driver.flow_map.is_empty());

        let overflow_controller = controller.clone();
        let overflow = tokio::spawn(async move {
            overflow_controller.receive_datagram(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            overflow.await.unwrap(),
            WebTransportDatagramReadOutcome::Overflow {
                datagrams: 2,
                bytes: 8,
            }
        );

        let receive_controller = controller.clone();
        let receive = tokio::spawn(async move {
            receive_controller.receive_datagram(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            receive.await.unwrap(),
            WebTransportDatagramReadOutcome::Datagram(datagram)
                if datagram.as_slice() == b"one"
        );
        assert!(helper.driver.flow_map.is_empty());
    }

    #[tokio::test]
    async fn webtransport_datagram_before_connect_is_classified_exactly_once() {
        let mut settings = webtransport_settings();
        settings.webtransport_max_pending_datagram_age =
            std::time::Duration::from_secs(60);
        let mut helper = webtransport_helper(settings);
        start_webtransport_driver(&mut helper);

        helper.pipe.client.dgram_send(b"\0native-early").unwrap();
        helper.advance_and_run_loop().unwrap();
        assert!(helper.driver.flow_map.is_empty());
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .pending_datagram_usage(),
            (1, 12),
        );

        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let receive_controller = controller.clone();
        let receive = tokio::spawn(async move {
            receive_controller.receive_datagram(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            receive.await.unwrap(),
            WebTransportDatagramReadOutcome::Datagram(datagram)
                if datagram.as_slice() == b"native-early"
        );
        assert!(helper.driver.flow_map.is_empty());

        helper.pipe.client.dgram_send(b"\x01legacy-early").unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .pending_datagram_usage(),
            (1, 12),
        );

        let headers = vec![
            h3::Header::new(b":method", b"CONNECT-UDP"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", b"quic.tech"),
            h3::Header::new(b":path", b"/"),
            h3::Header::new(b"datagram-flow-id", b"1"),
        ];
        assert_eq!(helper.peer_client_send_request(headers, false).unwrap(), 4);
        helper.advance_and_run_loop().unwrap();
        let mut legacy_recv = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Core(H3Event::NewFlow {
                flow_id: 1,
                recv,
                ..
            }) => recv
        );
        assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers { .. }
        );
        assert_matches!(
            legacy_recv.try_recv(),
            Ok(InboundFrame::Datagram(datagram))
                if datagram.as_slice() == b"legacy-early"
        );
        assert_matches!(
            legacy_recv.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
    }

    #[tokio::test]
    async fn webtransport_datagrams_are_isolated_and_released_per_session() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (first_session, first_response, _first_body) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(
            &mut helper,
            first_session,
            &first_response,
        );
        let (second_session, second_response, _second_body) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(
            &mut helper,
            second_session,
            &second_response,
        );
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let first_send_controller = controller.clone();
        let first_send = tokio::spawn(async move {
            first_send_controller
                .send_datagram(first_session, dgram_buf(b"out-first"))
                .await
        });
        let second_send_controller = controller.clone();
        let second_send = tokio::spawn(async move {
            second_send_controller
                .send_datagram(second_session, dgram_buf(b"out-second"))
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            first_send.await.unwrap(),
            WebTransportDatagramSendOutcome::Accepted
        );
        assert_matches!(
            second_send.await.unwrap(),
            WebTransportDatagramSendOutcome::Accepted
        );
        helper.pipe.advance().unwrap();
        assert_next_client_raw_h3_dgram(
            &mut helper,
            first_session / 4,
            b"out-first",
        );
        assert_next_client_raw_h3_dgram(
            &mut helper,
            second_session / 4,
            b"out-second",
        );
        assert_client_no_raw_h3_dgram(&mut helper);

        for (flow_id, payload) in [
            (first_session / 4, b"first".as_slice()),
            (second_session / 4, b"second".as_slice()),
        ] {
            let mut wire = vec![flow_id as u8];
            wire.extend_from_slice(payload);
            helper.pipe.client.dgram_send(&wire).unwrap();
        }
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .pending_datagram_usage(),
            (2, 11)
        );

        let second_receive_controller = controller.clone();
        let second_receive = tokio::spawn(async move {
            second_receive_controller
                .receive_datagram(second_session)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            second_receive.await.unwrap(),
            WebTransportDatagramReadOutcome::Datagram(datagram)
                if datagram.as_slice() == b"second"
        );

        let mut retained_second = vec![(second_session / 4) as u8];
        retained_second.extend_from_slice(b"still");
        helper.pipe.client.dgram_send(&retained_second).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .pending_datagram_usage(),
            (2, 10)
        );

        helper
            .peer_client_send_body(first_session, &[], true)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            first_session,
            WebTransportSessionCloseReason::Clean,
        );
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .pending_datagram_usage(),
            (1, 5)
        );

        let retained_controller = controller.clone();
        let retained = tokio::spawn(async move {
            retained_controller.receive_datagram(second_session).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            retained.await.unwrap(),
            WebTransportDatagramReadOutcome::Datagram(datagram)
                if datagram.as_slice() == b"still"
        );
        assert!(helper.driver.flow_map.is_empty());
    }

    #[tokio::test]
    async fn webtransport_selected_streams_enforce_direction_and_session() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (first_session, first_response, _first_body) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(
            &mut helper,
            first_session,
            &first_response,
        );
        let (second_session, second_response, _second_body) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(
            &mut helper,
            second_session,
            &second_response,
        );
        assert_eq!(first_session, 0);
        assert_eq!(second_session, 4);

        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let uni_controller = controller.clone();
        let uni = tokio::spawn(async move {
            uni_controller
                .open_unidirectional_stream(first_session)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let uni_stream = assert_matches!(
            uni.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        );
        assert_eq!(uni_stream & 0x3, 3);
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.peer_client_poll(),
            Ok((uni_stream, h3::Event::WebTransportStream {
                session_id: first_session,
                direction: h3::WebTransportStreamDirection::Unidirectional,
                prefix_len: 3,
            }))
        );

        let read_controller = controller.clone();
        let read = tokio::spawn(async move {
            read_controller
                .read_stream(first_session, uni_stream, 16)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            read.await.unwrap(),
            WebTransportStreamReadOutcome::Rejected(
                WebTransportSelectionError::WrongDirection,
            )
        );

        let bidi_controller = controller.clone();
        let bidi = tokio::spawn(async move {
            bidi_controller
                .open_bidirectional_stream(second_session)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let second_stream = assert_matches!(
            bidi.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        );
        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream {
                session_id,
                ..
            })) if id == second_stream && session_id == second_session
        );

        let foreign_controller = controller.clone();
        let foreign = tokio::spawn(async move {
            foreign_controller
                .write_stream(
                    first_session,
                    second_stream,
                    Bytes::from_static(b"not yours"),
                    false,
                )
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            foreign.await.unwrap(),
            WebTransportStreamWriteOutcome::Rejected {
                error: WebTransportSelectionError::ForeignStream {
                    owner_session_id: second_session,
                },
                data: Bytes::from_static(b"not yours"),
                fin: false,
            }
        );

        let write_controller = controller.clone();
        let write = tokio::spawn(async move {
            write_controller
                .write_stream(
                    first_session,
                    uni_stream,
                    Bytes::from_static(b"uni payload"),
                    true,
                )
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            write.await.unwrap(),
            WebTransportStreamWriteOutcome::Accepted {
                accepted: 11,
                remaining: None,
                fin_accepted: true,
            }
        );
        helper.pipe.advance().unwrap();
        let mut payload = [0; 16];
        assert_eq!(
            helper.pipe.client.stream_recv(uni_stream, &mut payload),
            Ok((11, true))
        );
        assert_eq!(&payload[..11], b"uni payload");

        for _ in 0..8 {
            helper.pipe.advance().unwrap();
            helper.work_loop_iter().unwrap();
            if helper.pipe.server.stream_closed(uni_stream) {
                break;
            }
        }
        assert!(helper.pipe.server.stream_closed(uni_stream));
        let stale_stream_controller = controller.clone();
        let stale_stream = tokio::spawn(async move {
            stale_stream_controller
                .write_stream(
                    first_session,
                    uni_stream,
                    Bytes::from_static(b"stale stream"),
                    false,
                )
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            stale_stream.await.unwrap(),
            WebTransportStreamWriteOutcome::Rejected {
                error: WebTransportSelectionError::StaleStream,
                data: Bytes::from_static(b"stale stream"),
                fin: false,
            }
        );
    }

    #[tokio::test]
    async fn webtransport_command_lane_returns_ownership_on_teardown() {
        let mut settings = webtransport_settings();
        settings.webtransport_command_capacity = 1;
        let mut helper = webtransport_helper(settings);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let write_controller = controller.clone();
        let write = tokio::spawn(async move {
            write_controller
                .write_stream(0, 4, Bytes::from_static(b"queued write"), true)
                .await
        });
        tokio::task::yield_now().await;
        assert_eq!(
            helper.driver.webtransport_cmd_recv.as_ref().unwrap().len(),
            1
        );

        let datagram_controller = controller.clone();
        let datagram = tokio::spawn(async move {
            datagram_controller
                .send_datagram(0, dgram_buf(b"queued datagram"))
                .await
        });
        tokio::task::yield_now().await;
        assert!(!datagram.is_finished());

        helper.driver.on_conn_close(
            &mut helper.pipe.server,
            &TestMetrics::default(),
            &Ok(()),
        );
        assert_eq!(
            write.await.unwrap(),
            WebTransportStreamWriteOutcome::Rejected {
                error: WebTransportSelectionError::ConnectionClosed,
                data: Bytes::from_static(b"queued write"),
                fin: true,
            }
        );
        assert_matches!(
            datagram.await.unwrap(),
            WebTransportDatagramSendOutcome::Rejected {
                error: WebTransportDatagramError::ConnectionClosed,
                datagram,
            } if datagram.as_slice() == b"queued datagram"
        );
    }

    #[tokio::test]
    async fn webtransport_selected_apis_reject_pending_terminal_and_stale_ids() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let pending_open_controller = controller.clone();
        let pending_open = tokio::spawn(async move {
            pending_open_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            pending_open.await.unwrap(),
            WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::PendingSession,
            )
        );

        let pending_datagram_controller = controller.clone();
        let pending_datagram = tokio::spawn(async move {
            pending_datagram_controller
                .send_datagram(session_id, dgram_buf(b"pending"))
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            pending_datagram.await.unwrap(),
            WebTransportDatagramSendOutcome::Rejected {
                error: WebTransportDatagramError::PendingSession,
                datagram,
            } if datagram.as_slice() == b"pending"
        );

        send_response_status(&to_client, 403);
        helper.advance_and_run_loop().unwrap();
        expect_session_rejected(&mut helper, session_id, 403);
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::Headers { .. })) if id == session_id
        );

        let terminal_controller = controller.clone();
        let terminal = tokio::spawn(async move {
            terminal_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            terminal.await.unwrap(),
            WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::TerminalSession,
            )
        );
        let terminal_datagram_controller = controller.clone();
        let terminal_datagram = tokio::spawn(async move {
            terminal_datagram_controller
                .send_datagram(session_id, dgram_buf(b"terminal"))
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            terminal_datagram.await.unwrap(),
            WebTransportDatagramSendOutcome::Rejected {
                error: WebTransportDatagramError::TerminalSession,
                datagram,
            } if datagram.as_slice() == b"terminal"
        );

        helper
            .peer
            .send_body(&mut helper.pipe.client, session_id, &[], true)
            .unwrap();
        to_client
            .try_send(OutboundFrame::Body(Bytes::new(), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        while helper.peer_client_poll().is_ok() {}
        helper.advance_and_run_loop().unwrap();
        assert!(!helper
            .driver
            .webtransport
            .as_ref()
            .unwrap()
            .is_session(session_id));

        let stale_controller = controller.clone();
        let stale = tokio::spawn(async move {
            stale_controller.open_bidirectional_stream(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            stale.await.unwrap(),
            WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::StaleSession,
            )
        );
        let stale_datagram_controller = controller.clone();
        let stale_datagram = tokio::spawn(async move {
            stale_datagram_controller
                .send_datagram(session_id, dgram_buf(b"stale"))
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            stale_datagram.await.unwrap(),
            WebTransportDatagramSendOutcome::Rejected {
                error: WebTransportDatagramError::StaleSession,
                datagram,
            } if datagram.as_slice() == b"stale"
        );
    }

    #[tokio::test]
    async fn webtransport_selected_apis_fail_closed_during_close_race() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                backpressured_webtransport_pipe(),
                webtransport_settings(),
            )
            .unwrap();
        let (to_client, _from_client) = accept_webtransport_session(&mut helper);
        let session_id = 0;
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let open_controller = controller.clone();
        let open = tokio::spawn(async move {
            open_controller.open_bidirectional_stream(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let stream_id = assert_matches!(
            open.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        );

        to_client
            .try_send(OutboundFrame::Body(Bytes::from_static(&[b'p'; 48]), false))
            .unwrap();
        helper
            .controller
            .close_webtransport_session(session_id, 5, "closing".to_string())
            .unwrap();
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert!(helper
            .driver
            .webtransport
            .as_ref()
            .unwrap()
            .is_closing(session_id));

        let write_controller = controller.clone();
        let write = tokio::spawn(async move {
            write_controller
                .write_stream(
                    session_id,
                    stream_id,
                    Bytes::from_static(b"after close"),
                    false,
                )
                .await
        });
        let datagram_controller = controller.clone();
        let datagram = tokio::spawn(async move {
            datagram_controller
                .send_datagram(session_id, dgram_buf(b"after close"))
                .await
        });
        let late_open_controller = controller.clone();
        let late_open = tokio::spawn(async move {
            late_open_controller
                .open_unidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();

        assert_eq!(
            write.await.unwrap(),
            WebTransportStreamWriteOutcome::Rejected {
                error: WebTransportSelectionError::ClosingSession,
                data: Bytes::from_static(b"after close"),
                fin: false,
            }
        );
        assert_matches!(
            datagram.await.unwrap(),
            WebTransportDatagramSendOutcome::Rejected {
                error: WebTransportDatagramError::ClosingSession,
                datagram,
            } if datagram.as_slice() == b"after close"
        );
        assert_eq!(
            late_open.await.unwrap(),
            WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::ClosingSession,
            )
        );
    }

    #[test]
    fn h3_datagram_multicast_channel_uses_quic_fallback_state() {
        let channel_id = vec![1, 2, 3, 4];
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                dgram_enabled_pipe(),
                webtransport_multicast_settings(channel_id.clone()),
            )
            .unwrap();
        let flow_sender = open_datagram_flow(&mut helper);

        flow_sender
            .get_ref()
            .unwrap()
            .try_send(OutboundFrame::Datagram(dgram_buf(b"fallback"), 0))
            .unwrap();
        helper.work_loop_iter().unwrap();
        helper.pipe.advance().unwrap();
        assert_client_raw_h3_dgram(&mut helper, 0, b"fallback");

        helper
            .pipe
            .server
            .multicast_process_peer_ack(multicast_ack(&channel_id))
            .unwrap();

        flow_sender
            .get_ref()
            .unwrap()
            .try_send(OutboundFrame::Datagram(dgram_buf(b"multicast-green"), 0))
            .unwrap();
        helper.work_loop_iter().unwrap();
        helper.pipe.advance().unwrap();
        assert_client_no_raw_h3_dgram(&mut helper);
    }

    #[test]
    fn h3_datagram_uses_quic_default_multicast_channel() {
        let channel_id = vec![1, 2, 3, 4];
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                dgram_enabled_pipe(),
                Http3Settings {
                    enable_extended_connect: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let flow_sender = open_datagram_flow(&mut helper);

        helper
            .pipe
            .server
            .multicast_set_default_dgram_channel(Some(channel_id.clone()))
            .unwrap();

        flow_sender
            .get_ref()
            .unwrap()
            .try_send(OutboundFrame::Datagram(dgram_buf(b"default-fallback"), 0))
            .unwrap();
        helper.work_loop_iter().unwrap();
        helper.pipe.advance().unwrap();
        assert_client_raw_h3_dgram(&mut helper, 0, b"default-fallback");

        helper
            .pipe
            .server
            .multicast_process_peer_ack(multicast_ack(&channel_id))
            .unwrap();

        flow_sender
            .get_ref()
            .unwrap()
            .try_send(OutboundFrame::Datagram(dgram_buf(b"after-ack"), 0))
            .unwrap();
        helper.work_loop_iter().unwrap();
        helper.pipe.advance().unwrap();
        assert_client_no_raw_h3_dgram(&mut helper);
    }

    #[test]
    fn webtransport_bidi_prefix_transfers_native_stream_ownership_once() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        let payload = b"quicast setup";
        let data =
            webtransport_stream_data(WEBTRANSPORT_BIDI_STREAM_TYPE, 0, payload);
        helper.pipe.client.stream_send(4, &data, true).unwrap();
        helper.advance_and_run_loop().unwrap();

        let prefix_len = data.len() - payload.len();
        expect_associated_stream(
            &mut helper,
            0,
            4,
            WebTransportStreamDirection::Bidi,
            prefix_len,
        );
        assert_no_driver_event(&mut helper);

        let mut received = [0; 64];
        let (len, fin) =
            helper.pipe.server.stream_recv(4, &mut received).unwrap();
        assert_eq!(&received[..len], payload);
        assert!(fin);
    }

    #[test]
    fn webtransport_uni_prefix_transfers_native_stream_ownership_once() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        let payload = b"uni setup";
        let data =
            webtransport_stream_data(WEBTRANSPORT_UNI_STREAM_TYPE, 0, payload);
        helper.pipe.client.stream_send(18, &data, true).unwrap();
        helper.advance_and_run_loop().unwrap();

        let prefix_len = data.len() - payload.len();
        expect_associated_stream(
            &mut helper,
            0,
            18,
            WebTransportStreamDirection::Uni,
            prefix_len,
        );
        assert_no_driver_event(&mut helper);

        let mut received = [0; 64];
        let (len, fin) =
            helper.pipe.server.stream_recv(18, &mut received).unwrap();
        assert_eq!(&received[..len], payload);
        assert!(fin);
    }

    #[test]
    fn webtransport_future_session_metadata_is_bounded_and_released_on_fin() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        let payload = b"not this session";
        let data =
            webtransport_stream_data(WEBTRANSPORT_BIDI_STREAM_TYPE, 99, payload);
        helper.pipe.client.stream_send(4, &data, true).unwrap();
        helper.advance_and_run_loop().unwrap();

        assert_no_driver_event(&mut helper);
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .pending_stream_count(),
            0
        );
    }

    #[test]
    fn webtransport_fin_before_full_prefix_never_transfers_ownership() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        let data = [0x40];
        helper.pipe.client.stream_send(4, &data, true).unwrap();
        helper.advance_and_run_loop().unwrap();

        assert_no_driver_event(&mut helper);
        assert!(!helper.driver.webtransport.as_ref().unwrap().owns_stream(4));
    }

    #[test]
    fn webtransport_informational_response_does_not_admit_before_final_2xx() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (stream_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);

        to_client
            .try_send(OutboundFrame::Headers(
                vec![
                    h3::Header::new(b":status", b"103"),
                    h3::Header::new(b"x-fill", &[b'x'; 40]),
                ],
                None,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_no_driver_event(&mut helper);
        assert!(!helper
            .driver
            .webtransport
            .as_ref()
            .unwrap()
            .is_active(stream_id));
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::Headers { .. })) if id == stream_id
        );

        accept_pending_webtransport_session(&mut helper, stream_id, &to_client);
    }

    #[test]
    fn webtransport_retryable_response_backpressure_does_not_admit_early() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                backpressured_webtransport_pipe(),
                webtransport_settings(),
            )
            .unwrap();
        start_webtransport_driver(&mut helper);
        let (stream_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);

        send_response_status(&to_client, 103);
        helper.work_loop_iter().unwrap();
        assert_no_driver_event(&mut helper);

        send_response_status(&to_client, 200);
        helper.work_loop_iter().unwrap();
        assert_no_driver_event(&mut helper);
        assert!(helper
            .driver
            .webtransport
            .as_ref()
            .unwrap()
            .is_pending(stream_id));
        assert!(helper
            .driver
            .stream_map
            .get(&stream_id)
            .unwrap()
            .queued_frame
            .is_some());

        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::Headers { .. })) if id == stream_id
        );
        helper.advance_and_run_loop().unwrap();
        expect_session_accepted(&mut helper, stream_id);
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::Headers { .. })) if id == stream_id
        );
    }

    #[test]
    fn webtransport_non_successful_final_response_rejects_session() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (stream_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);

        send_response_status(&to_client, 404);
        helper.advance_and_run_loop().unwrap();
        expect_session_rejected(&mut helper, stream_id, 404);
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::Headers { .. })) if id == stream_id
        );

        let data = webtransport_stream_data(
            WEBTRANSPORT_BIDI_STREAM_TYPE,
            stream_id,
            b"late",
        );
        helper.pipe.client.stream_send(4, &data, false).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_no_driver_event(&mut helper);
        assert_eq!(
            helper.pipe.client.stream_capacity(4),
            Err(quiche::Error::StreamStopped(webtransport::WT_SESSION_GONE))
        );
    }

    #[test]
    fn webtransport_stopped_response_send_never_admits_candidate() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (stream_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);

        helper
            .pipe
            .client
            .stream_shutdown(stream_id, quiche::Shutdown::Read, 0x42)
            .unwrap();
        helper.pipe.advance().unwrap();
        send_response_status(&to_client, 200);
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            stream_id,
            WebTransportSessionCloseReason::ConnectStopped { error_code: 0x42 },
        );
        assert!(!helper
            .driver
            .webtransport
            .as_ref()
            .unwrap()
            .is_active(stream_id));
    }

    #[test]
    fn webtransport_server_rejects_client_without_draft_settings() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_configs(
                dgram_enabled_pipe(),
                webtransport_settings(),
                h3::Config::new().unwrap(),
            )
            .unwrap();
        start_webtransport_driver(&mut helper);
        let (stream_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);

        send_response_status(&to_client, 200);
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            stream_id,
            WebTransportSessionCloseReason::AdmissionFailed,
        );
        assert!(!helper
            .driver
            .webtransport
            .as_ref()
            .unwrap()
            .is_active(stream_id));
    }

    #[test]
    fn webtransport_stream_before_connect_is_admitted_after_2xx() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);

        let payload = b"before connect";
        let data =
            webtransport_stream_data(WEBTRANSPORT_BIDI_STREAM_TYPE, 0, payload);
        helper.pipe.client.stream_send(4, &data, true).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_no_driver_event(&mut helper);

        let (stream_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        assert_eq!(stream_id, 0);
        accept_pending_webtransport_session(&mut helper, stream_id, &to_client);
        expect_associated_stream(
            &mut helper,
            0,
            4,
            WebTransportStreamDirection::Bidi,
            data.len() - payload.len(),
        );

        let mut received = [0; 64];
        let (len, fin) =
            helper.pipe.server.stream_recv(4, &mut received).unwrap();
        assert_eq!(&received[..len], payload);
        assert!(fin);
    }

    #[test]
    fn webtransport_stream_between_connect_and_2xx_waits_for_admission() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (stream_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);

        let payload = b"before response";
        let data = webtransport_stream_data(
            WEBTRANSPORT_BIDI_STREAM_TYPE,
            stream_id,
            payload,
        );
        helper.pipe.client.stream_send(4, &data, true).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_no_driver_event(&mut helper);

        accept_pending_webtransport_session(&mut helper, stream_id, &to_client);
        expect_associated_stream(
            &mut helper,
            stream_id,
            4,
            WebTransportStreamDirection::Bidi,
            data.len() - payload.len(),
        );
    }

    #[test]
    fn webtransport_fragmented_prefix_transfers_ownership_at_every_boundary() {
        let prefix =
            webtransport_stream_data(WEBTRANSPORT_BIDI_STREAM_TYPE, 0, &[]);
        let payload = b"payload";

        for split in 0..=prefix.len() {
            let mut helper = webtransport_helper(webtransport_settings());
            let (_to_client, _from_client) =
                accept_webtransport_session(&mut helper);

            if split != 0 {
                helper
                    .pipe
                    .client
                    .stream_send(4, &prefix[..split], false)
                    .unwrap();
            }
            helper.advance_and_run_loop().unwrap();

            let ownership_already_transferred = split == prefix.len();
            if ownership_already_transferred {
                expect_associated_stream(
                    &mut helper,
                    0,
                    4,
                    WebTransportStreamDirection::Bidi,
                    prefix.len(),
                );
            } else {
                assert_no_driver_event(&mut helper);
            }

            let mut rest = prefix[split..].to_vec();
            rest.extend_from_slice(payload);
            helper.pipe.client.stream_send(4, &rest, true).unwrap();
            helper.advance_and_run_loop().unwrap();
            if !ownership_already_transferred {
                expect_associated_stream(
                    &mut helper,
                    0,
                    4,
                    WebTransportStreamDirection::Bidi,
                    prefix.len(),
                );
            }
            assert_no_driver_event(&mut helper);

            let mut received = [0; 64];
            let (len, fin) =
                helper.pipe.server.stream_recv(4, &mut received).unwrap();
            assert_eq!(&received[..len], payload);
            assert!(fin);
        }
    }

    #[test]
    fn webtransport_concurrent_sessions_remain_strictly_isolated() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (first_id, first_send, _first_recv) =
            open_pending_webtransport_session(&mut helper);
        let (second_id, second_send, _second_recv) =
            open_pending_webtransport_session(&mut helper);
        assert_eq!((first_id, second_id), (0, 4));

        let first = webtransport_stream_data(
            WEBTRANSPORT_BIDI_STREAM_TYPE,
            first_id,
            b"first",
        );
        let second = webtransport_stream_data(
            WEBTRANSPORT_BIDI_STREAM_TYPE,
            second_id,
            b"second",
        );
        helper.pipe.client.stream_send(8, &first, false).unwrap();
        helper.pipe.client.stream_send(12, &second, false).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_no_driver_event(&mut helper);

        accept_pending_webtransport_session(&mut helper, first_id, &first_send);
        expect_associated_stream(
            &mut helper,
            first_id,
            8,
            WebTransportStreamDirection::Bidi,
            first.len() - b"first".len(),
        );

        send_response_status(&second_send, 403);
        helper.advance_and_run_loop().unwrap();
        expect_session_rejected(&mut helper, second_id, 403);
        assert_eq!(
            helper.pipe.client.stream_capacity(12),
            Err(quiche::Error::StreamStopped(
                webtransport::WT_BUFFERED_STREAM_REJECTED
            ))
        );
        assert!(helper
            .driver
            .webtransport
            .as_ref()
            .unwrap()
            .is_active(first_id));

        let later = webtransport_stream_data(
            WEBTRANSPORT_BIDI_STREAM_TYPE,
            first_id,
            b"still active",
        );
        helper.pipe.client.stream_send(16, &later, true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_associated_stream(
            &mut helper,
            first_id,
            16,
            WebTransportStreamDirection::Bidi,
            later.len() - b"still active".len(),
        );
    }

    #[test]
    fn webtransport_fin_before_admission_is_terminal() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let stream_id = helper
            .peer_client_send_request(make_webtransport_request_headers(), true)
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        expect_session_pending(&mut helper, stream_id);
        expect_session_terminated(
            &mut helper,
            stream_id,
            WebTransportSessionCloseReason::Clean,
        );
        assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers { .. }
        );
    }

    #[test]
    fn webtransport_reset_before_admission_is_terminal() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (stream_id, _to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);

        helper
            .pipe
            .client
            .stream_shutdown(stream_id, quiche::Shutdown::Write, 0x51)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            stream_id,
            WebTransportSessionCloseReason::ConnectReset { error_code: 0x51 },
        );
    }

    #[test]
    fn webtransport_reset_after_admission_terminates_only_that_session() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        helper
            .pipe
            .client
            .stream_shutdown(0, quiche::Shutdown::Write, 0x52)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            0,
            WebTransportSessionCloseReason::ConnectReset { error_code: 0x52 },
        );
    }

    #[test]
    fn webtransport_stop_after_admission_is_terminal() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (to_client, _from_client) = accept_webtransport_session(&mut helper);

        helper
            .pipe
            .client
            .stream_shutdown(0, quiche::Shutdown::Read, 0x53)
            .unwrap();
        helper.pipe.advance().unwrap();
        to_client
            .try_send(OutboundFrame::Body(Bytes::from_static(b"trigger"), false))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            0,
            WebTransportSessionCloseReason::ConnectStopped { error_code: 0x53 },
        );
    }

    #[test]
    fn webtransport_fin_after_admission_is_clean_terminal() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        helper.peer_client_send_body(0, &[], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            0,
            WebTransportSessionCloseReason::Clean,
        );
    }

    #[test]
    fn webtransport_termination_resets_associated_streams_only() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);
        let associated =
            webtransport_stream_data(WEBTRANSPORT_BIDI_STREAM_TYPE, 0, b"open");
        helper
            .pipe
            .client
            .stream_send(4, &associated, false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_associated_stream(
            &mut helper,
            0,
            4,
            WebTransportStreamDirection::Bidi,
            associated.len() - b"open".len(),
        );

        let close = webtransport_close_capsule(2, "close session");
        helper.peer_client_send_body(0, &close, true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            0,
            WebTransportSessionCloseReason::Peer {
                error_code: 2,
                message: "close session".to_string(),
            },
        );
        assert_eq!(
            helper.pipe.client.stream_capacity(4),
            Err(quiche::Error::StreamStopped(webtransport::WT_SESSION_GONE))
        );
        assert!(helper.pipe.server.local_error().is_none());
    }

    #[test]
    fn webtransport_closed_session_cleans_metadata_and_cannot_resurrect() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (to_client, _from_client) = accept_webtransport_session(&mut helper);

        helper.peer_client_send_body(0, &[], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            0,
            WebTransportSessionCloseReason::Clean,
        );
        to_client
            .try_send(OutboundFrame::Body(Bytes::new(), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            helper.driver.webtransport.as_ref().unwrap().session_count(),
            0
        );

        let late =
            webtransport_stream_data(WEBTRANSPORT_BIDI_STREAM_TYPE, 0, b"late");
        helper.pipe.client.stream_send(4, &late, false).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_no_webtransport_session_event(&mut helper);
        assert_eq!(
            helper.pipe.client.stream_capacity(4),
            Err(quiche::Error::StreamStopped(
                webtransport::WT_BUFFERED_STREAM_REJECTED
            ))
        );
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .pending_stream_count(),
            0
        );
    }

    #[test]
    fn webtransport_local_close_retries_partial_output_before_commit() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                backpressured_webtransport_pipe(),
                webtransport_settings(),
            )
            .unwrap();
        let (to_client, _from_client) = accept_webtransport_session(&mut helper);

        to_client
            .try_send(OutboundFrame::Body(Bytes::from_static(&[b'p'; 48]), false))
            .unwrap();
        helper
            .controller
            .close_webtransport_session(0, 3, "close after padding".to_string())
            .unwrap();
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_no_driver_event(&mut helper);

        let mut committed = false;
        for _ in 0..8 {
            helper.pipe.advance().unwrap();
            loop {
                match helper.peer_client_poll() {
                    Ok((0, h3::Event::Data)) => {
                        let _ =
                            helper.peer_client_recv_body_vec(0, 4096).unwrap();
                    },
                    Ok((0, h3::Event::Finished)) | Err(h3::Error::Done) => break,
                    other => panic!("unexpected peer event: {other:?}"),
                }
            }
            helper.work_loop_iter().unwrap();
            match helper.controller.event_receiver_mut().try_recv() {
                Ok(ServerH3Event::Core(H3Event::WebTransportSession(
                    WebTransportSessionEvent::Terminated {
                        session_id: 0,
                        reason:
                            WebTransportSessionCloseReason::Local {
                                error_code: 3,
                                message,
                            },
                    },
                ))) if message == "close after padding" => {
                    committed = true;
                    break;
                },
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {},
                other => panic!("unexpected driver event: {other:?}"),
            }
        }
        assert!(
            committed,
            "local close never committed after credit returned"
        );
    }

    #[test]
    fn webtransport_local_close_commits_exact_capsule_and_fin_once() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        helper
            .controller
            .close_webtransport_session(0, 0x1020_3040, "goodbye".to_string())
            .unwrap();
        assert_eq!(helper.process_commands().unwrap(), 1);
        expect_session_terminated(
            &mut helper,
            0,
            WebTransportSessionCloseReason::Local {
                error_code: 0x1020_3040,
                message: "goodbye".to_string(),
            },
        );

        helper.pipe.advance().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 2048).unwrap(),
            webtransport_close_capsule(0x1020_3040, "goodbye")
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        helper
            .controller
            .close_webtransport_session(0, 9, "duplicate".to_string())
            .unwrap();
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_no_driver_event(&mut helper);
    }

    #[test]
    fn webtransport_local_close_rejects_oversized_message_before_queueing() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        assert_eq!(
            helper
                .controller
                .close_webtransport_session(0, 1, "x".repeat(1025),),
            Err(WebTransportSessionCloseError::MessageTooLong { len: 1025 })
        );
        assert_eq!(helper.process_commands().unwrap(), 0);
        assert!(helper.driver.webtransport.as_ref().unwrap().is_active(0));
    }

    #[test]
    fn webtransport_peer_close_parses_at_every_fragment_boundary() {
        let close = webtransport_close_capsule(7, "peer close");
        for split in 0..=close.len() {
            let mut helper = webtransport_helper(webtransport_settings());
            let (_to_client, _from_client) =
                accept_webtransport_session(&mut helper);

            if split != 0 {
                helper
                    .peer_client_send_body(0, &close[..split], false)
                    .unwrap();
                helper.advance_and_run_loop().unwrap();
                if split == close.len() {
                    expect_session_terminated(
                        &mut helper,
                        0,
                        WebTransportSessionCloseReason::Peer {
                            error_code: 7,
                            message: "peer close".to_string(),
                        },
                    );
                } else {
                    assert_no_driver_event(&mut helper);
                }
            }
            helper
                .peer_client_send_body(0, &close[split..], true)
                .unwrap();
            helper.advance_and_run_loop().unwrap();
            if split != close.len() {
                expect_session_terminated(
                    &mut helper,
                    0,
                    WebTransportSessionCloseReason::Peer {
                        error_code: 7,
                        message: "peer close".to_string(),
                    },
                );
            } else {
                assert_no_webtransport_session_event(&mut helper);
            }
            assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
            let body = helper.peer_client_recv_body_vec(0, 1);
            assert!(
                matches!(&body, Ok(bytes) if bytes.is_empty()) ||
                    body == Err(h3::Error::Done)
            );
            assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));
        }
    }

    #[test]
    fn webtransport_malformed_peer_close_fails_only_connect_stream() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        let mut malformed = Vec::new();
        encode_varint(webtransport::WT_CLOSE_SESSION, &mut malformed);
        encode_varint(3, &mut malformed);
        malformed.extend_from_slice(&[0; 3]);
        helper.peer_client_send_body(0, &malformed, true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            0,
            WebTransportSessionCloseReason::ProtocolError,
        );
        assert!(helper.pipe.server.local_error().is_none());
    }

    #[test]
    fn webtransport_data_after_peer_close_is_message_error() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        let close = webtransport_close_capsule(0, "done");
        helper.peer_client_send_body(0, &close, false).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            0,
            WebTransportSessionCloseReason::Peer {
                error_code: 0,
                message: "done".to_string(),
            },
        );

        helper.peer_client_send_body(0, b"after", true).unwrap();
        helper.advance_and_run_loop().unwrap();
        assert!(helper.pipe.server.local_error().is_none());
        assert_eq!(
            helper.pipe.client.stream_recv(0, &mut [0; 16]),
            Err(quiche::Error::StreamReset(
                h3::WireErrorCode::MessageError as u64
            ))
        );
    }

    #[test]
    fn webtransport_crossed_close_has_one_terminal_winner() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);

        let peer_close = webtransport_close_capsule(8, "peer wins");
        helper.peer_client_send_body(0, &peer_close, true).unwrap();
        helper
            .controller
            .close_webtransport_session(0, 9, "local loses".to_string())
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            0,
            WebTransportSessionCloseReason::Peer {
                error_code: 8,
                message: "peer wins".to_string(),
            },
        );
        assert_no_webtransport_session_event(&mut helper);
    }

    #[test]
    fn webtransport_connection_teardown_is_terminal_and_clears_metadata() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);
        let associated =
            webtransport_stream_data(WEBTRANSPORT_BIDI_STREAM_TYPE, 0, b"open");
        helper
            .pipe
            .client
            .stream_send(4, &associated, false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_associated_stream(
            &mut helper,
            0,
            4,
            WebTransportStreamDirection::Bidi,
            associated.len() - b"open".len(),
        );

        crate::ApplicationOverQuic::on_conn_close(
            &mut helper.driver,
            &mut helper.pipe.server,
            &TestMetrics::default(),
            &Ok(()),
        );
        expect_session_terminated(
            &mut helper,
            0,
            WebTransportSessionCloseReason::ConnectionClosed,
        );
        let runtime = helper.driver.webtransport.as_ref().unwrap();
        assert_eq!(runtime.session_count(), 0);
        assert_eq!(runtime.pending_stream_count(), 0);
        assert_eq!(runtime.active_stream_count(), 0);
    }

    #[test]
    fn client_fin_before_server_body() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client reads response and sends body and fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], true), Ok(5));
        helper.advance_and_run_loop().unwrap();

        // server receives body
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, vec![1; 5]);
        assert!(fin);

        // server sends body and fin
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[42]), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    #[test]
    fn verify_pr_2162() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request but NO FIN.
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.work_loop_iter().unwrap();
        // server sends body and fin. This caused an infinite loop before #2162
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[42]), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends body and fin
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], true), Ok(5));
        helper.advance_and_run_loop().unwrap();

        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, &[1; 5]);
        assert!(fin);

        // Stream is done
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    /// Test the case where the client sends a STOP_SENDING quiche frame.
    #[test]
    fn client_sends_stop_sending() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client sends a STOP_SENDING
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Read, 4242),
            Ok(())
        );
        helper.advance_and_run_loop().unwrap();

        // the client didn't send any additional data, a try_recv on the server
        // returns empty
        assert_matches!(from_client.try_recv(), Err(TryRecvError::Empty));
        // The way quiche is implemented, we need to attempt a write to the stream
        // to learn that it's closed. So we add an OutboundFrame to the
        // channel and let the driver write it. The driver gets a
        // StreamStopped back and closes the channel.
        to_client
            .try_send(OutboundFrame::Body(
                Bytes::copy_from_slice(&[23; 10]),
                false,
            ))
            .unwrap();
        helper.work_loop_iter().unwrap();
        assert!(to_client.is_closed());
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), 4242);
        helper.work_loop_iter().unwrap();

        // STOP_SENDING only closes one half of the stream. The client
        // can still send data and it MUST send a `fin` to close the
        // other half.
        helper.peer_client_send_body(0, &[1, 2, 3], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, &[1, 2, 3]);
        assert!(fin);

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), 4242);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        // technically quiche will automatically respond to a STOP_SENDING
        // frame with a STREAM_RESET echoing the error code, but the user
        // didn't *actively* send a STREAM_RESET.
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 3);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
    }

    /// Test the case where the client sends a RESET_STREAM quiche frame.
    /// The peer sends its reset before we send a fin
    #[test]
    fn client_sends_reset_stream_before_server_fin() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client (peer) sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client sends a RESET_STREAM frame
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.advance_and_run_loop().unwrap();

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        // We can still write to the peer and in fact, we must eventually send a
        // fin.
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[5; 4]), false))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[6; 4]), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Ok(vec![5, 5, 5, 5, 6, 6, 6, 6])
        );

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 0);
        assert_eq!(audit_stats.downstream_bytes_sent(), 8);
    }

    /// Test the case where the client sends a RESET_STREAM quiche frame.
    /// We send a fin before the client sends reset
    #[test]
    fn client_sends_reset_stream_after_server_fin() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client (peer) sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        // Send response, body, and fin to client
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.work_loop_iter().unwrap();
        to_client
            .try_send(OutboundFrame::Body(
                Bytes::copy_from_slice(b"foobar 42"),
                true,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a RESET_STREAM frame
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_matches!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        helper.peer_client_recv_body_vec(0, 1024).unwrap();
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.advance_and_run_loop().unwrap();

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 0);
        assert_eq!(
            audit_stats.downstream_bytes_sent(),
            b"foobar 42".len() as u64
        );
    }

    /// Test the case where the client sends a RESET_STREAM quiche frame while
    /// we're in the middle of reading data. We want to excercise the
    /// code-path where `upstream_ready` is called before `process_reads`.
    /// If `process_reads()` is called first, it will get the Reset event.
    /// If `upstream_ready()` is called first, it will attempt to read from
    /// the h3::Connection and will get a
    /// `TransportError(StreamReset(code))`
    #[test]
    fn client_sends_reset_stream_while_reading_wait_for_data() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client (peer) sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers and some body bytes
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.work_loop_iter().unwrap();
        to_client
            .try_send(OutboundFrame::Body(
                Bytes::copy_from_slice(&[1, 2, 3, 4]),
                false,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends data
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_matches!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        // The client sends the first half of the body.
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));

        // Advance the pipe and let the driver read the buffered body into the
        // `from_client` channel, filling it (`STREAM_CAPACITY` is 1 in tests).
        helper.pipe.advance().unwrap();
        helper.work_loop_iter().unwrap();

        // The client sends the second half. With the downstream channel full
        // and the stream readable again, the driver blocks the stream waiting
        // for capacity (registering it in `waiting_streams`) without reading
        // further.
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));
        helper.pipe.advance().unwrap();
        helper.work_loop_iter().unwrap();

        // Drain the first body frame; this frees downstream capacity so the
        // blocked stream can make progress on the next `wait_for_data`.
        assert_matches!(from_client.try_recv(), Ok(InboundFrame::Body(buf, fin)) => {
            assert_eq!(buf.to_vec(), &[1; 5]);
            assert!(!fin);
        });
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(TryRecvError::Empty)
        );

        // The client resets the stream; the buffered-but-unread second half is
        // dropped when the reset is processed.
        // TODO: This is a bit finnicky to test properly. We don't want to run a
        // full `work_loop_iter()` because that would call `process_reads()`
        // first; we exercise the path where `wait_for_data` / `upstream_ready`
        // observes the reset while reading.
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.pipe.advance().unwrap();
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never()
        .unwrap_or(Ok(()))
        .unwrap();

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        // We can still write to the peer and in fact, we must eventually send a
        // fin.
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[6; 4]), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Ok(vec![1, 2, 3, 4, 6, 6, 6, 6])
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 8);
    }

    /// Test the case where the client sends a RESET_STREAM quiche frame while
    /// we're in the middle of reading data. We want to excercise the
    /// code-path where where we call `process_reads` before
    /// `upstream_ready()`.
    #[test]
    fn server_sends_reset_stream_while_reading_process_reads() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client (peer) sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends data
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        // The client sends the first half of the body.
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));

        // Advance the pipe and let the driver read the buffered body and put
        // it into the `from_client` channel.
        helper.pipe.advance().unwrap();
        helper.work_loop_iter().unwrap();
        assert_matches!(from_client.try_recv(), Ok(InboundFrame::Body(buf, fin)) => {
            assert_eq!(buf.to_vec(), &[1; 5]);
            assert!(!fin);
        });
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );

        // The client sends the second half of the body (delivered to the
        // server but not yet read by the driver), then resets the stream. The
        // buffered-but-unread bytes are dropped when the reset is processed, so
        // they are never counted.
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.advance_and_run_loop().unwrap();

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        // send fin to client
        to_client
            .try_send(OutboundFrame::Body(Default::default(), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
    }

    #[test]
    fn server_driver_send_stop_sending_after_channel_drop() {
        const REQUEST_CANCELED_ERR: u64 =
            h3::WireErrorCode::RequestCancelled as u64;
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        let audit_stats = req.h3_audit_stats.clone();
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client reads response and sends body without fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));
        helper.advance_and_run_loop().unwrap();

        // server receives body
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, vec![1; 5]);
        assert!(!fin);

        // peer (client) sends more data
        assert_eq!(helper.peer_client_send_body(0, &[1; 6], false), Ok(6));
        // advance the pipe only
        helper.pipe.advance().unwrap();
        // we drop the channel.
        drop(from_client);
        helper.advance_and_run_loop().unwrap();

        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(TryRecvError::Empty)
        );

        // Make sure the peer has received our STOP_SENDING frame
        assert_eq!(
            helper.peer_client_send_body(0, &[1; 7], false),
            Err(h3::Error::TransportError(quiche::Error::StreamStopped(
                REQUEST_CANCELED_ERR
            )))
        );
        helper.advance_and_run_loop().unwrap();

        // we still need to send a fin
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[42]), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_stop_sending_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 1);
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    // Verify we don't send a STOP_SENDING frame if we've already processed a
    // fin
    #[test]
    fn server_driver_drop_channel_after_fin() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        let audit_stats = req.h3_audit_stats.clone();
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client reads response and sends body WITH fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], true), Ok(5));
        helper.advance_and_run_loop().unwrap();

        // server receives body
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, vec![1; 5]);
        assert!(fin);

        helper.advance_and_run_loop().unwrap();
        // we drop the channel.
        drop(from_client);
        helper.advance_and_run_loop().unwrap();

        // we still need to send a fin
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[42]), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 1);
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    // Test the edge case where the driver has read a fin from the stream but
    // hasn't been able to deliver it before the channel is dropped.
    #[test]
    fn server_driver_drop_channel_after_fin_2() {
        const REQUEST_CANCELED_ERR: u64 =
            h3::WireErrorCode::RequestCancelled as u64;
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        let audit_stats = req.h3_audit_stats.clone();
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client reads response and sends body without fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));
        helper.advance_and_run_loop().unwrap();

        // peer (client) sends more data and fin
        assert_eq!(helper.peer_client_send_body(0, &[1; 6], true), Ok(6));
        helper.advance_and_run_loop().unwrap();
        // we drop the channel.
        drop(req.recv);
        helper.advance_and_run_loop().unwrap();

        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(TryRecvError::Empty)
        );

        // we still need to send a fin
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[42]), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_stop_sending_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 1);
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    #[test]
    fn server_send_trailers() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client reads response and sends body and fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], true), Ok(5));
        helper.advance_and_run_loop().unwrap();

        // server receives body
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, vec![1; 5]);
        assert!(fin);

        // server sends body
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[42]), false))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );

        // server sends trailers
        to_client
            .try_send(OutboundFrame::Trailers(make_response_trailers(), None))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );

        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
    }

    /// Test that calling `H3Controller::shutdown_stream` with
    /// `StreamShutdown::Write` sends a RESET_STREAM frame to the peer.
    #[test]
    fn server_shutdown_stream_write_direction() {
        use crate::http3::driver::StreamShutdown;
        const CUSTOM_ERROR_CODE: u64 = 0x1234;

        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // server reads request
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        let audit_stats = req.h3_audit_stats.clone();

        // Server calls shutdown_stream via the controller
        helper
            .controller
            .shutdown_stream(stream_id, StreamShutdown::Write {
                error_code: CUSTOM_ERROR_CODE,
            });

        helper.advance_and_run_loop().unwrap();

        // Client should receive the RESET_STREAM
        // Note: quiche::h3 reports RESET_STREAM via a TransportError when
        // trying to read from the stream
        assert_eq!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Reset(CUSTOM_ERROR_CODE)))
        );

        // Verify stats
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            CUSTOM_ERROR_CODE as i64
        );
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
    }

    /// Test that calling `H3Controller::shutdown_stream` with
    /// `StreamShutdown::Read` sends a STOP_SENDING frame to the peer.
    #[test]
    fn server_shutdown_stream_read_direction() {
        use crate::http3::driver::StreamShutdown;
        const CUSTOM_ERROR_CODE: u64 = 0x5678;

        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request without fin (expecting to send body)
        let stream_id = helper
            .peer_client_send_request(make_request_headers("POST"), false)
            .unwrap();

        // server reads request
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        let audit_stats = req.h3_audit_stats.clone();

        // Server calls shutdown_stream with Read direction (STOP_SENDING)
        helper
            .controller
            .shutdown_stream(stream_id, StreamShutdown::Read {
                error_code: CUSTOM_ERROR_CODE,
            });

        helper.advance_and_run_loop().unwrap();

        // Client tries to send body - should get StreamStopped error
        assert_eq!(
            helper.peer_client_send_body(0, &[1, 2, 3], false),
            Err(h3::Error::TransportError(quiche::Error::StreamStopped(
                CUSTOM_ERROR_CODE
            )))
        );

        // Verify stats
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_stop_sending_error_code(),
            CUSTOM_ERROR_CODE as i64
        );
    }

    /// Test that calling `H3Controller::shutdown_stream` with
    /// `StreamShutdown::Both` sends both RESET_STREAM and STOP_SENDING
    /// frames to the peer.
    #[test]
    fn server_shutdown_stream_both_directions() {
        use crate::http3::driver::StreamShutdown;
        const READ_ERROR_CODE: u64 = 0xAAAA;
        const WRITE_ERROR_CODE: u64 = 0xBBBB;

        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request without fin
        let stream_id = helper
            .peer_client_send_request(make_request_headers("POST"), false)
            .unwrap();

        // server reads request
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        let audit_stats = req.h3_audit_stats.clone();

        // Server calls shutdown_stream with Both directions
        helper
            .controller
            .shutdown_stream(stream_id, StreamShutdown::Both {
                read_error_code: READ_ERROR_CODE,
                write_error_code: WRITE_ERROR_CODE,
            });

        helper.advance_and_run_loop().unwrap();

        // Client should see STOP_SENDING when trying to send
        assert_eq!(
            helper.peer_client_send_body(0, &[1, 2, 3], false),
            Err(h3::Error::TransportError(quiche::Error::StreamStopped(
                READ_ERROR_CODE
            )))
        );

        // Client should see RESET_STREAM when trying to receive
        assert_eq!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Reset(WRITE_ERROR_CODE)))
        );

        // Verify stats
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            WRITE_ERROR_CODE as i64
        );
        assert_eq!(
            audit_stats.sent_stop_sending_error_code(),
            READ_ERROR_CODE as i64
        );
    }

    /// Verify that a GOAWAY received from the client does not affect
    /// in-flight response streams. The client sends GOAWAY with push
    /// ID 0 (the only value currently supported, since server push is
    /// not implemented). The server should surface the GoAway event
    /// and continue sending response data normally.
    ///
    /// Per RFC 9114 Section 5.2, when a client sends GOAWAY, the ID
    /// is a push ID indicating the range of pushes the client will
    /// accept. Since server push is unimplemented, the client always
    /// sends 0.
    #[test]
    fn server_receiving_goaway_keeps_connection_intact() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client sends a request.
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), true)
            .unwrap();
        assert_eq!(stream_id, 0);

        // Server receives the request and starts a streaming response.
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        let to_client = req.send.get_ref().unwrap().clone();
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client receives response headers.
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );

        // Server sends first body chunk.
        to_client
            .try_send(OutboundFrame::Body(
                Bytes::copy_from_slice(&[1; 10]),
                false,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client receives the first body chunk.
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![1; 10]));

        // Client sends GOAWAY with push ID 0 (graceful shutdown).
        helper.peer.send_goaway(&mut helper.pipe.client, 0).unwrap();
        helper.advance_and_run_loop().unwrap();

        // Server driver surfaces the GoAway event.
        loop {
            match helper.driver_recv_core_event().unwrap() {
                H3Event::GoAway { id } => {
                    assert_eq!(id, 0);
                    break;
                },
                H3Event::BodyBytesReceived { .. } => continue,
                H3Event::StreamClosed { .. } => continue,
                other => panic!("unexpected event: {other:?}"),
            }
        }

        // Server continues sending response body — the connection is
        // still alive.
        to_client
            .try_send(OutboundFrame::Body(
                Bytes::copy_from_slice(&[2; 10]),
                false,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client still receives the data.
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![2; 10]));

        // Server finishes the response.
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[3; 10]), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client receives the final chunk and fin.
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![3; 10]));
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));
    }

    // Test that dropping the H3 event receiver when there are no active streams
    // and datagram flows causes the connection to close immediately.
    #[test]
    fn h3_controller_drop_closes_connection_when_maps_empty() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();

        assert!(helper.driver.stream_map.is_empty());
        assert!(helper.driver.flow_map.is_empty());
        assert!(helper.pipe.server.local_error().is_none());

        // drop the controller to trigger receiver drop detection
        drop(helper.controller);

        // run wait_for_data to detect the receiver drop
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        // connection closed with H3 NoError
        let local_error = helper
            .pipe
            .server
            .local_error()
            .expect("connection should be closing");
        assert!(local_error.is_app, "should be application-level close");
        assert_eq!(
            local_error.error_code,
            h3::WireErrorCode::NoError as u64,
            "should close with H3 NoError"
        );
    }

    // Test that dropping the H3Controller when there are active streams/flows
    // does NOT close the connection immediately (e.g. tunnel scenarios).
    #[test]
    fn h3_controller_drop_keeps_connection_alive_when_streams_exist() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                quiche::test_utils::Pipe::with_config_and_buf(
                    &mut default_quiche_config(),
                )
                .unwrap(),
                Http3Settings {
                    enable_extended_connect: true,
                    ..Default::default()
                },
            )
            .unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // CONNECT-UDP request creates both a stream and a datagram flow
        let connect_headers = vec![
            h3::Header::new(b":method", b"CONNECT-UDP"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", b"quic.tech"),
            h3::Header::new(b":path", b"/"),
            h3::Header::new(b"datagram-flow-id", b"0"),
        ];
        helper
            .peer_client_send_request(connect_headers, false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // Consume events to keep channels alive
        assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Core(H3Event::NewFlow { .. })
        );
        assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers { .. }
        );

        assert_eq!(helper.driver.stream_map.len(), 1);
        assert_eq!(helper.driver.flow_map.len(), 1);

        drop(helper.controller);
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        // Connection stays open (stream and flow still active)
        assert!(helper.pipe.server.local_error().is_none());
    }

    /// Test that a CONNECT request with `:protocol` does NOT create a
    /// datagram flow when extended CONNECT is disabled.
    #[test]
    fn protocol_without_extended_connect_closes_on_controller_drop() {
        // Default settings have enable_extended_connect: false
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // CONNECT with :protocol, but extended CONNECT is disabled
        let connect_headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", b"quic.tech"),
            h3::Header::new(b":path", b"/"),
            h3::Header::new(b":protocol", b"webtransport"),
        ];
        helper
            .peer_client_send_request(connect_headers, true)
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // No NewFlow event — flow was not created
        assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers { .. }
        );

        assert_eq!(helper.driver.stream_map.len(), 1);
        assert_eq!(helper.driver.flow_map.len(), 0);

        // Drop controller, then run wait_for_data
        drop(helper.controller);
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        // Connection closes because stream_map and flow_map are empty
        let local_error = helper
            .pipe
            .server
            .local_error()
            .expect("connection should be closing");
        assert!(local_error.is_app, "should be application-level close");
        assert_eq!(
            local_error.error_code,
            h3::WireErrorCode::NoError as u64,
            "should close with H3 NoError"
        );
    }

    /// Drop the event receiver with an open stream, then close the
    /// stream via client fin. Verify the connection closes.
    #[test]
    fn controller_drop_then_stream_close_triggers_connection_close() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // Client sends a request the stream stays open
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => {
                incoming_headers
            }
        );
        assert_eq!(req.stream_id, stream_id);
        let to_client = req.send.get_ref().unwrap().clone();

        // Send response headers + body with fin
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        to_client
            .try_send(OutboundFrame::Body(Bytes::from_static(b"ok"), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        assert_eq!(helper.driver.stream_map.len(), 1);

        // Drop the stream channels so cleanup_stream can remove
        // the stream from the map
        drop(to_client);
        drop(req);

        // Client reads response and sends fin to close the stream
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Ok(vec![111, 107])
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        // Drop the controller
        drop(helper.controller);
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        // Connection should NOT close yet (stream still open)
        assert!(helper.pipe.server.local_error().is_none());

        // Client sends fin to close the stream
        assert_eq!(
            helper
                .peer
                .send_body(&mut helper.pipe.client, 0, b"done", true,),
            Ok(4)
        );
        // One IO worker iteration: deliver client fin, process it,
        // and close the connection.
        helper.pipe.advance().unwrap();
        helper
            .driver
            .process_reads(&mut helper.pipe.server)
            .unwrap();
        helper
            .driver
            .process_writes(&mut helper.pipe.server)
            .unwrap();
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        assert_eq!(helper.driver.stream_map.len(), 0);

        // Now the connection should close with NoError
        let local_error = helper
            .pipe
            .server
            .local_error()
            .expect("connection should be closing");
        assert!(local_error.is_app, "should be application-level close");
        assert_eq!(
            local_error.error_code,
            h3::WireErrorCode::NoError as u64,
            "should close with H3 NoError"
        );
    }

    /// Drop the event receiver with an autonomous flow open (a flow
    /// with no associated stream), then shut down the flow. Verify
    /// the connection closes.
    #[test]
    fn controller_drop_then_autonomous_flow_shutdown_triggers_connection_close() {
        let mut config = default_quiche_config();
        config.enable_dgram(true, 100, 100);

        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                quiche::test_utils::Pipe::with_config_and_buf(&mut config)
                    .unwrap(),
                Http3Settings {
                    enable_extended_connect: true,
                    ..Default::default()
                },
            )
            .unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // Peer sends an H3 datagram for a flow_id with no associated
        // CONNECT-UDP stream. Wire format: varint(flow_id) || payload.
        let flow_id: u64 = 8;
        let payload: &[u8] = b"hi";
        let prefix_len = octets::varint_len(flow_id);
        let mut wire = vec![0u8; prefix_len + payload.len()];
        {
            let mut enc = octets::OctetsMut::with_slice(&mut wire);
            enc.put_varint(flow_id).unwrap();
            enc.put_bytes(payload).unwrap();
        }
        helper.pipe.client.dgram_send(&wire).unwrap();

        // process_available_dgrams creates an autonomous flow and
        // emits NewFlow.
        helper.advance_and_run_loop().unwrap();

        let flow_send = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Core(H3Event::NewFlow { send, .. }) => send
        );
        let flow_sender = flow_send.get_ref().unwrap().clone();

        assert!(helper.driver.stream_map.is_empty());
        assert_eq!(helper.driver.flow_map.len(), 1);

        // Drop the controller. closed() fires, sets the flag, but
        // flow_map is non-empty so no close yet.
        drop(helper.controller);
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();
        assert!(helper.pipe.server.local_error().is_none());

        // Send FlowShutdown via the per-flow channel.
        flow_sender
            .try_send(OutboundFrame::FlowShutdown {
                flow_id,
                stream_id: flow_id,
            })
            .unwrap();

        // wait_for_data picks up the frame and calls dgram_ready.
        // shutdown_stream returns early (no stream), so the close
        // gate in cleanup_stream is never invoked.
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();
        drop(flow_sender);
        drop(flow_send);

        assert!(helper.driver.stream_map.is_empty());
        assert!(helper.driver.flow_map.is_empty());

        // closed() is gated off; no other arm can drive a close.
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        let local_error = helper
            .pipe
            .server
            .local_error()
            .expect("connection should be closing");
        assert!(local_error.is_app, "should be application-level close");
        assert_eq!(
            local_error.error_code,
            h3::WireErrorCode::NoError as u64,
            "should close with H3 NoError"
        );
    }

    /// Verify that datagrams are silently dropped and no flow is
    /// created when extended connect is disabled.
    #[test]
    fn process_dgram_skips_flow_creation_when_extended_connect_disabled() {
        let mut config = default_quiche_config();
        config.enable_dgram(true, 100, 100);

        // Default settings have enable_extended_connect: false
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                quiche::test_utils::Pipe::with_config_and_buf(&mut config)
                    .unwrap(),
                Http3Settings::default(),
            )
            .unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        let flow_id: u64 = 8;
        let payload: &[u8] = b"hi";
        let prefix_len = octets::varint_len(flow_id);
        let mut wire = vec![0u8; prefix_len + payload.len()];
        {
            let mut enc = octets::OctetsMut::with_slice(&mut wire);
            enc.put_varint(flow_id).unwrap();
            enc.put_bytes(payload).unwrap();
        }
        helper.pipe.client.dgram_send(&wire).unwrap();

        helper.advance_and_run_loop().unwrap();

        // No flow should be created
        assert!(
            helper.driver.flow_map.is_empty(),
            "flow_map should remain empty when extended connect is disabled"
        );
    }
}
