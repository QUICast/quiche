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
    fn client_rejects_second_session_without_consuming_a_stream_id() {
        let mut helper = webtransport_helper();
        start_webtransport_driver(&mut helper);
        let (_session_id, _body) =
            open_pending_webtransport_session(&mut helper, 21);

        helper.driver_enqueue_request(22, webtransport_request_headers(), None);
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::WebTransportRequestRejected { request_id: 22 }
        );

        helper.driver_enqueue_request(23, make_request_headers("GET"), None);
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::NewOutboundRequest {
                stream_id: 4,
                request_id: 23,
            }
        );
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

        helper.driver_enqueue_request(14, webtransport_request_headers(), None);
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_matches!(
            helper.driver_recv_client_event().unwrap(),
            ClientH3Event::WebTransportRequestRejected { request_id: 14 }
        );
        assert_eq!(helper.driver.hooks.queued_webtransport_request_count(), 1);

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

    fn single_dgram_queue_webtransport_pipe() -> DriverPipe {
        let mut config = default_quiche_config();
        config.enable_dgram(true, 10, 1);
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

    fn payload_backpressured_webtransport_pipe() -> DriverPipe {
        let mut client = default_quiche_config();
        client.set_initial_max_stream_data_bidi_remote(64);
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

    fn single_server_stream_each_direction_webtransport_pipe() -> DriverPipe {
        let mut client = default_quiche_config();
        client.set_initial_max_streams_bidi(1);
        // The server consumes four unidirectional streams for HTTP/3 control,
        // QPACK, and grease, leaving exactly one for WebTransport.
        client.set_initial_max_streams_uni(5);
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

    #[derive(Clone, Debug, Default)]
    struct MockWriteLeaseLog {
        exposures: usize,
        exposed_pointers: Vec<usize>,
        abandonments: Vec<WebTransportStreamWriteLeaseProgress>,
        drops: usize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockWriteLeaseError {
        Unavailable,
    }

    struct MockWriteLease {
        id: u64,
        payload: Box<[u8]>,
        declared_len: usize,
        retained_bytes: usize,
        fail_exposure: bool,
        log: std::sync::Arc<std::sync::Mutex<MockWriteLeaseLog>>,
    }

    impl fmt::Debug for MockWriteLease {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("MockWriteLease")
                .field("id", &self.id)
                .field("payload_len", &self.payload.len())
                .field("declared_len", &self.declared_len)
                .field("retained_bytes", &self.retained_bytes)
                .finish_non_exhaustive()
        }
    }

    impl WebTransportStreamWriteLease for MockWriteLease {
        type Error = MockWriteLeaseError;

        fn payload_len(&self) -> usize {
            self.declared_len
        }

        fn retained_bytes(&self) -> usize {
            self.retained_bytes
        }

        fn as_slice(&mut self) -> Result<&[u8], Self::Error> {
            if self.fail_exposure {
                return Err(MockWriteLeaseError::Unavailable);
            }
            let mut log = self
                .log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            log.exposures += 1;
            log.exposed_pointers.push(self.payload.as_ptr() as usize);
            drop(log);
            Ok(&self.payload)
        }

        fn on_write_abandoned(
            &mut self, progress: WebTransportStreamWriteLeaseProgress,
        ) {
            self.log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .abandonments
                .push(progress);
        }
    }

    impl Drop for MockWriteLease {
        fn drop(&mut self) {
            self.log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .drops += 1;
        }
    }

    fn mock_write_lease(
        id: u64, payload: &[u8],
    ) -> (
        MockWriteLease,
        std::sync::Arc<std::sync::Mutex<MockWriteLeaseLog>>,
    ) {
        let log = std::sync::Arc::new(std::sync::Mutex::new(
            MockWriteLeaseLog::default(),
        ));
        (
            MockWriteLease {
                id,
                payload: payload.into(),
                declared_len: payload.len(),
                retained_bytes: payload.len(),
                fail_exposure: false,
                log: std::sync::Arc::clone(&log),
            },
            log,
        )
    }

    fn mock_write_lease_log(
        log: &std::sync::Arc<std::sync::Mutex<MockWriteLeaseLog>>,
    ) -> MockWriteLeaseLog {
        log.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
            tokio::task::yield_now().await;
            if open.is_finished() {
                break;
            }
        }
        assert!(open.is_finished(), "bidirectional stream open stalled");
        assert_matches!(
            open.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        )
    }

    async fn open_server_webtransport_uni(
        helper: &mut DriverTestHelper<ServerHooks>,
        controller: &WebTransportController, session_id: u64,
    ) -> u64 {
        let open_controller = controller.clone();
        let open = tokio::spawn(async move {
            open_controller.open_unidirectional_stream(session_id).await
        });
        tokio::task::yield_now().await;
        for _ in 0..4 {
            helper.work_loop_iter().unwrap();
            tokio::task::yield_now().await;
            if open.is_finished() {
                break;
            }
        }
        assert!(open.is_finished(), "unidirectional stream open stalled");
        assert_matches!(
            open.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        )
    }

    fn receive_server_webtransport_stream(
        helper: &mut DriverTestHelper<ServerHooks>, session_id: u64,
        stream_id: u64, direction: h3::WebTransportStreamDirection,
    ) {
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.peer_client_poll(),
            Ok((stream_id, h3::Event::WebTransportStream {
                session_id,
                direction,
                prefix_len: 3,
            }))
        );
    }

    fn wait_for_send_terminal(
        controller: &WebTransportController, session_id: u64, stream_id: u64,
    ) -> tokio::task::JoinHandle<WebTransportStreamSendTerminalOutcome> {
        let controller = controller.clone();
        tokio::spawn(async move {
            controller
                .wait_stream_send_terminal(session_id, stream_id)
                .await
        })
    }

    fn wait_for_session_terminal(
        controller: &WebTransportController, session_id: u64,
    ) -> tokio::task::JoinHandle<WebTransportSessionTerminalOutcome> {
        let controller = controller.clone();
        tokio::spawn(
            async move { controller.wait_session_terminal(session_id).await },
        )
    }

    fn retire_send_terminal(
        controller: &WebTransportController, session_id: u64, stream_id: u64,
    ) -> tokio::task::JoinHandle<WebTransportStreamSendTerminalOutcome> {
        let controller = controller.clone();
        tokio::spawn(async move {
            controller
                .retire_stream_send_terminal(session_id, stream_id)
                .await
        })
    }

    fn retire_receive_terminal(
        controller: &WebTransportController, session_id: u64, stream_id: u64,
    ) -> tokio::task::JoinHandle<WebTransportStreamReceiveTerminalRetirementOutcome>
    {
        let controller = controller.clone();
        tokio::spawn(async move {
            controller
                .retire_stream_receive_terminal(session_id, stream_id)
                .await
        })
    }

    async fn webtransport_retention_stats(
        helper: &mut DriverTestHelper<ServerHooks>,
        controller: &WebTransportController,
    ) -> WebTransportRetentionStats {
        let controller = controller.clone();
        let stats =
            tokio::spawn(async move { controller.retention_stats().await });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        stats.await.unwrap().unwrap()
    }

    fn assert_terminal_retention_current_zero(
        stats: &WebTransportRetentionStats,
    ) {
        assert_eq!(stats.sessions, 0);
        assert_eq!(stats.associated_streams, 0);
        assert_eq!(stats.provisional_streams, 0);
        assert_eq!(stats.stream_open_waiters, 0);
        assert_eq!(stats.session_terminal_waiters, 0);
        assert_eq!(stats.waiters, 0);
        assert_eq!(stats.send_terminal_waiters, 0);
        assert_eq!(stats.send_terminal_states, 0);
        assert_eq!(stats.send_terminal_overloaded_sessions, 0);
        assert_eq!(stats.receive_terminal_observations, 0);
        assert_eq!(stats.receive_terminal_states, 0);
        assert_eq!(stats.receive_terminal_waiters, 0);
        assert_eq!(stats.receive_terminal_leases, 0);
        assert_eq!(stats.receive_terminal_bytes, 0);
        assert_eq!(stats.bounded_client_connect_owners, 0);
        assert_eq!(stats.metadata_index_entries, 0);
        assert_eq!(stats.pending_datagrams, 0);
        assert_eq!(stats.pending_datagram_payload_bytes, 0);
        assert_eq!(stats.pending_datagram_allocation_bytes, 0);
        assert_eq!(stats.terminal_retention_waiters, 0);
        assert_eq!(stats.live_connection_snapshot_requests, 0);
        assert_eq!(stats.queued_commands, 0);
        assert_eq!(stats.queued_command_payload_bytes_upper_bound, 0);
        assert_eq!(stats.write_leases, 0);
        assert_eq!(stats.write_lease_retained_bytes, 0);
        assert_eq!(stats.adapter_bytes_upper_bound(), 0);
        assert_eq!(stats.transport_queued_bytes(), 0);
    }

    async fn release_server_webtransport_stream_credit(
        helper: &mut DriverTestHelper<ServerHooks>,
        controller: &WebTransportController, session_id: u64, stream_id: u64,
        direction: WebTransportStreamDirection, application_error: u32,
    ) {
        let reset_controller = controller.clone();
        let reset = tokio::spawn(async move {
            reset_controller
                .reset_stream(session_id, stream_id, application_error)
                .await
        });
        let stop = (direction == WebTransportStreamDirection::Bidi).then(|| {
            let stop_controller = controller.clone();
            tokio::spawn(async move {
                stop_controller
                    .stop_stream(session_id, stream_id, application_error)
                    .await
            })
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
            helper.work_loop_iter().unwrap();
            if reset.is_finished() &&
                stop.as_ref()
                    .is_none_or(tokio::task::JoinHandle::is_finished)
            {
                break;
            }
        }
        assert_eq!(
            reset.await.unwrap(),
            WebTransportStreamControlOutcome::Applied
        );
        if let Some(stop) = stop {
            assert_eq!(
                stop.await.unwrap(),
                WebTransportStreamControlOutcome::Applied
            );
        }

        helper.pipe.advance().unwrap();
        let wire_error = webtransport_error_to_http3(application_error);
        if direction == WebTransportStreamDirection::Bidi {
            assert_eq!(
                helper.pipe.client.stream_capacity(stream_id),
                Err(quiche::Error::StreamStopped(wire_error))
            );
        }
        assert_eq!(
            helper.pipe.client.stream_recv(stream_id, &mut [0; 1]),
            Err(quiche::Error::StreamReset(wire_error))
        );
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
    fn webtransport_request_waits_for_client_settings_before_app_admission() {
        let mut helper = webtransport_helper(webtransport_settings());
        helper
            .driver
            .on_conn_established(
                &mut helper.pipe.server,
                &HandshakeInfo::new(Instant::now(), None),
            )
            .unwrap();
        assert!(helper
            .driver
            .conn
            .as_ref()
            .unwrap()
            .peer_settings_raw()
            .is_none());

        <ServerHooks as DriverHooks>::headers_received(
            &mut helper.driver,
            &mut helper.pipe.server,
            InboundHeaders {
                stream_id: 0,
                headers: make_webtransport_request_headers(),
                has_body: true,
            },
        )
        .unwrap();
        assert!(helper.driver.hooks.has_deferred_webtransport_request());
        assert!(helper.driver.webtransport.as_ref().unwrap().is_pending(0));
        assert_no_driver_event(&mut helper);

        helper.pipe.advance().unwrap();
        helper
            .driver
            .process_reads(&mut helper.pipe.server)
            .unwrap();
        assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingSettings { .. }
        );
        expect_session_pending(&mut helper, 0);
        assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers { incoming_headers, .. }
                if incoming_headers.stream_id == 0
        );
        assert!(!helper.driver.hooks.has_deferred_webtransport_request());
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
    async fn webtransport_write_lease_preflight_and_lane_rejections_preserve_owner(
    ) {
        let mut settings = webtransport_settings();
        settings.webtransport_command_capacity = 1;
        settings.webtransport_max_stream_write_bytes = 4;
        settings.webtransport_max_stream_write_lease_retained_bytes = 4;
        let mut helper = webtransport_helper(settings);
        start_webtransport_driver(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let (oversized, oversized_log) = mock_write_lease(1, b"12345");
        let oversized = assert_matches!(
            controller.try_write_stream_lease(0, 1, oversized, true),
            Err(outcome) => outcome
        );
        assert_eq!(
            oversized.progress(),
            WebTransportStreamWriteLeaseProgress::NeverExposed
        );
        let oversized = assert_matches!(
            oversized,
            WebTransportStreamWriteLeaseOutcome::TooLarge {
                limit: WebTransportStreamWriteLeaseLimit::Payload,
                max: 4,
                actual: 5,
                lease,
                fin: true,
            } => lease
        );
        assert_eq!(oversized.id, 1);
        assert_eq!(mock_write_lease_log(&oversized_log).exposures, 0);
        drop(oversized);

        let (mut retained_oversized, retained_oversized_log) =
            mock_write_lease(2, b"x");
        retained_oversized.retained_bytes = 5;
        let retained_oversized = assert_matches!(
            controller.try_write_stream_lease(
                0,
                1,
                retained_oversized,
                false,
            ),
            Err(WebTransportStreamWriteLeaseOutcome::TooLarge {
                limit: WebTransportStreamWriteLeaseLimit::RetainedBytes,
                max: 4,
                actual: 5,
                lease,
                fin: false,
            }) => lease
        );
        assert_eq!(retained_oversized.id, 2);
        assert_eq!(mock_write_lease_log(&retained_oversized_log).exposures, 0);
        drop(retained_oversized);

        let (held, held_log) = mock_write_lease(3, b"held");
        let held = controller.try_write_stream_lease(0, 1, held, true).unwrap();
        assert_eq!(
            helper.driver.webtransport_cmd_recv.as_ref().unwrap().len(),
            1
        );

        let (waiting, waiting_log) = mock_write_lease(4, b"wait");
        let waiting_controller = controller.clone();
        let waiting_task = tokio::spawn(async move {
            waiting_controller
                .write_stream_lease(0, 1, waiting, false)
                .await
        });
        tokio::task::yield_now().await;
        assert!(!waiting_task.is_finished());
        waiting_task.abort();
        assert!(waiting_task.await.unwrap_err().is_cancelled());
        let waiting_log = mock_write_lease_log(&waiting_log);
        assert_eq!(waiting_log.exposures, 0);
        assert_eq!(waiting_log.drops, 1);
        assert_eq!(waiting_log.abandonments, [
            WebTransportStreamWriteLeaseProgress::NeverExposed
        ]);

        let (full, full_log) = mock_write_lease(5, b"full");
        let full = assert_matches!(
            controller.try_write_stream_lease(0, 1, full, false),
            Err(WebTransportStreamWriteLeaseOutcome::QueueFull {
                lease,
                fin: false,
            }) => lease
        );
        assert_eq!(full.id, 5);
        assert_eq!(mock_write_lease_log(&full_log).exposures, 0);
        drop(full);

        helper.work_loop_iter().unwrap();
        let held = assert_matches!(
            held.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::UnknownSession,
                lease,
                fin: true,
            } => lease
        );
        assert_eq!(held.id, 3);
        assert_eq!(mock_write_lease_log(&held_log).exposures, 0);
        drop(held);

        let stats_controller = controller.clone();
        let stats =
            tokio::spawn(async move { stats_controller.retention_stats().await });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let stats = stats.await.unwrap().unwrap();
        assert_eq!(stats.write_leases, 0);
        assert_eq!(stats.write_lease_admitted_total, 1);
        assert_eq!(stats.write_lease_queue_full_total, 1);
        assert_eq!(stats.write_lease_resource_limit_total, 0);
        assert_eq!(stats.write_lease_too_large_total, 2);

        helper.driver.close_webtransport_command_lane();

        let (closed, closed_log) = mock_write_lease(6, b"shut");
        let closed = assert_matches!(
            controller.try_write_stream_lease(0, 1, closed, false),
            Err(WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::ConnectionClosed,
                lease,
                fin: false,
            }) => lease
        );
        assert_eq!(closed.id, 6);
        assert_eq!(mock_write_lease_log(&closed_log).exposures, 0);
    }

    #[tokio::test]
    async fn webtransport_write_lease_is_byte_exact_without_prewrite_copy() {
        let mut settings = webtransport_settings();
        settings.webtransport_max_stream_write_bytes = 8;
        settings.webtransport_max_stream_write_lease_retained_bytes = 8;
        let mut helper = webtransport_helper(settings);
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
        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { .. })) if id == stream_id
        );

        let (too_large, too_large_log) = mock_write_lease(10, b"123456789");
        let too_large = assert_matches!(
            controller.try_write_stream_lease(
                session_id,
                stream_id,
                too_large,
                true,
            ),
            Err(WebTransportStreamWriteLeaseOutcome::TooLarge {
                limit: WebTransportStreamWriteLeaseLimit::Payload,
                max: 8,
                actual: 9,
                lease,
                fin: true,
            }) => lease
        );
        assert_eq!(mock_write_lease_log(&too_large_log).exposures, 0);
        drop(too_large);

        let (mut unavailable, unavailable_log) = mock_write_lease(13, b"unready");
        unavailable.fail_exposure = true;
        let unavailable = controller
            .try_write_stream_lease(session_id, stream_id, unavailable, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let unavailable = assert_matches!(
            unavailable.outcome().await,
            WebTransportStreamWriteLeaseOutcome::LeaseError {
                error: MockWriteLeaseError::Unavailable,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(unavailable.id, 13);
        assert_eq!(mock_write_lease_log(&unavailable_log).exposures, 0);
        drop(unavailable);

        let (mut invalid_length, invalid_length_log) =
            mock_write_lease(14, b"12345678");
        invalid_length.declared_len = 7;
        let invalid_length = controller
            .try_write_stream_lease(session_id, stream_id, invalid_length, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let invalid_length = assert_matches!(
            invalid_length.outcome().await,
            WebTransportStreamWriteLeaseOutcome::InvalidLength {
                declared: 7,
                actual: 8,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(invalid_length.id, 14);
        assert_eq!(mock_write_lease_log(&invalid_length_log).exposures, 1);
        drop(invalid_length);

        let (lease, log) = mock_write_lease(11, b"12345678");
        let original_pointer = lease.payload.as_ptr() as usize;
        let operation = controller
            .try_write_stream_lease(session_id, stream_id, lease, true)
            .unwrap();
        assert_eq!(operation.retained_bytes(), 8);
        assert_eq!(mock_write_lease_log(&log).exposures, 0);
        helper.work_loop_iter().unwrap();
        let outcome = operation.outcome().await;
        assert_eq!(
            outcome.progress(),
            WebTransportStreamWriteLeaseProgress::AcceptedComplete {
                accepted: 8,
                fin_accepted: true,
            }
        );
        let lease = assert_matches!(
            outcome,
            WebTransportStreamWriteLeaseOutcome::Accepted {
                lease,
                accepted: 8,
                complete: true,
                fin_accepted: true,
            } => lease
        );
        assert_eq!(lease.id, 11);
        assert_eq!(lease.payload.as_ptr() as usize, original_pointer);
        let snapshot = mock_write_lease_log(&log);
        assert_eq!(snapshot.exposures, 1);
        assert_eq!(snapshot.exposed_pointers, [original_pointer]);
        assert!(snapshot.abandonments.is_empty());
        assert_eq!(snapshot.drops, 0);
        drop(lease);
        assert_eq!(mock_write_lease_log(&log).drops, 1);

        helper.pipe.advance().unwrap();
        let mut payload = [0; 16];
        assert_eq!(
            helper.pipe.client.stream_recv(stream_id, &mut payload),
            Ok((8, true))
        );
        assert_eq!(&payload[..8], b"12345678");

        let fin_stream =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { .. })) if id == fin_stream
        );
        let (fin_only, fin_log) = mock_write_lease(12, b"");
        let fin_only = controller
            .try_write_stream_lease(session_id, fin_stream, fin_only, true)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let fin_only = assert_matches!(
            fin_only.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Accepted {
                lease,
                accepted: 0,
                complete: true,
                fin_accepted: true,
            } => lease
        );
        assert_eq!(fin_only.id, 12);
        assert_eq!(mock_write_lease_log(&fin_log).exposures, 1);
        drop(fin_only);
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.pipe.client.stream_recv(fin_stream, &mut payload),
            Ok((0, true))
        );
    }

    #[tokio::test]
    async fn webtransport_write_lease_reports_exact_core_block_reasons() {
        #[derive(Clone, Copy)]
        enum Cause {
            Connection,
            Congestion,
            CapacityFactor,
            Retention,
            Mixed,
        }

        for (index, cause) in [
            Cause::Connection,
            Cause::Congestion,
            Cause::CapacityFactor,
            Cause::Retention,
            Cause::Mixed,
        ]
        .into_iter()
        .enumerate()
        {
            let mut client = default_quiche_config();
            client.set_initial_max_stream_data_bidi_remote(
                if matches!(cause, Cause::Mixed) {
                    3
                } else {
                    1_000_000
                },
            );
            if matches!(cause, Cause::Mixed) {
                client.set_initial_max_stream_data_uni(1_000_000);
            }
            if matches!(
                cause,
                Cause::Congestion |
                    Cause::CapacityFactor |
                    Cause::Retention |
                    Cause::Mixed
            ) {
                client.set_initial_max_data(1_000_000);
            }
            client.enable_dgram(true, 10, 10);
            client.enable_reset_stream_at(true);

            let mut server = default_quiche_config();
            if matches!(cause, Cause::CapacityFactor | Cause::Mixed) {
                server.set_send_capacity_factor(0.5);
            }
            server.enable_dgram(true, 10, 10);
            server.enable_reset_stream_at(true);
            let pipe =
                quiche::test_utils::Pipe::with_client_and_server_config_and_buf(
                    &mut client,
                    &mut server,
                )
                .unwrap();
            let mut helper =
                DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                    pipe,
                    webtransport_settings(),
                )
                .unwrap();
            start_webtransport_driver(&mut helper);
            let (session_id, to_client, _from_client) =
                open_pending_webtransport_session(&mut helper);
            accept_pending_webtransport_session(
                &mut helper,
                session_id,
                &to_client,
            );
            let controller = helper
                .controller
                .webtransport_controller()
                .expect("native WebTransport controller");
            let filler = if matches!(cause, Cause::Mixed) {
                open_server_webtransport_uni(&mut helper, &controller, session_id)
                    .await
            } else {
                open_server_webtransport_bidi(
                    &mut helper,
                    &controller,
                    session_id,
                )
                .await
            };
            let blocked = open_server_webtransport_bidi(
                &mut helper,
                &controller,
                session_id,
            )
            .await;

            let reasons = match cause {
                Cause::Connection => {
                    let capacity =
                        helper.pipe.server.stream_capacity(filler).unwrap();
                    assert!(capacity > 0);
                    assert_eq!(
                        helper.pipe.server.stream_send(
                            filler,
                            &vec![0; capacity],
                            false,
                        ),
                        Ok(capacity)
                    );
                    quiche::StreamSendBlockReasons {
                        connection_flow_control: true,
                        ..quiche::StreamSendBlockReasons::default()
                    }
                },
                Cause::Congestion => {
                    let capacity =
                        helper.pipe.server.stream_capacity(filler).unwrap();
                    assert!(capacity > 0);
                    assert_eq!(
                        helper.pipe.server.stream_send(
                            filler,
                            &vec![0; capacity],
                            false,
                        ),
                        Ok(capacity)
                    );
                    quiche::StreamSendBlockReasons {
                        congestion_control: true,
                        ..quiche::StreamSendBlockReasons::default()
                    }
                },
                Cause::CapacityFactor => {
                    let capacity =
                        helper.pipe.server.stream_capacity(filler).unwrap();
                    assert!(capacity > 0);
                    assert_eq!(
                        helper.pipe.server.stream_send(
                            filler,
                            &vec![0; capacity],
                            false,
                        ),
                        Ok(capacity)
                    );
                    quiche::StreamSendBlockReasons {
                        send_capacity_factor: true,
                        ..quiche::StreamSendBlockReasons::default()
                    }
                },
                Cause::Retention => {
                    let retained =
                        helper.pipe.server.stream_send_retention_stats();
                    helper
                        .pipe
                        .server
                        .set_stream_send_retention_limits(
                            quiche::StreamSendRetentionLimits {
                                max_bytes: retained.retained_bytes,
                                max_chunks: retained.retained_chunks,
                            },
                        )
                        .unwrap();
                    quiche::StreamSendBlockReasons {
                        stream_send_retention: true,
                        ..quiche::StreamSendBlockReasons::default()
                    }
                },
                Cause::Mixed => {
                    let capacity =
                        helper.pipe.server.stream_capacity(filler).unwrap();
                    assert!(capacity > 0);
                    assert_eq!(
                        helper.pipe.server.stream_send(
                            filler,
                            &vec![0; capacity],
                            false,
                        ),
                        Ok(capacity)
                    );
                    quiche::StreamSendBlockReasons {
                        stream_flow_control: true,
                        send_capacity_factor: true,
                        ..quiche::StreamSendBlockReasons::default()
                    }
                },
            };
            let retry_disposition = reasons.retry_disposition();
            let state_change_reasons = quiche::StreamSendBlockReasons {
                active_path_unavailable: reasons.active_path_unavailable,
                send_capacity_factor: reasons.send_capacity_factor,
                stream_send_retention: reasons.stream_send_retention,
                ..quiche::StreamSendBlockReasons::default()
            };

            if !matches!(cause, Cause::Retention) {
                assert_eq!(
                    helper.pipe.server.stream_send_status(blocked),
                    Ok(quiche::StreamSendStatus::Blocked(reasons))
                );
            }

            let (lease, log) = mock_write_lease(100 + index as u64, b"x");
            let pointer = lease.payload.as_ptr() as usize;
            let write = controller
                .try_write_stream_lease(session_id, blocked, lease, false)
                .unwrap();
            helper.work_loop_iter().unwrap();
            let outcome = write.outcome().await;
            assert_eq!(
                outcome.progress(),
                WebTransportStreamWriteLeaseProgress::ExposedKnownZero
            );
            let (mut lease, retry) = assert_matches!(
                outcome,
                WebTransportStreamWriteLeaseOutcome::Blocked {
                    lease,
                    fin: false,
                    reasons: actual,
                    retry,
                } if actual == reasons => (lease, retry)
            );
            assert_eq!(retry.session_id(), session_id);
            assert_eq!(retry.stream_id(), blocked);
            assert_eq!(retry.reasons(), reasons);
            assert_eq!(retry.disposition(), retry_disposition);
            assert_eq!(lease.id, 100 + index as u64);
            assert_eq!(lease.payload.as_ptr() as usize, pointer);
            assert_eq!(mock_write_lease_log(&log).exposed_pointers, [pointer]);

            if retry_disposition ==
                quiche::StreamSendRetryDisposition::StateChangeRequired
            {
                let wait_controller = controller.clone();
                let wait = tokio::spawn(async move {
                    wait_controller.wait_stream_writable(retry).await
                });
                tokio::task::yield_now().await;
                helper.work_loop_iter().unwrap();
                assert_eq!(
                    wait.await.unwrap(),
                    WebTransportStreamReadyOutcome::WriteStateChangeRequired {
                        blocked_reasons: reasons,
                        state_change_reasons,
                    }
                );

                let blocked_again = controller
                    .try_write_stream_lease(session_id, blocked, lease, false)
                    .unwrap();
                helper.work_loop_iter().unwrap();
                let (returned, retry) = assert_matches!(
                    blocked_again.outcome().await,
                    WebTransportStreamWriteLeaseOutcome::Blocked {
                        lease,
                        fin: false,
                        reasons: actual,
                        retry,
                    } if actual == reasons => (lease, retry)
                );
                lease = returned;
                assert_eq!(lease.payload.as_ptr() as usize, pointer);
                assert_eq!(retry.disposition(), retry_disposition);
                let wait_controller = controller.clone();
                let wait = tokio::spawn(async move {
                    wait_controller.wait_stream_writable(retry).await
                });
                tokio::task::yield_now().await;
                helper.work_loop_iter().unwrap();
                assert_eq!(
                    wait.await.unwrap(),
                    WebTransportStreamReadyOutcome::WriteStateChangeRequired {
                        blocked_reasons: reasons,
                        state_change_reasons,
                    }
                );
            } else {
                drop(retry);
            }
            if matches!(cause, Cause::Retention) {
                let retained_before =
                    helper.pipe.server.stream_send_retention_stats();
                assert!(retained_before.retained_bytes > 0);
                helper.pipe.advance().unwrap();
                let retained_after =
                    helper.pipe.server.stream_send_retention_stats();
                assert!(
                    retained_after.retained_bytes <
                        retained_before.retained_bytes
                );

                let retry = controller
                    .try_write_stream_lease(session_id, blocked, lease, false)
                    .unwrap();
                helper.work_loop_iter().unwrap();
                let lease = assert_matches!(
                    retry.outcome().await,
                    WebTransportStreamWriteLeaseOutcome::Accepted {
                        lease,
                        accepted: 1,
                        complete: true,
                        fin_accepted: false,
                    } => lease
                );
                assert_eq!(lease.payload.as_ptr() as usize, pointer);
                assert_eq!(mock_write_lease_log(&log).exposed_pointers, [
                    pointer, pointer, pointer
                ]);
                drop(lease);
            } else {
                drop(lease);
            }

            let stats =
                webtransport_retention_stats(&mut helper, &controller).await;
            assert_eq!(stats.write_leases, 0);
            assert_eq!(stats.write_lease_retained_bytes, 0);
        }
    }

    #[tokio::test]
    async fn webtransport_write_retry_tokens_are_attempt_bound() {
        let mut client = default_quiche_config();
        client.set_initial_max_data(1_000_000);
        client.set_initial_max_stream_data_bidi_remote(1_000_000);
        client.enable_dgram(true, 10, 10);
        client.enable_reset_stream_at(true);

        let mut server = default_quiche_config();
        server.set_send_capacity_factor(0.5);
        server.enable_dgram(true, 10, 10);
        server.enable_reset_stream_at(true);
        let pipe =
            quiche::test_utils::Pipe::with_client_and_server_config_and_buf(
                &mut client,
                &mut server,
            )
            .unwrap();
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                pipe,
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
        let filler =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        let blocked =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        let capacity = helper.pipe.server.stream_capacity(filler).unwrap();
        assert!(capacity > 0);
        assert_eq!(
            helper
                .pipe
                .server
                .stream_send(filler, &vec![0; capacity], false,),
            Ok(capacity)
        );
        let reasons = quiche::StreamSendBlockReasons {
            send_capacity_factor: true,
            ..quiche::StreamSendBlockReasons::default()
        };
        assert_eq!(
            helper.pipe.server.stream_send_status(blocked),
            Ok(quiche::StreamSendStatus::Blocked(reasons))
        );

        let (first_lease, first_log) = mock_write_lease(120, b"first");
        let first_pointer = first_lease.payload.as_ptr() as usize;
        let first = controller
            .try_write_stream_lease(session_id, blocked, first_lease, false)
            .unwrap();
        let (second_lease, second_log) = mock_write_lease(121, b"second");
        let second_pointer = second_lease.payload.as_ptr() as usize;
        let second = controller
            .try_write_stream_lease(session_id, blocked, second_lease, false)
            .unwrap();
        helper.work_loop_iter().unwrap();

        let (first_lease, first_retry) = assert_matches!(
            first.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease,
                fin: false,
                reasons: actual,
                retry,
            } if actual == reasons => (lease, retry)
        );
        let (second_lease, second_retry) = assert_matches!(
            second.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease,
                fin: false,
                reasons: actual,
                retry,
            } if actual == reasons => (lease, retry)
        );
        assert_eq!(first_lease.payload.as_ptr() as usize, first_pointer);
        assert_eq!(second_lease.payload.as_ptr() as usize, second_pointer);
        let retained =
            webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(retained.write_leases, 2);
        assert_eq!(retained.write_lease_retained_bytes, 0);

        let second_controller = controller.clone();
        let second_wait = tokio::spawn(async move {
            second_controller.wait_stream_writable(second_retry).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            second_wait.await.unwrap(),
            WebTransportStreamReadyOutcome::WriteStateChangeRequired {
                blocked_reasons: reasons,
                state_change_reasons: reasons,
            }
        );

        let first_controller = controller.clone();
        let first_wait = tokio::spawn(async move {
            first_controller.wait_stream_writable(first_retry).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            first_wait.await.unwrap(),
            WebTransportStreamReadyOutcome::WriteStateChangeRequired {
                blocked_reasons: reasons,
                state_change_reasons: reasons,
            }
        );

        assert_eq!(mock_write_lease_log(&first_log).exposed_pointers, [
            first_pointer
        ]);
        assert_eq!(mock_write_lease_log(&second_log).exposed_pointers, [
            second_pointer
        ]);
        drop(first_lease);
        drop(second_lease);
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.write_leases, 0);
        assert_eq!(stats.write_lease_retained_bytes, 0);
    }

    #[tokio::test]
    async fn webtransport_write_retry_tokens_are_controller_bound() {
        let mut first =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                exact_prefix_capacity_webtransport_pipe(),
                webtransport_settings(),
            )
            .unwrap();
        start_webtransport_driver(&mut first);
        let (first_session, first_to_client, _first_from_client) =
            open_pending_webtransport_session(&mut first);
        accept_pending_webtransport_session(
            &mut first,
            first_session,
            &first_to_client,
        );
        let first_controller = first
            .controller
            .webtransport_controller()
            .expect("first native WebTransport controller");
        let first_stream = open_server_webtransport_bidi(
            &mut first,
            &first_controller,
            first_session,
        )
        .await;

        let mut second =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                exact_prefix_capacity_webtransport_pipe(),
                webtransport_settings(),
            )
            .unwrap();
        start_webtransport_driver(&mut second);
        let (second_session, second_to_client, _second_from_client) =
            open_pending_webtransport_session(&mut second);
        accept_pending_webtransport_session(
            &mut second,
            second_session,
            &second_to_client,
        );
        let second_controller = second
            .controller
            .webtransport_controller()
            .expect("second native WebTransport controller");
        let second_stream = open_server_webtransport_bidi(
            &mut second,
            &second_controller,
            second_session,
        )
        .await;
        assert_eq!(first_session, second_session);
        assert_eq!(first_stream, second_stream);

        let reasons = quiche::StreamSendBlockReasons {
            stream_flow_control: true,
            ..quiche::StreamSendBlockReasons::default()
        };
        let (lease, log) = mock_write_lease(122, b"identity");
        let pointer = lease.payload.as_ptr() as usize;
        let write = first_controller
            .try_write_stream_lease(first_session, first_stream, lease, false)
            .unwrap();
        first.work_loop_iter().unwrap();
        let (lease, retry) = assert_matches!(
            write.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease,
                fin: false,
                reasons: actual,
                retry,
            } if actual == reasons => (lease, retry)
        );
        assert_eq!(lease.payload.as_ptr() as usize, pointer);
        let debug = format!("{retry:?}");
        assert!(!debug.contains("accounting"));
        assert!(!debug.contains("reservation"));
        assert!(!debug.contains("0x"));
        let retained =
            webtransport_retention_stats(&mut first, &first_controller).await;
        assert_eq!(retained.write_leases, 1);
        assert_eq!(retained.write_lease_retained_bytes, 0);

        let second_before =
            webtransport_retention_stats(&mut second, &second_controller).await;
        assert_eq!(
            second_controller.wait_stream_writable(retry).await,
            WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ForeignController,
            )
        );
        let second_after =
            webtransport_retention_stats(&mut second, &second_controller).await;
        assert_eq!(second_after.waiters, second_before.waiters);
        assert_eq!(
            second_after.metadata_index_entries,
            second_before.metadata_index_entries
        );
        let released =
            webtransport_retention_stats(&mut first, &first_controller).await;
        assert_eq!(released.write_leases, 0);
        assert_eq!(released.write_lease_retained_bytes, 0);
        assert_eq!(lease.payload.as_ptr() as usize, pointer);

        let write = first_controller
            .try_write_stream_lease(first_session, first_stream, lease, false)
            .unwrap();
        first.work_loop_iter().unwrap();
        let (lease, retry) = assert_matches!(
            write.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease,
                fin: false,
                reasons: actual,
                retry,
            } if actual == reasons => (lease, retry)
        );
        let cloned_controller = first_controller.clone();
        let writable = tokio::spawn(async move {
            cloned_controller.wait_stream_writable(retry).await
        });
        tokio::task::yield_now().await;
        first.work_loop_iter().unwrap();
        assert!(!writable.is_finished());

        first.pipe.advance().unwrap();
        assert_matches!(
            first.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { .. }))
                if id == first_stream
        );
        first.advance_and_run_loop().unwrap();
        assert_eq!(
            writable.await.unwrap(),
            WebTransportStreamReadyOutcome::WriteTransportWake { reasons }
        );

        let write = first_controller
            .try_write_stream_lease(first_session, first_stream, lease, false)
            .unwrap();
        first.work_loop_iter().unwrap();
        let lease = assert_matches!(
            write.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Accepted {
                lease,
                accepted: 3,
                complete: false,
                fin_accepted: false,
            } => lease
        );
        assert_eq!(lease.payload.as_ptr() as usize, pointer);
        assert_eq!(mock_write_lease_log(&log).exposed_pointers, [
            pointer, pointer, pointer,
        ]);
        drop(lease);
        let stats =
            webtransport_retention_stats(&mut first, &first_controller).await;
        assert_eq!(stats.write_leases, 0);
        assert_eq!(stats.write_lease_retained_bytes, 0);
    }

    #[tokio::test]
    async fn webtransport_blocked_write_lease_keeps_owner_through_terminals() {
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

        let (lease, log) = mock_write_lease(110, b"terminal");
        let pointer = lease.payload.as_ptr() as usize;
        let blocked = controller
            .try_write_stream_lease(session_id, stream_id, lease, true)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let (lease, retry) = assert_matches!(
            blocked.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease,
                fin: true,
                reasons,
                retry,
            } if reasons.stream_flow_control && retry.disposition() ==
                quiche::StreamSendRetryDisposition::WaitForTransportWritable =>
                (lease, retry)
        );
        assert_eq!(lease.payload.as_ptr() as usize, pointer);

        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            stream_id,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let wire_error = webtransport_error_to_http3(73);
        helper
            .pipe
            .client
            .stream_shutdown(stream_id, quiche::Shutdown::Read, wire_error)
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        let stopped_wait_controller = controller.clone();
        let stopped_wait = tokio::spawn(async move {
            stopped_wait_controller.wait_stream_writable(retry).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            stopped_wait.await.unwrap(),
            WebTransportStreamReadyOutcome::ResetRequired {
                wire_error_code: wire_error,
                application_error_code: Some(73),
            }
        );

        let stopped = controller
            .try_write_stream_lease(session_id, stream_id, lease, true)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let lease = assert_matches!(
            stopped.outcome().await,
            WebTransportStreamWriteLeaseOutcome::ResetRequired {
                wire_error_code,
                application_error_code: Some(73),
                lease,
                fin: true,
            } if wire_error_code == wire_error => lease
        );
        assert_eq!(lease.id, 110);
        assert_eq!(lease.payload.as_ptr() as usize, pointer);
        assert_eq!(mock_write_lease_log(&log).exposed_pointers, [
            pointer, pointer
        ]);
        drop(lease);

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
        let (lease, log) = mock_write_lease(111, b"teardown");
        let pointer = lease.payload.as_ptr() as usize;
        let blocked = controller
            .try_write_stream_lease(session_id, stream_id, lease, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let lease = assert_matches!(
            blocked.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked { lease, .. } => lease
        );
        assert_eq!(lease.payload.as_ptr() as usize, pointer);

        let closing = controller
            .try_write_stream_lease(session_id, stream_id, lease, false)
            .unwrap();
        helper.driver.on_conn_close(
            &mut helper.pipe.server,
            &TestMetrics::default(),
            &Ok(()),
        );
        let lease = assert_matches!(
            closing.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::ConnectionClosed,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(lease.id, 111);
        assert_eq!(lease.payload.as_ptr() as usize, pointer);
        assert_eq!(mock_write_lease_log(&log).exposed_pointers, [pointer]);
        drop(lease);
        assert_eq!(mock_write_lease_log(&log).drops, 1);
    }

    #[tokio::test]
    async fn webtransport_write_lease_partial_retry_and_wakeup_are_fair() {
        let mut settings = webtransport_settings();
        settings.webtransport_command_capacity = 4;
        settings.webtransport_max_session_work_per_callback = 1;
        settings.webtransport_max_stream_write_bytes = 128;
        settings.webtransport_max_stream_write_lease_retained_bytes = 128;
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                payload_backpressured_webtransport_pipe(),
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

        let blocked_stream =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { prefix_len: 3, .. }))
                if id == blocked_stream
        );
        let healthy_stream =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { prefix_len: 3, .. }))
                if id == healthy_stream
        );

        let payload: Vec<u8> = (0..80).collect();
        let (first_lease, first_log) = mock_write_lease(20, &payload);
        let first_pointer = first_lease.payload.as_ptr() as usize;
        let first = controller
            .try_write_stream_lease(session_id, blocked_stream, first_lease, true)
            .unwrap();
        let (healthy_lease, healthy_log) = mock_write_lease(21, b"healthy");
        let healthy = controller
            .try_write_stream_lease(
                session_id,
                healthy_stream,
                healthy_lease,
                true,
            )
            .unwrap();
        assert_eq!(
            helper.driver.webtransport_cmd_recv.as_ref().unwrap().len(),
            2
        );

        helper
            .driver
            .process_writes(&mut helper.pipe.server)
            .unwrap();
        assert_eq!(
            helper.driver.webtransport_cmd_recv.as_ref().unwrap().len(),
            1
        );
        assert_eq!(mock_write_lease_log(&healthy_log).exposures, 0);
        let first_lease = assert_matches!(
            first.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Accepted {
                lease,
                accepted: 61,
                complete: false,
                fin_accepted: false,
            } => lease
        );
        assert_eq!(first_lease.payload.as_ptr() as usize, first_pointer);
        assert_eq!(mock_write_lease_log(&first_log).exposed_pointers, [
            first_pointer
        ]);
        drop(first_lease);

        helper
            .driver
            .process_writes(&mut helper.pipe.server)
            .unwrap();
        let healthy_lease = assert_matches!(
            healthy.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Accepted {
                lease,
                accepted: 7,
                complete: true,
                fin_accepted: true,
            } => lease
        );
        assert_eq!(healthy_lease.id, 21);
        assert_eq!(mock_write_lease_log(&healthy_log).exposures, 1);
        drop(healthy_lease);

        let (retry_lease, retry_log) = mock_write_lease(22, &payload[61..]);
        let retry_pointer = retry_lease.payload.as_ptr() as usize;
        let blocked_retry = controller
            .try_write_stream_lease(session_id, blocked_stream, retry_lease, true)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let (retry_lease, retry_token) = assert_matches!(
            blocked_retry.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease,
                fin: true,
                reasons,
                retry,
            } if reasons == quiche::StreamSendBlockReasons {
                stream_flow_control: true,
                ..quiche::StreamSendBlockReasons::default()
            } && retry.disposition() ==
                quiche::StreamSendRetryDisposition::WaitForTransportWritable =>
                    (lease, retry)
        );
        assert_eq!(retry_lease.id, 22);
        assert_eq!(retry_lease.payload.as_ptr() as usize, retry_pointer);
        assert_eq!(mock_write_lease_log(&retry_log).exposed_pointers, [
            retry_pointer
        ]);

        let cancelled_controller = controller.clone();
        let cancelled_wait = tokio::spawn(async move {
            cancelled_controller.wait_stream_writable(retry_token).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!cancelled_wait.is_finished());
        cancelled_wait.abort();
        assert!(cancelled_wait.await.unwrap_err().is_cancelled());
        helper.work_loop_iter().unwrap();

        let blocked_retry = controller
            .try_write_stream_lease(session_id, blocked_stream, retry_lease, true)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let (retry_lease, retry_token) = assert_matches!(
            blocked_retry.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease,
                fin: true,
                reasons,
                retry,
            } if reasons == quiche::StreamSendBlockReasons {
                stream_flow_control: true,
                ..quiche::StreamSendBlockReasons::default()
            } && retry.disposition() ==
                quiche::StreamSendRetryDisposition::WaitForTransportWritable =>
                    (lease, retry)
        );
        assert_eq!(retry_lease.payload.as_ptr() as usize, retry_pointer);

        let wait_controller = controller.clone();
        let writable = tokio::spawn(async move {
            wait_controller.wait_stream_writable(retry_token).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!writable.is_finished());

        helper.pipe.advance().unwrap();
        let mut received = [0; 128];
        assert_eq!(
            helper
                .pipe
                .client
                .stream_recv(blocked_stream, &mut received),
            Ok((61, false))
        );
        assert_eq!(&received[..61], &payload[..61]);
        let mut healthy_payload = [0; 16];
        assert_eq!(
            helper
                .pipe
                .client
                .stream_recv(healthy_stream, &mut healthy_payload),
            Ok((7, true))
        );
        assert_eq!(&healthy_payload[..7], b"healthy");

        helper.pipe.advance().unwrap();
        for _ in 0..16 {
            helper.work_loop_iter().unwrap();
            if writable.is_finished() {
                break;
            }
            helper.pipe.advance().unwrap();
            tokio::task::yield_now().await;
        }
        assert_eq!(
            writable.await.unwrap(),
            WebTransportStreamReadyOutcome::WriteTransportWake {
                reasons: quiche::StreamSendBlockReasons {
                    stream_flow_control: true,
                    ..quiche::StreamSendBlockReasons::default()
                }
            }
        );

        let retry = controller
            .try_write_stream_lease(session_id, blocked_stream, retry_lease, true)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let retry_lease = assert_matches!(
            retry.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Accepted {
                lease,
                accepted: 19,
                complete: true,
                fin_accepted: true,
            } => lease
        );
        assert_eq!(retry_lease.id, 22);
        assert_eq!(retry_lease.payload.as_ptr() as usize, retry_pointer);
        assert_eq!(mock_write_lease_log(&retry_log).exposed_pointers, [
            retry_pointer,
            retry_pointer,
            retry_pointer,
        ]);
        drop(retry_lease);
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper
                .pipe
                .client
                .stream_recv(blocked_stream, &mut received),
            Ok((19, true))
        );
        assert_eq!(&received[..19], &payload[61..]);

        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.write_leases, 0);
        assert_eq!(stats.write_lease_retained_bytes, 0);
    }

    #[tokio::test]
    async fn webtransport_write_lease_cancellation_settles_exact_progress() {
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

        let (unexposed, unexposed_log) = mock_write_lease(30, b"unexposed");
        let unexposed = controller
            .try_write_stream_lease(session_id, stream_id, unexposed, false)
            .unwrap();
        drop(unexposed);
        helper.work_loop_iter().unwrap();
        let unexposed_log = mock_write_lease_log(&unexposed_log);
        assert_eq!(unexposed_log.exposures, 0);
        assert_eq!(unexposed_log.drops, 1);
        assert_eq!(unexposed_log.abandonments, [
            WebTransportStreamWriteLeaseProgress::NeverExposed
        ]);

        let (blocked, blocked_log) = mock_write_lease(31, b"blocked");
        let blocked = controller
            .try_write_stream_lease(session_id, stream_id, blocked, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        drop(blocked);
        let blocked_log = mock_write_lease_log(&blocked_log);
        assert_eq!(blocked_log.exposures, 1);
        assert_eq!(blocked_log.drops, 1);
        assert_eq!(blocked_log.abandonments, [
            WebTransportStreamWriteLeaseProgress::ExposedKnownZero
        ]);

        let stats_controller = controller.clone();
        let stats =
            tokio::spawn(async move { stats_controller.retention_stats().await });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let stats = stats.await.unwrap().unwrap();
        assert_eq!(stats.write_lease_abandoned_unexposed_total, 1);
        assert_eq!(stats.write_lease_abandoned_zero_total, 1);
        assert_eq!(stats.write_lease_abandoned_unknown_total, 0);

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
        helper.pipe.advance().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::WebTransportStream { .. })) if id == stream_id
        );
        let (accepted, accepted_log) = mock_write_lease(32, b"accepted");
        let accepted = controller
            .try_write_stream_lease(session_id, stream_id, accepted, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        drop(accepted);
        let accepted_log = mock_write_lease_log(&accepted_log);
        assert_eq!(accepted_log.exposures, 1);
        assert_eq!(accepted_log.drops, 1);
        assert_eq!(accepted_log.abandonments, [
            WebTransportStreamWriteLeaseProgress::Unknowable
        ]);
        helper.pipe.advance().unwrap();
        let mut payload = [0; 16];
        assert_eq!(
            helper.pipe.client.stream_recv(stream_id, &mut payload),
            Ok((8, false))
        );
        assert_eq!(&payload[..8], b"accepted");

        let stats_controller = controller.clone();
        let stats =
            tokio::spawn(async move { stats_controller.retention_stats().await });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let stats = stats.await.unwrap().unwrap();
        assert_eq!(stats.write_lease_abandoned_unknown_total, 1);
    }

    #[tokio::test]
    async fn webtransport_write_lease_retention_is_bounded_until_owner_return() {
        let mut settings = webtransport_settings();
        settings.webtransport_command_capacity = 2;
        settings.webtransport_max_stream_write_bytes = 8;
        settings.webtransport_max_stream_write_lease_retained_bytes = 8;
        let mut helper = webtransport_helper(settings);
        start_webtransport_driver(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let (first, first_log) = mock_write_lease(40, b"aaaa");
        let first = controller
            .try_write_stream_lease(99, 1, first, false)
            .unwrap();
        let (second, second_log) = mock_write_lease(41, b"bbbb");
        let second = controller
            .try_write_stream_lease(99, 5, second, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        assert_eq!(
            helper.driver.webtransport_cmd_recv.as_ref().unwrap().len(),
            0
        );

        let (limited, limited_log) = mock_write_lease(42, b"cccc");
        let limited = assert_matches!(
            controller.try_write_stream_lease(99, 9, limited, false),
            Err(WebTransportStreamWriteLeaseOutcome::ResourceLimit {
                lease,
                fin: false,
            }) => lease
        );
        assert_eq!(limited.id, 42);
        assert_eq!(mock_write_lease_log(&limited_log).exposures, 0);
        drop(limited);

        let stats_controller = controller.clone();
        let stats =
            tokio::spawn(async move { stats_controller.retention_stats().await });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let stats = stats.await.unwrap().unwrap();
        assert_eq!(stats.write_leases, 2);
        assert_eq!(stats.write_lease_retained_bytes, 8);
        assert_eq!(stats.max_write_leases, 2);
        assert_eq!(stats.max_write_lease_retained_bytes, 16);
        assert_eq!(stats.write_lease_admitted_total, 2);
        assert_eq!(stats.write_lease_resource_limit_total, 1);
        assert!(stats.write_leases <= stats.max_write_leases);
        assert!(
            stats.write_lease_retained_bytes <=
                stats.max_write_lease_retained_bytes
        );

        let first = assert_matches!(
            first.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::UnknownSession,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(first.id, 40);
        assert_eq!(mock_write_lease_log(&first_log).exposures, 0);
        drop(first);

        let (replacement, replacement_log) = mock_write_lease(43, b"dddd");
        let replacement = controller
            .try_write_stream_lease(99, 9, replacement, false)
            .unwrap();
        helper.driver.on_conn_close(
            &mut helper.pipe.server,
            &TestMetrics::default(),
            &Ok(()),
        );
        let replacement = assert_matches!(
            replacement.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::ConnectionClosed,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(replacement.id, 43);
        assert_eq!(mock_write_lease_log(&replacement_log).exposures, 0);
        drop(replacement);

        let second = assert_matches!(
            second.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::UnknownSession,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(second.id, 41);
        assert_eq!(mock_write_lease_log(&second_log).exposures, 0);
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

        readable.abort();
        let _ = readable.await;
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            webtransport_retention_stats(&mut helper, &controller)
                .await
                .receive_terminal_waiters,
            0
        );
        let read_controller = controller.clone();
        let readable = tokio::spawn(async move {
            read_controller
                .wait_stream_readable(session_id, stream_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!readable.is_finished());

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
        let terminal = assert_matches!(
            read.await.unwrap(),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert_eq!(terminal.data(), b"ready");
        assert_eq!(terminal.terminal(), WebTransportStreamReceiveTerminal::Fin);
        drop(terminal);
        let retired = retire_receive_terminal(&controller, session_id, stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            retired.await.unwrap(),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id,
                stream_id,
            }
        );

        let writable_stream =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        let (writable_lease, writable_log) = mock_write_lease(50, b"x");
        let writable_pointer = writable_lease.payload.as_ptr() as usize;
        let writable_attempt = controller
            .try_write_stream_lease(
                session_id,
                writable_stream,
                writable_lease,
                false,
            )
            .unwrap();
        helper.work_loop_iter().unwrap();
        let (writable_lease, writable_retry) = assert_matches!(
            writable_attempt.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease,
                fin: false,
                reasons,
                retry,
            } if reasons.stream_flow_control &&
                retry.disposition() ==
                    quiche::StreamSendRetryDisposition::WaitForTransportWritable =>
                        (lease, retry)
        );
        assert_eq!(writable_lease.payload.as_ptr() as usize, writable_pointer);
        let writable_controller = controller.clone();
        let writable = tokio::spawn(async move {
            writable_controller
                .wait_stream_writable(writable_retry)
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
            WebTransportStreamReadyOutcome::WriteTransportWake {
                reasons: quiche::StreamSendBlockReasons {
                    stream_flow_control: true,
                    ..quiche::StreamSendBlockReasons::default()
                }
            }
        );
        let writable_attempt = controller
            .try_write_stream_lease(
                session_id,
                writable_stream,
                writable_lease,
                false,
            )
            .unwrap();
        helper.work_loop_iter().unwrap();
        let writable_lease = assert_matches!(
            writable_attempt.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Accepted {
                lease,
                accepted: 1,
                complete: true,
                fin_accepted: false,
            } => lease
        );
        assert_eq!(writable_lease.payload.as_ptr() as usize, writable_pointer);
        assert_eq!(mock_write_lease_log(&writable_log).exposed_pointers, [
            writable_pointer,
            writable_pointer,
        ]);
        drop(writable_lease);

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
        let reset_terminal = assert_matches!(
            reset_read.await.unwrap(),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert!(reset_terminal.data().is_empty());
        assert_eq!(
            reset_terminal.terminal(),
            WebTransportStreamReceiveTerminal::Reset {
                wire_error_code: reset_wire,
                application_error_code: Some(29),
            }
        );
        drop(reset_terminal);
        let retired =
            retire_receive_terminal(&controller, session_id, reset_stream);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            retired.await.unwrap(),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id,
                stream_id: reset_stream,
            }
        );

        let stopped_stream =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        let (stopped_lease, stopped_log) = mock_write_lease(51, b"stop");
        let stopped_pointer = stopped_lease.payload.as_ptr() as usize;
        let stopped_attempt = controller
            .try_write_stream_lease(
                session_id,
                stopped_stream,
                stopped_lease,
                false,
            )
            .unwrap();
        helper.work_loop_iter().unwrap();
        let (stopped_lease, stopped_retry) = assert_matches!(
            stopped_attempt.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease,
                fin: false,
                reasons,
                retry,
            } if reasons.stream_flow_control &&
                retry.disposition() ==
                    quiche::StreamSendRetryDisposition::WaitForTransportWritable =>
                        (lease, retry)
        );
        assert_eq!(stopped_lease.payload.as_ptr() as usize, stopped_pointer);
        let stopped_controller = controller.clone();
        let stopped = tokio::spawn(async move {
            stopped_controller.wait_stream_writable(stopped_retry).await
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
        let stopped_attempt = controller
            .try_write_stream_lease(
                session_id,
                stopped_stream,
                stopped_lease,
                false,
            )
            .unwrap();
        helper.work_loop_iter().unwrap();
        let stopped_lease = assert_matches!(
            stopped_attempt.outcome().await,
            WebTransportStreamWriteLeaseOutcome::ResetRequired {
                wire_error_code,
                application_error_code: Some(23),
                lease,
                fin: false,
            } if wire_error_code == webtransport_error_to_http3(23) => lease
        );
        assert_eq!(stopped_lease.payload.as_ptr() as usize, stopped_pointer);
        assert_eq!(mock_write_lease_log(&stopped_log).exposed_pointers, [
            stopped_pointer,
            stopped_pointer,
        ]);
        drop(stopped_lease);

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
    async fn webtransport_send_terminal_stop_is_latched_before_and_after_wait() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let before =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            before,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let mapped_wire = webtransport_error_to_http3(19);
        helper
            .pipe
            .client
            .stream_shutdown(before, quiche::Shutdown::Read, mapped_wire)
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        for _ in 0..2 {
            let wait = wait_for_send_terminal(&controller, session_id, before);
            tokio::task::yield_now().await;
            helper.work_loop_iter().unwrap();
            assert_eq!(
                wait.await.unwrap(),
                WebTransportStreamSendTerminalOutcome::Stopped {
                    stream_id: before,
                    wire_error_code: mapped_wire,
                    application_error_code: Some(19),
                }
            );
        }

        let after =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            after,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let wait = wait_for_send_terminal(&controller, session_id, after);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!wait.is_finished());

        let grease_wire = webtransport_error_to_http3(29) + 1;
        helper
            .pipe
            .client
            .stream_shutdown(after, quiche::Shutdown::Read, grease_wire)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Stopped {
                stream_id: after,
                wire_error_code: grease_wire,
                application_error_code: None,
            }
        );
    }

    #[tokio::test]
    async fn webtransport_send_terminal_retirement_is_latched_and_reclaims_state()
    {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        // Retirement settles a pending waiter and suppresses a later STOP.
        let retire_first =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            retire_first,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let pending =
            wait_for_send_terminal(&controller, session_id, retire_first);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!pending.is_finished());
        let retirement =
            retire_send_terminal(&controller, session_id, retire_first);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let retired = WebTransportStreamSendTerminalOutcome::Retired {
            session_id,
            stream_id: retire_first,
        };
        assert_eq!(pending.await.unwrap(), retired);
        assert_eq!(retirement.await.unwrap(), retired);

        let stop_wire = webtransport_error_to_http3(71);
        helper
            .pipe
            .client
            .stream_shutdown(retire_first, quiche::Shutdown::Read, stop_wire)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.send_terminal_waiters, 0);
        assert_eq!(stats.send_terminal_states, 0);
        assert_eq!(stats.send_terminal_overloaded_sessions, 0);

        // Retirement remains idempotent while the selected stream is owned,
        // and re-registration observes the level-triggered retired state.
        for outcome in [
            retire_send_terminal(&controller, session_id, retire_first),
            wait_for_send_terminal(&controller, session_id, retire_first),
        ] {
            tokio::task::yield_now().await;
            helper.work_loop_iter().unwrap();
            assert_eq!(outcome.await.unwrap(), retired);
        }

        // A STOP that wins the race is retained until retirement, even after
        // one waiter has already consumed the reported terminal fact.
        let stop_first =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            stop_first,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let stop_wire = webtransport_error_to_http3(73);
        helper
            .pipe
            .client
            .stream_shutdown(stop_first, quiche::Shutdown::Read, stop_wire)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        let wait = wait_for_send_terminal(&controller, session_id, stop_first);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Stopped {
                stream_id: stop_first,
                wire_error_code: stop_wire,
                application_error_code: Some(73),
            }
        );
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.send_terminal_states, 1);

        let retirement =
            retire_send_terminal(&controller, session_id, stop_first);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            retirement.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Retired {
                session_id,
                stream_id: stop_first,
            }
        );
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.send_terminal_states, 0);
    }

    #[tokio::test]
    async fn webtransport_send_terminal_waits_through_blocking_and_idle_turns() {
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
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            stream_id,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        assert_eq!(
            helper.pipe.server.stream_send_status(stream_id),
            Ok(quiche::StreamSendStatus::Blocked(
                quiche::StreamSendBlockReasons {
                    stream_flow_control: true,
                    ..quiche::StreamSendBlockReasons::default()
                }
            ))
        );

        let wait = wait_for_send_terminal(&controller, session_id, stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!wait.is_finished());
        let before = webtransport_retention_stats(&mut helper, &controller).await;
        for _ in 0..32 {
            helper.work_loop_iter().unwrap();
        }
        let after = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(
            after.send_terminal_waiter_work_total,
            before.send_terminal_waiter_work_total
        );
        assert_eq!(after.send_terminal_waiters, 1);

        let wire_error = webtransport_error_to_http3(31);
        helper
            .pipe
            .client
            .stream_shutdown(stream_id, quiche::Shutdown::Read, wire_error)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Stopped {
                stream_id,
                wire_error_code: wire_error,
                application_error_code: Some(31),
            }
        );

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
            open_server_webtransport_uni(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            stream_id,
            h3::WebTransportStreamDirection::Unidirectional,
        );
        let wait = wait_for_send_terminal(&controller, session_id, stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!wait.is_finished());
        helper
            .pipe
            .client
            .stream_shutdown(stream_id, quiche::Shutdown::Read, wire_error)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Stopped {
                stream_id: actual,
                ..
            } if actual == stream_id
        );
    }

    #[tokio::test]
    async fn webtransport_send_terminal_cancellation_and_bounds_are_deterministic(
    ) {
        let mut settings = webtransport_settings();
        settings.webtransport_max_send_terminal_waiters = 1;
        settings.webtransport_max_send_terminal_waiters_per_session = 1;
        let mut helper = webtransport_helper(settings);
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let first =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            first,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let second =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            second,
            h3::WebTransportStreamDirection::Bidirectional,
        );

        let cancelled = wait_for_send_terminal(&controller, session_id, first);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let saturated = wait_for_send_terminal(&controller, session_id, second);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            saturated.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            )
        );

        cancelled.abort();
        let _ = cancelled.await;
        let admitted = wait_for_send_terminal(&controller, session_id, second);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!admitted.is_finished());

        let first_wire = webtransport_error_to_http3(41);
        helper
            .pipe
            .client
            .stream_shutdown(first, quiche::Shutdown::Read, first_wire)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        let second_wire = webtransport_error_to_http3(43);
        helper
            .pipe
            .client
            .stream_shutdown(second, quiche::Shutdown::Read, second_wire)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            admitted.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Stopped {
                stream_id: second,
                wire_error_code: second_wire,
                application_error_code: Some(43),
            }
        );

        let reregistered = wait_for_send_terminal(&controller, session_id, first);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            reregistered.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Stopped {
                stream_id: first,
                wire_error_code: first_wire,
                application_error_code: Some(41),
            }
        );
        let overloaded = wait_for_send_terminal(&controller, session_id, second);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            overloaded.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            )
        );

        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.send_terminal_waiters, 0);
        assert_eq!(stats.send_terminal_states, 1);
        assert_eq!(stats.send_terminal_overloaded_sessions, 1);
        assert_eq!(stats.send_terminal_waiter_saturation_total, 1);
        assert_eq!(stats.send_terminal_state_saturation_total, 1);

        let retire = retire_send_terminal(&controller, session_id, second);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            retire.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Retired {
                session_id,
                stream_id: second,
            }
        );
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.send_terminal_states, 1);
        assert_eq!(stats.send_terminal_overloaded_sessions, 0);

        let retire = retire_send_terminal(&controller, session_id, first);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            retire.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Retired { .. }
        );
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.send_terminal_states, 0);

        helper
            .pipe
            .client
            .stream_send(session_id, &[], true)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.send_terminal_waiters, 0);
        assert_eq!(stats.send_terminal_states, 0);
        assert_eq!(stats.send_terminal_overloaded_sessions, 0);
    }

    #[tokio::test]
    async fn webtransport_send_terminal_validates_direction_and_staleness() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        for (selected_session, stream_id, error) in [
            (session_id, 400, WebTransportSelectionError::UnknownStream),
            (4, 400, WebTransportSelectionError::UnknownSession),
        ] {
            let wait =
                wait_for_send_terminal(&controller, selected_session, stream_id);
            tokio::task::yield_now().await;
            helper.work_loop_iter().unwrap();
            assert_eq!(
                wait.await.unwrap(),
                WebTransportStreamSendTerminalOutcome::Rejected(error)
            );

            let retire =
                retire_send_terminal(&controller, selected_session, stream_id);
            tokio::task::yield_now().await;
            helper.work_loop_iter().unwrap();
            assert_eq!(
                retire.await.unwrap(),
                WebTransportStreamSendTerminalOutcome::Rejected(error)
            );
        }

        let peer_uni = 18;
        let prefix = webtransport_stream_data(
            WEBTRANSPORT_UNI_STREAM_TYPE,
            session_id,
            &[],
        );
        helper
            .pipe
            .client
            .stream_send(peer_uni, &prefix, false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_associated_stream(
            &mut helper,
            session_id,
            peer_uni,
            WebTransportStreamDirection::Uni,
            3,
        );
        let wrong_direction =
            wait_for_send_terminal(&controller, session_id, peer_uni);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            wrong_direction.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::WrongDirection,
            )
        );
        let wrong_direction =
            retire_send_terminal(&controller, session_id, peer_uni);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            wrong_direction.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::WrongDirection,
            )
        );

        helper.pipe.client.stream_send(peer_uni, &[], true).unwrap();
        for _ in 0..8 {
            helper.advance_and_run_loop().unwrap();
            if helper.pipe.server.stream_closed(peer_uni) {
                break;
            }
        }
        assert!(helper.pipe.server.stream_closed(peer_uni));
        let read_controller = controller.clone();
        let terminal = tokio::spawn(async move {
            read_controller.read_stream(session_id, peer_uni, 16).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let terminal = assert_matches!(
            terminal.await.unwrap(),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert!(terminal.data().is_empty());
        assert_eq!(terminal.terminal(), WebTransportStreamReceiveTerminal::Fin);
        drop(terminal);
        let retired = retire_receive_terminal(&controller, session_id, peer_uni);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            retired.await.unwrap(),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id,
                stream_id: peer_uni,
            }
        );
        helper.work_loop_iter().unwrap();
        let stale = wait_for_send_terminal(&controller, session_id, peer_uni);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            stale.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::StaleStream,
            )
        );
        let stale = retire_send_terminal(&controller, session_id, peer_uni);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            stale.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::StaleStream,
            )
        );
    }

    #[tokio::test]
    async fn webtransport_send_terminal_retirement_orders_with_local_closure() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let fin_first =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        let fin_wait = wait_for_send_terminal(&controller, session_id, fin_first);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let write_controller = controller.clone();
        let fin = tokio::spawn(async move {
            write_controller
                .write_stream(session_id, fin_first, Bytes::new(), true)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            fin.await.unwrap(),
            WebTransportStreamWriteOutcome::Accepted {
                accepted: 0,
                fin_accepted: true,
                ..
            }
        );
        assert_eq!(
            fin_wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Closed {
                stream_id: fin_first,
            }
        );
        let retirement = retire_send_terminal(&controller, session_id, fin_first);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            retirement.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Retired {
                session_id,
                stream_id: fin_first,
            }
        );

        let retire_first =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        let retirement =
            retire_send_terminal(&controller, session_id, retire_first);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            retirement.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Retired { .. }
        );
        let reset_controller = controller.clone();
        let reset = tokio::spawn(async move {
            reset_controller
                .reset_stream(session_id, retire_first, 79)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            reset.await.unwrap(),
            WebTransportStreamControlOutcome::Applied
        );
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.send_terminal_waiters, 0);
        assert_eq!(stats.send_terminal_states, 0);
    }

    #[tokio::test]
    async fn webtransport_send_terminal_retirement_orders_with_teardown() {
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
        let wait = wait_for_send_terminal(&controller, session_id, stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let retire = retire_send_terminal(&controller, session_id, stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let retired = WebTransportStreamSendTerminalOutcome::Retired {
            session_id,
            stream_id,
        };
        assert_eq!(wait.await.unwrap(), retired);
        assert_eq!(retire.await.unwrap(), retired);
        helper
            .controller
            .close_webtransport_session(session_id, 3, "closed".to_string())
            .unwrap();
        assert_eq!(helper.process_commands().unwrap(), 1);

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
        let wait = wait_for_send_terminal(&controller, session_id, stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        helper
            .controller
            .close_webtransport_session(session_id, 5, "closed".to_string())
            .unwrap();
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_eq!(
            wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::SessionTerminated {
                session_id,
                stream_id,
            }
        );
        let retire = retire_send_terminal(&controller, session_id, stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            retire.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::TerminalSession,
            )
        );

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
        let retire = retire_send_terminal(&controller, session_id, stream_id);
        for _ in 0..8 {
            if helper
                .driver
                .webtransport_cmd_recv
                .as_ref()
                .is_some_and(|receiver| receiver.len() == 1)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            helper
                .driver
                .webtransport_cmd_recv
                .as_ref()
                .map(tokio::sync::mpsc::Receiver::len),
            Some(1)
        );
        drop(helper);
        assert_eq!(
            retire.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::ConnectionTerminated {
                session_id,
                stream_id,
            }
        );
    }

    #[tokio::test]
    async fn webtransport_send_terminal_preserves_write_fin_and_reset_results() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let stopped =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            stopped,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let stopped_wait =
            wait_for_send_terminal(&controller, session_id, stopped);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let stop_wire = webtransport_error_to_http3(47);
        helper
            .pipe
            .client
            .stream_shutdown(stopped, quiche::Shutdown::Read, stop_wire)
            .unwrap();
        helper.pipe.advance().unwrap();

        let (stopped_lease, stopped_log) = mock_write_lease(70, b"not sent");
        let stopped_write = controller
            .try_write_stream_lease(session_id, stopped, stopped_lease, true)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let stopped_lease = assert_matches!(
            stopped_write.outcome().await,
            WebTransportStreamWriteLeaseOutcome::ResetRequired {
                wire_error_code,
                application_error_code: Some(47),
                lease,
                fin: true,
            } if wire_error_code == stop_wire => lease
        );
        assert_eq!(stopped_lease.id, 70);
        assert_eq!(mock_write_lease_log(&stopped_log).exposures, 1);
        drop(stopped_lease);
        assert_eq!(
            stopped_wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Stopped {
                stream_id: stopped,
                wire_error_code: stop_wire,
                application_error_code: Some(47),
            }
        );

        let uncertain =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            uncertain,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let uncertain_wait =
            wait_for_send_terminal(&controller, session_id, uncertain);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let (uncertain_lease, uncertain_log) = mock_write_lease(71, b"accepted");
        let uncertain_write = controller
            .try_write_stream_lease(session_id, uncertain, uncertain_lease, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        drop(uncertain_write);
        assert_eq!(mock_write_lease_log(&uncertain_log).abandonments, [
            WebTransportStreamWriteLeaseProgress::Unknowable
        ]);
        let uncertain_wire = webtransport_error_to_http3(49);
        helper
            .pipe
            .client
            .stream_shutdown(uncertain, quiche::Shutdown::Read, uncertain_wire)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            uncertain_wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Stopped {
                stream_id,
                wire_error_code,
                ..
            } if stream_id == uncertain && wire_error_code == uncertain_wire
        );

        let finished =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            finished,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let finished_wait =
            wait_for_send_terminal(&controller, session_id, finished);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let write_controller = controller.clone();
        let finish = tokio::spawn(async move {
            write_controller
                .write_stream(session_id, finished, Bytes::new(), true)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            finish.await.unwrap(),
            WebTransportStreamWriteOutcome::Accepted {
                accepted: 0,
                remaining: None,
                fin_accepted: true,
            }
        );
        assert_eq!(
            finished_wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Closed {
                stream_id: finished,
            }
        );

        let reset =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            reset,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let reset_wait = wait_for_send_terminal(&controller, session_id, reset);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let reset_controller = controller.clone();
        let reset_operation = tokio::spawn(async move {
            reset_controller.reset_stream(session_id, reset, 53).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            reset_operation.await.unwrap(),
            WebTransportStreamControlOutcome::Applied
        );
        assert_eq!(
            reset_wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Closed { stream_id: reset }
        );
    }

    #[tokio::test]
    async fn webtransport_send_terminal_wakes_on_session_and_connection_teardown()
    {
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
        let wait = wait_for_send_terminal(&controller, session_id, stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        helper
            .pipe
            .client
            .stream_send(session_id, &[], true)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::SessionTerminated {
                session_id,
                stream_id,
            }
        );

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
        let wait = wait_for_send_terminal(&controller, session_id, stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        helper
            .controller
            .close_webtransport_session(session_id, 5, "closed".to_string())
            .unwrap();
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_eq!(
            wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::SessionTerminated {
                session_id,
                stream_id,
            }
        );

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
        let wait = wait_for_send_terminal(&controller, session_id, stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        drop(helper);
        assert_eq!(
            wait.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::ConnectionTerminated {
                session_id,
                stream_id,
            }
        );
    }

    #[tokio::test]
    async fn webtransport_command_lane_nonblocking_admission_preserves_ownership()
    {
        let mut settings = webtransport_settings();
        settings.webtransport_command_capacity = 2;
        settings.webtransport_max_datagram_send_allocation_bytes = 64;
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

        let allocation_oversized =
            datagram_socket::DgramBuffer::with_capacity(65);
        assert_matches!(
            controller.try_send_datagram(0, allocation_oversized),
            Err(WebTransportDatagramSendOutcome::AllocationTooLarge {
                max: 64,
                allocated,
                datagram,
            }) if allocated >= 65 && datagram.allocated_capacity() == allocated
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
    async fn webtransport_stream_limit_waits_for_max_streams_credit() {
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

        let first =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        assert_eq!(first, 1);
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            first,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let blocked_controller = controller.clone();
        let blocked = tokio::spawn(async move {
            blocked_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!blocked.is_finished());
        let before = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(before.stream_open_waiters, 1);
        for _ in 0..32 {
            helper.work_loop_iter().unwrap();
        }
        let idle = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(
            idle.stream_open_waiter_work_total,
            before.stream_open_waiter_work_total
        );

        let reset_controller = controller.clone();
        let reset = tokio::spawn(async move {
            reset_controller.reset_stream(session_id, first, 83).await
        });
        let stop_controller = controller.clone();
        let stop = tokio::spawn(async move {
            stop_controller.stop_stream(session_id, first, 83).await
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
            helper.work_loop_iter().unwrap();
            if reset.is_finished() && stop.is_finished() {
                break;
            }
        }
        assert_eq!(
            reset.await.unwrap(),
            WebTransportStreamControlOutcome::Applied
        );
        assert_eq!(
            stop.await.unwrap(),
            WebTransportStreamControlOutcome::Applied
        );

        helper.pipe.advance().unwrap();
        let wire_error = webtransport_error_to_http3(83);
        assert_eq!(
            helper.pipe.client.stream_capacity(first),
            Err(quiche::Error::StreamStopped(wire_error))
        );
        assert_eq!(
            helper.pipe.client.stream_recv(first, &mut [0; 1]),
            Err(quiche::Error::StreamReset(wire_error))
        );

        for _ in 0..32 {
            helper.advance_and_run_loop().unwrap();
            tokio::task::yield_now().await;
            if blocked.is_finished() {
                break;
            }
        }
        assert!(
            blocked.is_finished(),
            "MAX_STREAMS did not resume the open: peer_left={} client_closed={} server_closed={}",
            helper.pipe.server.peer_streams_left_bidi(),
            helper.pipe.client.stream_closed(first),
            helper.pipe.server.stream_closed(first),
        );
        assert_eq!(
            blocked.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id: 5 }
        );
        let after = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(after.stream_open_waiters, 0);
        assert_eq!(
            after.stream_open_waiter_work_total,
            before.stream_open_waiter_work_total + 1
        );
    }

    #[tokio::test]
    async fn webtransport_stream_credit_is_directional_and_fifo() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                single_server_stream_each_direction_webtransport_pipe(),
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

        let first_bidi =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            first_bidi,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        let first_uni =
            open_server_webtransport_uni(&mut helper, &controller, session_id)
                .await;
        assert_eq!(first_uni, 19);
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            first_uni,
            h3::WebTransportStreamDirection::Unidirectional,
        );

        let bidi_controller = controller.clone();
        let first_bidi_waiter = tokio::spawn(async move {
            bidi_controller.open_bidirectional_stream(session_id).await
        });
        let bidi_controller = controller.clone();
        let second_bidi_waiter = tokio::spawn(async move {
            bidi_controller.open_bidirectional_stream(session_id).await
        });
        let uni_controller = controller.clone();
        let uni_waiter = tokio::spawn(async move {
            uni_controller.open_unidirectional_stream(session_id).await
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
            helper.work_loop_iter().unwrap();
        }
        assert!(!first_bidi_waiter.is_finished());
        assert!(!second_bidi_waiter.is_finished());
        assert!(!uni_waiter.is_finished());
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.stream_open_waiters, 3);

        release_server_webtransport_stream_credit(
            &mut helper,
            &controller,
            session_id,
            first_bidi,
            WebTransportStreamDirection::Bidi,
            89,
        )
        .await;
        for _ in 0..32 {
            helper.advance_and_run_loop().unwrap();
            tokio::task::yield_now().await;
            if first_bidi_waiter.is_finished() {
                break;
            }
        }
        assert!(first_bidi_waiter.is_finished(), "bidi credit wake stalled");
        assert_eq!(
            first_bidi_waiter.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id: 5 }
        );
        assert!(!second_bidi_waiter.is_finished());
        assert!(!uni_waiter.is_finished());
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            5,
            h3::WebTransportStreamDirection::Bidirectional,
        );

        release_server_webtransport_stream_credit(
            &mut helper,
            &controller,
            session_id,
            first_uni,
            WebTransportStreamDirection::Uni,
            97,
        )
        .await;
        for _ in 0..32 {
            helper.advance_and_run_loop().unwrap();
            tokio::task::yield_now().await;
            if uni_waiter.is_finished() {
                break;
            }
        }
        assert!(uni_waiter.is_finished(), "uni credit wake stalled");
        assert_eq!(
            uni_waiter.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id: 23 }
        );
        assert!(!second_bidi_waiter.is_finished());

        release_server_webtransport_stream_credit(
            &mut helper,
            &controller,
            session_id,
            5,
            WebTransportStreamDirection::Bidi,
            101,
        )
        .await;
        for _ in 0..32 {
            helper.advance_and_run_loop().unwrap();
            tokio::task::yield_now().await;
            if second_bidi_waiter.is_finished() {
                break;
            }
        }
        assert!(second_bidi_waiter.is_finished(), "second bidi wake stalled");
        assert_eq!(
            second_bidi_waiter.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id: 9 }
        );
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.stream_open_waiters, 0);
        assert_eq!(stats.stream_open_waiter_work_total, 3);
    }

    #[tokio::test]
    async fn webtransport_stream_credit_before_registration_is_not_lost() {
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
        let first =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            first,
            h3::WebTransportStreamDirection::Bidirectional,
        );
        release_server_webtransport_stream_credit(
            &mut helper,
            &controller,
            session_id,
            first,
            WebTransportStreamDirection::Bidi,
            103,
        )
        .await;
        for _ in 0..32 {
            helper.advance_and_run_loop().unwrap();
            if helper.pipe.server.peer_streams_left_bidi() == 1 {
                break;
            }
        }
        assert_eq!(helper.pipe.server.peer_streams_left_bidi(), 1);

        assert_eq!(
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await,
            5
        );
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.stream_open_waiters, 0);
        assert_eq!(stats.stream_open_waiter_work_total, 0);
    }

    #[tokio::test]
    async fn webtransport_stream_credit_cancellation_bounds_and_teardown() {
        let mut settings = webtransport_settings();
        settings.webtransport_max_pending_streams = 1;
        settings.webtransport_max_pending_streams_per_session = 1;
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                single_server_bidi_webtransport_pipe(),
                settings.clone(),
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
        let first =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        receive_server_webtransport_stream(
            &mut helper,
            session_id,
            first,
            h3::WebTransportStreamDirection::Bidirectional,
        );

        let cancelled_controller = controller.clone();
        let cancelled = tokio::spawn(async move {
            cancelled_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            webtransport_retention_stats(&mut helper, &controller)
                .await
                .stream_open_waiters,
            1
        );
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        helper.work_loop_iter().unwrap();
        assert_eq!(
            webtransport_retention_stats(&mut helper, &controller)
                .await
                .stream_open_waiters,
            0
        );

        let replacement_controller = controller.clone();
        let replacement = tokio::spawn(async move {
            replacement_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let saturated_controller = controller.clone();
        let saturated = tokio::spawn(async move {
            saturated_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            saturated.await.unwrap(),
            WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            )
        );
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.stream_open_waiters, 1);
        assert_eq!(stats.stream_open_waiter_saturation_total, 1);

        release_server_webtransport_stream_credit(
            &mut helper,
            &controller,
            session_id,
            first,
            WebTransportStreamDirection::Bidi,
            107,
        )
        .await;
        for _ in 0..32 {
            helper.advance_and_run_loop().unwrap();
            tokio::task::yield_now().await;
            if replacement.is_finished() {
                break;
            }
        }
        assert_eq!(
            replacement.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id: 5 }
        );

        let pending_controller = controller.clone();
        let pending = tokio::spawn(async move {
            pending_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!pending.is_finished());
        helper
            .controller
            .close_webtransport_session(session_id, 7, "closed".to_string())
            .unwrap();
        assert_eq!(helper.process_commands().unwrap(), 1);
        assert_eq!(
            pending.await.unwrap(),
            WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::ClosingSession,
            )
        );

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
        let _first =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        let pending_controller = controller.clone();
        let pending = tokio::spawn(async move {
            pending_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!pending.is_finished());
        drop(helper);
        assert_eq!(
            pending.await.unwrap(),
            WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            )
        );
    }

    #[tokio::test]
    async fn webtransport_stream_credit_cancellation_survives_a_full_lane() {
        let mut settings = webtransport_settings();
        settings.webtransport_command_capacity = 1;
        settings.webtransport_max_pending_streams = 1;
        settings.webtransport_max_pending_streams_per_session = 1;
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
        let _first =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;

        let pending_controller = controller.clone();
        let pending = tokio::spawn(async move {
            pending_controller
                .open_bidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            webtransport_retention_stats(&mut helper, &controller)
                .await
                .stream_open_waiters,
            1
        );

        let stats_controller = controller.clone();
        let queued =
            tokio::spawn(async move { stats_controller.retention_stats().await });
        for _ in 0..8 {
            if helper
                .driver
                .webtransport_cmd_recv
                .as_ref()
                .is_some_and(|receiver| receiver.len() == 1)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            helper
                .driver
                .webtransport_cmd_recv
                .as_ref()
                .map(tokio::sync::mpsc::Receiver::len),
            Some(1)
        );
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());

        helper.work_loop_iter().unwrap();
        assert!(queued.await.unwrap().is_ok());
        assert_eq!(
            webtransport_retention_stats(&mut helper, &controller)
                .await
                .stream_open_waiters,
            0
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
    async fn webtransport_blocked_prefix_does_not_starve_another_stream() {
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
                .open_unidirectional_stream(blocked_session)
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
                session_id: blocked_session,
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
        let fin_terminal = assert_matches!(
            read.await.unwrap(),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert_eq!(fin_terminal.data(), b"fin payload");
        assert_eq!(
            fin_terminal.terminal(),
            WebTransportStreamReceiveTerminal::Fin
        );
        drop(fin_terminal);
        let retire =
            retire_receive_terminal(&controller, session_id, fin_stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            retire.await.unwrap(),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id,
                stream_id: fin_stream_id,
            }
        );

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
        let reset_terminal = assert_matches!(
            second.await.unwrap(),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert!(reset_terminal.data().is_empty());
        assert_eq!(
            reset_terminal.terminal(),
            WebTransportStreamReceiveTerminal::Reset {
                wire_error_code: wire_error,
                application_error_code: Some(77),
            }
        );
        drop(reset_terminal);
        let retire =
            retire_receive_terminal(&controller, session_id, reset_stream_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            retire.await.unwrap(),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id,
                stream_id: reset_stream_id,
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
    async fn webtransport_datagram_readable_wait_is_level_and_terminal_safe() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let waiting_controller = controller.clone();
        let waiting = tokio::spawn(async move {
            waiting_controller.wait_datagram_readable(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!waiting.is_finished());

        helper.pipe.client.dgram_send(b"\0ready").unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(
            waiting.await.unwrap(),
            WebTransportDatagramReadyOutcome::Ready
        );

        let level_controller = controller.clone();
        let level = tokio::spawn(async move {
            level_controller.wait_datagram_readable(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            level.await.unwrap(),
            WebTransportDatagramReadyOutcome::Ready
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
                if datagram.as_slice() == b"ready"
        );

        let terminal_controller = controller.clone();
        let terminal = tokio::spawn(async move {
            terminal_controller.wait_datagram_readable(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!terminal.is_finished());

        let duplicate_controller = controller.clone();
        let duplicate = tokio::spawn(async move {
            duplicate_controller
                .wait_datagram_readable(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            duplicate.await.unwrap(),
            WebTransportDatagramReadyOutcome::ResourceLimit
        );

        helper.peer_client_send_body(session_id, &[], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            session_id,
            WebTransportSessionCloseReason::Clean,
        );
        assert_eq!(
            terminal.await.unwrap(),
            WebTransportDatagramReadyOutcome::Rejected(
                WebTransportDatagramError::TerminalSession,
            )
        );
    }

    #[tokio::test]
    async fn webtransport_datagram_send_wait_survives_capacity_race() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                single_dgram_queue_webtransport_pipe(),
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

        let send_controller = controller.clone();
        let send = tokio::spawn(async move {
            send_controller
                .send_datagram(session_id, dgram_buf(b"fill"))
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            send.await.unwrap(),
            WebTransportDatagramSendOutcome::Accepted
        );
        assert!(helper.pipe.server.is_dgram_send_queue_full());

        let waiting_controller = controller.clone();
        let waiting = tokio::spawn(async move {
            waiting_controller
                .wait_datagram_send_capacity(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!waiting.is_finished());

        let duplicate_controller = controller.clone();
        let duplicate = tokio::spawn(async move {
            duplicate_controller
                .wait_datagram_send_capacity(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            duplicate.await.unwrap(),
            WebTransportDatagramReadyOutcome::ResourceLimit
        );

        helper.pipe.advance().unwrap();
        assert!(!helper.pipe.server.is_dgram_send_queue_full());
        assert!(
            helper
                .driver
                .wait_for_data(&mut helper.pipe.server)
                .now_or_never()
                .is_some(),
            "send-capacity readiness must make the wait predicate runnable"
        );
        helper.work_loop_iter().unwrap();
        assert_eq!(
            waiting.await.unwrap(),
            WebTransportDatagramReadyOutcome::Ready
        );

        let level_controller = controller.clone();
        let level = tokio::spawn(async move {
            level_controller
                .wait_datagram_send_capacity(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            level.await.unwrap(),
            WebTransportDatagramReadyOutcome::Ready
        );

        let refill_controller = controller.clone();
        let refill = tokio::spawn(async move {
            refill_controller
                .send_datagram(session_id, dgram_buf(b"refill"))
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            refill.await.unwrap(),
            WebTransportDatagramSendOutcome::Accepted
        );
        let terminal_controller = controller.clone();
        let terminal = tokio::spawn(async move {
            terminal_controller
                .wait_datagram_send_capacity(session_id)
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!terminal.is_finished());

        helper.peer_client_send_body(session_id, &[], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            session_id,
            WebTransportSessionCloseReason::Clean,
        );
        assert_eq!(
            terminal.await.unwrap(),
            WebTransportDatagramReadyOutcome::Rejected(
                WebTransportDatagramError::TerminalSession,
            )
        );
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
    async fn webtransport_datagrams_are_released_on_session_termination() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, response, _body) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(&mut helper, session_id, &response);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let send_controller = controller.clone();
        let send = tokio::spawn(async move {
            send_controller
                .send_datagram(session_id, dgram_buf(b"outbound"))
                .await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            send.await.unwrap(),
            WebTransportDatagramSendOutcome::Accepted
        );
        helper.pipe.advance().unwrap();
        assert_next_client_raw_h3_dgram(&mut helper, session_id / 4, b"outbound");
        assert_client_no_raw_h3_dgram(&mut helper);

        for payload in [b"first".as_slice(), b"still".as_slice()] {
            let mut wire = vec![(session_id / 4) as u8];
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
            (2, 10)
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
                if datagram.as_slice() == b"first"
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

        helper.peer_client_send_body(session_id, &[], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            session_id,
            WebTransportSessionCloseReason::Clean,
        );
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .pending_datagram_usage(),
            (0, 0)
        );

        let terminal_controller = controller.clone();
        let terminal = tokio::spawn(async move {
            terminal_controller.receive_datagram(session_id).await
        });
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_matches!(
            terminal.await.unwrap(),
            WebTransportDatagramReadOutcome::Rejected(
                WebTransportDatagramError::TerminalSession
            )
        );
        assert!(helper.driver.flow_map.is_empty());
    }

    #[tokio::test]
    async fn webtransport_selected_streams_enforce_direction_and_staleness() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (first_session, first_response, _first_body) =
            open_pending_webtransport_session(&mut helper);
        accept_pending_webtransport_session(
            &mut helper,
            first_session,
            &first_response,
        );
        assert_eq!(first_session, 0);

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
        let terminal =
            wait_for_send_terminal(&controller, first_session, uni_stream);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            terminal.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Closed {
                stream_id: uni_stream,
            }
        );
        let retired =
            retire_send_terminal(&controller, first_session, uni_stream);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            retired.await.unwrap(),
            WebTransportStreamSendTerminalOutcome::Retired {
                session_id: first_session,
                stream_id: uni_stream,
            }
        );
        helper.work_loop_iter().unwrap();
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

    #[test]
    fn webtransport_h3_command_lane_reports_capacity_and_returns_close() {
        let mut settings = webtransport_settings();
        settings.command_capacity = 1;
        let helper = webtransport_helper(settings);

        assert_eq!(
            helper.controller.send_goaway(),
            H3CommandAdmission::Accepted
        );
        assert_eq!(
            helper
                .controller
                .shutdown_stream(4, StreamShutdown::Write { error_code: 7 },),
            H3CommandAdmission::QueueFull
        );

        let message = "queue-full close".to_string();
        assert_eq!(
            helper
                .controller
                .close_webtransport_session(0, 9, message.clone()),
            Err(WebTransportSessionCloseError::QueueFull {
                session_id: 0,
                error_code: 9,
                message: message.clone(),
            })
        );

        drop(helper.driver);
        assert_eq!(
            helper
                .controller
                .close_webtransport_session(0, 9, message.clone()),
            Err(WebTransportSessionCloseError::DriverGone {
                session_id: 0,
                error_code: 9,
                message,
            })
        );
        assert_eq!(
            helper.controller.send_goaway(),
            H3CommandAdmission::DriverGone
        );
    }

    #[tokio::test]
    async fn webtransport_retention_snapshot_covers_all_bounded_queues() {
        let mut settings = webtransport_settings();
        settings.webtransport_command_capacity = 4;
        settings.webtransport_max_stream_write_bytes = 32;
        settings.webtransport_max_stream_write_lease_retained_bytes = 32;
        settings.webtransport_max_datagram_send_allocation_bytes = 64;
        let mut helper = webtransport_helper(settings);
        let (_to_client, _from_client) = accept_webtransport_session(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let mut backing = Vec::with_capacity(64);
        backing.extend_from_slice(b"retained");
        let allocation = backing.capacity();
        assert!(helper
            .driver
            .webtransport
            .as_mut()
            .unwrap()
            .route_datagram(
                &helper.pipe.server,
                0,
                datagram_socket::DgramBuffer::from(backing),
            )
            .is_none());

        let stats_controller = controller.clone();
        let stats =
            tokio::spawn(async move { stats_controller.retention_stats().await });
        tokio::task::yield_now().await;
        assert_eq!(
            helper.driver.webtransport_cmd_recv.as_ref().unwrap().len(),
            1
        );

        let first = controller
            .try_write_stream(0, 999, Bytes::from_static(b"first"), false)
            .unwrap();
        let second = controller
            .try_write_stream(0, 999, Bytes::from_static(b"second"), false)
            .unwrap();
        helper.work_loop_iter().unwrap();

        let stats = stats.await.unwrap().unwrap();
        assert_eq!(stats.sessions, 1);
        assert_eq!(stats.pending_datagrams, 1);
        assert_eq!(stats.pending_datagram_payload_bytes, 8);
        assert_eq!(stats.pending_datagram_allocation_bytes, allocation);
        assert_eq!(stats.command_capacity, 4);
        assert_eq!(stats.queued_commands, 2);
        assert_eq!(
            stats.queued_command_payload_bytes_upper_bound,
            2 * webtransport::MAX_CLOSE_MESSAGE_LEN
        );
        assert_eq!(stats.write_leases, 2);
        assert_eq!(stats.write_lease_retained_bytes, 11);
        assert_eq!(stats.max_write_leases, 4);
        assert_eq!(stats.max_write_lease_retained_bytes, 128);
        assert_eq!(stats.write_lease_admitted_total, 2);
        assert_eq!(stats.write_lease_queue_full_total, 0);
        assert_eq!(stats.write_lease_resource_limit_total, 0);
        assert_eq!(stats.write_lease_too_large_total, 0);
        assert!(stats.metadata_index_entries >= 3);
        assert_eq!(
            stats.adapter_bytes_upper_bound(),
            (allocation + 2 * webtransport::MAX_CLOSE_MESSAGE_LEN + 11) as u64
        );
        assert_eq!(
            stats.transport_queued_bytes(),
            stats.transport_stream_send_bytes as u64 +
                stats.transport_stream_receive_bytes +
                stats.transport_datagram_send_bytes as u64 +
                stats.transport_datagram_receive_bytes as u64
        );

        assert_matches!(
            first.outcome().await,
            WebTransportStreamWriteOutcome::Rejected {
                error: WebTransportSelectionError::UnknownStream,
                ..
            }
        );
        assert_matches!(
            second.outcome().await,
            WebTransportStreamWriteOutcome::Rejected {
                error: WebTransportSelectionError::UnknownStream,
                ..
            }
        );
    }

    #[test]
    fn webtransport_never_polled_event_lane_fails_with_excessive_load() {
        let mut settings = webtransport_settings();
        settings.event_capacity = 1;
        let mut helper = webtransport_helper(settings);
        start_webtransport_driver(&mut helper);

        helper
            .peer_client_send_request(make_webtransport_request_headers(), false)
            .unwrap();
        helper.pipe.advance().unwrap();

        let error = helper
            .driver
            .process_reads(&mut helper.pipe.server)
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<H3ConnectionError>(),
            Some(&H3ConnectionError::EventQueueOverloaded)
        );
        assert_eq!(helper.controller.event_queue_stats(), H3EventQueueStats {
            capacity: 1,
            admitted_total: 1,
            overload_total: 1,
            receiver_closed_total: 0,
            overloaded: true,
        });
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Ok(ServerH3Event::Core(H3Event::WebTransportSession(
                WebTransportSessionEvent::Pending { session_id: 0 }
            )))
        );

        let wait_error = tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never()
        .expect("terminal overload must remain immediately runnable")
        .unwrap_err();
        assert_eq!(
            wait_error.downcast_ref::<H3ConnectionError>(),
            Some(&H3ConnectionError::EventQueueOverloaded)
        );

        let work_error: crate::QuicResult<()> =
            Err(H3ConnectionError::EventQueueOverloaded.into());
        helper.driver.on_conn_close(
            &mut helper.pipe.server,
            &TestMetrics::default(),
            &work_error,
        );
        let local_error = helper.pipe.server.local_error().unwrap();
        assert!(local_error.is_app);
        assert_eq!(
            local_error.error_code,
            h3::WireErrorCode::ExcessiveLoad as u64
        );
    }

    #[test]
    fn webtransport_closed_event_receiver_is_not_reported_as_overload() {
        let mut settings = webtransport_settings();
        settings.event_capacity = 1;
        let mut helper = webtransport_helper(settings);
        start_webtransport_driver(&mut helper);
        drop(helper.controller.take_event_receiver());

        helper
            .peer_client_send_request(make_webtransport_request_headers(), false)
            .unwrap();
        helper.pipe.advance().unwrap();
        let error = helper
            .driver
            .process_reads(&mut helper.pipe.server)
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<H3ConnectionError>(),
            Some(&H3ConnectionError::ControllerWentAway)
        );
        assert_eq!(helper.controller.event_queue_stats(), H3EventQueueStats {
            capacity: 1,
            admitted_total: 0,
            overload_total: 0,
            receiver_closed_total: 1,
            overloaded: false,
        });
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

        let (unknown_lease, unknown_log) = mock_write_lease(50, b"unknown");
        let unknown = controller
            .try_write_stream_lease(session_id + 4, 1, unknown_lease, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let unknown_lease = assert_matches!(
            unknown.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::UnknownSession,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(unknown_lease.id, 50);
        assert_eq!(mock_write_lease_log(&unknown_log).exposures, 0);
        drop(unknown_lease);

        let (pending_lease, pending_log) = mock_write_lease(51, b"pending");
        let pending = controller
            .try_write_stream_lease(session_id, 1, pending_lease, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let pending_lease = assert_matches!(
            pending.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::PendingSession,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(pending_lease.id, 51);
        assert_eq!(mock_write_lease_log(&pending_log).exposures, 0);
        drop(pending_lease);

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
        let (terminal_lease, terminal_log) = mock_write_lease(52, b"terminal");
        let terminal_lease = controller
            .try_write_stream_lease(session_id, 1, terminal_lease, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let terminal_lease = assert_matches!(
            terminal_lease.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::TerminalSession,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(terminal_lease.id, 52);
        assert_eq!(mock_write_lease_log(&terminal_log).exposures, 0);
        drop(terminal_lease);

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
        let (stale_lease, stale_log) = mock_write_lease(53, b"stale");
        let stale_lease = controller
            .try_write_stream_lease(session_id, 1, stale_lease, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let stale_lease = assert_matches!(
            stale_lease.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::StaleSession,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(stale_lease.id, 53);
        assert_eq!(mock_write_lease_log(&stale_log).exposures, 0);
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
        let (closing_lease, closing_log) = mock_write_lease(54, b"closing");
        let closing_lease = controller
            .try_write_stream_lease(session_id, stream_id, closing_lease, false)
            .unwrap();
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
        let closing_lease = assert_matches!(
            closing_lease.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::ClosingSession,
                lease,
                fin: false,
            } => lease
        );
        assert_eq!(closing_lease.id, 54);
        assert_eq!(mock_write_lease_log(&closing_log).exposures, 0);
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
        let stream_id = helper
            .peer_client_send_request(make_webtransport_request_headers(), false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_no_driver_event(&mut helper);
        assert_eq!(
            helper.pipe.client.stream_capacity(stream_id),
            Err(quiche::Error::StreamStopped(
                h3::WireErrorCode::MessageError as u64,
            ))
        );
        assert_eq!(
            helper.peer_client_poll(),
            Ok((
                stream_id,
                h3::Event::Reset(h3::WireErrorCode::MessageError as u64),
            ))
        );
        assert_eq!(
            helper.driver.webtransport.as_ref().unwrap().session_count(),
            0
        );
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
    fn webtransport_optimistic_capsule_is_deferred_until_2xx() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (stream_id, to_client, mut from_client) =
            open_pending_webtransport_session(&mut helper);
        let close = webtransport_close_capsule(7, "optimistic");

        helper
            .peer_client_send_body(stream_id, &close, false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_no_driver_event(&mut helper);
        assert_matches!(
            from_client.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );

        accept_pending_webtransport_session(&mut helper, stream_id, &to_client);
        expect_session_terminated(
            &mut helper,
            stream_id,
            WebTransportSessionCloseReason::Peer {
                error_code: 7,
                message: "optimistic".to_string(),
            },
        );
        assert_matches!(
            from_client.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
        assert!(helper.driver.deferred_webtransport_capsule_reads.is_empty());
    }

    #[test]
    fn webtransport_optimistic_capsule_is_discarded_after_rejection() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (stream_id, to_client, mut from_client) =
            open_pending_webtransport_session(&mut helper);
        let close = webtransport_close_capsule(8, "discard me");

        helper
            .peer_client_send_body(stream_id, &close, false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_no_driver_event(&mut helper);

        send_response_status(&to_client, 403);
        helper.advance_and_run_loop().unwrap();
        expect_session_rejected(&mut helper, stream_id, 403);
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::Headers { .. })) if id == stream_id
        );
        assert_matches!(
            from_client.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        );
        assert!(helper.driver.deferred_webtransport_capsule_reads.is_empty());
        assert_no_webtransport_session_event(&mut helper);
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
    fn webtransport_excessive_session_is_reset_without_app_admission() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (first_id, first_send, _first_recv) =
            open_pending_webtransport_session(&mut helper);
        assert_eq!(first_id, 0);

        let excessive_stream = webtransport_stream_data(
            WEBTRANSPORT_BIDI_STREAM_TYPE,
            4,
            b"excessive",
        );
        helper
            .pipe
            .client
            .stream_send(8, &excessive_stream, false)
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_no_driver_event(&mut helper);

        let second_id = helper
            .peer_client_send_request(make_webtransport_request_headers(), false)
            .unwrap();
        assert_eq!(second_id, 4);
        helper.advance_and_run_loop().unwrap();
        assert_no_driver_event(&mut helper);
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper.peer_client_poll(),
            Ok((
                second_id,
                h3::Event::Reset(h3::WireErrorCode::RequestRejected as u64),
            ))
        );
        assert_eq!(
            helper.pipe.client.stream_capacity(8),
            Err(quiche::Error::StreamStopped(
                webtransport::WT_BUFFERED_STREAM_REJECTED
            ))
        );
        assert_eq!(
            helper.peer_client_poll(),
            Ok((
                8,
                h3::Event::Reset(webtransport::WT_BUFFERED_STREAM_REJECTED),
            ))
        );

        accept_pending_webtransport_session(&mut helper, first_id, &first_send);
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
        helper.pipe.client.stream_send(12, &later, true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_associated_stream(
            &mut helper,
            first_id,
            12,
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

    #[tokio::test]
    async fn webtransport_session_terminal_wait_is_stream_free_and_latched() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let (session_id, to_client, _from_client) =
            open_pending_webtransport_session(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let bidi_credit = helper.pipe.server.peer_streams_left_bidi();
        let uni_credit = helper.pipe.server.peer_streams_left_uni();

        let wait = wait_for_session_terminal(&controller, session_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!wait.is_finished());
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .active_stream_count(),
            0,
        );
        assert_eq!(helper.pipe.server.peer_streams_left_bidi(), bidi_credit);
        assert_eq!(helper.pipe.server.peer_streams_left_uni(), uni_credit);

        accept_pending_webtransport_session(&mut helper, session_id, &to_client);
        assert!(!wait.is_finished());
        helper.peer_client_send_body(session_id, &[], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            session_id,
            WebTransportSessionCloseReason::Clean,
        );
        assert_eq!(
            wait.await.unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id,
                reason: WebTransportSessionCloseReason::Clean,
            }
        );

        let late = wait_for_session_terminal(&controller, session_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            late.await.unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id,
                reason: WebTransportSessionCloseReason::Clean,
            }
        );
        assert_eq!(
            helper
                .driver
                .webtransport
                .as_ref()
                .unwrap()
                .active_stream_count(),
            0,
        );

        let queued_before_teardown =
            wait_for_session_terminal(&controller, session_id);
        tokio::task::yield_now().await;
        drop(helper);
        assert_eq!(
            queued_before_teardown.await.unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id,
                reason: WebTransportSessionCloseReason::Clean,
            }
        );
    }

    #[tokio::test]
    async fn webtransport_session_terminal_wait_cancels_and_reuses_capacity() {
        let mut settings = webtransport_settings();
        settings.webtransport_max_session_terminal_waiters = 1;
        settings.webtransport_max_session_terminal_waiters_per_session = 1;
        let mut helper = webtransport_helper(settings);
        let (to_client, _from_client) = accept_webtransport_session(&mut helper);
        let session_id = 0;
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let first = wait_for_session_terminal(&controller, session_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!first.is_finished());

        let saturated = wait_for_session_terminal(&controller, session_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            saturated.await.unwrap(),
            WebTransportSessionTerminalOutcome::ResourceLimit { session_id }
        );

        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.session_terminal_waiters, 0);
        assert_eq!(stats.max_session_terminal_waiters, 1);
        assert_eq!(stats.max_session_terminal_waiters_per_session, 1);
        assert_eq!(stats.session_terminal_waiter_saturation_total, 1);

        let replacement = wait_for_session_terminal(&controller, session_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert!(!replacement.is_finished());
        helper.peer_client_send_body(session_id, &[], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            session_id,
            WebTransportSessionCloseReason::Clean,
        );
        assert_eq!(
            replacement.await.unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id,
                reason: WebTransportSessionCloseReason::Clean,
            }
        );
        drop(to_client);
    }

    #[tokio::test]
    async fn webtransport_session_terminal_wait_types_absence_and_teardown() {
        let mut helper = webtransport_helper(webtransport_settings());
        let (to_client, _from_client) = accept_webtransport_session(&mut helper);
        let session_id = 0;
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let unknown = wait_for_session_terminal(&controller, 4000);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            unknown.await.unwrap(),
            WebTransportSessionTerminalOutcome::UnknownSession {
                session_id: 4000,
            }
        );

        helper.peer_client_send_body(session_id, &[], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        expect_session_terminated(
            &mut helper,
            session_id,
            WebTransportSessionCloseReason::Clean,
        );
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

        let stale = wait_for_session_terminal(&controller, session_id);
        tokio::task::yield_now().await;
        helper.work_loop_iter().unwrap();
        assert_eq!(
            stale.await.unwrap(),
            WebTransportSessionTerminalOutcome::StaleSession { session_id }
        );

        let mut closing = webtransport_helper(webtransport_settings());
        let (_to_client, _from_client) =
            accept_webtransport_session(&mut closing);
        let closing_controller = closing
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let connection = wait_for_session_terminal(&closing_controller, 0);
        tokio::task::yield_now().await;
        closing.work_loop_iter().unwrap();
        assert!(!connection.is_finished());
        drop(closing);
        assert_eq!(
            connection.await.unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id: 0,
                reason: WebTransportSessionCloseReason::ConnectionClosed,
            }
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
            Err(WebTransportSessionCloseError::MessageTooLong {
                len: 1025,
                message: "x".repeat(1025),
            })
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

    #[tokio::test]
    async fn webtransport_live_connection_snapshot_is_bounded_and_monotonic() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let cloned = controller.clone();

        let first = controller.live_connection_snapshot();
        assert_eq!(
            cloned.live_connection_snapshot().await,
            WebTransportLiveConnectionSnapshotOutcome::Saturated,
        );
        assert_eq!(
            helper.driver.webtransport_cmd_recv.as_ref().unwrap().len(),
            1,
        );
        helper.work_loop_iter().unwrap();
        let first = assert_matches!(
            first.await,
            WebTransportLiveConnectionSnapshotOutcome::Sampled(sample) => sample
        );
        let expected = helper.pipe.server.connection_path_snapshot();
        assert_matches!(
            expected,
            quiche::ConnectionPathSnapshot::SingleActive {
                path_generation,
                smoothed_rtt,
                congestion_window_bytes,
                bytes_in_flight,
            } if first.path_generation == path_generation &&
                first.smoothed_rtt == smoothed_rtt &&
                first.congestion_window_bytes == congestion_window_bytes &&
                first.bytes_in_flight == bytes_in_flight
        );
        assert_eq!(first.sample_sequence, 0);

        let second = cloned.live_connection_snapshot();
        helper.work_loop_iter().unwrap();
        let second = assert_matches!(
            second.await,
            WebTransportLiveConnectionSnapshotOutcome::Sampled(sample) => sample
        );
        assert_eq!(second.sample_sequence, 1);
        assert_eq!(second.path_generation, first.path_generation);

        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.live_connection_snapshot_requests, 0);
        assert_eq!(stats.max_live_connection_snapshot_requests, 1);
        assert_eq!(stats.live_connection_snapshot_saturation_total, 1);
        assert_eq!(stats.live_connection_snapshot_cancellation_total, 0);
        assert_eq!(stats.live_connection_snapshot_sample_total, 2);
        assert!(!std::mem::needs_drop::<WebTransportLiveConnectionSnapshot>());
    }

    #[tokio::test]
    async fn webtransport_live_connection_snapshot_cancellation_is_race_free() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        assert_eq!(
            controller.live_connection_snapshot().cancel(),
            WebTransportLiveConnectionSnapshotOutcome::Cancelled,
        );
        assert_eq!(
            controller.live_connection_snapshot().await,
            WebTransportLiveConnectionSnapshotOutcome::Saturated,
        );
        helper.work_loop_iter().unwrap();

        let sampled_then_cancelled = controller.live_connection_snapshot();
        helper.work_loop_iter().unwrap();
        assert_eq!(
            sampled_then_cancelled.cancel(),
            WebTransportLiveConnectionSnapshotOutcome::Cancelled,
        );

        let final_sample = controller.live_connection_snapshot();
        helper.work_loop_iter().unwrap();
        assert_matches!(
            final_sample.await,
            WebTransportLiveConnectionSnapshotOutcome::Sampled(
                WebTransportLiveConnectionSnapshot {
                    sample_sequence: 1,
                    ..
                }
            )
        );
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.live_connection_snapshot_requests, 0);
        assert_eq!(stats.live_connection_snapshot_saturation_total, 1);
        assert_eq!(stats.live_connection_snapshot_cancellation_total, 2);
        assert_eq!(stats.live_connection_snapshot_sample_total, 2);
    }

    #[tokio::test]
    async fn webtransport_live_connection_snapshot_closure_is_terminal() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let sampled_before_close = controller.live_connection_snapshot();
        helper.work_loop_iter().unwrap();

        crate::ApplicationOverQuic::on_conn_close(
            &mut helper.driver,
            &mut helper.pipe.server,
            &crate::metrics::DefaultMetrics,
            &Ok(()),
        );
        assert_eq!(
            sampled_before_close.await,
            WebTransportLiveConnectionSnapshotOutcome::ConnectionClosed,
        );
        assert_eq!(
            controller.live_connection_snapshot().await,
            WebTransportLiveConnectionSnapshotOutcome::ConnectionClosed,
        );

        let helper = webtransport_helper(webtransport_settings());
        let driver_gone = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let pending = driver_gone.live_connection_snapshot();
        let DriverTestHelper {
            pipe,
            driver,
            controller,
            peer,
        } = helper;
        drop(driver);
        assert_eq!(
            pending.await,
            WebTransportLiveConnectionSnapshotOutcome::DriverGone,
        );
        assert_eq!(
            driver_gone.live_connection_snapshot().await,
            WebTransportLiveConnectionSnapshotOutcome::DriverGone,
        );
        drop(controller);
        drop(peer);
        drop(pipe);
    }

    #[tokio::test]
    async fn webtransport_live_connection_snapshot_reports_lane_saturation() {
        let mut settings = webtransport_settings();
        settings.webtransport_command_capacity = 1;
        let mut helper = webtransport_helper(settings);
        start_webtransport_driver(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");

        let stats_controller = controller.clone();
        let queued =
            tokio::spawn(async move { stats_controller.retention_stats().await });
        tokio::task::yield_now().await;
        assert_eq!(
            helper.driver.webtransport_cmd_recv.as_ref().unwrap().len(),
            1,
        );
        assert_eq!(
            controller.live_connection_snapshot().await,
            WebTransportLiveConnectionSnapshotOutcome::Saturated,
        );
        helper.work_loop_iter().unwrap();
        assert!(queued.await.unwrap().is_ok());

        let sample = controller.live_connection_snapshot();
        helper.work_loop_iter().unwrap();
        assert_matches!(
            sample.await,
            WebTransportLiveConnectionSnapshotOutcome::Sampled(_)
        );
        let stats = webtransport_retention_stats(&mut helper, &controller).await;
        assert_eq!(stats.live_connection_snapshot_saturation_total, 1);
        assert_eq!(stats.live_connection_snapshot_requests, 0);
    }

    #[tokio::test]
    async fn webtransport_terminal_retention_preserves_snapshot_totals() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let claim = controller.terminal_retention_claim();
        let hook = helper
            .driver
            .connection_owner_drop_hook()
            .expect("WebTransport driver installs a core-owner hook");

        let sample = controller.live_connection_snapshot();
        assert_eq!(
            controller.live_connection_snapshot().await,
            WebTransportLiveConnectionSnapshotOutcome::Saturated,
        );
        helper.work_loop_iter().unwrap();
        assert_matches!(
            sample.await,
            WebTransportLiveConnectionSnapshotOutcome::Sampled(_)
        );
        assert_eq!(
            controller.live_connection_snapshot().cancel(),
            WebTransportLiveConnectionSnapshotOutcome::Cancelled,
        );

        crate::ApplicationOverQuic::on_conn_close(
            &mut helper.driver,
            &mut helper.pipe.server,
            &crate::metrics::DefaultMetrics,
            &Ok(()),
        );
        let DriverTestHelper {
            pipe,
            driver,
            controller: h3_controller,
            peer,
        } = helper;
        drop(h3_controller);
        drop(driver);
        drop(peer);
        drop(pipe);
        hook.fire();

        let stats = assert_matches!(
            controller.wait_terminal_retention(claim).await,
            WebTransportTerminalRetentionOutcome::Taken(stats) => stats
        );
        assert_terminal_retention_current_zero(&stats);
        assert_eq!(stats.max_live_connection_snapshot_requests, 1);
        assert_eq!(stats.live_connection_snapshot_saturation_total, 1);
        assert_eq!(stats.live_connection_snapshot_cancellation_total, 1);
        assert_eq!(stats.live_connection_snapshot_sample_total, 1);
    }

    #[tokio::test]
    async fn webtransport_terminal_retention_follows_event_and_core_teardown() {
        let mut settings = webtransport_settings();
        settings.webtransport_command_capacity = 1;
        let mut helper = webtransport_helper(settings);
        let (to_client, _from_client) = accept_webtransport_session(&mut helper);
        let session_id = 0;
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let claim = controller.terminal_retention_claim();
        let hook = helper
            .driver
            .connection_owner_drop_hook()
            .expect("WebTransport driver installs a core-owner hook");

        let (queued, queued_log) = mock_write_lease(500, b"queued");
        let queued = controller
            .try_write_stream_lease(session_id, 400, queued, false)
            .unwrap();
        let (full, full_log) = mock_write_lease(501, b"full");
        let full = assert_matches!(
            controller.try_write_stream_lease(session_id, 404, full, false),
            Err(WebTransportStreamWriteLeaseOutcome::QueueFull {
                lease,
                fin: false,
            }) => lease
        );
        drop(full);

        crate::ApplicationOverQuic::on_conn_close(
            &mut helper.driver,
            &mut helper.pipe.server,
            &crate::metrics::DefaultMetrics,
            &Ok(()),
        );
        assert_eq!(
            controller.retention_stats().await,
            Err(WebTransportDatagramError::ConnectionClosed)
        );
        expect_session_terminated(
            &mut helper,
            session_id,
            WebTransportSessionCloseReason::ConnectionClosed,
        );
        assert_matches!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::Early(
                WebTransportTerminalRetentionPending {
                    runtime_settled: true,
                    connection_owner_attached: true,
                    connection_owner_dropped: false,
                    write_leases: 1,
                    ..
                }
            )
        );

        let DriverTestHelper {
            pipe,
            driver,
            controller: h3_controller,
            peer,
        } = helper;
        drop(to_client);
        drop(peer);
        drop(pipe);
        hook.fire();

        let wait_controller = controller.clone();
        let wait_claim = claim.clone();
        let wait = tokio::spawn(async move {
            wait_controller.wait_terminal_retention(wait_claim).await
        });
        tokio::task::yield_now().await;
        assert!(!wait.is_finished());
        drop(queued);
        let stats = assert_matches!(
            wait.await.unwrap(),
            WebTransportTerminalRetentionOutcome::Taken(stats) => stats
        );
        assert_terminal_retention_current_zero(&stats);
        assert_eq!(stats.write_lease_admitted_total, 1);
        assert_eq!(stats.write_lease_queue_full_total, 1);
        assert_eq!(stats.write_lease_abandoned_unexposed_total, 1);
        assert_eq!(mock_write_lease_log(&queued_log).drops, 1);
        assert_eq!(mock_write_lease_log(&full_log).drops, 1);
        assert_eq!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::AlreadyTaken
        );

        drop(h3_controller);
        drop(driver);
    }

    #[tokio::test]
    async fn webtransport_terminal_retention_survives_event_lane_and_driver_loss()
    {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let claim = controller.terminal_retention_claim();
        let hook = helper
            .driver
            .connection_owner_drop_hook()
            .expect("WebTransport driver installs a core-owner hook");
        drop(helper.controller.take_event_receiver());

        let error: crate::QuicResult<()> =
            Err(H3ConnectionError::PostAcceptTimeout.into());
        crate::ApplicationOverQuic::on_conn_close(
            &mut helper.driver,
            &mut helper.pipe.server,
            &crate::metrics::DefaultMetrics,
            &error,
        );

        let DriverTestHelper {
            pipe,
            driver,
            controller: h3_controller,
            peer,
        } = helper;
        drop(h3_controller);
        drop(driver);
        drop(peer);
        drop(pipe);
        hook.fire();

        let stats = assert_matches!(
            controller.wait_terminal_retention(claim).await,
            WebTransportTerminalRetentionOutcome::Taken(stats) => stats
        );
        assert_terminal_retention_current_zero(&stats);
    }

    #[tokio::test]
    async fn webtransport_terminal_retention_survives_event_lane_overload() {
        let mut settings = webtransport_settings();
        settings.event_capacity = 1;
        let mut helper = webtransport_helper(settings);
        start_webtransport_driver(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let claim = controller.terminal_retention_claim();
        let hook = helper
            .driver
            .connection_owner_drop_hook()
            .expect("WebTransport driver installs a core-owner hook");
        helper
            .driver
            .h3_event_sender
            .send(ServerH3Event::Core(H3Event::IncomingSettings {
                settings: vec![],
            }))
            .unwrap();
        assert_eq!(
            helper.driver.h3_event_sender.send(ServerH3Event::Core(
                H3Event::IncomingSettings { settings: vec![] }
            )),
            Err(H3ConnectionError::EventQueueOverloaded)
        );

        crate::ApplicationOverQuic::on_conn_close(
            &mut helper.driver,
            &mut helper.pipe.server,
            &crate::metrics::DefaultMetrics,
            &Ok(()),
        );
        let DriverTestHelper {
            pipe,
            driver,
            controller: h3_controller,
            peer,
        } = helper;
        drop(h3_controller);
        drop(driver);
        drop(peer);
        drop(pipe);
        hook.fire();
        let stats = assert_matches!(
            controller.wait_terminal_retention(claim).await,
            WebTransportTerminalRetentionOutcome::Taken(stats) => stats
        );
        assert_terminal_retention_current_zero(&stats);
    }

    #[tokio::test]
    async fn webtransport_terminal_retention_survives_service_drop() {
        let helper = webtransport_helper(webtransport_settings());
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let claim = controller.terminal_retention_claim();
        let hook = helper
            .driver
            .connection_owner_drop_hook()
            .expect("WebTransport driver installs a core-owner hook");
        let DriverTestHelper {
            pipe,
            driver,
            controller: h3_controller,
            peer,
        } = helper;

        drop(h3_controller);
        drop(driver);
        assert_matches!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::Early(
                WebTransportTerminalRetentionPending {
                    runtime_settled: true,
                    connection_owner_dropped: false,
                    ..
                }
            )
        );
        drop(peer);
        drop(pipe);
        hook.fire();
        assert_matches!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::Taken(_)
        );
    }

    #[tokio::test]
    async fn webtransport_terminal_retention_waits_for_retry_permission() {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                exact_prefix_capacity_webtransport_pipe(),
                webtransport_settings(),
            )
            .unwrap();
        let (to_client, _from_client) = accept_webtransport_session(&mut helper);
        let session_id = 0;
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let stream_id =
            open_server_webtransport_bidi(&mut helper, &controller, session_id)
                .await;
        let (lease, _log) = mock_write_lease(600, b"blocked");
        let operation = controller
            .try_write_stream_lease(session_id, stream_id, lease, false)
            .unwrap();
        helper.work_loop_iter().unwrap();
        let (lease, retry) = assert_matches!(
            operation.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Blocked {
                lease,
                retry,
                ..
            } => (lease, retry)
        );
        drop(lease);

        let claim = controller.terminal_retention_claim();
        let hook = helper
            .driver
            .connection_owner_drop_hook()
            .expect("WebTransport driver installs a core-owner hook");
        crate::ApplicationOverQuic::on_conn_close(
            &mut helper.driver,
            &mut helper.pipe.server,
            &crate::metrics::DefaultMetrics,
            &Ok(()),
        );
        let DriverTestHelper {
            pipe,
            driver,
            controller: h3_controller,
            peer,
        } = helper;
        drop(to_client);
        drop(h3_controller);
        drop(driver);
        drop(peer);
        drop(pipe);
        hook.fire();

        let pending = assert_matches!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::Early(pending) => pending
        );
        assert_eq!(pending.write_leases, 1);
        assert_eq!(pending.write_lease_retained_bytes, 0);
        drop(retry);
        let stats = assert_matches!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::Taken(stats) => stats
        );
        assert_terminal_retention_current_zero(&stats);
    }

    #[tokio::test]
    async fn webtransport_terminal_retention_survives_transport_failure() {
        let mut helper = webtransport_helper(webtransport_settings());
        start_webtransport_driver(&mut helper);
        let controller = helper
            .controller
            .webtransport_controller()
            .expect("native WebTransport controller");
        let claim = controller.terminal_retention_claim();
        let hook = helper
            .driver
            .connection_owner_drop_hook()
            .expect("WebTransport driver installs a core-owner hook");
        let error: crate::QuicResult<()> = Err(H3ConnectionError::H3(
            h3::Error::TransportError(quiche::Error::TlsFail),
        )
        .into());
        crate::ApplicationOverQuic::on_conn_close(
            &mut helper.driver,
            &mut helper.pipe.server,
            &crate::metrics::DefaultMetrics,
            &error,
        );
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ConnectionError(h3::Error::TransportError(
                quiche::Error::TlsFail
            )))
        );
        let DriverTestHelper {
            pipe,
            driver,
            controller: h3_controller,
            peer,
        } = helper;
        drop(h3_controller);
        drop(driver);
        drop(peer);
        drop(pipe);
        hook.fire();
        let stats = assert_matches!(
            controller.wait_terminal_retention(claim).await,
            WebTransportTerminalRetentionOutcome::Taken(stats) => stats
        );
        assert_terminal_retention_current_zero(&stats);
    }
}
