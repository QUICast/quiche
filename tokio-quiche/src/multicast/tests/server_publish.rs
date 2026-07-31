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

#[test]
fn server_runtime_announces_and_joins_after_limits() {
    let settings = test_settings();
    let server_settings = test_server_settings();
    let mut pipe = test_pipe(&settings);
    let backend = FakePublishBackend::default();
    let (_command_sender, command_receiver, _command_observer) =
        test_server_command_channel();
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerRuntime::with_backend(
        server_settings,
        event_sender,
        command_receiver,
        backend,
    );

    runtime.on_conn_established(&mut pipe.server).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    let announce = match pipe.client.multicast_recv() {
        Ok(quiche::multicast::Frame::Announce(frame)) => frame,
        other => panic!("expected announce, got {other:?}"),
    };
    let key = match pipe.client.multicast_recv() {
        Ok(quiche::multicast::Frame::Key(frame)) => frame,
        other => panic!("expected key, got {other:?}"),
    };

    assert_eq!(announce, test_ipv4_announce());
    assert_eq!(key, test_key(&announce.channel_id));

    pipe.client
        .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
        .unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    runtime.process_reads(&mut pipe.server).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Join(quiche::multicast::Join {
            channel_id: announce.channel_id.clone(),
            mc_limits_sequence: 1,
            mc_state_sequence: 0,
            mc_key_sequence: 1,
        }))
    );
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientLimits(frame))
            if frame.sequence == 1 &&
                frame.limits == test_transport_params().limits
    ));
}
#[test]
fn server_runtime_emits_client_ack() {
    let settings = test_settings();
    let server_settings = test_server_settings();
    let mut pipe = test_pipe(&settings);
    let backend = FakePublishBackend::default();
    let (_command_sender, command_receiver, _command_observer) =
        test_server_command_channel();
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerRuntime::with_backend(
        server_settings,
        event_sender,
        command_receiver,
        backend,
    );
    let ack = quiche::multicast::Ack {
        channel_id: vec![1, 2, 3, 4],
        largest_acknowledged: 7,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: vec![quiche::multicast::AckRange {
            gap: 1,
            ack_range_length: 1,
        }],
        ecn_counts: None,
    };

    runtime.on_conn_established(&mut pipe.server).unwrap();
    let mut out = [0; 256];
    let channel = runtime.channels.get_mut(&ack.channel_id).unwrap();

    for _ in 0..8 {
        channel
            .send_state
            .write_packet(&[quiche::multicast::ChannelFrame::Ping], &mut out)
            .unwrap();
    }

    pipe.client
        .multicast_send(quiche::multicast::Frame::Ack(ack.clone()))
        .unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    runtime.process_reads(&mut pipe.server).unwrap();

    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientAck(frame)) if frame == ack
    ));
    assert_eq!(
        pipe.server.multicast_probe_status(&[1, 2, 3, 4]),
        Some(quiche::multicast::ProbeStatus::Viable)
    );
    assert_eq!(
        pipe.server.multicast_probe_recv(),
        Ok(quiche::multicast::ProbeEvent {
            channel_id: vec![1, 2, 3, 4],
            status: quiche::multicast::ProbeStatus::Viable,
            reason_scope: None,
            reason_code: None,
            reason_phrase: Vec::new(),
        })
    );
    let metrics = runtime
        .channels
        .get([1, 2, 3, 4].as_slice())
        .unwrap()
        .send_state
        .metrics_snapshot();
    assert_eq!(metrics.ack_frames_processed, 1);
    assert_eq!(metrics.ack_blocks_processed, 2);
    assert_eq!(metrics.acked_packets_reported, 3);
    assert_eq!(metrics.ack_errors, 0);
    assert_eq!(metrics.largest_acknowledged, Some(7));
}

#[test]
fn server_runtime_processes_unique_acks_and_deduplicates_notifications() {
    let settings = test_settings();
    let server_settings = test_server_settings();
    let mut pipe = test_pipe(&settings);
    let backend = FakePublishBackend::default();
    let (_command_sender, command_receiver, _command_observer) =
        test_server_command_channel();
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerRuntime::with_backend(
        server_settings,
        event_sender,
        command_receiver,
        backend,
    );
    let ack = |largest_acknowledged| quiche::multicast::Ack {
        channel_id: vec![1, 2, 3, 4],
        largest_acknowledged,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: Vec::new(),
        ecn_counts: None,
    };

    runtime.on_conn_established(&mut pipe.server).unwrap();
    let mut out = [0; 256];
    let channel = runtime.channels.get_mut(&[1, 2, 3, 4][..]).unwrap();
    for _ in 0..8 {
        channel
            .send_state
            .write_packet(&[quiche::multicast::ChannelFrame::Ping], &mut out)
            .unwrap();
    }

    for frame in [ack(5), ack(5), ack(7)] {
        pipe.client
            .multicast_send(quiche::multicast::Frame::Ack(frame))
            .unwrap();
    }
    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
    runtime.process_reads(&mut pipe.server).unwrap();

    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientAck(frame))
            if frame.largest_acknowledged == 5
    ));
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientAck(frame))
            if frame.largest_acknowledged == 7
    ));
    assert!(event_receiver.try_recv().is_err());

    pipe.client
        .multicast_send(quiche::multicast::Frame::Ack(ack(7)))
        .unwrap();
    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
    runtime.process_reads(&mut pipe.server).unwrap();
    assert!(event_receiver.try_recv().is_err());

    let metrics = runtime
        .channels
        .get([1, 2, 3, 4].as_slice())
        .unwrap()
        .send_state
        .metrics_snapshot();
    // The reliable core handoff safely coalesces the exact duplicate ACK
    // before the runtime sees it. Distinct range updates are retained.
    assert_eq!(metrics.ack_frames_processed, 3);
    assert_eq!(metrics.largest_acknowledged, Some(7));
}
#[test]
fn server_runtime_does_not_probe_unknown_ack() {
    let settings = test_settings();
    let server_settings = test_server_settings();
    let mut pipe = test_pipe(&settings);
    let backend = FakePublishBackend::default();
    let (_command_sender, command_receiver, _command_observer) =
        test_server_command_channel();
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerRuntime::with_backend(
        server_settings,
        event_sender,
        command_receiver,
        backend,
    );
    let ack = quiche::multicast::Ack {
        channel_id: vec![9, 9, 9, 9],
        largest_acknowledged: 3,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: Vec::new(),
        ecn_counts: None,
    };

    runtime.on_conn_established(&mut pipe.server).unwrap();

    pipe.client
        .multicast_send(quiche::multicast::Frame::Ack(ack.clone()))
        .unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    runtime.process_reads(&mut pipe.server).unwrap();

    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientAck(frame)) if frame == ack
    ));
    assert_eq!(pipe.server.multicast_probe_status(&ack.channel_id), None);
    assert_eq!(pipe.server.multicast_probe_recv(), Err(quiche::Error::Done));
}
#[test]
fn server_runtime_publishes_encoded_channel_packet() {
    let settings = test_settings();
    let server_settings = test_server_settings();
    let channel_id = server_settings.channels[0].channel_id.clone();
    let mut pipe = test_pipe(&settings);
    let backend = FakePublishBackend::default();
    let published = Arc::clone(&backend.sent);
    let (command_sender, command_receiver, _command_observer) =
        test_server_command_channel();
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerRuntime::with_backend(
        server_settings,
        event_sender,
        command_receiver,
        backend,
    );

    runtime.on_conn_established(&mut pipe.server).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    let announce = match pipe.client.multicast_recv() {
        Ok(quiche::multicast::Frame::Announce(frame)) => frame,
        other => panic!("expected announce, got {other:?}"),
    };
    let key = match pipe.client.multicast_recv() {
        Ok(quiche::multicast::Frame::Key(frame)) => frame,
        other => panic!("expected key, got {other:?}"),
    };

    command_sender
        .try_send(ServerCommand::Send {
            channel_id: channel_id.clone(),
            frames: vec![quiche::multicast::ChannelFrame::Datagram {
                data: b"hello multicast".to_vec(),
            }],
        })
        .unwrap();

    runtime.process_writes(&mut pipe.server).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    let integrity = match pipe.client.multicast_recv() {
        Ok(quiche::multicast::Frame::Integrity(frame)) => frame,
        other => panic!("expected integrity, got {other:?}"),
    };
    let packet = published.lock().unwrap()[0].clone();
    let mut receiver =
        quiche::multicast::ChannelReceiveState::new(announce).unwrap();

    receiver.insert_key(key).unwrap();
    assert!(receiver.insert_integrity(integrity).unwrap().is_empty());

    let events = receiver.recv(&packet.payload, ()).unwrap();

    assert!(matches!(
        &events[0],
        quiche::multicast::ChannelReceiveEvent::Packet {
            packet,
            metadata: (),
        } if packet.channel_id == channel_id &&
            packet.frames == vec![quiche::multicast::ChannelFrame::Datagram {
                data: b"hello multicast".to_vec(),
            }]
    ));
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::Published {
            channel_id: published_channel,
            packet_number: 0,
            report,
        }) if published_channel == channel_id &&
            report.bytes_sent == packet.payload.len()
    ));
}
