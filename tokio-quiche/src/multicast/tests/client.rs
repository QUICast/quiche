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

fn assert_next_local_state(
    event_receiver: &mut ClientEventStream,
    expected: quiche::multicast::ChannelState,
) {
    loop {
        match event_receiver.try_recv() {
            Ok(ClientEvent::LocalState(frame)) => {
                assert_eq!(frame.state, expected);
                return;
            },

            Ok(ClientEvent::MetricsUpdated { .. }) => continue,

            other => panic!("expected local state, got {other:?}"),
        }
    }
}

fn joined_client_runtime() -> (
    ClientRuntime<FakeJoinBackend>,
    Pipe,
    ClientEventStream,
    quiche::multicast::Announce,
) {
    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let (event_sender, mut event_receiver, _event_observer) =
        test_client_event_channel();
    let mut runtime = ClientRuntime::with_backend(
        settings,
        event_sender,
        FakeJoinBackend::default(),
    );
    let announce = test_ipv4_announce();

    runtime.handle_announce(announce.clone()).unwrap();
    runtime
        .handle_key(&mut pipe.client, test_key(&announce.channel_id))
        .unwrap();
    runtime
        .handle_join(&mut pipe.client, quiche::multicast::Join {
            channel_id: announce.channel_id.clone(),
            mc_limits_sequence: 0,
            mc_state_sequence: 0,
            mc_key_sequence: 1,
        })
        .unwrap();
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ClientEvent::Announce(frame)) if frame == announce
    ));
    assert_next_local_state(
        &mut event_receiver,
        quiche::multicast::ChannelState::Joined,
    );
    while event_receiver.try_recv().is_ok() {}

    (runtime, pipe, event_receiver, announce)
}

#[test]
fn client_ingress_overload_releases_join_and_reports_fallback() {
    let (mut runtime, mut pipe, mut events, announce) = joined_client_runtime();
    let retained_bytes = 4096;
    let max_retained_bytes = 1024;

    runtime
        .ingress_sender
        .try_send(IngressEvent::Overload {
            channel_id: announce.channel_id.clone(),
            retained_bytes,
            max_retained_bytes,
        })
        .unwrap();
    assert!(runtime.transfer_one_ingress());
    assert!(runtime.process_one_ingress(&mut pipe.client).unwrap());

    let channel = &runtime.channels[&announce.channel_id];
    assert!(channel.receive_handle.is_none());
    assert!(channel.receive_state.is_none());
    assert_eq!(channel.ack_state, quiche::multicast::AckTracker::default());

    assert!(matches!(
        events.try_recv(),
        Ok(ClientEvent::IngressOverload {
            channel_id,
            retained_bytes: 4096,
            max_retained_bytes: 1024,
        }) if channel_id == announce.channel_id
    ));
    assert_next_local_state(&mut events, quiche::multicast::ChannelState::Left);
}

#[test]
fn client_control_retry_preserves_state_sequence_order() {
    let settings = test_settings();
    let mut client_config =
        quiche::test_utils::Pipe::default_config("cubic").unwrap();
    client_config
        .set_multicast_client_params(Some(settings.transport_params.clone()))
        .unwrap();
    client_config.set_multicast_send_queue_limits(1, 4096);
    let mut server_config =
        quiche::test_utils::Pipe::default_config("cubic").unwrap();
    server_config.enable_multicast_server_support(true);
    let mut pipe = Pipe::with_client_and_server_config_and_buf(
        &mut client_config,
        &mut server_config,
    )
    .unwrap();
    pipe.handshake().unwrap();

    let (event_sender, mut events, _event_observer) = test_client_event_channel();
    let mut runtime = ClientRuntime::with_backend(
        settings,
        event_sender,
        FakeJoinBackend::default(),
    );
    runtime.on_conn_established(&mut pipe.client).unwrap();
    let channel_id = vec![1, 2, 3, 4];
    runtime
        .channels
        .insert(channel_id.clone(), Channel::default());

    runtime
        .send_state(
            &mut pipe.client,
            channel_id.clone(),
            quiche::multicast::ChannelState::Joined,
            quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            b"first".to_vec(),
        )
        .unwrap();
    runtime
        .send_state(
            &mut pipe.client,
            channel_id.clone(),
            quiche::multicast::ChannelState::Left,
            quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            b"second".to_vec(),
        )
        .unwrap();
    assert_eq!(runtime.pending_control.observer().stats().retained_items, 2);
    assert_eq!(runtime.channels[&channel_id].next_state_sequence, 0);
    assert_eq!(runtime.reserved_state_sequences[&channel_id], 2);

    pipe.advance().unwrap();
    runtime.process_reads(&mut pipe.client).unwrap();
    assert!(runtime.flush_one_pending_control(&mut pipe.client).unwrap());
    assert_eq!(runtime.channels[&channel_id].next_state_sequence, 1);
    assert_eq!(runtime.pending_control.observer().stats().retained_items, 1);

    pipe.advance().unwrap();
    runtime.process_reads(&mut pipe.client).unwrap();
    assert!(runtime.flush_one_pending_control(&mut pipe.client).unwrap());
    assert_eq!(runtime.channels[&channel_id].next_state_sequence, 2);
    assert!(runtime.pending_control.is_empty());

    let first = events.try_recv().unwrap();
    let second = events.try_recv().unwrap();
    assert!(matches!(
        first,
        ClientEvent::LocalState(frame)
            if frame.sequence == 1 &&
                frame.state == quiche::multicast::ChannelState::Joined
    ));
    assert!(matches!(
        second,
        ClientEvent::LocalState(frame)
            if frame.sequence == 2 &&
                frame.state == quiche::multicast::ChannelState::Left
    ));

    pipe.advance().unwrap();
    assert!(matches!(
        pipe.server.multicast_recv(),
        Ok(quiche::multicast::Frame::Limits(_))
    ));
    assert!(matches!(
        pipe.server.multicast_recv(),
        Ok(quiche::multicast::Frame::State(frame)) if frame.sequence == 1
    ));
    assert!(matches!(
        pipe.server.multicast_recv(),
        Ok(quiche::multicast::Frame::State(frame)) if frame.sequence == 2
    ));
}

#[test]
fn client_runtime_bounds_unique_channel_ids_across_retirement() {
    let settings = test_settings();
    let (event_sender, _events, _event_observer) = test_client_event_channel();
    let limits = RuntimeLimits {
        max_tracked_channel_ids: 2,
        ..RuntimeLimits::default()
    };
    let mut runtime = ClientRuntime::with_backend_and_limits(
        settings,
        event_sender,
        FakeJoinBackend::default(),
        limits,
    );

    for id in [1_u8, 2] {
        let mut announce = test_ipv4_announce();
        announce.channel_id = vec![id];
        runtime.handle_announce(announce).unwrap();
    }
    assert_eq!(runtime.channels.len(), 2);

    runtime.channels.get_mut(&[1][..]).unwrap().retired = true;
    let mut rejected = test_ipv4_announce();
    rejected.channel_id = vec![3];
    assert!(matches!(
        runtime.handle_announce(rejected),
        Err(error) if error.to_string().contains(
            "connection-lifetime Channel ID limit"
        )
    ));
    assert_eq!(runtime.channels.len(), 2);
    assert_eq!(runtime.channels.keys().map(Vec::len).sum::<usize>(), 2);
}

#[test]
fn server_runtime_bounds_ids_and_unknown_acks_do_not_allocate() {
    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, _events, _event_observer) = test_server_event_channel();
    let limits = RuntimeLimits {
        max_tracked_channel_ids: 2,
        ..RuntimeLimits::default()
    };
    let mut runtime = ServerControlRuntime::with_limits(
        ServerControlSettings {
            mode: ServerControlMode::Manual,
            channels: Vec::new(),
            stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
        },
        event_sender,
        command_receiver,
        limits,
    );
    runtime.on_conn_established(&mut pipe.server).unwrap();

    for id in [1_u8, 2] {
        let mut config = test_stream_control_config();
        config.announce.channel_id = vec![id];
        config.key.channel_id = vec![id];
        runtime
            .upsert_channel_config(&mut pipe.server, config, false, false)
            .unwrap();
    }
    assert_eq!(runtime.channels.len(), 2);

    for id in 10_u16..110 {
        runtime
            .handle_frame(
                &mut pipe.server,
                quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                    channel_id: id.to_be_bytes().to_vec(),
                    largest_acknowledged: 0,
                    ack_delay: 0,
                    first_ack_range: 0,
                    ack_ranges: Vec::new(),
                    ecn_counts: None,
                }),
            )
            .unwrap();
    }
    assert_eq!(runtime.channels.len(), 2);
    assert!(runtime.event_coalescer.pending_client_acks.is_empty());
    assert!(runtime.event_coalescer.last_client_acks.is_empty());
    assert!(runtime.event_coalescer.last_probe_events.is_empty());

    let mut rejected = test_stream_control_config();
    rejected.announce.channel_id = vec![3];
    rejected.key.channel_id = vec![3];
    assert!(runtime
        .upsert_channel_config(&mut pipe.server, rejected, false, false)
        .is_err());
    assert_eq!(runtime.channels.len(), 2);
}

fn assert_client_receives_dgram(pipe: &mut Pipe, expected: &[u8]) {
    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    let mut out = [0; 128];
    assert_eq!(pipe.client.dgram_recv(&mut out), Ok(expected.len()));
    assert_eq!(&out[..expected.len()], expected);
    assert_eq!(pipe.client.dgram_recv(&mut out), Err(quiche::Error::Done));
}
#[test]
fn runtime_sends_initial_limits() {
    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let (event_sender, _event_receiver, _event_observer) =
        test_client_event_channel();
    let mut runtime = ClientRuntime::with_backend(
        settings.clone(),
        event_sender,
        FakeJoinBackend::default(),
    );

    runtime.on_conn_established(&mut pipe.client).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    assert_eq!(
        pipe.server.multicast_recv(),
        Ok(quiche::multicast::Frame::Limits(
            quiche::multicast::Limits {
                sequence: 1,
                limits: settings.transport_params.limits,
                max_joined_count: settings.max_joined_channels,
            }
        ))
    );
}

#[test]
fn runtime_joins_ipv4_channel() {
    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let backend = FakeJoinBackend::default();
    let recorded = Arc::clone(&backend.joins);
    let (event_sender, mut event_receiver, _event_observer) =
        test_client_event_channel();
    let mut runtime =
        ClientRuntime::with_backend(settings, event_sender, backend);
    let announce = test_ipv4_announce();

    pipe.server
        .multicast_send(quiche::multicast::Frame::Announce(announce.clone()))
        .unwrap();
    pipe.server
        .multicast_send(quiche::multicast::Frame::Key(test_key(
            &announce.channel_id,
        )))
        .unwrap();
    pipe.server
        .multicast_send(quiche::multicast::Frame::Join(quiche::multicast::Join {
            channel_id: announce.channel_id.clone(),
            mc_limits_sequence: 0,
            mc_state_sequence: 0,
            mc_key_sequence: 1,
        }))
        .unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    runtime.process_reads(&mut pipe.client).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    assert_eq!(
        pipe.server.multicast_recv(),
        Ok(quiche::multicast::Frame::State(quiche::multicast::State {
            channel_id: announce.channel_id.clone(),
            sequence: 1,
            state: quiche::multicast::ChannelState::Joined,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: Vec::new(),
        }))
    );

    assert_eq!(recorded.lock().unwrap().as_slice(), &[JoinRequest {
        channel_id: announce.channel_id.clone(),
        source: Ipv4Addr::new(10, 0, 0, 1),
        group: Ipv4Addr::new(232, 1, 2, 3),
        udp_port: 4444,
        interface: None,
    }]);

    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ClientEvent::Announce(frame)) if frame == announce
    ));
    assert_next_local_state(
        &mut event_receiver,
        quiche::multicast::ChannelState::Joined,
    );
}

#[test]
fn runtime_delays_leave_until_authenticated_packet_threshold() {
    let (mut runtime, mut pipe, mut events, announce) = joined_client_runtime();
    let channel_id = announce.channel_id.clone();

    runtime
        .handle_leave(&mut pipe.client, quiche::multicast::Leave {
            channel_id: channel_id.clone(),
            mc_state_sequence: 0,
            after_packet_number: 10,
        })
        .unwrap();
    assert!(runtime.channels[&channel_id].receive_handle.is_some());
    assert_eq!(
        runtime.channels[&channel_id].pending_leave,
        Some(PendingLeave {
            state_sequence: 0,
            after_packet_number: 10,
        })
    );
    assert!(events.try_recv().is_err());

    runtime
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .largest_authenticated_packet_number = Some(9);
    runtime
        .settle_pending_transitions(&mut pipe.client, &channel_id)
        .unwrap();
    assert!(runtime.channels[&channel_id].receive_handle.is_some());
    assert!(events.try_recv().is_err());

    runtime
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .largest_authenticated_packet_number = Some(10);
    runtime
        .settle_pending_transitions(&mut pipe.client, &channel_id)
        .unwrap();
    assert!(runtime.channels[&channel_id].receive_handle.is_none());
    assert_eq!(runtime.channels[&channel_id].pending_leave, None);
    assert_next_local_state(&mut events, quiche::multicast::ChannelState::Left);
}

#[test]
fn runtime_leave_is_idempotent_and_newer_join_cancels_pending_leave() {
    let (mut runtime, mut pipe, mut events, announce) = joined_client_runtime();
    let channel_id = announce.channel_id.clone();

    for threshold in [10, 10, 12] {
        runtime
            .handle_leave(&mut pipe.client, quiche::multicast::Leave {
                channel_id: channel_id.clone(),
                mc_state_sequence: 0,
                after_packet_number: threshold,
            })
            .unwrap();
    }
    assert_eq!(
        runtime.channels[&channel_id].pending_leave,
        Some(PendingLeave {
            state_sequence: 0,
            after_packet_number: 12,
        })
    );

    runtime
        .handle_join(&mut pipe.client, quiche::multicast::Join {
            channel_id: channel_id.clone(),
            mc_limits_sequence: 0,
            mc_state_sequence: 1,
            mc_key_sequence: 1,
        })
        .unwrap();
    assert_eq!(runtime.channels[&channel_id].pending_leave, None);

    runtime
        .handle_leave(&mut pipe.client, quiche::multicast::Leave {
            channel_id: channel_id.clone(),
            mc_state_sequence: 0,
            after_packet_number: 0,
        })
        .unwrap();
    assert!(runtime.channels[&channel_id].receive_handle.is_some());
    assert!(events.try_recv().is_err());
}

#[test]
fn runtime_pending_leave_is_bounded_and_cleared_on_decline_and_teardown() {
    let (mut runtime, mut pipe, mut events, announce) = joined_client_runtime();
    let channel_id = announce.channel_id.clone();

    runtime
        .handle_leave(&mut pipe.client, quiche::multicast::Leave {
            channel_id: channel_id.clone(),
            mc_state_sequence: 0,
            after_packet_number: u64::MAX,
        })
        .unwrap();
    assert!(runtime.channels[&channel_id].pending_leave.is_some());

    runtime
        .decline_join(
            &mut pipe.client,
            channel_id.clone(),
            b"test join failure".to_vec(),
        )
        .unwrap();
    assert_eq!(runtime.channels[&channel_id].pending_leave, None);
    assert!(runtime.channels[&channel_id].receive_handle.is_none());
    assert_next_local_state(
        &mut events,
        quiche::multicast::ChannelState::DeclinedJoin,
    );

    runtime.clear();
    assert!(runtime.channels.is_empty());
}

#[test]
fn runtime_delays_retire_and_coalesces_thresholds_safely() {
    let (mut runtime, mut pipe, mut events, announce) = joined_client_runtime();
    let channel_id = announce.channel_id.clone();
    runtime
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .largest_authenticated_packet_number = Some(5);

    for threshold in [10, 10, 12] {
        runtime
            .handle_retire(&mut pipe.client, quiche::multicast::Retire {
                channel_id: channel_id.clone(),
                after_packet_number: threshold,
            })
            .unwrap();
    }
    assert_eq!(runtime.channels[&channel_id].pending_retire_after, Some(12));
    assert!(runtime.channels[&channel_id].receive_handle.is_some());
    assert!(events.try_recv().is_err());

    runtime
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .largest_authenticated_packet_number = Some(10);
    runtime
        .settle_pending_transitions(&mut pipe.client, &channel_id)
        .unwrap();
    assert!(!runtime.channels[&channel_id].retired);
    assert!(events.try_recv().is_err());

    runtime
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .largest_authenticated_packet_number = Some(12);
    runtime
        .settle_pending_transitions(&mut pipe.client, &channel_id)
        .unwrap();
    let channel = &runtime.channels[&channel_id];
    assert!(channel.retired);
    assert!(channel.receive_handle.is_none());
    assert!(channel.receive_state.is_none());
    assert!(channel.announce.is_none());
    assert!(channel.key.is_none());
    assert_next_local_state(
        &mut events,
        quiche::multicast::ChannelState::Retired,
    );

    runtime
        .handle_retire(&mut pipe.client, quiche::multicast::Retire {
            channel_id,
            after_packet_number: 0,
        })
        .unwrap();
    assert!(events.try_recv().is_err());
}

#[test]
fn runtime_retires_immediately_without_joined_data_or_after_leave() {
    let (mut runtime, mut pipe, mut events, announce) = joined_client_runtime();
    let channel_id = announce.channel_id.clone();

    runtime
        .handle_retire(&mut pipe.client, quiche::multicast::Retire {
            channel_id: channel_id.clone(),
            after_packet_number: 100,
        })
        .unwrap();
    assert!(runtime.channels[&channel_id].retired);
    assert_next_local_state(
        &mut events,
        quiche::multicast::ChannelState::Retired,
    );

    let (mut runtime, mut pipe, mut events, announce) = joined_client_runtime();
    let channel_id = announce.channel_id.clone();
    runtime
        .execute_leave(&mut pipe.client, channel_id.clone())
        .unwrap();
    assert_next_local_state(&mut events, quiche::multicast::ChannelState::Left);
    runtime
        .handle_retire(&mut pipe.client, quiche::multicast::Retire {
            channel_id: channel_id.clone(),
            after_packet_number: 100,
        })
        .unwrap();
    assert!(runtime.channels[&channel_id].retired);
    assert_next_local_state(
        &mut events,
        quiche::multicast::ChannelState::Retired,
    );
}

#[test]
fn runtime_conflicting_integrity_fails_only_the_multicast_channel() {
    let (mut runtime, mut pipe, mut events, announce) = joined_client_runtime();
    let channel_id = announce.channel_id.clone();
    let integrity = quiche::multicast::Integrity {
        channel_id: channel_id.clone(),
        packet_number_start: 0,
        packet_hash_count: Some(1),
        packet_hashes: vec![0xaa; 32],
    };

    runtime
        .handle_integrity(&mut pipe.client, integrity.clone())
        .unwrap();
    let mut conflicting = integrity;
    conflicting.packet_hashes[0] ^= 0xff;
    runtime
        .handle_integrity(&mut pipe.client, conflicting)
        .unwrap();
    for _ in 0..4 {
        if runtime.channels[&channel_id]
            .receive_state
            .as_ref()
            .is_some_and(|receiver| {
                receiver.terminal_failure().is_some() ||
                    !receiver.has_pending_work()
            })
        {
            break;
        }
        runtime
            .process_one_receiver_maintenance(&mut pipe.client)
            .unwrap();
    }

    let channel = &runtime.channels[&channel_id];
    assert!(channel.receive_handle.is_none());
    assert!(channel.key.is_none());
    assert_eq!(
        channel.receive_state.as_ref().unwrap().terminal_failure(),
        Some(quiche::multicast::ChannelReceiveFailure::ConflictingIntegrity)
    );
    assert!(!pipe.client.is_closed());

    loop {
        match events.try_recv() {
            Ok(ClientEvent::LocalState(state)) => {
                assert_eq!(state.state, quiche::multicast::ChannelState::Left);
                assert_eq!(state.reason_code, STATE_REASON_PROTOCOL_ERROR);
                break;
            },

            Ok(ClientEvent::MetricsUpdated { .. }) => continue,

            other => panic!("expected failed-channel state, got {other:?}"),
        }
    }
}

#[test]
fn runtime_receive_limit_failure_uses_limit_violated_reason() {
    let (mut runtime, mut pipe, mut events, announce) = joined_client_runtime();
    let channel_id = announce.channel_id.clone();
    let limits = quiche::multicast::ChannelReceiveLimits {
        max_pending_integrity_entries: 1,
        ..quiche::multicast::ChannelReceiveLimits::default()
    };
    runtime.channels.get_mut(&channel_id).unwrap().receive_state = Some(
        quiche::multicast::ChannelReceiveState::with_limits(announce, limits)
            .unwrap(),
    );

    runtime
        .handle_integrity(&mut pipe.client, quiche::multicast::Integrity {
            channel_id: channel_id.clone(),
            packet_number_start: 0,
            packet_hash_count: Some(2),
            packet_hashes: vec![0xaa; 64],
        })
        .unwrap();
    assert!(!pipe.client.is_closed());

    loop {
        match events.try_recv() {
            Ok(ClientEvent::LocalState(state)) => {
                assert_eq!(state.state, quiche::multicast::ChannelState::Left);
                assert_eq!(state.reason_code, STATE_REASON_LIMIT_VIOLATED);
                break;
            },

            Ok(ClientEvent::MetricsUpdated { .. }) => continue,

            other => panic!("expected failed-channel state, got {other:?}"),
        }
    }
}

#[test]
fn runtime_declines_ipv6_channel_with_placeholder_event() {
    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let backend = FakeJoinBackend::default();
    let recorded = Arc::clone(&backend.joins);
    let (event_sender, mut event_receiver, _event_observer) =
        test_client_event_channel();
    let mut runtime =
        ClientRuntime::with_backend(settings, event_sender, backend);
    let announce = test_ipv6_announce();

    pipe.server
        .multicast_send(quiche::multicast::Frame::Announce(announce.clone()))
        .unwrap();
    pipe.server
        .multicast_send(quiche::multicast::Frame::Key(test_key(
            &announce.channel_id,
        )))
        .unwrap();
    pipe.server
        .multicast_send(quiche::multicast::Frame::Join(quiche::multicast::Join {
            channel_id: announce.channel_id.clone(),
            mc_limits_sequence: 0,
            mc_state_sequence: 0,
            mc_key_sequence: 1,
        }))
        .unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    runtime.process_reads(&mut pipe.client).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    assert_eq!(
        pipe.server.multicast_recv(),
        Ok(quiche::multicast::Frame::State(quiche::multicast::State {
            channel_id: announce.channel_id.clone(),
            sequence: 1,
            state: quiche::multicast::ChannelState::DeclinedJoin,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: STATE_REASON_UNSPECIFIED_OTHER,
            reason_phrase: b"ipv6 multicast not yet supported".to_vec(),
        }))
    );

    assert!(recorded.lock().unwrap().is_empty());
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ClientEvent::UnsupportedIpv6Announce(frame)) if frame == announce
    ));
    assert_next_local_state(
        &mut event_receiver,
        quiche::multicast::ChannelState::DeclinedJoin,
    );
}

#[test]
fn runtime_declines_join_for_missing_key_sequence() {
    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let backend = FakeJoinBackend::default();
    let recorded = Arc::clone(&backend.joins);
    let (event_sender, mut event_receiver, _event_observer) =
        test_client_event_channel();
    let mut runtime =
        ClientRuntime::with_backend(settings, event_sender, backend);
    let announce = test_ipv4_announce();

    pipe.server
        .multicast_send(quiche::multicast::Frame::Announce(announce.clone()))
        .unwrap();
    pipe.server
        .multicast_send(quiche::multicast::Frame::Key(test_key(
            &announce.channel_id,
        )))
        .unwrap();
    pipe.server
        .multicast_send(quiche::multicast::Frame::Join(quiche::multicast::Join {
            channel_id: announce.channel_id.clone(),
            mc_limits_sequence: 0,
            mc_state_sequence: 0,
            mc_key_sequence: 2,
        }))
        .unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    runtime.process_reads(&mut pipe.client).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    assert_eq!(
        pipe.server.multicast_recv(),
        Ok(quiche::multicast::Frame::State(quiche::multicast::State {
            channel_id: announce.channel_id.clone(),
            sequence: 1,
            state: quiche::multicast::ChannelState::DeclinedJoin,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: STATE_REASON_UNSYNCHRONIZED_PROPERTIES,
            reason_phrase: b"unsynchronized multicast properties".to_vec(),
        }))
    );

    assert!(recorded.lock().unwrap().is_empty());
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ClientEvent::Announce(frame)) if frame == announce
    ));
    assert_next_local_state(
        &mut event_receiver,
        quiche::multicast::ChannelState::DeclinedJoin,
    );
}
#[test]
fn channel_ack_state_encodes_non_contiguous_ranges() {
    let mut ack_state = quiche::multicast::AckTracker::default();

    for packet_number in [0, 2, 3, 6] {
        ack_state.record_packet(packet_number);
    }

    let ack = ack_state.pending_ack(&[1, 2, 3, 4]).unwrap();

    assert_eq!(ack.channel_id, vec![1, 2, 3, 4]);
    assert_eq!(ack.largest_acknowledged, 6);
    assert_eq!(ack.ack_delay, 0);
    assert_eq!(ack.first_ack_range, 0);
    assert_eq!(ack.ack_ranges, vec![
        quiche::multicast::AckRange {
            gap: 1,
            ack_range_length: 1,
        },
        quiche::multicast::AckRange {
            gap: 0,
            ack_range_length: 0,
        },
    ]);
    assert_eq!(ack.ecn_counts, None);

    ack_state.mark_sent();
    assert_eq!(ack_state.pending_ack(&[1, 2, 3, 4]), None);
}

#[test]
fn runtime_flushes_pending_mc_ack() {
    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let backend = FakeJoinBackend::default();
    let (event_sender, _event_receiver, _event_observer) =
        test_client_event_channel();
    let mut runtime =
        ClientRuntime::with_backend(settings, event_sender, backend);
    let announce = test_ipv4_announce();

    runtime
        .channels
        .entry(announce.channel_id.clone())
        .or_default()
        .ack_state
        .record_packet(7);
    assert!(runtime.flush_one_pending_ack(&mut pipe.client).unwrap());

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    assert_eq!(
        pipe.server.multicast_recv(),
        Ok(quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: announce.channel_id.clone(),
            largest_acknowledged: 7,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }))
    );
}
