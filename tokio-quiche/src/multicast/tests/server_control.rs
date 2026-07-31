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
fn server_control_retries_atomic_announce_key_after_prolonged_full_queue() {
    let settings = test_settings();
    let mut pipe = test_pipe_with_server_control_queue(&settings, 1, 4096);
    let (_command_sender, command_receiver, command_observer) =
        test_server_control_command_channel();
    let (event_sender, _event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::with_limits(
        test_server_control_settings(),
        event_sender,
        command_receiver,
        RuntimeLimits::default(),
    );

    runtime.on_conn_established(&mut pipe.server).unwrap();
    assert_eq!(pipe.server.multicast_send_queue_len(), 1);
    assert_eq!(runtime.pending_commands.len(), 1);
    assert!(!runtime.channels[&[1, 2, 3, 4][..]].announce_sent);

    for _ in 0..32 {
        runtime.process_reads(&mut pipe.server).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        assert_eq!(pipe.server.multicast_send_queue_len(), 1);
        assert_eq!(runtime.pending_commands.len(), 1);
        assert_eq!(command_observer.stats().retained_items, 1);
        assert!(!runtime.channels[&[1, 2, 3, 4][..]].announce_sent);
    }

    pipe.advance().unwrap();
    runtime.process_reads(&mut pipe.server).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    assert!(runtime.pending_commands.is_empty());
    assert_eq!(command_observer.stats().retained_items, 0);
    assert!(runtime.channels[&[1, 2, 3, 4][..]].announce_sent);

    pipe.advance().unwrap();
    assert!(matches!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Announce(_))
    ));
    assert!(matches!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Key(_))
    ));
    assert_eq!(pipe.client.multicast_recv(), Err(quiche::Error::Done));
}

#[tokio::test(start_paused = true)]
async fn server_control_blocked_publisher_waits_for_retry_deadline() {
    let settings = test_settings();
    let mut pipe = test_pipe_with_server_control_queue(&settings, 1, 4096);
    let limits = RuntimeLimits {
        max_work_per_call: 16,
        control_retry_delay: Duration::from_millis(100),
        ..RuntimeLimits::default()
    };
    let control_settings = ServerControlSettings {
        mode: ServerControlMode::Manual,
        channels: Vec::new(),
        stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
    };
    let (driver, controller) = ServerControlDriver::new_with_runtime_limits(
        (),
        control_settings,
        limits,
    )
    .unwrap();
    let mut runtime = driver.runtime;
    runtime.on_conn_established(&mut pipe.server).unwrap();

    let blocked_channel_id = vec![1, 2, 3, 4];
    let healthy_channel_id = vec![5, 6, 7, 8];
    let blocked_publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    let mut healthy_config = test_stream_control_config();
    healthy_config.announce.channel_id = healthy_channel_id.clone();
    healthy_config.key.channel_id = healthy_channel_id.clone();
    let healthy_publisher = ServerStreamPublisher::new(healthy_config).unwrap();
    let _blocked_attachment = blocked_publisher.attach(&controller).unwrap();
    let _healthy_attachment = healthy_publisher.attach(&controller).unwrap();

    for _ in 0..8 {
        runtime.process_writes(&mut pipe.server).unwrap();
        if runtime.pending_commands.is_empty() &&
            runtime.command_receiver.try_recv().is_err()
        {
            break;
        }
    }
    assert!(runtime.channels[&blocked_channel_id].stream_publisher);
    assert!(runtime.channels[&healthy_channel_id].stream_publisher);

    let mut filler = test_ipv4_announce();
    filler.channel_id = vec![9];
    pipe.server
        .multicast_send(quiche::multicast::Frame::Announce(filler))
        .unwrap();
    assert_eq!(pipe.server.multicast_send_queue_len(), 1);
    controller.send_key(test_key(&blocked_channel_id)).unwrap();

    for _ in 0..8 {
        runtime.process_writes(&mut pipe.server).unwrap();
        if runtime
            .blocked_command_channels
            .contains(&blocked_channel_id)
        {
            break;
        }
    }
    assert!(runtime
        .blocked_command_channels
        .contains(&blocked_channel_id));
    let retry_deadline = runtime.control_retry_deadline.unwrap();
    assert!(retry_deadline > Instant::now());

    blocked_publisher.declare_stream(3).unwrap();
    healthy_publisher.declare_stream(7).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let blocked_queue = runtime.channels[&blocked_channel_id]
        .stream_publication_queue
        .as_ref()
        .unwrap();
    let healthy_queue = runtime.channels[&healthy_channel_id]
        .stream_publication_queue
        .as_ref()
        .unwrap();
    assert!(blocked_queue.has_pending());
    assert!(!healthy_queue.has_pending());
    assert_eq!(runtime.channels[&healthy_channel_id].max_stream_id, Some(7));
    assert_eq!(runtime.channels[&blocked_channel_id].max_stream_id, None);
    assert!(runtime.command_receiver.try_recv().is_err());
    assert!(!runtime.has_pending_work());
    assert_eq!(runtime.next_runtime_deadline(), Some(retry_deadline));

    pipe.advance().unwrap();
    assert_eq!(pipe.server.multicast_send_queue_len(), 0);
    assert!(tokio::time::timeout(
        Duration::from_millis(99),
        runtime.wait_for_work()
    )
    .await
    .is_err());
    assert!(tokio::time::timeout(
        Duration::from_millis(2),
        runtime.wait_for_work()
    )
    .await
    .is_ok());
    assert!(runtime.has_pending_work());

    for _ in 0..8 {
        runtime.process_writes(&mut pipe.server).unwrap();
        if !runtime.channels[&blocked_channel_id]
            .stream_publication_queue
            .as_ref()
            .unwrap()
            .has_pending() &&
            runtime.pending_commands.is_empty()
        {
            break;
        }
    }
    assert!(!runtime
        .blocked_command_channels
        .contains(&blocked_channel_id));
    assert!(!runtime.channels[&blocked_channel_id]
        .stream_publication_queue
        .as_ref()
        .unwrap()
        .has_pending());
    assert_eq!(runtime.channels[&blocked_channel_id].max_stream_id, Some(3));
    assert_eq!(runtime.channels[&healthy_channel_id].max_stream_id, Some(7));
}

#[test]
fn server_control_deferred_barrier_remains_runnable_with_one_work_item() {
    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, _event_receiver, _event_observer) =
        test_server_event_channel();
    let limits = RuntimeLimits {
        max_work_per_call: 1,
        ..RuntimeLimits::default()
    };
    let mut runtime = ServerControlRuntime::with_limits(
        test_server_control_settings(),
        event_sender,
        command_receiver,
        limits,
    );

    runtime.on_conn_established(&mut pipe.server).unwrap();
    assert_eq!(runtime.pending_commands.len(), 1);
    assert!(runtime.pending_commands[0].deferred_barrier);
    assert!(runtime.has_pending_work());
    assert!(!runtime.channels[&[1, 2, 3, 4][..]].announce_sent);

    runtime.process_writes(&mut pipe.server).unwrap();
    assert!(runtime.pending_commands.is_empty());
    assert!(runtime.channels[&[1, 2, 3, 4][..]].announce_sent);

    pipe.advance().unwrap();
    assert!(matches!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Announce(_))
    ));
    assert!(matches!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Key(_))
    ));
}

#[test]
fn server_control_retries_integrity_without_loss_or_duplication() {
    let (mut runtime, _command_sender, _command_observer, _events, mut pipe) =
        test_manual_control_runtime_with_small_core_queue();
    let announce = quiche::multicast::Frame::Announce(test_ipv4_announce());
    pipe.server.multicast_try_send(announce.clone()).unwrap();
    let integrity = test_stream_integrity(9, 0xdd);
    runtime.queue_integrity(integrity.clone()).unwrap();
    let integrity_observer = runtime.pending_integrities.observer();

    for _ in 0..16 {
        runtime.process_reads(&mut pipe.server).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();
        assert_eq!(integrity_observer.stats().retained_items, 1);
        assert_eq!(pipe.server.multicast_send_queue_len(), 1);
    }

    pipe.advance().unwrap();
    runtime.process_reads(&mut pipe.server).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    assert!(runtime.pending_integrities.is_empty());
    assert_eq!(integrity_observer.stats().retained_items, 0);

    pipe.advance().unwrap();
    assert_eq!(pipe.client.multicast_recv(), Ok(announce));
    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Integrity(integrity))
    );
    assert_eq!(pipe.client.multicast_recv(), Err(quiche::Error::Done));
}

#[test]
fn server_control_commits_leave_only_after_queue_admission() {
    let (mut runtime, _command_sender, command_observer, _events, mut pipe) =
        test_manual_control_runtime_with_small_core_queue();
    let channel_id = vec![1, 2, 3, 4];
    let announce = quiche::multicast::Frame::Announce(test_ipv4_announce());
    pipe.server.multicast_try_send(announce.clone()).unwrap();
    {
        let channel = runtime.channels.get_mut(&channel_id).unwrap();
        channel.join_sent = true;
        channel.last_client_state_sequence = 7;
    }

    runtime
        .leave_channel(&mut pipe.server, &channel_id, 11)
        .unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    assert!(runtime.channels[&channel_id].join_sent);
    assert!(runtime.channels[&channel_id].leave_pending);
    assert_eq!(runtime.pending_commands.len(), 1);
    assert_eq!(command_observer.stats().retained_items, 1);

    pipe.advance().unwrap();
    runtime.process_reads(&mut pipe.server).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    assert!(!runtime.channels[&channel_id].join_sent);
    assert!(!runtime.channels[&channel_id].leave_pending);
    assert!(runtime.pending_commands.is_empty());
    assert_eq!(command_observer.stats().retained_items, 0);

    pipe.advance().unwrap();
    assert_eq!(pipe.client.multicast_recv(), Ok(announce));
    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Leave(quiche::multicast::Leave {
            channel_id,
            mc_state_sequence: 7,
            after_packet_number: 11,
        }))
    );
}

#[test]
fn server_control_commits_retire_only_after_queue_admission() {
    let (mut runtime, _command_sender, command_observer, _events, mut pipe) =
        test_manual_control_runtime_with_small_core_queue();
    let channel_id = vec![1, 2, 3, 4];
    let announce = quiche::multicast::Frame::Announce(test_ipv4_announce());
    pipe.server.multicast_try_send(announce.clone()).unwrap();
    let retire = quiche::multicast::Retire {
        channel_id: channel_id.clone(),
        after_packet_number: 0,
    };
    runtime
        .queue_command_back(ServerControlCommand::StreamPublisherRetire {
            frame: retire.clone(),
        })
        .unwrap();
    runtime
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .retirement_pending = true;

    runtime.process_writes(&mut pipe.server).unwrap();
    assert!(!runtime.channels[&channel_id].retired);
    assert!(runtime.channels[&channel_id].retirement_pending);
    assert_eq!(runtime.pending_commands.len(), 1);
    assert_eq!(command_observer.stats().retained_items, 1);

    pipe.advance().unwrap();
    runtime.process_reads(&mut pipe.server).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    assert!(runtime.channels[&channel_id].retired);
    assert!(!runtime.channels[&channel_id].retirement_pending);
    assert!(runtime.pending_commands.is_empty());
    assert_eq!(command_observer.stats().retained_items, 0);

    pipe.advance().unwrap();
    assert_eq!(pipe.client.multicast_recv(), Ok(announce));
    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Retire(retire))
    );
}

#[test]
fn server_control_teardown_releases_blocked_secret_command() {
    let (mut runtime, command_sender, command_observer, _events, mut pipe) =
        test_manual_control_runtime_with_small_core_queue();
    pipe.server
        .multicast_try_send(quiche::multicast::Frame::Announce(
            test_ipv4_announce(),
        ))
        .unwrap();
    let mut key = test_key(&[1, 2, 3, 4]);
    key.key_sequence = 2;
    command_sender
        .try_send(ServerControlCommand::SendKey {
            frame: key,
            cached: None,
        })
        .unwrap();

    runtime.process_writes(&mut pipe.server).unwrap();
    assert_eq!(runtime.pending_commands.len(), 1);
    assert_eq!(command_observer.stats().retained_items, 1);

    runtime.clear();
    assert!(runtime.pending_commands.is_empty());
    assert!(runtime.channels.is_empty());
    assert_eq!(command_observer.stats().retained_items, 0);
}

#[test]
fn server_control_announce_waits_for_allowed_address_family() {
    let mut settings = test_settings();
    settings.transport_params.limits.ipv4_channels_allowed = false;
    let mut pipe = test_pipe(&settings);
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, _event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::new(
        test_server_control_settings(),
        event_sender,
        command_receiver,
    );
    runtime.on_conn_established(&mut pipe.server).unwrap();

    assert_eq!(pipe.server.multicast_send_queue_len(), 0);
    assert!(!runtime.channels[&[1, 2, 3, 4][..]].announce_sent);

    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(test_limits()),
    );
    deliver_server_flight(&mut pipe);

    assert!(matches!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Announce(_))
    ));
    assert!(matches!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Key(_))
    ));
    assert!(matches!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Join(_))
    ));
}

#[test]
fn server_control_reduced_limits_leave_joined_channel() {
    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, _event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::new(
        test_server_control_settings(),
        event_sender,
        command_receiver,
    );
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(test_limits()),
    );
    deliver_server_flight(&mut pipe);
    while pipe.client.multicast_recv().is_ok() {}

    let mut reduced = test_limits();
    reduced.sequence = 2;
    reduced.max_joined_count = 0;
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(reduced),
    );
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);

    assert!(matches!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Leave(quiche::multicast::Leave {
            channel_id,
            ..
        })) if channel_id == vec![1, 2, 3, 4]
    ));
    assert!(!runtime.channels[&[1, 2, 3, 4][..]].join_sent);
    assert_eq!(
        pipe.server.multicast_probe_status(&[1, 2, 3, 4]),
        Some(quiche::multicast::ProbeStatus::Left)
    );
}

#[test]
fn server_control_limit_retirement_drains_stream_barriers_first() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let channel_id = vec![5, 6, 7, 8];
    let mut second_config = test_stream_control_config();
    second_config.announce.channel_id = channel_id.clone();
    second_config.key.channel_id = channel_id.clone();
    let server_settings = ServerControlSettings {
        mode: ServerControlMode::Automatic,
        channels: vec![test_stream_control_config(), second_config.clone()],
        stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
    };
    let (command_sender, command_receiver, command_observer) =
        test_server_control_command_channel();
    let (event_sender, event_receiver, event_observer) =
        test_server_event_channel();
    let controller = ServerControlController {
        command_sender,
        command_observer,
        pending_publication_observer: test_retained_queue_observer(),
        pending_integrity_observer: test_retained_queue_observer(),
        event_receiver: Some(event_receiver),
        event_observer,
    };
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
    );
    runtime.on_conn_established(&mut pipe.server).unwrap();

    let publisher = ServerStreamPublisher::new(second_config).unwrap();
    publisher.declare_stream(3).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(test_limits()),
    );
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);
    while pipe.client.multicast_recv().is_ok() {}
    send_webtransport_stream_prefix(&mut pipe, 3, 11);

    let first = publisher.prepare_stream(3, 10, false, b"a").unwrap();
    publisher.commit(first).unwrap();
    let second = publisher.prepare_stream(3, 11, true, b"b").unwrap();
    publisher.commit(second).unwrap();

    let mut reduced = test_limits();
    reduced.sequence = 2;
    reduced.limits.max_channel_ids = 1;
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(reduced),
    );
    if !runtime.channels[&channel_id].retired {
        assert!(runtime.channels[&channel_id].retirement_pending);
        runtime.process_writes(&mut pipe.server).unwrap();
    }
    assert!(runtime.channels[&channel_id].retired);
    deliver_server_flight(&mut pipe);

    let mut out = [0; 8];
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((2, true)));
    assert_eq!(&out[..2], b"ab");
    for packet_number_start in 0..=1 {
        assert!(matches!(
            pipe.client.multicast_recv(),
            Ok(quiche::multicast::Frame::Integrity(
                quiche::multicast::Integrity {
                    channel_id: ref integrity_channel,
                    packet_number_start: actual,
                    packet_hash_count: Some(1),
                    ..
                }
            )) if integrity_channel == &channel_id &&
                actual == packet_number_start
        ));
    }
    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Retire(
            quiche::multicast::Retire {
                channel_id,
                after_packet_number: 1,
            }
        ))
    );
}

#[test]
fn server_control_reduced_channel_id_limit_retires_excess_state() {
    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let mut second_announce = test_ipv4_announce();
    second_announce.channel_id = vec![5, 6, 7, 8];
    let server_settings = ServerControlSettings {
        mode: ServerControlMode::Automatic,
        channels: vec![
            test_stream_control_config(),
            ServerControlChannelConfig {
                announce: second_announce,
                key: test_key(&[5, 6, 7, 8]),
            },
        ],
        stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
    };
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, _event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
    );
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(test_limits()),
    );
    deliver_server_flight(&mut pipe);
    while pipe.client.multicast_recv().is_ok() {}

    let mut reduced = test_limits();
    reduced.sequence = 2;
    reduced.limits.max_channel_ids = 1;
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(reduced),
    );
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);

    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Retire(
            quiche::multicast::Retire {
                channel_id: vec![5, 6, 7, 8],
                after_packet_number: 0,
            }
        ))
    );
    assert!(runtime.channels[&[5, 6, 7, 8][..]].retired);
    assert_eq!(
        pipe.server.multicast_probe_status(&[5, 6, 7, 8]),
        Some(quiche::multicast::ProbeStatus::Retired)
    );
}
#[test]
fn server_control_runtime_announces_and_joins_after_limits() {
    let settings = test_settings();
    let server_settings = test_server_control_settings();
    let mut pipe = test_pipe(&settings);
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
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
fn server_control_runtime_installs_default_dgram_fallback_channel() {
    let settings = test_settings();
    let server_settings = test_server_control_settings();
    let channel_id = server_settings.channels[0].announce.channel_id.clone();
    let mut pipe = test_pipe(&settings);
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, _event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
    );

    runtime.on_conn_established(&mut pipe.server).unwrap();

    assert_eq!(
        pipe.server.multicast_default_dgram_channel(),
        Some(channel_id.as_slice())
    );

    pipe.server.dgram_send(b"default-fallback").unwrap();
    assert_client_receives_dgram(&mut pipe, b"default-fallback");

    pipe.server
        .multicast_process_peer_ack(quiche::multicast::Ack {
            channel_id,
            largest_acknowledged: 1,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        })
        .unwrap();
    pipe.server.dgram_send(b"do-not-duplicate").unwrap();
    assert_eq!(pipe.server.dgram_send_queue_len(), 0);
}

#[test]
fn server_control_runtime_ack_timeout_reenters_dgram_fallback() {
    let settings = test_settings();
    let mut server_settings = test_server_control_settings();
    server_settings.channels[0].announce.max_ack_delay_ms = 0;
    let channel_id = server_settings.channels[0].announce.channel_id.clone();
    let mut pipe = test_pipe(&settings);
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
    );

    runtime.on_conn_established(&mut pipe.server).unwrap();

    pipe.client
        .multicast_send(quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 1,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }))
        .unwrap();
    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
    runtime.process_reads(&mut pipe.server).unwrap();

    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientAck(frame)) if frame.channel_id == channel_id
    ));
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ProbeStatusChanged(quiche::multicast::ProbeEvent {
            channel_id: event_channel,
            status: quiche::multicast::ProbeStatus::Viable,
            ..
        })) if event_channel == channel_id
    ));

    assert_eq!(
        pipe.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::Viable)
    );

    pipe.server.on_timeout();
    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(
        pipe.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::TimedOut)
    );
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ProbeStatusChanged(quiche::multicast::ProbeEvent {
            channel_id: event_channel,
            status: quiche::multicast::ProbeStatus::TimedOut,
            ..
        })) if event_channel == channel_id
    ));

    pipe.server.dgram_send(b"fallback-after-stall").unwrap();
    assert_client_receives_dgram(&mut pipe, b"fallback-after-stall");
}

#[test]
fn server_control_runtime_join_without_first_ack_times_out() {
    let settings = test_settings();
    let mut server_settings = test_server_control_settings();
    server_settings.channels[0].announce.max_ack_delay_ms = 0;
    let channel_id = server_settings.channels[0].announce.channel_id.clone();
    let mut pipe = test_pipe(&settings);
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
    );

    runtime.on_conn_established(&mut pipe.server).unwrap();
    pipe.client
        .multicast_send(quiche::multicast::Frame::State(
            quiche::multicast::State {
                channel_id: channel_id.clone(),
                sequence: 1,
                state: quiche::multicast::ChannelState::Joined,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                reason_phrase: Vec::new(),
            },
        ))
        .unwrap();
    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
    runtime.process_reads(&mut pipe.server).unwrap();

    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientState(frame)) if frame.channel_id == channel_id
    ));
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ProbeStatusChanged(quiche::multicast::ProbeEvent {
            channel_id: event_channel,
            status: quiche::multicast::ProbeStatus::Probing,
            ..
        })) if event_channel == channel_id
    ));
    pipe.server.on_timeout();
    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(
        pipe.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::TimedOut)
    );
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ProbeStatusChanged(quiche::multicast::ProbeEvent {
            channel_id: event_channel,
            status: quiche::multicast::ProbeStatus::TimedOut,
            ..
        })) if event_channel == channel_id
    ));
}
#[test]
fn server_control_runtime_relays_external_integrity() {
    let settings = test_settings();
    let server_settings = test_server_control_settings();
    let mut pipe = test_pipe(&settings);
    let (command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, _event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
    );
    let integrity = quiche::multicast::Integrity {
        channel_id: vec![1, 2, 3, 4],
        packet_number_start: 11,
        packet_hash_count: Some(1),
        packet_hashes: vec![0xaa; 32],
    };

    runtime.on_conn_established(&mut pipe.server).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    let _ = pipe.client.multicast_recv().unwrap();
    let _ = pipe.client.multicast_recv().unwrap();

    command_sender
        .try_send(ServerControlCommand::RelayIntegrity {
            frame: integrity.clone(),
        })
        .unwrap();

    runtime.process_writes(&mut pipe.server).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Integrity(integrity))
    );
}

#[test]
fn server_control_runtime_upserts_channel_after_limits() {
    let settings = test_settings();
    let server_settings = ServerControlSettings {
        mode: ServerControlMode::Automatic,
        channels: Vec::new(),
        stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
    };
    let mut pipe = test_pipe(&settings);
    let (command_sender, command_receiver, command_observer) =
        test_server_control_command_channel();
    let (event_sender, mut event_receiver, event_observer) =
        test_server_event_channel();
    let mut controller = ServerControlController {
        command_sender,
        command_observer,
        pending_publication_observer: test_retained_queue_observer(),
        pending_integrity_observer: test_retained_queue_observer(),
        event_receiver: None,
        event_observer,
    };
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
    );
    let config = ServerControlChannelConfig {
        announce: test_ipv4_announce(),
        key: test_key(&[1, 2, 3, 4]),
    };

    runtime.on_conn_established(&mut pipe.server).unwrap();

    pipe.client
        .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
        .unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    runtime.process_reads(&mut pipe.server).unwrap();
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientLimits(frame))
            if frame.sequence == 1 &&
                frame.limits == test_transport_params().limits
    ));

    controller.upsert_channel(config).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(
        pipe.server.multicast_default_dgram_channel(),
        Some(&[1, 2, 3, 4][..])
    );

    pipe.server.dgram_send(b"upsert-fallback").unwrap();
    assert_client_receives_dgram(&mut pipe, b"upsert-fallback");

    let announce = match pipe.client.multicast_recv() {
        Ok(quiche::multicast::Frame::Announce(frame)) => frame,
        other => panic!("expected announce, got {other:?}"),
    };
    let key = match pipe.client.multicast_recv() {
        Ok(quiche::multicast::Frame::Key(frame)) => frame,
        other => panic!("expected key, got {other:?}"),
    };
    let join = match pipe.client.multicast_recv() {
        Ok(quiche::multicast::Frame::Join(frame)) => frame,
        other => panic!("expected join, got {other:?}"),
    };

    assert_eq!(announce, test_ipv4_announce());
    assert_eq!(key, test_key(&[1, 2, 3, 4]));
    assert_eq!(join, quiche::multicast::Join {
        channel_id: vec![1, 2, 3, 4],
        mc_limits_sequence: 1,
        mc_state_sequence: 0,
        mc_key_sequence: 1,
    });

    let _ = controller.take_event_receiver();
}

#[test]
fn server_control_runtime_manual_mode_allows_explicit_sequencing() {
    let settings = test_settings();
    let server_settings = ServerControlSettings {
        mode: ServerControlMode::Manual,
        channels: Vec::new(),
        stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
    };
    let mut pipe = test_pipe(&settings);
    let (command_sender, command_receiver, command_observer) =
        test_server_control_command_channel();
    let (event_sender, mut event_receiver, event_observer) =
        test_server_event_channel();
    let controller = ServerControlController {
        command_sender,
        command_observer,
        pending_publication_observer: test_retained_queue_observer(),
        pending_integrity_observer: test_retained_queue_observer(),
        event_receiver: None,
        event_observer,
    };
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
    );
    let announce = test_ipv4_announce();
    let key = test_key(&announce.channel_id);
    let join = quiche::multicast::Join {
        channel_id: announce.channel_id.clone(),
        mc_limits_sequence: 1,
        mc_state_sequence: 0,
        mc_key_sequence: key.key_sequence,
    };

    runtime.on_conn_established(&mut pipe.server).unwrap();
    if let Ok(flight) = quiche::test_utils::emit_flight(&mut pipe.server) {
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();
    }
    assert_eq!(pipe.client.multicast_recv(), Err(quiche::Error::Done));

    pipe.client
        .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
        .unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    runtime.process_reads(&mut pipe.server).unwrap();
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientLimits(frame))
            if frame.sequence == 1 &&
                frame.limits == test_transport_params().limits
    ));
    if let Ok(flight) = quiche::test_utils::emit_flight(&mut pipe.server) {
        quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();
    }
    assert_eq!(pipe.client.multicast_recv(), Err(quiche::Error::Done));

    controller.send_announce(announce.clone()).unwrap();
    controller.send_key(key.clone()).unwrap();
    controller.send_join(join.clone()).unwrap();

    runtime.process_writes(&mut pipe.server).unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Announce(announce))
    );
    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Key(key))
    );
    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Join(join))
    );
}

#[test]
fn server_control_runtime_emits_client_state_and_ack() {
    let settings = test_settings();
    let server_settings = test_server_control_settings();
    let mut pipe = test_pipe(&settings);
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
    );
    let state = quiche::multicast::State {
        channel_id: vec![1, 2, 3, 4],
        sequence: 1,
        state: quiche::multicast::ChannelState::Joined,
        reason_scope: quiche::multicast::StateReasonScope::Transport,
        reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
        reason_phrase: Vec::new(),
    };
    let ack = quiche::multicast::Ack {
        channel_id: vec![1, 2, 3, 4],
        largest_acknowledged: 3,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: Vec::new(),
        ecn_counts: None,
    };

    runtime.on_conn_established(&mut pipe.server).unwrap();

    pipe.client
        .multicast_send(quiche::multicast::Frame::State(state.clone()))
        .unwrap();
    pipe.client
        .multicast_send(quiche::multicast::Frame::Ack(ack.clone()))
        .unwrap();

    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    runtime.process_reads(&mut pipe.server).unwrap();

    let mut saw_state = false;
    let mut saw_ack = false;
    for _ in 0..8 {
        match event_receiver.try_recv() {
            Ok(ServerEvent::ClientState(frame)) if frame == state => {
                assert!(!saw_ack);
                saw_state = true;
            },

            Ok(ServerEvent::ClientAck(frame)) if frame == ack => {
                assert!(saw_state);
                saw_ack = true;
            },

            Ok(ServerEvent::ProbeStatusChanged(..)) => (),
            Ok(other) => panic!("unexpected server event: {other:?}"),
            Err(_) => break,
        }
    }
    assert!(saw_state);
    assert!(saw_ack);
    assert_eq!(
        pipe.server.multicast_probe_status(&[1, 2, 3, 4]),
        Some(quiche::multicast::ProbeStatus::Viable)
    );
}

#[test]
fn server_control_runtime_does_not_probe_unknown_ack() {
    let settings = test_settings();
    let server_settings = ServerControlSettings {
        mode: ServerControlMode::Manual,
        channels: Vec::new(),
        stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
    };
    let mut pipe = test_pipe(&settings);
    let (_command_sender, command_receiver, _command_observer) =
        test_server_control_command_channel();
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::new(
        server_settings,
        event_sender,
        command_receiver,
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
