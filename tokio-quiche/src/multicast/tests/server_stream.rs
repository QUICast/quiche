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

fn test_stream_control_config() -> ServerControlChannelConfig {
    ServerControlChannelConfig {
        announce: test_ipv4_announce(),
        key: test_key(&[1, 2, 3, 4]),
    }
}

fn test_stream_control_runtime() -> (ServerControlRuntime, ServerControlController)
{
    test_stream_control_runtime_with_integrity_batching(
        StreamIntegrityBatchingSettings::default(),
    )
}

fn test_stream_control_runtime_with_integrity_batching(
    stream_integrity_batching: StreamIntegrityBatchingSettings,
) -> (ServerControlRuntime, ServerControlController) {
    let (command_sender, command_receiver, command_observer) =
        test_server_control_command_channel();
    let (event_sender, event_receiver, event_observer) =
        test_server_event_channel();

    (
        ServerControlRuntime::new(
            ServerControlSettings {
                mode: ServerControlMode::Automatic,
                channels: Vec::new(),
                stream_integrity_batching,
            },
            event_sender,
            command_receiver,
        ),
        ServerControlController {
            command_sender,
            command_observer,
            pending_publication_observer: test_retained_queue_observer(),
            pending_integrity_observer: test_retained_queue_observer(),
            event_receiver: Some(event_receiver),
            event_observer,
        },
    )
}

fn test_manual_control_runtime_with_small_core_queue() -> (
    ServerControlRuntime,
    BoundedSender<ServerControlCommand>,
    RetainedQueueObserver,
    ServerEventStream,
    Pipe,
) {
    let settings = test_settings();
    let pipe = test_pipe_with_server_control_queue(&settings, 1, 4096);
    let (command_sender, command_receiver, command_observer) =
        test_server_control_command_channel();
    let (event_sender, event_receiver, _event_observer) =
        test_server_event_channel();
    let mut control_settings = test_server_control_settings();
    control_settings.mode = ServerControlMode::Manual;
    let mut runtime = ServerControlRuntime::new(
        control_settings,
        event_sender,
        command_receiver,
    );
    let mut pipe = pipe;
    runtime.on_conn_established(&mut pipe.server).unwrap();

    (
        runtime,
        command_sender,
        command_observer,
        event_receiver,
        pipe,
    )
}

fn test_stream_integrity(
    packet_number: u64, hash_byte: u8,
) -> quiche::multicast::Integrity {
    quiche::multicast::Integrity {
        channel_id: vec![1, 2, 3, 4],
        packet_number_start: packet_number,
        packet_hash_count: Some(1),
        packet_hashes: vec![hash_byte; 32],
    }
}

fn send_webtransport_stream_prefix(
    pipe: &mut Pipe, stream_id: u64, session_id: u64,
) {
    let mut prefix = [0; 10];
    prefix[..2].copy_from_slice(&[0x40, 0x54]);
    prefix[2..].copy_from_slice(&session_id.to_be_bytes());

    assert_eq!(
        pipe.server.stream_send(stream_id, &prefix, false),
        Ok(prefix.len())
    );
    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    let mut out = [0; 16];
    assert_eq!(
        pipe.client.stream_recv(stream_id, &mut out),
        Ok((prefix.len(), false))
    );
    assert_eq!(&out[..prefix.len()], &prefix);
}

fn deliver_server_flight(pipe: &mut Pipe) {
    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();
}

fn send_client_control(
    pipe: &mut Pipe, runtime: &mut ServerControlRuntime,
    frame: quiche::multicast::Frame,
) {
    pipe.client.multicast_send(frame).unwrap();
    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();
    runtime.process_reads(&mut pipe.server).unwrap();
}

struct StreamProfileConnection {
    pipe: Pipe,
    runtime: ServerControlRuntime,
    controller: ServerControlController,
    _attachment: ServerStreamAttachment,
}

#[derive(Default)]
struct StreamProfileWakeCounter {
    wakes: AtomicU64,
}

impl Wake for StreamProfileWakeCounter {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }
}

fn setup_stream_profile_connections(
    settings: &ClientSettings, publisher: &ServerStreamPublisher,
    channel_id: &[u8], stream_id: u64, client_count: usize,
    batching: StreamIntegrityBatchingSettings,
) -> Vec<StreamProfileConnection> {
    let mut connections = Vec::with_capacity(client_count);

    for client_id in 0..client_count {
        let mut pipe =
            test_stream_pipe_with_flow_control(settings, 3, 512 * 1024);
        let (mut runtime, controller) =
            test_stream_control_runtime_with_integrity_batching(batching);
        runtime.on_conn_established(&mut pipe.server).unwrap();
        send_webtransport_stream_prefix(&mut pipe, stream_id, client_id as u64);
        let attachment = publisher.attach(&controller).unwrap();
        runtime.process_writes(&mut pipe.server).unwrap();

        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::Limits(test_limits()),
        );
        send_client_control(
            &mut pipe,
            &mut runtime,
            quiche::multicast::Frame::State(quiche::multicast::State {
                channel_id: channel_id.to_vec(),
                sequence: 1,
                state: quiche::multicast::ChannelState::Joined,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                reason_phrase: Vec::new(),
            }),
        );

        connections.push(StreamProfileConnection {
            pipe,
            runtime,
            controller,
            _attachment: attachment,
        });
    }

    connections
}

fn publish_profile_burst(
    publisher: &ServerStreamPublisher,
    connections: &mut [StreamProfileConnection], stream_id: u64,
    start_offset: u64, range_count: usize, payload: &Bytes, finish: bool,
) -> (u64, u64) {
    const PROFILE_PUBLISH_BATCH: usize = 128;
    let mut offset = start_offset;
    let mut wake_count = 0_u64;

    for batch_start in (0..range_count).step_by(PROFILE_PUBLISH_BATCH) {
        let batch_len = PROFILE_PUBLISH_BATCH.min(range_count - batch_start);
        let wake_counter = Arc::new(StreamProfileWakeCounter::default());
        let waker = Waker::from(Arc::clone(&wake_counter));
        let mut context = Context::from_waker(&waker);
        let mut waiters = connections
            .iter_mut()
            .map(|connection| Box::pin(connection.runtime.wait_for_work()))
            .collect::<Vec<_>>();

        for waiter in &mut waiters {
            assert!(matches!(waiter.as_mut().poll(&mut context), Poll::Pending));
        }

        for batch_index in 0..batch_len {
            let range_index = batch_start + batch_index;
            let range_fin = finish && range_index + 1 == range_count;
            let publication = publisher
                .prepare_stream_buf(stream_id, offset, range_fin, payload.clone())
                .unwrap();
            assert!(!publication.packet().is_empty());
            publisher.commit(publication).unwrap();
            offset += payload.len() as u64;
        }

        wake_count =
            wake_count.saturating_add(wake_counter.wakes.load(Ordering::Relaxed));
        drop(waiters);

        for connection in &mut *connections {
            let max_passes = batch_len
                .div_ceil(connection.runtime.limits.max_work_per_call)
                .saturating_add(4);
            for _ in 0..max_passes {
                connection
                    .runtime
                    .process_writes(&mut connection.pipe.server)
                    .unwrap();

                let publisher_commands =
                    connection.runtime.pending_commands.iter().any(|pending| {
                        matches!(
                                pending.command.as_ref(),
                                ServerControlCommand::StreamPublisherQueueReady {
                                    ..
                                } |
                                ServerControlCommand::DetachStreamPublisher {
                                    ..
                                } |
                                ServerControlCommand::StreamPublication {
                                    ..
                                } |
                                ServerControlCommand::StreamPublisherKey {
                                    ..
                                } |
                                ServerControlCommand::StreamPublisherMaxStreamId {
                                    ..
                                } |
                                ServerControlCommand::StreamPublisherRetire {
                                    ..
                                }
                            )
                    });
                let attachment_items =
                    connection.runtime.channels.values().any(|channel| {
                        channel
                            .stream_publication_queue
                            .as_ref()
                            .is_some_and(|queue| queue.has_items())
                    });
                if !publisher_commands &&
                    !attachment_items &&
                    connection.runtime.pending_stream_publications.is_empty()
                {
                    break;
                }
            }

            assert!(!connection.runtime.pending_commands.iter().any(|pending| {
                matches!(
                    pending.command.as_ref(),
                    ServerControlCommand::StreamPublisherQueueReady { .. } |
                        ServerControlCommand::StreamPublication { .. }
                )
            }));
            assert!(!connection.runtime.channels.values().any(|channel| {
                channel
                    .stream_publication_queue
                    .as_ref()
                    .is_some_and(|queue| queue.has_items())
            }));
            assert!(connection.runtime.pending_stream_publications.is_empty());
        }
    }

    (offset, wake_count)
}

fn assert_no_queued_join(qconn: &mut QuicheConnection) {
    loop {
        match qconn.multicast_recv() {
            Ok(quiche::multicast::Frame::Join(frame)) => {
                panic!("unexpected MC_JOIN: {frame:?}");
            },

            Ok(_) => (),

            Err(quiche::Error::Done) => return,

            Err(error) => panic!("unexpected multicast receive error: {error:?}"),
        }
    }
}

#[test]
fn server_stream_publisher_encodes_shared_stream_packet() {
    let config = test_stream_control_config();
    let publisher = ServerStreamPublisher::new(config.clone()).unwrap();
    publisher.declare_stream(3).unwrap();

    let publication = publisher
        .prepare_stream(3, 10, true, b"shared stream body")
        .unwrap();
    assert_eq!(publication.packet_number(), 0);
    assert_eq!(publication.frame().offset, 10);

    let mut receiver =
        quiche::multicast::ChannelReceiveState::new(config.announce).unwrap();
    receiver.insert_key(config.key).unwrap();
    assert!(receiver
        .insert_integrity(publication.integrity().clone())
        .unwrap()
        .is_empty());

    let events = receiver.recv(publication.packet(), ()).unwrap();
    assert!(matches!(
        &events[0],
        quiche::multicast::ChannelReceiveEvent::Packet { packet, .. }
            if packet.frames == vec![quiche::multicast::ChannelFrame::Stream {
                stream_id: 3,
                offset: 10,
                fin: true,
                data: b"shared stream body".to_vec(),
            }]
    ));
}

#[test]
fn server_stream_unresolved_publication_fail_stops_channel() {
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();

    drop(publisher.prepare_stream(3, 0, false, b"uncertain").unwrap());

    assert!(matches!(
        publisher.prepare_stream(3, 9, false, b"later"),
        Err(ServerStreamPublisherError::Retired)
    ));
}

#[test]
fn server_stream_explicit_abandon_fail_stops_without_reuse() {
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();

    let publication = publisher
        .prepare_stream(3, 0, false, b"unpublished")
        .unwrap();
    publisher.abandon(publication).unwrap();

    assert!(matches!(
        publisher.prepare_stream(3, 11, false, b"later"),
        Err(ServerStreamPublisherError::Retired)
    ));
}

#[test]
fn server_stream_foreign_resolution_retires_actual_publisher() {
    let first = ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    let mut second_config = test_stream_control_config();
    second_config.announce.channel_id = vec![5, 6, 7, 8];
    second_config.key.channel_id = vec![5, 6, 7, 8];
    let second = ServerStreamPublisher::new(second_config).unwrap();
    first.declare_stream(3).unwrap();
    second.declare_stream(7).unwrap();

    let publication = first.prepare_stream(3, 0, false, b"foreign").unwrap();
    assert!(matches!(
        second.commit(publication),
        Err(ServerStreamPublisherError::UnknownPublication)
    ));
    assert!(matches!(
        first.prepare_stream(3, 7, false, b"later"),
        Err(ServerStreamPublisherError::Retired)
    ));
    assert!(second.prepare_stream(7, 0, false, b"healthy").is_ok());
}

#[test]
fn server_stream_prepare_preflights_effective_payload_boundary() {
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    let maximum_payload = vec![0x5a; 16_383];
    let publication = publisher
        .prepare_stream(3, 0, true, &maximum_payload)
        .unwrap();
    assert_eq!(publication.packet_number(), 0);
    publisher.commit(publication).unwrap();
    assert_eq!(publisher.metrics_snapshot().unwrap().next_packet_number, 1);

    let rejected =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    assert!(matches!(
        rejected.prepare_stream(3, 0, false, &vec![0x5a; 16_384]),
        Err(ServerStreamPublisherError::Encode(
            quiche::Error::InvalidFrame
        ))
    ));
    assert_eq!(rejected.metrics_snapshot().unwrap().next_packet_number, 0);
    assert_eq!(rejected.next_stream_offset(3).unwrap(), None);

    let retry = rejected.prepare_stream(3, 0, true, b"retry").unwrap();
    assert_eq!(retry.packet_number(), 0);
    rejected.commit(retry).unwrap();
}

#[test]
fn server_stream_publisher_bounds_active_and_completed_stream_state() {
    let limits = ServerStreamPublisherLimits {
        max_active_streams: 1,
        max_completed_stream_storage_units: 1,
        ..ServerStreamPublisherLimits::default()
    };
    let publisher =
        ServerStreamPublisher::with_limits(test_stream_control_config(), limits)
            .unwrap();

    let active = publisher.prepare_stream(3, 0, false, b"a").unwrap();
    publisher.commit(active).unwrap();
    assert!(matches!(
        publisher.prepare_stream(7, 0, false, b"blocked"),
        Err(ServerStreamPublisherError::ActiveStreamLimit { limit: 1 })
    ));
    assert_eq!(publisher.metrics_snapshot().unwrap().next_packet_number, 1);
    assert_eq!(publisher.next_stream_offset(7).unwrap(), None);

    let finish = publisher.prepare_stream(3, 1, true, b"b").unwrap();
    publisher.commit(finish).unwrap();

    let sparse_stream_id = ((1024_u64 * 2) << 2) | 0x3;
    assert!(matches!(
        publisher.prepare_stream(sparse_stream_id, 0, true, b"sparse"),
        Err(ServerStreamPublisherError::CompletedStreamHistoryLimit { limit: 1 })
    ));
    let profile = publisher.test_profile().unwrap();
    assert_eq!(profile.tracked_streams, 0);
    assert_eq!(profile.finished_streams, 1);
    assert_eq!(profile.finished_stream_storage_units, 1);
    assert_eq!(publisher.metrics_snapshot().unwrap().next_packet_number, 2);
}

#[test]
fn server_stream_key_structural_boundary_is_transactional() {
    const ITEM_RESERVE: usize = 64 * 1024;

    let (_runtime, controller) = test_stream_control_runtime();
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    let channel_id = vec![1, 2, 3, 4];
    let exact_secret_len = ITEM_RESERVE - channel_id.len() - 64;
    publisher
        .update_key(quiche::multicast::Key {
            channel_id: channel_id.clone(),
            key_sequence: 2,
            from_packet_number: 0,
            secret: vec![0xdd; exact_secret_len],
        })
        .unwrap();
    assert_eq!(publisher.metrics_snapshot().unwrap().key_updates, 1);

    assert!(matches!(
        publisher.update_key(quiche::multicast::Key {
            channel_id: channel_id.clone(),
            key_sequence: 3,
            from_packet_number: 0,
            secret: vec![0xee; exact_secret_len + 1],
        }),
        Err(ServerStreamPublisherError::KeyTooLarge {
            retained_bytes,
            max_retained_bytes: ITEM_RESERVE,
        }) if retained_bytes == ITEM_RESERVE + 1
    ));
    assert_eq!(publisher.metrics_snapshot().unwrap().key_updates, 1);

    publisher
        .update_key(quiche::multicast::Key {
            channel_id,
            key_sequence: 3,
            from_packet_number: 0,
            secret: vec![0xff; 16],
        })
        .unwrap();
    assert_eq!(publisher.metrics_snapshot().unwrap().key_updates, 2);
}

#[test]
fn server_stream_attachment_saturation_detaches_without_failing_commit() {
    let limits = ServerStreamPublisherLimits {
        max_attachment_queue_items: 2,
        max_attachment_queue_bytes: 128 * 1024,
        ..ServerStreamPublisherLimits::default()
    };
    let publisher =
        ServerStreamPublisher::with_limits(test_stream_control_config(), limits)
            .unwrap();
    let (_runtime, controller) = test_stream_control_runtime();
    let _attachment = publisher.attach(&controller).unwrap();

    for (offset, fin) in [(0, false), (1, true)] {
        let publication = publisher.prepare_stream(3, offset, fin, b"x").unwrap();
        publisher.commit(publication).unwrap();
    }

    assert_eq!(publisher.attached_connections().unwrap(), 0);
    assert_eq!(publisher.metrics_snapshot().unwrap().next_packet_number, 2);
}

#[test]
fn server_stream_attach_distinguishes_full_oversized_and_closed() {
    let full_limits = RuntimeLimits {
        commands: RetainedQueueLimits {
            max_items: 1,
            max_retained_bytes: 4096,
        },
        ..RuntimeLimits::default()
    };
    let (_full_driver, full_controller) =
        ServerControlDriver::new_with_runtime_limits(
            (),
            ServerControlSettings::default(),
            full_limits,
        )
        .unwrap();
    full_controller.send_announce(test_ipv4_announce()).unwrap();
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    assert!(matches!(
        publisher.attach(&full_controller),
        Err(ServerStreamPublisherError::ControllerQueueFull)
    ));

    let oversized_limits = RuntimeLimits {
        commands: RetainedQueueLimits {
            max_items: 4,
            max_retained_bytes: 256,
        },
        ..RuntimeLimits::default()
    };
    let (_oversized_driver, oversized_controller) =
        ServerControlDriver::new_with_runtime_limits(
            (),
            ServerControlSettings::default(),
            oversized_limits,
        )
        .unwrap();
    assert!(matches!(
        publisher.attach(&oversized_controller),
        Err(ServerStreamPublisherError::ControllerCommandTooLarge)
    ));

    let (closed_driver, closed_controller) =
        ServerControlDriver::new((), ServerControlSettings::default()).unwrap();
    drop(closed_driver);
    assert!(matches!(
        publisher.attach(&closed_controller),
        Err(ServerStreamPublisherError::ControllerClosed)
    ));
    assert_eq!(publisher.attached_connections().unwrap(), 0);
}

#[test]
fn server_stream_publisher_queue_is_edge_triggered_and_ordered() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();

    let channel_id = vec![1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    let queue = Arc::clone(
        runtime.channels[&channel_id]
            .stream_publication_queue
            .as_ref()
            .unwrap(),
    );

    let first = publisher.prepare_stream(3, 0, false, b"first").unwrap();
    publisher.commit(first).unwrap();
    let rotated = quiche::multicast::Key {
        channel_id: channel_id.clone(),
        key_sequence: 2,
        from_packet_number: 1,
        secret: vec![0xdd; 16],
    };
    publisher.update_key(rotated.clone()).unwrap();
    let second = publisher.prepare_stream(3, 5, false, b"second").unwrap();
    publisher.commit(second).unwrap();

    let profile = publisher.test_profile().unwrap();
    assert_eq!(profile.publication_commands_sent, 1);
    let items = queue.drain().into_iter().collect::<Vec<_>>();
    assert!(matches!(
        &items[..],
        [
            server_stream::ServerStreamPublisherQueueItem::Publication(
                first
            ),
            server_stream::ServerStreamPublisherQueueItem::Key(key),
            server_stream::ServerStreamPublisherQueueItem::Publication(
                second
            ),
        ] if first.packet_number == 0 &&
            key == &rotated &&
            second.packet_number == 1
    ));
}

#[test]
fn server_stream_publisher_stages_transactionally_under_command_pressure() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    send_webtransport_stream_prefix(&mut pipe, 3, 11);

    let limits = RuntimeLimits {
        commands: RetainedQueueLimits {
            max_items: 2,
            max_retained_bytes: 64 * 1024,
        },
        max_work_per_call: 1,
        ..RuntimeLimits::default()
    };
    let (command_sender, command_receiver, command_observer) =
        bounded_channel(limits.commands);
    let (event_sender, event_receiver, event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::with_limits(
        ServerControlSettings::default(),
        event_sender,
        command_receiver,
        limits,
    );
    let controller = ServerControlController {
        command_sender,
        command_observer: command_observer.clone(),
        pending_publication_observer: test_retained_queue_observer(),
        pending_integrity_observer: test_retained_queue_observer(),
        event_receiver: Some(event_receiver),
        event_observer,
    };
    runtime.on_conn_established(&mut pipe.server).unwrap();

    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    for offset in 10..13 {
        let publication =
            publisher.prepare_stream(3, offset, false, b"x").unwrap();
        publisher.commit(publication).unwrap();
    }

    for pass in 0..32 {
        if let Err(error) = runtime.process_writes(&mut pipe.server) {
            panic!(
                "pass={pass} pending={} command_stats={:?} blocked={:?}: \
                     {error}",
                runtime.pending_commands.len(),
                command_observer.stats(),
                runtime.blocked_command_channels,
            );
        }
        assert!(runtime.callback_write_work_last_call <= 1);
    }

    assert_eq!(runtime.stream_publication_registrations, 3);
    assert!(runtime.pending_stream_publications.is_empty());
    assert!(runtime.pending_commands.is_empty());
    assert!(!runtime.channels[&[1, 2, 3, 4][..]]
        .stream_publication_queue
        .as_ref()
        .unwrap()
        .has_items());
    let stats = command_observer.stats();
    assert!(stats.peak_retained_items <= stats.max_items);
    assert!(stats.peak_retained_bytes <= stats.max_retained_bytes);
}

#[test]
fn server_stream_detach_releases_undrained_publications() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);

    let channel_id = vec![1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    for (offset, fin, data) in
        [(10, false, b"one".as_slice()), (13, true, b"two")]
    {
        let publication = publisher.prepare_stream(3, offset, fin, data).unwrap();
        publisher.commit(publication).unwrap();
    }
    assert_eq!(
        publisher.test_profile().unwrap().publication_commands_sent,
        1
    );

    drop(attachment);
    assert_eq!(publisher.attached_connections().unwrap(), 0);
    runtime.process_writes(&mut pipe.server).unwrap();

    assert!(runtime.pending_stream_publications.is_empty());
    assert_eq!(
        pipe.server.multicast_stream_recovery_pending(&channel_id),
        0
    );
    deliver_server_flight(&mut pipe);
    let mut out = [0; 16];
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((6, true)));
    assert_eq!(&out[..6], b"onetwo");
    assert_eq!(
        publisher.delivery_metrics_snapshot(),
        quiche::multicast::StreamDeliveryMetricsSnapshot {
            direct_fallback_ranges_total: 2,
            direct_fallback_bytes_total: 6,
            ..Default::default()
        }
    );
}

#[test]
fn server_stream_detach_waits_for_blocked_committed_publication() {
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let past = publisher.prepare_stream(3, 10, false, b"past").unwrap();
    publisher.commit(past).unwrap();

    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);
    let attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let live = publisher.prepare_stream(3, 14, true, b"live").unwrap();
    publisher.commit(live).unwrap();
    drop(attachment);
    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(runtime.pending_stream_publications.len(), 1);
    assert!(runtime.pending_stream_publications.is_retry_blocked());
    assert!(runtime.channels[&[1, 2, 3, 4][..]].stream_publisher);

    assert_eq!(pipe.server.stream_send(3, b"past", false), Ok(4));
    runtime.process_writes(&mut pipe.server).unwrap();
    assert!(runtime.pending_stream_publications.is_empty());
    assert!(!runtime.channels[&[1, 2, 3, 4][..]].stream_publisher);
    deliver_server_flight(&mut pipe);

    let mut out = [0; 16];
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((8, true)));
    assert_eq!(&out[..8], b"pastlive");
}

#[test]
fn server_stream_detach_waits_for_missing_webtransport_prefix() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();

    let channel_id = [1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let publication = publisher
        .prepare_stream(3, 10, true, b"after prefix")
        .unwrap();
    publisher.commit(publication).unwrap();
    drop(attachment);
    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(runtime.pending_stream_publications.len(), 1);
    assert!(runtime.pending_stream_publications.is_retry_blocked());
    assert!(runtime.channels[&channel_id[..]].stream_publisher);

    send_webtransport_stream_prefix(&mut pipe, 3, 11);
    runtime.process_writes(&mut pipe.server).unwrap();

    assert!(runtime.pending_stream_publications.is_empty());
    assert!(!runtime.pending_stream_publications.is_retry_blocked());
    assert!(!runtime.channels[&channel_id[..]].stream_publisher);
    deliver_server_flight(&mut pipe);

    let mut out = [0; 16];
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((12, true)));
    assert_eq!(&out[..12], b"after prefix");
}

#[test]
fn server_stream_detach_discards_collected_stream_publication() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);

    let channel_id = [1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let publication = publisher.prepare_stream(3, 10, true, b"stale").unwrap();
    publisher.commit(publication).unwrap();

    assert_eq!(
        pipe.server.stream_send(3, b"ordinary", true),
        Ok(b"ordinary".len())
    );
    pipe.advance().unwrap();

    let mut out = [0; 16];
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((8, true)));
    assert_eq!(&out[..8], b"ordinary");
    assert_eq!(
        pipe.server.stream_capacity(3),
        Err(quiche::Error::InvalidStreamState(3))
    );

    drop(attachment);
    runtime.process_writes(&mut pipe.server).unwrap();

    assert!(runtime.pending_stream_publications.is_empty());
    assert!(!runtime.pending_stream_publications.is_retry_blocked());
    assert!(!runtime.channels[&channel_id[..]].stream_publisher);
    assert_eq!(
        pipe.server.multicast_stream_recovery_pending(&channel_id),
        0
    );
}

#[test]
fn server_stream_reattach_requires_fresh_ack_before_cutover() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);

    let channel_id = vec![1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let old = publisher.prepare_stream(3, 10, false, b"old").unwrap();
    publisher.commit(old).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);
    let mut out = [0; 16];
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((3, false)));

    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );
    assert_eq!(
        pipe.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::Viable)
    );

    drop(attachment);
    runtime.process_writes(&mut pipe.server).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    assert_eq!(
        pipe.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::Probing)
    );

    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );
    assert_eq!(
        pipe.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::Probing)
    );

    let new = publisher.prepare_stream(3, 13, false, b"new").unwrap();
    publisher.commit(new).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((3, false)));
    assert_eq!(&out[..3], b"new");

    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );
    assert_eq!(
        pipe.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::Probing)
    );

    let end = publisher.prepare_stream(3, 16, true, b"end").unwrap();
    publisher.commit(end).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((3, true)));
    assert_eq!(&out[..3], b"end");

    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id,
            largest_acknowledged: 2,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );
    assert_eq!(
        pipe.server.multicast_probe_status(&[1, 2, 3, 4]),
        Some(quiche::multicast::ProbeStatus::Viable)
    );
}

fn structural_profile_percentile(
    sorted_nanos: &[u128], percentile: usize,
) -> u128 {
    let index = sorted_nanos
        .len()
        .saturating_sub(1)
        .saturating_mul(percentile) /
        100;
    sorted_nanos[index]
}

fn run_stream_attachment_structural_profile(client_count: usize) {
    const PUBLICATION_COUNT: usize = 32;
    const STREAM_ID: u64 = 3;

    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(STREAM_ID).unwrap();
    let mut attachments = Vec::with_capacity(client_count);

    for _ in 0..client_count {
        let (command_sender, command_receiver, command_observer) =
            test_server_control_command_channel();
        let (_event_sender, event_receiver, event_observer) =
            test_server_event_channel();
        let controller = ServerControlController {
            command_sender,
            command_observer: command_observer.clone(),
            pending_publication_observer: test_retained_queue_observer(),
            pending_integrity_observer: test_retained_queue_observer(),
            event_receiver: Some(event_receiver),
            event_observer,
        };
        let attachment = publisher.attach(&controller).unwrap();
        attachments.push((command_receiver, command_observer, attachment));
    }

    let payload = Bytes::from(vec![0x5a; 256]);
    let mut offset = 10_u64;
    let mut publication_nanos = Vec::with_capacity(PUBLICATION_COUNT);
    for index in 0..PUBLICATION_COUNT {
        let publication = publisher
            .prepare_stream_buf(
                STREAM_ID,
                offset,
                index + 1 == PUBLICATION_COUNT,
                payload.clone(),
            )
            .unwrap();
        let started = std::time::Instant::now();
        publisher.commit(publication).unwrap();
        publication_nanos.push(started.elapsed().as_nanos());
        offset = offset.saturating_add(payload.len() as u64);
    }
    publication_nanos.sort_unstable();

    let profile = publisher.test_profile().unwrap();
    let command_peak_items = attachments
        .iter()
        .map(|(_, observer, _)| observer.stats().peak_retained_items)
        .sum::<usize>();
    let command_peak_bytes = attachments
        .iter()
        .map(|(_, observer, _)| observer.stats().peak_retained_bytes)
        .sum::<usize>();

    assert_eq!(profile.attached_connections, client_count);
    assert_eq!(
        profile.attachment_queue_items,
        client_count * PUBLICATION_COUNT
    );
    assert!(
        profile.attachment_queue_bytes <=
            client_count *
                ServerStreamPublisherLimits::default()
                    .max_attachment_queue_bytes
    );

    println!(
        concat!(
            "MCQUIC_ATTACHMENT_PROFILE clients={} publications={} ",
            "queue_items={} queue_bytes={} command_peak_items={} ",
            "command_peak_bytes={} p50_ns={} p95_ns={} p99_ns={} ",
            "worst_ns={} notifications={}"
        ),
        client_count,
        PUBLICATION_COUNT,
        profile.attachment_queue_items,
        profile.attachment_queue_bytes,
        command_peak_items,
        command_peak_bytes,
        structural_profile_percentile(&publication_nanos, 50),
        structural_profile_percentile(&publication_nanos, 95),
        structural_profile_percentile(&publication_nanos, 99),
        publication_nanos.last().copied().unwrap_or(0),
        profile.publication_commands_sent,
    );
}

#[test]
#[ignore = "release-mode structural profile; run explicitly"]
fn server_stream_publisher_profiles_one_and_ten_thousand_attachments() {
    run_stream_attachment_structural_profile(1_000);
    run_stream_attachment_structural_profile(10_000);
}

#[test]
#[ignore = "deterministic performance profile; run explicitly"]
fn server_stream_publisher_profiles_eighty_connections() {
    const CLIENT_COUNT: usize = 80;
    const RANGES_PER_PHASE: usize = 32;
    const STREAM_ID: u64 = 3;
    const WEBTRANSPORT_PREFIX_LEN: u64 = 10;

    let settings = test_settings();
    let config = test_stream_control_config();
    let channel_id = config.announce.channel_id.clone();
    let publisher = ServerStreamPublisher::new(config).unwrap();
    publisher.declare_stream(STREAM_ID).unwrap();

    let mut connections = setup_stream_profile_connections(
        &settings,
        &publisher,
        &channel_id,
        STREAM_ID,
        CLIENT_COUNT,
        StreamIntegrityBatchingSettings::default(),
    );

    let mut stream_offset = WEBTRANSPORT_PREFIX_LEN;
    let mut task_wakes = 0_u64;
    let payload = Bytes::from(vec![0x5a; 1024]);

    let (next_offset, wakes) = publish_profile_burst(
        &publisher,
        &mut connections,
        STREAM_ID,
        stream_offset,
        RANGES_PER_PHASE,
        &payload,
        false,
    );
    stream_offset = next_offset;
    task_wakes = task_wakes.saturating_add(wakes);

    for connection in &mut connections {
        send_client_control(
            &mut connection.pipe,
            &mut connection.runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: RANGES_PER_PHASE as u64 - 1,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );
    }

    let (next_offset, wakes) = publish_profile_burst(
        &publisher,
        &mut connections,
        STREAM_ID,
        stream_offset,
        RANGES_PER_PHASE,
        &payload,
        false,
    );
    stream_offset = next_offset;
    task_wakes = task_wakes.saturating_add(wakes);
    let peak_recovery_ranges = connections
        .iter()
        .map(|connection| {
            connection
                .pipe
                .server
                .multicast_stream_recovery_pending(&channel_id)
        })
        .sum::<usize>();
    assert_eq!(peak_recovery_ranges, CLIENT_COUNT * RANGES_PER_PHASE);

    for connection in &mut connections {
        send_client_control(
            &mut connection.pipe,
            &mut connection.runtime,
            quiche::multicast::Frame::State(quiche::multicast::State {
                channel_id: channel_id.clone(),
                sequence: 2,
                state: quiche::multicast::ChannelState::Left,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
                reason_phrase: Vec::new(),
            }),
        );
    }

    let (_, wakes) = publish_profile_burst(
        &publisher,
        &mut connections,
        STREAM_ID,
        stream_offset,
        RANGES_PER_PHASE,
        &payload,
        true,
    );
    task_wakes = task_wakes.saturating_add(wakes);

    let final_recovery_ranges = connections
        .iter()
        .map(|connection| {
            connection
                .pipe
                .server
                .multicast_stream_recovery_pending(&channel_id)
        })
        .sum::<usize>();
    assert_eq!(final_recovery_ranges, 0);

    let mut client_limits_events = 0_u64;
    let mut client_state_events = 0_u64;
    let mut client_ack_events = 0_u64;
    let mut probe_events = 0_u64;
    for connection in &mut connections {
        let event_receiver = connection
            .controller
            .event_receiver
            .as_mut()
            .expect("profile receiver is retained");
        while let Ok(event) = event_receiver.try_recv() {
            match event {
                ServerEvent::ClientLimits(..) => client_limits_events += 1,

                ServerEvent::ClientState(..) => client_state_events += 1,

                ServerEvent::ClientAck(..) => client_ack_events += 1,

                ServerEvent::ProbeStatusChanged(..) => probe_events += 1,

                ServerEvent::Published { .. } |
                ServerEvent::EncodeError { .. } |
                ServerEvent::PublishError { .. } => (),
            }
        }
    }

    let metric_fold_attempts = connections
        .iter()
        .map(|connection| connection.runtime.stream_delivery_metric_fold_attempts)
        .sum::<u64>();
    let publication_registrations = connections
        .iter()
        .map(|connection| connection.runtime.stream_publication_registrations)
        .sum::<u64>();
    let profile = publisher.test_profile().unwrap();
    let delivery = publisher.delivery_metrics_snapshot();

    assert_eq!(client_ack_events, CLIENT_COUNT as u64);
    assert_eq!(
        publication_registrations,
        (CLIENT_COUNT * RANGES_PER_PHASE * 3) as u64
    );
    assert_eq!(
        delivery.direct_fallback_ranges_total,
        (CLIENT_COUNT * RANGES_PER_PHASE * 2) as u64
    );
    assert_eq!(
        delivery.fallback_reentry_ranges_total,
        (CLIENT_COUNT * RANGES_PER_PHASE) as u64
    );
    assert_eq!(profile.tracked_streams, 0);
    assert_eq!(profile.finished_streams, 1);
    assert_eq!(profile.finished_stream_storage_units, 1);
    assert_eq!(profile.attached_connections, CLIENT_COUNT);
    assert!(
        profile.preparation_capacity_bytes < (RANGES_PER_PHASE * 3 * 2048) as u64
    );

    println!(
        concat!(
            "MCQUIC_PROFILE clients={} ranges_per_phase={} ",
            "publication_commands={} task_wakes={} ",
            "publication_registrations={} ",
            "preparation_capacity_bytes={} ack_events={} ",
            "probe_events={} limits_events={} state_events={} ",
            "metric_fold_attempts={} peak_recovery_ranges={} ",
            "final_recovery_ranges={} direct_ranges={} ",
            "gap_recovery_ranges={} reentry_ranges={} ",
            "publisher_tracked_streams={} ",
            "publisher_finished_streams={} ",
            "publisher_finished_stream_storage_units={}"
        ),
        CLIENT_COUNT,
        RANGES_PER_PHASE,
        profile.publication_commands_sent,
        task_wakes,
        publication_registrations,
        profile.preparation_capacity_bytes,
        client_ack_events,
        probe_events,
        client_limits_events,
        client_state_events,
        metric_fold_attempts,
        peak_recovery_ranges,
        final_recovery_ranges,
        delivery.direct_fallback_ranges_total,
        delivery.ack_gap_recovery_ranges_total,
        delivery.fallback_reentry_ranges_total,
        profile.tracked_streams,
        profile.finished_streams,
        profile.finished_stream_storage_units,
    );
}

#[tokio::test]
#[ignore = "long established-connection performance profile"]
async fn server_stream_publisher_profiles_established_connections() {
    const CLIENT_COUNT: usize = 80;
    const RANGES_PER_ROUND: usize = 4_096;
    const ROUND_COUNT: usize = 4;
    const STREAM_ID: u64 = 3;
    const WEBTRANSPORT_PREFIX_LEN: u64 = 10;

    let settings = test_settings();
    let config = test_stream_control_config();
    let channel_id = config.announce.channel_id.clone();
    let publisher = ServerStreamPublisher::new(config).unwrap();
    publisher.declare_stream(STREAM_ID).unwrap();
    let batching = StreamIntegrityBatchingSettings {
        max_packet_hashes: 16,
        max_delay: Duration::from_secs(1),
    };

    let mut connections = setup_stream_profile_connections(
        &settings,
        &publisher,
        &channel_id,
        STREAM_ID,
        CLIENT_COUNT,
        batching,
    );

    let payload = Bytes::from(vec![0x5a; 24]);
    let (mut stream_offset, _) = publish_profile_burst(
        &publisher,
        &mut connections,
        STREAM_ID,
        WEBTRANSPORT_PREFIX_LEN,
        1,
        &payload,
        false,
    );
    for connection in &mut connections {
        send_client_control(
            &mut connection.pipe,
            &mut connection.runtime,
            quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                channel_id: channel_id.clone(),
                largest_acknowledged: 0,
                ack_delay: 0,
                first_ack_range: 0,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }),
        );
    }

    let baseline_registrations = connections
        .iter()
        .map(|connection| connection.runtime.stream_publication_registrations)
        .sum::<u64>();
    let started = Instant::now();
    let mut task_wakes = 0_u64;
    let mut peak_recovery_ranges = 0_usize;

    for round in 0..ROUND_COUNT {
        let (next_offset, wakes) = publish_profile_burst(
            &publisher,
            &mut connections,
            STREAM_ID,
            stream_offset,
            RANGES_PER_ROUND,
            &payload,
            round + 1 == ROUND_COUNT,
        );
        stream_offset = next_offset;
        task_wakes = task_wakes.saturating_add(wakes);

        let recovery_ranges = connections
            .iter()
            .map(|connection| {
                connection
                    .pipe
                    .server
                    .multicast_stream_recovery_pending(&channel_id)
            })
            .sum::<usize>();
        peak_recovery_ranges = peak_recovery_ranges.max(recovery_ranges);
        assert_eq!(recovery_ranges, CLIENT_COUNT * RANGES_PER_ROUND);

        let largest_acknowledged = ((round + 1) * RANGES_PER_ROUND) as u64;
        for connection in &mut connections {
            send_client_control(
                &mut connection.pipe,
                &mut connection.runtime,
                quiche::multicast::Frame::Ack(quiche::multicast::Ack {
                    channel_id: channel_id.clone(),
                    largest_acknowledged,
                    ack_delay: 0,
                    first_ack_range: RANGES_PER_ROUND as u64 - 1,
                    ack_ranges: Vec::new(),
                    ecn_counts: None,
                }),
            );
        }
    }

    let elapsed = started.elapsed();
    let registrations = connections
        .iter()
        .map(|connection| connection.runtime.stream_publication_registrations)
        .sum::<u64>()
        .saturating_sub(baseline_registrations);
    let final_recovery_ranges = connections
        .iter()
        .map(|connection| {
            connection
                .pipe
                .server
                .multicast_stream_recovery_pending(&channel_id)
        })
        .sum::<usize>();
    let profile = publisher.test_profile().unwrap();

    assert_eq!(
        registrations,
        (CLIENT_COUNT * RANGES_PER_ROUND * ROUND_COUNT) as u64
    );
    assert_eq!(final_recovery_ranges, 0);
    assert_eq!(profile.tracked_streams, 0);
    assert_eq!(profile.finished_streams, 1);

    println!(
        concat!(
            "MCQUIC_ESTABLISHED_PROFILE clients={} rounds={} ",
            "ranges_per_round={} registrations={} task_wakes={} ",
            "peak_recovery_ranges={} final_recovery_ranges={} ",
            "elapsed_us={} ns_per_registration={}"
        ),
        CLIENT_COUNT,
        ROUND_COUNT,
        RANGES_PER_ROUND,
        registrations,
        task_wakes,
        peak_recovery_ranges,
        final_recovery_ranges,
        elapsed.as_micros(),
        elapsed.as_nanos() / u128::from(registrations),
    );
}

#[test]
fn server_stream_integrity_batches_contiguous_hashes_by_count() {
    let (mut runtime, _controller) =
        test_stream_control_runtime_with_integrity_batching(
            StreamIntegrityBatchingSettings {
                max_packet_hashes: 3,
                max_delay: Duration::from_millis(75),
            },
        );
    let now = Instant::now();

    runtime
        .queue_stream_integrity(test_stream_integrity(10, 0xaa), now)
        .unwrap();
    runtime
        .queue_stream_integrity(test_stream_integrity(11, 0xbb), now)
        .unwrap();
    assert!(runtime.pending_integrities.is_empty());
    assert_eq!(runtime.pending_stream_integrity_batches.len(), 1);

    runtime
        .queue_stream_integrity(test_stream_integrity(12, 0xcc), now)
        .unwrap();
    assert!(runtime.pending_stream_integrity_batches.is_empty());
    assert_eq!(
        runtime.pending_integrities.pop_front(),
        Some(quiche::multicast::Integrity {
            channel_id: vec![1, 2, 3, 4],
            packet_number_start: 10,
            packet_hash_count: Some(3),
            packet_hashes: [vec![0xaa; 32], vec![0xbb; 32], vec![0xcc; 32]]
                .concat(),
        })
    );
}

#[test]
fn server_stream_integrity_does_not_batch_across_packet_gaps() {
    let (mut runtime, _controller) =
        test_stream_control_runtime_with_integrity_batching(
            StreamIntegrityBatchingSettings {
                max_packet_hashes: 3,
                max_delay: Duration::from_millis(75),
            },
        );
    let now = Instant::now();
    let first = test_stream_integrity(10, 0xaa);
    let after_gap = test_stream_integrity(12, 0xcc);

    runtime.queue_stream_integrity(first.clone(), now).unwrap();
    runtime
        .queue_stream_integrity(after_gap.clone(), now)
        .unwrap();

    assert_eq!(runtime.pending_integrities.pop_front(), Some(first));
    assert_eq!(
        runtime.pending_stream_integrity_batches[&[1, 2, 3, 4][..]]
            .as_ref()
            .frame,
        after_gap
    );
}

#[test]
fn server_stream_integrity_batches_share_bounded_send_budget() {
    let limits = RuntimeLimits {
        pending_integrity: RetainedQueueLimits {
            max_items: 2,
            max_retained_bytes: 1024,
        },
        ..RuntimeLimits::default()
    };
    let (_command_sender, command_receiver, _command_observer) =
        bounded_channel(limits.commands);
    let (event_sender, _event_receiver, _event_observer) =
        test_server_event_channel();
    let mut runtime = ServerControlRuntime::with_limits(
        ServerControlSettings {
            mode: ServerControlMode::Automatic,
            channels: Vec::new(),
            stream_integrity_batching: StreamIntegrityBatchingSettings {
                max_packet_hashes: 3,
                max_delay: Duration::from_millis(75),
            },
        },
        event_sender,
        command_receiver,
        limits,
    );

    let now = Instant::now();
    let first = test_stream_integrity(10, 0xaa);
    let mut second = test_stream_integrity(10, 0xbb);
    let mut rejected = test_stream_integrity(10, 0xcc);
    second.channel_id = vec![5, 6, 7, 8];
    rejected.channel_id = vec![9, 10, 11, 12];

    runtime.queue_stream_integrity(first.clone(), now).unwrap();
    runtime.queue_stream_integrity(second, now).unwrap();
    assert!(runtime.queue_stream_integrity(rejected, now).is_err());

    let observer = runtime.pending_integrities.observer();
    let stats = observer.stats();
    assert_eq!(stats.retained_items, 2);
    assert!(stats.retained_bytes <= stats.max_retained_bytes);
    assert_eq!(stats.saturations_total, 1);

    runtime
        .flush_stream_integrity_batch(&first.channel_id)
        .unwrap();
    assert_eq!(observer.stats().retained_items, 2);
    assert_eq!(runtime.pending_integrities.pop_front(), Some(first));
    assert_eq!(observer.stats().retained_items, 1);
}

#[tokio::test(start_paused = true)]
async fn server_stream_integrity_tail_wakes_at_max_delay() {
    let (mut runtime, _controller) =
        test_stream_control_runtime_with_integrity_batching(
            StreamIntegrityBatchingSettings {
                max_packet_hashes: 3,
                max_delay: Duration::from_millis(75),
            },
        );
    let integrity = test_stream_integrity(10, 0xaa);
    runtime
        .queue_stream_integrity(integrity.clone(), Instant::now())
        .unwrap();

    assert!(!runtime.has_pending_work());
    assert!(tokio::time::timeout(
        Duration::from_millis(74),
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

    assert!(runtime
        .stage_one_due_stream_integrity(Instant::now())
        .unwrap());
    assert_eq!(runtime.pending_integrities.pop_front(), Some(integrity));
    assert!(runtime.pending_stream_integrity_batches.is_empty());
}

#[test]
fn server_stream_publisher_fans_out_unicast_fallback_to_two_clients() {
    let settings = test_settings();
    let mut first = test_stream_pipe(&settings);
    let mut second = test_stream_pipe(&settings);
    let (mut first_runtime, first_controller) = test_stream_control_runtime();
    let (mut second_runtime, second_controller) = test_stream_control_runtime();
    first_runtime
        .on_conn_established(&mut first.server)
        .unwrap();
    second_runtime
        .on_conn_established(&mut second.server)
        .unwrap();
    send_webtransport_stream_prefix(&mut first, 3, 11);
    send_webtransport_stream_prefix(&mut second, 3, 22);

    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let first_attachment = publisher.attach(&first_controller).unwrap();
    let second_attachment = publisher.attach(&second_controller).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();

    let publication = publisher
        .prepare_stream(3, 10, false, b"one shared body")
        .unwrap();
    publisher.commit(publication).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();
    let channel_metrics = publisher.metrics_snapshot().unwrap();
    assert_eq!(
        publisher.delivery_metrics_snapshot(),
        quiche::multicast::StreamDeliveryMetricsSnapshot {
            direct_fallback_ranges_total: 2,
            direct_fallback_bytes_total: 30,
            ..Default::default()
        }
    );
    assert_eq!(publisher.metrics_snapshot().unwrap(), channel_metrics);
    deliver_server_flight(&mut first);
    deliver_server_flight(&mut second);

    let mut out = [0; 32];
    assert_eq!(first.client.stream_recv(3, &mut out), Ok((15, false)));
    assert_eq!(&out[..15], b"one shared body");
    assert_eq!(second.client.stream_recv(3, &mut out), Ok((15, false)));
    assert_eq!(&out[..15], b"one shared body");
    assert_eq!(publisher.attached_connections().unwrap(), 2);

    drop(first_attachment);
    drop(second_attachment);
    assert_eq!(publisher.attached_connections().unwrap(), 0);
    assert_eq!(
        publisher.delivery_metrics_snapshot(),
        quiche::multicast::StreamDeliveryMetricsSnapshot {
            direct_fallback_ranges_total: 2,
            direct_fallback_bytes_total: 30,
            ..Default::default()
        }
    );
}

#[test]
fn server_stream_stalled_connection_does_not_block_healthy_connection() {
    let settings = test_settings();
    let mut stalled = test_stream_pipe(&settings);
    let mut healthy = test_stream_pipe(&settings);
    let (mut stalled_runtime, stalled_controller) = test_stream_control_runtime();
    let (mut healthy_runtime, healthy_controller) = test_stream_control_runtime();
    stalled_runtime
        .on_conn_established(&mut stalled.server)
        .unwrap();
    healthy_runtime
        .on_conn_established(&mut healthy.server)
        .unwrap();
    send_webtransport_stream_prefix(&mut healthy, 3, 22);

    let channel_id = vec![1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let _stalled_attachment = publisher.attach(&stalled_controller).unwrap();
    let _healthy_attachment = publisher.attach(&healthy_controller).unwrap();
    stalled_runtime.process_writes(&mut stalled.server).unwrap();
    healthy_runtime.process_writes(&mut healthy.server).unwrap();

    let publication = publisher
        .prepare_stream(3, 10, true, b"independent progress")
        .unwrap();
    publisher.commit(publication).unwrap();
    stalled_runtime.process_writes(&mut stalled.server).unwrap();
    healthy_runtime.process_writes(&mut healthy.server).unwrap();

    assert_eq!(
        stalled_runtime
            .pending_stream_publications
            .observer()
            .stats()
            .retained_items,
        1
    );
    assert_eq!(
        healthy_runtime
            .pending_stream_publications
            .observer()
            .stats()
            .retained_items,
        0
    );
    deliver_server_flight(&mut healthy);
    let mut out = [0; 32];
    assert_eq!(
        healthy.client.stream_recv(3, &mut out),
        Ok((b"independent progress".len(), true))
    );
    assert_eq!(
        &out[..b"independent progress".len()],
        b"independent progress"
    );

    send_webtransport_stream_prefix(&mut stalled, 3, 11);
    stalled_runtime.process_writes(&mut stalled.server).unwrap();
    assert_eq!(
        stalled
            .server
            .multicast_stream_recovery_pending(&channel_id),
        0
    );
    deliver_server_flight(&mut stalled);
    assert_eq!(
        stalled.client.stream_recv(3, &mut out),
        Ok((b"independent progress".len(), true))
    );
}

#[test]
fn server_stream_publisher_attaches_directly_to_sparse_high_stream_id() {
    let settings = test_settings();
    let stream_ordinal = 1_000_003;
    let stream_id = (stream_ordinal << 2) | 0x3;
    let mut pipe =
        test_stream_pipe_with_max_streams_uni(&settings, stream_ordinal + 1);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(test_limits()),
    );
    send_webtransport_stream_prefix(&mut pipe, stream_id, 11);

    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    publisher.declare_stream(stream_id).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let publication = publisher
        .prepare_stream(stream_id, 10, true, b"direct high-id body")
        .unwrap();
    publisher.commit(publication).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);

    let mut out = [0; 32];
    assert_eq!(pipe.client.stream_recv(stream_id, &mut out), Ok((19, true)));
    assert_eq!(&out[..19], b"direct high-id body");
    assert_eq!(pipe.server.peer_streams_left_uni(), 0);
}

#[test]
fn server_stream_ack_cuts_over_left_falls_back_and_later_rejoins() {
    let settings = test_settings();
    let mut first = test_stream_pipe(&settings);
    let mut second = test_stream_pipe(&settings);
    let (mut first_runtime, first_controller) = test_stream_control_runtime();
    let (mut second_runtime, second_controller) = test_stream_control_runtime();
    first_runtime
        .on_conn_established(&mut first.server)
        .unwrap();
    second_runtime
        .on_conn_established(&mut second.server)
        .unwrap();
    send_webtransport_stream_prefix(&mut first, 3, 11);
    send_webtransport_stream_prefix(&mut second, 3, 22);

    let channel_id = vec![1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let _first_attachment = publisher.attach(&first_controller).unwrap();
    let _second_attachment = publisher.attach(&second_controller).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();

    send_client_control(
        &mut first,
        &mut first_runtime,
        quiche::multicast::Frame::Limits(test_limits()),
    );
    deliver_server_flight(&mut first);
    send_client_control(
        &mut first,
        &mut first_runtime,
        quiche::multicast::Frame::State(quiche::multicast::State {
            channel_id: channel_id.clone(),
            sequence: 1,
            state: quiche::multicast::ChannelState::Joined,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: Vec::new(),
        }),
    );

    let baseline = publisher.prepare_stream(3, 10, false, b"baseline").unwrap();
    publisher.commit(baseline).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();
    deliver_server_flight(&mut first);
    deliver_server_flight(&mut second);

    let mut out = [0; 64];
    assert_eq!(first.client.stream_recv(3, &mut out), Ok((8, false)));
    assert_eq!(&out[..8], b"baseline");
    assert_eq!(second.client.stream_recv(3, &mut out), Ok((8, false)));
    assert_eq!(&out[..8], b"baseline");

    send_client_control(
        &mut first,
        &mut first_runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );
    assert_eq!(
        first.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::Viable),
        "work={} readable={} queued={} channel_present={}",
        first_runtime.callback_read_work_last_call,
        first.server.is_multicast_readable(),
        first.server.multicast_recv_queue_len(),
        first_runtime.channels.contains_key(&channel_id),
    );

    let multicast_only = publisher
        .prepare_stream(3, 18, false, b"green-gap")
        .unwrap();
    publisher.commit(multicast_only).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();
    deliver_server_flight(&mut first);
    deliver_server_flight(&mut second);

    assert_eq!(
        first.client.stream_recv(3, &mut out),
        Err(quiche::Error::Done)
    );
    assert_eq!(second.client.stream_recv(3, &mut out), Ok((9, false)));
    assert_eq!(&out[..9], b"green-gap");
    assert_eq!(
        first.server.multicast_stream_recovery_pending(&channel_id),
        1
    );
    assert_eq!(
        publisher.delivery_metrics_snapshot(),
        quiche::multicast::StreamDeliveryMetricsSnapshot {
            direct_fallback_ranges_total: 3,
            direct_fallback_bytes_total: 25,
            ..Default::default()
        }
    );

    send_client_control(
        &mut first,
        &mut first_runtime,
        quiche::multicast::Frame::State(quiche::multicast::State {
            channel_id: channel_id.clone(),
            sequence: 2,
            state: quiche::multicast::ChannelState::Left,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: Vec::new(),
        }),
    );

    let fallback = publisher.prepare_stream(3, 27, true, b"fallback").unwrap();
    publisher.commit(fallback).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();
    deliver_server_flight(&mut first);
    deliver_server_flight(&mut second);

    assert_eq!(first.client.stream_recv(3, &mut out), Ok((17, true)));
    assert_eq!(&out[..17], b"green-gapfallback");
    assert_eq!(second.client.stream_recv(3, &mut out), Ok((8, true)));
    assert_eq!(&out[..8], b"fallback");
    assert_eq!(
        first.server.multicast_stream_recovery_pending(&channel_id),
        0
    );

    send_webtransport_stream_prefix(&mut first, 7, 11);
    send_webtransport_stream_prefix(&mut second, 7, 22);
    publisher.declare_stream(7).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();
    let mut renewed_limits = test_limits();
    renewed_limits.sequence = 2;
    send_client_control(
        &mut first,
        &mut first_runtime,
        quiche::multicast::Frame::Limits(renewed_limits),
    );
    deliver_server_flight(&mut first);
    send_client_control(
        &mut first,
        &mut first_runtime,
        quiche::multicast::Frame::State(quiche::multicast::State {
            channel_id: channel_id.clone(),
            sequence: 3,
            state: quiche::multicast::ChannelState::Joined,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: Vec::new(),
        }),
    );

    let rejoin_probe = publisher
        .prepare_stream(7, 10, false, b"rejoin-probe")
        .unwrap();
    publisher.commit(rejoin_probe).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();
    deliver_server_flight(&mut first);
    deliver_server_flight(&mut second);
    assert_eq!(first.client.stream_recv(7, &mut out), Ok((12, false)));
    assert_eq!(&out[..12], b"rejoin-probe");
    assert_eq!(second.client.stream_recv(7, &mut out), Ok((12, false)));
    assert_eq!(&out[..12], b"rejoin-probe");

    send_client_control(
        &mut first,
        &mut first_runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 3,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );
    assert_eq!(
        first.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::Viable)
    );

    let multicast_again = publisher
        .prepare_stream(7, 22, true, b"green-again")
        .unwrap();
    publisher.commit(multicast_again).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();
    deliver_server_flight(&mut first);
    deliver_server_flight(&mut second);
    assert_eq!(
        first.client.stream_recv(7, &mut out),
        Err(quiche::Error::Done)
    );
    assert_eq!(second.client.stream_recv(7, &mut out), Ok((11, true)));
    assert_eq!(&out[..11], b"green-again");
}

#[test]
fn server_stream_publisher_aggregates_exact_ack_gap_recovery() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);

    let channel_id = vec![1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.set_reordering_threshold(1).unwrap();
    publisher.declare_stream(3).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let baseline = publisher.prepare_stream(3, 10, false, b"a").unwrap();
    publisher.commit(baseline).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );

    for (offset, data, fin) in [
        (11, &b"one"[..], false),
        (14, &b"two"[..], false),
        (17, &b"three"[..], true),
    ] {
        let publication = publisher.prepare_stream(3, offset, fin, data).unwrap();
        publisher.commit(publication).unwrap();
    }
    runtime.process_writes(&mut pipe.server).unwrap();

    let ack = quiche::multicast::Ack {
        channel_id: channel_id.clone(),
        largest_acknowledged: 3,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: Vec::new(),
        ecn_counts: None,
    };
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Ack(ack.clone()),
    );
    let after_recovery = publisher.delivery_metrics_snapshot();
    assert_eq!(
        after_recovery,
        quiche::multicast::StreamDeliveryMetricsSnapshot {
            direct_fallback_ranges_total: 1,
            direct_fallback_bytes_total: 1,
            ack_gap_recovery_ranges_total: 2,
            ack_gap_recovery_bytes_total: 6,
            ..Default::default()
        }
    );

    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Ack(ack),
    );
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id,
            largest_acknowledged: 2,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );
    assert_eq!(publisher.delivery_metrics_snapshot(), after_recovery);
}

#[test]
fn server_stream_timeout_and_close_fold_retained_backlog_once() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);

    let channel_id = vec![1, 2, 3, 4];
    let mut config = test_stream_control_config();
    config.announce.max_ack_delay_ms = 0;
    let publisher = ServerStreamPublisher::new(config).unwrap();
    publisher.declare_stream(3).unwrap();
    let attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let baseline = publisher.prepare_stream(3, 10, false, b"a").unwrap();
    publisher.commit(baseline).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );

    let held = publisher.prepare_stream(3, 11, true, b"timeout").unwrap();
    publisher.commit(held).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    pipe.server.on_timeout();
    assert_eq!(
        pipe.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::TimedOut)
    );

    runtime.on_conn_close(&pipe.server);
    let after_close = publisher.delivery_metrics_snapshot();
    assert_eq!(
        after_close,
        quiche::multicast::StreamDeliveryMetricsSnapshot {
            direct_fallback_ranges_total: 1,
            direct_fallback_bytes_total: 1,
            fallback_reentry_ranges_total: 1,
            fallback_reentry_bytes_total: 7,
            ..Default::default()
        }
    );
    runtime.on_conn_close(&pipe.server);
    drop(attachment);
    assert_eq!(publisher.delivery_metrics_snapshot(), after_close);
}

#[test]
fn server_stream_retirement_folds_retained_backlog_once() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);

    let channel_id = vec![1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let baseline = publisher.prepare_stream(3, 10, false, b"a").unwrap();
    publisher.commit(baseline).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );

    let retained = publisher.prepare_stream(3, 11, true, b"retired").unwrap();
    publisher.commit(retained).unwrap();
    publisher
        .retire(quiche::multicast::Retire {
            channel_id,
            after_packet_number: 1,
        })
        .unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let after_retirement = publisher.delivery_metrics_snapshot();
    assert_eq!(
        after_retirement,
        quiche::multicast::StreamDeliveryMetricsSnapshot {
            direct_fallback_ranges_total: 1,
            direct_fallback_bytes_total: 1,
            fallback_reentry_ranges_total: 1,
            fallback_reentry_bytes_total: 7,
            ..Default::default()
        }
    );
    runtime.process_writes(&mut pipe.server).unwrap();
    runtime.on_conn_close(&pipe.server);
    assert_eq!(publisher.delivery_metrics_snapshot(), after_retirement);
}

#[test]
fn server_stream_publishers_keep_channel_metrics_isolated() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);
    send_webtransport_stream_prefix(&mut pipe, 7, 22);

    let first = ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    let mut second_config = test_stream_control_config();
    second_config.announce.channel_id = vec![5, 6, 7, 8];
    second_config.key.channel_id = vec![5, 6, 7, 8];
    let second = ServerStreamPublisher::new(second_config).unwrap();
    first.declare_stream(3).unwrap();
    second.declare_stream(7).unwrap();
    let _first_attachment = first.attach(&controller).unwrap();
    let _second_attachment = second.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let first_publication = first.prepare_stream(3, 10, true, b"first").unwrap();
    first.commit(first_publication).unwrap();
    let second_publication =
        second.prepare_stream(7, 10, true, b"second").unwrap();
    second.commit(second_publication).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(
        first.delivery_metrics_snapshot(),
        quiche::multicast::StreamDeliveryMetricsSnapshot {
            direct_fallback_ranges_total: 1,
            direct_fallback_bytes_total: 5,
            ..Default::default()
        }
    );
    assert_eq!(
        second.delivery_metrics_snapshot(),
        quiche::multicast::StreamDeliveryMetricsSnapshot {
            direct_fallback_ranges_total: 1,
            direct_fallback_bytes_total: 6,
            ..Default::default()
        }
    );
}

#[test]
fn server_stream_reset_and_attachment_teardown_are_connection_local() {
    let settings = test_settings();
    let mut first = test_stream_pipe(&settings);
    let mut second = test_stream_pipe(&settings);
    let (mut first_runtime, first_controller) = test_stream_control_runtime();
    let (mut second_runtime, second_controller) = test_stream_control_runtime();
    first_runtime
        .on_conn_established(&mut first.server)
        .unwrap();
    second_runtime
        .on_conn_established(&mut second.server)
        .unwrap();
    send_webtransport_stream_prefix(&mut first, 3, 11);
    send_webtransport_stream_prefix(&mut second, 3, 22);

    let channel_id = vec![1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let first_attachment = publisher.attach(&first_controller).unwrap();
    let second_attachment = publisher.attach(&second_controller).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();

    let baseline = publisher.prepare_stream(3, 10, false, b"base").unwrap();
    publisher.commit(baseline).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();
    deliver_server_flight(&mut first);
    deliver_server_flight(&mut second);

    let mut out = [0; 32];
    assert_eq!(first.client.stream_recv(3, &mut out), Ok((4, false)));
    assert_eq!(second.client.stream_recv(3, &mut out), Ok((4, false)));

    send_client_control(
        &mut first,
        &mut first_runtime,
        quiche::multicast::Frame::Ack(quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
    );

    let held = publisher.prepare_stream(3, 14, false, b"held").unwrap();
    publisher.commit(held).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();
    assert_eq!(
        first.server.multicast_stream_recovery_pending(&channel_id),
        1
    );

    first
        .server
        .stream_shutdown(3, quiche::Shutdown::Write, 42)
        .unwrap();
    assert_eq!(
        first.server.multicast_stream_recovery_pending(&channel_id),
        0
    );
    deliver_server_flight(&mut first);
    deliver_server_flight(&mut second);
    assert_eq!(
        first.client.stream_recv(3, &mut out),
        Err(quiche::Error::StreamReset(42))
    );
    assert_eq!(second.client.stream_recv(3, &mut out), Ok((4, false)));
    assert_eq!(&out[..4], b"held");

    drop(first_attachment);
    assert_eq!(publisher.attached_connections().unwrap(), 1);
    let remaining = publisher.prepare_stream(3, 18, true, b"other").unwrap();
    publisher.commit(remaining).unwrap();
    first_runtime.process_writes(&mut first.server).unwrap();
    second_runtime.process_writes(&mut second.server).unwrap();
    deliver_server_flight(&mut second);
    assert_eq!(second.client.stream_recv(3, &mut out), Ok((5, true)));
    assert_eq!(&out[..5], b"other");

    drop(second_attachment);
    assert_eq!(publisher.attached_connections().unwrap(), 0);
}

#[test]
fn server_stream_fallback_survives_mc_limits_that_forbid_joining() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);

    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    let mut limits = test_limits();
    limits.max_joined_count = 0;
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(limits),
    );
    deliver_server_flight(&mut pipe);
    assert_no_queued_join(&mut pipe.client);

    let publication = publisher
        .prepare_stream(3, 10, true, b"fallback only")
        .unwrap();
    publisher.commit(publication).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);

    let mut out = [0; 32];
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((13, true)));
    assert_eq!(&out[..13], b"fallback only");
}

#[test]
fn server_stream_auto_join_waits_for_quic_stream_credit() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    let max_streams_uni = pipe.server.peer_max_streams_uni();
    let blocked_stream_id = (max_streams_uni << 2) | 0x3;

    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(test_limits()),
    );

    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(blocked_stream_id).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);

    assert_no_queued_join(&mut pipe.client);
    assert!(!runtime.channels[&[1, 2, 3, 4][..]].join_sent);

    let publication = publisher
        .prepare_stream(blocked_stream_id, 0, false, b"wait for credit")
        .unwrap();
    publisher.commit(publication).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(runtime.pending_stream_publications.len(), 1);
    assert!(runtime.pending_stream_publications.is_retry_blocked());
    assert_eq!(pipe.server.multicast_send_queue_len(), 0);
    assert_eq!(
        publisher.delivery_metrics_snapshot(),
        quiche::multicast::StreamDeliveryMetricsSnapshot::default()
    );
}

#[test]
fn server_stream_publisher_relays_key_rotation_and_retirement() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();

    let channel_id = vec![1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);
    while pipe.client.multicast_recv().is_ok() {}

    assert!(matches!(
        publisher.update_key(quiche::multicast::Key {
            channel_id: channel_id.clone(),
            key_sequence: 2,
            from_packet_number: 5,
            secret: vec![0xdd; 16],
        }),
        Err(ServerStreamPublisherError::InvalidState)
    ));
    let rotated = quiche::multicast::Key {
        channel_id: channel_id.clone(),
        key_sequence: 2,
        from_packet_number: 0,
        secret: vec![0xdd; 16],
    };
    publisher.update_key(rotated.clone()).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);
    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Key(rotated))
    );

    let retire = quiche::multicast::Retire {
        channel_id: channel_id.clone(),
        after_packet_number: 0,
    };
    publisher.retire(retire.clone()).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);
    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Retire(retire))
    );
    assert_eq!(
        pipe.server.multicast_probe_status(&channel_id),
        Some(quiche::multicast::ProbeStatus::Retired)
    );
    assert!(matches!(
        publisher.prepare_stream(3, 0, false, b"retired"),
        Err(ServerStreamPublisherError::Retired)
    ));
}

#[test]
fn server_stream_barriers_do_not_wait_for_another_blocked_channel() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 7, 22);

    let blocked_channel = vec![1, 2, 3, 4];
    let healthy_channel = vec![5, 6, 7, 8];
    let blocked =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    let mut healthy_config = test_stream_control_config();
    healthy_config.announce.channel_id = healthy_channel.clone();
    healthy_config.key.channel_id = healthy_channel.clone();
    let healthy = ServerStreamPublisher::new(healthy_config).unwrap();
    blocked.declare_stream(3).unwrap();
    healthy.declare_stream(7).unwrap();
    let _blocked_attachment = blocked.attach(&controller).unwrap();
    let _healthy_attachment = healthy.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);
    while pipe.client.multicast_recv().is_ok() {}

    let blocked_publication = blocked
        .prepare_stream(3, 10, false, b"missing prefix")
        .unwrap();
    blocked.commit(blocked_publication).unwrap();
    let healthy_publication = healthy
        .prepare_stream(7, 10, true, b"healthy channel")
        .unwrap();
    healthy.commit(healthy_publication).unwrap();
    healthy
        .retire(quiche::multicast::Retire {
            channel_id: healthy_channel.clone(),
            after_packet_number: 0,
        })
        .unwrap();

    runtime.process_writes(&mut pipe.server).unwrap();

    assert!(runtime
        .pending_stream_publications
        .contains_channel(&blocked_channel));
    assert!(!runtime
        .pending_stream_publications
        .contains_channel(&healthy_channel));
    assert!(runtime.channels[&healthy_channel[..]].retired);
    assert!(!runtime.channels[&healthy_channel[..]].stream_publisher);

    deliver_server_flight(&mut pipe);
    let mut out = [0; 32];
    assert_eq!(
        pipe.client.stream_recv(7, &mut out),
        Ok((b"healthy channel".len(), true))
    );
    assert_eq!(&out[..b"healthy channel".len()], b"healthy channel");
}

#[test]
fn server_stream_integrity_precedes_following_key_barrier() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);

    let channel_id = vec![1, 2, 3, 4];
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);
    while pipe.client.multicast_recv().is_ok() {}

    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(test_limits()),
    );
    deliver_server_flight(&mut pipe);
    while pipe.client.multicast_recv().is_ok() {}

    let publication = publisher
        .prepare_stream(3, 10, false, b"before rotation")
        .unwrap();
    let integrity = publication.integrity().clone();
    publisher.commit(publication).unwrap();
    let rotated = quiche::multicast::Key {
        channel_id,
        key_sequence: 2,
        from_packet_number: 1,
        secret: vec![0xdd; 16],
    };
    publisher.update_key(rotated.clone()).unwrap();

    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);

    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Integrity(integrity))
    );
    assert_eq!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Key(rotated))
    );
}

#[test]
fn server_stream_publisher_compacts_finished_streams_and_rejects_reuse() {
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();

    for sequence in 0..100 {
        let stream_id = (sequence << 2) | 0x3;
        let publication = publisher
            .prepare_stream(stream_id, 10, true, b"finished")
            .unwrap();
        publisher.commit(publication).unwrap();
    }

    let profile = publisher.test_profile().unwrap();
    assert_eq!(profile.tracked_streams, 0);
    assert_eq!(profile.finished_streams, 100);
    assert_eq!(profile.finished_stream_storage_units, 1);
    assert_eq!(publisher.next_stream_offset(3).unwrap(), None);
    assert!(matches!(
        publisher.prepare_stream(3, 10, false, b"reuse"),
        Err(ServerStreamPublisherError::StreamFinished { stream_id: 3 })
    ));
}

#[test]
fn server_stream_late_attachment_waits_for_unicast_catch_up() {
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let past = publisher.prepare_stream(3, 10, false, b"past").unwrap();
    publisher.commit(past).unwrap();
    assert_eq!(publisher.next_stream_offset(3).unwrap(), Some(14));

    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);
    let _attachment = publisher.attach(&controller).unwrap();

    let live = publisher.prepare_stream(3, 14, true, b"live").unwrap();
    publisher.commit(live).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    assert_eq!(runtime.pending_stream_publications.len(), 1);
    assert!(runtime.pending_stream_publications.is_retry_blocked());

    assert_eq!(pipe.server.stream_send(3, b"past", false), Ok(4));
    runtime.process_writes(&mut pipe.server).unwrap();
    assert!(runtime.pending_stream_publications.is_empty());
    deliver_server_flight(&mut pipe);

    let mut out = [0; 16];
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((8, true)));
    assert_eq!(&out[..8], b"pastlive");
}

#[test]
fn server_stream_retirement_waits_for_prior_recovery_registration() {
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();
    publisher.declare_stream(3).unwrap();
    let past = publisher.prepare_stream(3, 10, false, b"past").unwrap();
    publisher.commit(past).unwrap();

    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    send_webtransport_stream_prefix(&mut pipe, 3, 11);
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::Limits(test_limits()),
    );
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);
    while pipe.client.multicast_recv().is_ok() {}
    send_client_control(
        &mut pipe,
        &mut runtime,
        quiche::multicast::Frame::State(quiche::multicast::State {
            channel_id: vec![1, 2, 3, 4],
            sequence: 1,
            state: quiche::multicast::ChannelState::Joined,
            reason_scope: quiche::multicast::StateReasonScope::Transport,
            reason_code: quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: Vec::new(),
        }),
    );

    let live = publisher.prepare_stream(3, 14, true, b"live").unwrap();
    publisher.commit(live).unwrap();
    publisher
        .retire(quiche::multicast::Retire {
            channel_id: vec![1, 2, 3, 4],
            after_packet_number: 1,
        })
        .unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(runtime.pending_stream_publications.len(), 1);
    assert!(!runtime.channels[&[1, 2, 3, 4][..]].retired);
    assert!(runtime.pending_stream_publications.is_retry_blocked());

    assert_eq!(pipe.server.stream_send(3, b"past", false), Ok(4));
    runtime.process_writes(&mut pipe.server).unwrap();
    deliver_server_flight(&mut pipe);

    assert!(matches!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Integrity(_))
    ));
    assert!(matches!(
        pipe.client.multicast_recv(),
        Ok(quiche::multicast::Frame::Retire(_))
    ));
    let mut out = [0; 16];
    assert_eq!(pipe.client.stream_recv(3, &mut out), Ok((8, true)));
    assert_eq!(&out[..8], b"pastlive");
}
