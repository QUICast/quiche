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
fn client_maintenance_budget_is_aggregate_and_fair() {
    const CHANNELS: usize = 300;
    const BUDGET: usize = 32;

    let mut settings = test_settings();
    settings.transport_params.limits.max_channel_ids = CHANNELS as u64;
    settings.max_joined_channels = CHANNELS as u64;
    let (event_sender, _events, _) = test_client_event_channel();
    let limits = RuntimeLimits {
        max_work_per_call: BUDGET,
        ..RuntimeLimits::default()
    };
    let mut runtime = ClientRuntime::with_backend_and_limits(
        settings.clone(),
        event_sender,
        FakeJoinBackend::default(),
        limits,
    );

    for index in 0..CHANNELS {
        let channel_id = (index as u32).to_be_bytes().to_vec();
        let mut announce = test_ipv4_announce();
        announce.channel_id = channel_id.clone();
        let mut receiver = quiche::multicast::ChannelReceiveState::<
            PacketWithMetadata,
        >::new(announce.clone())
        .unwrap();
        receiver
            .insert_integrity(quiche::multicast::Integrity {
                channel_id: channel_id.clone(),
                packet_number_start: 0,
                packet_hash_count: Some(257),
                packet_hashes: vec![0; 257 * 32],
            })
            .unwrap();
        assert!(receiver.has_pending_work());

        let mut channel = Channel::default();
        channel.announce = Some(announce);
        channel.receive_state = Some(receiver);
        runtime.channels.insert(channel_id, channel);
    }

    let mut pipe = test_pipe(&settings);
    let max_passes = (CHANNELS * 4).div_ceil(BUDGET);
    let mut passes = 0;
    while runtime.channels.values().any(|channel| {
        channel
            .receive_state
            .as_ref()
            .is_some_and(|receiver| receiver.has_pending_work())
    }) {
        runtime.process_reads(&mut pipe.client).unwrap();
        passes += 1;
        assert!(
            runtime.callback_read_work_last_call <= BUDGET,
            "one complete callback exceeded the aggregate work budget"
        );
        assert!(passes <= max_passes, "maintenance failed to converge");
    }

    assert!(runtime.channels.values().all(|channel| {
        !channel.receive_state.as_ref().unwrap().has_pending_work()
    }));
    assert_eq!(
        runtime.receiver_maintenance_cursor,
        Some(((CHANNELS - 1) as u32).to_be_bytes().to_vec())
    );
}

#[test]
fn client_callbacks_share_one_budget_across_adversarial_phase_backlog() {
    let (mut runtime, mut pipe, _events, announce) = joined_client_runtime();
    let channel_id = announce.channel_id.clone();
    runtime.limits.max_work_per_call = 4;
    runtime.read_work_cursor = 0;

    runtime
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .receive_state
        .as_mut()
        .unwrap()
        .insert_integrity_with_budget(
            quiche::multicast::Integrity {
                channel_id: channel_id.clone(),
                packet_number_start: 100,
                packet_hash_count: Some(2),
                packet_hashes: vec![0; 64],
            },
            1,
            1,
        )
        .unwrap();
    runtime
        .ingress_sender
        .try_send(IngressEvent::Overload {
            channel_id: vec![9],
            retained_bytes: 1,
            max_retained_bytes: 1,
        })
        .unwrap();
    assert!(runtime.transfer_one_ingress());
    runtime
        .ingress_sender
        .try_send(IngressEvent::Overload {
            channel_id: vec![8],
            retained_bytes: 1,
            max_retained_bytes: 1,
        })
        .unwrap();

    let mut key = test_key(&channel_id);
    key.key_sequence = 2;
    key.from_packet_number = 100;
    pipe.server
        .multicast_send(quiche::multicast::Frame::Key(key))
        .unwrap();
    let flight = quiche::test_utils::emit_flight(&mut pipe.server).unwrap();
    quiche::test_utils::process_flight(&mut pipe.client, flight).unwrap();

    let work_before = runtime.channels[&channel_id]
        .receive_state
        .as_ref()
        .unwrap()
        .metrics_snapshot()
        .work_performed;
    assert_eq!(runtime.pending_ingress.len(), 1);
    assert_eq!(runtime.ingress_observer.stats().retained_items, 2);
    assert_eq!(pipe.client.multicast_recv_queue_len(), 1);

    runtime.process_reads(&mut pipe.client).unwrap();

    assert_eq!(runtime.callback_read_work_last_call, 4);
    assert!(
        runtime.channels[&channel_id]
            .receive_state
            .as_ref()
            .unwrap()
            .metrics_snapshot()
            .work_performed >
            work_before
    );
    assert_eq!(runtime.pending_ingress.len(), 1);
    assert_eq!(runtime.ingress_observer.stats().retained_items, 1);
    assert_eq!(pipe.client.multicast_recv_queue_len(), 0);

    for _ in 0..16 {
        if !runtime.has_pending_work() && !pipe.client.is_multicast_readable() {
            break;
        }
        runtime.process_reads(&mut pipe.client).unwrap();
        assert!(runtime.callback_read_work_last_call <= 4);
    }
    assert!(!runtime.has_pending_work());
    assert!(!pipe.client.is_multicast_readable());

    let (mut runtime, mut pipe, _events, announce) = joined_client_runtime();
    let channel_id = announce.channel_id.clone();
    runtime.limits.max_work_per_call = 5;
    runtime.write_work_cursor = 0;
    runtime
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .receive_state
        .as_mut()
        .unwrap()
        .insert_integrity_with_budget(
            quiche::multicast::Integrity {
                channel_id: channel_id.clone(),
                packet_number_start: 200,
                packet_hash_count: Some(2),
                packet_hashes: vec![0; 64],
            },
            1,
            1,
        )
        .unwrap();
    runtime
        .ingress_sender
        .try_send(IngressEvent::Overload {
            channel_id: vec![9],
            retained_bytes: 1,
            max_retained_bytes: 1,
        })
        .unwrap();
    assert!(runtime.transfer_one_ingress());
    runtime
        .ingress_sender
        .try_send(IngressEvent::Overload {
            channel_id: vec![8],
            retained_bytes: 1,
            max_retained_bytes: 1,
        })
        .unwrap();
    assert!(runtime
        .pending_control
        .push_back(PendingClientControl {
            frame: ClientControlFrame::Limits {
                frame: test_limits(),
                commit: Some(test_limits()),
            },
            blocked_since: None,
        })
        .is_ok());
    runtime
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .ack_state
        .record_packet(1);

    runtime.process_writes(&mut pipe.client).unwrap();

    assert_eq!(runtime.callback_write_work_last_call, 5);
    assert_eq!(runtime.pending_ingress.len(), 1);
    assert_eq!(runtime.ingress_observer.stats().retained_items, 1);
    assert!(runtime.pending_control.is_empty());
    assert!(!runtime.channels[&channel_id].ack_state.has_pending_ack());
}

fn seed_server_control_callback_backlog(
    runtime: &mut ServerControlRuntime,
    command_sender: &BoundedSender<ServerControlCommand>, pipe: &mut Pipe,
) {
    let publisher_channel_id = vec![2];
    let publisher_queue =
        Arc::new(server_stream::ServerStreamPublisherQueue::new(
            publisher_channel_id.clone(),
            server_stream::ServerStreamPublisherLimits::default(),
        ));
    publisher_queue.seal();
    runtime
        .channels
        .insert(publisher_channel_id, ServerControlChannel {
            stream_publisher: true,
            stream_publication_queue: Some(publisher_queue),
            ..ServerControlChannel::default()
        });

    let mut pending_announce = test_ipv4_announce();
    pending_announce.channel_id = vec![8];
    runtime
        .queue_command_back(ServerControlCommand::SendAnnounce {
            frame: pending_announce,
            cached: None,
        })
        .unwrap();
    let mut incoming_announce = test_ipv4_announce();
    incoming_announce.channel_id = vec![9];
    assert!(command_sender
        .try_send(ServerControlCommand::SendAnnounce {
            frame: incoming_announce,
            cached: None,
        })
        .is_ok());

    assert_eq!(pipe.server.stream_send(3, b"p", false), Ok(1));
    let publication_channel_id = vec![3];
    runtime
        .channels
        .entry(publication_channel_id.clone())
        .or_default();
    runtime
        .pending_stream_publications
        .push(Arc::new(server_stream::CommittedServerStreamPublication {
            packet_number: 0,
            integrity: quiche::multicast::Integrity {
                channel_id: publication_channel_id,
                packet_number_start: 0,
                packet_hash_count: Some(1),
                packet_hashes: vec![0xaa; 32],
            },
            frame: ServerStreamFrame {
                stream_id: 3,
                offset: 1,
                fin: false,
                data: Bytes::from_static(b"x"),
            },
        }))
        .unwrap();

    let due_channel_id = vec![5];
    runtime
        .store_stream_integrity_batch(
            due_channel_id.clone(),
            PendingStreamIntegrityBatch {
                frame: quiche::multicast::Integrity {
                    channel_id: due_channel_id,
                    packet_number_start: 0,
                    packet_hash_count: Some(1),
                    packet_hashes: vec![0xbb; 32],
                },
                hash_len: 32,
                deadline: Instant::now(),
            },
        )
        .unwrap();
    let mut pending_integrity = test_stream_integrity(0, 0xcc);
    pending_integrity.channel_id = vec![6];
    runtime.queue_integrity(pending_integrity).unwrap();

    assert_eq!(pipe.server.stream_send(7, b"p", false), Ok(1));
    pipe.server
        .multicast_stream_send(&[4], 0, 7, 1, b"m", false)
        .unwrap();
    pipe.server
        .multicast_probe_start(&[7], Duration::from_secs(1))
        .unwrap();
}

fn server_control_callback_backlog_drained(
    runtime: &ServerControlRuntime, pipe: &Pipe,
) -> bool {
    !runtime.has_pending_work() &&
        !pipe.server.is_multicast_stream_delivery_metrics_readable() &&
        !pipe.server.is_multicast_probe_readable() &&
        !pipe.server.is_multicast_readable()
}

#[test]
fn server_control_callbacks_share_one_budget_across_adversarial_backlog() {
    let limits = RuntimeLimits {
        max_work_per_call: 8,
        ..RuntimeLimits::default()
    };
    let (command_sender, command_receiver, _command_observer) =
        bounded_channel(limits.commands);
    let (event_sender, _events, _) = test_server_event_channel();
    let mut runtime = ServerControlRuntime::with_limits(
        ServerControlSettings::default(),
        event_sender,
        command_receiver,
        limits,
    );
    let mut pipe = test_stream_pipe(&test_settings());
    runtime.on_conn_established(&mut pipe.server).unwrap();
    seed_server_control_callback_backlog(
        &mut runtime,
        &command_sender,
        &mut pipe,
    );

    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(runtime.callback_write_work_last_call, 8);
    assert!(runtime.command_receiver.try_recv().is_err());
    assert!(runtime.pending_stream_integrity_batches.is_empty());
    assert_eq!(pipe.server.multicast_probe_queue_len(), 1);

    for _ in 0..64 {
        if server_control_callback_backlog_drained(&runtime, &pipe) {
            break;
        }
        runtime.process_reads(&mut pipe.server).unwrap();
        assert!(runtime.callback_read_work_last_call <= 8);
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.callback_write_work_last_call <= 8);
    }
    assert!(server_control_callback_backlog_drained(&runtime, &pipe));

    let limits = RuntimeLimits {
        max_work_per_call: 10,
        ..RuntimeLimits::default()
    };
    let (command_sender, command_receiver, _command_observer) =
        bounded_channel(limits.commands);
    let (event_sender, _events, _) = test_server_event_channel();
    let mut runtime = ServerControlRuntime::with_limits(
        ServerControlSettings::default(),
        event_sender,
        command_receiver,
        limits,
    );
    let mut pipe = test_stream_pipe(&test_settings());
    runtime.on_conn_established(&mut pipe.server).unwrap();
    seed_server_control_callback_backlog(
        &mut runtime,
        &command_sender,
        &mut pipe,
    );
    runtime.event_coalescer.queue_client_ack(
        &runtime.event_sender,
        quiche::multicast::Ack {
            channel_id: vec![10],
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        },
    );
    pipe.client
        .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
        .unwrap();
    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    runtime.process_reads(&mut pipe.server).unwrap();

    assert_eq!(runtime.callback_read_work_last_call, 10);
    assert!(runtime.command_receiver.try_recv().is_err());
    assert!(runtime
        .event_coalescer
        .last_client_acks
        .contains_key(&[10][..]));
    assert_eq!(
        runtime
            .event_coalescer
            .pending_client_acks
            .values()
            .map(VecDeque::len)
            .sum::<usize>(),
        1
    );
    assert!(runtime.pending_stream_integrity_batches.is_empty());
    assert_eq!(pipe.server.multicast_probe_queue_len(), 1);

    for _ in 0..64 {
        if server_control_callback_backlog_drained(&runtime, &pipe) {
            break;
        }
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.callback_write_work_last_call <= 10);
        runtime.process_reads(&mut pipe.server).unwrap();
        assert!(runtime.callback_read_work_last_call <= 10);
    }
    assert!(server_control_callback_backlog_drained(&runtime, &pipe));
}

#[derive(Default)]
enum ProbeTestAction {
    #[default]
    None,
    Start(Vec<u8>),
    Drain,
}

#[derive(Default)]
struct ProbeReadinessTestApp {
    established_action: ProbeTestAction,
    read_action: ProbeTestAction,
}

impl ProbeReadinessTestApp {
    fn apply_action(
        action: &mut ProbeTestAction, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        match std::mem::take(action) {
            ProbeTestAction::None => {},

            ProbeTestAction::Start(channel_id) => {
                qconn
                    .multicast_probe_start(&channel_id, Duration::from_secs(1))?;
            },

            ProbeTestAction::Drain => loop {
                match qconn.multicast_probe_recv() {
                    Ok(_) => {},
                    Err(quiche::Error::Done) => break,
                    Err(error) => return Err(error.into()),
                }
            },
        }

        Ok(())
    }
}

impl ApplicationOverQuic for ProbeReadinessTestApp {
    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection,
        _handshake_info: &crate::quic::HandshakeInfo,
    ) -> QuicResult<()> {
        Self::apply_action(&mut self.established_action, qconn)
    }

    fn should_act(&self) -> bool {
        true
    }

    fn wait_for_data(
        &mut self, _qconn: &mut QuicheConnection,
    ) -> impl Future<Output = QuicResult<()>> + Send {
        pending()
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        Self::apply_action(&mut self.read_action, qconn)
    }

    fn process_writes(
        &mut self, _qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        Ok(())
    }
}

#[tokio::test]
async fn server_control_driver_resyncs_inner_probe_creation() {
    const BUDGET: usize = 1;

    let app = ProbeReadinessTestApp {
        established_action: ProbeTestAction::Start(vec![1]),
        ..ProbeReadinessTestApp::default()
    };
    let limits = RuntimeLimits {
        max_work_per_call: BUDGET,
        ..RuntimeLimits::default()
    };
    let (mut driver, _controller) = ServerControlDriver::new_with_runtime_limits(
        app,
        ServerControlSettings::default(),
        limits,
    )
    .unwrap();
    let mut pipe = test_pipe(&test_settings());
    let handshake_info =
        crate::quic::HandshakeInfo::new(std::time::Instant::now(), None);

    driver
        .on_conn_established(&mut pipe.server, &handshake_info)
        .unwrap();

    assert!(pipe.server.is_multicast_probe_readable());
    assert!(driver.runtime.probe_read_pending);
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_millis(1),
            driver.wait_for_data(&mut pipe.server)
        )
        .await,
        Ok(Ok(()))
    ));

    driver.process_writes(&mut pipe.server).unwrap();
    assert_eq!(driver.runtime.callback_write_work_last_call, BUDGET);
    assert!(!pipe.server.is_multicast_probe_readable());
    assert!(!driver.runtime.probe_read_pending);

    driver.inner_mut().read_action = ProbeTestAction::Start(vec![2]);
    driver.process_reads(&mut pipe.server).unwrap();

    assert_eq!(driver.runtime.callback_read_work_last_call, 0);
    assert!(pipe.server.is_multicast_probe_readable());
    assert!(driver.runtime.probe_read_pending);
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_millis(1),
            driver.wait_for_data(&mut pipe.server)
        )
        .await,
        Ok(Ok(()))
    ));

    driver.process_writes(&mut pipe.server).unwrap();
    assert!(driver.runtime.callback_write_work_last_call <= BUDGET);
    assert!(!driver.runtime.probe_read_pending);

    pipe.server
        .multicast_probe_start(&[3], Duration::from_secs(1))
        .unwrap();
    assert!(!driver.runtime.probe_read_pending);
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_millis(1),
            driver.wait_for_data(&mut pipe.server)
        )
        .await,
        Ok(Ok(()))
    ));
}

#[tokio::test]
async fn server_control_driver_clears_probe_readiness_after_inner_drain() {
    const BUDGET: usize = 1;

    let app = ProbeReadinessTestApp {
        read_action: ProbeTestAction::Drain,
        ..ProbeReadinessTestApp::default()
    };
    let limits = RuntimeLimits {
        max_work_per_call: BUDGET,
        ..RuntimeLimits::default()
    };
    let (mut driver, _controller) = ServerControlDriver::new_with_runtime_limits(
        app,
        ServerControlSettings::default(),
        limits,
    )
    .unwrap();
    let mut pipe = test_pipe(&test_settings());
    let handshake_info =
        crate::quic::HandshakeInfo::new(std::time::Instant::now(), None);
    driver
        .on_conn_established(&mut pipe.server, &handshake_info)
        .unwrap();

    pipe.server
        .multicast_probe_start(&[1], Duration::from_secs(1))
        .unwrap();
    pipe.client
        .multicast_send(quiche::multicast::Frame::Limits(test_limits()))
        .unwrap();
    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    driver.process_reads(&mut pipe.server).unwrap();

    assert_eq!(driver.runtime.callback_read_work_last_call, BUDGET);
    assert_eq!(pipe.server.multicast_probe_queue_len(), 0);
    assert!(!driver.runtime.probe_read_pending);
    assert!(!driver.runtime.has_pending_work());
    assert!(tokio::time::timeout(
        Duration::from_millis(1),
        driver.wait_for_data(&mut pipe.server)
    )
    .await
    .is_err());
}

#[tokio::test]
async fn server_control_probe_backlog_keeps_wait_path_runnable() {
    const BUDGET: usize = 2;
    const PROBE_EVENTS: u8 = 5;

    let limits = RuntimeLimits {
        max_work_per_call: BUDGET,
        ..RuntimeLimits::default()
    };
    let (_command_sender, command_receiver, _command_observer) =
        bounded_channel(limits.commands);
    let (event_sender, mut events, _) = test_server_event_channel();
    let mut runtime = ServerControlRuntime::with_limits(
        ServerControlSettings::default(),
        event_sender,
        command_receiver,
        limits,
    );
    let mut pipe = test_pipe(&test_settings());
    runtime.on_conn_established(&mut pipe.server).unwrap();

    for channel_id in 1..=PROBE_EVENTS {
        pipe.server
            .multicast_probe_start(&[channel_id], Duration::from_secs(1))
            .unwrap();
    }
    assert!(!runtime.probe_read_pending);
    assert_eq!(
        pipe.server.multicast_probe_queue_len(),
        usize::from(PROBE_EVENTS)
    );

    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(runtime.callback_write_work_last_call, BUDGET);
    assert_eq!(
        pipe.server.multicast_probe_queue_len(),
        usize::from(PROBE_EVENTS) - BUDGET
    );
    assert!(runtime.probe_read_pending);
    assert!(runtime.has_pending_work());

    let wait = async {
        if runtime.has_pending_work() {
            Ok(())
        } else {
            runtime.wait_for_work().await
        }
    };
    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(1), wait).await,
        Ok(Ok(()))
    ));

    while pipe.server.is_multicast_probe_readable() {
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.callback_write_work_last_call <= BUDGET);
    }
    assert_eq!(pipe.server.multicast_probe_queue_len(), 0);
    assert!(!runtime.probe_read_pending);
    assert!(!runtime.has_pending_work());

    let mut delivered = 0;
    while let Ok(event) = events.try_recv() {
        if matches!(event, ServerEvent::ProbeStatusChanged(_)) {
            delivered += 1;
        }
    }
    assert_eq!(delivered, usize::from(PROBE_EVENTS));
}

fn publishing_server_runtime(
    max_work_per_call: usize,
) -> (
    ServerRuntime<FakePublishBackend>,
    BoundedSender<ServerCommand>,
    ServerEventStream,
    Pipe,
) {
    let limits = RuntimeLimits {
        max_work_per_call,
        ..RuntimeLimits::default()
    };
    let (command_sender, command_receiver, _) = bounded_channel(limits.commands);
    let (event_sender, events, _) = test_server_event_channel();
    let mut runtime = ServerRuntime::with_backend_and_limits(
        test_server_settings(),
        event_sender,
        command_receiver,
        FakePublishBackend::default(),
        limits,
    );
    let mut pipe = test_pipe(&test_settings());
    runtime.on_conn_established(&mut pipe.server).unwrap();

    (runtime, command_sender, events, pipe)
}

#[test]
fn publishing_server_callbacks_share_one_budget_across_adversarial_backlog() {
    let (mut runtime, command_sender, _events, mut pipe) =
        publishing_server_runtime(5);
    let channel_id = vec![1, 2, 3, 4];
    let mut first_integrity = test_stream_integrity(10, 0xaa);
    first_integrity.channel_id = channel_id.clone();
    assert!(command_sender
        .try_send(ServerCommand::RelayIntegrity {
            frame: first_integrity,
        })
        .is_ok());
    assert!(runtime.transfer_one_server_command());
    let mut second_integrity = test_stream_integrity(11, 0xbb);
    second_integrity.channel_id = channel_id.clone();
    assert!(command_sender
        .try_send(ServerCommand::RelayIntegrity {
            frame: second_integrity,
        })
        .is_ok());
    runtime
        .queue_server_control(ServerPendingControl::Join(
            quiche::multicast::Join {
                channel_id: channel_id.clone(),
                mc_limits_sequence: 0,
                mc_state_sequence: 0,
                mc_key_sequence: 1,
            },
        ))
        .unwrap();
    let mut publication_integrity = test_stream_integrity(12, 0xcc);
    publication_integrity.channel_id = channel_id.clone();
    runtime
        .queue_publication(PendingPublication {
            channel_id: channel_id.clone(),
            packet: vec![1, 2, 3],
            packet_number: 12,
            integrity: publication_integrity,
        })
        .unwrap();
    let mut pending_integrity = test_stream_integrity(13, 0xdd);
    pending_integrity.channel_id = channel_id.clone();
    runtime.queue_integrity(pending_integrity).unwrap();

    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(runtime.callback_write_work_last_call, 5);
    assert!(runtime.command_receiver.try_recv().is_err());
    for _ in 0..32 {
        if !runtime.has_pending_work() {
            break;
        }
        runtime.process_writes(&mut pipe.server).unwrap();
        assert!(runtime.callback_write_work_last_call <= 5);
    }
    assert!(!runtime.has_pending_work());

    let (mut runtime, _command_sender, _events, mut pipe) =
        publishing_server_runtime(3);
    runtime.event_coalescer.queue_client_ack(
        &runtime.event_sender,
        quiche::multicast::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        },
    );
    runtime
        .queue_server_control(ServerPendingControl::Join(
            quiche::multicast::Join {
                channel_id: channel_id.clone(),
                mc_limits_sequence: 0,
                mc_state_sequence: 0,
                mc_key_sequence: 1,
            },
        ))
        .unwrap();
    pipe.client
        .multicast_send(quiche::multicast::Frame::State(
            quiche::multicast::State {
                channel_id,
                sequence: 1,
                state: quiche::multicast::ChannelState::DeclinedJoin,
                reason_scope: quiche::multicast::StateReasonScope::Transport,
                reason_code: STATE_REASON_UNSPECIFIED_OTHER,
                reason_phrase: Vec::new(),
            },
        ))
        .unwrap();
    let flight = quiche::test_utils::emit_flight(&mut pipe.client).unwrap();
    quiche::test_utils::process_flight(&mut pipe.server, flight).unwrap();

    runtime.process_reads(&mut pipe.server).unwrap();

    assert_eq!(runtime.callback_read_work_last_call, 3);
    assert!(!runtime.event_coalescer.has_pending_client_acks());
    assert!(runtime.pending_controls.is_empty());
    assert!(!pipe.server.is_multicast_readable());
}

#[test]
fn publisher_staging_budget_is_aggregate_and_fair() {
    const CHANNELS: usize = 300;
    const BUDGET: usize = 32;

    let limits = RuntimeLimits {
        max_work_per_call: BUDGET,
        ..RuntimeLimits::default()
    };
    let (_command_sender, command_receiver, _) = bounded_channel(limits.commands);
    let (event_sender, _events, _) = test_server_event_channel();
    let mut runtime = ServerControlRuntime::with_limits(
        ServerControlSettings::default(),
        event_sender,
        command_receiver,
        limits,
    );

    for index in 0..CHANNELS {
        let channel_id = (index as u32).to_be_bytes().to_vec();
        let queue = Arc::new(server_stream::ServerStreamPublisherQueue::new(
            channel_id.clone(),
            server_stream::ServerStreamPublisherLimits::default(),
        ));
        queue.seal();
        runtime.channels.insert(channel_id, ServerControlChannel {
            stream_publication_queue: Some(queue),
            ..ServerControlChannel::default()
        });
    }

    let settings = test_settings();
    let mut pipe = test_pipe(&settings);
    let max_passes = (CHANNELS * 4).div_ceil(BUDGET);
    let mut passes = 0;
    while runtime.channels.values().any(|channel| {
        channel
            .stream_publication_queue
            .as_ref()
            .is_some_and(|queue| queue.has_pending())
    }) {
        runtime.process_writes(&mut pipe.server).unwrap();
        passes += 1;
        assert!(
            runtime.callback_write_work_last_call <= BUDGET,
            "one complete callback exceeded the aggregate work budget"
        );
        assert!(passes <= max_passes, "publisher staging starved");
    }

    assert!(runtime.channels.values().all(|channel| {
        channel.stream_publication_queue.is_none() ||
            !channel
                .stream_publication_queue
                .as_ref()
                .unwrap()
                .has_pending()
    }));
    assert!(runtime.publisher_stage_cursor.is_some());
}

#[test]
#[ignore = "release-mode aggregate scheduler scaling probe"]
fn aggregate_scheduler_scaling_release_probe() {
    const BUDGET: usize = 256;

    for active_channels in [1_usize, 128, 1024] {
        let mut settings = test_settings();
        settings.transport_params.limits.max_channel_ids = active_channels as u64;
        settings.max_joined_channels = active_channels as u64;
        let (event_sender, _events, _) = test_client_event_channel();
        let limits = RuntimeLimits {
            max_work_per_call: BUDGET,
            ..RuntimeLimits::default()
        };
        let mut runtime = ClientRuntime::with_backend_and_limits(
            settings.clone(),
            event_sender,
            FakeJoinBackend::default(),
            limits,
        );

        for index in 0..active_channels {
            let channel_id = (index as u32).to_be_bytes().to_vec();
            let mut announce = test_ipv4_announce();
            announce.channel_id = channel_id.clone();
            let receiver_limits = quiche::multicast::ChannelReceiveLimits {
                max_work_per_call: 1,
                ..quiche::multicast::ChannelReceiveLimits::default()
            };
            let mut receiver = quiche::multicast::ChannelReceiveState::<
                PacketWithMetadata,
            >::with_limits(
                announce.clone(), receiver_limits
            )
            .unwrap();
            receiver
                .insert_integrity(quiche::multicast::Integrity {
                    channel_id: channel_id.clone(),
                    packet_number_start: 0,
                    packet_hash_count: Some(2),
                    packet_hashes: vec![0; 2 * 32],
                })
                .unwrap();
            let mut channel = Channel::default();
            channel.announce = Some(announce);
            channel.receive_state = Some(receiver);
            runtime.channels.insert(channel_id, channel);
        }

        let mut pipe = test_pipe(&settings);
        let started = Instant::now();
        let mut calls = 0_usize;
        let mut peak_work = 0_usize;
        while runtime.channels.values().any(|channel| {
            channel
                .receive_state
                .as_ref()
                .is_some_and(|receiver| receiver.has_pending_work())
        }) {
            runtime.process_reads(&mut pipe.client).unwrap();
            calls += 1;
            peak_work = peak_work.max(runtime.callback_read_work_last_call);
            assert!(runtime.callback_read_work_last_call <= BUDGET);
        }
        let elapsed = started.elapsed();
        println!(
            "client_process_reads active={active_channels} calls={calls} \
                 total_us={} per_call_us={} peak_work={peak_work}",
            elapsed.as_micros(),
            elapsed.as_micros() / calls.max(1) as u128,
        );

        let (_command_sender, command_receiver, _) =
            bounded_channel(limits.commands);
        let (event_sender, _events, _) = test_server_event_channel();
        let mut runtime = ServerControlRuntime::with_limits(
            ServerControlSettings::default(),
            event_sender,
            command_receiver,
            limits,
        );
        for index in 0..active_channels {
            let channel_id = (index as u32).to_be_bytes().to_vec();
            let queue = Arc::new(server_stream::ServerStreamPublisherQueue::new(
                channel_id.clone(),
                server_stream::ServerStreamPublisherLimits::default(),
            ));
            queue.seal();
            runtime.channels.insert(channel_id, ServerControlChannel {
                stream_publication_queue: Some(queue),
                ..ServerControlChannel::default()
            });
        }

        let started = Instant::now();
        let mut calls = 0_usize;
        let mut peak_work = 0_usize;
        while !runtime.pending_commands.is_empty() ||
            runtime.channels.values().any(|channel| {
                channel
                    .stream_publication_queue
                    .as_ref()
                    .is_some_and(|queue| queue.has_pending())
            })
        {
            runtime.process_writes(&mut pipe.server).unwrap();
            calls += 1;
            peak_work = peak_work.max(runtime.callback_write_work_last_call);
            assert!(runtime.callback_write_work_last_call <= BUDGET);
        }
        let elapsed = started.elapsed();
        println!(
            "server_process_writes active={active_channels} calls={calls} \
                 total_us={} per_call_us={} peak_work={peak_work}",
            elapsed.as_micros(),
            elapsed.as_micros() / calls.max(1) as u128,
        );
    }
}

#[test]
fn tokio_settings_and_explicit_controls_validate_before_admission() {
    let invalid = 1 << 62;

    assert!(Instant::now().checked_add(Duration::MAX).is_none());
    let runtime_limits = RuntimeLimits {
        control_retry_delay: Duration::MAX,
        ..RuntimeLimits::default()
    };
    assert!(matches!(
        ClientDriver::new_with_runtime_limits(
            (),
            test_settings(),
            runtime_limits,
        ),
        Err(RuntimeLimitsError::UnrepresentableControlRetryDelay)
    ));
    let runtime_limits = RuntimeLimits {
        control_backpressure_timeout: Duration::MAX,
        ..RuntimeLimits::default()
    };
    assert!(matches!(
        ClientDriver::new_with_runtime_limits(
            (),
            test_settings(),
            runtime_limits,
        ),
        Err(RuntimeLimitsError::UnrepresentableControlBackpressureTimeout)
    ));

    let mut client_settings = test_settings();
    client_settings.transport_params.limits.max_channel_ids = invalid;
    assert!(matches!(
        ClientDriver::new((), client_settings),
        Err(RuntimeLimitsError::InvalidMulticastSettings(
            quiche::Error::InvalidTransportParam
        ))
    ));
    let mut client_settings = test_settings();
    client_settings.max_joined_channels = invalid;
    assert!(matches!(
        ClientDriver::new((), client_settings),
        Err(RuntimeLimitsError::InvalidMulticastSettings(
            quiche::Error::InvalidFrame
        ))
    ));

    let mut control_settings = test_server_control_settings();
    control_settings.channels[0].announce.channel_id = Vec::new();
    assert!(matches!(
        ServerControlDriver::new((), control_settings),
        Err(RuntimeLimitsError::InvalidMulticastSettings(
            quiche::Error::InvalidFrame
        ))
    ));
    let mut control_settings = test_server_control_settings();
    control_settings.stream_integrity_batching.max_packet_hashes = invalid;
    assert!(matches!(
        ServerControlDriver::new((), control_settings),
        Err(RuntimeLimitsError::InvalidMulticastSettings(
            quiche::Error::InvalidFrame
        ))
    ));
    let mut control_settings = test_server_control_settings();
    control_settings.stream_integrity_batching.max_delay = Duration::MAX;
    assert!(matches!(
        ServerControlDriver::new((), control_settings),
        Err(RuntimeLimitsError::InvalidMulticastSettings(
            quiche::Error::InvalidState
        ))
    ));
    let mut control_settings = test_server_control_settings();
    control_settings.channels[0].announce.max_ack_delay_ms = invalid;
    assert!(matches!(
        ServerControlDriver::new((), control_settings),
        Err(RuntimeLimitsError::InvalidMulticastSettings(
            quiche::Error::InvalidFrame
        ))
    ));
    let mut server_settings = test_server_settings();
    server_settings.channels[0].max_rate_kibps = invalid;
    assert!(matches!(
        ServerDriver::new((), server_settings),
        Err(RuntimeLimitsError::InvalidMulticastSettings(
            quiche::Error::InvalidFrame
        ))
    ));

    let (_driver, controller) =
        ServerControlDriver::new((), ServerControlSettings::default()).unwrap();
    let mut announce = test_ipv4_announce();
    announce.channel_id = vec![0; 21];
    assert_eq!(
        controller.send_announce(announce).unwrap_err().kind(),
        ControllerSendErrorKind::InvalidValue
    );
    let mut announce = test_ipv4_announce();
    announce.max_ack_delay_ms = invalid;
    assert_eq!(
        controller.send_announce(announce).unwrap_err().kind(),
        ControllerSendErrorKind::InvalidValue
    );
    let mut key = test_key(&[1]);
    key.key_sequence = invalid;
    assert_eq!(
        controller.send_key(key).unwrap_err().kind(),
        ControllerSendErrorKind::InvalidValue
    );
    assert_eq!(
        controller
            .send_join(quiche::multicast::Join {
                channel_id: vec![1],
                mc_limits_sequence: invalid,
                mc_state_sequence: 0,
                mc_key_sequence: 0,
            })
            .unwrap_err()
            .kind(),
        ControllerSendErrorKind::InvalidValue
    );
    assert_eq!(
        controller
            .send_integrity(quiche::multicast::Integrity {
                channel_id: vec![1],
                packet_number_start: invalid,
                packet_hash_count: Some(1),
                packet_hashes: vec![0; 32],
            })
            .unwrap_err()
            .kind(),
        ControllerSendErrorKind::InvalidValue
    );
    let mut config = test_server_control_settings().channels.remove(0);
    config.key.channel_id = vec![2];
    assert_eq!(
        controller.upsert_channel(config).unwrap_err().kind(),
        ControllerSendErrorKind::InvalidValue
    );
    assert_eq!(controller.command_queue_stats().retained_items, 0);

    controller
        .send_join(quiche::multicast::Join {
            channel_id: vec![1],
            mc_limits_sequence: 0,
            mc_state_sequence: 0,
            mc_key_sequence: 0,
        })
        .unwrap();
    assert_eq!(controller.command_queue_stats().retained_items, 1);

    let (_driver, publisher_controller) =
        ServerDriver::new((), ServerSettings::default()).unwrap();
    assert_eq!(
        publisher_controller
            .send_on_channel(vec![1], vec![
                quiche::multicast::ChannelFrame::Stream {
                    stream_id: 3,
                    offset: invalid,
                    fin: false,
                    data: Vec::new(),
                }
            ],)
            .unwrap_err()
            .kind(),
        ControllerSendErrorKind::InvalidValue
    );
    assert_eq!(publisher_controller.command_queue_stats().retained_items, 0);
    publisher_controller
        .send_on_channel(vec![1], vec![
            quiche::multicast::ChannelFrame::Datagram { data: vec![1] },
        ])
        .unwrap();
    assert_eq!(publisher_controller.command_queue_stats().retained_items, 1);
}

#[test]
fn stream_declaration_validates_before_publisher_mutation() {
    let settings = test_settings();
    let mut pipe = test_stream_pipe(&settings);
    let (mut runtime, controller) = test_stream_control_runtime();
    runtime.on_conn_established(&mut pipe.server).unwrap();
    let publisher =
        ServerStreamPublisher::new(test_stream_control_config()).unwrap();

    assert!(matches!(
        publisher.declare_stream((1 << 62) | 3),
        Err(ServerStreamPublisherError::Encode(
            quiche::Error::InvalidFrame
        ))
    ));
    publisher.declare_stream(3).unwrap();
    let _attachment = publisher.attach(&controller).unwrap();
    runtime.process_writes(&mut pipe.server).unwrap();

    assert_eq!(runtime.channels[&[1, 2, 3, 4][..]].max_stream_id, Some(3));
}

fn test_server_control_command_channel() -> (
    BoundedSender<ServerControlCommand>,
    BoundedReceiver<ServerControlCommand>,
    RetainedQueueObserver,
) {
    bounded_channel(RuntimeLimits::default().commands)
}

fn test_server_command_channel() -> (
    BoundedSender<ServerCommand>,
    BoundedReceiver<ServerCommand>,
    RetainedQueueObserver,
) {
    bounded_channel(RuntimeLimits::default().commands)
}

fn test_retained_queue_observer() -> RetainedQueueObserver {
    retained_queue_budget::<quiche::multicast::Integrity>(
        RuntimeLimits::default().pending_integrity,
    )
    .1
}

#[test]
fn controller_event_receivers_can_be_taken_only_once() {
    let (_client_sender, client_receiver, client_observer) =
        test_client_event_channel();
    let mut client = ClientController {
        event_receiver: Some(client_receiver),
        event_observer: client_observer,
        ingress_observer: test_retained_queue_observer(),
        control_observer: test_retained_queue_observer(),
    };
    assert!(client.event_receiver_mut().is_some());
    let client_receiver = client.take_event_receiver().unwrap();
    assert!(client.take_event_receiver().is_none());
    assert!(client.event_receiver_mut().is_none());
    drop(client_receiver);
    assert_eq!(
        client
            .event_queue_stats()
            .terminal
            .map(|terminal| terminal.reason),
        Some(EventStreamTerminalReason::ReceiverDropped)
    );

    let (command_sender, _command_receiver, command_observer) =
        test_server_control_command_channel();
    let (_server_sender, server_receiver, server_observer) =
        test_server_event_channel();
    let mut server = ServerControlController {
        command_sender,
        command_observer,
        pending_publication_observer: test_retained_queue_observer(),
        pending_integrity_observer: test_retained_queue_observer(),
        event_receiver: Some(server_receiver),
        event_observer: server_observer,
    };
    assert!(server.take_event_receiver().is_some());
    assert!(server.take_event_receiver().is_none());
}

#[test]
fn server_controller_command_queue_saturates_without_blocking() {
    let limits = RuntimeLimits {
        commands: RetainedQueueLimits {
            max_items: 1,
            max_retained_bytes: 4096,
        },
        ..RuntimeLimits::default()
    };
    let (_driver, controller) = ServerControlDriver::new_with_runtime_limits(
        (),
        ServerControlSettings::default(),
        limits,
    )
    .unwrap();

    controller.send_announce(test_ipv4_announce()).unwrap();
    let rejected = test_ipv4_announce();
    let error = controller.send_announce(rejected.clone()).unwrap_err();
    assert_eq!(error.kind(), ControllerSendErrorKind::Full);
    assert_eq!(error.into_inner(), rejected);

    let stats = controller.runtime_queue_stats().commands;
    assert_eq!(stats.retained_items, 1);
    assert!(stats.retained_bytes <= stats.max_retained_bytes);
    assert_eq!(stats.peak_retained_items, 1);
    assert_eq!(stats.saturations_total, 1);
}

#[test]
fn server_controller_returns_owned_oversized_and_closed_commands() {
    let oversized_limits = RuntimeLimits {
        commands: RetainedQueueLimits {
            max_items: 1,
            max_retained_bytes: 1,
        },
        ..RuntimeLimits::default()
    };
    let (_driver, controller) = ServerControlDriver::new_with_runtime_limits(
        (),
        ServerControlSettings::default(),
        oversized_limits,
    )
    .unwrap();
    let key = test_key(&[1, 2, 3, 4]);
    let error = controller.send_key(key.clone()).unwrap_err();
    assert_eq!(error.kind(), ControllerSendErrorKind::Oversized);
    assert_eq!(error.into_inner(), key);

    let (driver, controller) =
        ServerControlDriver::new((), ServerControlSettings::default()).unwrap();
    drop(driver);
    let integrity = test_stream_integrity(1, 0xaa);
    let error = controller.send_integrity(integrity.clone()).unwrap_err();
    assert_eq!(error.kind(), ControllerSendErrorKind::Closed);
    assert_eq!(error.into_inner(), integrity);
}

#[test]
fn runtime_limits_reserve_space_for_ingress_overload_notification() {
    let limits = RuntimeLimits {
        ingress: RetainedQueueLimits {
            max_items: 1,
            max_retained_bytes: MIN_INGRESS_NOTIFICATION_RETAINED_BYTES - 1,
        },
        ..RuntimeLimits::default()
    };

    assert_eq!(
        limits.validate(),
        Err(RuntimeLimitsError::IngressNotificationByteCapacity {
            minimum: MIN_INGRESS_NOTIFICATION_RETAINED_BYTES,
        })
    );
}

#[test]
fn client_control_sequence_exhaustion_does_not_reserve_or_queue() {
    let settings = test_settings();
    let (event_sender, _events, _) = test_client_event_channel();
    let mut runtime = ClientRuntime::with_backend(
        settings.clone(),
        event_sender,
        FakeJoinBackend::default(),
    );
    let mut pipe = test_pipe(&settings);
    let max_varint = (1 << 62) - 1;

    runtime.reserved_limits_sequence = max_varint;
    assert!(runtime.send_limits(&mut pipe.client).is_err());
    assert_eq!(runtime.reserved_limits_sequence, max_varint);
    assert!(runtime.pending_control.is_empty());

    let channel_id = vec![1, 2, 3, 4];
    let mut channel = Channel::default();
    channel.next_state_sequence = max_varint;
    runtime.channels.insert(channel_id.clone(), channel);
    assert!(runtime
        .send_state(
            &mut pipe.client,
            channel_id.clone(),
            quiche::multicast::ChannelState::Left,
            STATE_REASON_UNSPECIFIED_OTHER,
            Vec::new(),
        )
        .is_err());
    assert_eq!(
        runtime.channels[&channel_id].next_state_sequence,
        max_varint
    );
    assert!(!runtime.reserved_state_sequences.contains_key(&channel_id));
    assert!(runtime.pending_control.is_empty());
}

#[test]
fn server_secret_bearing_config_debug_output_is_redacted() {
    let mut announce = test_ipv4_announce();
    announce.header_secret = vec![0xde, 0xad, 0xbe, 0xef];
    let mut key = test_key(&[1, 2, 3, 4]);
    key.secret = vec![0xca, 0xfe, 0xba, 0xbe];
    let control = ServerControlChannelConfig { announce, key };
    let control_debug = format!("{control:?}");
    assert!(control_debug.contains("<redacted:4 bytes>"));
    assert!(!control_debug.contains("[222, 173, 190, 239]"));
    assert!(!control_debug.contains("[202, 254, 186, 190]"));

    let mut publication = test_server_settings()
        .channels
        .first()
        .expect("test server has one channel")
        .clone();
    publication.header_secret = vec![0x11, 0x22, 0x33, 0x44];
    publication.secret = vec![0x55, 0x66, 0x77, 0x88];
    let publication_debug = format!("{publication:?}");
    assert!(publication_debug.matches("<redacted:4 bytes>").count() >= 2);
    assert!(!publication_debug.contains("[17, 34, 51, 68]"));
    assert!(!publication_debug.contains("[85, 102, 119, 136]"));
}
