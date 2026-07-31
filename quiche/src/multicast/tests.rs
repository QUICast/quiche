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

use super::*;

#[test]
fn client_transport_params_roundtrip() {
    let params = ClientTransportParams {
        limits: ClientLimits {
            ipv6_channels_allowed: true,
            ipv4_channels_allowed: true,
            max_aggregate_rate_kibps: 1024,
            max_channel_ids: 16,
        },
        hash_algorithms: vec![1, 2, 3],
        encryption_algorithms: vec![0x1301, 0x1302],
    };

    let mut out = [0; 128];
    let written = params.to_bytes(&mut out).unwrap();
    let decoded = ClientTransportParams::from_bytes(&out[..written]).unwrap();

    assert_eq!(decoded, params);
}

#[test]
fn announce_ipv4_roundtrip() {
    let frame = Frame::Announce(Announce {
        channel_id: vec![1, 2, 3, 4],
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
        udp_port: 4433,
        header_protection_algorithm: 0x1301,
        header_secret: vec![0xaa; 12],
        aead_algorithm: 0x1301,
        integrity_hash_algorithm: 1,
        max_rate_kibps: 2500,
        max_ack_delay_ms: 25,
    });

    let mut out = [0; 256];
    let written = frame.to_bytes(&mut out).unwrap();
    let decoded = Frame::from_bytes(&out[..written]).unwrap();

    assert_eq!(decoded, frame);
}

#[test]
fn announce_ipv6_roundtrip() {
    let frame = Frame::Announce(Announce {
        channel_id: vec![7, 7, 7, 7],
        source: IpAddr::V6("2001:db8::1".parse().unwrap()),
        group: IpAddr::V6("ff3e::8000:1".parse().unwrap()),
        udp_port: 8443,
        header_protection_algorithm: 0x1302,
        header_secret: vec![0xbb; 24],
        aead_algorithm: 0x1302,
        integrity_hash_algorithm: 2,
        max_rate_kibps: 9000,
        max_ack_delay_ms: 7,
    });

    let mut out = [0; 256];
    let written = frame.to_bytes(&mut out).unwrap();
    let decoded = Frame::from_bytes(&out[..written]).unwrap();

    assert_eq!(decoded, frame);
}

#[test]
fn secret_bearing_frame_debug_output_is_redacted() {
    let mut announce = test_announce();
    announce.header_secret = vec![0xde, 0xad, 0xbe, 0xef];
    let mut key = test_key(&announce.channel_id);
    key.secret = vec![0xca, 0xfe, 0xba, 0xbe];

    let announce_debug = format!("{announce:?}");
    assert!(announce_debug.contains("<redacted:4 bytes>"));
    assert!(!announce_debug.contains("[222, 173, 190, 239]"));

    let key_debug = format!("{key:?}");
    assert!(key_debug.contains("<redacted:4 bytes>"));
    assert!(!key_debug.contains("[202, 254, 186, 190]"));
}

#[test]
fn ack_with_ecn_roundtrip() {
    let frame = Frame::Ack(Ack {
        channel_id: vec![1, 3, 3, 7],
        largest_acknowledged: 1234,
        ack_delay: 25,
        first_ack_range: 12,
        ack_ranges: vec![
            AckRange {
                gap: 1,
                ack_range_length: 4,
            },
            AckRange {
                gap: 3,
                ack_range_length: 2,
            },
        ],
        ecn_counts: Some(AckEcnCounts {
            ect0_count: 10,
            ect1_count: 11,
            ecn_ce_count: 12,
        }),
    });

    let mut out = [0; 256];
    let written = frame.to_bytes(&mut out).unwrap();
    let decoded = Frame::from_bytes(&out[..written]).unwrap();

    assert_eq!(decoded, frame);
}

#[test]
fn ack_tracker_encodes_non_contiguous_ranges() {
    let mut tracker = AckTracker::default();

    for packet_number in [0, 2, 3, 6] {
        tracker.record_packet(packet_number);
    }

    let ack = tracker.pending_ack(&[1, 2, 3, 4]).unwrap();

    assert_eq!(ack.channel_id, vec![1, 2, 3, 4]);
    assert_eq!(ack.largest_acknowledged, 6);
    assert_eq!(ack.ack_delay, 0);
    assert_eq!(ack.first_ack_range, 0);
    assert_eq!(ack.ack_ranges, vec![
        AckRange {
            gap: 1,
            ack_range_length: 1,
        },
        AckRange {
            gap: 0,
            ack_range_length: 0,
        },
    ]);
    assert_eq!(ack.ecn_counts, None);

    tracker.mark_sent();
    assert_eq!(tracker.pending_ack(&[1, 2, 3, 4]), None);
}

#[test]
fn ack_tracker_bounds_ranges_and_packet_history() {
    let mut tracker = AckTracker::default();
    for index in 0..(MAX_TRACKED_ACK_RANGES + 16) {
        tracker.record_packet((index * 2) as u64);
    }

    assert_eq!(tracker.ranges.len(), MAX_TRACKED_ACK_RANGES);
    assert!(tracker.retired_before > 0);
    assert_eq!(
        tracker.pending_ack(&[1, 2, 3, 4]).unwrap().ack_ranges.len(),
        MAX_TRACKED_ACK_RANGES - 1
    );

    let mut contiguous = AckTracker::default();
    for packet_number in 0..ACK_HISTORY_PACKET_WINDOW + 10 {
        contiguous.record_packet(packet_number);
    }
    assert_eq!(contiguous.retired_before, 10);
    assert_eq!(contiguous.ranges, vec![AckSpan {
        start: 10,
        end: ACK_HISTORY_PACKET_WINDOW + 9,
    }]);
}

#[test]
fn channel_receive_prunes_retired_packet_history() {
    let mut receiver = ChannelReceiveState::<()>::new(test_announce()).unwrap();
    for packet_number in 0..ACK_HISTORY_PACKET_WINDOW + 10 {
        receiver.accepted_packets.insert(packet_number);
    }
    receiver.prune_receive_history();

    assert_eq!(receiver.accepted_packets.len(), 4096);
    assert_eq!(receiver.accepted_packets.first(), Some(&10));
}

#[test]
fn channel_send_state_processes_ack() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut sender = ChannelSendState::new(announce.clone(), key).unwrap();
    let mut out = [0; 256];

    for _ in 0..7 {
        sender
            .write_packet(&[ChannelFrame::Ping], &mut out)
            .unwrap();
    }

    let summary = sender
        .on_ack(&Ack {
            channel_id: announce.channel_id.clone(),
            largest_acknowledged: 6,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: vec![
                AckRange {
                    gap: 1,
                    ack_range_length: 1,
                },
                AckRange {
                    gap: 0,
                    ack_range_length: 0,
                },
            ],
            ecn_counts: None,
        })
        .unwrap();

    assert_eq!(summary, ChannelSendAckSummary {
        ack_blocks: 3,
        acked_packets: 4,
        largest_acknowledged: 6,
        smallest_acknowledged: 0,
    });
    let metrics = sender.metrics_snapshot();

    assert_eq!(metrics.write_calls, 7);
    assert_eq!(metrics.packets_encoded, 7);
    assert_eq!(metrics.frames_encoded, 7);
    assert_eq!(metrics.key_updates, 0);
    assert_eq!(metrics.encode_errors, 0);
    assert_eq!(metrics.ack_frames_processed, 1);
    assert_eq!(metrics.ack_blocks_processed, 3);
    assert_eq!(metrics.acked_packets_reported, 4);
    assert_eq!(metrics.ack_errors, 0);
    assert_eq!(metrics.largest_acknowledged, Some(6));
    assert_eq!(metrics.last_packet_number, Some(6));
    assert_eq!(metrics.next_packet_number, 7);
}

#[test]
fn channel_send_state_rejects_ack_for_unsent_packet() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut sender = ChannelSendState::new(announce.clone(), key).unwrap();

    assert_eq!(
        sender.on_ack(&Ack {
            channel_id: announce.channel_id.clone(),
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }),
        Err(Error::InvalidAckRange)
    );
    assert_eq!(sender.metrics_snapshot().ack_errors, 1);
}

#[test]
fn channel_send_state_rejects_non_contiguous_key_update() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut sender =
        ChannelSendState::new(announce.clone(), key.clone()).unwrap();

    let mut skipped = key.clone();
    skipped.key_sequence += 2;
    skipped.secret = vec![0xdd; 16];

    assert_eq!(sender.update_key(skipped), Err(Error::InvalidState));

    let mut next = key.clone();
    next.key_sequence += 1;
    next.from_packet_number = 5;
    next.secret = vec![0xee; 16];

    assert_eq!(sender.update_key(next), Ok(()));
    assert_eq!(sender.metrics_snapshot().key_updates, 1);

    assert_eq!(sender.update_key(key), Err(Error::InvalidState));
}

#[test]
fn frame_decode_rejects_impossible_ack_range_count() {
    let mut out = [0; 64];
    let mut b = octets::OctetsMut::with_slice(&mut out);

    b.put_varint(FRAME_TYPE_ACK).unwrap();
    encode_channel_id(&[1, 2, 3, 4], &mut b).unwrap();
    b.put_varint(0).unwrap();
    b.put_varint(0).unwrap();
    b.put_varint(2).unwrap();
    b.put_varint(0).unwrap();

    let written = b.off();

    assert_eq!(Frame::from_bytes(&out[..written]), Err(Error::InvalidFrame));
}

#[test]
fn client_transport_params_reject_impossible_algorithm_count() {
    let mut out = [0; 64];
    let mut b = octets::OctetsMut::with_slice(&mut out);

    b.put_u8(0).unwrap();
    b.put_varint(0).unwrap();
    b.put_varint(0).unwrap();
    b.put_varint(2).unwrap();
    b.put_varint(0).unwrap();

    let written = b.off();

    assert_eq!(
        ClientTransportParams::from_bytes(&out[..written]),
        Err(Error::InvalidTransportParam)
    );
}

#[test]
fn state_roundtrip() {
    let frame = Frame::State(State {
        channel_id: vec![9, 9, 9, 9],
        sequence: 44,
        state: ChannelState::Joined,
        reason_scope: StateReasonScope::Transport,
        reason_code: STATE_REASON_REQUESTED_BY_SERVER,
        reason_phrase: b"joined".to_vec(),
    });

    let mut out = [0; 256];
    let written = frame.to_bytes(&mut out).unwrap();
    let decoded = Frame::from_bytes(&out[..written]).unwrap();

    assert_eq!(decoded, frame);
}

fn test_announce() -> Announce {
    Announce {
        channel_id: vec![1, 2, 3, 4],
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
        udp_port: 4433,
        header_protection_algorithm: 0x1301,
        header_secret: vec![0xaa; 16],
        aead_algorithm: 0x1301,
        integrity_hash_algorithm: 1,
        max_rate_kibps: 2500,
        max_ack_delay_ms: 25,
    }
}

fn test_key(channel_id: &[u8]) -> Key {
    Key {
        channel_id: channel_id.to_vec(),
        key_sequence: 1,
        from_packet_number: 0,
        secret: vec![0xcc; 16],
    }
}

#[test]
fn checked_lengths_reject_every_public_u64_wire_field() {
    let invalid = MAX_VARINT + 1;
    let assert_invalid = |frame: Frame| {
        assert_eq!(frame.encoded_len(), Err(Error::InvalidFrame));
    };

    let mut announce = test_announce();
    announce.max_rate_kibps = invalid;
    assert_invalid(Frame::Announce(announce));
    let mut announce = test_announce();
    announce.max_ack_delay_ms = invalid;
    assert_invalid(Frame::Announce(announce));

    let mut key = test_key(&[1]);
    key.key_sequence = invalid;
    assert_invalid(Frame::Key(key));
    let mut key = test_key(&[1]);
    key.from_packet_number = invalid;
    assert_invalid(Frame::Key(key));

    for join in [
        Join {
            channel_id: vec![1],
            mc_limits_sequence: invalid,
            mc_state_sequence: 0,
            mc_key_sequence: 0,
        },
        Join {
            channel_id: vec![1],
            mc_limits_sequence: 0,
            mc_state_sequence: invalid,
            mc_key_sequence: 0,
        },
        Join {
            channel_id: vec![1],
            mc_limits_sequence: 0,
            mc_state_sequence: 0,
            mc_key_sequence: invalid,
        },
    ] {
        assert_invalid(Frame::Join(join));
    }

    assert_invalid(Frame::Leave(Leave {
        channel_id: vec![1],
        mc_state_sequence: invalid,
        after_packet_number: 0,
    }));
    assert_invalid(Frame::Leave(Leave {
        channel_id: vec![1],
        mc_state_sequence: 0,
        after_packet_number: invalid,
    }));
    assert_invalid(Frame::Integrity(Integrity {
        channel_id: vec![1],
        packet_number_start: invalid,
        packet_hash_count: None,
        packet_hashes: Vec::new(),
    }));
    assert_invalid(Frame::Integrity(Integrity {
        channel_id: vec![1],
        packet_number_start: 0,
        packet_hash_count: Some(invalid),
        packet_hashes: Vec::new(),
    }));

    let valid_ack = || Ack {
        channel_id: vec![1],
        largest_acknowledged: MAX_VARINT,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: Vec::new(),
        ecn_counts: None,
    };
    let mut ack = valid_ack();
    ack.largest_acknowledged = invalid;
    assert_invalid(Frame::Ack(ack));
    let mut ack = valid_ack();
    ack.ack_delay = invalid;
    assert_invalid(Frame::Ack(ack));
    let mut ack = valid_ack();
    ack.first_ack_range = invalid;
    assert_invalid(Frame::Ack(ack));
    let mut ack = valid_ack();
    ack.ack_ranges.push(AckRange {
        gap: invalid,
        ack_range_length: 0,
    });
    assert_invalid(Frame::Ack(ack));
    let mut ack = valid_ack();
    ack.ack_ranges.push(AckRange {
        gap: 0,
        ack_range_length: invalid,
    });
    assert_invalid(Frame::Ack(ack));
    for ecn_counts in [
        AckEcnCounts {
            ect0_count: invalid,
            ect1_count: 0,
            ecn_ce_count: 0,
        },
        AckEcnCounts {
            ect0_count: 0,
            ect1_count: invalid,
            ecn_ce_count: 0,
        },
        AckEcnCounts {
            ect0_count: 0,
            ect1_count: 0,
            ecn_ce_count: invalid,
        },
    ] {
        let mut ack = valid_ack();
        ack.ecn_counts = Some(ecn_counts);
        assert_invalid(Frame::Ack(ack));
    }

    for limits in [
        Limits {
            sequence: invalid,
            limits: ClientLimits::default(),
            max_joined_count: 0,
        },
        Limits {
            sequence: 0,
            limits: ClientLimits {
                max_aggregate_rate_kibps: invalid,
                ..ClientLimits::default()
            },
            max_joined_count: 0,
        },
        Limits {
            sequence: 0,
            limits: ClientLimits {
                max_channel_ids: invalid,
                ..ClientLimits::default()
            },
            max_joined_count: 0,
        },
        Limits {
            sequence: 0,
            limits: ClientLimits::default(),
            max_joined_count: invalid,
        },
    ] {
        assert_invalid(Frame::Limits(limits));
    }

    assert_invalid(Frame::Retire(Retire {
        channel_id: vec![1],
        after_packet_number: invalid,
    }));
    assert_invalid(Frame::State(State {
        channel_id: vec![1],
        sequence: invalid,
        state: ChannelState::Left,
        reason_scope: StateReasonScope::Application,
        reason_code: 0,
        reason_phrase: Vec::new(),
    }));
    assert_invalid(Frame::State(State {
        channel_id: vec![1],
        sequence: 0,
        state: ChannelState::Left,
        reason_scope: StateReasonScope::Application,
        reason_code: invalid,
        reason_phrase: Vec::new(),
    }));

    for params in [
        ClientTransportParams {
            limits: ClientLimits {
                max_aggregate_rate_kibps: invalid,
                ..ClientLimits::default()
            },
            ..ClientTransportParams::default()
        },
        ClientTransportParams {
            limits: ClientLimits {
                max_channel_ids: invalid,
                ..ClientLimits::default()
            },
            ..ClientTransportParams::default()
        },
    ] {
        assert_eq!(params.encoded_len(), Err(Error::InvalidTransportParam));
        assert_eq!(params.wire_len(), usize::MAX);
    }

    for channel_frame in [
        ChannelFrame::Stream {
            stream_id: invalid,
            offset: 0,
            fin: false,
            data: Vec::new(),
        },
        ChannelFrame::Stream {
            stream_id: 3,
            offset: invalid,
            fin: false,
            data: Vec::new(),
        },
        ChannelFrame::ResetStream {
            stream_id: invalid,
            error_code: 0,
            final_size: 0,
        },
        ChannelFrame::ResetStream {
            stream_id: 3,
            error_code: invalid,
            final_size: 0,
        },
        ChannelFrame::ResetStream {
            stream_id: 3,
            error_code: 0,
            final_size: invalid,
        },
        ChannelFrame::ResetStreamAt {
            stream_id: invalid,
            error_code: 0,
            final_size: 0,
            reliable_size: 0,
        },
        ChannelFrame::ResetStreamAt {
            stream_id: 3,
            error_code: invalid,
            final_size: 0,
            reliable_size: 0,
        },
        ChannelFrame::ResetStreamAt {
            stream_id: 3,
            error_code: 0,
            final_size: invalid,
            reliable_size: 0,
        },
        ChannelFrame::ResetStreamAt {
            stream_id: 3,
            error_code: 0,
            final_size: 0,
            reliable_size: invalid,
        },
    ] {
        assert_eq!(channel_frame.encoded_len(), Err(Error::InvalidFrame));
    }
}

#[test]
fn checked_lengths_reject_invalid_channel_ids_and_state_reasons() {
    for channel_id in [Vec::new(), vec![0; 21]] {
        let mut announce = test_announce();
        announce.channel_id = channel_id.clone();
        assert_eq!(announce.validate(), Err(Error::InvalidFrame));

        let key = test_key(&channel_id);
        assert_eq!(key.validate(), Err(Error::InvalidFrame));
        assert_eq!(
            ChannelReceiveState::<()>::new(announce.clone()).err(),
            Some(Error::InvalidFrame)
        );
        assert_eq!(
            ChannelSendState::new(announce, key).err(),
            Some(Error::InvalidFrame)
        );
    }

    let invalid = Frame::State(State {
        channel_id: vec![1],
        sequence: 1,
        state: ChannelState::Left,
        reason_scope: StateReasonScope::Transport,
        reason_code: 0x11,
        reason_phrase: Vec::new(),
    });
    assert_eq!(invalid.encoded_len(), Err(Error::InvalidFrame));
}

#[test]
fn invalid_packet_preflight_preserves_output_and_packet_number() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut sender = ChannelSendState::new(announce, key).unwrap();
    let mut output = vec![0xa5; 256];
    let before = output.clone();

    assert_eq!(
        sender.write_packet(
            &[ChannelFrame::Stream {
                stream_id: 3,
                offset: MAX_VARINT + 1,
                fin: false,
                data: vec![1],
            }],
            &mut output,
        ),
        Err(Error::InvalidFrame)
    );
    assert_eq!(output, before);
    assert_eq!(sender.next_packet_number(), 0);

    let written = sender
        .write_packet(&[ChannelFrame::Datagram { data: vec![1] }], &mut output)
        .unwrap();
    assert_eq!(written.packet_number, 0);
}

#[test]
fn channel_packet_number_exhaustion_stops_before_wrap() {
    let announce = test_announce();
    let mut key = test_key(&announce.channel_id);
    key.from_packet_number = MAX_VARINT;
    let mut sender = ChannelSendState::new(announce, key).unwrap();
    let mut output = vec![0; 256];

    let last = sender
        .write_packet(&[ChannelFrame::Datagram { data: vec![1] }], &mut output)
        .unwrap();
    assert_eq!(last.packet_number, MAX_VARINT);
    assert_eq!(sender.next_packet_number(), MAX_VARINT + 1);

    let before = output.clone();
    assert_eq!(
        sender.write_packet(
            &[ChannelFrame::Datagram { data: vec![2] }],
            &mut output,
        ),
        Err(Error::InvalidState)
    );
    assert_eq!(output, before);
    assert_eq!(sender.next_packet_number(), MAX_VARINT + 1);
}

fn build_packet_seal(announce: &Announce, key: &Key) -> crypto::Seal {
    let alg = tls_cipher_to_algorithm(announce.aead_algorithm).unwrap();
    let mut pkt_key = vec![0; alg.key_len()];
    let mut pkt_iv = vec![0; alg.nonce_len()];
    let mut hp_key = vec![0; alg.key_len()];

    crypto::derive_pkt_key(alg, &key.secret, &mut pkt_key).unwrap();
    crypto::derive_pkt_iv(alg, &key.secret, &mut pkt_iv).unwrap();
    crypto::derive_hdr_key(alg, &announce.header_secret, &mut hp_key).unwrap();

    crypto::Seal::new(alg, pkt_key, pkt_iv, hp_key, key.secret.clone()).unwrap()
}

fn encode_channel_packet(
    announce: &Announce, key: &Key, packet_number: u64, key_phase: bool,
    frames: &[frame::Frame],
) -> Vec<u8> {
    encode_channel_packet_with_pn_len(
        announce,
        key,
        packet_number,
        key_phase,
        4,
        frames,
    )
}

fn encode_channel_packet_with_pn_len(
    announce: &Announce, key: &Key, packet_number: u64, key_phase: bool,
    packet_number_len: usize, frames: &[frame::Frame],
) -> Vec<u8> {
    let mut out = vec![0; 256];
    let mut b = octets::OctetsMut::with_slice(&mut out);
    let mut seal = build_packet_seal(announce, key);
    let first = 0x40 |
        (((key_phase as u8) << 2) & 0x04) |
        ((packet_number_len as u8) - 1);

    b.put_u8(first).unwrap();
    b.put_bytes(&announce.channel_id).unwrap();
    packet::encode_pkt_num(packet_number, packet_number_len, &mut b).unwrap();

    let payload_offset = b.off();

    for frame in frames {
        frame.to_bytes(&mut b).unwrap();
    }

    let payload_len = b.off() - payload_offset;

    let written = packet::encrypt_pkt(
        &mut b,
        packet_number,
        packet_number_len,
        payload_len,
        payload_offset,
        None,
        &mut seal,
    )
    .unwrap();

    out.truncate(written);
    out
}

fn integrity_frame(
    announce: &Announce, packet_number: u64, packet: &[u8],
) -> Integrity {
    Integrity {
        channel_id: announce.channel_id.clone(),
        packet_number_start: packet_number,
        packet_hash_count: Some(1),
        packet_hashes: IntegrityHashAlgorithm::from_id(
            announce.integrity_hash_algorithm,
        )
        .unwrap()
        .hash(packet),
    }
}

#[test]
fn channel_send_state_roundtrip() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut sender =
        ChannelSendState::new(announce.clone(), key.clone()).unwrap();
    let mut receiver = ChannelReceiveState::new(announce).unwrap();
    let mut out = [0; 256];

    receiver.insert_key(key).unwrap();

    let sent = sender
        .write_packet(
            &[ChannelFrame::Datagram {
                data: b"hello multicast".to_vec(),
            }],
            &mut out,
        )
        .unwrap();
    let events = receiver.insert_integrity(sent.integrity.clone()).unwrap();

    assert!(events.is_empty());

    let events = receiver.recv(&out[..sent.packet_len], ()).unwrap();
    assert_eq!(events.len(), 1);

    match &events[0] {
        ChannelReceiveEvent::Packet {
            packet,
            metadata: (),
        } => {
            assert_eq!(packet.packet_number, sent.packet_number);
            assert_eq!(packet.key_sequence, sent.key_sequence);
            assert!(packet.key_phase);
            assert_eq!(packet.frames, vec![ChannelFrame::Datagram {
                data: b"hello multicast".to_vec(),
            }]);
        },

        ChannelReceiveEvent::Error { error, .. } => {
            panic!("unexpected receive error: {error:?}");
        },
    }

    let send_metrics = sender.metrics_snapshot();
    assert_eq!(send_metrics, ChannelSendMetricsSnapshot {
        write_calls: 1,
        packets_encoded: 1,
        bytes_encoded: send_metrics.bytes_encoded,
        frames_encoded: 1,
        key_updates: 0,
        encode_errors: 0,
        ack_frames_processed: 0,
        ack_blocks_processed: 0,
        acked_packets_reported: 0,
        ack_errors: 0,
        largest_acknowledged: None,
        last_packet_number: Some(0),
        next_packet_number: 1,
    });

    let recv_metrics = receiver.metrics_snapshot();
    assert_eq!(recv_metrics.recv_calls, 1);
    assert_eq!(recv_metrics.recv_bytes, send_metrics.bytes_encoded);
    assert_eq!(recv_metrics.packets_buffered, 1);
    assert_eq!(recv_metrics.packets_delivered, 1);
    assert_eq!(recv_metrics.packets_released_on_recv, 1);
    assert_eq!(recv_metrics.packets_released_on_key, 0);
    assert_eq!(recv_metrics.packets_released_on_integrity, 0);
    assert_eq!(recv_metrics.keys_received, 1);
    assert_eq!(recv_metrics.integrity_frames_received, 1);
    assert_eq!(recv_metrics.integrity_hashes_received, 1);
    assert_eq!(recv_metrics.pending_packets, 0);
    assert_eq!(recv_metrics.waiting_for_key_packets, 0);
    assert_eq!(recv_metrics.waiting_for_integrity_packets, 0);
}

#[test]
fn channel_stream_frames_roundtrip() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut sender =
        ChannelSendState::new(announce.clone(), key.clone()).unwrap();
    let mut receiver = ChannelReceiveState::new(announce).unwrap();
    let mut out = [0; 256];
    let frames = vec![
        ChannelFrame::Stream {
            stream_id: 3,
            offset: 10,
            fin: true,
            data: b"shared body".to_vec(),
        },
        ChannelFrame::ResetStreamAt {
            stream_id: 7,
            error_code: 42,
            final_size: 128,
            reliable_size: 10,
        },
    ];

    receiver.insert_key(key).unwrap();
    let sent = sender.write_packet(&frames, &mut out).unwrap();
    assert!(receiver
        .insert_integrity(sent.integrity.clone())
        .unwrap()
        .is_empty());

    let events = receiver.recv(&out[..sent.packet_len], ()).unwrap();
    let ChannelReceiveEvent::Packet { packet, .. } = &events[0] else {
        panic!("expected decoded channel packet");
    };

    assert_eq!(packet.frames, frames);
}

#[test]
fn borrowed_channel_stream_encoding_matches_owned_frame() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let data = b"shared WebTransport stream body";
    let frames = [ChannelFrame::Stream {
        stream_id: 3,
        offset: 10,
        fin: true,
        data: data.to_vec(),
    }];
    let mut owned = ChannelSendState::new(announce.clone(), key.clone()).unwrap();
    let mut borrowed = ChannelSendState::new(announce, key).unwrap();

    let owned_len = owned.packet_len(&frames).unwrap();
    let borrowed_len = borrowed.stream_packet_len(3, 10, data.len()).unwrap();
    assert_eq!(owned_len, borrowed_len);

    let mut owned_packet = vec![0; owned_len];
    let mut borrowed_packet = vec![0; borrowed_len];
    let owned_output = owned.write_packet(&frames, &mut owned_packet).unwrap();
    let borrowed_output = borrowed
        .write_stream_packet(3, 10, true, data, &mut borrowed_packet)
        .unwrap();

    assert_eq!(owned_output.packet_len, owned_len);
    assert_eq!(borrowed_output.packet_len, borrowed_len);
    assert_eq!(owned_packet, borrowed_packet);
    assert_eq!(owned_output.integrity, borrowed_output.integrity);
}

#[test]
fn channel_packet_len_rejects_oversized_two_byte_payload() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut sender = ChannelSendState::new(announce, key).unwrap();

    assert_eq!(
        sender.stream_packet_len(3, 0, 16384),
        Err(Error::InvalidFrame)
    );
    assert_eq!(
        sender.packet_len(&[ChannelFrame::Datagram {
            data: vec![0; 16384],
        }]),
        Err(Error::InvalidFrame)
    );
    let metrics = sender.metrics_snapshot();
    assert_eq!(metrics.write_calls, 0);
    assert_eq!(metrics.encode_errors, 2);
    assert_eq!(metrics.next_packet_number, 0);
}

#[test]
fn channel_stream_frames_reject_non_server_unidirectional_streams() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut sender = ChannelSendState::new(announce, key).unwrap();
    let mut out = [0; 256];

    assert_eq!(
        sender.write_packet(
            &[ChannelFrame::Stream {
                stream_id: 0,
                offset: 0,
                fin: false,
                data: b"invalid".to_vec(),
            }],
            &mut out,
        ),
        Err(Error::InvalidFrame)
    );
}

#[test]
fn channel_receive_state_releases_packet_after_integrity() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let packet =
        encode_channel_packet(&announce, &key, 1, true, &[frame::Frame::Ping {
            mtu_probe: None,
        }]);
    let integrity = integrity_frame(&announce, 1, &packet);
    let mut state = ChannelReceiveState::new(announce.clone()).unwrap();

    assert!(state.insert_key(key).unwrap().is_empty());
    assert!(state.recv(&packet, ()).unwrap().is_empty());

    let events = state.insert_integrity(integrity).unwrap();
    assert_eq!(events.len(), 1);

    match &events[0] {
        ChannelReceiveEvent::Packet { packet, .. } => {
            assert_eq!(packet.channel_id, announce.channel_id);
            assert_eq!(packet.packet_number, 1);
            assert_eq!(packet.key_sequence, 1);
            assert!(packet.key_phase);
            assert_eq!(packet.frames, vec![ChannelFrame::Ping]);
        },

        ChannelReceiveEvent::Error { error, .. } =>
            panic!("unexpected decode error: {error:?}"),
    }

    let metrics = state.metrics_snapshot();
    assert_eq!(metrics.packets_released_on_recv, 0);
    assert_eq!(metrics.packets_released_on_key, 0);
    assert_eq!(metrics.packets_released_on_integrity, 1);
}

#[test]
fn channel_receive_state_releases_packet_after_key() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let packet =
        encode_channel_packet(&announce, &key, 7, true, &[frame::Frame::Ping {
            mtu_probe: None,
        }]);
    let integrity = integrity_frame(&announce, 7, &packet);
    let mut state = ChannelReceiveState::new(announce.clone()).unwrap();

    assert!(state.insert_integrity(integrity).unwrap().is_empty());
    assert!(state.recv(&packet, "late-key").unwrap().is_empty());

    let events = state.insert_key(key).unwrap();
    assert_eq!(events.len(), 1);

    match &events[0] {
        ChannelReceiveEvent::Packet { packet, metadata } => {
            assert_eq!(packet.channel_id, announce.channel_id);
            assert_eq!(packet.packet_number, 7);
            assert_eq!(*metadata, "late-key");
        },

        ChannelReceiveEvent::Error { error, .. } =>
            panic!("unexpected decode error: {error:?}"),
    }

    let metrics = state.metrics_snapshot();
    assert_eq!(metrics.packets_released_on_recv, 0);
    assert_eq!(metrics.packets_released_on_key, 1);
    assert_eq!(metrics.packets_released_on_integrity, 0);
}

#[test]
fn channel_receive_state_bounds_pending_packet_items_and_bytes() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let first =
        encode_channel_packet(&announce, &key, 0, true, &[frame::Frame::Ping {
            mtu_probe: None,
        }]);
    let second =
        encode_channel_packet(&announce, &key, 1, true, &[frame::Frame::Ping {
            mtu_probe: None,
        }]);

    let item_limits = ChannelReceiveLimits {
        max_pending_packets: 1,
        ..ChannelReceiveLimits::default()
    };
    let mut item_bounded =
        ChannelReceiveState::with_limits(announce.clone(), item_limits).unwrap();
    assert!(item_bounded.recv(&first, "first").unwrap().is_empty());
    assert_eq!(
        item_bounded.recv(&second, "second").unwrap_err(),
        Error::InvalidState
    );
    assert_eq!(
        item_bounded.terminal_failure(),
        Some(ChannelReceiveFailure::PendingPacketCount)
    );
    assert_eq!(item_bounded.metrics_snapshot().pending_packets, 0);

    let byte_limits = ChannelReceiveLimits {
        max_pending_packet_bytes: first.len(),
        ..ChannelReceiveLimits::default()
    };
    let mut byte_bounded =
        ChannelReceiveState::with_limits(announce, byte_limits).unwrap();
    assert!(byte_bounded.recv(&first, "first").unwrap().is_empty());
    assert_eq!(
        byte_bounded.recv(&second, "second").unwrap_err(),
        Error::InvalidState
    );
    assert_eq!(
        byte_bounded.terminal_failure(),
        Some(ChannelReceiveFailure::PendingPacketBytes)
    );
    assert_eq!(byte_bounded.metrics_snapshot().pending_packet_bytes, 0);
}

#[test]
fn channel_receive_state_bounds_integrity_items_and_bytes() {
    let announce = test_announce();
    let hashes = vec![0xaa; 64];
    let integrity = Integrity {
        channel_id: announce.channel_id.clone(),
        packet_number_start: 0,
        packet_hash_count: Some(2),
        packet_hashes: hashes,
    };

    let item_limits = ChannelReceiveLimits {
        max_pending_integrity_entries: 1,
        ..ChannelReceiveLimits::default()
    };
    let mut item_bounded =
        ChannelReceiveState::<()>::with_limits(announce.clone(), item_limits)
            .unwrap();
    assert_eq!(
        item_bounded.insert_integrity(integrity).unwrap_err(),
        Error::InvalidState
    );
    assert_eq!(
        item_bounded.terminal_failure(),
        Some(ChannelReceiveFailure::PendingIntegrityEntries)
    );

    let byte_limits = ChannelReceiveLimits {
        max_pending_integrity_bytes: 63,
        ..ChannelReceiveLimits::default()
    };
    let mut byte_bounded =
        ChannelReceiveState::<()>::with_limits(announce.clone(), byte_limits)
            .unwrap();
    assert_eq!(
        byte_bounded
            .insert_integrity(Integrity {
                channel_id: announce.channel_id.clone(),
                packet_number_start: 0,
                packet_hash_count: Some(1),
                packet_hashes: vec![0xbb; 32],
            })
            .unwrap_err(),
        Error::InvalidState
    );
    assert_eq!(
        byte_bounded.terminal_failure(),
        Some(ChannelReceiveFailure::PendingIntegrityBytes)
    );
}

#[test]
fn channel_receive_state_separates_wire_and_future_limits() {
    let announce = test_announce();
    let mut wire_bounded =
        ChannelReceiveState::<()>::new(announce.clone()).unwrap();
    assert_eq!(
        wire_bounded
            .insert_integrity(Integrity {
                channel_id: announce.channel_id.clone(),
                packet_number_start: MAX_VARINT,
                packet_hash_count: Some(2),
                packet_hashes: vec![0xaa; 64],
            })
            .unwrap_err(),
        Error::InvalidFrame
    );
    assert_eq!(wire_bounded.terminal_failure(), None);

    let limits = ChannelReceiveLimits {
        max_future_packet_number_distance: 4,
        ..ChannelReceiveLimits::default()
    };
    let mut future_bounded =
        ChannelReceiveState::with_limits(announce.clone(), limits).unwrap();
    let key = test_key(&announce.channel_id);
    future_bounded.insert_key(key.clone()).unwrap();
    let packet =
        encode_channel_packet(&announce, &key, 5, true, &[frame::Frame::Ping {
            mtu_probe: None,
        }]);

    assert_eq!(
        future_bounded.recv(&packet, ()).unwrap_err(),
        Error::InvalidState
    );
    assert_eq!(
        future_bounded.terminal_failure(),
        Some(ChannelReceiveFailure::FuturePacketNumber)
    );
}

#[test]
fn unauthenticated_packets_cannot_walk_trusted_frontier() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let limits = ChannelReceiveLimits {
        max_future_packet_number_distance: 4,
        ..ChannelReceiveLimits::default()
    };
    let mut state =
        ChannelReceiveState::with_limits(announce.clone(), limits).unwrap();
    state.insert_key(key.clone()).unwrap();

    let first =
        encode_channel_packet(&announce, &key, 4, true, &[frame::Frame::Ping {
            mtu_probe: None,
        }]);
    let second =
        encode_channel_packet(&announce, &key, 8, true, &[frame::Frame::Ping {
            mtu_probe: None,
        }]);

    assert!(state.recv(&first, "first forged step").unwrap().is_empty());
    assert_eq!(state.trusted_packet_number_frontier, Some(0));
    assert_eq!(
        state.recv(&second, "second forged step").unwrap_err(),
        Error::InvalidState
    );
    assert_eq!(
        state.terminal_failure(),
        Some(ChannelReceiveFailure::FuturePacketNumber)
    );
}

#[test]
fn forged_truncated_packet_does_not_poison_later_authenticated_decode() {
    let announce = test_announce();
    let mut key = test_key(&announce.channel_id);
    key.from_packet_number = 255;
    let limits = ChannelReceiveLimits {
        max_future_packet_number_distance: 128,
        ..ChannelReceiveLimits::default()
    };
    let mut state =
        ChannelReceiveState::with_limits(announce.clone(), limits).unwrap();
    state.insert_key(key.clone()).unwrap();

    let forged =
        encode_channel_packet_with_pn_len(&announce, &key, 383, true, 1, &[
            frame::Frame::Padding { len: 4 },
            frame::Frame::Ping { mtu_probe: None },
        ]);
    assert!(state.recv(&forged, "forged").unwrap().is_empty());
    assert_eq!(state.trusted_packet_number_frontier, Some(255));

    let legitimate =
        encode_channel_packet_with_pn_len(&announce, &key, 256, true, 1, &[
            frame::Frame::Padding { len: 4 },
            frame::Frame::Ping { mtu_probe: None },
        ]);
    state
        .insert_integrity(integrity_frame(&announce, 256, &legitimate))
        .unwrap();
    let events = state.recv(&legitimate, "legitimate").unwrap();

    assert_eq!(events.len(), 1);
    match &events[0] {
        ChannelReceiveEvent::Packet { packet, metadata } => {
            assert_eq!(packet.packet_number, 256);
            assert_eq!(*metadata, "legitimate");
        },

        ChannelReceiveEvent::Error { error, .. } =>
            panic!("unexpected decode error: {error:?}"),
    }
    assert_eq!(state.trusted_packet_number_frontier, Some(256));
}

#[test]
fn channel_receive_state_bounds_retained_key_generations() {
    let announce = test_announce();
    let limits = ChannelReceiveLimits {
        max_key_generations: 1,
        ..ChannelReceiveLimits::default()
    };
    let mut state =
        ChannelReceiveState::<()>::with_limits(announce.clone(), limits).unwrap();
    let first = test_key(&announce.channel_id);
    let mut second = first.clone();
    second.key_sequence += 1;
    second.from_packet_number = 1;
    second.secret = vec![0xdd; 16];

    state.insert_key(first).unwrap();
    assert_eq!(state.insert_key(second).unwrap_err(), Error::InvalidState);
    assert_eq!(
        state.terminal_failure(),
        Some(ChannelReceiveFailure::KeyGenerations)
    );
}

#[test]
fn channel_receive_key_derivation_failure_preserves_lifecycle_state() {
    let announce = test_announce();
    let start = Instant::now();
    let first = test_key(&announce.channel_id);
    let mut second = first.clone();
    second.key_sequence = 2;
    second.from_packet_number = 10;
    second.secret = vec![0xdd; 16];
    let mut state = ChannelReceiveState::<()>::new(announce).unwrap();

    state.insert_key_at(first, start).unwrap();
    state.announce.aead_algorithm = u16::MAX;
    let metrics = state.metrics_snapshot();

    assert_eq!(
        state
            .insert_key_at(second, start + Duration::from_secs(1))
            .unwrap_err(),
        Error::InvalidState
    );
    assert_eq!(state.keys.len(), 1);
    assert_eq!(state.keys[0].superseded_at, None);
    assert_eq!(state.trusted_packet_number_frontier, Some(0));
    assert_eq!(state.metrics_snapshot(), metrics);
}

#[test]
fn channel_receive_state_expires_idle_old_key() {
    let announce = test_announce();
    let start = Instant::now();
    let first = test_key(&announce.channel_id);
    let mut second = first.clone();
    second.key_sequence = 2;
    second.from_packet_number = 10;
    second.secret = vec![0xdd; 16];
    let mut state = ChannelReceiveState::<()>::new(announce).unwrap();

    state.insert_key_at(first, start).unwrap();
    state
        .insert_key_at(second, start + Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        state.next_key_expiry(),
        Some(start + Duration::from_secs(4))
    );

    state
        .expire_keys_at(start + Duration::from_secs(3))
        .unwrap();
    assert_eq!(state.metrics_snapshot().active_keys, 2);

    state
        .expire_keys_at(start + Duration::from_secs(4))
        .unwrap();
    let metrics = state.metrics_snapshot();
    assert_eq!(metrics.active_keys, 1);
    assert_eq!(metrics.keys_expired, 1);
}

#[test]
fn channel_receive_state_old_data_refreshes_idle_but_not_age_expiry() {
    let announce = test_announce();
    let start = Instant::now();
    let first = test_key(&announce.channel_id);
    let mut second = first.clone();
    second.key_sequence = 2;
    second.from_packet_number = 10;
    second.secret = vec![0xdd; 16];
    let first_packet = encode_channel_packet(&announce, &first, 9, true, &[
        frame::Frame::Ping { mtu_probe: None },
    ]);
    let second_packet = encode_channel_packet(&announce, &first, 8, true, &[
        frame::Frame::Ping { mtu_probe: None },
    ]);
    let third_packet = encode_channel_packet(&announce, &first, 7, true, &[
        frame::Frame::Ping { mtu_probe: None },
    ]);
    let fourth_packet = encode_channel_packet(&announce, &first, 6, true, &[
        frame::Frame::Ping { mtu_probe: None },
    ]);
    let mut state = ChannelReceiveState::new(announce.clone()).unwrap();

    state.insert_key_at(first, start).unwrap();
    state
        .insert_key_at(second, start + Duration::from_secs(1))
        .unwrap();

    for (packet, packet_number, elapsed) in [
        (&first_packet, 9, 3),
        (&second_packet, 8, 5),
        (&third_packet, 7, 7),
        (&fourth_packet, 6, 9),
    ] {
        state
            .insert_integrity_at(
                integrity_frame(&announce, packet_number, packet),
                start + Duration::from_secs(elapsed),
            )
            .unwrap();
        let events = state
            .recv_buf_at(
                Bytes::copy_from_slice(packet),
                (),
                start + Duration::from_secs(elapsed),
            )
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    // The second delayed packet refreshes the idle deadline to 12s, but
    // the recommended 10s age from receipt of the newer key still wins.
    assert_eq!(
        state.next_key_expiry(),
        Some(start + Duration::from_secs(11))
    );
    state
        .expire_keys_at(start + Duration::from_secs(10))
        .unwrap();
    assert_eq!(state.metrics_snapshot().active_keys, 2);
    state
        .expire_keys_at(start + Duration::from_secs(11))
        .unwrap();
    assert_eq!(state.metrics_snapshot().active_keys, 1);

    let late =
        encode_channel_packet(&announce, &test_key(&[1, 2, 3, 4]), 7, true, &[
            frame::Frame::Ping { mtu_probe: None },
        ]);
    assert!(state
        .recv_buf_at(Bytes::from(late), (), start + Duration::from_secs(12),)
        .unwrap()
        .is_empty());
    assert_eq!(state.metrics_snapshot().pending_packets, 0);
}

#[test]
fn channel_receive_state_enforces_sixty_second_key_maximum() {
    let announce = test_announce();
    let start = Instant::now();
    let limits = ChannelReceiveLimits {
        old_key_delete_after: Duration::from_secs(120),
        old_key_idle_timeout: Duration::from_secs(120),
        ..ChannelReceiveLimits::default()
    };
    let mut state =
        ChannelReceiveState::<()>::with_limits(announce.clone(), limits).unwrap();
    let first = test_key(&announce.channel_id);
    let mut second = first.clone();
    second.key_sequence = 2;
    second.from_packet_number = 10;
    second.secret = vec![0xdd; 16];

    state.insert_key_at(first, start).unwrap();
    state
        .insert_key_at(second, start + Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        state.next_key_expiry(),
        Some(start + Duration::from_secs(61))
    );
    state
        .expire_keys_at(start + Duration::from_secs(60))
        .unwrap();
    assert_eq!(state.metrics_snapshot().active_keys, 2);
    state
        .expire_keys_at(start + Duration::from_secs(61))
        .unwrap();
    assert_eq!(state.metrics_snapshot().active_keys, 1);

    let invalid_limits = ChannelReceiveLimits {
        old_key_max_retention: Duration::from_secs(61),
        ..limits
    };
    assert!(
        ChannelReceiveState::<()>::with_limits(announce, invalid_limits).is_err()
    );
}

#[test]
fn channel_receive_state_handles_reordered_rotations_and_duplicates() {
    let announce = test_announce();
    let start = Instant::now();
    let first = test_key(&announce.channel_id);
    let mut second = first.clone();
    second.key_sequence = 2;
    second.from_packet_number = 10;
    second.secret = vec![0xdd; 16];
    let mut third = first.clone();
    third.key_sequence = 3;
    third.from_packet_number = 20;
    third.secret = vec![0xee; 16];
    let mut state = ChannelReceiveState::<()>::new(announce).unwrap();

    state.insert_key_at(first.clone(), start).unwrap();
    state
        .insert_key_at(third, start + Duration::from_secs(1))
        .unwrap();
    state
        .insert_key_at(second, start + Duration::from_secs(2))
        .unwrap();
    assert_eq!(state.metrics_snapshot().active_keys, 3);

    // An exact retransmission neither creates a generation nor refreshes
    // the supersession deadline.
    state
        .insert_key_at(first, start + Duration::from_secs(3))
        .unwrap();
    assert_eq!(
        state.next_key_expiry(),
        Some(start + Duration::from_secs(4))
    );

    state
        .expire_keys_at(start + Duration::from_secs(4))
        .unwrap();
    assert_eq!(state.metrics_snapshot().active_keys, 1);

    // A late retransmission of an expired key cannot resurrect it.
    state
        .insert_key_at(
            Key {
                channel_id: vec![1, 2, 3, 4],
                key_sequence: 2,
                from_packet_number: 10,
                secret: vec![0xdd; 16],
            },
            start + Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(state.metrics_snapshot().active_keys, 1);
}

#[test]
fn channel_receive_state_rejects_decreasing_rotation_packet_number() {
    let announce = test_announce();
    let start = Instant::now();
    let mut first = test_key(&announce.channel_id);
    first.from_packet_number = 10;
    let mut second = first.clone();
    second.key_sequence = 2;
    second.from_packet_number = 9;
    second.secret = vec![0xdd; 16];
    let mut state = ChannelReceiveState::<()>::new(announce).unwrap();

    state.insert_key_at(first, start).unwrap();
    assert_eq!(
        state
            .insert_key_at(second, start + Duration::from_secs(1))
            .unwrap_err(),
        Error::InvalidFrame
    );
    assert_eq!(state.terminal_failure(), None);
}

#[test]
#[ignore = "release-mode receive resource profile; run explicitly"]
fn channel_receive_profiles_metadata_floods_and_key_rotation() {
    const PACKET_COUNT: u64 = 4_000;
    const ROTATION_COUNT: u64 = 1_000;

    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let packets = (0..PACKET_COUNT)
        .map(|packet_number| {
            let packet =
                encode_channel_packet(&announce, &key, packet_number, true, &[
                    frame::Frame::Ping { mtu_probe: None },
                ]);
            let integrity = integrity_frame(&announce, packet_number, &packet);
            (packet, integrity)
        })
        .collect::<Vec<_>>();

    let mut integrity_first = ChannelReceiveState::new(announce.clone()).unwrap();
    integrity_first.insert_key(key.clone()).unwrap();
    let started = Instant::now();
    let mut peak_integrity_entries = 0;
    for (_, integrity) in &packets {
        assert!(integrity_first
            .insert_integrity(integrity.clone())
            .unwrap()
            .is_empty());
        peak_integrity_entries = peak_integrity_entries
            .max(integrity_first.metrics_snapshot().pending_integrity_entries);
    }
    let mut integrity_first_events = 0_usize;
    for (packet, _) in &packets {
        integrity_first_events = integrity_first_events
            .saturating_add(integrity_first.recv(packet, ()).unwrap().len());
    }
    let integrity_first_elapsed = started.elapsed();

    let mut data_first = ChannelReceiveState::new(announce.clone()).unwrap();
    data_first.insert_key(key.clone()).unwrap();
    let started = Instant::now();
    let mut peak_pending_packets = 0;
    let mut peak_pending_packet_bytes = 0;
    for (packet, _) in &packets {
        assert!(data_first.recv(packet, ()).unwrap().is_empty());
        let metrics = data_first.metrics_snapshot();
        peak_pending_packets = peak_pending_packets.max(metrics.pending_packets);
        peak_pending_packet_bytes =
            peak_pending_packet_bytes.max(metrics.pending_packet_bytes);
    }
    let mut data_first_events = 0_usize;
    for (_, integrity) in &packets {
        data_first_events = data_first_events.saturating_add(
            data_first
                .insert_integrity(integrity.clone())
                .unwrap()
                .len(),
        );
    }
    let data_first_elapsed = started.elapsed();

    let start = Instant::now();
    let mut rotating = ChannelReceiveState::<()>::new(announce).unwrap();
    rotating.insert_key_at(key.clone(), start).unwrap();
    for generation in 2..=ROTATION_COUNT {
        let now = start + Duration::from_secs(generation * 2);
        rotating
            .insert_key_at(
                Key {
                    channel_id: key.channel_id.clone(),
                    key_sequence: generation,
                    from_packet_number: generation,
                    secret: vec![(generation & 0xff) as u8; 16],
                },
                now,
            )
            .unwrap();
        rotating.expire_keys_at(now).unwrap();
        assert!(rotating.metrics_snapshot().active_keys <= 3);
    }

    assert_eq!(integrity_first_events, PACKET_COUNT as usize);
    assert_eq!(data_first_events, PACKET_COUNT as usize);
    let integrity_metrics = integrity_first.metrics_snapshot();
    let data_metrics = data_first.metrics_snapshot();
    println!(
        concat!(
            "MCQUIC_RECEIVE_PROFILE packets={} rotations={} ",
            "integrity_first_us={} data_first_us={} ",
            "peak_integrity_entries={} peak_pending_packets={} ",
            "peak_pending_packet_bytes={} integrity_work={} ",
            "data_work={} integrity_max_work_per_call={} ",
            "data_max_work_per_call={} active_keys={}"
        ),
        PACKET_COUNT,
        ROTATION_COUNT,
        integrity_first_elapsed.as_micros(),
        data_first_elapsed.as_micros(),
        peak_integrity_entries,
        peak_pending_packets,
        peak_pending_packet_bytes,
        integrity_metrics.work_performed,
        data_metrics.work_performed,
        integrity_metrics.max_work_per_call,
        data_metrics.max_work_per_call,
        rotating.metrics_snapshot().active_keys,
    );
}

#[test]
fn channel_receive_state_teardown_owns_sensitive_key_drops() {
    assert!(std::mem::needs_drop::<ChannelKey>());
    assert!(std::mem::needs_drop::<crypto::Open>());

    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut state = ChannelReceiveState::<()>::new(announce).unwrap();
    state.insert_key(key).unwrap();
    assert_eq!(state.metrics_snapshot().active_keys, 1);

    drop(state);
}

#[test]
fn channel_receive_state_rejects_conflicting_integrity_fail_closed() {
    let announce = test_announce();
    let mut state = ChannelReceiveState::<()>::new(announce.clone()).unwrap();
    let integrity = Integrity {
        channel_id: announce.channel_id.clone(),
        packet_number_start: 7,
        packet_hash_count: Some(1),
        packet_hashes: vec![0xaa; 32],
    };

    assert!(state
        .insert_integrity(integrity.clone())
        .unwrap()
        .is_empty());
    assert!(state
        .insert_integrity(integrity.clone())
        .unwrap()
        .is_empty());
    assert_eq!(state.metrics_snapshot().buffered_integrity_entries, 1);
    assert_eq!(state.metrics_snapshot().integrity_hash_overwrites, 1);

    let mut conflicting = integrity;
    conflicting.packet_hashes[0] ^= 0xff;
    assert_eq!(
        state.insert_integrity(conflicting).unwrap_err(),
        Error::InvalidFrame
    );
    assert_eq!(
        state.terminal_failure(),
        Some(ChannelReceiveFailure::ConflictingIntegrity)
    );
    assert_eq!(state.metrics_snapshot().pending_integrity_entries, 0);
    assert_eq!(
        state.continue_processing().unwrap_err(),
        Error::InvalidFrame
    );
}

#[test]
fn channel_receive_state_caps_work_and_events_per_call() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let packets = (0..3)
        .map(|packet_number| {
            encode_channel_packet(&announce, &key, packet_number, true, &[
                frame::Frame::Ping { mtu_probe: None },
            ])
        })
        .collect::<Vec<_>>();
    let packet_hashes = packets
        .iter()
        .flat_map(|packet| {
            IntegrityHashAlgorithm::from_id(announce.integrity_hash_algorithm)
                .unwrap()
                .hash(packet)
        })
        .collect();
    let limits = ChannelReceiveLimits {
        max_work_per_call: 1,
        max_events_per_call: 1,
        ..ChannelReceiveLimits::default()
    };
    let mut state =
        ChannelReceiveState::with_limits(announce.clone(), limits).unwrap();

    for (index, packet) in packets.iter().enumerate() {
        assert!(state.recv(packet, index).unwrap().is_empty());
    }
    assert!(state.insert_key(key).unwrap().is_empty());

    let before = state.metrics_snapshot();
    let mut events = state
        .insert_integrity(Integrity {
            channel_id: announce.channel_id.clone(),
            packet_number_start: 0,
            packet_hash_count: Some(3),
            packet_hashes,
        })
        .unwrap();

    let mut calls = 1;
    while state.has_pending_work() {
        let call_before = state.metrics_snapshot();
        let mut call_events = state.continue_processing().unwrap();
        let call_after = state.metrics_snapshot();

        assert!(call_after.work_performed - call_before.work_performed <= 1);
        assert!(call_after.events_emitted - call_before.events_emitted <= 1);
        events.append(&mut call_events);
        calls += 1;
        assert!(calls < 32);
    }

    let after = state.metrics_snapshot();
    assert_eq!(events.len(), 3);
    assert_eq!(after.packets_delivered, 3);
    assert_eq!(after.max_work_per_call, 1);
    assert_eq!(after.max_events_per_call, 1);
    assert!(after.work_performed - before.work_performed >= 6);
}

#[test]
fn channel_receive_state_rejects_forbidden_frame() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let packet = encode_channel_packet(&announce, &key, 11, true, &[
        frame::Frame::ConnectionClose {
            error_code: 0,
            frame_type: 0,
            reason: Vec::new(),
        },
    ]);
    let integrity = integrity_frame(&announce, 11, &packet);
    let mut state = ChannelReceiveState::new(announce).unwrap();

    assert!(state.insert_key(key).unwrap().is_empty());
    assert!(state.insert_integrity(integrity).unwrap().is_empty());

    let events = state.recv(&packet, "bad-frame").unwrap();
    assert_eq!(events.len(), 1);

    match &events[0] {
        ChannelReceiveEvent::Packet { .. } => panic!("unexpected decoded packet"),

        ChannelReceiveEvent::Error { error, metadata } => {
            assert_eq!(*error, Error::InvalidFrame);
            assert_eq!(*metadata, "bad-frame");
        },
    }

    let metrics = state.metrics_snapshot();
    assert_eq!(metrics.invalid_frame_errors, 1);
    assert_eq!(metrics.packets_delivered, 0);
}

#[test]
fn channel_send_metrics_delta_tracks_changes() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut sender = ChannelSendState::new(announce, key).unwrap();
    let before = sender.metrics_snapshot();
    let mut out = [0; 256];

    sender
        .write_packet(&[ChannelFrame::Ping], &mut out)
        .unwrap();

    let after = sender.metrics_snapshot();
    let delta = ChannelSendMetricsDelta::between(before, after);

    assert_eq!(delta, ChannelSendMetricsDelta {
        write_calls: 1,
        packets_encoded: 1,
        bytes_encoded: after.bytes_encoded,
        frames_encoded: 1,
        key_updates: 0,
        encode_errors: 0,
        ack_frames_processed: 0,
        ack_blocks_processed: 0,
        acked_packets_reported: 0,
        ack_errors: 0,
        largest_acknowledged: None,
        last_packet_number: Some(0),
        next_packet_number: 1,
    });
}

#[test]
fn stream_delivery_metrics_delta_is_saturating() {
    let before = StreamDeliveryMetricsSnapshot {
        direct_fallback_ranges_total: 9,
        direct_fallback_bytes_total: 8,
        ack_gap_recovery_ranges_total: 7,
        ack_gap_recovery_bytes_total: 6,
        fallback_reentry_ranges_total: 5,
        fallback_reentry_bytes_total: 4,
        recovery_limit_fallbacks_total: 3,
    };
    let after = StreamDeliveryMetricsSnapshot {
        direct_fallback_ranges_total: 10,
        direct_fallback_bytes_total: 3,
        ack_gap_recovery_ranges_total: 9,
        ack_gap_recovery_bytes_total: 12,
        fallback_reentry_ranges_total: 2,
        fallback_reentry_bytes_total: 11,
        recovery_limit_fallbacks_total: 5,
    };

    assert_eq!(
        StreamDeliveryMetricsDelta::between(before, after),
        StreamDeliveryMetricsDelta {
            direct_fallback_ranges_total: 1,
            direct_fallback_bytes_total: 0,
            ack_gap_recovery_ranges_total: 2,
            ack_gap_recovery_bytes_total: 6,
            fallback_reentry_ranges_total: 0,
            fallback_reentry_bytes_total: 7,
            recovery_limit_fallbacks_total: 2,
        }
    );
}

#[test]
fn channel_receive_metrics_delta_tracks_changes() {
    let announce = test_announce();
    let key = test_key(&announce.channel_id);
    let mut sender =
        ChannelSendState::new(announce.clone(), key.clone()).unwrap();
    let mut receiver = ChannelReceiveState::new(announce).unwrap();
    let before = receiver.metrics_snapshot();
    let mut out = [0; 256];

    receiver.insert_key(key).unwrap();
    let sent = sender
        .write_packet(&[ChannelFrame::Ping], &mut out)
        .unwrap();
    receiver.insert_integrity(sent.integrity).unwrap();
    receiver.recv(&out[..sent.packet_len], ()).unwrap();

    let after = receiver.metrics_snapshot();
    let delta = ChannelReceiveMetricsDelta::between(before, after);

    assert_eq!(delta.recv_calls, 1);
    assert_eq!(delta.recv_bytes, sent.packet_len as u64);
    assert_eq!(delta.packets_buffered, 1);
    assert_eq!(delta.packets_delivered, 1);
    assert_eq!(delta.packets_released_on_recv, 1);
    assert_eq!(delta.keys_received, 1);
    assert_eq!(delta.integrity_frames_received, 1);
    assert_eq!(delta.integrity_hashes_received, 1);
    assert_eq!(delta.pending_packets, 0);
}

#[test]
fn control_frame_queue_preserves_mixed_burst_order() {
    let channel_id = vec![1, 2, 3, 4];
    let frames = [
        Frame::Key(test_key(&channel_id)),
        Frame::Integrity(Integrity {
            channel_id: channel_id.clone(),
            packet_number_start: 3,
            packet_hash_count: Some(1),
            packet_hashes: vec![0xaa; 32],
        }),
        Frame::Leave(Leave {
            channel_id: channel_id.clone(),
            mc_state_sequence: 7,
            after_packet_number: 3,
        }),
        Frame::Retire(Retire {
            channel_id,
            after_packet_number: 4,
        }),
    ];
    let mut queue = ControlFrameQueue::new(frames.len());

    for frame in &frames {
        queue.push(frame.clone()).unwrap();
    }

    assert_eq!(queue.len(), frames.len());
    for frame in frames {
        assert_eq!(queue.pop(), Some(frame));
    }
    assert_eq!(queue.pop(), None);
}

#[test]
fn control_frame_queue_coalesces_only_exact_duplicates() {
    let channel_id = vec![1, 2, 3, 4];
    let first = Frame::State(State {
        channel_id: channel_id.clone(),
        sequence: 1,
        state: ChannelState::Joined,
        reason_scope: StateReasonScope::Transport,
        reason_code: STATE_REASON_REQUESTED_BY_SERVER,
        reason_phrase: Vec::new(),
    });
    let second = Frame::State(State {
        channel_id,
        sequence: 2,
        state: ChannelState::Left,
        reason_scope: StateReasonScope::Transport,
        reason_code: STATE_REASON_REQUESTED_BY_SERVER,
        reason_phrase: Vec::new(),
    });
    let mut queue = ControlFrameQueue::new(2);

    queue.push(first.clone()).unwrap();
    queue.push(first.clone()).unwrap();
    queue.push(second.clone()).unwrap();

    assert_eq!(queue.len(), 2);
    assert_eq!(queue.pop(), Some(first));
    assert_eq!(queue.pop(), Some(second));
}

#[test]
fn control_frame_queue_overflow_preserves_retained_frames() {
    let channel_id = vec![1, 2, 3, 4];
    let first = Frame::Limits(Limits {
        sequence: 1,
        limits: ClientLimits {
            ipv6_channels_allowed: false,
            ipv4_channels_allowed: true,
            max_aggregate_rate_kibps: 4096,
            max_channel_ids: 4,
        },
        max_joined_count: 2,
    });
    let second = Frame::Ack(Ack {
        channel_id,
        largest_acknowledged: 2,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: Vec::new(),
        ecn_counts: None,
    });
    let mut queue = ControlFrameQueue::new(1);

    queue.push(first.clone()).unwrap();
    assert_eq!(queue.push(second), Err(Error::Done));
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.pop(), Some(first));
}

#[test]
fn control_send_queue_bounds_items_and_retained_bytes() {
    let first = Frame::Key(test_key(&[1, 2, 3, 4]));
    let second = Frame::Leave(Leave {
        channel_id: vec![1, 2, 3, 4],
        mc_state_sequence: 1,
        after_packet_number: 9,
    });
    let first_bytes = first.encoded_len().unwrap();
    let mut item_bounded =
        ControlSendQueue::new(1, first_bytes + second.encoded_len().unwrap());

    assert_eq!(item_bounded.push_back(first.clone()), Ok(()));
    assert_eq!(
        item_bounded.push_back(second.clone()),
        Err(ControlSendQueueError::Full(second))
    );
    assert_eq!(item_bounded.len(), 1);
    assert_eq!(item_bounded.retained_bytes(), first_bytes);
    assert_eq!(item_bounded.pop_front_for_send(), Some(first.clone()));
    assert!(item_bounded.is_empty());
    assert_eq!(item_bounded.len(), 0);
    assert_eq!(item_bounded.accounted_len(), 1);
    assert_eq!(item_bounded.in_flight_len(), 1);
    assert_eq!(item_bounded.in_flight_retained_bytes(), first_bytes);
    assert_eq!(item_bounded.retained_bytes(), first_bytes);

    item_bounded.release_acked(&first);
    assert_eq!(item_bounded.len(), 0);
    assert_eq!(item_bounded.retained_bytes(), 0);

    let mut byte_bounded =
        ControlSendQueue::new(2, first_bytes.saturating_sub(1));
    assert_eq!(
        byte_bounded.push_back(first.clone()),
        Err(ControlSendQueueError::Oversized(first))
    );
    assert!(byte_bounded.is_empty());
}

#[test]
fn invalid_control_frame_does_not_poison_send_queue() {
    let mut invalid = test_key(&[1, 2, 3, 4]);
    invalid.key_sequence = MAX_VARINT + 1;
    let invalid = Frame::Key(invalid);
    let valid = Frame::Key(test_key(&[1, 2, 3, 4]));
    let mut queue = ControlSendQueue::new(2, 4096);

    assert_eq!(
        queue.push_back(invalid.clone()),
        Err(ControlSendQueueError::Invalid(invalid))
    );
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.accounted_len(), 0);
    assert_eq!(queue.retained_bytes(), 0);

    queue.push_back(valid.clone()).unwrap();
    assert_eq!(queue.pop_front_for_send(), Some(valid));
}

#[test]
#[ignore = "release-mode ControlSendQueue performance probe"]
fn control_send_queue_ack_loss_churn_release_probe() {
    for retained in [1_usize, 128, 1024] {
        let frames = (0..retained)
            .map(|sequence| {
                Frame::Key(Key {
                    channel_id: vec![1, 2, 3, 4],
                    key_sequence: sequence as u64,
                    from_packet_number: sequence as u64,
                    secret: vec![(sequence & 0xff) as u8; 16],
                })
            })
            .collect::<Vec<_>>();
        let retained_bytes = frames.iter().fold(0_usize, |total, frame| {
            total.saturating_add(frame.encoded_len().unwrap())
        });
        let started = Instant::now();
        let mut queue = ControlSendQueue::new(retained, retained_bytes.max(1));
        for frame in &frames {
            queue.push_back(frame.clone()).unwrap();
        }
        while queue.pop_front_for_send().is_some() {}
        for frame in frames.iter().rev() {
            queue.requeue_lost(frame.clone());
            queue.release_acked(frame);
        }
        let elapsed = started.elapsed();

        assert_eq!(queue.accounted_len(), 0);
        println!(
            "control_send_queue retained={retained} churn_us={}",
            elapsed.as_micros()
        );
    }
}

#[test]
fn control_send_queue_reserves_retransmission_capacity_until_ack() {
    let key = Frame::Key(test_key(&[1, 2, 3, 4]));
    let leave = Frame::Leave(Leave {
        channel_id: vec![1, 2, 3, 4],
        mc_state_sequence: 1,
        after_packet_number: 9,
    });
    let retained_bytes =
        key.encoded_len().unwrap() + leave.encoded_len().unwrap();
    let mut queue = ControlSendQueue::new(2, retained_bytes);

    queue.push_back(key.clone()).unwrap();
    assert_eq!(queue.pop_front_for_send(), Some(key.clone()));
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.accounted_len(), 1);

    queue.push_back(leave.clone()).unwrap();
    let rejected = Frame::Retire(Retire {
        channel_id: vec![1, 2, 3, 4],
        after_packet_number: 10,
    });
    assert_eq!(
        queue.push_back(rejected.clone()),
        Err(ControlSendQueueError::Full(rejected))
    );

    queue.requeue_lost(key.clone());
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.accounted_len(), 2);
    assert_eq!(queue.in_flight_len(), 0);
    assert_eq!(queue.pop_front_for_send(), Some(key.clone()));

    queue.release_acked(&key);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.accounted_len(), 1);
    assert_eq!(queue.retained_bytes(), leave.encoded_len().unwrap());
}

#[test]
fn control_send_queue_coalesces_duplicate_retry_and_late_ack() {
    let key = Frame::Key(test_key(&[1, 2, 3, 4]));
    let mut queue = ControlSendQueue::new(1, key.encoded_len().unwrap());

    queue.push_back(key.clone()).unwrap();
    queue.push_back(key.clone()).unwrap();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.accounted_len(), 1);
    assert_eq!(queue.retained_bytes(), key.encoded_len().unwrap());

    assert_eq!(queue.pop_front_for_send(), Some(key.clone()));
    queue.requeue_lost(key.clone());
    queue.requeue_lost(key.clone());
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.in_flight_len(), 0);

    assert_eq!(queue.pop_front_for_send(), Some(key.clone()));
    assert_eq!(queue.in_flight_len(), 1);

    // A late ACK for the original transmission also satisfies the
    // identical retransmission and releases its one logical reservation.
    queue.release_acked(&key);
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.accounted_len(), 0);
    assert_eq!(queue.in_flight_len(), 0);
    assert_eq!(queue.retained_bytes(), 0);

    // A later loss report for the now-obsolete retransmission is ignored.
    queue.requeue_lost(key);
    assert!(queue.is_empty());
    assert_eq!(queue.accounted_len(), 0);
}
