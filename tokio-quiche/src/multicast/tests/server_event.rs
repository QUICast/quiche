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
fn server_event_coalescer_preserves_same_largest_ack_with_new_ranges() {
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut coalescer = ServerEventCoalescer::default();
    let first = quiche::multicast::Ack {
        channel_id: vec![1, 2, 3, 4],
        largest_acknowledged: 7,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: Vec::new(),
        ecn_counts: None,
    };
    let mut fills_lower_range = first.clone();
    fills_lower_range
        .ack_ranges
        .push(quiche::multicast::AckRange {
            gap: 1,
            ack_range_length: 0,
        });

    coalescer.queue_client_ack(&event_sender, first.clone());
    coalescer.queue_client_ack(&event_sender, fills_lower_range.clone());
    coalescer
        .flush_client_acks(&event_sender, usize::MAX)
        .unwrap();

    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientAck(received)) if received == first
    ));
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientAck(received))
            if received == fills_lower_range
    ));
    assert!(event_receiver.try_recv().is_err());
}

#[test]
fn server_event_coalescer_resets_ack_and_probe_history_per_generation() {
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut coalescer = ServerEventCoalescer::default();
    let ack = quiche::multicast::Ack {
        channel_id: vec![1, 2, 3, 4],
        largest_acknowledged: 7,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: Vec::new(),
        ecn_counts: None,
    };
    let probe = quiche::multicast::ProbeEvent {
        channel_id: ack.channel_id.clone(),
        status: quiche::multicast::ProbeStatus::Probing,
        reason_scope: None,
        reason_code: None,
        reason_phrase: Vec::new(),
    };

    coalescer.queue_client_ack(&event_sender, ack.clone());
    coalescer
        .flush_client_acks(&event_sender, usize::MAX)
        .unwrap();
    coalescer
        .forward_probe_event(&event_sender, probe.clone())
        .unwrap();
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientAck(received)) if received == ack
    ));
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ProbeStatusChanged(received)) if received == probe
    ));

    coalescer.queue_client_ack(&event_sender, ack.clone());
    coalescer
        .forward_probe_event(&event_sender, probe.clone())
        .unwrap();
    assert!(event_receiver.try_recv().is_err());

    coalescer.reset_channel(&ack.channel_id);
    coalescer.queue_client_ack(&event_sender, ack.clone());
    coalescer
        .flush_client_acks(&event_sender, usize::MAX)
        .unwrap();
    coalescer
        .forward_probe_event(&event_sender, probe.clone())
        .unwrap();
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ClientAck(received)) if received == ack
    ));
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ProbeStatusChanged(received)) if received == probe
    ));
}

#[test]
fn server_event_coalescer_suppresses_identical_probe_events() {
    let (event_sender, mut event_receiver, _event_observer) =
        test_server_event_channel();
    let mut coalescer = ServerEventCoalescer::default();
    let event = quiche::multicast::ProbeEvent {
        channel_id: vec![1, 2, 3, 4],
        status: quiche::multicast::ProbeStatus::Probing,
        reason_scope: Some(quiche::multicast::StateReasonScope::Transport),
        reason_code: Some(quiche::multicast::STATE_REASON_REQUESTED_BY_SERVER),
        reason_phrase: Vec::new(),
    };

    coalescer
        .forward_probe_event(&event_sender, event.clone())
        .unwrap();
    coalescer
        .forward_probe_event(&event_sender, event.clone())
        .unwrap();

    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ProbeStatusChanged(received)) if received == event
    ));
    assert!(event_receiver.try_recv().is_err());

    let mut changed = event;
    changed.reason_phrase = b"path changed".to_vec();
    coalescer
        .forward_probe_event(&event_sender, changed.clone())
        .unwrap();
    assert!(matches!(
        event_receiver.try_recv(),
        Ok(ServerEvent::ProbeStatusChanged(received))
            if received == changed
    ));
}
