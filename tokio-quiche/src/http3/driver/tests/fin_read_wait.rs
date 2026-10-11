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

use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Delivery {
    FinOnly,
    LostFin,
    RequeuedTail,
}

// Poll the public controller transaction and the actual ApplicationOverQuic
// callbacks. No copied readiness loop or direct Runtime handlers are used.
async fn transact<H: DriverHooks + GetConnectionForHook, F: Future>(
    helper: &mut DriverTestHelper<H>, future: F,
) -> F::Output {
    tokio::pin!(future);
    for _ in 0..4 {
        if let Poll::Ready(value) = futures::poll!(future.as_mut()) {
            return value;
        }
        helper.work_loop_iter().unwrap();
        tokio::task::yield_now().await;
    }
    if let Poll::Ready(value) = futures::poll!(future.as_mut()) {
        return value;
    }
    panic!("selected transaction failed to complete in bounded driver turns");
}

fn open_peer_stream<H: DriverHooks + GetConnectionForHook>(
    helper: &mut DriverTestHelper<H>, session: u64,
    direction: h3::WebTransportStreamDirection,
) -> (u64, u64) {
    let qconn = H::peer_qconn(&mut helper.pipe);
    // Consume peer SETTINGS through the real H3 connection before reserving.
    while helper.peer.poll(qconn).is_ok() {}
    let reservation = helper
        .peer
        .reserve_webtransport_stream(qconn, session, direction)
        .unwrap();
    let id = reservation.stream_id();
    assert_eq!(
        qconn.stream_send(id, reservation.prefix(), false),
        Ok(reservation.prefix_len())
    );
    helper
        .peer
        .commit_webtransport_stream(qconn, &reservation)
        .unwrap();
    helper.advance_and_run_loop().unwrap();
    (id, reservation.prefix_len() as u64)
}

// Independently inspect authenticated STREAM frame contents, rather than
// inferring FIN from a retransmission-byte counter. Frame is an internal core
// type, so inspect its wire encoding through the existing test utility.
fn assert_stream_flight(
    receiver: &mut QuicheConnection, flight: &[(Vec<u8>, quiche::SendInfo)],
    id: u64, offset: u64, payload: &[u8], fin: bool,
) {
    let mut seen = 0;
    for (packet, _) in flight {
        for frame in
            quiche::test_utils::decode_pkt(receiver, &mut packet.clone()).unwrap()
        {
            let mut wire = vec![0; frame.wire_len()];
            frame
                .to_bytes(&mut octets::OctetsMut::with_slice(&mut wire))
                .unwrap();
            let mut wire = octets::Octets::with_slice(&wire);
            let ty = wire.get_varint().unwrap();
            if !(0x08..=0x0f).contains(&ty) {
                continue;
            }
            let stream_id = wire.get_varint().unwrap();
            let off = if ty & 4 != 0 {
                wire.get_varint().unwrap()
            } else {
                0
            };
            let len = if ty & 2 != 0 {
                wire.get_varint().unwrap() as usize
            } else {
                wire.cap()
            };
            let data = wire.get_bytes(len).unwrap();
            if stream_id == id {
                assert_eq!(off, offset);
                assert_eq!(data.as_ref(), payload);
                assert_eq!(ty & 1 != 0, fin);
                seen += 1;
            }
        }
    }
    assert_eq!(seen, 1, "exactly one authentic target STREAM frame");
}

async fn expire_loss_timer(qconn: &mut QuicheConnection) {
    // A real PTO, not a polling workaround: advance no receiver ACKs between
    // consumption and the retransmission. Sleep only for the advertised timer.
    tokio::time::sleep(qconn.timeout().unwrap() + Duration::from_millis(2)).await;
    qconn.on_timeout();
}

pub(super) async fn check<H: DriverHooks + GetConnectionForHook>(
    helper: &mut DriverTestHelper<H>, session: u64,
    direction: h3::WebTransportStreamDirection, delivery: Delivery,
    early_wait: bool,
) {
    let controller = helper.controller.webtransport_controller().unwrap();
    let (id, prefix) = open_peer_stream(helper, session, direction);
    let (sibling, _) = open_peer_stream(
        helper,
        session,
        h3::WebTransportStreamDirection::Bidirectional,
    );
    const PAYLOAD: &[u8] = b"last payload";
    assert_eq!(
        H::peer_qconn(&mut helper.pipe).stream_send(id, PAYLOAD, false),
        Ok(PAYLOAD.len())
    );
    let data =
        quiche::test_utils::emit_flight(H::peer_qconn(&mut helper.pipe)).unwrap();
    assert_stream_flight(
        H::qconn(&mut helper.pipe),
        &data,
        id,
        prefix,
        PAYLOAD,
        false,
    );
    quiche::test_utils::process_flight(H::qconn(&mut helper.pipe), data).unwrap();
    helper.work_loop_iter().unwrap();
    assert_eq!(
        transact(helper, controller.read_stream(session, id, 64)).await,
        WebTransportStreamReadOutcome::Data {
            data: Bytes::from_static(PAYLOAD),
            fin: false
        }
    );
    assert_eq!(
        transact(helper, controller.read_stream(session, id, 64)).await,
        WebTransportStreamReadOutcome::Blocked
    );

    let mut cancelled = Box::pin(controller.wait_stream_readable(session, id));
    assert!(futures::poll!(cancelled.as_mut()).is_pending());
    helper.work_loop_iter().unwrap();
    assert!(futures::poll!(cancelled.as_mut()).is_pending());
    let stats = transact(helper, controller.retention_stats())
        .await
        .unwrap();
    assert_eq!(stats.receive_terminal_waiters, 1);
    drop(cancelled);
    let stats = transact(helper, controller.retention_stats())
        .await
        .unwrap();
    assert_eq!(stats.receive_terminal_waiters, 0);

    let mut waiting = Box::pin(controller.wait_stream_readable(session, id));
    if early_wait {
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        helper.work_loop_iter().unwrap();
        assert!(futures::poll!(waiting.as_mut()).is_pending());
    }

    let before = H::peer_qconn(&mut helper.pipe).stats().stream_retrans_bytes;
    if delivery == Delivery::RequeuedTail {
        expire_loss_timer(H::peer_qconn(&mut helper.pipe)).await;
        // send() processes loss before packet encoding. An undersized output
        // requeues the tail but cannot emit it or any FIN.
        assert_eq!(
            H::peer_qconn(&mut helper.pipe).send(&mut [0; 1]),
            Err(quiche::Error::Done)
        );
        assert_eq!(
            H::peer_qconn(&mut helper.pipe).stats().stream_retrans_bytes - before,
            PAYLOAD.len() as u64
        );
    }
    assert_eq!(
        H::peer_qconn(&mut helper.pipe).stream_send(id, b"", true),
        Ok(0)
    );
    if delivery == Delivery::LostFin {
        let lost =
            quiche::test_utils::emit_flight(H::peer_qconn(&mut helper.pipe))
                .unwrap();
        assert_stream_flight(
            H::qconn(&mut helper.pipe),
            &lost,
            id,
            prefix + PAYLOAD.len() as u64,
            b"",
            true,
        );
        drop(lost);
        expire_loss_timer(H::peer_qconn(&mut helper.pipe)).await;
    }
    let flight =
        quiche::test_utils::emit_flight(H::peer_qconn(&mut helper.pipe)).unwrap();
    let (offset, bytes) = if delivery == Delivery::FinOnly {
        (prefix + PAYLOAD.len() as u64, b"".as_slice())
    } else {
        (prefix, PAYLOAD)
    };
    assert_stream_flight(
        H::qconn(&mut helper.pipe),
        &flight,
        id,
        offset,
        bytes,
        true,
    );
    quiche::test_utils::process_flight(H::qconn(&mut helper.pipe), flight)
        .unwrap();
    assert!(H::qconn(&mut helper.pipe).stream_finished(id));
    helper.work_loop_iter().unwrap();
    assert_eq!(
        transact(helper, waiting.as_mut()).await,
        WebTransportStreamReadyOutcome::Ready
    );
    drop(waiting);
    let terminal = assert_matches!(transact(helper, controller.read_stream(session, id, 64)).await,
        WebTransportStreamReadOutcome::Terminal(terminal) => terminal);
    assert_eq!(terminal.terminal(), WebTransportStreamReceiveTerminal::Fin);
    assert!(terminal.data().is_empty());
    assert_eq!(
        transact(
            helper,
            controller.retire_stream_receive_terminal(session, id)
        )
        .await,
        WebTransportStreamReceiveTerminalRetirementOutcome::OutstandingRead {
            session_id: session,
            stream_id: id
        }
    );

    // A genuinely independent stream progresses while the terminal lease lives.
    H::peer_qconn(&mut helper.pipe)
        .stream_send(sibling, b"sibling", true)
        .unwrap();
    helper.advance_and_run_loop().unwrap();
    let sibling_terminal = assert_matches!(transact(helper, controller.read_stream(session, sibling, 64)).await,
        WebTransportStreamReadOutcome::Terminal(terminal) => terminal);
    assert_eq!(sibling_terminal.data(), b"sibling");
    assert_eq!(
        sibling_terminal.terminal(),
        WebTransportStreamReceiveTerminal::Fin
    );
    drop(sibling_terminal);
    drop(terminal);

    // Repeated level-triggered observations must give FIN, never Ready/Blocked.
    for _ in 0..3 {
        assert_eq!(
            transact(helper, controller.wait_stream_readable(session, id)).await,
            WebTransportStreamReadyOutcome::Ready
        );
        let terminal = assert_matches!(transact(helper, controller.read_stream(session, id, 64)).await,
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal);
        assert_eq!(terminal.terminal(), WebTransportStreamReceiveTerminal::Fin);
        assert!(terminal.data().is_empty());
        drop(terminal);
    }
    for stream_id in [id, sibling] {
        assert_eq!(
            transact(
                helper,
                controller.retire_stream_receive_terminal(session, stream_id)
            )
            .await,
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id: session,
                stream_id
            }
        );
    }
    let stats = transact(helper, controller.retention_stats())
        .await
        .unwrap();
    assert_eq!(stats.receive_terminal_leases, 0);
    assert_eq!(stats.receive_terminal_waiters, 0);
    assert_eq!(stats.receive_terminal_states, 0);
    assert_eq!(stats.receive_terminal_bytes, 0);

    // Receive retirement must not finish the independent bidi send direction.
    // Close it through the selected API, deliver/ACK the authentic FIN, and
    // retire its observation before asserting stream collection.
    for stream_id in [id, sibling] {
        if stream_id == id &&
            direction == h3::WebTransportStreamDirection::Unidirectional
        {
            continue;
        }
        assert!(!H::qconn(&mut helper.pipe).stream_closed(stream_id));
        let write = controller
            .try_write_stream(
                session,
                stream_id,
                Bytes::from_static(b"reply"),
                true,
            )
            .unwrap();
        assert_eq!(
            transact(helper, write.outcome()).await,
            WebTransportStreamWriteOutcome::Accepted {
                accepted: 5,
                remaining: None,
                fin_accepted: true
            }
        );
        helper.advance_and_run_loop().unwrap();
        let mut reply = [0; 5];
        assert_eq!(
            H::peer_qconn(&mut helper.pipe).stream_recv(stream_id, &mut reply),
            Ok((5, true))
        );
        assert_eq!(&reply, b"reply");
        assert_eq!(
            transact(
                helper,
                controller.wait_stream_send_terminal(session, stream_id)
            )
            .await,
            WebTransportStreamSendTerminalOutcome::Closed { stream_id }
        );
        assert_eq!(
            transact(
                helper,
                controller.retire_stream_send_terminal(session, stream_id)
            )
            .await,
            WebTransportStreamSendTerminalOutcome::Retired {
                session_id: session,
                stream_id
            }
        );
    }
    helper.advance_and_run_loop().unwrap();
    let stats = transact(helper, controller.retention_stats())
        .await
        .unwrap();
    assert_eq!(stats.associated_streams, 0);
    assert_eq!(stats.receive_terminal_observations, 0);
    assert_eq!(stats.send_terminal_states, 0);
    assert_eq!(stats.waiters, 0);
    for stream_id in [id, sibling] {
        assert!(!H::qconn(&mut helper.pipe).stream_readable(stream_id));
        assert_eq!(
            H::qconn(&mut helper.pipe).stream_send_status(stream_id),
            Err(quiche::Error::InvalidStreamState(stream_id))
        );
    }
}
