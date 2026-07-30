# MCQUIC STREAM Server API

`tokio_quiche::multicast::ServerStreamPublisher` separates shared multicast
publication from per-client QUIC state. It owns no sockets and has no
WebTransport, HTTP/3, media, or MoQ knowledge.

One publisher owns the channel packet-number space, channel encryption,
integrity generation, and shared STREAM bytes. Each attached
`ServerControlDriver` retains independent `MC_LIMITS`, `MC_STATE`, `MC_ACK`,
probe generation, stream flow control, reset state, recovery, and fallback.

The ordinary application stream remains the source of truth. Multicast is an
alternate transport path for identical stream IDs, offsets, FIN, and bytes.

## Connection Integration

For each client connection:

1. Construct `ServerControlDriver` with `ServerControlDriver::new()` or
   `new_with_runtime_limits()`, handle the returned
   `Result<(ServerControlDriver<_>, ServerControlController), RuntimeLimitsError>`,
   and retain the controller.
2. Queue any connection-specific stream prefix through ordinary
   `qconn.stream_send()`.
3. Call `publisher.declare_stream(stream_id)` before the stream's first channel
   packet. Automatic mode uses the declaration to enforce the client's
   `MAX_STREAMS_UNI` before `MC_JOIN`.
4. Call `publisher.attach(&controller)` and retain the returned
   `ServerStreamAttachment` for the connection lifetime.

For the current Yggdrasil WebTransport convention, the connection-specific
prefix is the two-byte encoding of stream type `0x54` followed by the
fixed-width eight-byte Session ID. Shared data therefore starts at offset 10.
That convention belongs to Yggdrasil, not this API.

Dropping an attachment seals it against future fanout. Already committed
publications and FIN remain ordered and drain before connection-local recovery
state is released.

## Publication Contract

For each shared range:

```rust,ignore
let publication = publisher.prepare_stream_buf(
    stream_id,
    offset,
    fin,
    shared_bytes,
)?;

// The application owns multicast socket I/O.
multicast_sender.send(publication.packet())?;

// Commit only after publication is known to have succeeded.
publisher.commit(publication)?;
```

`prepare_stream_buf()` accepts only server-initiated unidirectional stream IDs
and contiguous offsets within each stream. The first shared offset may be
nonzero because connection-specific bytes can precede it. Only one unresolved
publication may exist at a time, preserving continuous channel packet numbers
and preventing AEAD nonce reuse.

Preparation is structurally committable. Before consuming a packet number,
advancing an offset, rotating a key, or exposing ciphertext, the publisher
checks the active-stream bound, completed-history capacity, and fixed 64 KiB
attachment-item bound. Queue saturation is reported separately from an item
that can never fit. Attached and unattached publishers use the same checks.

A `ServerStreamPublication` is a consuming one-use resolution handle:

- If no external progress has occurred, retain the same handle and retry its
  identical `packet()` bytes.
- After known successful publication, call `commit()` exactly once.
- To stop before any external attempt, call `abandon()`. The current channel is
  retired, so no packet-number gap is introduced into a continuing channel.
- If the external send may or may not have progressed, call
  `publication_progress_uncertain()`. The publisher fail-stops and retires.
- Dropping an unresolved handle also fail-stops and retires.
- Foreign, stale, duplicate, or crossed resolutions return
  `UnknownPublication`.

An uncertain socket result is never rolled back. Prepared packet numbers and
nonce material are not reused.

`commit()` fans one shared `Bytes` allocation and matching `MC_INTEGRITY`
metadata to attached connections. Each connection registers recovery before
its integrity frame is relayed.

## Fallback And Recovery

- Before a validated `MC_ACK`, every committed range is sent on the ordinary
  unicast QUIC stream.
- `MC_STATE(JOINED)` alone never disables fallback.
- Reattachment starts a fresh probe generation. Prior viability and delayed
  ACKs cannot suppress initial fallback.
- After an advancing valid `MC_ACK` makes a channel viable, new ranges are
  withheld without unicast duplication.
- Duplicate or regressive ACKs may resolve retained ranges but do not refresh
  green status.
- A missing range beyond the reordering threshold is released through ordinary
  QUIC.
- ACK timeout, failed join, leave, retirement, recovery-limit saturation, or
  probe re-entry releases retained ranges and resumes fallback.
- Local reset or peer `STOP_SENDING` removes only that connection's retained
  ranges.
- A client that never negotiates multicast or never becomes green remains on
  ordinary QUIC.

For a late attachment, call `publisher.next_stream_offset(stream_id)` and send
the identical earlier bytes over unicast until that connection reaches the
reported offset. A committed range ahead of the connection offset waits without
blocking other streams. An overlapping range is rejected because duplicate
offset bytes must be identical.

## Ordering And Fairness

Pending publications are queued per stream and scheduled round-robin. A stream
waiting for a prefix, flow-control credit, or a stream limit does not block
another stream or channel.

The following operations are channel-local barriers:

- publisher key rotation;
- explicit publisher retirement;
- live attachment detach;
- automatic retirement after a reduced client Channel ID limit.

The runtime drains that channel's committed STREAM ranges, flushes its integrity
batch and pending integrity, and only then emits the key/retire control or
releases recovery state. Other channels continue while one barrier waits.

STREAM publications are never dropped independently. If a connection cannot
retain required publication state within configured bounds, that connection
runtime fail-stops. A saturated attachment is sealed and detached without
stalling or increasing memory for healthy attachments.

Transfer from an attachment queue into connection commands is transactional.
Each staging operation consumes one unit from the complete driver callback
budget. If command admission stops, the exact unadmitted suffix is restored at
the front with its logical byte charge intact. A deferred barrier remains
runnable after preceding work consumes the callback's final work slot, so it
does not require an unrelated socket, timer, or command wake.

`max_work_per_call` is one aggregate budget across every callback work class,
not a separate allowance for attachment staging, command handling,
publications, integrity, controls, metrics, or probes. One unit is one
successful scheduled class operation. Processing one receive ingress/control
includes its single core admission and cannot open a nested receive budget.
Readiness scans and unsuccessful attempts are not charged.

Client reads use 4 classes and writes 5; control-server reads use 10 and writes
8; publication-owning-server reads use 3 and writes 5. With `K` continuously
ready classes and budget `B`, each class progresses within `ceil(K / B)`
callbacks. A class with `N` continuously ready channels reaches all of them
within the conservative `N * ceil(K / B)` callback bound. Rotating class and
Channel-ID cursors prevent low-sorted work from starving later work and remain
valid across insertion, removal, replacement, blocking, and closure.

## Configurable Bounds

`RuntimeLimits` configures one Tokio multicast connection wrapper:

| Field | Default |
| --- | ---: |
| `events` | 4,096 events / 64 MiB |
| `commands` | 4,096 items / 64 MiB |
| `ingress` | 4,096 items / 64 MiB |
| `pending_publications` | 4,096 items / 64 MiB |
| `pending_integrity` | 8,192 items / 8 MiB |
| `max_work_per_call` | 256 |
| `control_retry_delay` | 1 ms |
| `control_backpressure_timeout` | 30 seconds |
| `max_tracked_channel_ids` | 1,024 connection-lifetime IDs |

Retry and backpressure durations are validated with checked `Instant`
arithmetic. An unrepresentable deadline is rejected by driver construction
before queues or runtime state are created.

Create a driver with explicit limits:

```rust,ignore
let (driver, mut controller) =
    ServerControlDriver::new_with_runtime_limits(
        app,
        control_settings,
        runtime_limits,
    )?;
```

`ServerStreamPublisher::with_limits()` accepts
`ServerStreamPublisherLimits`. Its defaults are 4,096 committed items and
8 MiB of logical retained bytes per attachment, 65,536 concurrently active
streams, and 4,096 completed-stream sparse/range storage units. Attachment byte
capacity must be at least 128 KiB, and one publication/key item may retain at
most 64 KiB. A high initial WebTransport stream ID does not allocate history
from zero; sparse chunks become fixed-size bitmaps only when dense.

`ServerControlController::runtime_queue_stats()` returns current/peak items and
bytes plus admission and saturation counters for commands, pending
publications, and pending integrity. Queue accounting follows items from the
Tokio channel into runtime staging.

Core quiche recovery bounds are configured with
`Config::set_multicast_stream_recovery_limits()`. Defaults are:

- 65,536 ranges and 64 MiB per connection;
- 16,384 ranges and 16 MiB per channel.

Reaching a recovery bound releases the affected channel through ordinary
unicast and marks it recovery-limited until a fresh probe generation.

## Event Stream Migration

`ClientEventStream` and `ServerEventStream` are managed bounded receiver
structs, not aliases to `tokio::sync::mpsc::UnboundedReceiver`.

Both implement `futures::Stream` and provide:

```rust,ignore
let event = events.recv().await;
let immediate = events.try_recv();
events.close();
let stats = events.stats();
let terminal = events.terminal();
```

They also implement `futures::stream::FusedStream`. Runtime completion seals
every sender clone immediately. Events accepted before completion remain
drainable in order, after which the stream returns `None` permanently.

Controller access changed at the source level:

```rust,ignore
let events = controller
    .take_event_receiver()
    .expect("event receiver already taken");
```

- `event_receiver_mut()` now returns `Option<&mut ClientEventStream>` or
  `Option<&mut ServerEventStream>`.
- `take_event_receiver()` now returns `Option<ClientEventStream>` or
  `Option<ServerEventStream>`.
- The receiver can be taken only once; later calls return `None`.
- Taking or dropping it never creates a replacement or unbounded queue.

Lifecycle, state, error, packet, publication, and ACK events are required.
Failure to admit one terminates the affected runtime deterministically; the
terminal reason and rejected event kind remain in wrapper-owned state even when
the full queue cannot carry another event. Client metric snapshots are
latest-only per channel. Exact duplicate diagnostics coalesce only where their
meaning is identical.

Use `event_queue_stats()` on the controller or `stats()` on the stream to
inspect saturation, retained/peak items and bytes, metric coalescing/eviction,
diagnostic coalescing, receiver drops, and terminal overload without consuming
events.

Controller sends now return an owned `ControllerSendError<T>` rather than
erasing admission causes or consuming rejected input:

```rust,ignore
match controller.send_integrity(integrity) {
    Ok(()) => {},
    Err(error) if error.kind() == ControllerSendErrorKind::Full => {
        integrity = error.into_inner();
        // Retry after the driver makes progress.
    },
    Err(error) => return Err(error.into()),
}
```

`kind()` distinguishes `Full`, `Oversized`, `InvalidValue`, and `Closed`;
`value()` borrows the rejected value and `into_inner()` recovers it.
`InvalidValue` is returned before queue reservation or control-state mutation.
`ServerController::send_on_channel()` uses the `ServerChannelPacket` and
`ServerChannelSendError` aliases.

At core level, `Connection::multicast_try_send()` similarly returns an owned
`multicast::ControlSendError`. The consuming
`Connection::multicast_send()` compatibility wrapper remains, mapping
saturation to `Error::Done`. Reliable control reservations remain charged
until ACK, so a loss retry never competes for new queue capacity.

`Announce` and `Key` redact secret fields from `Debug` and overwrite their
owned vectors with safe Rust writes on explicit drop paths. This is
best-effort logical clearing, not a claim of non-elidable cryptographic
zeroization or backend-internal key erasure. Their `Drop` implementations
prevent moving individual fields out directly; borrow, clone required
non-secret data, or destructure by reference.

## Delivery Metrics

Core quiche exposes a cumulative per-connection/channel snapshot through
`Connection::multicast_stream_delivery_metrics_snapshot(channel_id)`.
`StreamDeliveryMetricsDelta::between(before, after)` computes a saturating
difference. `ServerStreamPublisher::delivery_metrics_snapshot()` aggregates
these counters across every connection attached during the publisher's
lifetime and retains totals after detach.

The snapshot contains:

- `direct_fallback_*`: ranges sent through ordinary QUIC before viability;
- `ack_gap_recovery_*`: viable-channel ranges released for ACK-proven gaps;
- `fallback_reentry_*`: retained ranges released when viability is lost;
- recovery-limit fallback counters for local retention protection.

Bytes are unique STREAM payload bytes accepted by ordinary QUIC, not wire bytes.
Framing, encryption, retransmission, control traffic, and socket egress are
excluded. A zero-length FIN can add one range and zero bytes.

`ServerStreamPublisher::metrics_snapshot()` remains the independent multicast
packet-encoding snapshot.

## Controls

Automatic `ServerControlMode` sends admitted `MC_ANNOUNCE` and `MC_KEY`, then
`MC_JOIN` when current client and stream limits permit. Manual mode leaves exact
announce/key/join sequencing to `ServerControlController`.

Dynamic controller methods support post-handshake announce/update, key relay,
explicit join, and external integrity relay. `send_integrity()` always uses the
client-facing unicast control connection; it is not coupled to mctx publication.
Publisher `update_key()` and `retire()` preserve publication/integrity barriers.

All public local control, probe, timeout, DATAGRAM, STREAM-recovery,
default-channel, state, and ACK entry points use the canonical draft-08 Channel
ID validator (1..=20 bytes) and checked QUIC-varint/frame preflight. Invalid
state reasons, packet numbers, offsets, lengths, ACK fields, or timeout
deadlines fail before consuming tracked-ID capacity or mutating queues, probe
state, recovery, packet numbers, metrics, or payload accounting.

The runtime ignores stale `MC_LIMITS`, filters address family and algorithms,
enforces channel/join/rate/stream limits, sends delayed `MC_LEAVE` where needed,
and retires excess announced channels only after committed STREAM barriers.
Unknown peer `MC_ACK` and `MC_STATE` frames do not allocate persistent channel
state. Every peer-selected Channel ID that does allocate state consumes one of
the connection-lifetime tracked-ID slots, including after retirement.

The older publication-owning `ServerDriver` and all existing DATAGRAM behavior
remain available independently.

## Current Boundary

This API completes the server publication and unicast recovery side, but it is
not transport-adapter-ready. Core quiche does not yet inject authenticated
multicast STREAM, RESET_STREAM, and RESET_STREAM_AT frames into the ordinary
client receive stream map. That work is intentionally deferred because
draft-08 does not define source-neutral flow-control accounting, read-credit
generation, overlap accounting, or the bounded-memory outcome.

The following wire outcomes are also intentionally deferred because draft-08
does not define enough semantics to choose them safely:

- `MC_STATE` equal-sequence conflicts and sequence exhaustion;
- multicast packet-number exhaustion after `2^62 - 1`;
- `MC_LIMITS` equal-sequence conflicts and sequence exhaustion;
- conflicting repeated `MC_KEY` content while `MC_EXTENSION_ERROR` remains
  unassigned.

The implementation prevents local arithmetic wrap and rejects invalid
publication before mutation, but preserves existing inbound behavior and does
not invent channel-versus-connection failure scope or substitute
`PROTOCOL_VIOLATION`.
