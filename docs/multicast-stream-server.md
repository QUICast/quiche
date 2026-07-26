# MCQUIC STREAM server API

`tokio_quiche::multicast::ServerStreamPublisher` separates shared multicast
publication from per-client QUIC state. It owns no sockets. One publisher owns
the channel packet number, channel encryption, integrity generation, and shared
STREAM bytes. Each attached `ServerControlDriver` retains its own `MC_LIMITS`,
`MC_STATE`, `MC_ACK`, stream flow control, loss recovery, and fallback state.

The ordinary application stream remains the source of truth. Multicast is an
alternate transport path for identical stream IDs, offsets, FIN, and bytes.

## Yggdrasil integration

For each client connection:

1. Construct `ServerControlDriver` and retain its `ServerControlController`.
2. Queue the connection-specific stream prefix through ordinary
   `qconn.stream_send()`. For the current WebTransport contract this is the
   two-byte encoding of stream type `0x54` followed by the fixed-width eight-byte
   Session ID, so shared data starts at offset 10.
3. Call `publisher.declare_stream(stream_id)` before the stream's first channel
   packet. Automatic mode uses the declaration to enforce the client's
   `MAX_STREAMS_UNI` before sending `MC_JOIN`.
4. Call `publisher.attach(&controller)` and retain the returned
   `ServerStreamAttachment` for the connection lifetime. Dropping it stops new
   publications from being fanned out to that connection. Already committed
   publications and FIN are drained in order before connection-local recovery
   state is released.

For each shared range:

```rust,ignore
let publication = publisher.prepare_stream_buf(
    stream_id,
    offset,
    fin,
    shared_bytes,
)?;

// Yggdrasil owns multicast I/O. Retry this same publication on failure.
multicast_sender.send(publication.packet())?;

// Commit only after the encrypted packet has been published successfully.
publisher.commit(publication)?;
```

`prepare_stream_buf()` requires contiguous offsets per stream and permits only
server-initiated unidirectional stream IDs. It intentionally allows the first
shared offset to be non-zero because connection-specific bytes can precede the
shared body. Only one publication may be prepared but uncommitted at a time;
this prevents silent gaps in the channel packet number space.

`commit()` fans the retained `Bytes` and matching `MC_INTEGRITY` metadata to all
attached connections. The control runtime registers recovery state first and
relays integrity only after registration succeeds. The same `Bytes` allocation
is shared across connections.

## Fallback and recovery

- Before a validated `MC_ACK`, every committed range is sent on the ordinary
  unicast QUIC stream. `MC_STATE(JOINED)` alone does not disable fallback.
- Reattaching a publisher starts a fresh probe generation. Prior viability and
  delayed ACKs from the previous attachment cannot suppress initial fallback.
- After `MC_ACK` makes a channel viable, committed ranges are retained without
  unicast duplication.
- Duplicate or regressive ACKs can still resolve retained ranges but do not
  refresh multicast-green status; ACK progression must advance.
- A missing packet beyond the configured reordering threshold releases its
  exact stream range to ordinary QUIC retransmission.
- `MC_STATE(LEFT)`, join failure, retirement, or ACK freshness timeout releases
  all retained ranges and resumes unicast fallback.
- A local stream reset or peer `STOP_SENDING` removes only that connection's
  retained ranges. Other attachments continue unchanged.
- Clients that never negotiate multicast or never become green continue on the
  ordinary stream path.

For a late attachment, call `publisher.next_stream_offset(stream_id)` and send
the identical earlier bytes over unicast until that connection reaches the
reported offset. The runtime waits if a committed range is ahead of the current
connection offset; it rejects an overlap because duplicate offsets must contain
identical data.

## Delivery metrics

Core quiche exposes one cumulative snapshot per connection and channel through
`Connection::multicast_stream_delivery_metrics_snapshot(channel_id)`.
`StreamDeliveryMetricsDelta::between(before, after)` computes a saturating
difference between snapshots. `ServerStreamPublisher::delivery_metrics_snapshot()`
aggregates those counters across every connection attached during the
publisher's lifetime. Its atomic snapshot is O(1), does not enumerate clients,
and retains totals after detach or connection teardown.

The snapshot contains three range/byte pairs:

- `direct_fallback_*` counts new ranges scheduled directly into ordinary QUIC
  while the channel is not viable. Initial probing and `MC_STATE(JOINED)` before
  the first valid `MC_ACK` are included.
- `ack_gap_recovery_*` counts retained viable-channel ranges released after an
  advancing `MC_ACK` proves them missing beyond the reordering threshold.
- `fallback_reentry_*` counts retained ranges released when timeout, probing
  re-entry, failed join, leave, or retirement makes the channel non-viable.

A range is counted only after it successfully enters the ordinary QUIC stream
send or retransmit machinery. Bytes are unique STREAM payload bytes; a
zero-length FIN can add one range and zero bytes. The counters exclude QUIC
framing, encryption, retransmissions, control frames, and socket overhead, so
they must not be interpreted as wire egress. Reset, `STOP_SENDING`, blocked,
missing, or otherwise unschedulable ranges are not counted.

`ServerStreamPublisher::metrics_snapshot()` remains the independent multicast
channel packet-encoding snapshot. For Yggdrasil, account for logical unicast
payload as:

```text
logical unicast payload =
  ordinary WebTransport bytes counted by Yggdrasil
  + shared prefix/late-catch-up bytes counted by Yggdrasil
  + ServerStreamPublisher direct fallback bytes
  + ServerStreamPublisher ACK-gap recovery bytes
  + ServerStreamPublisher fallback-reentry bytes
  + native DATAGRAM fallback bytes counted by Yggdrasil
```

## Controls

Automatic `ServerControlMode` sends admitted `MC_ANNOUNCE` and `MC_KEY` frames,
then sends `MC_JOIN` after current `MC_LIMITS` and QUIC stream limits permit it.
Manual mode leaves announce/key/join sequencing to `ServerControlController`.
In both modes, publisher key rotation uses `update_key()`, and channel teardown
uses `retire()`. Key rotation must begin at the publisher's next packet number
so packet numbers remain continuous.

The runtime ignores stale `MC_LIMITS`, filters automatic announcements by
address family and negotiated algorithms, enforces channel count and aggregate
rate limits, and sends `MC_LEAVE` when a later limits update or stream-ID change
makes an existing join invalid.

The existing DATAGRAM APIs and publication-owning `ServerDriver` remain
available and are independent of this STREAM publisher path.
