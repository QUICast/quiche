# QUIC Multicast Extension Implementation Review

Review baseline: clean `c779bb98`, including the focused correctness and
resource-bounds pass performed afterward. The implementation continues to
target
[`draft-jholland-quic-multicast-08`](https://www.ietf.org/archive/id/draft-jholland-quic-multicast-08.html).
No newer draft behavior is assumed.

## Executive Summary

The fork now has a sound experimental draft-08 control plane, bounded channel
packet authentication, server-side DATAGRAM fallback, and a reusable
server-side STREAM publication and recovery path. Socket ownership remains
outside core quiche. A shared `ServerStreamPublisher` can serve many independent
QUIC connections without copying shared payload bytes, while each connection
retains its own control, ACK, flow-control, reset, and recovery state.

The resource and lifecycle blockers identified in the previous review are
closed:

- reliable multicast control frames are never evicted after QUIC acknowledges
  them;
- receive-side packets, integrity, keys, work, and released events are bounded;
- old receive secrets expire at the draft-08 recommended and mandatory times;
- delayed `MC_LEAVE` and `MC_RETIRE` thresholds are honored;
- Tokio command, ingress, publication, integrity, attachment, and event queues
  are bounded by items and logical retained bytes;
- required application events fail explicitly on overload, while metrics are
  latest-only;
- STREAM publication is fair across streams and channels, with channel-local
  key, integrity, detach, and retirement barriers;
- prepared publication resolution is one-use and fail-stops uncertain external
  publication;
- connection and channel STREAM recovery retention is bounded.
- every locally generated multicast wire value is checked before queue, crypto,
  packet-number, sequence, or Channel-ID state is mutated;
- every top-level Tokio multicast read/write callback shares one aggregate work
  budget across all work classes and channels, with rotating continuation
  cursors;
- managed event streams are fused after runtime completion.

This is not yet a complete transparent MCQUIC transport and must not be
described as transport-adapter-ready. The two previously identified draft-08
blockers remain intentionally deferred and unchanged: source-neutral
STREAM/reset receive accounting, and conflicting or exhausted `MC_STATE`
sequence numbers. Packet-number exhaustion, `MC_LIMITS` equal-sequence or
exhaustion behavior, and `MC_KEY` conflict error mapping are three additional
explicit draft gaps. Authenticated multicast STREAM and RESET frames are
decoded and surfaced, but core quiche does not yet apply them to its ordinary
receive stream map. Congestion response and correlated circuit-breaker recovery
also remain application policy rather than a complete transport implementation.

MCQUIC in draft-08 is not the QUIC multipath extension. This implementation
correctly uses a Channel ID and an independent channel packet-number space with
`MC_ACK`; it does not create a quiche multipath path or use `ACK_MP`. Draft-08
itself leaves possible future `ACK_MP` reuse as a TODO.

## Implemented Draft Surface

| Area | Current implementation |
| --- | --- |
| Negotiation | Client/server transport parameters and algorithm/address-family capabilities |
| Control frames | `MC_ANNOUNCE`, `MC_KEY`, `MC_JOIN`, `MC_LEAVE`, `MC_INTEGRITY`, `MC_ACK`, `MC_LIMITS`, `MC_RETIRE`, and `MC_STATE` encode/decode |
| Reliable control | Exact duplicates may coalesce; distinct receive overflow closes explicitly; owned send errors permit exact retry |
| Channel packets | Header protection, payload protection, integrity hashing, independent packet numbers, and restricted frame validation |
| Permitted channel frames | PADDING, PING, RESET_STREAM, RESET_STREAM_AT, STREAM, DATAGRAM, KEY, LEAVE, cross-channel INTEGRITY, and RETIRE |
| Client lifecycle | Limits, join/decline, leave, delayed leave, delayed retire, retirement, ACK generation, and IPv4 receive integration |
| Server lifecycle | Automatic or manual control sequencing, dynamic announce/key/join/integrity, per-client limits/state/ACK events, and probe status |
| DATAGRAM | Decoded receive queue and server ordinary-QUIC fallback before viability or after re-entry |
| STREAM publication | Shared socket-free publisher, exact STREAM bytes/offset/FIN, integrity relay, per-connection fallback/recovery, resets, and teardown |
| Metrics | Core receive/send/recovery snapshots, Tokio queue/event counters, and mcrx/mctx snapshots |

## Resource Bounds

Defaults are local implementation policy, not draft wire limits.

| Resource | Default bound |
| --- | ---: |
| Core received control frames | 32 frames |
| Core outgoing control frames | 1,024 frames / 2 MiB |
| Connection-lifetime tracked Channel IDs | 1,024 IDs |
| Pending encrypted channel packets | 4,096 / 8 MiB |
| Pending integrity hashes | 8,192 / 1 MiB |
| Future packet-number distance | 1,048,576 |
| Retained receive key generations | 8 |
| Receive work per input call | 256 operations |
| Receive events per input call | 128 events |
| STREAM recovery per connection | 65,536 ranges / 64 MiB |
| STREAM recovery per channel | 16,384 ranges / 16 MiB |
| Tokio required/coalesced events | 4,096 / 64 MiB |
| Tokio commands | 4,096 / 64 MiB |
| Tokio multicast ingress | 4,096 / 64 MiB |
| Tokio pending publications | 4,096 / 64 MiB |
| Tokio pending integrity | 8,192 / 8 MiB |
| Tokio Client read/write callback work | 256 aggregate units across 4 / 5 classes |
| Tokio control-server read/write callback work | 256 aggregate units across 10 / 8 classes |
| Tokio publishing-server read/write callback work | 256 aggregate units across 3 / 5 classes |
| Shared publisher attachment | 4,096 items / 8 MiB |
| Publisher active streams | 65,536 streams |
| Publisher completed-stream history | 4,096 sparse/range storage units |

Accounting permits follow an item after it leaves a Tokio channel and enters
runtime staging. Moving an item between queues therefore cannot temporarily
escape its item or byte charge. Integrity batching uses the same retained-byte
budget as ready integrity frames. Attachment items are structurally limited to
64 KiB and attachment byte capacity must be at least 128 KiB, guaranteeing that
a successfully prepared publication can fit an empty attachment queue.

### Overload Outcomes

| Resource | Deterministic outcome |
| --- | --- |
| Received reliable control queue | Exact duplicate coalesces; distinct overflow closes the connection with `INTERNAL_ERROR` |
| Outgoing reliable control queue | `multicast_try_send()` returns the owned frame with `Full`, `Oversized`, `InvalidValue`, `Closed`, or another typed cause; reliable reservations remain charged through ACK or loss retry |
| Channel receive packet/integrity/key bounds | Decoder fails closed, clears secrets and pending metadata, and the Tokio client leaves a joined channel |
| Conflicting integrity hash | Channel fails closed with protocol-error state; neither hash is trusted |
| STREAM recovery bound | Retained ranges are released through ordinary QUIC and the channel becomes recovery-limited until a fresh probe generation |
| Tokio required event bound | Runtime/event stream terminates; the rejected kind and terminal reason remain observable out of band |
| Tokio metric pressure | Latest snapshot per channel is coalesced or evicted; counters record both cases |
| Controller command/integrity bound | Admission returns the owned command with `Full`, `Oversized`, `InvalidValue`, or `Closed`; transient core-queue pressure retries fairly for up to 30 seconds |
| Multicast socket ingress bound | Producers asynchronously wait for logical item and byte capacity; oversize and closure remain typed, cancellation-safe terminal outcomes |
| Publisher attachment bound | Only the slow attachment is sealed and detached after committed items drain; other attachments continue |
| Runtime cannot retain a committed required item | The affected connection runtime fail-stops rather than dropping STREAM state |

## Lifecycle Correctness

### Wire Preflight

`Frame::encoded_len()` and `ClientTransportParams::encoded_len()` are complete,
non-mutating checked sizing paths. They cover every multicast QUIC varint,
collection length, 1..=20-byte Channel ID, address-family shape, ACK ranges,
and `MC_STATE` reason combination before encoding or admission.

Core send queues cache the validated size. Invalid values return an owned
`ControlSendErrorKind::InvalidValue`; Tokio explicit controls return the owned
input with `ControllerSendErrorKind::InvalidValue`. Channel sender/receiver
construction and Tokio settings use the same preflight before crypto
derivation. The legacy infallible transport-parameter `wire_len()` remains
non-panicking and returns `usize::MAX` for invalid input; protocol paths use the
typed checked method.

Every mutating core local API routes Channel IDs through the same 1..=20-byte
validator, including tracking, probes, timeout configuration, DATAGRAM,
STREAM-recovery, default-channel, peer/local ACK, and local-state entry points.
Full `MC_STATE`, ACK, packet-number, offset, and payload-length validation runs
before maps, queues, probe generations, recovery, metrics, packet numbers, or
payload accounting change. Public timeout deadlines use checked `Instant`
arithmetic; an unrepresentable deadline fails before mutation. Mutation-snapshot
tests follow each invalid call with a valid one to prove that no Channel-ID or
queue capacity was consumed.

Fallible key opener/sealer construction completes before trusted packet-number,
supersession, sequence, or lifecycle state changes. A forced receive-opener
derivation failure leaves the prior generation, trusted frontier, and metrics
unchanged.

### Receive Readiness

Pending packets are indexed by missing key phase and missing integrity packet
number. A key or integrity input visits only newly actionable entries, subject
to `max_work_per_call`. Remaining ready work is exposed through a continuation
path. Required metadata is never evicted to authenticate a packet later.

Tokio does not grant receive maintenance, ingress, controls, publications, or
integrity separate budgets. One unit is one successful scheduled class
operation: one control frame handled; one queue item transferred or handled;
one standalone indexed receive operation; or one ACK, metric, or probe event
forwarded. Processing an ingress packet or receive-side KEY/INTEGRITY control
includes its one core admission and cannot start a nested receive drain.
Readiness scans and unsuccessful class attempts do not consume units.

Class and per-class Channel-ID cursors persist across callbacks. Client reads
use 4 classes and writes 5; control-server reads use 10 and writes 8; the
publication-owning server reads use 3 and writes 5. With `K` continuously ready
classes and callback budget `B`, every class receives one successful turn
within `ceil(K / B)` callbacks. A class with `N` continuously ready channels
therefore reaches every channel within the conservative bound
`N * ceil(K / B)` callbacks. Insertion, removal, replacement, blocking, and
closure do not privilege low-sorted Channel IDs. Deferred work remains visible
to the driver wait path, so exhausting a callback budget does not require an
unrelated socket event to continue.

Packet and integrity byte counts are maintained incrementally. A packet number
beyond the configured future distance fails the channel. Draft varint and
packet-number limits are validated separately from local resource limits.
Parsed but unauthenticated packet headers never advance the shared packet-number
reconstruction frontier. Integrity metadata and successfully authenticated
release establish trusted progress, so repeated bounded forged jumps cannot
walk the anchor or prevent a later valid lower packet from decoding.

Peer-selected Channel IDs have one connection-lifetime admission registry,
including retired identifiers. ANNOUNCE, KEY, INTEGRITY, control diagnostics,
probe state, and coalescer state cannot allocate beyond it. Unknown `MC_ACK` or
`MC_STATE` does not allocate persistent channel state. At the default maximum
20-byte Channel ID, the registry retains at most 20 KiB of identifier payload
plus collection overhead.

### Key Expiry

When a newer key supersedes an old generation, the old secret and derived
openers are removed at the earliest of:

- 10 seconds after supersession;
- 3 seconds without decoding data with the old key;
- the unconditional 60-second maximum.

Deleting a generation removes its secret and derived opener from protocol
state. Owned Rust secret vectors are overwritten on explicit multicast
teardown paths before release, but this pass does not claim non-elidable
zeroization of compiler-managed buffers or backend-internal key material.
Packets below the surviving key window cannot later be authenticated.
Duplicate keys are idempotent; conflicting sequence/from-packet-number
relationships fail.

### Secret Ownership

Secret-bearing `Debug` implementations report only redacted lengths.
Multicast-owned `Key.secret`, `Announce.header_secret`, and cached or queued
copies are overwritten with safe Rust operations on explicit replacement and
teardown paths. This is best-effort logical clearing, not comprehensive
cryptographic zeroization: ordinary Rust writes can be elided and the TLS
backends own additional derived material.

The earlier broad `crypto::Open`/`Seal`, BoringSSL context, key, IV, and
header-protection cleanup claims were reverted rather than presenting partial
clearing as comprehensive. No zeroization dependency, allocator hook, or new
unsafe primitive was introduced. OpenSSL now frees a newly allocated
`EVP_CIPHER_CTX` when `EVP_CipherInit_ex2` fails before a wrapper owns it. This
uses the existing unsafe FFI block and adds no new unsafe block.

### Leave And Retirement

`MC_LEAVE.after_packet_number == 0` leaves immediately. A nonzero threshold
waits until an authenticated packet at or above the threshold arrives.
Already-left, declined, retired, or superseded state requests are ignored.
Same-sequence duplicates retain the greatest threshold so reordering cannot
cause an early leave.

`MC_RETIRE` waits only when the channel is joined and has authenticated data,
as draft-08 specifies. Otherwise it retires immediately. Duplicate retire
thresholds retain the greatest value. Retirement clears the receive socket,
decoder, keys, ACK state, and pending transitions, and emits only
`MC_STATE(RETIRED)`.

If a threshold never arrives, one bounded pending transition remains until a
newer transition or teardown. The implementation does not invent a timeout
that draft-08 does not define.

### Server Publication Barriers

STREAM ranges are ordered per stream and scheduled round-robin across ready
streams. A stream waiting for its connection-specific prefix, flow-control
credit, or stream limit does not block another stream or channel.

Key rotation, explicit retirement, live detach, and client-limit retirement
are channel-local barriers:

1. stop accepting future attachment publications when teardown requires it;
2. drain already committed publications for that connection;
3. register connection-local recovery;
4. flush that channel's integrity batch and pending integrity;
5. emit the key/retire control or release recovery state.

An unrelated blocked channel is skipped rather than becoming a global retry
barrier.

Attachment-to-runtime transfer is transactional: only the admitted prefix
leaves the attachment queue, and unadmitted committed items are restored in
original order with unchanged byte accounting. Each staging operation consumes
one unit from the complete control-server callback budget rather than receiving
a separate per-queue or per-phase allowance. A rotating Channel-ID cursor gives
the same class-aware fairness bound as receive maintenance. A runnable deferred
barrier keeps the driver active even when the preceding callback consumes its
final work slot.

Prepared publication validates stream lifetime capacity, completed-history
capacity, and the fixed attachment item bound before consuming a packet number,
advancing an offset, rotating a key, or exposing ciphertext. A dropped or
uncertain one-use handle fail-stops and retires the publisher; successful
publication commits exactly once.

Each asynchronous ingress producer may own one packet outside queue accounting
while it waits for capacity. The item is not duplicated, queue-retained memory
stays within the configured bounds, receiver close wakes the producer, and an
item that can never fit triggers a visible channel overload/fallback transition.

## Managed Event API

The former public aliases to Tokio unbounded receivers were removed.
`ClientEventStream` and `ServerEventStream` are owned managed receiver types.
Both implement `futures::Stream` and `FusedStream`, and expose `recv()`,
`try_recv()`, `close()`, `stats()`, and `terminal()`. After the runtime calls
`finish()`, every sender clone rejects required events, metrics, and diagnostic
counter updates. Events admitted before finish drain in sequence; the receiver
then returns `None` permanently.

Driver construction validates settings before creating runtime queues.
`ClientDriver::new()`, `ServerControlDriver::new()`, and `ServerDriver::new()`
return `Result<(_, _), RuntimeLimitsError>`. Invalid transport parameters,
Channel IDs, batching counts, or channel control fields produce
`InvalidMulticastSettings` without retaining secrets or commands.

Controller receiver access is take-once:

- `event_receiver_mut()` returns `Option<&mut ...>`;
- `take_event_receiver()` returns `Option<...>`;
- after a successful take, later calls return `None`;
- no replacement queue or compatibility unbounded buffer is created.

Lifecycle events, errors, state transitions, packets, publications, and ACKs
are required. If one cannot be admitted, the runtime terminates
deterministically without awaiting the consumer. If the queue is full enough
that termination cannot itself be enqueued, terminal state is retained in
wrapper-owned shared state and becomes visible through `terminal()` and
`stats()` after admitted events drain.

Client metric snapshots are latest-only by channel. Exact duplicate
diagnostics may coalesce only where their semantics are identical. Queue
saturation, metric coalescing/eviction, diagnostic coalescing, receiver drop,
and terminal overload all have non-consuming counters.

Core `Connection::multicast_try_send()` returns
`multicast::ControlSendError`, retaining the rejected frame for exact retry.
`Connection::multicast_send()` remains a consuming compatibility wrapper and
maps queue saturation to `Error::Done`. Tokio controller methods return
`ControllerSendError<T>` with `kind()`, `value()`, and `into_inner()`; server
channel sends use the `ServerChannelPacket` and `ServerChannelSendError`
aliases. `InvalidValue` returns the original owned input before command-queue
reservation. Because `Announce` and `Key` have best-effort clearing `Drop`
implementations, callers cannot move individual fields out directly; borrow,
clone the required non-secret field, or destructure by reference.

## Remaining Differences, Ranked

### P0: Transparent Client STREAM Delivery And Accounting

`Connection::multicast_process_channel_packet[_ref]()` currently places only
DATAGRAM payloads into a core receive queue. Tokio handles multicast control
frames and exposes the full authenticated packet as `ClientEvent::Packet`, but
STREAM, RESET_STREAM, and RESET_STREAM_AT frames are not applied to the normal
quiche receive stream state.

This prevents the draft's transparency goal for applications using ordinary
QUIC streams. Implementation is intentionally deferred because draft-08 says
ordinary `MAX_DATA` and `MAX_STREAM_DATA` cannot limit multicast but does not
define unique-byte accounting, read-credit generation, overlap accounting, or
bounded-memory fallback. No private policy was selected, and dependent
receive-copy optimization is deferred with it.

### P0: `MC_STATE` Conflict And Sequence Exhaustion

Draft-08 requires increasing state sequences but does not define conflicting
equal-sequence frames, sequence exhaustion, or a usable error code while
`MC_EXTENSION_ERROR` remains unassigned. Monotonic conflict/exhaustion handling
is intentionally deferred; the implementation preserves its existing behavior
and does not substitute `PROTOCOL_VIOLATION`.

### P0: Multicast Packet-Number Exhaustion

Draft-08 requires continuous channel packet numbers but does not define the
channel or connection outcome when the QUIC varint packet-number space is
exhausted. The sender now emits packet number `2^62 - 1` at most once and
locally rejects subsequent publication before encryption or packet-number
mutation. It deliberately does not choose channel failure versus connection
failure.

### P0: `MC_LIMITS` Equal Sequence And Exhaustion

Draft-08 says each new `MC_LIMITS` increases the sequence by one and newer
frames replace older ones. It does not define conflicting contents at the same
sequence or the outcome at `2^62 - 1`. Local generation now rejects exhaustion
before reserving a sequence or queue item; existing inbound equal-sequence
behavior is preserved rather than inventing a wire error.

### P0: `MC_KEY` Conflict And Error Mapping

Draft-08 says a conflicting repeated key sequence should close with
`MC_EXTENSION_ERROR`, but that error remains unassigned. Core receive state
fails closed on conflicting key content and prevents arithmetic wrap; Tokio
continues its existing channel-local protocol-error handling. This pass does
not substitute a generic QUIC error or choose a new connection-level mapping.

### P1: Congestion Control And Circuit Breakers

The implementation records `MC_ACK`, detects ACK freshness loss, and can reenter
unicast fallback. It does not implement sustained-loss thresholds, receiver
rate reduction, high-loss/spurious-traffic leave policy, or correlated pacing
when many clients lose multicast simultaneously.

Draft-08 deliberately leaves much of hybrid congestion policy experimental, but
an operator still needs a safe deployment policy before production rollout.

### P2: Runtime Enforcement Of Advertised Channel Properties

Join admission enforces address family, algorithms, channel count, joined
count, aggregate announced rate, and stream IDs. The receiver does not yet
measure actual channel rate against `MC_ANNOUNCE.max_rate_kibps`, nor derive
`MAX_RATE_EXCEEDED`, `HIGH_LOSS`, or `EXCESSIVE_SPURIOUS_TRAFFIC` transitions
from live packet observations.

### P2: Connection-ID Collision Integration

Draft-08 expects announce processing to make Channel ID collisions manageable.
The current out-of-band multicast socket path validates Channel IDs but does
not coordinate Channel IDs with quiche's ordinary connection-ID issuance and
retirement machinery. This needs an explicit router/CID policy before a shared
UDP receive path uses the same demultiplexing namespace.

### P2: Dedicated Extension Error Mapping

Draft-08 refers to `MC_EXTENSION_ERROR`, but its code point remains TBD. Invalid
channel frames and resource/protocol failures therefore map to existing quiche
errors, channel-local `MC_STATE`, or explicit internal connection failure.
Once the draft assigns stable error semantics, mappings need a narrow audit.

### P3: IPv6 Tokio Data Path

Core frames and capability filtering understand IPv6, but Tokio socket joining
intentionally emits `UnsupportedIpv6Announce` and declines the join. The
placeholder is explicit so IPv6 can be added after cross-platform testing.

### P3: Generated MC_ACK ECN Counts

MC_ACK with ECN counts encodes and decodes, but the current ACK tracker emits
no ECN counts from multicast receive metadata. This does not block basic ACK
and recovery behavior.

## Draft Ambiguities And Local Policy

- Draft-08 contains a TODO for the server-side state machine. The implementation
  uses per-connection, per-channel probe generations: `MC_STATE(JOINED)` is not
  enough; only validated advancing `MC_ACK` makes a channel viable.
- Draft-08 asks whether `ACK_MP` should replace `MC_ACK`. This implementation
  follows the defined draft-08 `MC_ACK` wire format and does not depend on the
  separate QUIC multipath extension.
- Draft-08 does not define how to handle two different integrity hashes for the
  same packet number. The implementation fails that channel closed and reports
  a protocol error instead of choosing either attacker-controlled value.
- Draft-08 does not define ordinary QUIC flow-control accounting for
  authenticated multicast STREAM bytes. Transparent receive insertion and
  dependent copy optimization remain deferred rather than selecting a private
  transport behavior.
- Draft-08 does not define conflicting equal-sequence `MC_STATE`, sequence
  exhaustion, or an assigned `MC_EXTENSION_ERROR`. Existing behavior is
  preserved; no generic QUIC error is substituted.
- Draft-08 does not define the failure scope at multicast packet-number
  exhaustion. Publication stops locally before wrap; no close policy is
  invented.
- Draft-08 does not define equal-sequence `MC_LIMITS` conflicts or sequence
  exhaustion. Local generation stops before reservation and inbound policy is
  unchanged.
- Draft-08 names `MC_EXTENSION_ERROR` for conflicting `MC_KEY` content but does
  not assign it. The implementation fails the channel closed without inventing
  a wire code.
- Draft-08 does not define local memory-overflow policy. Receive metadata fails
  the channel closed; reliable control overflow closes the connection; STREAM
  recovery overflow releases data over unicast and disables viability.
- Draft-08 permits integrity roots over unicast or a separately authenticated
  multicast channel. The control-only Tokio server relays roots over unicast.
  It does not couple integrity emission to mctx publication.
- Draft-08 does not define application APIs for uncertain external UDP send
  outcomes. A prepared publication is a consuming one-use handle: success
  commits exactly once, known zero progress can be retried, explicit abandon
  retires, and uncertain progress fail-stops and retires without nonce or packet
  number reuse.
- The no-count `MC_INTEGRITY` form extends to packet end. The encoder therefore
  requires it to be the final frame rather than guessing a boundary.
- The current Tokio receive path is intentionally IPv4-only despite draft-08
  supporting both families.

## Cleanup Assessment

The implementation no longer needs an unbounded compatibility event adapter or
a parallel raw control sender. Shared bounded queue accounting is centralized
in `bounded_queue.rs`; managed event policy is isolated in `event_stream.rs`.
The STREAM scheduler is connection-local because offsets, flow control, resets,
ACK progress, and fallback decisions cannot safely be shared.

A global recovery catalogue is not justified by current profiles. Shared
`Bytes` already avoids payload duplication, while the remaining metadata is
genuinely per connection. No sockets were added to core quiche.

## Recommended Next Order

1. Resolve draft-08 STREAM accounting and `MC_STATE` error/sequence semantics,
   or define an explicitly versioned compatibility profile.
2. Only then apply authenticated STREAM/reset frames to the ordinary receive
   map and optimize the dependent receive path.
3. Define and test an operator congestion/circuit-breaker policy, including
   correlated fallback pacing.
4. Add observed-rate, sustained-loss, and spurious-traffic enforcement.
5. Integrate Channel ID collision handling with the actual UDP router/CID
   namespace.
6. Add and validate the IPv6 receive path.
7. Revisit error codes and possible `ACK_MP` alignment only when the draft
   resolves those open items.
