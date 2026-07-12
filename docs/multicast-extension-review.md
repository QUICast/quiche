# QUIC Multicast Extension Implementation Review

Date: 2026-05-16

Scope:

- Core multicast wire format and channel state in `quiche/src/multicast.rs`.
- Core QUIC integration in `quiche/src/lib.rs`, `quiche/src/frame.rs`, and
  `quiche/src/transport_params.rs`.
- Tokio integration in `tokio-quiche/src/multicast.rs`.
- Example multicast clients/servers under `tokio-quiche/examples/`.
- Comparison target: `draft-jholland-quic-multicast-08`.

## Executive Summary

The implementation is a useful experimental foundation for QUICast-style
multicast: the wire codecs exist, negotiation is wired into QUIC transport
parameters, unicast MC_* control frames are carried on 1-RTT packets, multicast
channel packets can be encoded/decoded, integrity is enforced before release,
`MC_ACK` is generated/processed, and the tokio layer has both a publication-
owning path and a control-only path for an external publisher.

It is not yet a complete implementation of the draft's transparent transport
semantics. The largest gaps are resource-limit enforcement, full channel state
machine sequencing, transparent STREAM/DATAGRAM delivery into normal QUIC APIs,
receive-side key lifecycle, congestion control, recovery, circuit breakers, and
bounded receiver memory. The current implementation is best described as
"experimental multicast channel/control support with an application-facing
DATAGRAM path", not "fully transparent multicast QUIC".

This is also not IETF Multipath QUIC. The draft itself notes a possible
relationship between `MC_ACK` and multipath ACK_MP, but the current code uses
the multicast draft's separate channel packet number spaces and `MC_ACK` frames.

## 2026-07-12 STREAM Server Update

The server-side assessment below predates the production STREAM publisher added
after this review. Core quiche now retains exact multicast STREAM ranges per
connection, keeps ordinary unicast fallback active until validated `MC_ACK`,
recovers ACK gaps over the normal QUIC stream, and resumes fallback on leave,
retirement, reset, or ACK-freshness timeout. Tokio-quiche now exposes one
socket-free shared `ServerStreamPublisher` that can attach to multiple
`ServerControlDriver` connections. See `docs/multicast-stream-server.md`.

`ServerControlRuntime` now also gates automatic announce/join by negotiated
address family and algorithms, current `MC_LIMITS`, aggregate rate, channel
counts, and `MAX_STREAMS_UNI`; join/rate reductions trigger `MC_LEAVE`, while a
reduced channel-ID limit retires excess channels. The older publication-owning
`ServerRuntime` has intentionally retained its DATAGRAM behavior and does not
yet share all of these admission checks.

The remaining transparent-delivery gap is client-side: decoded multicast STREAM
frames are not yet injected into core quiche's ordinary receive stream state.
The native browser implementation supplies that receive-side integration for
the current Yggdrasil deployment.

## Changes Made During This Review

1. Hardened attacker-controlled list decoding in `quiche/src/multicast.rs`.
   `MC_ACK` range counts and transport-parameter algorithm counts are now
   checked against the remaining buffer before allocating vectors.

2. Tightened send-side `MC_KEY` updates in `ChannelSendState`.
   Updates now reject lower key sequence numbers, skipped sequence numbers, and
   lower `from_packet_number` values. Identical retransmitted keys are accepted
   as no-ops instead of counting as updates.

3. Added client-side `MC_JOIN` sequence sanity checking in
   `tokio-quiche/src/multicast.rs`.
   The client now declines joins that reference future `MC_LIMITS`, `MC_STATE`,
   or `MC_KEY` sequence numbers it has not observed, using the draft's
   `UNSYNCHRONIZED_PROPERTIES` reason code.

4. Prevented unknown-channel `MC_ACK` frames from marking a control-only server
   probe viable.
   `ServerControlRuntime` still emits the event to the application, but it only
   updates core probe state if the ACK references a locally known channel.

5. Removed small duplicated map-entry lookups in `ServerControlRuntime`
   explicit command handling.

Validation:

- `cargo +nightly fmt`
- `cargo test -p quiche multicast --lib`
- `cargo test -p tokio-quiche multicast --lib --features multicast`

## Priority Findings

### P0: Client-Side Transparent STREAM Delivery Is Not Implemented

Draft expectation:

- Channel data should be transparent to an enabled client application. The
  draft says datagrams or server-initiated unidirectional stream bytes can be
  delivered over unicast or multicast without special handling by the
  application.

Current implementation:

- Server-side STREAM publication, ACK cutover, retained loss recovery, and
  ordinary unicast fallback are implemented.
- Core quiche exposes multicast channel payloads through
  `multicast_dgram_recv()` only for decoded `ChannelFrame::Datagram` frames.
- STREAM frames can be decoded into `ChannelFrame::Stream`, but they are not fed
  into quiche's normal stream receive state.
- The tokio client emits full multicast packets as `ClientEvent::Packet`, and
  examples do application-level file reassembly/deduplication.

Impact:

- This is fine for the current file-transfer/video-probing demos, but it is not
  the transparent transport behavior the draft describes.
- Any STREAM use will need careful handling of duplicate data across unicast and
  multicast, stream final sizes, flow-control interactions, and retransmission.

Recommendation:

- Keep the server publisher generic and complete the corresponding receive-side
  stream injection separately from the mcrx socket integration.

### P0: Congestion Control, Circuit Breakers, and Recovery Are Mostly Missing

Draft expectation:

- The multicast extension is intended to provide multicast-safe flow control and
  congestion-control behavior, and it points at graceful degradation/circuit
  breaker behavior for network safety.
- The server remains responsible for ensuring reliable frame data that needs to
  arrive eventually does arrive, either through unicast repair or multicast
  retransmission.

Current implementation:

- `MC_ACK` frames are generated and processed.
- Send-side metrics count acknowledged packet ranges.
- Probe state can become viable on first ACK or time out.
- STREAM ranges now have ACK-gap unicast repair and fallback re-entry. There is
  still no multicast congestion controller, rate adaptation, or circuit-breaker
  policy.

Impact:

- The implementation can demonstrate multicast delivery and collect metrics, but
  it should not yet be considered network-safe for unconstrained experiments.
- Loss and receiver failure currently require application policy.

Recommendation:

- Add an explicit "experimental/no congestion controller" marker in public docs
  and examples.
- Define a sender-side policy interface that consumes `MC_ACK` metrics and can
  signal leave/fallback decisions before trying to implement a complete
  controller in core.

### P0: Server Limit Enforcement Is Incomplete

Draft expectation:

- Servers must not announce channels that use unsupported IP families, hash
  algorithms, or encryption algorithms for a client.
- Servers should ensure the set of requested channels fits the client's limits:
  aggregate rate, max channel IDs, and max joined count.

Current implementation:

- Core negotiation exposes client transport parameters.
- The client enforces some local limits before joining.
- `ServerControlRuntime` enforces announce capabilities and current join limits,
  including dynamic reductions.
- The older publication-owning `ServerRuntime` still primarily checks whether
  `multicast_client_params` exists before announcing and joining channels.

Impact:

- A server can ask a client to join channels outside its advertised limits.
- The client will often decline, but the server side is still not respecting the
  draft's responsibility to keep requested channel sets within limits.

Recommendation:

- Reuse the control runtime's admission policy in the older `ServerRuntime`
  without changing its established DATAGRAM publication behavior.

### P1: Client Channel State Machine Sequencing Is Partial

Draft expectation:

- `MC_JOIN`, `MC_LEAVE`, and `MC_RETIRE` interact with client channel state and
  sequence numbers.
- `MC_LEAVE` and `MC_RETIRE` can be delayed by `after_packet_number`.
- A client ignores stale leave/join instructions in some sequence-number cases.

Current implementation:

- `MC_JOIN` now declines joins that reference future state/key/limits sequence
  numbers.
- Missing `MC_ANNOUNCE` or `MC_KEY` produces `DECLINED_JOIN`.
- `MC_LEAVE` leaves immediately and ignores `after_packet_number`.
- `MC_RETIRE` retires immediately, does not wait for `after_packet_number`, and
  does not fully discard all local channel state.
- Stale join/leave ordering rules are not fully modeled.

Impact:

- Basic join/leave works, but reordering and delayed leave/retire semantics are
  not spec-complete.
- A channel can be torn down earlier than the server requested.

Recommendation:

- Introduce an explicit per-channel client state machine with remembered last
  join/leave state sequence, pending leave/retire thresholds, and final cleanup.

### P1: Receive-Side Memory Is Unbounded

Draft expectation:

- The extension is meant to respect client-side resource limits and remain
  robust under loss, spurious traffic, or malicious traffic.

Current implementation:

- `ChannelReceiveState` stores `integrity_packets`, `pending_packets`,
  `accepted_packets`, and `keys` without explicit bounds.
- `AckTracker` stores ACK spans without an ACK-range retention policy.
- Unknown or unverifiable traffic can cause buffering until matching integrity
  or keys arrive.

Impact:

- A malicious or misconfigured sender can grow memory through unique packet
  numbers, integrity hashes, or sparse ACK ranges.
- Long-running streams will grow `accepted_packets` indefinitely.

Recommendation:

- Add configurable receive windows and retention limits.
- Drop old integrity entries once a packet is accepted or too old to decode.
- Prune ACK history similarly to QUIC ACK range handling.
- Emit metrics when data is dropped due to resource limits.

### P1: Receive-Side Key Lifecycle Does Not Meet Forward-Secrecy Guidance

Draft expectation:

- Clients must delete old secrets and derived keys after receiving new
  `MC_KEY` frames.
- The draft allows a short implementation-dependent delay but says old keys must
  not be retained indefinitely.

Current implementation:

- `ChannelReceiveState` keeps all received `ChannelKey` entries indefinitely.
- Duplicate-key detection also keeps the old secret material in memory.

Impact:

- This weakens forward-secrecy properties and can grow memory over time.

Recommendation:

- Add key retention policy keyed by packet number and wall-clock deadline.
- Default to a conservative short retention window and expose configuration for
  experiments.

### P1: Packet Number Reconstruction Is Fragile For Late Joins At Large Packet Numbers

Draft expectation:

- Channels have independent continuous packet number spaces.
- Clients can join channels after they have been running for a long time.

Current implementation:

- Channel packets are encoded with a fixed 4-byte packet number length.
- Receive-side packet number reconstruction uses `largest_observed_pkt_num`,
  initialized to zero.

Impact:

- Late joins at very large packet numbers can be decoded incorrectly if the
  truncated packet number cannot be reconstructed relative to zero.
- The fixed 4-byte encoding postpones this problem, but does not eliminate it
  for long-lived channels.

Recommendation:

- Seed reconstruction from `MC_KEY.from_packet_number` or integrity metadata
  where possible.
- Consider explicit channel packet number reconstruction state for newly joined
  receivers.

### P1: `MC_ACK` Is Functional But Not Complete

Draft expectation:

- `MC_ACK` extends QUIC ACK semantics for multicast packet number spaces and can
  carry ECN counts.

Current implementation:

- ACK ranges are encoded/decoded and cumulative ACKs are generated.
- ACK delay is always zero.
- ECN counts can be decoded/encoded but are not populated from socket metadata
  or used by control logic.
- ACK history can grow without pruning in sparse-loss cases.

Impact:

- Good enough for "is multicast viable?" and basic metrics.
- Not enough for congestion-control or ECN experiments yet.

Recommendation:

- Add ACK delay tracking based on receipt time and announced `max_ack_delay_ms`.
- Add ACK range pruning.
- Wire ECN support only when the mcrx/mctx socket layer can provide trustworthy
  ECN metadata.

### P2: Control Frame Loss Retransmission Order Needs A Feature-Gated Audit

Draft expectation:

- `MC_ANNOUNCE` should precede `MC_KEY`, and `MC_KEY` should precede `MC_JOIN`
  for a channel, although they may be in the same packet.

Current implementation:

- Lost multicast control frames are requeued through `push_front()`.
- With the legacy recovery implementation, lost frames are popped in reverse
  order, so this tends to restore original packet order.
- With `gcongestion`, lost frames are popped from a `VecDeque` front, so the
  same `push_front()` can reverse multicast control frame order.

Impact:

- This may cause feature-dependent reordering on retransmission.

Recommendation:

- Add a targeted test under both recovery backends.
- Normalize lost-frame replay order in recovery or requeue lost multicast frames
  in a batch.

### P2: Error Mapping Is Still Generic

Draft expectation:

- Invalid multicast behavior should often close the connection with
  `MC_EXTENSION_ERROR`.

Current implementation:

- The draft's error code is still TBD.
- The implementation maps errors to existing quiche errors such as
  `InvalidFrame`, `InvalidState`, `InvalidTransportParam`, and `CryptoFail`.

Impact:

- This is expected while the draft is experimental, but it makes interop/debug
  output less precise.

Recommendation:

- Add a named internal multicast error mapping now, even if the final wire code
  remains TBD.

### P2: IPv6 Is A Placeholder

Draft expectation:

- Both IPv4 and IPv6 announce formats exist.

Current implementation:

- Core codecs support IPv6.
- Tokio runtime intentionally treats IPv6 multicast joins as unsupported and
  emits placeholder events.

Impact:

- This is an intentional project decision for now, not a bug.

Recommendation:

- Keep the placeholder API shape, but document that runtime multicast reception
  is IPv4-only.

## Draft Deviations Caused By Draft Ambiguity Or Open Issues

1. Server-side state machine.
   The draft explicitly has a TODO to incorporate a server-side state diagram.
   The implementation therefore exposes pragmatic server APIs:
   `ServerRuntime` for publication ownership and `ServerControlRuntime` for
   yggdrasil-style external publication.

2. `MC_ACK` versus multipath ACK_MP.
   The draft itself asks whether `ACK_MP` from Multipath QUIC should be reused.
   The implementation follows draft-08's current `MC_ACK` frame shape instead
   of implementing Multipath QUIC semantics.

3. `MC_INTEGRITY` without explicit hash count.
   The draft's legacy form says hashes extend to the end of the packet. The
   implementation enforces this on send by ending the packet after such a frame.
   For the explicit-count form, the parser needs the hash length learned from
   `MC_ANNOUNCE` to avoid swallowing subsequent frames.

4. `MC_EXTENSION_ERROR`.
   The draft leaves the error code as TODO in IANA considerations. The
   implementation cannot yet emit the exact final error code, so it uses
   existing quiche error categories.

5. Receive-side key deletion timing.
   The draft gives recommended deletion timing and calls it arbitrary, with
   future experimentation expected. The current implementation has not chosen a
   timer policy yet and therefore retains keys indefinitely. This is a real
   implementation gap, but the ideal policy still needs design.

6. Security binding between unicast server and multicast sender.
   The draft security section contains open author comments about proving that
   a unicast server is authorized to use a multicast stream. The implementation
   currently relies on unicast-delivered integrity hashes and does not add a
   separate multicast-sender authorization proof.

7. Congestion-control mechanism.
   The draft points toward multicast congestion-control/circuit-breaker work,
   but does not provide a complete algorithm in the multicast draft itself. The
   implementation records ACK/receive metrics and leaves policy to the
   application for now.

8. Transparent stream semantics.
   The draft says applications should not need special handling, but it also
   acknowledges late join stream constraints. In this sans-IO implementation
   with external multicast sockets, feeding multicast STREAM frames directly
   into normal stream state needs careful duplicate/retransmission design. The
   current implementation intentionally avoids that by surfacing DATAGRAMs.

## Redundancy And Overengineering Review

Mostly appropriate:

- The split between core `quiche` and socket-owning `tokio-quiche` is correct.
  Core remains sans-IO and only receives decoded multicast channel packets from
  the integration layer.
- `ServerControlRuntime` and `ServerRuntime` are both justified because
  QUICast needs external multicast publication, while demos still benefit from
  publication ownership.
- The generic metadata parameter on `ChannelReceiveState<M>` is useful. It lets
  tokio preserve socket metadata through delayed integrity/key release without
  coupling core quiche to mcrx.

Worth simplifying later:

- `ServerControlRuntime` and `ServerRuntime` duplicate inbound
  `MC_LIMITS`/`MC_STATE`/`MC_ACK` handling. A small shared helper would reduce
  drift once server-side admission checks are added.
- The three queue wrappers in core (`ControlFrameQueue`, `ProbeEventQueue`,
  `ChannelDatagramQueue`) are mechanically similar. They are not harmful, but a
  generic bounded queue helper would reduce repeated code.
- The publication-owning examples and old `ServerDriver` path should be clearly
  labelled as demo/owned-publisher support so applications do not accidentally
  assume yggdrasil must own multicast sockets.

Not worth simplifying now:

- Metrics snapshots/deltas are verbose, but they are valuable for Heimdall and
  for bottleneck analysis.
- Manual and automatic server-control modes are both useful. Removing either
  would make yggdrasil or simple examples worse.

## Suggested Next Implementation Order

1. Add shared server-side admission checks before `MC_ANNOUNCE`/`MC_JOIN`.
2. Add a real client channel state machine for JOIN/LEAVE/RETIRE sequencing.
3. Add bounded receive memory and key-retention policy.
4. Add ACK delay/range pruning and ECN plumbing.
5. Add sender-side policy hooks for ACK-driven viability, leave, fallback, and
   circuit-breaker decisions.
6. Decide whether transparent STREAM delivery is a project goal for quiche core
   or whether QUICast should remain DATAGRAM/application-dedup first.
7. Audit lost-control-frame ordering under `gcongestion`.
8. Add qlog or dedicated multicast trace events once behavior stabilizes.

## References

- Multicast Extension for QUIC,
  `draft-jholland-quic-multicast-08`:
  https://datatracker.ietf.org/doc/html/draft-jholland-quic-multicast-08
- Managing multiple paths for a QUIC connection,
  `draft-ietf-quic-multipath`:
  https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath
