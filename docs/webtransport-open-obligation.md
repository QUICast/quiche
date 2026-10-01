# Selected WebTransport open obligations

This additive provider boundary targets INT-139. It does not establish
downstream integration, three/four-participant acceptance, or adequate topology
capacity. The unchanged downstream fixture needs 9/12 aliases against eight;
its process admission is four sessions. Waiting cannot fit permanently retained
topology into an insufficient limit. No limit or wire behavior is raised here.

## Public API and migration

Both `WebTransportController` and `BoundedSelectedWebTransportController` expose:

```rust,ignore
pub fn try_open_stream_obligation(
    &self,
    session_id: u64,
    direction: WebTransportStreamDirection,
) -> Result<WebTransportOpenOperation, WebTransportOpenAdmissionError>;
```

`WebTransportOpenOperation` is a non-cloneable Future yielding
`Result<WebTransportOpenedStream, WebTransportOpenFailure>`. The successful
non-cloneable offer is not application stream ownership until its consuming
`accept() -> Result<u64, WebTransportOpenFailure>` succeeds. The returned number
is the exact physical QUIC stream ID. Selection rejects an unaccepted offer.

```rust,ignore
let operation = selected.try_open_stream_obligation(session, direction)?;
let offer = operation.await?;
let stream_id = offer.accept()?;
// Use the existing selected read/write/terminal APIs for stream_id.
```

Do not turn `RegistrationFull` or `QueueFull` into a busy retry. They refuse
registration before stream reservation; the provider has accepted no opening.
`DriverGone` means selected command admission is closed. Once admitted, genuine
local active/provisional/receive-observation capacity pressure and peer
MAX_STREAMS exhaustion retain the operation instead of returning ResourceLimit.
The existing legacy open methods remain source/behavior compatible, including
their immediate local ResourceLimit refusal; consumers must deliberately migrate.

Failures carry the existing exact `WebTransportOpenStreamOutcome` (never Opened)
and `WebTransportOpenExposure`. No new error-code mapping is introduced.
Pending, closing, terminal, unknown, and unsupported sessions retain their typed
selection outcomes. A recorded failure is not overwritten by later teardown.

## Ownership and cancellation

The one owner passes through command admission, capacity wait, QUIC reservation,
prefix acceptance, queued success, and affine offer. It is never reconstructed
from a stream number. Drop cancels through every pre-accept stage, including a
success that was queued but never polled. `cancel(self)` returns exposure at
cancellation, not a cleanup-completion claim:

- `Unreserved`: no QUIC reservation exists and cancellation prevents one.
- `Reserved { stream_id, prefix_bytes_accepted }`: a physical reservation exists,
  including zero accepted prefix bytes. Cleanup remains provider-owned.

Cancellation and each reservation/prefix-write plus exposure update share a
small synchronous mutex. No await or borrowed payload survives that lock.
Accept serializes with terminal invalidation under the same lock. Cancellation
after accept cannot reset the newly application-owned stream.

ReliablePrefixReset retains its existing prefix obligation: cancellation can
require further prefix acceptance and reset traffic. No peer credit means no
cleanup-progress guarantee, not permission to claim zero. StandardReset keeps
the existing standard-reset policy. Prefix bytes are never replayed. Provider
observation retirement applies only to never-accepted streams. Their active slot
and registration remain charged until actual core collection, not merely FIN or
RESET admission. Collection uses the pinned core's collected-stream predicate
and exact absent-stream result; stopped/closed send direction is insufficient.
The core receive handlers now also perform their existing completed-stream
collection when drained receive FIN/RESET arrives after local send ACK. Without
this correction no readable callback exists to collect that stream. The guard
still preserves an unobserved STOP and does not collect readable terminals.
There is no new public core API or reset/error policy.
When the peer terminal and local reset ACK precede offer drop, cancellation
also consumes the never-accepted direction's provider-owned STOP through the
existing core capacity API. It cannot consume an accepted application's STOP.
The same cleanup applies when STOP precedes H3 commitment and the opening fails
normally; awaiting that failure does not rely on cancellation to reclaim it.

Session close retains the existing peer CONNECT-close teardown barrier. Its
bounded teardown cursor skips already-issued resets without forgetting those
owners or blocking sibling teardown. Late prefix completion and final collection
recheck session completion. Connection destruction settles core ownership via
the unchanged V2-INT-051/053 hook. A held result/offer still delays the terminal
claim until dropped; diagnostics alone do not retain payload bytes.

The owner retains one bounded command sender for cancellation, not a driver,
connection, or socket. It works after the last public controller drops. Lane
closure serializes with publication using the existing terminal-admission lock,
then explicitly rejects queued work. A saturated lane already has runnable work;
cancellation additionally uses the existing coalesced flag, not another queue.

## Bounds and scheduling

Let C = selected command capacity, P = per-session pending-stream bound.
Outstanding obligations are bounded by C globally and P per session, separately
from active/provisional slots. In the one-session bounded profile the effective
owner bound is min(C, P). Queued commands, waits, reservations, offers, externally
held unpolled failed operations, and cancelled cleanup owners share these counters.
No increased setting or consumer-side shadow counter is required.

The capacity-wait VecDeque preallocates C entries and never grows. New map
entries are O(C). `selected_open_obligation_metadata` is a checked additional
component of `BoundedDynamicMemoryComponents`, included in the unchanged dynamic
ceiling validation. It charges each shared owner plus Arc counters, C pending
entries, and one full Rust 1.94 BTree internal node per possible entry in each of
the five additional indexes (11 values, 12 edges, aligned header). Existing
prefix/reservation, active-stream and selected-lane budgets remain separate.
Allocator overhead and executor-owned Wakers retain the existing envelope's
implementation-margin exclusions. Overflow fails settings construction.

The immutable applied profile exposes `max_open_obligations()` and
`max_open_obligations_per_session()` derived from its actual selected limits.
Retention stats report owner count/limits/high-water/admissions/saturations,
`waiting_open_obligations`, and `retained_open_handoffs`. The latter includes
accept notifications not yet consumed by the driver. Runtime metadata
indexes are counted; owner counts additionally cover external result custody.
Final take-once accounting requires zero open owners, preserving cumulative and
high-water values. No payload is retained to support these diagnostics.

The existing callback budget is shared across three rotating open work classes:
offer resolution, capacity wait examination, and legacy peer-credit/prefix work.
One inspected or advanced entry consumes one work unit. With all classes ready,
each receives a turn within three such units; a finite capacity sweep visits
each waiting entry once, and rotates the next starting point. A blocked direction
cannot head-of-line block an eligible opposite direction. Finite metadata
invalidation at session termination is bounded by C; it is not a new unbounded
task or callback lane.

Capacity release, explicit retirement, cancellation/acceptance, and genuine
MAX_STREAMS transitions schedule reconsideration. Received-packet turns schedule
bounded collection continuations through the existing cursor. Exhausted work
remains runnable; once a sweep finds only held/blocked state, idle turns do not
rearm it. No timer, polling task, retry loop, or fabricated credit is added.
Failed-opening retirement also schedules a bounded collection continuation,
including when another live stream consumes the callback's final work unit.

## Evidence and upstream boundary

Focused tests cover active/provisional pressure, competing openings,
release-before-registration, peer credit alone and combined with local pressure,
both directions, queue/registration saturation, closing sessions, exact first
failure, unpolled drop, partial prefix boundaries, queued and returned success
drop, and held terminal accounting. Test-only barriers force cancellation after
real reservation and real prefix acceptance but before exposure publication.
Lane-close races and cancellation after last-controller drop are covered.
Collection continuation is tested with budget one and an unrelated live stream.
Core tests deliver peer FIN, RESET and RESET_STREAM_AT after an ACK-only
packet settles the local standard/reliable reset. The same regression failed
before the collection correction and passes after it. Undrained terminal bytes
and exact unobserved STOP codes remain observable in controls.

The public real-UDP test holds an authentic receive-terminal payload owner in the
only active slot. Retirement refuses while it is held. Dropping and retiring it
resumes the pending open without an application retry. Payload/FIN delivery and
both endpoints' authoritative terminal zero are asserted. Existing sibling,
accepted-close, CONNECT-FIN, pre-owner, multicast, and partial-write suites remain
part of validation, not replaced with destruction-only checks.

Baseline comparison uses the same active-slot fixture and pending assertion:
the exact base's legacy open returns ResourceLimit; the candidate's additive
obligation stays pending. Because the old base lacks this API, the comparison
explicitly changes the registration call; it is an API-migration proof, not a
claim that unchanged legacy behavior was fixed. Candidate release/resumption
tests separately prove scoped settlement. Queued-success cancellation is a
tested source-derived concern, not claimed as the historical incident cause.

This generic boundary is independently upstream-worthy after review. A natural
PR split is the affine operation/admission/accounting contract, followed by
driver capacity/reservation cleanup integration and its public-UDP evidence.
It depends on the existing selected-I/O, terminal retirement and reliable-prefix
reservation APIs. No media, application aliases, WT_BUFFERED_STREAM_REJECTED
classification fix, or new pooled-session policy belongs in this patch.
