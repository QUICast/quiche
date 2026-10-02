# Native inbound WebTransport refusal history

This INT-139 provider prerequisite adds reporting only. It does not change
admission predicates, their order, WT_BUFFERED_STREAM_REJECTED, reset behavior,
error scope, limits, retries, outbound opening ownership, or wire negotiation.

## Public surface

`WebTransportRetentionStats::inbound_stream_refusals` has type
`WebTransportInboundStreamRefusalStats`, exported from `http3::driver`.
It is a fixed-size `Clone + Copy + Debug + Default + Eq + PartialEq` value:

| Field (`u64`) | First failing native predicate |
| --- | --- |
| `active_connection` | Aggregate active-capacity limit |
| `active_session` | Per-session active-capacity limit |
| `provisional_connection` | Aggregate provisional-capacity limit |
| `provisional_session` | Per-session provisional-capacity limit |
| `receive_terminal_connection` | Aggregate receive-observation capacity |
| `receive_terminal_session` | Per-session receive-observation capacity |

`overflowed: bool` is sticky and becomes true only when an increment would exceed
`u64::MAX`. That counter stays at the maximum; other counters continue recording.
Reaching exactly the maximum is still exact. With `overflowed`, history is
explicitly incomplete and consumers must not present it as an exact total.

All counters are connection-lifetime history, starting at driver construction.
The `*_session` suffix describes the exhausted scope, not an indexed session
history. Reading does not reset counters. No session/stream IDs, strings, payloads,
credentials, maps, per-refusal allocations, events, or waiters are added.

## Decision semantics

Exactly one counter increments when initial classification or buffered promotion
refuses an incoming associated stream because of capacity. It increments at the
native decision, before the existing shutdown call, even if transport cleanup
has already progressed. It counts refusal decisions, not distinct streams,
packets, successfully transmitted STOP frames, or simultaneous exhausted limits.

Existing short-circuit order is preserved:

1. Buffering: provisional connection, provisional session, active connection,
   active session.
2. Active admission/promotion: active connection, active session, receive-terminal
   connection, receive-terminal session.

Only the first failure is attributed. Buffering's active predicate counts active
plus provisional ownership. Active admission counts active plus reserved openings.
Receive admission counts retained observation slots plus reserved bidi openings,
not terminal-read payload bytes or waiter count. These are the existing native
predicates, not new restrictions.

Pending and not-yet-observed sessions can buffer. The peer CONNECT-close barrier
can also buffer after a local session-terminal event; capacity refusals there
still count. Successful/already-owned classification, outbound opens/probes,
non-session or collected CONNECT rejection, WT_SESSION_GONE teardown, provisional
expiry, and read-byte/waiter overload do not count. The pre-existing
`receive_terminal_state_saturation_total` is preserved; it overlaps the new
receive categories and also covers outbound admission. Do not add it to these
counters as though it were an independent refusal population.

## Lifetime and consumer use

The ordinary and bounded selected controllers expose the history through their
existing `retention_stats()` operation. After command-lane closure, use the
existing take-once terminal-retention claim/result. The terminal result preserves
history and its overflow flag while reporting genuine current ownership zero.
History neither owns streams nor delays terminal settlement. Existing Early,
Unavailable, cancellation, foreign-claim and AlreadyTaken semantics are unchanged.

```rust,ignore
let stats = selected.retention_stats().await?;
let history = stats.inbound_stream_refusals;
if history.overflowed {
    // Report incomplete cumulative diagnostics, not an exact total.
}
// For final history, retain a terminal_retention_claim before teardown and
// read Taken(stats).inbound_stream_refusals from wait_terminal_retention().
```

These counters are not a reservation, wakeup, cancellation receipt, stream
terminal fact, or permission to retry. They cannot identify which stream was
refused. UnknownStream/StaleStream remains selection failure, not refusal cause
or terminal authority. No new recovery/event capability is introduced.

## Checked storage

`checked_memory_envelope()` includes fixed runtime history and the enlarged
preallocated terminal snapshot in `selected_state_metadata` using actual type
sizes. Its existing conservative duplication factor remains unchanged.

The new `selected_retention_snapshot_values` component additionally charges
`(selected_command_capacity + 1) * size_of::<Result<Stats, Error>>()`, checked for
both addition and multiplication overflow. Reserved plus queued requests share
the command capacity; the driver can execute one dequeued request. This component
charges complete response value storage, including the previously implicit
base snapshot, not just the new fields. No limit or ceiling is raised.

On this Rust 1.94 AArch64 build, history occupies 56 bytes and Stats/reply values
736 bytes. At the default command capacity 256, the response-value component is
189,152 bytes. Runtime plus snapshot growth adds another 224 charged bytes under
the existing duplication factor. Layout is not a portable constant; consumers
must use the provider's checked calculation rather than copy these numbers.

Response channel bookkeeping/alignment, allocator and executor costs retain the
existing implementation-margin boundary. Once the synchronous send relinquishes
the provider's sender, any unconsumed reply/channel storage belongs exclusively
to the caller, even if its future is never polled again. Caller-retained snapshots
and copies need caller budgeting and do not delay transport terminal zero. This
does not claim exact RSS or kernel accounting.

## Evidence and limits

Tests cover all six classes in applicable admission phases and both directions,
repeated decisions, buffered promotion, competing predicates, successful and
unrelated controls, the CONNECT-close barrier, saturation, and checked storage.
Public loopback UDP fills sixteen active slots, observes two exact peer refusals,
checks corresponding local history, transfers fresh exact bytes/FIN on every
admitted sibling, and verifies held terminal owners prevent early retirement.
Both endpoints finish through authoritative take-once accounting with zero
current ownership and preserved history.

The original downstream gap witness is unchanged. The new public assertion
fails with only the additive counter surface and unchanged admission recording,
then passes with native hooks; this is explicitly a surface-scaffold comparison,
not a claim that the absent API could compile on the unmodified base.

This completes a reporting prerequisite only. It does not resolve the separate
WT_BUFFERED_STREAM_REJECTED session-escalation question or resize a deployment
profile. It does not validate the approved target of one configurable
four-person room, a sixteen-person workload, or INT-139 capacity/browser
acceptance. Deployment sizing and memory measurements remain downstream work.
