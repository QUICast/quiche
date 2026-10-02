# Authoritative listener/router completion

This additive API separates admission, router resource retirement, and delivered
connection accounting. It does not prove an entire application invocation is
gone and does not establish INT-139 capacity or browser acceptance.

## API

The crate root exports:

```rust,ignore
listen_with_completion(sockets, params, metrics)
    -> Result<Vec<QuicListenerEndpoint<M>>, QuicListenerStartupError<M>>;
listen_with_capabilities_and_completion(sockets, params, metrics)
    -> Result<Vec<QuicListenerEndpoint<M>>, QuicListenerStartupError<M>>;

struct QuicListenerEndpoint<M: Metrics> {
    pub incoming: QuicConnectionStream<M>,
    pub terminal: QuicListenerTerminal,
}

impl QuicListenerTerminal {
    fn try_take(&mut self) -> QuicListenerTerminalOutcome;
    fn wait(&mut self) -> QuicListenerTerminalWait<'_>;
}
// QuicListenerTerminalWait implements Future<Output =
//     QuicListenerTerminalOutcome> and deregisters on Drop.
```

The terminal capability is non-cloneable and unique to its endpoint. It has no
caller-supplied identity and exposes no task handle or abort method. Exclusive
borrowing permits one observer; there is no observer registry, history queue,
per-observation allocation, timer, packet probe or polling task. Endpoint count
is bounded by the caller's finite input socket collection.

`try_take` returns `Pending`, `Taken(Clean | Failed(reason))`, or `AlreadyTaken`.
`wait` never returns `Pending`; cancellation before Ready, including timeout,
releases the caller's registered waker but retains any joined result. Another
wait remains safe. Once Ready returns, the caller owns the sole result. Repeated
observations after that return `AlreadyTaken`. Observation after task exit works
without another command or network event.

Finite failures are `ConnectionMapCommandLaneSaturated`, `RouterIo { kind }`,
`TaskCancelled`, `TaskPanicked`, and `AncillaryTaskInterrupted`. No error text,
panic payload, packet, address, connection or socket is kept in the result.
The router's joined failure takes precedence over auxiliary interruption; a
clean join is downgraded to interruption if a tracked helper/backlog destructor
was interrupted. Later observations cannot overwrite the consumed result.

## Three distinct boundaries

1. `incoming.close()` stops admission and wakes an idle router, even with no
   traffic or timer. Closing is idempotent. It does not cancel delivered
   connections or claim that a task has exited. Buffered Initials remain
   drainable under the existing API.
2. Drop `incoming` to retire the accepted lane and destroy its remaining Initials.
   The completion capability waits for this even if the closed lane is empty.
   A close without receiver retirement is deliberately insufficient.
3. `terminal.wait()` joins the existing router task and waits for tracked
   auxiliary/backlog destruction. Clean additionally requires the existing
   Initial/worker shutdown guards to be released. Delivered connections retain
   their existing graceful routing and must be closed/joined by their own owners.

Tokio guarantees that the joined task future has been destroyed. A fixed release
barrier also covers the accepted receiver and existing stateless Retry/version-
negotiation sends, which formerly escaped the router join. It covers the existing
Initial-handler error-delivery task as well. The receiver acknowledges release
only AFTER destroying its queue: an Initial's internal shutdown guard can drop
before its core and socket fields, so guard closure alone is insufficient.
Helper future fields are destroyed before their inline release token.

The release barrier carries only current ownership and an interruption flag.
It is not a connection registry or a second task. It does not claim all helper
task allocations or killswitch entries are joined: it proves their tracked
socket/buffer/resource captures have been destroyed. Executor bookkeeping is
separate. Router socket references, configuration, map, map-command lane, receive
buffers and transient Initials are covered by destruction of the joined router.

On router failure, delivered Initials/connections can still exist. The result
waits for the accepted receiver and helper resources, but must NOT be interpreted
as their connection terminal zero. Even on Clean, the shutdown guard is not a
substitute for core-owner destruction or caller-held selected-I/O settlement.
Use each connection's independent terminal-retention claim/result.

Dropping the terminal handle forfeits observation, not cleanup: it neither
aborts the router nor keeps its resources alive. Dropping an endpoint drops its
accept stream and requests shutdown. Dropping a startup error does likewise, but
forfeits the completion authorities it held. Observer loss, timeout, cancellation,
runtime disappearance and failure are never success.

Router poll and destruction panics are caught outside instrumentation and reduced
to a finite result. Cancellation destroys the wrapper and reports TaskCancelled.
Process abort, abort-on-panic, a non-returning destructor, or a panic while disposing
of a panic payload are outside the cleanup guarantee. No completion is synthesized
for a process that cannot execute destructors. Normal teardown makes no new
lifecycle allocation; pre-existing logging/backend/executor costs are separate.

## Partial startup

Both new constructors return earlier endpoints on a later startup failure.
`QuicListenerStartupError::failure()` distinguishes `Io(kind)`,
`RuntimeUnavailable`, and `Panicked`. `error()` preserves a normal I/O error;
`into_parts()` returns that error plus earlier endpoints in input order. Their
admission streams have already been closed. Drop ALL those streams, retain their
terminal handles, settle delivered owners if any, and await every terminal.
Panics in iterator advancement, socket conversion and per-endpoint construction
are projected without discarding earlier authority. External binding performed
before calling the constructor remains caller-owned; sequential callers must
retain prior endpoint handles when a later bind fails.

The legacy `listen` and `listen_with_capabilities` signatures and stream behavior
remain available. They discard the new completion capability, so consumers
requiring authoritative cleanup must adopt the new constructors. No wire codes,
Retry policy, deadlines, capacities, H3/selected-WebTransport semantics, or
connection accounting semantics change. Packet/Initial errors and backlog
refusals are not newly made router-fatal. CID-map overload remains fail-stop and
is rechecked after the last worker releases its shutdown guard.

## Bounds and a remaining memory limitation

`BoundedFixedPoolCeilings::listener_completion_metadata_bytes` charges the new
fixed endpoint values once through `fixed_egress_bytes`, not per connection.
It covers two shared wake/release allocations, their handles, inline root tokens,
terminal result/join values and the catcher pointer. On this Rust 1.94 AArch64
build it is 209 bytes, before existing allocator/executor margin. The instrumented
router future moves into one construction-time boxed allocation; its resource
storage is not duplicated. No limits or ceilings are increased.

`listener_auxiliary_task_tracking_bytes` reports 16 inline bytes per existing
auxiliary send task on this build. It is NOT an aggregate ceiling and is NOT
added once to a fixed total. Use the checked provider API, not these target-
specific numbers. Completed caller-retained results/handles are caller-owned.

The existing Retry/version-negotiation task population has no configured finite
ceiling. It is not bounded by accept backlog or connection count. Aggregate
auxiliary future, buffer, socket-reference, tracking-token and executor storage
therefore remains unbounded by configuration. Fixed completion observation does
not fix that separate pre-admission memory gap. Completion waits for tracked
auxiliary resource destruction; a stalled helper may delay it indefinitely.
Capping or rescheduling reply admission would change policy and is not part of
this pass. A whole-service finite-memory proof must address it separately.

Historical Initial overflow and WebTransport refusal counters remain history,
not current ownership. Nonzero history does not obstruct genuine cleanup; Clean
does not imply that every attempted Initial was admitted.

## Consumer handoff

Retain the endpoint's terminal capability before moving its accept stream into
an application task. Bound the application's task, report and connection-owner
populations independently. In schematic form (application methods are not new
provider APIs):

```rust,ignore
let QuicListenerEndpoint { mut incoming, mut terminal } = endpoint;
// Move incoming to a bounded admission owner; retain terminal in its supervisor.
// Before each connection escapes, independently retain:
let claim = selected.terminal_retention_claim();

// On shutdown, the admission owner performs:
incoming.close();
drop(incoming); // reject/destroy any undelivered Initials
signal_application_shutdown();
join_application_tasks().await; // real joins, including cancelled tasks

// Independent bounded connection supervisors settle their existing claims:
match selected.wait_terminal_retention(claim).await {
    WebTransportTerminalRetentionOutcome::Taken(stats) => report(stats),
    other => preserve_unresolved_failure(other), // never infer zero
}
join_connection_supervisors().await;
join_report_tasks().await;

match terminal.wait().await {
    QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Clean) => {},
    other => preserve_listener_failure(other),
}
```

The exact application task ordering must avoid its own reporting dependencies.
The provider handle proves only the stated router/resource boundary. It cannot
prove all application/report tasks, other listeners, or an entire invocation are
gone. This prerequisite neither closes INT-139 nor proves four-person capacity.

## Evidence

The unchanged deterministic wake regression fails on the requested base: closing
admission does not wake the registered router. It passes after explicit waking.
Tests pause backlog destruction AFTER an early guard disappears and require
completion to remain Pending; join alone is insufficient. Tests also hold a real
stateless Retry send, queue/deliver Initials, saturate backlog/CID lanes, exercise
cancelled/replaced observers, task/runtime failure, duplicate close/take, partial
bind/startup failure, checked accounting and independent endpoints.

Public loopback UDP closes admission with two established bounded WebTransport
connections. Both transfer fresh exact data; the second still progresses after
the first's authentic connection-terminal zero. Held receive-terminal owners
prevent premature retirement. Each connection is accounted separately before
the router's terminal result. No timer, socket rebinding or elapsed-time threshold
is accepted as destruction evidence.
