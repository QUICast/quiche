# WebTransport Live Connection Snapshot

V2-INT-049 adds a bounded observational boundary for Acceptance C transport
telemetry. It does not add a logger, background sampler, HTTP/3 policy, or a new
wire feature.

## Core contract

`quiche::Connection::connection_path_snapshot()` returns one
`quiche::ConnectionPathSnapshot`:

- `SingleActive` contains one address-free path generation, smoothed RTT,
  congestion-window bytes, and bytes in flight;
- `Unavailable` means no path can currently carry non-probing packets; and
- `AmbiguousMultipath` means more than one path was eligible, so the API did not
  choose one arbitrarily.

The three numeric transport values are read from the same active path's
recovery object during one connection-owner call. Sampling does not process
timers, ACKs, loss, recovery, path selection, congestion control, or outgoing
packets. The connection-local path generation starts at zero, advances when
quiche selects a different active path, and saturates rather than wrapping. It
is not a path-map index and cannot be resolved to an address through this API.

## Tokio contract

`WebTransportController::live_connection_snapshot()` and
`BoundedSelectedWebTransportController::live_connection_snapshot()` return a
`WebTransportLiveConnectionSnapshotOperation`. The operation is a future with
an explicit `cancel()` method. A successful result is one of:

- `Sampled(WebTransportLiveConnectionSnapshot)`;
- `Unavailable { sample_sequence, path_generation }`; or
- `AmbiguousMultipath { sample_sequence, path_generation, active_paths }`.

Typed non-sample outcomes are `Saturated`, `Cancelled`, `ConnectionClosed`,
`DriverGone`, and `SequenceExhausted`. A connection that is closing never
returns a retained earlier sample as current.

The driver preallocates one controller-bound state slot. Admission uses the
existing bounded selected-I/O command lane without waiting for capacity. At
most one live-snapshot obligation can exist per connection; a competing request
or full command lane returns `Saturated`. Controller clones share the slot and
the monotonic sample sequence. Independent controllers do not share either.

Dropping or cancelling before command exposure detaches the waiter while the
single queued command is discarded on its normal driver turn. Cancelling after
sampling removes the unconsumed result. Neither case fabricates a sample or
creates another retained obligation. Connection and driver teardown clear the
slot before waking it with the corresponding terminal outcome.

`WebTransportRetentionStats` reports current requests, the intrinsic limit of
one, saturation and cancellation totals, and owner-side sample count. Terminal
retention accounting sets the current request count to zero while preserving
those cumulative values. `AppliedBoundedWebTransportProfile` exposes the same
one-request limit, and the checked bounded memory envelope includes the fixed
state and command representation. A sample is a `Copy` value containing no
addresses, connection IDs, credentials, payload backing, or arbitrary errors;
the driver stores no history and allocates no per-sample result channel.

## Yggdrasil handoff

V2-INT-034 should request this fact from the selected WebTransport controller
and project the typed result through Heimdall's existing Aegir V2 API. It must
not reconstruct bytes in flight from cumulative counters, join values from a
later path lookup, or treat `Unavailable`, `AmbiguousMultipath`, or a terminal
outcome as a zero-valued live sample. Scheduling, sample cadence, labels, and
Acceptance C policy remain Yggdrasil responsibilities.

This boundary intentionally does not implement V2-INT-053, periodic polling,
history retention, multipath aggregation, or kernel/network memory telemetry.
