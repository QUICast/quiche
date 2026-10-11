# FIN on an already-consumed retransmission

## Correction

Base: `7add1cf0d5b3cfb2e3292d80ef4fcffa69b42e26`.

`RecvBuf::write()` used to validate and record a first final offset, then
discard a nonempty range whose bytes the application had already consumed.
The stream consequently reported finished without becoming readable. This
prevented an existing selected WebTransport readable waiter from waking. A new
wait could return `Ready`, but `read_stream()` still returned `Blocked`.

The receive buffer now preserves that first FIN as an empty range through its
existing insertion path. It does not retain the retransmitted payload. Final
size and flow-control checks still precede mutation, reset precedence remains
unchanged, and drain mode stores no marker. Repeated FIN cannot recreate an
already-consumed marker. No wire, public API, timer, or waiter change is needed.

An empty FIN marker is also consumed when the read/discard capacity is zero.
Previously such a read could return FIN while leaving the marker readable,
preventing core collection of a completed bidi stream. The correction does not
consume nonempty payload without output capacity.

The bounded profile already accounts for one empty FIN fragment per live
stream. No new persistent field, retained-byte class, or metadata requirement
is introduced. Receiving this marker does not settle any independently owned
WebTransport terminal-read lease or the other direction of a bidi stream.

## Regression coverage

Core tests cover read/discard, consumed duplicates, overlapping and out-of-order
data, partial reads, duplicate FIN, conflicting final size, flow control,
RESET_STREAM, RESET_STREAM_AT, and receive shutdown.

Controller tests use real QUIC endpoints and H3 admission plus the actual
`ApplicationOverQuic` callbacks, not a copy of the wake loop. They cover both
endpoint directions, uni/bidi streams, early/late waits, an ordinary FIN-only
control, a lost FIN-only packet followed by a consumed-tail retransmission,
and FIN committed after the tail has been requeued by loss recovery. They
decode the emitted STREAM frames to assert the FIN, offset, and payload.

They also check cancelled registration, terminal replay and retirement, held
read leases, fresh sibling data, independent bidi send completion, and zero
remaining associated-stream/terminal/waiter ownership after retirement.

## Consumer handoff and evidence limits

Consumers need only adopt the finalized provider revision; retain their normal
selected `read_stream()` / `wait_stream_readable()` loop and explicit terminal
retirement. Do not add polling, special EOF synthesis, or a timeout increase.

The triggering mechanism is reproduced in controlled in-memory transports.
This does not establish that it caused Yggdrasil's historical release timeout.
That original **981-pass / 1-failure** record remains unchanged. These tests
are not browser/device evidence and do not close INT-139.

The original diagnostic's X/Y cases only recorded outcomes and used a trimmed
development workspace after an offline-build stop was overridden. That run is
diagnostic evidence, not official provider validation. This correction's
assertion regressions use the intact workspace with its full-workspace lockfile;
missing locked dependencies were restored explicitly, without manifest edits.
