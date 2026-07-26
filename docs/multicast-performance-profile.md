# MCQUIC Server STREAM Performance Pass

## Scope

This report covers the performance pass from baseline commit `54684d20`
through `4359ea47`. The wire format, cryptography, congestion control,
WebTransport offsets, and unicast fallback semantics are unchanged.

Changed files:

- `quiche/src/lib.rs`: ordered ACK recovery, dirty delivery metrics, and
  explicit recovery-state retirement.
- `quiche/src/multicast.rs`: exact packet sizing and borrowed STREAM encoding.
- `quiche/src/stream/mod.rs`: generic completed-stream range tracking.
- `quiche/src/tests.rs`: core fallback, recovery, metrics, and lifetime tests.
- `tokio-quiche/src/multicast.rs`: event coalescing, edge-triggered publication
  draining, dirty metrics, lifecycle cleanup, and the profile harness.
- `tokio-quiche/src/multicast/server_stream.rs`: shared publisher queues,
  exact packet preparation, and compact completed-stream tracking.

The `StreamMap` change in `4ec488bc` is generic basic QUIC behavior. All other
production changes in this pass are MCQUIC-specific.

## Reproducible Workload

The ignored deterministic test
`server_stream_publisher_profiles_eighty_connections` creates 80 in-memory QUIC
client/server pairs. Every connection writes its own 10-byte WebTransport
prefix. One shared publisher then commits three bursts of 32 ranges, each with
a 1,024-byte payload:

1. `Joined` without `MC_ACK`, so ordinary unicast fallback remains active.
2. One advancing `MC_ACK` per client, followed by a multicast-green burst.
3. `Left` on every client, followed by fallback re-entry and a final FIN.

Run it with:

```bash
cargo test -p tokio-quiche --lib --features multicast \
  server_stream_publisher_profiles_eighty_connections -- \
  --ignored --nocapture
```

CPU and memory were measured by launching the already-built test binary from
`tokio-quiche/` under `/usr/bin/time -l`. CPU samples were captured with the
macOS Time Profiler. The traces are:

- `/tmp/mcquic-baseline-time-valid.trace`
- `/tmp/mcquic-post-time.trace`

The Instruments Allocations template did not attach reliably to this short
test process. Allocation improvement is therefore demonstrated by an exact
test counter over preparation-buffer capacity, not an inferred wall-clock
allocation count.

## Before And After

| Metric | Baseline | Final | Result |
| --- | ---: | ---: | ---: |
| Publisher notification commands | 7,680 | 240 | -96.88% |
| Task wake calls | 240 | 240 | unchanged |
| Preparation-buffer capacity | 6,291,456 B | 101,439 B | -98.39% |
| Delivery metric fold attempts | 8,800 | 240 | -97.27% |
| Connection-local registrations | 7,680 | 7,680 | required work unchanged |
| Peak retained recovery ranges | 2,560 | 2,560 | semantics unchanged |
| Final retained recovery ranges | 0 | 0 | bounded |
| Active publisher stream entries after FIN | 1 | 0 | removed |
| Compact publisher completion ranges | n/a | 1 | bounded |
| Application ACK events | 80 | 80 | no duplicates in workload |
| Application probe events | 240 | 240 | no duplicates in workload |
| Wall time | 1.92 s | 1.67-1.69 s | about -12% |
| User CPU | 1.62 s | 1.58-1.59 s | slightly lower |
| System CPU | 0.15 s | 0.06-0.07 s | materially lower |
| Maximum RSS | 149,635,072 B | 149,389,312-149,422,080 B | effectively flat |

The macOS `peak memory footprint` counter was not stable between runs even
though maximum RSS was stable, so it is not used as evidence.

Targeted event tests process four valid ACK frames internally while forwarding
one advancing `ClientAck`, and forward one copy of two identical probe events.
The ordered ACK test starts with 1,000 pending packets, examines three map
entries for two sparse ACK hits plus the loss boundary, and leaves the expected
998 pending packets.

Both publisher and generic completion tests insert one million sequential
server-unidirectional stream IDs and retain one range. Sparse high IDs,
out-of-order completion, all four stream spaces, stream limits, and recreation
rejection remain covered.

## Time Profiler

The sampled test is dominated by fixture setup, not multicast recovery:

| Inclusive sampled CPU | Baseline | Final |
| --- | ---: | ---: |
| Total | 1,646 ms | 1,642 ms |
| `quiche::tls::Context::new` | 1,248 ms | 1,242 ms |
| `ServerControlRuntime::process_writes` | 15 ms | 12 ms |
| `flush_pending_stream_publications` | 10 ms | 6 ms |
| `multicast_stream_send_buf` | 8 ms | 4 ms |
| `ServerStreamPublisher::commit` | 3 ms | 1 ms |
| Delivery metric folding | 2 ms | 1 ms |

The 7,680 connection-local registrations are the largest remaining operation
count, but only account for about 4 ms, or 0.24%, of sampled CPU. This workload
does not justify a shared recovery catalogue. Such a redesign should wait for
a production trace showing registration or retained per-connection payloads as
a leading cost.

The unchanged 2,560-range peak is intentional: each green connection retains
32 ranges until ACK, loss recovery, or fallback re-entry. A longer production
profile with delayed or missing ACKs is the next useful memory-scaling test.

## Commits

- `99f4e90f` tests: add MCQUIC connection profile harness
- `e371189c` perf: coalesce multicast server events
- `1ffc2a2a` perf: edge-trigger stream publication fanout
- `84ad3aa4` perf: right-size multicast packet preparation
- `be245511` perf: match multicast ACKs against ordered ranges
- `e6b6a1fe` perf: fold multicast delivery metrics on change
- `94d2fdf3` perf: retire multicast stream state
- `ef4d761b` perf: fast-path completed publisher streams
- `4ec488bc` perf: compact collected stream tracking
- `7828d107` tests: count multicast stream registrations
- `4359ea47` refactor: tidy multicast stream encoding

## Verification

- `cargo test -p quiche multicast`: 63 passed.
- `cargo test -p tokio-quiche --lib --features multicast`: 93 passed, 1
  intentionally ignored profile.
- `cargo test -p tokio-quiche --features multicast -- --test-threads=1`: 93
  library passed, 1 ignored; 19 integration passed; 1 doc test passed.
- Strict all-target clippy with `-D warnings`: passed for `quiche` with
  `boringssl-vendored` and `tokio-quiche` with `multicast`.
- Yggdrasil `cargo test --locked --features tokio-quiche-interop`: 232 library
  tests and 1 CLI integration test passed. Its worktree remained clean.
- `cargo +nightly fmt -- --check` and `git diff --check`: passed.
