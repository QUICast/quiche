# MCQUIC Server STREAM Performance And Corrective Pass

## Scope

This report covers the performance pass from baseline commit `54684d20`
through review commit `6d7e917c` and its lifecycle corrective follow-up. The
wire format, cryptography, congestion control, WebTransport offsets, and
unicast fallback semantics are unchanged.

Changed files:

- `quiche/src/lib.rs`: ordered ACK recovery, dirty delivery metrics, and
  explicit recovery-state retirement.
- `quiche/src/multicast.rs`: exact packet sizing and borrowed STREAM encoding.
- `quiche/src/stream/mod.rs`: generic completed-stream chunk tracking.
- `quiche/src/tests.rs`: core fallback, recovery, metrics, and lifetime tests.
- `tokio-quiche/src/multicast.rs`: event coalescing, edge-triggered publication
  draining, dirty metrics, lifecycle cleanup, and the profile harness.
- `tokio-quiche/src/multicast/server_stream.rs`: shared publisher queues,
  exact packet preparation, ordered detach barriers, and compact
  completed-stream tracking.

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

The longer
`server_stream_publisher_profiles_established_connections` test excludes TLS
fixture creation from its timer. After all 80 connections are established and
multicast-green, it publishes four rounds of 4,096 24-byte ranges. Each round
is ACKed before the next starts, bounding retained recovery at 327,680 entries
while performing 1,310,720 connection-local registrations:

```bash
cargo test --release -p tokio-quiche --lib --features multicast \
  server_stream_publisher_profiles_established_connections -- \
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
| Compact publisher completion storage units | n/a | 1 | bounded |
| Application ACK events | 80 | 80 | no duplicates in workload |
| Application probe events | 240 | 240 | no duplicates in workload |
| Wall time | 1.92 s | 1.67-1.69 s | about -12% |
| User CPU | 1.62 s | 1.58-1.59 s | slightly lower |
| System CPU | 0.15 s | 0.06-0.07 s | materially lower |
| Maximum RSS | 149,635,072 B | 149,389,312-149,422,080 B | effectively flat |

The macOS `peak memory footprint` counter was not stable between runs even
though maximum RSS was stable, so it is not used as evidence.

Targeted event tests process four valid ACK frames internally while forwarding
the two distinct `ClientAck` frames and suppressing exact duplicates. An ACK
whose largest packet number is unchanged but whose lower ranges differ is
preserved. Coalescer history is reset when a channel generation is replaced.
Probe tests forward one copy of two identical events within one generation.
The ordered ACK test starts with 1,000 pending packets, examines three map
entries for two sparse ACK hits plus the loss boundary, and leaves the expected
998 pending packets.

Both publisher and generic completion tests insert one million sequential
server-unidirectional stream IDs and retain one prefix marker. Interleaved
million-stream tests retain fewer than 2,000 fixed-size chunks rather than one
tree node per completed stream. Sparse high IDs, out-of-order completion, all
four stream spaces, stream limits, and recreation rejection remain covered.

## Corrective Lifecycle Pass

The post-review pass adds coverage for cases the first profile did not model:

- Dropping a live attachment seals its queue against future fanout, drains
  already committed publications and FIN in order, waits through stream-offset
  backpressure, then releases recovery state.
- Detach and channel reuse start a fresh probe generation. Prior `Viable`
  state cannot suppress fallback, and an ACK from the previous publication
  generation cannot make the replacement green.
- Publisher and generic completed-stream tracking use 1,024-bit chunks that
  begin sparse and become dense at 32 entries.
- Distinct ACK frames are no longer conflated solely because their largest
  packet number is unchanged.
- Exact-size preflight failures increment `encode_errors` even when packet
  writing is never attempted.

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

The short profile cannot support a catalogue decision because TLS setup
dominates its samples. The established-connection profile addresses that
limitation:

| Build | Measured steady-state | Per registration | Whole test |
| --- | ---: | ---: | ---: |
| Debug | 3.911 s | 2,984 ns | 5.60 s |
| Release | 417.329 ms | 318 ns | 0.87 s |

The timer starts after TLS setup, stream-prefix construction, attachment, and
the first successful ACK. It includes publication fanout, connection-local
registration, integrity batching, and ACK processing.

This result still does not justify a shared recovery catalogue. `Bytes`
already shares payload backing across connections, while stream offsets, flow
control, ACK progress, loss decisions, reset handling, and teardown are
connection-local. At 318 ns per registration in this synthetic release
workload, a catalogue would add synchronization and lifecycle complexity
without removing the dominant required state. Revisit this only if a
production release profile identifies registration lookup or per-connection
range metadata as a leading cost.

The short profile's unchanged 2,560-range peak is intentional: each green
connection retains
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

- `cargo test -p quiche multicast`: 64 passed.
- The same 64 multicast tests passed with
  `--no-default-features --features boringssl-boring-crate`.
- Generic collected-stream chunk tests: 4 passed, including one million
  sequential, one million interleaved, and dense-to-prefix promotion.
- `cargo test -p tokio-quiche --features multicast -- --test-threads=1`: 99
  library passed, 2 ignored profiles; 19 integration passed; 1 doc test passed.
- Both ignored profiles passed explicitly. The established profile passed in
  debug and release builds.
- Strict clippy with `-D warnings`: passed for `quiche` tests with
  `boringssl-boring-crate` and `tokio-quiche` tests with `multicast`.
- Yggdrasil `cargo test --locked --features tokio-quiche-interop`: 232 library
  tests and 1 CLI integration test passed. Its worktree remained clean.
- `cargo +nightly fmt -- --check` and `git diff --check`: passed.
