# MCQUIC Resource And Performance Profile

## Scope

This report covers the correctness/resource pass after baseline `c779bb98`.
It measures the structures that can grow with multicast packet reordering,
missing ACKs, key rotation, shared publisher fanout, and stalled connections.
It does not include TLS setup, socket throughput, kernel multicast behavior, or
media encoding.

The implementation keeps socket ownership outside quiche and uses shared
`Bytes` for STREAM publication fanout. Queue byte counters are deliberately
logical retained bytes per connection or attachment. They represent overload
risk and recovery obligations, not necessarily unique allocator-backed payload
bytes.

## Default Bounds

| Resource | Items | Logical retained bytes |
| --- | ---: | ---: |
| Core outgoing multicast control | 1,024 | 2 MiB |
| Connection-lifetime Channel IDs | 1,024 | At most 20 KiB ID payload |
| Pending encrypted receive packets | 4,096 | 8 MiB |
| Pending receive integrity | 8,192 | 1 MiB |
| Core STREAM recovery, connection | 65,536 ranges | 64 MiB |
| Core STREAM recovery, channel | 16,384 ranges | 16 MiB |
| Tokio events | 4,096 | 64 MiB |
| Tokio commands | 4,096 | 64 MiB |
| Tokio receive ingress | 4,096 | 64 MiB |
| Tokio pending publications | 4,096 | 64 MiB |
| Tokio pending integrity | 8,192 | 8 MiB |
| Publisher attachment queue | 4,096 | 8 MiB |
| Publisher active streams | 65,536 | Stream-state dependent |
| Publisher completed-stream history | 4,096 storage units | Representation dependent |

The receive decoder performs at most 256 indexed operations and releases at
most 128 packet/error events per convenience input call. Its budget-aware
entry points let Tokio admit one packet, key, or integrity frame without
opening a nested 256-operation drain.

Each complete Tokio multicast driver callback has one aggregate 256-unit
budget. One unit is one successful scheduled work-class operation: a control
frame handled; an ingress, command, publisher, publication, integrity, or
pending-control item transferred or handled; a standalone core maintenance
operation; or an ACK, metric, or probe forwarded. Ingress/control processing
includes its one core receive admission. Readiness scans and unsuccessful class
attempts are free. Class and Channel-ID continuation cursors rotate across
callbacks.

Permits remain charged when an item moves from a bounded Tokio channel to
runtime staging. Pending integrity batches and ready integrity frames share one
budget. Attachment-to-runtime staging removes only the admitted ordered prefix,
restores any rejected suffix with exact byte accounting, and never creates a
hidden unbounded transfer queue. One attachment item may retain at most 64 KiB;
the configured attachment byte budget must be at least 128 KiB. Each
asynchronous multicast ingress producer can own one packet outside queue
accounting while it waits for capacity; that packet is not duplicated.

## Release Probes

All probes are deterministic ignored tests so normal test runs stay fast.
Timing rows are one local run and are intentionally secondary to deterministic
item, byte, work, and progress assertions.

### Aggregate Scheduler Scaling

Run:

```bash
cargo test --release -p tokio-quiche --features multicast --lib \
  aggregate_scheduler_scaling_release_probe -- --ignored --nocapture
```

| Complete callback | Active channels | Calls | Total | Per call | Peak work |
| --- | ---: | ---: | ---: | ---: | ---: |
| Client `process_reads` | 1 | 1 | 65 us | 65 us | 2 |
| Client `process_reads` | 128 | 1 | 106 us | 106 us | 256 |
| Client `process_reads` | 1,024 | 8 | 879 us | 109 us | 256 |
| Control server `process_writes` | 1 | 1 | 15 us | 15 us | 3 |
| Control server `process_writes` | 128 | 2 | 186 us | 93 us | 256 |
| Control server `process_writes` | 1,024 | 12 | 2,545 us | 212 us | 256 |

These are complete callback invocations with the real work-class scheduler, not
helper-level maintenance/staging calls. For `K` continuously ready classes and
budget `B`, every class receives a successful turn within `ceil(K / B)`
callbacks. A class containing `N` continuously ready channels reaches every
channel within the conservative `N * ceil(K / B)` callback bound. If it is the
only ready class, this tightens to `ceil(N / B)`. Deterministic 300-channel
tests use `B = 32`, never exceed 32 units in a complete callback, and prove
eventual progress through the highest-sorted Channel ID. Cursor lookup remains
correct when channels are inserted, removed, replaced, blocked, or closed.

### Reliable Control ACK/Loss Churn

Run:

```bash
cargo test --release -p quiche --lib \
  control_send_queue_ack_loss_churn_release_probe -- \
  --ignored --nocapture
```

The initial payload-equality scan showed material quadratic growth, so the
queue now indexes reliable reservations by a collision-checked frame
fingerprint. The frame itself remains the source of truth; hash collisions
fall back to exact equality within the bounded bucket.

| Retained reliable frames | Before | After |
| ---: | ---: | ---: |
| 1 | 103 us | 190 us |
| 128 | 115 us | 97 us |
| 1,024 | 5,010 us | 1,642 us |

At 1,024 retained frames the identical probe improved by 67.2%. The one-frame
row is dominated by cold-start and timer noise rather than the indexed lookup.
The internal
index adds one bounded ID entry per reliable reservation and does not duplicate
secret-bearing frame payloads.

### Publisher Producer/Stager Lock Contention

Run:

```bash
cargo test --release -p tokio-quiche --features multicast --lib \
  publisher_queue_staging_lock_contention_release_probe -- \
  --ignored --nocapture
```

Four producers enqueue 80,000 items, first without and then with a concurrent
256-item stager.

| Concurrent staging | Elapsed | Push p50 | Push p95 | Push p99 | Worst |
| --- | ---: | ---: | ---: | ---: | ---: |
| No | 12 ms | 41 ns | 42 ns | 42 ns | 3.466 ms |
| Yes | 39 ms | 41 ns | 42 ns | 42 ns | 11.949 ms |

Concurrent staging still drains 80,000 items in 39 ms with a 42 ns p99 and no
retention leak. The isolated worst cases are scheduler-sensitive and much
higher than the percentiles. This remains a production-profile watch point; the
distribution and absolute throughput did not justify replacing the small mutex
with a more complex queue in this pass.

### Attachment Fanout

Run:

```bash
cargo test --release -p tokio-quiche --features multicast --lib \
  server_stream_publisher_profiles_one_and_ten_thousand_attachments -- \
  --ignored --nocapture
```

The probe attaches lightweight connection controllers, then commits 32 shared
256-byte STREAM ranges. It excludes TLS and QUIC fixture creation and times
only each `commit()` fanout.

| Clients | Queue items | Logical queue bytes | Command peak items | Command peak bytes |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 32,000 | 13,312,000 | 2,000 | 648,000 |
| 10,000 | 320,000 | 133,120,000 | 20,000 | 6,480,000 |

| Clients | p50 | p95 | p99 | Worst | Edge notifications |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 11.375 us | 123.000 us | 178.667 us | 222.041 us | 1,000 |
| 10,000 | 381.250 us | 1.303 ms | 3.671 ms | 3.905 ms | 10,000 |

There is one queue-ready notification per attachment, not one notification per
publication. The 10,000-client result therefore retains 320,000 logical
connection obligations while issuing 10,000 edge notifications.

The payload allocation is shared. The logical queue-byte total includes
per-attachment STREAM and integrity obligations, so it must not be read as 133
MiB of duplicate payload backing.

### Receive Floods And Key Rotation

Run:

```bash
cargo test --release -p quiche --lib \
  channel_receive_profiles_metadata_floods_and_key_rotation -- \
  --ignored --nocapture
```

The probe covers 4,000 integrity-before-data packets, 4,000
data-before-integrity packets, and 1,000 key rotations using the injected test
clock.

| Metric | Result |
| --- | ---: |
| Integrity-first elapsed | 10.581 ms |
| Data-first elapsed | 3.759 ms |
| Peak integrity entries | 4,000 |
| Peak pending packets | 4,000 |
| Peak pending packet bytes | 104,000 |
| Integrity-first indexed work | 16,002 |
| Data-first indexed work | 16,002 |
| Maximum work in one integrity-first input | 2 |
| Maximum work in one data-first input | 3 |
| Active keys after rapid rotations | 3 |

Work is proportional to newly actionable metadata. Inserting one key or hash
does not rescan every pending packet. Three keys can coexist under the tested
two-second rotation cadence because the three-second idle grace overlaps two
superseded generations; this remains below the default eight-generation bound.

### One-Minute Missing ACK Window

Run:

```bash
cargo test --release -p quiche --lib \
  multicast_stream_profiles_sixty_second_missing_ack_window -- \
  --ignored --nocapture
```

The structural horizon represents 60 seconds at 16 ranges per second after the
channel becomes viable, with no later ACK.

| Metric | Result |
| --- | ---: |
| Retained ranges | 960 |
| Retained payload bytes | 3,840 |
| Registration p50 | 125 ns |
| Registration p95 | 166 ns |
| Registration p99 | 292 ns |
| Worst registration | 1.916 us |

A local `LEFT` transition releases all 960 ranges and returns both connection
and channel retained-byte accounting to zero. The test is structural; it does
not sleep for one minute.

## Fairness And Saturation

Focused tests cover one connection whose STREAM prefix never becomes available
beside a healthy connection. The stalled connection retains one bounded
publication while the healthy connection reaches zero pending publications and
receives the complete STREAM plus FIN in the same processing pass. Once the
stalled prefix arrives, it resumes independently.

Separate tests cover:

- multiple channels where one stream is blocked and another channel publishes
  and retires;
- integrity-before-key and publication-before-key barriers;
- a never-polled event consumer;
- required-event saturation mixed with latest-only metrics;
- receiver take, transfer, close, and drop;
- shutdown while the event queue is full;
- command, integrity-batch, ingress, and attachment saturation;
- transactional attachment staging with a one-item work budget and a
  two-command capacity;
- live detach with committed bytes and FIN;
- stale viability after reattachment;
- recovery release on ACK gaps, timeout, leave, reset, and teardown.
- simultaneous adversarial backlog in every client, control-server, and
  publication-owning-server callback phase.

Required event or control state is not silently discarded. A full required
event stream records terminal overload out of band and terminates its runtime.
A saturated publisher attachment is sealed and detached without affecting
healthy attachments. If the runtime cannot retain an already committed
required item, that connection fail-stops rather than continuing with a STREAM
offset gap.

The adversarial callback tests observe exact peak work equal to their configured
budgets: client read/write 4/5 units, control-server read/write 10/8 units, and
publication-owning-server read/write 3/5 units. Subsequent callbacks remain at
or below the same limit while every preloaded class drains.

## Copies And Allocations

- Shared STREAM publication uses one `Bytes` backing allocation across
  attachments.
- The Tokio receive path no longer clones a complete decoded `ChannelPacket`
  before passing it to core quiche and emitting diagnostics.
- Only DATAGRAM payloads copied into the owned core receive queue are cloned.
- Exact packet sizing avoids a maximum-size temporary publication buffer.
- Queue metrics use O(1) item/byte accounting.
- Delivery metric snapshots are folded only when dirty and use atomic
  accumulators across detached connections.

No unsafe allocator hooks or pooling were added. Exact global allocation counts
are therefore not claimed. The observable copy count for the decoded packet
path falls from one complete packet clone plus owned DATAGRAM payloads to only
the owned DATAGRAM payload clones.

## Historical Established-Connection Profile

The existing 80-connection established profile remains useful for comparison.
The current release result was 2.145 seconds for 1,310,720 connection-local
registrations, or 1,636 ns per registration, after TLS setup and first viability
ACK. Publications are fed in batches of 128 while callbacks preserve their
256-item work budget. The run issued 10,240 task wakes, peaked at 327,680
recovery ranges, and returned to zero retained ranges. It also demonstrated:

- 96.88% fewer publisher notification commands;
- 98.39% less preparation-buffer capacity;
- 97.27% fewer delivery metric fold attempts;
- unchanged required connection-local registration work;
- zero retained ranges after ACK/re-entry teardown.

This still does not justify a shared recovery catalogue. Payload bytes are
already shared, while stream offsets, flow control, reset state, ACK progress,
loss decisions, and teardown are connection-local.

## Interpretation

The probes establish bounded structure and healthy-client isolation, not
production throughput. The 10,000-attachment fanout remains linear in client
count because each connection needs independent recovery metadata. Publication
p99 was 3.671 ms in this synthetic release run, but scheduling, allocator, TLS,
kernel, and socket costs are absent.

No additional receive-copy optimization was attempted in this pass. The
existing borrowed core handoff avoids cloning a complete decoded
`ChannelPacket`, but ownership/accounting changes that depend on transparent
multicast STREAM flow control remain deferred with that draft-08 question.

Before deployment, capture a production release profile with real established
connections, delayed ACK distributions, socket publication, and application
load. Reconsider queue defaults only from observed retained-byte peaks and
fallback objectives, not from synthetic wall time alone.
