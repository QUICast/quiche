# Running the example server

⚠️ This example demonstrate simples usage of the tokio-quiche API. It is not
intended to be used in production environments; no performance, security or
reliability guarantees are provided.

First, start the server. In this example, we'll be listening on
`127.0.0.1:5757`. We can pass that to the `address` argument to specify it as
the listening address:

```shell
RUST_LOG=info cargo run --example async_http3_server -- --address <listening_address>
```

Verbosities can be specified with typical [`env_logger`](https://docs.rs/env_logger/latest/env_logger/#enabling-logging) syntax.

The default TLS certificate covers `test.com`. Certificates can be passed via
the `--tls-cert-path` CLI argument, while private keys can be passed via the
`--tls-private-key-path` argument.

Once the server is up and running, you can hit it with your favorite client:

```shell
❮ RUST_LOG=debug cargo run --bin quiche-client -- https://test.com --no-verify --connect-to 127.0.0.1:5757

    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.13s
     Running `target/debug/quiche-client 'https://test.com' --no-verify --connect-to '127.0.0.1:5757'`
[2025-07-08T00:06:11.363952000Z INFO  quiche_apps::client] connecting to 127.0.0.1:5757 from 0.0.0.0:55110 with scid 531c918fbe27cc86abb7bd3e92695f2caf0d7809
[2025-07-08T00:06:11.369728000Z DEBUG quiche_apps::common] Sent HTTP request [":method: GET", ":scheme: https", ":authority: test.com", ":path: /", "user-agent: quiche"]
[2025-07-08T00:06:11.371084000Z DEBUG quiche_apps::common] got response headers [(":status", "200")] on stream id 0
[2025-07-08T00:06:11.371113000Z DEBUG quiche_apps::common] 1/1 responses received
[2025-07-08T00:06:11.371121000Z INFO  quiche_apps::common] 1/1 response(s) received in 6.605ms, closing...
[2025-07-08T00:06:11.402352000Z INFO  quiche_apps::client] connection closed, recv=9 sent=13 lost=0 retrans=0 sent_bytes=2793 recv_bytes=2436 lost_bytes=0 [local_addr=0.0.0.0:55110 peer_addr=127.0.0.1:5757 validation_state=Validated active=true recv=9 sent=13 lost=0 retrans=0 rtt=2.396186ms min_rtt=Some(199.677µs) rttvar=1.915735ms cwnd=13500 sent_bytes=2793 recv_bytes=2436 lost_bytes=0 stream_retrans_bytes=0 pmtu=1350 delivery_rate=1137163]
```

The server should print the events something like this:

```shell
[2025-07-08T00:06:11.365942000Z INFO  async_http3_server] received new connection!
[2025-07-08T00:06:11.370735000Z INFO  async_http3_server::server] received unhandled event: IncomingSettings { settings: [(2777032016412723649, 2920255815440916575)] }
[2025-07-08T00:06:11.370759000Z INFO  async_http3_server::server] received headers: IncomingH3Headers { stream_id: 0, headers: [":method: GET", ":scheme: https", ":authority: test.com", ":path: /", "user-agent: quiche"], read_fin: true, h3_audit_stats: H3AuditStats { stream_id: 0, downstream_bytes_sent: 0, downstream_bytes_recvd: 0, recvd_stop_sending_error_code: -1, recvd_reset_stream_error_code: -1, sent_stop_sending_error_code: -1, sent_reset_stream_error_code: -1, recvd_stream_fin: AtomicCell { value: Explicit }, sent_stream_fin: AtomicCell { value: None } } }
[2025-07-08T00:06:11.370838000Z INFO  async_http3_server::server] received unhandled event: BodyBytesReceived { stream_id: 0, num_bytes: 0, fin: true }
[2025-07-08T00:06:11.370983000Z INFO  async_http3_server::server] received unhandled event: StreamClosed { stream_id: 0 }
```

Logging can be suppressed entirely by omitting the `RUST_LOG` environment variable.

The server also exposes a `/stream-bytes/<n>` endpoint. When a request is made to said
endpoint, `n` bytes will come back in the response body:

```shell
❯ RUST_LOG=debug cargo run --bin quiche-client -- https://test.com/stream-bytes/3 --no-verify --connect-to 127.0.0.1:5757

   Compiling quiche v0.24.4 (/Users/erittenhouse/Documents/projects/quiche/quiche)
   Compiling quiche_apps v0.1.0 (/Users/erittenhouse/Documents/projects/quiche/apps)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.66s
     Running `target/debug/quiche-client 'https://test.com/stream-bytes/3' --no-verify --connect-to '127.0.0.1:5757'`
[2025-07-08T00:05:42.201487000Z INFO  quiche_apps::client] connecting to 127.0.0.1:5757 from 0.0.0.0:61497 with scid d6d1a81656e0a650c9466cb97de14faba3c8d7f8
[2025-07-08T00:05:42.210185000Z DEBUG quiche_apps::common] Sent HTTP request [":method: GET", ":scheme: https", ":authority: test.com", ":path: /stream-bytes/3", "user-agent: quiche"]
[2025-07-08T00:05:42.211799000Z DEBUG quiche_apps::common] got response headers [(":status", "200")] on stream id 0
[2025-07-08T00:05:42.211834000Z DEBUG quiche_apps::common] got 3 bytes of response data on stream 0
[2025-07-08T00:05:42.211845000Z DEBUG quiche_apps::common] 1/1 responses received
[2025-07-08T00:05:42.211850000Z INFO  quiche_apps::common] 1/1 response(s) received in 9.849541ms, closing...
[2025-07-08T00:05:42.270737000Z INFO  quiche_apps::client] connection closed, recv=9 sent=13 lost=0 retrans=0 sent_bytes=2805 recv_bytes=2436 lost_bytes=0 [local_addr=0.0.0.0:61497 peer_addr=127.0.0.1:5757 validation_state=Validated active=true recv=9 sent=13 lost=0 retrans=0 rtt=5.045481ms min_rtt=Some(130.486µs) rttvar=3.559643ms cwnd=13500 sent_bytes=2805 recv_bytes=2436 lost_bytes=0 stream_retrans_bytes=0 pmtu=1350 delivery_rate=1104879]
```

# Running the multicast client example

The multicast client example lives on the `tokio-quiche` side because that is
where the current `mcrx-core` integration exists. It sends one HTTP/3 `GET`
request and keeps the connection alive long enough to print multicast announce,
state, and decoded packet events.

Build it with the `multicast` feature enabled:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_multicast_client --features multicast -- https://test.com/ --connect-to 127.0.0.1:5757
```

Useful flags:

```shell
--run-for-secs 60
--multicast-interface 192.0.2.10
--max-joined-channels 8
--max-aggregate-rate-kibps 16384
```

Notes:

- Peer verification is off by default, matching `tokio-quiche`'s client
  defaults. Pass `--verify-peer` if you want certificate validation.
- The current multicast receive path is IPv4-only. IPv6 announces are surfaced
  as explicit placeholder events instead of being joined.
- If the server does not advertise multicast support, the example still works
  as a normal HTTP/3 client and will only print HTTP/3 events.

# Running the multicast server example

The multicast server example pairs with the client example above. It serves the
same simple HTTP/3 responses as `async_http3_server`, but it also:

- advertises multicast server support during the QUIC handshake
- announces one IPv4 multicast channel
- sends `MC_KEY` and `MC_JOIN`
- starts publishing multicast DATAGRAM packets after the client reports
  `Joined`

Start it like this:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_multicast_server --features multicast -- --address 127.0.0.1:5757
```

Then connect with the multicast client example:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_multicast_client --features multicast -- https://test.com/ --connect-to 127.0.0.1:5757 --multicast-interface 127.0.0.1 --run-for-secs 10
```

By default, the server uses loopback-friendly multicast settings:

```shell
--multicast-source 127.0.0.1
--multicast-interface 127.0.0.1
--multicast-group 232.1.2.3
--multicast-port 4444
```

# Running the multicast file transfer examples

These examples use the multicast data path for something concrete: the server
repeats a file forever as multicast DATAGRAM chunks, with a small in-band
manifest packet mixed in regularly so a client can join mid-stream and still
learn the file layout.

Start the file sender:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_multicast_file_server --features multicast -- --address 127.0.0.1:5757 --file ./README.md
```

Then start the receiver:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_multicast_file_client --features multicast -- --connect-to 127.0.0.1:5757 --multicast-interface 127.0.0.1 --output /tmp/README.copy
```

You can start multiple receivers against the same sender. Each receiver gets
its control plane through its own unicast QUIC connection, while the file data
itself is delivered through the shared multicast stream:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_multicast_file_client --features multicast -- --connect-to 127.0.0.1:5757 --multicast-interface 127.0.0.1 --output /tmp/README.client1
RUST_LOG=info cargo run -p tokio-quiche --example async_multicast_file_client --features multicast -- --connect-to 127.0.0.1:5757 --multicast-interface 127.0.0.1 --output /tmp/README.client2
```

To emit Heimdall-ingestible receiver metrics while receiving the file:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_multicast_file_client --features multicast -- --connect-to 127.0.0.1:5757 --multicast-interface 127.0.0.1 --output /tmp/README.client1 --heimdall-metrics-jsonl /tmp/receiver-a.jsonl
```

Useful flags:

```shell
--chunk-payload-bytes 1024
--integrity-hash-algorithm sha256-32
--integrity-hashes-per-frame 1
--manifest-interval-packets 32
--publish-interval-ms 20
--metrics-interval-secs 5
--heimdall-metrics-jsonl /tmp/receiver-a.jsonl
--max-run-secs 300
```

To stress the shared multicast publisher with a rolling wave of receivers, use
the helper script in [tools/run_multicast_file_stress.sh](/Users/mfranke/Devtools/Multicast/quiche/tools/run_multicast_file_stress.sh). It starts one server, then launches a new client every second until something fails or you stop it:

```shell
tools/run_multicast_file_stress.sh --file /tmp/quicast-100m.bin
```

By default it creates one run directory and then nests each receiver under
`client-<id>/`, so Heimdall-ready files land in a shape like:

```text
<run>/
  client-0001/network.jsonl
  client-0001/network_hardware.jsonl
  client-0001/network_quiche.jsonl
  client-0002/network.jsonl
  ...
```

Handy options for that script:

```shell
--generate-file-mb 100
--client-interval-secs 1
--max-clients 50
--integrity-hash-algorithm sha256-32
--integrity-hashes-per-frame 1
--publish-interval-ms 1
--heimdall-metrics
--work-dir /tmp/quicast-stress-run
```

Notes:

- The file example is IPv4-only on the multicast path, matching the current
  `mcrx-core` / `mctx-core` integration.
- The default integrity hash algorithm is currently `sha256-32`, which maps to
  draft hash algorithm ID `1` and emits a full 32-byte SHA-256 digest per
  multicast packet.
- The sender is now a shared multicast publisher that runs independently of
  any single client connection. Each client receives only draft control frames
  over unicast, while the file chunks themselves stay on multicast.
- Both the sender and receiver can emit periodic metrics summaries. The sender
  reports `mctx-core` send counters plus `quiche` channel-encode counters and
  multicast control fanout counters; the receiver reports `mcrx-core` socket
  counters together with `quiche` channel decode/buffering counters and async
  receive/decode error counts.
- `--integrity-hash-algorithm` accepts `sha256-32`, `sha256-16`, `sha256-15`,
  `sha256-12`, `sha256-8`, `sha256-4`, `sha384-48`, or `sha512-64`.
- `--integrity-hashes-per-frame` controls how many packet hashes are
  aggregated into each `MC_INTEGRITY` frame, which directly changes the
  control-plane frame size and the number of unicast integrity frames each
  client must process.
- The paired receiver metrics are useful for spotting whether a bottleneck is
  before decode (`mcrx-core` sees packets but `quiche` does not), or inside
  the draft receive path because packets are delayed waiting for `MC_KEY` or
  `MC_INTEGRITY`.
- `--heimdall-metrics-jsonl` writes an `mcrx`-compatible network metrics file
  plus sibling `*_hardware.jsonl` and `*_quiche.jsonl` files. The network and
  hardware files are directly ingestible by Heimdall:

```shell
heimdall ingest-mcrx --run-id run-001 receiver-a /tmp/receiver-a.jsonl /path/to/heimdall-workspace
heimdall ingest-mcrx-hardware --run-id run-001 receiver-a /tmp/receiver-a_hardware.jsonl /path/to/heimdall-workspace
```

- The `*_quiche.jsonl` sidecar keeps the receiver-side draft/decode counters in
  a separate log file, so the main `mcrx` network JSONL stays clean.
- The JSONL files now begin with a single header line identified by
  `schema="heimdall-jsonl-v1"`, carrying `artifact_type`, `node_id`,
  `producer`, and a `flags` object. The metric rows that follow are
  intentionally compact and inherit that context from the single file header,
  which should make multi-file batch ingest much easier once Heimdall learns
  the same convention.
- Clients now emit `MC_ACK` frames for multicast packets they validate and
  decode. The current example still relies on looped chunks rather than
  `MC_ACK` for transfer completion, so a client exits as soon as it has
  received every chunk once.
- The file-transfer server now counts those `MC_ACK` frames in its periodic
  control metrics, which makes it easier to compare “clients joined” versus
  “clients are actively reporting multicast receive progress.”

# Running the raw QUIC file transfer examples

These examples use the same payload model as the multicast file demo, but send
the entire file through plain unicast QUIC on a single stream. That gives you
an easier apples-to-apples baseline when you want to compare connection count,
throughput, and per-client transport cost without the multicast extension.

Start the raw QUIC file server:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_quic_file_server -- --address 127.0.0.1:5757 --file ./README.md
```

Then start one client:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_quic_file_client -- --connect-to 127.0.0.1:5757 --output /tmp/README.quic.copy
```

You can also launch multiple clients against the same server. Unlike the draft
multicast path, every client receives the entire file over its own unicast QUIC
stream:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_quic_file_client -- --connect-to 127.0.0.1:5757 --output /tmp/README.quic.client1
RUST_LOG=info cargo run -p tokio-quiche --example async_quic_file_client -- --connect-to 127.0.0.1:5757 --output /tmp/README.quic.client2
```

Each client can also write a compact QUIC stats summary:

```shell
RUST_LOG=info cargo run -p tokio-quiche --example async_quic_file_client -- --connect-to 127.0.0.1:5757 --output /tmp/README.quic.client1 --stats-json /tmp/README.quic.client1.stats.json
```

To stress the unicast baseline with the same rolling-client pattern, use
[tools/run_quic_file_stress.sh](/Users/mfranke/Devtools/Multicast/quiche/tools/run_quic_file_stress.sh):

```shell
tools/run_quic_file_stress.sh --file /tmp/quicast-100m.bin
```

It uses the same run-directory structure as the multicast stress helper, but
each client directory contains raw QUIC output and stats instead:

```text
<run>/
  client-0001/output.bin
  client-0001/client.log
  client-0001/stats.json
  client-0002/output.bin
  ...
```

Handy options for that script:

```shell
--generate-file-mb 100
--client-interval-secs 1
--max-clients 50
--client-max-run-secs 300
--work-dir /tmp/quicast-quic-stress-run
--capture-quiche-logs
```
