#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: tools/run_multicast_file_stress.sh [options]

Starts the multicast file server once, then launches new multicast file clients
at a fixed interval until one fails, the server dies, or you stop the test.

Options:
  --address ADDR                    QUIC server address (default: 127.0.0.1:5757)
  --multicast-interface ADDR        IPv4 interface for sender/receivers
                                    (default: 127.0.0.1)
  --multicast-source ADDR           IPv4 multicast source address
                                    (default: value of --multicast-interface)
  --multicast-group ADDR            Multicast group (default: 232.1.2.3)
  --multicast-port PORT             Multicast UDP port (default: 4444)
  --file PATH                       File to send
  --generate-file-mb SIZE           Generate a payload of this size in MiB when
                                    --file is omitted (default: 100)
  --client-interval-secs SECS       Delay between client starts (default: 1)
  --max-clients COUNT               Stop after launching this many clients
                                    (default: unlimited)
  --client-max-run-secs SECS        Receiver timeout per client (default: 300)
  --publish-interval-ms MS          Server multicast pacing interval
                                    (default: 1)
  --chunk-payload-bytes BYTES       File chunk payload size (default: 1024)
  --manifest-interval-packets N     Manifest cadence (default: 32)
  --server-metrics-interval-secs N  Server metrics cadence (default: 0)
  --client-metrics-interval-secs N  Client metrics cadence (default: 0)
  --rust-log VALUE                  RUST_LOG value (default: info)
  --work-dir PATH                   Run directory; each client gets its own
                                    client-<id>/ subdirectory
  --heimdall-metrics                Emit Heimdall JSONL files per client
  --keep-going                      Keep launching clients after a failure
  --help                            Show this help

Examples:
  tools/run_multicast_file_stress.sh

  tools/run_multicast_file_stress.sh \
    --file /tmp/quicast-100m.bin \
    --client-interval-secs 1 \
    --publish-interval-ms 1
EOF
}

log() {
    printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

generate_file() {
    local path="$1"
    local size_mb="$2"

    log "generating ${size_mb} MiB payload at $path"

    if command -v mkfile >/dev/null 2>&1; then
        mkfile "${size_mb}m" "$path"
        return
    fi

    dd if=/dev/zero of="$path" bs=1048576 count="$size_mb" status=none
}

output_path_for() {
    local client_id="$1"
    printf '%s/output.bin' "$(client_dir_for "$client_id")"
}

log_path_for() {
    local client_id="$1"
    printf '%s/client.log' "$(client_dir_for "$client_id")"
}

metrics_path_for() {
    local client_id="$1"
    printf '%s/network.jsonl' "$(client_dir_for "$client_id")"
}

client_dir_for() {
    local client_id="$1"
    printf '%s/client-%04d' "$WORK_DIR" "$client_id"
}

has_active_clients() {
    [[ -n "${ACTIVE_CLIENTS[*]-}" ]]
}

cleanup() {
    local entry

    if has_active_clients; then
        for entry in "${ACTIVE_CLIENTS[@]}"; do
            local pid="${entry#*:}"
            kill "$pid" >/dev/null 2>&1 || true
        done
    fi

    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
    fi

    if has_active_clients; then
        for entry in "${ACTIVE_CLIENTS[@]}"; do
            local pid="${entry#*:}"
            wait "$pid" >/dev/null 2>&1 || true
        done
    fi

    if [[ -n "${SERVER_PID:-}" ]]; then
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
}

record_client_result() {
    local client_id="$1"
    local exit_code="$2"
    local log_path
    local output_path

    log_path="$(log_path_for "$client_id")"
    output_path="$(output_path_for "$client_id")"

    if [[ "$exit_code" -eq 0 ]] && [[ -f "$output_path" ]]; then
        if cmp -s "$FILE_PATH" "$output_path"; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            log "client $client_id completed ok"
            return 0
        fi

        exit_code=200
        log "client $client_id output mismatch"
    else
        log "client $client_id exited with code $exit_code"
    fi

    FAILURE_COUNT=$((FAILURE_COUNT + 1))
    LAST_FAILURE_CLIENT="$client_id"
    LAST_FAILURE_LOG="$log_path"

    log "last 40 lines from client $client_id log:"
    tail -n 40 "$log_path" || true

    return 1
}

reap_finished_clients() {
    local entry
    local next_active=()

    if ! has_active_clients; then
        ACTIVE_CLIENTS=()
        return
    fi

    for entry in "${ACTIVE_CLIENTS[@]}"; do
        local client_id="${entry%%:*}"
        local pid="${entry#*:}"

        if kill -0 "$pid" >/dev/null 2>&1; then
            next_active+=("$entry")
            continue
        fi

        local exit_code
        if wait "$pid"; then
            exit_code=0
        else
            exit_code=$?
        fi

        if ! record_client_result "$client_id" "$exit_code"; then
            if [[ "$KEEP_GOING" -eq 0 ]]; then
                STOP_REQUESTED=1
            fi
        fi
    done

    ACTIVE_CLIENTS=("${next_active[@]}")
}

check_server_alive() {
    if kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        return 0
    fi

    log "server exited unexpectedly"
    tail -n 80 "$SERVER_LOG" || true
    STOP_REQUESTED=1
    return 1
}

ADDRESS="127.0.0.1:5757"
MULTICAST_INTERFACE="127.0.0.1"
MULTICAST_SOURCE=""
MULTICAST_GROUP="232.1.2.3"
MULTICAST_PORT="4444"
FILE_PATH=""
GENERATE_FILE_MB="100"
CLIENT_INTERVAL_SECS="1"
MAX_CLIENTS="0"
CLIENT_MAX_RUN_SECS="300"
PUBLISH_INTERVAL_MS="1"
CHUNK_PAYLOAD_BYTES="1024"
MANIFEST_INTERVAL_PACKETS="32"
SERVER_METRICS_INTERVAL_SECS="0"
CLIENT_METRICS_INTERVAL_SECS="0"
RUST_LOG_VALUE="info"
WORK_DIR=""
EMIT_HEIMDALL_METRICS="0"
KEEP_GOING="0"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --address)
            ADDRESS="$2"
            shift 2
            ;;
        --multicast-interface)
            MULTICAST_INTERFACE="$2"
            shift 2
            ;;
        --multicast-source)
            MULTICAST_SOURCE="$2"
            shift 2
            ;;
        --multicast-group)
            MULTICAST_GROUP="$2"
            shift 2
            ;;
        --multicast-port)
            MULTICAST_PORT="$2"
            shift 2
            ;;
        --file)
            FILE_PATH="$2"
            shift 2
            ;;
        --generate-file-mb)
            GENERATE_FILE_MB="$2"
            shift 2
            ;;
        --client-interval-secs)
            CLIENT_INTERVAL_SECS="$2"
            shift 2
            ;;
        --max-clients)
            MAX_CLIENTS="$2"
            shift 2
            ;;
        --client-max-run-secs)
            CLIENT_MAX_RUN_SECS="$2"
            shift 2
            ;;
        --publish-interval-ms)
            PUBLISH_INTERVAL_MS="$2"
            shift 2
            ;;
        --chunk-payload-bytes)
            CHUNK_PAYLOAD_BYTES="$2"
            shift 2
            ;;
        --manifest-interval-packets)
            MANIFEST_INTERVAL_PACKETS="$2"
            shift 2
            ;;
        --server-metrics-interval-secs)
            SERVER_METRICS_INTERVAL_SECS="$2"
            shift 2
            ;;
        --client-metrics-interval-secs)
            CLIENT_METRICS_INTERVAL_SECS="$2"
            shift 2
            ;;
        --rust-log)
            RUST_LOG_VALUE="$2"
            shift 2
            ;;
        --work-dir)
            WORK_DIR="$2"
            shift 2
            ;;
        --heimdall-metrics)
            EMIT_HEIMDALL_METRICS="1"
            shift
            ;;
        --keep-going)
            KEEP_GOING="1"
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [[ -z "$WORK_DIR" ]]; then
    WORK_DIR="/tmp/quicast-stress-$(date '+%Y%m%d-%H%M%S')"
fi

mkdir -p "$WORK_DIR"

if [[ -z "$MULTICAST_SOURCE" ]]; then
    MULTICAST_SOURCE="$MULTICAST_INTERFACE"
fi

if [[ -z "$FILE_PATH" ]]; then
    FILE_PATH="$WORK_DIR/payload.bin"
    generate_file "$FILE_PATH" "$GENERATE_FILE_MB"
fi

if [[ ! -f "$FILE_PATH" ]]; then
    echo "file does not exist: $FILE_PATH" >&2
    exit 1
fi

ACTIVE_CLIENTS=()
SERVER_PID=""
SERVER_LOG="$WORK_DIR/server.log"
SUCCESS_COUNT=0
FAILURE_COUNT=0
LAUNCHED_COUNT=0
STOP_REQUESTED=0
LAST_FAILURE_CLIENT=""
LAST_FAILURE_LOG=""

trap cleanup EXIT INT TERM

log "work directory: $WORK_DIR"
log "building multicast file examples"
cargo build -p tokio-quiche \
    --example async_multicast_file_server \
    --example async_multicast_file_client \
    --features multicast

SERVER_BIN="$REPO_ROOT/target/debug/examples/async_multicast_file_server"
CLIENT_BIN="$REPO_ROOT/target/debug/examples/async_multicast_file_client"

log "starting server"
RUST_LOG="$RUST_LOG_VALUE" "$SERVER_BIN" \
    --address "$ADDRESS" \
    --file "$FILE_PATH" \
    --multicast-source "$MULTICAST_SOURCE" \
    --multicast-interface "$MULTICAST_INTERFACE" \
    --multicast-group "$MULTICAST_GROUP" \
    --multicast-port "$MULTICAST_PORT" \
    --chunk-payload-bytes "$CHUNK_PAYLOAD_BYTES" \
    --manifest-interval-packets "$MANIFEST_INTERVAL_PACKETS" \
    --publish-interval-ms "$PUBLISH_INTERVAL_MS" \
    --metrics-interval-secs "$SERVER_METRICS_INTERVAL_SECS" \
    >"$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

sleep 2
check_server_alive

while [[ "$STOP_REQUESTED" -eq 0 ]]; do
    if [[ "$MAX_CLIENTS" -gt 0 ]] && [[ "$LAUNCHED_COUNT" -ge "$MAX_CLIENTS" ]]; then
        break
    fi

    check_server_alive

    client_id=$((LAUNCHED_COUNT + 1))
    client_dir="$(client_dir_for "$client_id")"
    client_log="$(log_path_for "$client_id")"
    client_output="$(output_path_for "$client_id")"

    mkdir -p "$client_dir"

    client_cmd=(
        "$CLIENT_BIN"
        --connect-to "$ADDRESS"
        --multicast-interface "$MULTICAST_INTERFACE"
        --output "$client_output"
        --metrics-interval-secs "$CLIENT_METRICS_INTERVAL_SECS"
        --max-run-secs "$CLIENT_MAX_RUN_SECS"
    )

    if [[ "$EMIT_HEIMDALL_METRICS" -eq 1 ]]; then
        client_cmd+=(
            --heimdall-metrics-jsonl "$(metrics_path_for "$client_id")"
        )
    fi

    RUST_LOG="$RUST_LOG_VALUE" "${client_cmd[@]}" >"$client_log" 2>&1 &
    client_pid="$!"
    ACTIVE_CLIENTS+=("${client_id}:${client_pid}")
    LAUNCHED_COUNT="$client_id"

    log "started client $client_id pid=$client_pid"

    sleep "$CLIENT_INTERVAL_SECS"
    reap_finished_clients
done

while has_active_clients && [[ "$STOP_REQUESTED" -eq 0 ]]; do
    check_server_alive
    sleep 1
    reap_finished_clients
done

log "summary: launched=$LAUNCHED_COUNT ok=$SUCCESS_COUNT failed=$FAILURE_COUNT"

if [[ -n "$LAST_FAILURE_CLIENT" ]]; then
    log "first failing client: $LAST_FAILURE_CLIENT"
    log "failing log: $LAST_FAILURE_LOG"
fi

if [[ "$FAILURE_COUNT" -gt 0 ]]; then
    exit 1
fi
