// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::fs::OpenOptions;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
use mcrx_core::jsonl::append_jsonl_sample_row;
use mcrx_core::jsonl::ensure_single_header;
use mcrx_core::jsonl::header_json;
use mcrx_core::jsonl::infer_node_id_from_path;
use mcrx_core::jsonl::HARDWARE_ARTIFACT_TYPE;
#[cfg(test)]
use mcrx_core::jsonl::HEIMDALL_JSONL_SCHEMA;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mcrx_core::HardwareMetricsSampler;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mcrx_core::HardwareMetricsSnapshot;
use mcrx_core::SubscriptionMetricsDelta;
use mcrx_core::SubscriptionMetricsSampler;
use mcrx_core::SubscriptionMetricsSnapshot;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;
use tokio_quiche::multicast::ClientChannelMetricsSnapshot;

pub struct ReceiverMetricSample {
    pub socket: SubscriptionMetricsSnapshot,
    pub socket_delta: SubscriptionMetricsDelta,
    pub receive: quiche::multicast::ChannelReceiveMetricsSnapshot,
    pub receive_delta: quiche::multicast::ChannelReceiveMetricsDelta,
    pub decode_errors: u64,
    pub receive_task_errors: u64,
}

#[derive(Clone, Debug)]
pub struct HeimdallJsonlMetadata {
    pub node_id: Option<String>,
    pub producer: &'static str,
    pub transport: String,
    pub role: String,
    pub connect_to: String,
    pub multicast_interface: Option<String>,
    pub integrity_hash_algorithm: String,
    pub integrity_hash_algorithm_id: u16,
    pub integrity_hashes_per_frame: usize,
    pub max_joined_channels: u64,
    pub max_aggregate_rate_kibps: u64,
    pub max_channel_ids: u64,
}

const MCRX_NETWORK_ARTIFACT_TYPE: &str = "mcrx-network";
const QUICHE_RECEIVE_ARTIFACT_TYPE: &str = "quiche-receive";

#[allow(dead_code)]
fn main() {}

pub fn sample_receiver_metrics(
    metrics: &ClientChannelMetricsSnapshot,
    previous_socket_metrics: &mut SubscriptionMetricsSampler,
    previous_receive_metrics: &mut Option<
        quiche::multicast::ChannelReceiveMetricsSnapshot,
    >,
    decode_errors: u64, receive_task_errors: u64,
) -> Option<ReceiverMetricSample> {
    let socket_delta = previous_socket_metrics.sample(metrics.socket.clone())?;
    let previous_receive = previous_receive_metrics.replace(metrics.receive)?;
    let receive_delta = quiche::multicast::ChannelReceiveMetricsDelta::between(
        previous_receive,
        metrics.receive,
    );
    *previous_receive_metrics = Some(metrics.receive);

    Some(ReceiverMetricSample {
        socket: metrics.socket.clone(),
        socket_delta,
        receive: metrics.receive,
        receive_delta,
        decode_errors,
        receive_task_errors,
    })
}

pub struct HeimdallMetricsWriter {
    network_path: PathBuf,
    hardware_path: Option<(PathBuf, Value)>,
    quiche_path: PathBuf,
    network_header: Value,
    quiche_header: Value,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    hardware_sampler: Option<HardwareMetricsSampler>,
}

impl HeimdallJsonlMetadata {
    fn flags_json(&self) -> Map<String, Value> {
        let mut flags = Map::new();
        flags.insert("transport".to_string(), self.transport.clone().into());
        flags.insert("role".to_string(), self.role.clone().into());
        flags.insert("connect_to".to_string(), self.connect_to.clone().into());
        flags.insert(
            "multicast_interface".to_string(),
            self.multicast_interface.clone().into(),
        );
        flags.insert(
            "integrity_hash_algorithm".to_string(),
            self.integrity_hash_algorithm.clone().into(),
        );
        flags.insert(
            "integrity_hash_algorithm_id".to_string(),
            self.integrity_hash_algorithm_id.into(),
        );
        flags.insert(
            "integrity_hashes_per_frame".to_string(),
            self.integrity_hashes_per_frame.into(),
        );
        flags.insert(
            "max_joined_channels".to_string(),
            self.max_joined_channels.into(),
        );
        flags.insert(
            "max_aggregate_rate_kibps".to_string(),
            self.max_aggregate_rate_kibps.into(),
        );
        flags.insert("max_channel_ids".to_string(), self.max_channel_ids.into());
        flags
    }
}

impl HeimdallMetricsWriter {
    pub fn new(
        network_path: PathBuf, metadata: HeimdallJsonlMetadata,
    ) -> anyhow::Result<Self> {
        truncate_file(&network_path)?;
        let quiche_path = quiche_summary_file_path(&network_path);
        truncate_file(&quiche_path)?;
        let flags = metadata.flags_json();
        let node_id = metadata
            .node_id
            .unwrap_or_else(|| infer_node_id_from_path(&network_path));
        let network_header = header_json(
            MCRX_NETWORK_ARTIFACT_TYPE,
            metadata.producer,
            &node_id,
            SystemTime::now(),
            &flags,
        );
        ensure_single_header(&network_path, &network_header).with_context(
            || format!("failed to write {}", network_path.display()),
        )?;
        let quiche_header = header_json(
            QUICHE_RECEIVE_ARTIFACT_TYPE,
            metadata.producer,
            &node_id,
            SystemTime::now(),
            &flags,
        );
        ensure_single_header(&quiche_path, &quiche_header).with_context(
            || format!("failed to write {}", quiche_path.display()),
        )?;

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let (hardware_path, hardware_sampler) = {
            let hardware_path = hardware_summary_file_path(&network_path);
            truncate_file(&hardware_path)?;
            let hardware_header = header_json(
                HARDWARE_ARTIFACT_TYPE,
                metadata.producer,
                &node_id,
                SystemTime::now(),
                &flags,
            );
            ensure_single_header(&hardware_path, &hardware_header).with_context(
                || format!("failed to write {}", hardware_path.display()),
            )?;

            let mut hardware_sampler = HardwareMetricsSampler::new();
            let initial = HardwareMetricsSnapshot::capture_current_process()
                .context("failed to capture initial hardware metrics")?;
            let _ = hardware_sampler.sample(initial);

            (
                Some((hardware_path, hardware_header)),
                Some(hardware_sampler),
            )
        };

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let hardware_path = None;

        Ok(Self {
            network_path,
            hardware_path,
            quiche_path,
            network_header,
            quiche_header,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            hardware_sampler,
        })
    }

    pub fn network_path(&self) -> &Path {
        &self.network_path
    }

    pub fn hardware_path(&self) -> Option<&Path> {
        self.hardware_path.as_ref().map(|(path, _)| path.as_path())
    }

    pub fn quiche_path(&self) -> &Path {
        &self.quiche_path
    }

    pub fn write_receiver_sample(
        &mut self, channel_id: &[u8], sample: &ReceiverMetricSample,
    ) -> anyhow::Result<()> {
        let channel_id = format_channel_id(channel_id);
        let timestamp_secs = unix_timestamp_secs(sample.socket.captured_at);
        let quiche_rx_bytes_per_sec = if sample.socket_delta.interval_secs > 0.0 {
            sample.receive_delta.recv_bytes as f64 /
                sample.socket_delta.interval_secs
        } else {
            0.0
        };

        let line = json!({
            "ts": timestamp_secs,
            "interval_secs": sample.socket_delta.interval_secs,
            "active_subscriptions": 1,
            "joined_subscriptions": 1,
            "packets_received": sample.socket_delta.packets_received,
            "bytes_received": sample.socket_delta.bytes_received,
            "would_block_count": sample.socket_delta.would_block_count,
            "receive_errors": sample.socket_delta.receive_errors,
            "join_count": sample.socket_delta.join_count,
            "leave_count": sample.socket_delta.leave_count,
            "batch_calls": 0,
            "batch_packets_received": 0,
            "packets_per_sec": sample.socket_delta.packets_per_sec(),
            "bytes_per_sec": sample.socket_delta.bytes_per_sec(),
            "would_block_per_sec": sample.socket_delta.would_block_per_sec(),
            "receive_errors_per_sec": sample.socket_delta.receive_errors_per_sec(),
        });

        let quiche_line = json!({
            "ts": timestamp_secs,
            "interval_secs": sample.socket_delta.interval_secs,
            "channel_id": channel_id,
            "quiche_recv_calls": sample.receive_delta.recv_calls,
            "quiche_recv_bytes": sample.receive_delta.recv_bytes,
            "quiche_recv_packets_per_sec": if sample.socket_delta.interval_secs > 0.0 {
                sample.receive_delta.recv_calls as f64 /
                    sample.socket_delta.interval_secs
            } else {
                0.0
            },
            "quiche_recv_bytes_per_sec": quiche_rx_bytes_per_sec,
            "quiche_packets_delivered": sample.receive_delta.packets_delivered,
            "quiche_packets_released_on_recv": sample.receive_delta.packets_released_on_recv,
            "quiche_packets_released_on_key": sample.receive_delta.packets_released_on_key,
            "quiche_packets_released_on_integrity": sample.receive_delta.packets_released_on_integrity,
            "quiche_pending_packets": sample.receive.pending_packets,
            "quiche_waiting_for_key_packets": sample.receive.waiting_for_key_packets,
            "quiche_waiting_for_integrity_packets": sample.receive.waiting_for_integrity_packets,
            "quiche_duplicate_packets": sample.receive_delta.duplicate_packets,
            "quiche_invalid_packet_errors": sample.receive_delta.invalid_packet_errors,
            "quiche_invalid_frame_errors": sample.receive_delta.invalid_frame_errors,
            "quiche_integrity_mismatch_errors": sample.receive_delta.integrity_mismatch_errors,
            "quiche_decrypt_errors": sample.receive_delta.decrypt_errors,
            "quiche_keys_received": sample.receive_delta.keys_received,
            "quiche_integrity_frames_received": sample.receive_delta.integrity_frames_received,
            "quiche_decode_errors": sample.decode_errors,
            "quiche_task_receive_errors": sample.receive_task_errors,
            "quiche_largest_observed_packet_number": sample.receive.largest_observed_packet_number,
        });

        append_jsonl_sample_row(&self.network_path, &self.network_header, &line)
            .with_context(|| {
                format!("failed to write {}", self.network_path.display())
            })?;
        append_jsonl_sample_row(
            &self.quiche_path,
            &self.quiche_header,
            &quiche_line,
        )
        .with_context(|| {
            format!("failed to write {}", self.quiche_path.display())
        })?;
        self.write_hardware_sample()?;

        Ok(())
    }

    fn write_hardware_sample(&mut self) -> anyhow::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let Some((hardware_path, hardware_header)) =
                self.hardware_path.as_ref()
            else {
                return Ok(());
            };
            let Some(hardware_sampler) = self.hardware_sampler.as_mut() else {
                return Ok(());
            };

            let snapshot = HardwareMetricsSnapshot::capture_current_process()
                .context("failed to capture hardware metrics")?;
            let timestamp_secs = unix_timestamp_secs(snapshot.captured_at);
            let Some(delta) = hardware_sampler.sample(snapshot) else {
                return Ok(());
            };

            let line = json!({
                "ts": timestamp_secs,
                "interval_secs": delta.interval_secs,
                "cpu_user_secs": delta.cpu_user_secs,
                "cpu_system_secs": delta.cpu_system_secs,
                "cpu_total_secs": delta.cpu_total_secs,
                "cpu_util_percent": delta.cpu_util_percent,
                "rss_bytes": delta.rss_bytes,
                "virtual_memory_bytes": delta.virtual_memory_bytes,
                "thread_count": delta.thread_count,
                "open_fds": delta.open_fds,
                "page_faults_minor": delta.page_faults_minor,
                "page_faults_major": delta.page_faults_major,
                "ctx_switches_voluntary": delta.ctx_switches_voluntary,
                "ctx_switches_involuntary": delta.ctx_switches_involuntary,
            });

            append_jsonl_sample_row(hardware_path, hardware_header, &line)
                .with_context(|| {
                    format!("failed to write {}", hardware_path.display())
                })?;
        }

        Ok(())
    }
}

fn hardware_summary_file_path(network_path: &Path) -> PathBuf {
    sibling_summary_file_path(network_path, "hardware")
}

fn quiche_summary_file_path(network_path: &Path) -> PathBuf {
    sibling_summary_file_path(network_path, "quiche")
}

fn sibling_summary_file_path(network_path: &Path, suffix: &str) -> PathBuf {
    let parent = network_path.parent().map(PathBuf::from).unwrap_or_default();
    let stem = network_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("metrics");
    let extension = network_path.extension().and_then(|ext| ext.to_str());

    let file_name = match extension {
        Some(ext) if !ext.is_empty() => format!("{stem}_{suffix}.{ext}"),
        _ => format!("{stem}_{suffix}"),
    };

    parent.join(file_name)
}

fn unix_timestamp_secs(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn truncate_file(path: &Path) -> anyhow::Result<()> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    Ok(())
}

fn format_channel_id(id: &[u8]) -> String {
    let mut out = String::with_capacity(id.len() * 2);
    for byte in id {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use serde_json::Value;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct HeimdallJsonlHeader {
        artifact_type: String,
        node_id: String,
        producer: String,
    }

    fn parse_required_header(
        value: &Value,
    ) -> anyhow::Result<HeimdallJsonlHeader> {
        let schema = value
            .get("schema")
            .and_then(Value::as_str)
            .context("missing `schema` in Heimdall JSONL header")?;

        if schema != HEIMDALL_JSONL_SCHEMA {
            anyhow::bail!("unsupported Heimdall JSONL schema `{schema}`");
        }

        let artifact_type = value
            .get("artifact_type")
            .and_then(Value::as_str)
            .context("missing `artifact_type` in Heimdall JSONL header")?;
        let node_id = value
            .get("node_id")
            .and_then(Value::as_str)
            .context("missing `node_id` in Heimdall JSONL header")?;
        let producer = value
            .get("producer")
            .and_then(Value::as_str)
            .context("missing `producer` in Heimdall JSONL header")?;

        Ok(HeimdallJsonlHeader {
            artifact_type: artifact_type.to_string(),
            node_id: node_id.to_string(),
            producer: producer.to_string(),
        })
    }

    fn validate_heimdall_jsonl_file(
        path: &Path,
    ) -> anyhow::Result<HeimdallJsonlHeader> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let first_line = loop {
            let Some(line) = lines.next() else {
                anyhow::bail!("{} is empty", path.display());
            };

            let line = line
                .with_context(|| format!("failed to read {}", path.display()))?;

            if !line.trim().is_empty() {
                break line;
            }
        };

        let first_value: Value =
            serde_json::from_str(&first_line).with_context(|| {
                format!(
                    "failed to decode Heimdall JSONL header from {}",
                    path.display()
                )
            })?;
        let header = parse_required_header(&first_value)?;

        for (index, line) in lines.enumerate() {
            let line = line
                .with_context(|| format!("failed to read {}", path.display()))?;

            if line.trim().is_empty() {
                continue;
            }

            let value: Value =
                serde_json::from_str(&line).with_context(|| {
                    format!(
                        "failed to decode Heimdall JSONL sample from {} line {}",
                        path.display(),
                        index + 2
                    )
                })?;

            if value.get("schema").is_some() {
                anyhow::bail!(
                    "{} contains an unexpected additional header at line {}",
                    path.display(),
                    index + 2
                );
            }
        }

        Ok(header)
    }

    fn temp_jsonl_path(name: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("quiche-heimdall-jsonl-{name}-{id}.jsonl"))
    }

    fn write_test_lines(path: &Path, lines: &[&str]) {
        let body = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };

        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn hardware_path_keeps_extension() {
        let path = PathBuf::from("/tmp/metrics.jsonl");
        assert_eq!(
            hardware_summary_file_path(&path),
            PathBuf::from("/tmp/metrics_hardware.jsonl"),
        );
    }

    #[test]
    fn hardware_path_handles_missing_extension() {
        let path = PathBuf::from("/tmp/metrics");
        assert_eq!(
            hardware_summary_file_path(&path),
            PathBuf::from("/tmp/metrics_hardware"),
        );
    }

    #[test]
    fn quiche_path_keeps_extension() {
        let path = PathBuf::from("/tmp/metrics.jsonl");
        assert_eq!(
            quiche_summary_file_path(&path),
            PathBuf::from("/tmp/metrics_quiche.jsonl"),
        );
    }

    #[test]
    fn quiche_path_handles_missing_extension() {
        let path = PathBuf::from("/tmp/metrics");
        assert_eq!(
            quiche_summary_file_path(&path),
            PathBuf::from("/tmp/metrics_quiche"),
        );
    }

    #[test]
    fn infer_node_id_prefers_parent_directory() {
        let path = PathBuf::from("/tmp/run-a/client-0007/network.jsonl");
        assert_eq!(infer_node_id_from_path(&path), "client-0007");
    }

    #[test]
    fn infer_node_id_falls_back_to_stem() {
        let path = PathBuf::from("receiver-a.jsonl");
        assert_eq!(infer_node_id_from_path(&path), "receiver-a");
    }

    #[test]
    fn header_uses_schema_marker_without_record_type() {
        let flags = HeimdallJsonlMetadata {
            node_id: None,
            producer: "tokio-quiche/async_multicast_file_client",
            transport: "quic-multicast-draft-08".to_string(),
            role: "receiver".to_string(),
            connect_to: "127.0.0.1:5757".to_string(),
            multicast_interface: Some("127.0.0.1".to_string()),
            integrity_hash_algorithm: "sha256-32".to_string(),
            integrity_hash_algorithm_id: 1,
            integrity_hashes_per_frame: 32,
            max_joined_channels: 4,
            max_aggregate_rate_kibps: 8192,
            max_channel_ids: 16,
        }
        .flags_json();
        let header = header_json(
            MCRX_NETWORK_ARTIFACT_TYPE,
            "tokio-quiche/async_multicast_file_client",
            "client-0001",
            UNIX_EPOCH,
            &flags,
        );

        assert_eq!(header["schema"], HEIMDALL_JSONL_SCHEMA);
        assert_eq!(header["artifact_type"], MCRX_NETWORK_ARTIFACT_TYPE);
        assert_eq!(header["node_id"], "client-0001");
        assert!(header.get("record_type").is_none());
    }

    #[test]
    fn validate_jsonl_accepts_single_header_followed_by_samples() {
        let path = temp_jsonl_path("valid");
        write_test_lines(&path, &[
            r#"{"schema":"heimdall-jsonl-v1","artifact_type":"mcrx-network","node_id":"client-0001","producer":"tokio-quiche/test","created_at":0,"flags":{"role":"receiver"}}"#,
            r#"{"ts":1.0,"interval_secs":1.0,"packets_received":10}"#,
            r#"{"ts":2.0,"interval_secs":1.0,"packets_received":11}"#,
        ]);

        let header = validate_heimdall_jsonl_file(&path).unwrap();
        assert_eq!(header.artifact_type, "mcrx-network");
        assert_eq!(header.node_id, "client-0001");
        assert_eq!(header.producer, "tokio-quiche/test");

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn validate_jsonl_rejects_missing_header() {
        let path = temp_jsonl_path("missing-header");
        write_test_lines(&path, &[
            r#"{"ts":1.0,"interval_secs":1.0,"packets_received":10}"#,
        ]);

        let error = validate_heimdall_jsonl_file(&path).unwrap_err();
        assert!(error
            .to_string()
            .contains("missing `schema` in Heimdall JSONL header"));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn validate_jsonl_rejects_multiple_headers() {
        let path = temp_jsonl_path("multiple-headers");
        write_test_lines(&path, &[
            r#"{"schema":"heimdall-jsonl-v1","artifact_type":"mcrx-network","node_id":"client-0001","producer":"tokio-quiche/test","created_at":0,"flags":{"role":"receiver"}}"#,
            r#"{"ts":1.0,"interval_secs":1.0,"packets_received":10}"#,
            r#"{"schema":"heimdall-jsonl-v1","artifact_type":"mcrx-network","node_id":"client-0002","producer":"tokio-quiche/test","created_at":0,"flags":{"role":"receiver"}}"#,
        ]);

        let error = validate_heimdall_jsonl_file(&path).unwrap_err();
        assert!(error.to_string().contains("unexpected additional header"));

        std::fs::remove_file(path).unwrap();
    }
}
