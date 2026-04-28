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
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mcrx_core::HardwareMetricsSampler;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mcrx_core::HardwareMetricsSnapshot;
use mcrx_core::SubscriptionMetricsDelta;
use mcrx_core::SubscriptionMetricsSampler;
use mcrx_core::SubscriptionMetricsSnapshot;
use tokio_quiche::multicast::ClientChannelMetricsSnapshot;

pub struct ReceiverMetricSample {
    pub socket: SubscriptionMetricsSnapshot,
    pub socket_delta: SubscriptionMetricsDelta,
    pub receive: quiche::multicast::ChannelReceiveMetricsSnapshot,
    pub receive_delta: quiche::multicast::ChannelReceiveMetricsDelta,
    pub decode_errors: u64,
    pub receive_task_errors: u64,
}

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
    hardware_path: Option<PathBuf>,
    quiche_path: PathBuf,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    hardware_sampler: Option<HardwareMetricsSampler>,
}

impl HeimdallMetricsWriter {
    pub fn new(network_path: PathBuf) -> anyhow::Result<Self> {
        truncate_file(&network_path)?;
        let quiche_path = quiche_summary_file_path(&network_path);
        truncate_file(&quiche_path)?;

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let (hardware_path, hardware_sampler) = {
            let hardware_path = hardware_summary_file_path(&network_path);
            truncate_file(&hardware_path)?;

            let mut hardware_sampler = HardwareMetricsSampler::new();
            let initial = HardwareMetricsSnapshot::capture_current_process()
                .context("failed to capture initial hardware metrics")?;
            let _ = hardware_sampler.sample(initial);

            (Some(hardware_path), Some(hardware_sampler))
        };

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let hardware_path = None;

        Ok(Self {
            network_path,
            hardware_path,
            quiche_path,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            hardware_sampler,
        })
    }

    pub fn network_path(&self) -> &Path {
        &self.network_path
    }

    pub fn hardware_path(&self) -> Option<&Path> {
        self.hardware_path.as_deref()
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

        let line = format!(
            concat!(
                "{{",
                "\"ts\":{},",
                "\"interval_secs\":{},",
                "\"active_subscriptions\":1,",
                "\"joined_subscriptions\":1,",
                "\"packets_received\":{},",
                "\"bytes_received\":{},",
                "\"would_block_count\":{},",
                "\"receive_errors\":{},",
                "\"join_count\":{},",
                "\"leave_count\":{},",
                "\"batch_calls\":0,",
                "\"batch_packets_received\":0,",
                "\"packets_per_sec\":{},",
                "\"bytes_per_sec\":{},",
                "\"would_block_per_sec\":{},",
                "\"receive_errors_per_sec\":{}",
                "}}\n"
            ),
            timestamp_secs,
            sample.socket_delta.interval_secs,
            sample.socket_delta.packets_received,
            sample.socket_delta.bytes_received,
            sample.socket_delta.would_block_count,
            sample.socket_delta.receive_errors,
            sample.socket_delta.join_count,
            sample.socket_delta.leave_count,
            sample.socket_delta.packets_per_sec(),
            sample.socket_delta.bytes_per_sec(),
            sample.socket_delta.would_block_per_sec(),
            sample.socket_delta.receive_errors_per_sec(),
        );

        let quiche_line = format!(
            concat!(
                "{{",
                "\"ts\":{},",
                "\"interval_secs\":{},",
                "\"channel_id\":\"{}\",",
                "\"quiche_recv_calls\":{},",
                "\"quiche_recv_bytes\":{},",
                "\"quiche_recv_packets_per_sec\":{},",
                "\"quiche_recv_bytes_per_sec\":{},",
                "\"quiche_packets_delivered\":{},",
                "\"quiche_packets_released_on_recv\":{},",
                "\"quiche_packets_released_on_key\":{},",
                "\"quiche_packets_released_on_integrity\":{},",
                "\"quiche_pending_packets\":{},",
                "\"quiche_waiting_for_key_packets\":{},",
                "\"quiche_waiting_for_integrity_packets\":{},",
                "\"quiche_duplicate_packets\":{},",
                "\"quiche_invalid_packet_errors\":{},",
                "\"quiche_invalid_frame_errors\":{},",
                "\"quiche_integrity_mismatch_errors\":{},",
                "\"quiche_decrypt_errors\":{},",
                "\"quiche_keys_received\":{},",
                "\"quiche_integrity_frames_received\":{},",
                "\"quiche_decode_errors\":{},",
                "\"quiche_task_receive_errors\":{},",
                "\"quiche_largest_observed_packet_number\":{}",
                "}}\n"
            ),
            timestamp_secs,
            sample.socket_delta.interval_secs,
            channel_id,
            sample.receive_delta.recv_calls,
            sample.receive_delta.recv_bytes,
            if sample.socket_delta.interval_secs > 0.0 {
                sample.receive_delta.recv_calls as f64 /
                    sample.socket_delta.interval_secs
            } else {
                0.0
            },
            quiche_rx_bytes_per_sec,
            sample.receive_delta.packets_delivered,
            sample.receive_delta.packets_released_on_recv,
            sample.receive_delta.packets_released_on_key,
            sample.receive_delta.packets_released_on_integrity,
            sample.receive.pending_packets,
            sample.receive.waiting_for_key_packets,
            sample.receive.waiting_for_integrity_packets,
            sample.receive_delta.duplicate_packets,
            sample.receive_delta.invalid_packet_errors,
            sample.receive_delta.invalid_frame_errors,
            sample.receive_delta.integrity_mismatch_errors,
            sample.receive_delta.decrypt_errors,
            sample.receive_delta.keys_received,
            sample.receive_delta.integrity_frames_received,
            sample.decode_errors,
            sample.receive_task_errors,
            sample.receive.largest_observed_packet_number,
        );

        append_line(&self.network_path, &line)?;
        append_line(&self.quiche_path, &quiche_line)?;
        self.write_hardware_sample()?;

        Ok(())
    }

    fn write_hardware_sample(&mut self) -> anyhow::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let Some(hardware_path) = self.hardware_path.as_ref() else {
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

            let line = format!(
                concat!(
                    "{{",
                    "\"ts\":{},",
                    "\"interval_secs\":{},",
                    "\"cpu_user_secs\":{},",
                    "\"cpu_system_secs\":{},",
                    "\"cpu_total_secs\":{},",
                    "\"cpu_util_percent\":{},",
                    "\"rss_bytes\":{},",
                    "\"virtual_memory_bytes\":{},",
                    "\"thread_count\":{},",
                    "\"open_fds\":{},",
                    "\"page_faults_minor\":{},",
                    "\"page_faults_major\":{},",
                    "\"ctx_switches_voluntary\":{},",
                    "\"ctx_switches_involuntary\":{}",
                    "}}\n"
                ),
                timestamp_secs,
                delta.interval_secs,
                delta.cpu_user_secs,
                delta.cpu_system_secs,
                delta.cpu_total_secs,
                delta.cpu_util_percent,
                delta.rss_bytes,
                delta.virtual_memory_bytes,
                delta.thread_count,
                delta.open_fds,
                delta.page_faults_minor,
                delta.page_faults_major,
                delta.ctx_switches_voluntary,
                delta.ctx_switches_involuntary,
            );

            append_line(hardware_path, &line)?;
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

fn append_line(path: &Path, line: &str) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
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
}
