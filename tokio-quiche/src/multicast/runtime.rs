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

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;
use std::time::Duration;

use tokio::time::Instant;

use super::bounded_queue::QueueSendError;
use super::bounded_queue::RetainedQueueConfigError;
use super::bounded_queue::RetainedQueueLimits;
use super::bounded_queue::RetainedQueueStats;
use super::event_stream::EventQueueConfigError;
use super::event_stream::EventQueueLimits;
use super::ClientSettings;

pub(super) const STATE_REASON_UNSPECIFIED_OTHER: u64 = 0x0;
pub(super) const STATE_REASON_PROTOCOL_ERROR: u64 = 0x3;
pub(super) const STATE_REASON_UNSYNCHRONIZED_PROPERTIES: u64 = 0x5;
pub(super) const STATE_REASON_LIMIT_VIOLATED: u64 = 0x16;
const SERVER_ACK_FRESHNESS_TIMEOUT_MULTIPLIER: u64 = 4;
pub(super) const PUBLISH_RETRY_DELAY: Duration = Duration::from_millis(10);
pub(super) const MIN_INGRESS_NOTIFICATION_RETAINED_BYTES: usize = 64;

pub(super) fn fair_ready_channel_ids<T>(
    channels: &BTreeMap<Vec<u8>, T>, cursor: Option<&[u8]>, limit: usize,
    mut ready: impl FnMut(&T) -> bool,
) -> Vec<Vec<u8>> {
    if limit == 0 {
        return Vec::new();
    }

    let mut selected = Vec::with_capacity(limit.min(channels.len()));

    if let Some(cursor) = cursor {
        for (channel_id, channel) in
            channels.range((Bound::Excluded(cursor.to_vec()), Bound::Unbounded))
        {
            if ready(channel) {
                selected.push(channel_id.clone());
            }
            if selected.len() == limit {
                return selected;
            }
        }
        for (channel_id, channel) in channels.range(..=cursor.to_vec()) {
            if ready(channel) {
                selected.push(channel_id.clone());
            }
            if selected.len() == limit {
                break;
            }
        }
    } else {
        for (channel_id, channel) in channels {
            if ready(channel) {
                selected.push(channel_id.clone());
            }
            if selected.len() == limit {
                break;
            }
        }
    }

    selected
}

pub(super) fn run_callback_work<E>(
    max_work: usize, cursor: &mut usize, class_count: usize,
    mut process_one: impl FnMut(usize) -> Result<bool, E>,
) -> Result<usize, E> {
    debug_assert!(class_count > 0);
    let mut work = 0;

    while work < max_work {
        let mut progressed = false;

        for _ in 0..class_count {
            let class = *cursor % class_count;
            *cursor = (class + 1) % class_count;

            if process_one(class)? {
                work += 1;
                progressed = true;
                break;
            }
        }

        if !progressed {
            break;
        }
    }

    Ok(work)
}

pub(super) fn validate_client_settings(
    settings: &ClientSettings,
) -> quiche::Result<()> {
    settings.transport_params.encoded_len()?;
    quiche::multicast::Frame::Limits(quiche::multicast::Limits {
        sequence: 0,
        limits: settings.transport_params.limits.clone(),
        max_joined_count: settings.max_joined_channels,
    })
    .encoded_len()
    .map(|_| ())
}

pub(super) fn validate_server_announce(
    announce: &quiche::multicast::Announce,
) -> quiche::Result<()> {
    announce.validate()?;
    std::time::Instant::now()
        .checked_add(server_ack_freshness_timeout(announce.max_ack_delay_ms))
        .ok_or(quiche::Error::InvalidState)?;

    Ok(())
}

pub(super) fn server_ack_freshness_timeout(max_ack_delay_ms: u64) -> Duration {
    Duration::from_millis(
        max_ack_delay_ms.saturating_mul(SERVER_ACK_FRESHNESS_TIMEOUT_MULTIPLIER),
    )
}

/// Owned controller-command admission failure.
///
/// The rejected input is retained so callers can retry transient saturation
/// without cloning a secret-bearing or potentially large value.
#[derive(Debug)]
pub struct ControllerSendError<T> {
    kind: ControllerSendErrorKind,
    value: Box<T>,
}

impl<T> ControllerSendError<T> {
    pub(super) fn invalid(value: T) -> Self {
        Self {
            kind: ControllerSendErrorKind::InvalidValue,
            value: Box::new(value),
        }
    }

    pub(super) fn from_queue(error: QueueSendError<T>) -> Self {
        match error {
            QueueSendError::Full(value) => Self {
                kind: ControllerSendErrorKind::Full,
                value: Box::new(value),
            },

            QueueSendError::Oversized(value) => Self {
                kind: ControllerSendErrorKind::Oversized,
                value: Box::new(value),
            },

            QueueSendError::Closed(value) => Self {
                kind: ControllerSendErrorKind::Closed,
                value: Box::new(value),
            },
        }
    }

    /// Returns the failure category.
    pub fn kind(&self) -> ControllerSendErrorKind {
        self.kind
    }

    /// Returns the value that was not admitted.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Recovers ownership of the value that was not admitted.
    pub fn into_inner(self) -> T {
        *self.value
    }
}

impl<T> fmt::Display for ControllerSendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "multicast controller send failed: {}", self.kind)
    }
}

impl<T: fmt::Debug> std::error::Error for ControllerSendError<T> {}

/// Category reported by [`ControllerSendError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerSendErrorKind {
    /// The bounded command queue is temporarily full.
    Full,

    /// The command can never fit the configured retained-byte limit.
    Oversized,

    /// The connection runtime no longer accepts commands.
    Closed,

    /// One or more command fields cannot be represented on the wire.
    InvalidValue,
}

impl fmt::Display for ControllerSendErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::Full => "queue full",
            Self::Oversized => "command oversized",
            Self::Closed => "runtime closed",
            Self::InvalidValue => "invalid command value",
        };
        f.write_str(description)
    }
}

/// Channel ID and channel frames recovered from a rejected server send.
pub type ServerChannelPacket = (Vec<u8>, Vec<quiche::multicast::ChannelFrame>);

/// Owned admission error returned by
/// [`ServerController::send_on_channel`](crate::multicast::ServerController::send_on_channel).
pub type ServerChannelSendError = ControllerSendError<ServerChannelPacket>;

/// Local resource and work limits for one Tokio multicast connection wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeLimits {
    /// Required event and coalesced metric retention limits.
    pub events: EventQueueLimits,

    /// Controller command limits, including commands staged by the runtime.
    pub commands: RetainedQueueLimits,

    /// Client multicast socket ingress limits.
    pub ingress: RetainedQueueLimits,

    /// Encoded or shared publications awaiting connection-local processing.
    pub pending_publications: RetainedQueueLimits,

    /// Integrity frames awaiting unicast control delivery.
    pub pending_integrity: RetainedQueueLimits,

    /// Aggregate multicast work units processed by one driver callback.
    ///
    /// One unit is one successful scheduled work-class operation: one control
    /// frame handled; one ingress, controller, publisher, publication,
    /// integrity, or pending-control item transferred or handled; one
    /// standalone indexed receive-maintenance operation; or one coalesced ACK,
    /// delivery-metric update, or probe event forwarded. Processing one ingress
    /// packet or receive-side control includes its single core receive
    /// admission and never opens a nested work budget. Queue readiness scans
    /// and class attempts that perform no mutation are not charged. All ready
    /// work classes are selected round-robin under this one budget.
    pub max_work_per_call: usize,

    /// Delay before retrying a control frame rejected by the core send queue.
    pub control_retry_delay: Duration,

    /// Maximum continuous control-queue saturation before failing explicitly.
    pub control_backpressure_timeout: Duration,

    /// Maximum connection-lifetime multicast Channel IDs retained by a
    /// runtime, including retired-ID tombstones.
    pub max_tracked_channel_ids: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            events: EventQueueLimits::default(),
            commands: RetainedQueueLimits {
                max_items: 4096,
                max_retained_bytes: 64 * 1024 * 1024,
            },
            ingress: RetainedQueueLimits {
                max_items: 4096,
                max_retained_bytes: 64 * 1024 * 1024,
            },
            pending_publications: RetainedQueueLimits {
                max_items: 4096,
                max_retained_bytes: 64 * 1024 * 1024,
            },
            pending_integrity: RetainedQueueLimits {
                max_items: 8192,
                max_retained_bytes: 8 * 1024 * 1024,
            },
            max_work_per_call: 256,
            control_retry_delay: Duration::from_millis(1),
            control_backpressure_timeout: Duration::from_secs(30),
            max_tracked_channel_ids: 1024,
        }
    }
}

impl RuntimeLimits {
    pub(super) fn validate(self) -> Result<Self, RuntimeLimitsError> {
        self.events.validate()?;
        self.commands.validate("multicast command")?;
        self.ingress.validate("multicast ingress")?;
        if self.ingress.max_retained_bytes <
            MIN_INGRESS_NOTIFICATION_RETAINED_BYTES
        {
            return Err(RuntimeLimitsError::IngressNotificationByteCapacity {
                minimum: MIN_INGRESS_NOTIFICATION_RETAINED_BYTES,
            });
        }
        self.pending_publications
            .validate("multicast pending publication")?;
        self.pending_integrity
            .validate("multicast pending integrity")?;
        if self.max_work_per_call == 0 {
            return Err(RuntimeLimitsError::ZeroWorkBudget);
        }
        if self.control_retry_delay.is_zero() {
            return Err(RuntimeLimitsError::ZeroControlRetryDelay);
        }
        if Instant::now()
            .checked_add(self.control_retry_delay)
            .is_none()
        {
            return Err(RuntimeLimitsError::UnrepresentableControlRetryDelay);
        }
        if self.control_backpressure_timeout.is_zero() {
            return Err(RuntimeLimitsError::ZeroControlBackpressureTimeout);
        }
        if Instant::now()
            .checked_add(self.control_backpressure_timeout)
            .is_none()
        {
            return Err(
                RuntimeLimitsError::UnrepresentableControlBackpressureTimeout,
            );
        }
        if self.max_tracked_channel_ids == 0 {
            return Err(RuntimeLimitsError::ZeroTrackedChannelIds);
        }

        Ok(self)
    }
}

/// Invalid Tokio multicast runtime limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeLimitsError {
    /// Event queue limits are invalid.
    #[error(transparent)]
    EventQueue(#[from] EventQueueConfigError),

    /// Another retained runtime queue has invalid limits.
    #[error(transparent)]
    RetainedQueue(#[from] RetainedQueueConfigError),

    /// Driver callbacks could never make queue progress.
    #[error("multicast runtime work budget must be greater than zero")]
    ZeroWorkBudget,

    /// Control queue retries could spin without yielding.
    #[error("multicast control retry delay must be greater than zero")]
    ZeroControlRetryDelay,

    /// The control retry deadline cannot be represented by Tokio's clock.
    #[error("multicast control retry delay cannot be represented")]
    UnrepresentableControlRetryDelay,

    /// Control queue saturation could never reach a terminal outcome.
    #[error("multicast control backpressure timeout must be greater than zero")]
    ZeroControlBackpressureTimeout,

    /// The control saturation deadline cannot be represented by Tokio's clock.
    #[error("multicast control backpressure timeout cannot be represented")]
    UnrepresentableControlBackpressureTimeout,

    /// No multicast Channel ID could ever be retained.
    #[error("multicast tracked Channel ID capacity must be greater than zero")]
    ZeroTrackedChannelIds,

    /// The ingress byte limit cannot retain a terminal overload notification.
    #[error("multicast ingress byte capacity must be at least {minimum} bytes")]
    IngressNotificationByteCapacity {
        /// Smallest safe retained-byte capacity.
        minimum: usize,
    },

    /// Multicast settings contain a value that cannot be encoded.
    #[error("invalid multicast settings: {0}")]
    InvalidMulticastSettings(quiche::Error),
}

/// Point-in-time retained queue counters for a multicast client runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientRuntimeQueueStats {
    /// Multicast socket ingress retained by tasks or runtime staging.
    pub ingress: RetainedQueueStats,

    /// Client control frames awaiting core QUIC queue admission.
    pub control: RetainedQueueStats,
}

/// Point-in-time retained queue counters for a multicast server runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerRuntimeQueueStats {
    /// Controller commands retained by the channel or runtime staging.
    pub commands: RetainedQueueStats,

    /// Connection-local publications awaiting recovery registration or send.
    pub pending_publications: RetainedQueueStats,

    /// Delayed and ready-to-send integrity frames.
    pub pending_integrity: RetainedQueueStats,
}
