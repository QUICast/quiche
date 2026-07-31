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

//! Multicast client/server integration for tokio-quiche.
//!
//! This module keeps multicast socket ownership outside core [`quiche`] while
//! still integrating with the multicast draft's unicast control plane. It is
//! currently IPv4-only on the multicast data path and emits explicit
//! placeholders for IPv6-specific behavior.

mod bounded_queue;
mod client;
mod event_stream;
mod runtime;
mod server;
mod server_control;
mod server_publish;
mod server_stream;

pub use bounded_queue::RetainedQueueConfigError;
pub use bounded_queue::RetainedQueueLimits;
pub use bounded_queue::RetainedQueueStats;
pub use client::ClientChannelMetricsSnapshot;
pub use client::ClientController;
pub use client::ClientDriver;
pub use client::ClientEvent;
pub use event_stream::ClientEventStream;
pub use event_stream::EventQueueConfigError;
pub use event_stream::EventQueueLimits;
pub use event_stream::EventQueueStats;
pub use event_stream::EventStreamTerminal;
pub use event_stream::EventStreamTerminalReason;
pub use event_stream::ServerEventStream;
pub use runtime::ClientRuntimeQueueStats;
pub use runtime::ControllerSendError;
pub use runtime::ControllerSendErrorKind;
pub use runtime::RuntimeLimits;
pub use runtime::RuntimeLimitsError;
pub use runtime::ServerChannelPacket;
pub use runtime::ServerChannelSendError;
pub use runtime::ServerRuntimeQueueStats;
pub use server::ServerChannelConfig;
pub use server::ServerControlChannelConfig;
pub use server::ServerControlMode;
pub use server::ServerControlSettings;
pub use server::ServerEvent;
pub use server::ServerSettings;
pub use server::StreamIntegrityBatchingSettings;
pub use server_control::ServerControlController;
pub use server_control::ServerControlDriver;
pub use server_publish::ServerController;
pub use server_publish::ServerDriver;
pub use server_stream::ServerStreamAttachment;
pub use server_stream::ServerStreamFrame;
pub use server_stream::ServerStreamPublication;
pub use server_stream::ServerStreamPublisher;
pub use server_stream::ServerStreamPublisherError;
pub use server_stream::ServerStreamPublisherLimits;

#[cfg(test)]
use client::Channel;
#[cfg(test)]
use client::ClientControlFrame;
#[cfg(test)]
use client::ClientRuntime;
#[cfg(test)]
use client::IngressEvent;
#[cfg(test)]
use client::JoinBackend;
#[cfg(test)]
use client::JoinError;
#[cfg(test)]
use client::PendingClientControl;
#[cfg(test)]
use client::PendingLeave;

pub use crate::settings::MulticastClientSettings as ClientSettings;

#[cfg(test)]
use self::runtime::MIN_INGRESS_NOTIFICATION_RETAINED_BYTES;
#[cfg(test)]
use self::runtime::STATE_REASON_LIMIT_VIOLATED;
#[cfg(test)]
use self::runtime::STATE_REASON_PROTOCOL_ERROR;
#[cfg(test)]
use self::runtime::STATE_REASON_UNSPECIFIED_OTHER;
#[cfg(test)]
use self::runtime::STATE_REASON_UNSYNCHRONIZED_PROPERTIES;

#[cfg(test)]
mod tests;
