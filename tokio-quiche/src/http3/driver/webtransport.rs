// Copyright (C) 2025, Cloudflare, Inc.
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
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use bytes::BufMut as _;
use bytes::Bytes;
use bytes::BytesMut;
use datagram_socket::DgramBuffer;
use quiche::h3::NameValue as _;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use super::WebTransportStreamDirection;
use crate::quic::QuicheConnection;

pub(crate) const WT_BUFFERED_STREAM_REJECTED: u64 = 0x3994_bd84;
pub(crate) const WT_SESSION_GONE: u64 = 0x170d_7b68;
pub(crate) const WT_CLOSE_SESSION: u64 = 0x2843;

pub(super) const MAX_CLOSE_MESSAGE_LEN: usize = 1024;
const MAX_CLOSE_CAPSULE_PAYLOAD_LEN: usize = 4 + MAX_CLOSE_MESSAGE_LEN;
const WT_APPLICATION_ERROR_FIRST: u64 = 0x52e4_a40f_a8db;
const WT_APPLICATION_ERROR_LAST: u64 = 0x52e5_ac98_3162;

/// Maps a 32-bit WebTransport application error to draft-16's HTTP/3 range.
pub const fn webtransport_error_to_http3(error_code: u32) -> u64 {
    let error_code = error_code as u64;
    WT_APPLICATION_ERROR_FIRST + error_code + error_code / 0x1e
}

/// Maps a draft-16 HTTP/3 WebTransport error to its application error.
///
/// Returns `None` for values outside the reserved range and for HTTP/3 grease
/// values skipped by the draft's mapping.
pub const fn webtransport_error_from_http3(error_code: u64) -> Option<u32> {
    if error_code < WT_APPLICATION_ERROR_FIRST ||
        error_code > WT_APPLICATION_ERROR_LAST ||
        error_code.wrapping_sub(0x21).is_multiple_of(0x1f)
    {
        return None;
    }

    let shifted = error_code - WT_APPLICATION_ERROR_FIRST;
    Some((shifted - shifted / 0x1f) as u32)
}

pub(crate) fn is_connect(headers: &[quiche::h3::Header]) -> bool {
    let mut method = None;
    let mut protocol = None;
    let mut scheme = None;
    let mut authority = None;
    let mut path = None;

    for header in headers {
        match header.name() {
            b":method" => method = Some(header.value()),
            b":protocol" => protocol = Some(header.value()),
            b":scheme" => scheme = Some(header.value()),
            b":authority" => authority = Some(header.value()),
            b":path" => path = Some(header.value()),
            _ => {},
        }
    }

    method == Some(b"CONNECT".as_slice()) &&
        protocol == Some(b"webtransport-h3".as_slice()) &&
        scheme == Some(b"https".as_slice()) &&
        authority.is_some_and(|value| !value.is_empty()) &&
        path.is_some_and(|value| !value.is_empty())
}

/// Why a WebTransport session reached its terminal state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebTransportSessionCloseReason {
    /// The CONNECT stream closed cleanly without a close capsule.
    Clean,
    /// The local application sent a close capsule.
    Local {
        /// Application-defined close code.
        error_code: u32,
        /// UTF-8 application close message.
        message: String,
    },
    /// The peer sent a close capsule.
    Peer {
        /// Application-defined close code.
        error_code: u32,
        /// UTF-8 application close message.
        message: String,
    },
    /// The CONNECT stream was reset by the peer.
    ConnectReset {
        /// Peer-provided HTTP/3 stream error code.
        error_code: u64,
    },
    /// The peer stopped the local CONNECT-stream send side.
    ConnectStopped {
        /// Peer-provided HTTP/3 stream error code.
        error_code: u64,
    },
    /// The final response could not be accepted by the H3 output path.
    AdmissionFailed,
    /// Session output failed after admission.
    OutputFailed,
    /// The CONNECT stream contained malformed capsule data.
    ProtocolError,
    /// The enclosing QUIC connection ended.
    ConnectionClosed,
}

/// A typed WebTransport session or associated-stream lifecycle event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebTransportSessionEvent {
    /// A syntactically valid CONNECT is awaiting a final admission decision.
    Pending {
        /// CONNECT stream ID and WebTransport Session ID.
        session_id: u64,
    },
    /// A final successful 2xx response established the session.
    Accepted {
        /// CONNECT stream ID and WebTransport Session ID.
        session_id: u64,
    },
    /// A final non-2xx response rejected the session.
    Rejected {
        /// CONNECT stream ID and WebTransport Session ID.
        session_id: u64,
        /// Final HTTP response status.
        status: u16,
    },
    /// The native H3 classifier transferred one associated QUIC stream.
    AssociatedStream {
        /// CONNECT stream ID identifying the WebTransport session.
        session_id: u64,
        /// Physical QUIC stream ID now owned by the WebTransport application.
        stream_id: u64,
        /// Whether the associated stream is bidirectional or unidirectional.
        direction: WebTransportStreamDirection,
        /// Number of prefix bytes consumed by the H3 classifier.
        prefix_len: usize,
    },
    /// The session reached its terminal state.
    Terminated {
        /// CONNECT stream ID and WebTransport Session ID.
        session_id: u64,
        /// Terminal close reason.
        reason: WebTransportSessionCloseReason,
    },
}

/// Error returned before a local WebTransport close command is queued.
#[derive(Debug, Eq, PartialEq)]
pub enum WebTransportSessionCloseError {
    /// The UTF-8 close message exceeds draft-16's 1024-byte limit.
    MessageTooLong {
        /// Actual encoded message length.
        len: usize,
        /// Original close message.
        message: String,
    },
    /// The bounded H3 command lane has no capacity.
    QueueFull {
        /// CONNECT stream ID and WebTransport Session ID.
        session_id: u64,
        /// Application-defined close code.
        error_code: u32,
        /// Original close message.
        message: String,
    },
    /// The paired H3 driver is no longer accepting commands.
    DriverGone {
        /// CONNECT stream ID and WebTransport Session ID.
        session_id: u64,
        /// Application-defined close code.
        error_code: u32,
        /// Original close message.
        message: String,
    },
}

impl fmt::Display for WebTransportSessionCloseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLong { len, .. } => write!(
                f,
                "WebTransport close message is {len} bytes; maximum is {MAX_CLOSE_MESSAGE_LEN}",
            ),
            Self::QueueFull { .. } =>
                f.write_str("WebTransport H3 command queue is full"),
            Self::DriverGone { .. } =>
                f.write_str("WebTransport H3 driver is gone"),
        }
    }
}

impl std::error::Error for WebTransportSessionCloseError {}

/// Why a selected native WebTransport operation could not target an object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportSelectionError {
    /// Native WebTransport support is disabled or was not negotiated.
    Unsupported,
    /// The Session ID has never identified a native session on this connection.
    UnknownSession,
    /// The Session ID belonged to a session that has already been collected.
    StaleSession,
    /// The session is still awaiting a final successful CONNECT response.
    PendingSession,
    /// The session is sending or receiving its close capsule.
    ClosingSession,
    /// The session has reached a terminal state.
    TerminalSession,
    /// The physical stream ID is not owned by the selected session.
    UnknownStream,
    /// The physical stream has already been collected.
    StaleStream,
    /// The physical stream belongs to another active session.
    ForeignStream {
        /// Actual owning Session ID.
        owner_session_id: u64,
    },
    /// The requested operation is invalid for this stream direction.
    WrongDirection,
    /// A configured ownership bound or the peer's current stream limit was
    /// reached. Retrying can succeed after ownership or `MAX_STREAMS` credit is
    /// released.
    ResourceLimit,
    /// An invariant failed after the physical stream became externally visible.
    InternalFailure,
    /// The paired H3 driver or QUIC connection has terminated.
    ConnectionClosed,
}

/// Outcome of opening a native draft-16 WebTransport stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportOpenStreamOutcome {
    /// The prefix was accepted exactly once and the stream is
    /// application-owned.
    Opened {
        /// Exact physical QUIC stream ID.
        stream_id: u64,
    },
    /// The selected session could not open a stream.
    Rejected(WebTransportSelectionError),
    /// The peer stopped the stream while its WebTransport prefix was opening.
    ResetRequired {
        /// HTTP/3 wire error received in STOP_SENDING.
        wire_error_code: u64,
        /// Decoded 32-bit WebTransport application error, when valid.
        application_error_code: Option<u32>,
    },
}

/// Outcome of one bounded selected-stream write.
#[derive(Debug, Eq, PartialEq)]
pub enum WebTransportStreamWriteOutcome {
    /// QUIC accepted some or all bytes, and possibly FIN.
    Accepted {
        /// Number of payload bytes accepted by QUIC.
        accepted: usize,
        /// Unaccepted suffix, retained without copying when possible.
        remaining: Option<Bytes>,
        /// Whether FIN was accepted with the final payload byte.
        fin_accepted: bool,
    },
    /// Flow control currently prevents any progress.
    Blocked {
        /// Entire unaccepted payload.
        data: Bytes,
        /// FIN requested by the caller.
        fin: bool,
    },
    /// The bounded controller command lane has no free slot.
    QueueFull {
        /// Entire caller-owned payload.
        data: Bytes,
        /// FIN requested by the caller.
        fin: bool,
    },
    /// The selected stream's send side is already closed.
    Closed {
        /// Entire unaccepted payload.
        data: Bytes,
        /// FIN requested by the caller.
        fin: bool,
    },
    /// STOP_SENDING closed the send side and triggered the required reliable
    /// WebTransport-prefix reset.
    ResetRequired {
        /// HTTP/3 wire error received in STOP_SENDING.
        wire_error_code: u64,
        /// Decoded 32-bit WebTransport application error, when valid.
        application_error_code: Option<u32>,
        /// Entire unaccepted payload.
        data: Bytes,
        /// FIN requested by the caller.
        fin: bool,
    },
    /// The command exceeds the configured per-write ownership bound.
    TooLarge {
        /// Maximum payload accepted by one write command.
        max: usize,
        /// Entire unaccepted payload.
        data: Bytes,
        /// FIN requested by the caller.
        fin: bool,
    },
    /// Session or stream selection failed without consuming payload ownership.
    Rejected {
        /// Selection failure.
        error: WebTransportSelectionError,
        /// Entire unaccepted payload.
        data: Bytes,
        /// FIN requested by the caller.
        fin: bool,
    },
}

/// Transport progress made while processing one selected-stream write lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportStreamWriteLeaseProgress {
    /// The driver never requested a payload slice from the owner.
    NeverExposed,
    /// The driver borrowed the payload, but core reported known zero progress.
    ExposedKnownZero,
    /// Core accepted a strict payload prefix without accepting the full lease.
    AcceptedPartial {
        /// Exact number of payload bytes accepted by core.
        accepted: usize,
    },
    /// Core accepted the complete payload and possibly FIN.
    AcceptedComplete {
        /// Exact number of payload bytes accepted by core.
        accepted: usize,
        /// Whether the requested FIN committed with the complete payload.
        fin_accepted: bool,
    },
    /// The result consumer disappeared after possible transport mutation.
    ///
    /// The owner must conservatively settle or reset its source transaction;
    /// it must not assume zero accepted bytes.
    Unknowable,
}

/// Configured bound that rejected a selected-stream write lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportStreamWriteLeaseLimit {
    /// The declared payload length exceeded the per-write payload bound.
    Payload,
    /// The owner-declared retained bytes exceeded the per-lease memory bound.
    RetainedBytes,
}

/// An owned payload that can be borrowed for one synchronous stream write.
///
/// Implementations remain concrete and non-cloneable. `as_slice()` is called
/// at most once and its borrow is not retained after the core write returns.
/// Returning `Err` from `as_slice()` means no payload slice was exposed.
/// Declared lengths must remain stable, and all methods must complete without
/// blocking or panicking on the QUIC driver thread.
pub trait WebTransportStreamWriteLease: Send + 'static {
    /// Error returned when the owner cannot expose its payload.
    type Error: Send + 'static;

    /// Returns the exact payload length without exposing the payload bytes.
    fn payload_len(&self) -> usize;

    /// Returns a conservative byte count retained by this owner.
    ///
    /// Shared backing allocations that are already counted by the application
    /// should be counted once there and represented here by the retained slice
    /// length. Owner-specific metadata not counted elsewhere must be included.
    fn retained_bytes(&self) -> usize;

    /// Borrows the payload for one synchronous core stream-write attempt.
    fn as_slice(&mut self) -> Result<&[u8], Self::Error>;

    /// Records deterministic settlement when the result consumer disappears.
    ///
    /// The default relies on the owner's `Drop` behavior. Transactional owners
    /// can use this notification to distinguish safe zero-progress release
    /// from a required fail-closed reset. This callback runs synchronously
    /// during owner drop and must not block.
    fn on_write_abandoned(
        &mut self, _progress: WebTransportStreamWriteLeaseProgress,
    ) {
    }
}

/// Outcome of one generic selected-stream write-lease operation.
#[derive(Debug)]
pub enum WebTransportStreamWriteLeaseOutcome<L>
where
    L: WebTransportStreamWriteLease,
{
    /// Core accepted some or all payload bytes, and possibly FIN.
    Accepted {
        /// The exact original owner.
        lease: L,
        /// Number of payload bytes accepted by core.
        accepted: usize,
        /// Whether the complete declared payload was accepted.
        complete: bool,
        /// Whether FIN committed with the complete payload.
        fin_accepted: bool,
    },
    /// Flow control prevented progress after one payload exposure.
    Blocked {
        /// The exact original owner.
        lease: L,
        /// Whether FIN remains requested.
        fin: bool,
    },
    /// The bounded command lane was full before payload exposure.
    QueueFull {
        /// The exact original owner.
        lease: L,
        /// Whether FIN remains requested.
        fin: bool,
    },
    /// The configured aggregate outstanding-lease bound was full.
    ResourceLimit {
        /// The exact original owner.
        lease: L,
        /// Whether FIN remains requested.
        fin: bool,
    },
    /// A declared per-lease bound was exceeded before payload exposure.
    TooLarge {
        /// Bound that rejected the owner.
        limit: WebTransportStreamWriteLeaseLimit,
        /// Configured maximum.
        max: usize,
        /// Owner-declared value.
        actual: usize,
        /// The exact original owner.
        lease: L,
        /// Whether FIN remains requested.
        fin: bool,
    },
    /// The selected stream's send side was closed after known zero progress.
    Closed {
        /// The exact original owner.
        lease: L,
        /// Whether FIN remains requested.
        fin: bool,
    },
    /// STOP_SENDING requires a reliable WebTransport-prefix reset.
    ResetRequired {
        /// HTTP/3 wire error received in STOP_SENDING.
        wire_error_code: u64,
        /// Decoded WebTransport application error, when valid.
        application_error_code: Option<u32>,
        /// The exact original owner.
        lease: L,
        /// Whether FIN remains requested.
        fin: bool,
    },
    /// Session or stream selection failed before payload exposure.
    Rejected {
        /// Selection failure.
        error: WebTransportSelectionError,
        /// The exact original owner.
        lease: L,
        /// Whether FIN remains requested.
        fin: bool,
    },
    /// The owner could not expose its payload; no core write was attempted.
    LeaseError {
        /// Owner-defined exposure error.
        error: L::Error,
        /// The exact original owner.
        lease: L,
        /// Whether FIN remains requested.
        fin: bool,
    },
    /// The exposed slice length differed from the preflight declaration.
    InvalidLength {
        /// Length returned before payload exposure.
        declared: usize,
        /// Length of the exposed slice.
        actual: usize,
        /// The exact original owner.
        lease: L,
        /// Whether FIN remains requested.
        fin: bool,
    },
    /// An internal result path disappeared after possible transport mutation.
    ///
    /// The exact owner is returned, but the caller must fail closed and must
    /// not assume zero progress.
    ProgressUnknowable {
        /// The exact original owner.
        lease: L,
        /// Whether FIN was requested.
        fin: bool,
    },
}

impl<L> WebTransportStreamWriteLeaseOutcome<L>
where
    L: WebTransportStreamWriteLease,
{
    /// Returns the exact transport exposure/progress classification.
    pub fn progress(&self) -> WebTransportStreamWriteLeaseProgress {
        match self {
            Self::Accepted {
                accepted,
                complete: true,
                fin_accepted,
                ..
            } => WebTransportStreamWriteLeaseProgress::AcceptedComplete {
                accepted: *accepted,
                fin_accepted: *fin_accepted,
            },
            Self::Accepted { accepted, .. } =>
                WebTransportStreamWriteLeaseProgress::AcceptedPartial {
                    accepted: *accepted,
                },
            Self::Blocked { .. } |
            Self::Closed { .. } |
            Self::ResetRequired { .. } |
            Self::InvalidLength { .. } =>
                WebTransportStreamWriteLeaseProgress::ExposedKnownZero,
            Self::ProgressUnknowable { .. } =>
                WebTransportStreamWriteLeaseProgress::Unknowable,
            Self::QueueFull { .. } |
            Self::ResourceLimit { .. } |
            Self::TooLarge { .. } |
            Self::Rejected { .. } |
            Self::LeaseError { .. } =>
                WebTransportStreamWriteLeaseProgress::NeverExposed,
        }
    }
}

/// Outcome of one bounded selected-stream read.
#[derive(Debug, Eq, PartialEq)]
pub enum WebTransportStreamReadOutcome {
    /// Payload bytes were read, optionally including the final offset.
    Data {
        /// Payload bytes after the WebTransport stream prefix.
        data: Bytes,
        /// Whether the peer's FIN was reached.
        fin: bool,
    },
    /// No payload or terminal signal is currently readable.
    Blocked,
    /// RESET_STREAM became visible after any reliable prefix was released.
    Reset {
        /// HTTP/3 wire error carried by RESET_STREAM or RESET_STREAM_AT.
        wire_error_code: u64,
        /// Decoded 32-bit WebTransport application error, when valid.
        application_error_code: Option<u32>,
    },
    /// The requested read size is zero or exceeds the configured bound.
    InvalidSize {
        /// Maximum accepted read size.
        max: usize,
    },
    /// Session or stream selection failed.
    Rejected(WebTransportSelectionError),
}

/// Outcome of sending RESET_STREAM_AT or STOP_SENDING on a selected stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportStreamControlOutcome {
    /// The transport accepted the control operation.
    Applied,
    /// The relevant stream direction was already closed.
    Closed,
    /// Session or stream selection failed.
    Rejected(WebTransportSelectionError),
}

/// Outcome of waiting for one exact selected stream to become ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportStreamReadyOutcome {
    /// The selected read or write operation can make progress.
    Ready,
    /// STOP_SENDING made a selected write terminal.
    ResetRequired {
        /// HTTP/3 wire error received in STOP_SENDING.
        wire_error_code: u64,
        /// Decoded 32-bit WebTransport application error, when valid.
        application_error_code: Option<u32>,
    },
    /// The selected stream direction has closed.
    Closed,
    /// Session or stream selection failed.
    Rejected(WebTransportSelectionError),
}

/// Why a typed WebTransport Datagram operation was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportDatagramError {
    /// QUIC DATAGRAM or draft-16 WebTransport support was not negotiated.
    Unsupported,
    /// The Session ID is unknown on this connection.
    UnknownSession,
    /// The Session ID belonged to a session that has been collected.
    StaleSession,
    /// The session is awaiting its final successful response.
    PendingSession,
    /// The session is closing.
    ClosingSession,
    /// The session is terminal.
    TerminalSession,
    /// The paired H3 driver or QUIC connection has terminated.
    ConnectionClosed,
}

/// Outcome of atomically sending one WebTransport Datagram.
#[derive(Debug)]
pub enum WebTransportDatagramSendOutcome {
    /// QUIC accepted ownership of the complete Datagram.
    Accepted,
    /// The bounded QUIC Datagram queue is currently full.
    Blocked(DgramBuffer),
    /// The bounded controller command lane has no free slot.
    QueueFull(DgramBuffer),
    /// The payload exceeds the currently usable draft-16 payload size.
    TooLarge {
        /// Maximum accepted by the rejecting controller or connection layer.
        /// Use [`WebTransportController::max_datagram_payload()`] for the
        /// current connection-specific value.
        max: usize,
        /// Unaccepted Datagram payload.
        datagram: DgramBuffer,
    },
    /// The backing allocation exceeds the configured command-retention bound.
    AllocationTooLarge {
        /// Maximum accepted backing allocation.
        max: usize,
        /// Actual backing allocation.
        allocated: usize,
        /// Unaccepted Datagram payload.
        datagram: DgramBuffer,
    },
    /// Session selection or negotiation failed without consuming ownership.
    Rejected {
        /// Typed rejection reason.
        error: WebTransportDatagramError,
        /// Unaccepted Datagram payload.
        datagram: DgramBuffer,
    },
    /// The command result channel closed after ownership entered the driver.
    OwnershipLost,
}

/// Aggregate accounting for incoming native WebTransport Datagram ownership.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WebTransportDatagramStats {
    /// Datagram items currently retained for native or provisional delivery.
    pub retained_datagrams: usize,
    /// Readable payload bytes currently retained.
    pub retained_payload_bytes: usize,
    /// Physical `Vec` allocation bytes currently retained.
    pub retained_allocation_bytes: usize,
    /// Configured aggregate retained-item limit.
    pub max_retained_datagrams: usize,
    /// Configured aggregate readable-payload byte limit.
    pub max_retained_payload_bytes: usize,
    /// Configured aggregate physical-allocation byte limit.
    pub max_retained_allocation_bytes: usize,
    /// Datagram items dropped because configured item or byte limits were full.
    pub overflow_datagrams: u64,
    /// Datagram bytes dropped because configured item or byte limits were full.
    pub overflow_bytes: u64,
    /// Provisional Datagram items dropped when their association deadline
    /// passed.
    pub expired_datagrams: u64,
    /// Provisional Datagram bytes dropped when their association deadline
    /// passed.
    pub expired_bytes: u64,
    /// Provisional Datagram items released exactly once to ordinary H3 flows.
    pub legacy_datagrams: u64,
    /// Provisional Datagram bytes released exactly once to ordinary H3 flows.
    pub legacy_bytes: u64,
    /// Datagram items discarded by session rejection or connection teardown.
    pub terminal_datagrams: u64,
    /// Datagram bytes discarded by session rejection or connection teardown.
    pub terminal_bytes: u64,
}

/// Point-in-time native WebTransport retention accounting.
///
/// Byte counters distinguish physical `DgramBuffer` allocation from logical
/// QUIC queue bytes. `metadata_index_entries` counts retained map/set/queue
/// entries rather than estimating allocator overhead. A process memory policy
/// can combine these values with its per-entry metadata budget and any shared
/// `Bytes` source allocations retained by the application.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WebTransportRetentionStats {
    /// Pending, active, closing, or terminal session records.
    pub sessions: usize,
    /// Associated streams currently owned by native WebTransport.
    pub associated_streams: usize,
    /// Inbound or locally opening streams awaiting completed association.
    pub provisional_streams: usize,
    /// One-shot stream and Datagram readiness registrations.
    pub waiters: usize,
    /// Aggregate retained runtime index entries, including duplicate indexes.
    pub metadata_index_entries: usize,
    /// Incoming native/provisional Datagram items retained by the runtime.
    pub pending_datagrams: usize,
    /// Readable bytes in retained incoming Datagrams.
    pub pending_datagram_payload_bytes: usize,
    /// Physical backing allocations for retained incoming Datagrams.
    pub pending_datagram_allocation_bytes: usize,
    /// Configured selected-I/O command capacity.
    pub command_capacity: usize,
    /// Selected-I/O commands queued behind this snapshot command.
    pub queued_commands: usize,
    /// Conservative logical payload bound for those queued commands.
    pub queued_command_payload_bytes_upper_bound: usize,
    /// Outstanding generic write leases in commands or unconsumed results.
    pub write_leases: usize,
    /// Owner-declared bytes retained by outstanding generic write leases.
    pub write_lease_retained_bytes: usize,
    /// Configured outstanding generic write-lease count bound.
    pub max_write_leases: usize,
    /// Configured aggregate generic write-lease retained-byte bound.
    pub max_write_lease_retained_bytes: usize,
    /// Generic write leases admitted since driver construction.
    pub write_lease_admitted_total: u64,
    /// Generic write leases rejected because the command lane was full.
    pub write_lease_queue_full_total: u64,
    /// Generic write leases rejected by the aggregate outstanding bound.
    pub write_lease_resource_limit_total: u64,
    /// Generic write leases rejected by a per-owner size bound.
    pub write_lease_too_large_total: u64,
    /// Admitted, never-exposed owners abandoned after caller cancellation.
    pub write_lease_abandoned_unexposed_total: u64,
    /// Admitted, exposed known-zero owners abandoned after cancellation.
    pub write_lease_abandoned_zero_total: u64,
    /// Admitted owners abandoned with unknowable settlement progress.
    pub write_lease_abandoned_unknown_total: u64,
    /// Logical bytes retained by QUIC stream send buffers.
    pub transport_stream_send_bytes: usize,
    /// Logical bytes retained by QUIC stream receive buffers.
    pub transport_stream_receive_bytes: u64,
    /// Logical bytes retained by the QUIC Datagram send queue.
    pub transport_datagram_send_bytes: usize,
    /// Logical bytes retained by the QUIC Datagram receive queue.
    pub transport_datagram_receive_bytes: usize,
}

impl WebTransportRetentionStats {
    /// Returns adapter/runtime retained bytes covered directly by byte bounds.
    ///
    /// This includes physical incoming Datagram allocation, the conservative
    /// logical payload bound for queued selected-I/O commands, and exact
    /// owner-declared bytes for admitted write leases. Shared backing already
    /// counted by the application must still be counted only once there.
    pub fn adapter_bytes_upper_bound(&self) -> u64 {
        (self.pending_datagram_allocation_bytes as u64)
            .saturating_add(self.queued_command_payload_bytes_upper_bound as u64)
            .saturating_add(self.write_lease_retained_bytes as u64)
    }

    /// Returns logical application bytes currently queued by QUIC.
    pub fn transport_queued_bytes(&self) -> u64 {
        (self.transport_stream_send_bytes as u64)
            .saturating_add(self.transport_stream_receive_bytes)
            .saturating_add(self.transport_datagram_send_bytes as u64)
            .saturating_add(self.transport_datagram_receive_bytes as u64)
    }
}

#[derive(Debug, Default)]
struct WriteLeaseAccountingState {
    current: usize,
    retained_bytes: usize,
    admitted_total: u64,
    queue_full_total: u64,
    resource_limit_total: u64,
    too_large_total: u64,
    abandoned_unexposed_total: u64,
    abandoned_zero_total: u64,
    abandoned_unknown_total: u64,
}

#[derive(Debug)]
pub(crate) struct WriteLeaseAccounting {
    max_count: usize,
    max_retained_bytes: usize,
    state: Mutex<WriteLeaseAccountingState>,
}

impl WriteLeaseAccounting {
    pub(crate) fn new(
        max_count: usize, max_retained_bytes_per_lease: usize,
    ) -> Self {
        let max_count = max_count.max(1);
        Self {
            max_count,
            max_retained_bytes: max_count
                .saturating_mul(max_retained_bytes_per_lease),
            state: Mutex::new(WriteLeaseAccountingState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WriteLeaseAccountingState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn try_admit(
        self: &Arc<Self>, retained_bytes: usize,
    ) -> Option<WriteLeaseAccountingGuard> {
        let mut state = self.lock();
        let Some(next_bytes) = state.retained_bytes.checked_add(retained_bytes)
        else {
            state.resource_limit_total =
                state.resource_limit_total.saturating_add(1);
            return None;
        };
        if state.current >= self.max_count || next_bytes > self.max_retained_bytes
        {
            state.resource_limit_total =
                state.resource_limit_total.saturating_add(1);
            return None;
        }

        state.current += 1;
        state.retained_bytes = next_bytes;
        state.admitted_total = state.admitted_total.saturating_add(1);
        drop(state);
        Some(WriteLeaseAccountingGuard {
            accounting: Arc::clone(self),
            retained_bytes,
        })
    }

    fn record_queue_full(&self) {
        let mut state = self.lock();
        state.queue_full_total = state.queue_full_total.saturating_add(1);
    }

    fn record_too_large(&self) {
        let mut state = self.lock();
        state.too_large_total = state.too_large_total.saturating_add(1);
    }

    fn record_abandonment(&self, progress: WebTransportStreamWriteLeaseProgress) {
        let mut state = self.lock();
        match progress {
            WebTransportStreamWriteLeaseProgress::NeverExposed => {
                state.abandoned_unexposed_total =
                    state.abandoned_unexposed_total.saturating_add(1);
            },
            WebTransportStreamWriteLeaseProgress::ExposedKnownZero => {
                state.abandoned_zero_total =
                    state.abandoned_zero_total.saturating_add(1);
            },
            WebTransportStreamWriteLeaseProgress::AcceptedPartial { .. } |
            WebTransportStreamWriteLeaseProgress::AcceptedComplete { .. } |
            WebTransportStreamWriteLeaseProgress::Unknowable => {
                state.abandoned_unknown_total =
                    state.abandoned_unknown_total.saturating_add(1);
            },
        }
    }

    fn snapshot(&self) -> WriteLeaseAccountingSnapshot {
        let state = self.lock();
        WriteLeaseAccountingSnapshot {
            current: state.current,
            retained_bytes: state.retained_bytes,
            max_count: self.max_count,
            max_retained_bytes: self.max_retained_bytes,
            admitted_total: state.admitted_total,
            queue_full_total: state.queue_full_total,
            resource_limit_total: state.resource_limit_total,
            too_large_total: state.too_large_total,
            abandoned_unexposed_total: state.abandoned_unexposed_total,
            abandoned_zero_total: state.abandoned_zero_total,
            abandoned_unknown_total: state.abandoned_unknown_total,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct WriteLeaseAccountingSnapshot {
    current: usize,
    retained_bytes: usize,
    max_count: usize,
    max_retained_bytes: usize,
    admitted_total: u64,
    queue_full_total: u64,
    resource_limit_total: u64,
    too_large_total: u64,
    abandoned_unexposed_total: u64,
    abandoned_zero_total: u64,
    abandoned_unknown_total: u64,
}

#[derive(Debug)]
struct WriteLeaseAccountingGuard {
    accounting: Arc<WriteLeaseAccounting>,
    retained_bytes: usize,
}

impl Drop for WriteLeaseAccountingGuard {
    fn drop(&mut self) {
        let mut state = self.accounting.lock();
        state.current = state.current.saturating_sub(1);
        state.retained_bytes =
            state.retained_bytes.saturating_sub(self.retained_bytes);
    }
}

enum WriteLeaseCompletion<E> {
    Accepted {
        accepted: usize,
        complete: bool,
        fin_accepted: bool,
    },
    Blocked,
    Closed,
    ResetRequired {
        wire_error_code: u64,
        application_error_code: Option<u32>,
    },
    Rejected(WebTransportSelectionError),
    LeaseError(E),
    InvalidLength {
        declared: usize,
        actual: usize,
    },
    ProgressUnknowable,
}

struct WriteLeaseOwner<L>
where
    L: WebTransportStreamWriteLease,
{
    lease: Option<L>,
    progress: WebTransportStreamWriteLeaseProgress,
    accounting: Option<WriteLeaseAccountingGuard>,
}

impl<L> WriteLeaseOwner<L>
where
    L: WebTransportStreamWriteLease,
{
    fn take(&mut self) -> L {
        self.accounting.take();
        self.lease
            .take()
            .expect("write-lease owner must be returned exactly once")
    }
}

impl<L> Drop for WriteLeaseOwner<L>
where
    L: WebTransportStreamWriteLease,
{
    fn drop(&mut self) {
        let Some(lease) = self.lease.as_mut() else {
            return;
        };
        let progress = match self.progress {
            WebTransportStreamWriteLeaseProgress::AcceptedPartial {
                accepted,
            } if accepted != 0 =>
                WebTransportStreamWriteLeaseProgress::Unknowable,
            WebTransportStreamWriteLeaseProgress::AcceptedComplete {
                accepted,
                fin_accepted,
            } if accepted != 0 || fin_accepted =>
                WebTransportStreamWriteLeaseProgress::Unknowable,
            progress => progress,
        };
        lease.on_write_abandoned(progress);
        if let Some(accounting) = self.accounting.as_ref() {
            accounting.accounting.record_abandonment(progress);
        }
    }
}

struct WriteLeaseShared<L>
where
    L: WebTransportStreamWriteLease,
{
    owner: WriteLeaseOwner<L>,
    completion: Option<WriteLeaseCompletion<L::Error>>,
    declared_len: usize,
    fin: bool,
}

impl<L> WriteLeaseShared<L>
where
    L: WebTransportStreamWriteLease,
{
    fn outcome(&mut self) -> WebTransportStreamWriteLeaseOutcome<L> {
        let completion = self.completion.take().unwrap_or_else(|| {
            self.owner.progress =
                WebTransportStreamWriteLeaseProgress::Unknowable;
            WriteLeaseCompletion::ProgressUnknowable
        });
        let lease = self.owner.take();
        match completion {
            WriteLeaseCompletion::Accepted {
                accepted,
                complete,
                fin_accepted,
            } => WebTransportStreamWriteLeaseOutcome::Accepted {
                lease,
                accepted,
                complete,
                fin_accepted,
            },
            WriteLeaseCompletion::Blocked =>
                WebTransportStreamWriteLeaseOutcome::Blocked {
                    lease,
                    fin: self.fin,
                },
            WriteLeaseCompletion::Closed =>
                WebTransportStreamWriteLeaseOutcome::Closed {
                    lease,
                    fin: self.fin,
                },
            WriteLeaseCompletion::ResetRequired {
                wire_error_code,
                application_error_code,
            } => WebTransportStreamWriteLeaseOutcome::ResetRequired {
                wire_error_code,
                application_error_code,
                lease,
                fin: self.fin,
            },
            WriteLeaseCompletion::Rejected(error) =>
                WebTransportStreamWriteLeaseOutcome::Rejected {
                    error,
                    lease,
                    fin: self.fin,
                },
            WriteLeaseCompletion::LeaseError(error) =>
                WebTransportStreamWriteLeaseOutcome::LeaseError {
                    error,
                    lease,
                    fin: self.fin,
                },
            WriteLeaseCompletion::InvalidLength { declared, actual } =>
                WebTransportStreamWriteLeaseOutcome::InvalidLength {
                    declared,
                    actual,
                    lease,
                    fin: self.fin,
                },
            WriteLeaseCompletion::ProgressUnknowable =>
                WebTransportStreamWriteLeaseOutcome::ProgressUnknowable {
                    lease,
                    fin: self.fin,
                },
        }
    }
}

/// Awaitable result of one admitted generic selected-stream write lease.
pub struct WebTransportStreamWriteLeaseOperation<L>
where
    L: WebTransportStreamWriteLease,
{
    response: oneshot::Receiver<()>,
    shared: Arc<Mutex<WriteLeaseShared<L>>>,
    retained_bytes: usize,
}

impl<L> fmt::Debug for WebTransportStreamWriteLeaseOperation<L>
where
    L: WebTransportStreamWriteLease,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebTransportStreamWriteLeaseOperation")
            .field("retained_bytes", &self.retained_bytes)
            .finish_non_exhaustive()
    }
}

impl<L> WebTransportStreamWriteLeaseOperation<L>
where
    L: WebTransportStreamWriteLease,
{
    /// Returns owner-declared bytes retained until this operation is settled.
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Waits for one synchronous core write attempt and returns the same owner.
    pub async fn outcome(self) -> WebTransportStreamWriteLeaseOutcome<L> {
        let Self {
            response, shared, ..
        } = self;
        let _ = response.await;
        let outcome = shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outcome();
        outcome
    }
}

struct BytesWriteLease(Bytes);

impl WebTransportStreamWriteLease for BytesWriteLease {
    type Error = std::convert::Infallible;

    fn payload_len(&self) -> usize {
        self.0.len()
    }

    fn retained_bytes(&self) -> usize {
        self.0.len()
    }

    fn as_slice(&mut self) -> Result<&[u8], Self::Error> {
        Ok(&self.0)
    }
}

fn bytes_write_outcome(
    outcome: WebTransportStreamWriteLeaseOutcome<BytesWriteLease>,
) -> WebTransportStreamWriteOutcome {
    match outcome {
        WebTransportStreamWriteLeaseOutcome::Accepted {
            lease: BytesWriteLease(mut data),
            accepted,
            fin_accepted,
            ..
        } => {
            let remaining =
                (accepted < data.len()).then(|| data.split_off(accepted));
            WebTransportStreamWriteOutcome::Accepted {
                accepted,
                remaining,
                fin_accepted,
            }
        },
        WebTransportStreamWriteLeaseOutcome::Blocked {
            lease: BytesWriteLease(data),
            fin,
        } => WebTransportStreamWriteOutcome::Blocked { data, fin },
        WebTransportStreamWriteLeaseOutcome::QueueFull {
            lease: BytesWriteLease(data),
            fin,
        } |
        WebTransportStreamWriteLeaseOutcome::ResourceLimit {
            lease: BytesWriteLease(data),
            fin,
        } => WebTransportStreamWriteOutcome::QueueFull { data, fin },
        WebTransportStreamWriteLeaseOutcome::TooLarge {
            max,
            lease: BytesWriteLease(data),
            fin,
            ..
        } => WebTransportStreamWriteOutcome::TooLarge { max, data, fin },
        WebTransportStreamWriteLeaseOutcome::Closed {
            lease: BytesWriteLease(data),
            fin,
        } => WebTransportStreamWriteOutcome::Closed { data, fin },
        WebTransportStreamWriteLeaseOutcome::ResetRequired {
            wire_error_code,
            application_error_code,
            lease: BytesWriteLease(data),
            fin,
        } => WebTransportStreamWriteOutcome::ResetRequired {
            wire_error_code,
            application_error_code,
            data,
            fin,
        },
        WebTransportStreamWriteLeaseOutcome::Rejected {
            error,
            lease: BytesWriteLease(data),
            fin,
        } => WebTransportStreamWriteOutcome::Rejected { error, data, fin },
        WebTransportStreamWriteLeaseOutcome::LeaseError { error, .. } =>
            match error {},
        WebTransportStreamWriteLeaseOutcome::InvalidLength {
            lease: BytesWriteLease(data),
            fin,
            ..
        } |
        WebTransportStreamWriteLeaseOutcome::ProgressUnknowable {
            lease: BytesWriteLease(data),
            fin,
        } => WebTransportStreamWriteOutcome::Rejected {
            error: WebTransportSelectionError::ConnectionClosed,
            data,
            fin,
        },
    }
}

/// Awaitable result of a successfully admitted selected-stream `Bytes` write.
#[derive(Debug)]
pub struct WebTransportStreamWriteOperation {
    inner: WebTransportStreamWriteLeaseOperation<BytesWriteLease>,
}

impl WebTransportStreamWriteOperation {
    /// Waits for the transport admission attempt to complete.
    pub async fn outcome(self) -> WebTransportStreamWriteOutcome {
        bytes_write_outcome(self.inner.outcome().await)
    }
}

/// Awaitable result of a successfully admitted Datagram send command.
#[derive(Debug)]
pub struct WebTransportDatagramSendOperation {
    response: oneshot::Receiver<WebTransportDatagramSendOutcome>,
}

impl WebTransportDatagramSendOperation {
    /// Waits for the atomic transport admission attempt to complete.
    pub async fn outcome(self) -> WebTransportDatagramSendOutcome {
        self.response
            .await
            .unwrap_or(WebTransportDatagramSendOutcome::OwnershipLost)
    }
}

/// Outcome of receiving one queued WebTransport Datagram.
#[derive(Debug)]
pub enum WebTransportDatagramReadOutcome {
    /// One complete Datagram, with its Quarter Stream ID prefix removed.
    Datagram(DgramBuffer),
    /// No Datagram or overflow notification is currently queued.
    Blocked,
    /// Datagram payload was discarded because the configured queue bound was
    /// reached. This notification is returned before retained payload dequeue
    /// resumes.
    Overflow {
        /// Number of discarded Datagram items since the prior notification.
        datagrams: u64,
        /// Number of discarded payload bytes since the prior notification.
        bytes: u64,
    },
    /// Session selection or negotiation failed.
    Rejected(WebTransportDatagramError),
}

/// Outcome of waiting for exact-session Datagram readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportDatagramReadyOutcome {
    /// A receive or atomic send attempt can make progress now.
    Ready,
    /// The configured aggregate Datagram waiter bound is full, or this exact
    /// session already has a waiter for the same readiness kind.
    ResourceLimit,
    /// Session selection or negotiation failed.
    Rejected(WebTransportDatagramError),
}

/// A cloneable, bounded command boundary for one native WebTransport driver.
///
/// Calls wait asynchronously for space in the configured command lane, without
/// blocking the QUIC event loop. Once admitted, the driver owns each supplied
/// buffer until it returns an outcome. Stream-open commands internally retry
/// only the draft-16 prefix; payload writes and Datagrams make one transport
/// admission attempt and return unaccepted ownership to the caller. Connection
/// teardown resolves every admitted command with a terminal outcome.
///
/// Buffer-bearing async calls retain their buffer in the caller-owned future
/// while waiting for lane admission. Adapters requiring a hard aggregate bound
/// should use [`Self::try_write_stream()`],
/// [`Self::try_write_stream_lease()`], and [`Self::try_send_datagram()`], which
/// return `QueueFull` and the original owner without waiting. Generic leases
/// remain bounded until their result is consumed or dropped, even after their
/// command leaves the lane.
#[derive(Clone)]
pub struct WebTransportController {
    sender: mpsc::Sender<WebTransportCommand>,
    max_stream_write_bytes: usize,
    max_stream_write_lease_retained_bytes: usize,
    max_stream_read_bytes: usize,
    max_datagram_send_bytes: usize,
    max_datagram_send_allocation_bytes: usize,
    write_lease_accounting: Arc<WriteLeaseAccounting>,
}

impl WebTransportController {
    pub(crate) fn new(
        sender: mpsc::Sender<WebTransportCommand>, max_stream_write_bytes: usize,
        max_stream_write_lease_retained_bytes: usize,
        max_stream_read_bytes: usize, max_datagram_send_allocation_bytes: usize,
        write_lease_accounting: Arc<WriteLeaseAccounting>,
    ) -> Self {
        Self {
            sender,
            max_stream_write_bytes,
            max_stream_write_lease_retained_bytes,
            max_stream_read_bytes,
            max_datagram_send_bytes: datagram_socket::MAX_DATAGRAM_SIZE,
            max_datagram_send_allocation_bytes,
            write_lease_accounting,
        }
    }

    /// Opens a bidirectional stream for an exact active Session ID.
    ///
    /// The result contains the physical QUIC stream ID after the complete
    /// draft-16 prefix has been accepted exactly once.
    pub async fn open_bidirectional_stream(
        &self, session_id: u64,
    ) -> WebTransportOpenStreamOutcome {
        self.open_stream(session_id, WebTransportStreamDirection::Bidi)
            .await
    }

    /// Opens a unidirectional stream for an exact active Session ID.
    ///
    /// The result contains the physical QUIC stream ID after the complete
    /// draft-16 prefix has been accepted exactly once.
    pub async fn open_unidirectional_stream(
        &self, session_id: u64,
    ) -> WebTransportOpenStreamOutcome {
        self.open_stream(session_id, WebTransportStreamDirection::Uni)
            .await
    }

    async fn open_stream(
        &self, session_id: u64, direction: WebTransportStreamDirection,
    ) -> WebTransportOpenStreamOutcome {
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            );
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::Open {
            session_id,
            direction,
            response,
        });
        recv.await
            .unwrap_or(WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            ))
    }

    /// Writes one bounded payload suffix and optional FIN to a selected stream.
    ///
    /// This performs one QUIC write attempt. The caller must retry only the
    /// returned suffix and FIN state; accepted bytes are never replayed by the
    /// controller.
    pub async fn write_stream(
        &self, session_id: u64, stream_id: u64, data: Bytes, fin: bool,
    ) -> WebTransportStreamWriteOutcome {
        bytes_write_outcome(
            self.write_stream_lease(
                session_id,
                stream_id,
                BytesWriteLease(data),
                fin,
            )
            .await,
        )
    }

    /// Attempts immediate command-lane admission for one selected-stream write.
    ///
    /// `QueueFull` returns the exact caller-owned payload without waiting. The
    /// returned operation owns only a bounded command slot; waiting on its
    /// outcome remains the caller task's responsibility.
    pub fn try_write_stream(
        &self, session_id: u64, stream_id: u64, data: Bytes, fin: bool,
    ) -> Result<WebTransportStreamWriteOperation, WebTransportStreamWriteOutcome>
    {
        match self.try_write_stream_lease(
            session_id,
            stream_id,
            BytesWriteLease(data),
            fin,
        ) {
            Ok(inner) => Ok(WebTransportStreamWriteOperation { inner }),
            Err(outcome) => Err(bytes_write_outcome(outcome)),
        }
    }

    /// Writes one generic owned lease to an exact selected stream.
    ///
    /// The owner remains caller-owned while waiting for bounded command-lane
    /// capacity. Once admitted, the driver calls `L::as_slice()` at most once,
    /// borrows it only for one synchronous core `stream_send()` call, and
    /// returns the same concrete owner with exact progress.
    pub async fn write_stream_lease<L>(
        &self, session_id: u64, stream_id: u64, lease: L, fin: bool,
    ) -> WebTransportStreamWriteLeaseOutcome<L>
    where
        L: WebTransportStreamWriteLease,
    {
        let preflight = match self.preflight_write_lease(&lease) {
            Ok(preflight) => preflight,
            Err((limit, max, actual)) =>
                return WebTransportStreamWriteLeaseOutcome::TooLarge {
                    limit,
                    max,
                    actual,
                    lease,
                    fin,
                },
        };
        let retained_bytes = preflight.1;
        let mut owner = WriteLeaseOwner {
            lease: Some(lease),
            progress: WebTransportStreamWriteLeaseProgress::NeverExposed,
            accounting: None,
        };
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::ConnectionClosed,
                lease: owner.take(),
                fin,
            };
        };
        let Some(accounting) =
            self.write_lease_accounting.try_admit(retained_bytes)
        else {
            return WebTransportStreamWriteLeaseOutcome::ResourceLimit {
                lease: owner.take(),
                fin,
            };
        };
        owner.accounting = Some(accounting);
        self.admit_stream_write_lease(
            permit, session_id, stream_id, owner, preflight, fin,
        )
        .outcome()
        .await
    }

    /// Attempts immediate admission of one generic selected-stream write lease.
    ///
    /// Every pre-admission failure returns the exact concrete owner without
    /// exposing its payload bytes.
    pub fn try_write_stream_lease<L>(
        &self, session_id: u64, stream_id: u64, lease: L, fin: bool,
    ) -> Result<
        WebTransportStreamWriteLeaseOperation<L>,
        WebTransportStreamWriteLeaseOutcome<L>,
    >
    where
        L: WebTransportStreamWriteLease,
    {
        let preflight = match self.preflight_write_lease(&lease) {
            Ok(preflight) => preflight,
            Err((limit, max, actual)) =>
                return Err(WebTransportStreamWriteLeaseOutcome::TooLarge {
                    limit,
                    max,
                    actual,
                    lease,
                    fin,
                }),
        };
        let retained_bytes = preflight.1;
        let permit = match self.sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                self.write_lease_accounting.record_queue_full();
                return Err(WebTransportStreamWriteLeaseOutcome::QueueFull {
                    lease,
                    fin,
                });
            },
            Err(mpsc::error::TrySendError::Closed(())) => {
                return Err(WebTransportStreamWriteLeaseOutcome::Rejected {
                    error: WebTransportSelectionError::ConnectionClosed,
                    lease,
                    fin,
                });
            },
        };
        let Some(accounting) =
            self.write_lease_accounting.try_admit(retained_bytes)
        else {
            return Err(WebTransportStreamWriteLeaseOutcome::ResourceLimit {
                lease,
                fin,
            });
        };
        let owner = WriteLeaseOwner {
            lease: Some(lease),
            progress: WebTransportStreamWriteLeaseProgress::NeverExposed,
            accounting: Some(accounting),
        };
        Ok(self.admit_stream_write_lease(
            permit, session_id, stream_id, owner, preflight, fin,
        ))
    }

    fn preflight_write_lease<L>(
        &self, lease: &L,
    ) -> Result<(usize, usize), (WebTransportStreamWriteLeaseLimit, usize, usize)>
    where
        L: WebTransportStreamWriteLease,
    {
        let payload_len = lease.payload_len();
        if payload_len > self.max_stream_write_bytes {
            self.write_lease_accounting.record_too_large();
            return Err((
                WebTransportStreamWriteLeaseLimit::Payload,
                self.max_stream_write_bytes,
                payload_len,
            ));
        }
        let retained_bytes = lease.retained_bytes();
        if retained_bytes > self.max_stream_write_lease_retained_bytes {
            self.write_lease_accounting.record_too_large();
            return Err((
                WebTransportStreamWriteLeaseLimit::RetainedBytes,
                self.max_stream_write_lease_retained_bytes,
                retained_bytes,
            ));
        }
        Ok((payload_len, retained_bytes))
    }

    fn admit_stream_write_lease<L>(
        &self, permit: mpsc::Permit<'_, WebTransportCommand>, session_id: u64,
        stream_id: u64, owner: WriteLeaseOwner<L>, preflight: (usize, usize),
        fin: bool,
    ) -> WebTransportStreamWriteLeaseOperation<L>
    where
        L: WebTransportStreamWriteLease,
    {
        let (declared_len, retained_bytes) = preflight;
        let (response, recv) = oneshot::channel();
        let shared = Arc::new(Mutex::new(WriteLeaseShared {
            owner,
            completion: None,
            declared_len,
            fin,
        }));
        permit.send(WebTransportCommand::WriteLease(Box::new(
            WriteLeaseCommand {
                session_id,
                stream_id,
                shared: Arc::clone(&shared),
                response: Some(response),
            },
        )));
        WebTransportStreamWriteLeaseOperation {
            response: recv,
            shared,
            retained_bytes,
        }
    }

    /// Reads up to `max_bytes` from one selected associated stream.
    pub async fn read_stream(
        &self, session_id: u64, stream_id: u64, max_bytes: usize,
    ) -> WebTransportStreamReadOutcome {
        if max_bytes == 0 || max_bytes > self.max_stream_read_bytes {
            return WebTransportStreamReadOutcome::InvalidSize {
                max: self.max_stream_read_bytes,
            };
        }
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportStreamReadOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            );
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::Read {
            session_id,
            stream_id,
            max_bytes,
            response,
        });
        recv.await
            .unwrap_or(WebTransportStreamReadOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            ))
    }

    /// Waits without polling for one exact selected stream to become readable.
    pub async fn wait_stream_readable(
        &self, session_id: u64, stream_id: u64,
    ) -> WebTransportStreamReadyOutcome {
        self.wait_stream(session_id, stream_id, false).await
    }

    /// Waits without polling for one exact selected stream to become writable.
    pub async fn wait_stream_writable(
        &self, session_id: u64, stream_id: u64,
    ) -> WebTransportStreamReadyOutcome {
        self.wait_stream(session_id, stream_id, true).await
    }

    async fn wait_stream(
        &self, session_id: u64, stream_id: u64, write: bool,
    ) -> WebTransportStreamReadyOutcome {
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            );
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::Wait {
            session_id,
            stream_id,
            write,
            response,
        });
        recv.await
            .unwrap_or(WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            ))
    }

    /// Sends RESET_STREAM_AT using the draft-16 application-error mapping.
    pub async fn reset_stream(
        &self, session_id: u64, stream_id: u64, error_code: u32,
    ) -> WebTransportStreamControlOutcome {
        self.control_stream(session_id, stream_id, error_code, true)
            .await
    }

    /// Sends STOP_SENDING using the draft-16 application-error mapping.
    pub async fn stop_stream(
        &self, session_id: u64, stream_id: u64, error_code: u32,
    ) -> WebTransportStreamControlOutcome {
        self.control_stream(session_id, stream_id, error_code, false)
            .await
    }

    async fn control_stream(
        &self, session_id: u64, stream_id: u64, error_code: u32, reset: bool,
    ) -> WebTransportStreamControlOutcome {
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportStreamControlOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            );
        };
        let (response, recv) = oneshot::channel();
        let command = if reset {
            WebTransportCommand::Reset {
                session_id,
                stream_id,
                error_code,
                response,
            }
        } else {
            WebTransportCommand::Stop {
                session_id,
                stream_id,
                error_code,
                response,
            }
        };
        permit.send(command);
        recv.await
            .unwrap_or(WebTransportStreamControlOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            ))
    }

    /// Atomically sends one Datagram for an exact active Session ID.
    ///
    /// Payload above `datagram_socket::MAX_DATAGRAM_SIZE` is rejected before
    /// command-lane admission. Otherwise this performs one QUIC queue admission
    /// attempt, whose connection-specific maximum can be smaller. A blocked or
    /// rejected outcome returns the original payload buffer.
    pub async fn send_datagram(
        &self, session_id: u64, datagram: DgramBuffer,
    ) -> WebTransportDatagramSendOutcome {
        if datagram.as_slice().len() > self.max_datagram_send_bytes {
            return WebTransportDatagramSendOutcome::TooLarge {
                max: self.max_datagram_send_bytes,
                datagram,
            };
        }
        if datagram.allocated_capacity() > self.max_datagram_send_allocation_bytes
        {
            return WebTransportDatagramSendOutcome::AllocationTooLarge {
                max: self.max_datagram_send_allocation_bytes,
                allocated: datagram.allocated_capacity(),
                datagram,
            };
        }
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportDatagramSendOutcome::Rejected {
                error: WebTransportDatagramError::ConnectionClosed,
                datagram,
            };
        };
        self.admit_datagram_send(permit, session_id, datagram)
            .outcome()
            .await
    }

    /// Attempts immediate command-lane admission for one atomic Datagram send.
    ///
    /// Oversized payload is rejected before admission, and `QueueFull` returns
    /// the original buffer without waiting.
    pub fn try_send_datagram(
        &self, session_id: u64, datagram: DgramBuffer,
    ) -> Result<WebTransportDatagramSendOperation, WebTransportDatagramSendOutcome>
    {
        if datagram.as_slice().len() > self.max_datagram_send_bytes {
            return Err(WebTransportDatagramSendOutcome::TooLarge {
                max: self.max_datagram_send_bytes,
                datagram,
            });
        }
        if datagram.allocated_capacity() > self.max_datagram_send_allocation_bytes
        {
            return Err(WebTransportDatagramSendOutcome::AllocationTooLarge {
                max: self.max_datagram_send_allocation_bytes,
                allocated: datagram.allocated_capacity(),
                datagram,
            });
        }
        let permit = match self.sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                return Err(WebTransportDatagramSendOutcome::QueueFull(datagram));
            },
            Err(mpsc::error::TrySendError::Closed(())) => {
                return Err(WebTransportDatagramSendOutcome::Rejected {
                    error: WebTransportDatagramError::ConnectionClosed,
                    datagram,
                });
            },
        };
        Ok(self.admit_datagram_send(permit, session_id, datagram))
    }

    fn admit_datagram_send(
        &self, permit: mpsc::Permit<'_, WebTransportCommand>, session_id: u64,
        datagram: DgramBuffer,
    ) -> WebTransportDatagramSendOperation {
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::SendDatagram {
            session_id,
            datagram,
            response,
        });
        WebTransportDatagramSendOperation { response: recv }
    }

    /// Receives one queued Datagram for an exact active Session ID.
    ///
    /// Incoming ownership is bounded by the per-connection and per-session
    /// item and byte limits in [`crate::http3::settings::Http3Settings`].
    pub async fn receive_datagram(
        &self, session_id: u64,
    ) -> WebTransportDatagramReadOutcome {
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportDatagramReadOutcome::Rejected(
                WebTransportDatagramError::ConnectionClosed,
            );
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::ReceiveDatagram {
            session_id,
            response,
        });
        recv.await
            .unwrap_or(WebTransportDatagramReadOutcome::Rejected(
                WebTransportDatagramError::ConnectionClosed,
            ))
    }

    /// Waits without polling for an exact session to have a queued Datagram or
    /// overflow notification.
    pub async fn wait_datagram_readable(
        &self, session_id: u64,
    ) -> WebTransportDatagramReadyOutcome {
        self.wait_datagram(session_id, false).await
    }

    /// Waits without polling for an exact session to have QUIC Datagram send
    /// capacity.
    pub async fn wait_datagram_send_capacity(
        &self, session_id: u64,
    ) -> WebTransportDatagramReadyOutcome {
        self.wait_datagram(session_id, true).await
    }

    async fn wait_datagram(
        &self, session_id: u64, send: bool,
    ) -> WebTransportDatagramReadyOutcome {
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportDatagramReadyOutcome::Rejected(
                WebTransportDatagramError::ConnectionClosed,
            );
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::WaitDatagram {
            session_id,
            send,
            response,
        });
        recv.await
            .unwrap_or(WebTransportDatagramReadyOutcome::Rejected(
                WebTransportDatagramError::ConnectionClosed,
            ))
    }

    /// Returns the current maximum Datagram payload for one active session.
    pub async fn max_datagram_payload(
        &self, session_id: u64,
    ) -> Result<usize, WebTransportDatagramError> {
        let Ok(permit) = self.sender.reserve().await else {
            return Err(WebTransportDatagramError::ConnectionClosed);
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::MaxDatagramPayload {
            session_id,
            response,
        });
        recv.await
            .unwrap_or(Err(WebTransportDatagramError::ConnectionClosed))
    }

    /// Returns aggregate provisional/overflow Datagram ownership accounting.
    pub async fn datagram_stats(
        &self,
    ) -> Result<WebTransportDatagramStats, WebTransportDatagramError> {
        let Ok(permit) = self.sender.reserve().await else {
            return Err(WebTransportDatagramError::ConnectionClosed);
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::DatagramStats { response });
        recv.await
            .unwrap_or(Err(WebTransportDatagramError::ConnectionClosed))
    }

    /// Returns bounded runtime, adapter-lane, and QUIC queue accounting.
    pub async fn retention_stats(
        &self,
    ) -> Result<WebTransportRetentionStats, WebTransportDatagramError> {
        let Ok(permit) = self.sender.reserve().await else {
            return Err(WebTransportDatagramError::ConnectionClosed);
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::RetentionStats { response });
        recv.await
            .unwrap_or(Err(WebTransportDatagramError::ConnectionClosed))
    }
}

pub(crate) trait ErasedWriteLeaseCommand: Send {
    fn execute(self: Box<Self>, runtime: &Runtime, qconn: &mut QuicheConnection);

    fn reject(self: Box<Self>, error: WebTransportSelectionError);
}

struct WriteLeaseCommand<L>
where
    L: WebTransportStreamWriteLease,
{
    session_id: u64,
    stream_id: u64,
    shared: Arc<Mutex<WriteLeaseShared<L>>>,
    response: Option<oneshot::Sender<()>>,
}

impl<L> WriteLeaseCommand<L>
where
    L: WebTransportStreamWriteLease,
{
    fn finish(
        &mut self, completion: WriteLeaseCompletion<L::Error>,
        progress: WebTransportStreamWriteLeaseProgress,
    ) {
        {
            let mut shared = self
                .shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if shared.completion.is_none() {
                shared.owner.progress = progress;
                shared.completion = Some(completion);
            }
        }
        if let Some(response) = self.response.take() {
            let _ = response.send(());
        }
    }
}

impl<L> ErasedWriteLeaseCommand for WriteLeaseCommand<L>
where
    L: WebTransportStreamWriteLease,
{
    fn execute(
        mut self: Box<Self>, runtime: &Runtime, qconn: &mut QuicheConnection,
    ) {
        if self
            .response
            .as_ref()
            .is_none_or(oneshot::Sender::is_closed)
        {
            return;
        }
        if let Err(error) =
            runtime.select_stream(self.session_id, self.stream_id, true, qconn)
        {
            self.finish(
                WriteLeaseCompletion::Rejected(error),
                WebTransportStreamWriteLeaseProgress::NeverExposed,
            );
            return;
        }
        if self
            .response
            .as_ref()
            .is_none_or(oneshot::Sender::is_closed)
        {
            return;
        }

        let (completion, progress) = {
            let mut shared = self
                .shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let declared = shared.declared_len;
            let fin = shared.fin;
            let result = {
                let lease = shared
                    .owner
                    .lease
                    .as_mut()
                    .expect("admitted write lease must retain its owner");
                match lease.as_slice() {
                    Ok(data) if data.len() != declared => Err((
                        WriteLeaseCompletion::InvalidLength {
                            declared,
                            actual: data.len(),
                        },
                        WebTransportStreamWriteLeaseProgress::ExposedKnownZero,
                    )),
                    Ok(data) => Ok((
                        data.len(),
                        qconn.stream_send(self.stream_id, data, fin),
                    )),
                    Err(error) => Err((
                        WriteLeaseCompletion::LeaseError(error),
                        WebTransportStreamWriteLeaseProgress::NeverExposed,
                    )),
                }
            };

            match result {
                Err(result) => result,
                Ok((actual, Ok(accepted))) => {
                    let complete = accepted == actual;
                    let fin_accepted = fin && complete;
                    let progress = if complete {
                        WebTransportStreamWriteLeaseProgress::AcceptedComplete {
                            accepted,
                            fin_accepted,
                        }
                    } else {
                        WebTransportStreamWriteLeaseProgress::AcceptedPartial {
                            accepted,
                        }
                    };
                    (
                        WriteLeaseCompletion::Accepted {
                            accepted,
                            complete,
                            fin_accepted,
                        },
                        progress,
                    )
                },
                Ok((_, Err(quiche::Error::Done))) => (
                    WriteLeaseCompletion::Blocked,
                    WebTransportStreamWriteLeaseProgress::ExposedKnownZero,
                ),
                Ok((_, Err(quiche::Error::StreamStopped(error_code)))) => (
                    WriteLeaseCompletion::ResetRequired {
                        wire_error_code: error_code,
                        application_error_code: webtransport_error_from_http3(
                            error_code,
                        ),
                    },
                    WebTransportStreamWriteLeaseProgress::ExposedKnownZero,
                ),
                Ok((_, Err(_))) => (
                    WriteLeaseCompletion::Closed,
                    WebTransportStreamWriteLeaseProgress::ExposedKnownZero,
                ),
            }
        };
        self.finish(completion, progress);
    }

    fn reject(mut self: Box<Self>, error: WebTransportSelectionError) {
        self.finish(
            WriteLeaseCompletion::Rejected(error),
            WebTransportStreamWriteLeaseProgress::NeverExposed,
        );
    }
}

impl<L> Drop for WriteLeaseCommand<L>
where
    L: WebTransportStreamWriteLease,
{
    fn drop(&mut self) {
        if self.response.is_some() {
            self.finish(
                WriteLeaseCompletion::Rejected(
                    WebTransportSelectionError::ConnectionClosed,
                ),
                WebTransportStreamWriteLeaseProgress::NeverExposed,
            );
        }
    }
}

pub(crate) enum WebTransportCommand {
    Open {
        session_id: u64,
        direction: WebTransportStreamDirection,
        response: oneshot::Sender<WebTransportOpenStreamOutcome>,
    },
    WriteLease(Box<dyn ErasedWriteLeaseCommand>),
    Read {
        session_id: u64,
        stream_id: u64,
        max_bytes: usize,
        response: oneshot::Sender<WebTransportStreamReadOutcome>,
    },
    Wait {
        session_id: u64,
        stream_id: u64,
        write: bool,
        response: oneshot::Sender<WebTransportStreamReadyOutcome>,
    },
    Reset {
        session_id: u64,
        stream_id: u64,
        error_code: u32,
        response: oneshot::Sender<WebTransportStreamControlOutcome>,
    },
    Stop {
        session_id: u64,
        stream_id: u64,
        error_code: u32,
        response: oneshot::Sender<WebTransportStreamControlOutcome>,
    },
    SendDatagram {
        session_id: u64,
        datagram: DgramBuffer,
        response: oneshot::Sender<WebTransportDatagramSendOutcome>,
    },
    ReceiveDatagram {
        session_id: u64,
        response: oneshot::Sender<WebTransportDatagramReadOutcome>,
    },
    WaitDatagram {
        session_id: u64,
        send: bool,
        response: oneshot::Sender<WebTransportDatagramReadyOutcome>,
    },
    MaxDatagramPayload {
        session_id: u64,
        response: oneshot::Sender<Result<usize, WebTransportDatagramError>>,
    },
    DatagramStats {
        response: oneshot::Sender<
            Result<WebTransportDatagramStats, WebTransportDatagramError>,
        >,
    },
    RetentionStats {
        response: oneshot::Sender<
            Result<WebTransportRetentionStats, WebTransportDatagramError>,
        >,
    },
}

impl WebTransportCommand {
    pub(crate) fn reject_connection_closed(self) {
        match self {
            Self::Open { response, .. } => {
                let _ = response.send(WebTransportOpenStreamOutcome::Rejected(
                    WebTransportSelectionError::ConnectionClosed,
                ));
            },
            Self::WriteLease(command) =>
                command.reject(WebTransportSelectionError::ConnectionClosed),
            Self::Read { response, .. } => {
                let _ = response.send(WebTransportStreamReadOutcome::Rejected(
                    WebTransportSelectionError::ConnectionClosed,
                ));
            },
            Self::Wait { response, .. } => {
                let _ = response.send(WebTransportStreamReadyOutcome::Rejected(
                    WebTransportSelectionError::ConnectionClosed,
                ));
            },
            Self::Reset { response, .. } | Self::Stop { response, .. } => {
                let _ =
                    response.send(WebTransportStreamControlOutcome::Rejected(
                        WebTransportSelectionError::ConnectionClosed,
                    ));
            },
            Self::SendDatagram {
                datagram, response, ..
            } => {
                let _ =
                    response.send(WebTransportDatagramSendOutcome::Rejected {
                        error: WebTransportDatagramError::ConnectionClosed,
                        datagram,
                    });
            },
            Self::ReceiveDatagram { response, .. } => {
                let _ = response.send(WebTransportDatagramReadOutcome::Rejected(
                    WebTransportDatagramError::ConnectionClosed,
                ));
            },
            Self::WaitDatagram { response, .. } => {
                let _ =
                    response.send(WebTransportDatagramReadyOutcome::Rejected(
                        WebTransportDatagramError::ConnectionClosed,
                    ));
            },
            Self::MaxDatagramPayload { response, .. } => {
                let _ = response
                    .send(Err(WebTransportDatagramError::ConnectionClosed));
            },
            Self::DatagramStats { response } => {
                let _ = response
                    .send(Err(WebTransportDatagramError::ConnectionClosed));
            },
            Self::RetentionStats { response } => {
                let _ = response
                    .send(Err(WebTransportDatagramError::ConnectionClosed));
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AssociatedStream {
    pub(crate) session_id: u64,
    pub(crate) stream_id: u64,
    pub(crate) direction: WebTransportStreamDirection,
    pub(crate) prefix_len: usize,
}

#[derive(Debug)]
pub(crate) enum RequestObservation {
    Observed(Vec<WebTransportSessionEvent>),
    Excessive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapsuleReadMode {
    Regular,
    Defer,
    Parse,
    Discard,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CloseCapsule {
    pub(crate) error_code: u32,
    pub(crate) message: String,
}

impl CloseCapsule {
    pub(crate) fn new(
        error_code: u32, message: String,
    ) -> Result<Self, WebTransportSessionCloseError> {
        if message.len() > MAX_CLOSE_MESSAGE_LEN {
            return Err(WebTransportSessionCloseError::MessageTooLong {
                len: message.len(),
                message,
            });
        }
        Ok(Self {
            error_code,
            message,
        })
    }

    pub(crate) fn encode(&self) -> Bytes {
        let payload_len = 4 + self.message.len();
        let mut out = BytesMut::with_capacity(
            octets::varint_len(WT_CLOSE_SESSION) +
                octets::varint_len(payload_len as u64) +
                payload_len,
        );
        put_varint(&mut out, WT_CLOSE_SESSION);
        put_varint(&mut out, payload_len as u64);
        out.put_u32(self.error_code);
        out.put_slice(self.message.as_bytes());
        out.freeze()
    }
}

fn put_varint(out: &mut BytesMut, value: u64) {
    let len = octets::varint_len(value);
    let start = out.len();
    out.resize(start + len, 0);
    octets::OctetsMut::with_slice(&mut out[start..])
        .put_varint(value)
        .expect("pre-sized QUIC varint buffer");
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapsuleError {
    InvalidLength,
    InvalidUtf8,
    Truncated,
    DataAfterClose,
}

#[derive(Debug)]
enum CapsuleState {
    Type(VarIntDecoder),
    Length {
        capsule_type: u64,
        decoder: VarIntDecoder,
    },
    Payload {
        capsule_type: u64,
        remaining: u64,
        close_payload: Option<Vec<u8>>,
    },
    AfterClose,
}

#[derive(Debug)]
pub(crate) struct CapsuleParser {
    state: CapsuleState,
}

impl Default for CapsuleParser {
    fn default() -> Self {
        Self {
            state: CapsuleState::Type(VarIntDecoder::default()),
        }
    }
}

impl CapsuleParser {
    pub(crate) fn consume(
        &mut self, mut input: &[u8],
    ) -> Result<Option<CloseCapsule>, CapsuleError> {
        let mut close = None;

        while !input.is_empty() {
            match &mut self.state {
                CapsuleState::Type(decoder) => {
                    let Some(capsule_type) = decoder.consume(&mut input) else {
                        continue;
                    };
                    self.state = CapsuleState::Length {
                        capsule_type,
                        decoder: VarIntDecoder::default(),
                    };
                },
                CapsuleState::Length {
                    capsule_type,
                    decoder,
                } => {
                    let Some(length) = decoder.consume(&mut input) else {
                        continue;
                    };
                    let capsule_type = *capsule_type;
                    if capsule_type == WT_CLOSE_SESSION &&
                        !(4..=MAX_CLOSE_CAPSULE_PAYLOAD_LEN as u64)
                            .contains(&length)
                    {
                        return Err(CapsuleError::InvalidLength);
                    }
                    self.state = CapsuleState::Payload {
                        capsule_type,
                        remaining: length,
                        close_payload: (capsule_type == WT_CLOSE_SESSION)
                            .then(|| Vec::with_capacity(length as usize)),
                    };
                    if length == 0 {
                        self.finish_payload(&mut close)?;
                    }
                },
                CapsuleState::Payload {
                    remaining,
                    close_payload,
                    ..
                } => {
                    let take =
                        usize::try_from((*remaining).min(input.len() as u64))
                            .expect("bounded by input length");
                    if let Some(payload) = close_payload {
                        payload.extend_from_slice(&input[..take]);
                    }
                    input = &input[take..];
                    *remaining -= take as u64;
                    if *remaining == 0 {
                        self.finish_payload(&mut close)?;
                    }
                },
                CapsuleState::AfterClose =>
                    return Err(CapsuleError::DataAfterClose),
            }
        }

        Ok(close)
    }

    fn finish_payload(
        &mut self, close: &mut Option<CloseCapsule>,
    ) -> Result<(), CapsuleError> {
        let CapsuleState::Payload {
            capsule_type,
            remaining: 0,
            close_payload,
        } = std::mem::replace(
            &mut self.state,
            CapsuleState::Type(VarIntDecoder::default()),
        )
        else {
            unreachable!("payload completion requires a complete payload");
        };

        if capsule_type != WT_CLOSE_SESSION {
            return Ok(());
        }

        let payload = close_payload.expect("close capsule retains its payload");
        let error_code = u32::from_be_bytes(
            payload[..4]
                .try_into()
                .expect("close payload length was validated"),
        );
        let message = String::from_utf8(payload[4..].to_vec())
            .map_err(|_| CapsuleError::InvalidUtf8)?;
        *close = Some(CloseCapsule {
            error_code,
            message,
        });
        self.state = CapsuleState::AfterClose;
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<(), CapsuleError> {
        match &self.state {
            CapsuleState::Type(decoder) if decoder.is_empty() => Ok(()),
            CapsuleState::AfterClose => Ok(()),
            _ => Err(CapsuleError::Truncated),
        }
    }
}

#[derive(Debug, Default)]
struct VarIntDecoder {
    bytes: [u8; 8],
    len: usize,
    expected: usize,
}

impl VarIntDecoder {
    fn consume(&mut self, input: &mut &[u8]) -> Option<u64> {
        if self.expected == 0 && !input.is_empty() {
            self.expected = 1 << (input[0] >> 6);
        }

        let take = (self.expected.saturating_sub(self.len)).min(input.len());
        self.bytes[self.len..self.len + take].copy_from_slice(&input[..take]);
        self.len += take;
        *input = &input[take..];

        if self.expected == 0 || self.len != self.expected {
            return None;
        }

        octets::Octets::with_slice(&self.bytes[..self.len])
            .get_varint()
            .ok()
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeLimits {
    pub(crate) max_pending_streams: usize,
    pub(crate) max_pending_streams_per_session: usize,
    pub(crate) max_stream_waiters: usize,
    pub(crate) max_datagram_waiters: usize,
    pub(crate) max_pending_datagrams: usize,
    pub(crate) max_pending_datagrams_per_session: usize,
    pub(crate) max_pending_datagram_bytes: usize,
    pub(crate) max_pending_datagram_bytes_per_session: usize,
    pub(crate) max_pending_datagram_allocation_bytes: usize,
    pub(crate) max_pending_datagram_allocation_bytes_per_session: usize,
    pub(crate) max_pending_datagram_age: Duration,
    pub(crate) command_capacity: usize,
    pub(crate) max_command_payload_bytes: usize,
    pub(crate) max_write_lease_retained_bytes_per_lease: usize,
    pub(crate) max_session_work_per_callback: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnedStream {
    session_id: u64,
    direction: WebTransportStreamDirection,
    local_prefix_len: u64,
    locally_initiated: bool,
}

#[derive(Debug)]
struct OpeningStream {
    reservation: quiche::h3::WebTransportStreamReservation,
    prefix_offset: usize,
    reset_after_prefix: Option<u64>,
    response: Option<oneshot::Sender<WebTransportOpenStreamOutcome>>,
}

#[derive(Debug)]
struct QueuedDatagram {
    received_at: Instant,
    datagram: DgramBuffer,
}

#[derive(Debug, Default)]
struct SessionDatagrams {
    queue: VecDeque<QueuedDatagram>,
    bytes: usize,
    allocation_bytes: usize,
    dropped_datagrams: u64,
    dropped_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SessionPhase {
    Pending,
    Active,
    Closing {
        close: CloseCapsule,
        output_queued: bool,
    },
    Terminal,
}

#[derive(Debug)]
struct Session {
    phase: SessionPhase,
    application_visible: bool,
    parser: CapsuleParser,
    streams: BTreeSet<u64>,
    capsules_negotiated: bool,
    connect_recv_closed: bool,
    connect_send_closed: bool,
    peer_close_received: bool,
    peer_close_fin_pending: bool,
    terminal_stream_error: u64,
}

impl Session {
    fn pending(application_visible: bool) -> Self {
        Self {
            phase: SessionPhase::Pending,
            application_visible,
            parser: CapsuleParser::default(),
            streams: BTreeSet::new(),
            capsules_negotiated: false,
            connect_recv_closed: false,
            connect_send_closed: false,
            peer_close_received: false,
            peer_close_fin_pending: false,
            terminal_stream_error: WT_SESSION_GONE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionWork {
    Admit(u64),
    Terminate { session_id: u64, error_code: u64 },
}

#[derive(Debug)]
pub(crate) struct Runtime {
    limits: RuntimeLimits,
    write_lease_accounting: Arc<WriteLeaseAccounting>,
    sessions: BTreeMap<u64, Session>,
    pending_streams: BTreeMap<u64, AssociatedStream>,
    pending_by_session: BTreeMap<u64, BTreeSet<u64>>,
    stream_sessions: BTreeMap<u64, OwnedStream>,
    opening_streams: BTreeMap<u64, OpeningStream>,
    opening_order: VecDeque<u64>,
    opening_by_session: BTreeMap<u64, BTreeSet<u64>>,
    readable_waiters:
        BTreeMap<u64, oneshot::Sender<WebTransportStreamReadyOutcome>>,
    writable_waiters:
        BTreeMap<u64, oneshot::Sender<WebTransportStreamReadyOutcome>>,
    datagram_readable_waiters:
        BTreeMap<u64, oneshot::Sender<WebTransportDatagramReadyOutcome>>,
    datagram_send_waiters:
        BTreeMap<u64, oneshot::Sender<WebTransportDatagramReadyOutcome>>,
    datagrams: BTreeMap<u64, SessionDatagrams>,
    provisional_deadlines: BTreeSet<(Instant, u64)>,
    legacy_sessions: VecDeque<u64>,
    legacy_session_set: BTreeSet<u64>,
    pending_datagram_count: usize,
    pending_datagram_bytes: usize,
    pending_datagram_allocation_bytes: usize,
    datagram_stats: WebTransportDatagramStats,
    non_session_requests: BTreeSet<u64>,
    work: VecDeque<SessionWork>,
    deferred_responses: BTreeSet<u64>,
    maintenance_cursor: Option<u64>,
    #[cfg(test)]
    commit_errors: VecDeque<quiche::h3::Error>,
}

impl Runtime {
    #[cfg(test)]
    pub(crate) fn new(limits: RuntimeLimits) -> Self {
        let write_lease_accounting = Arc::new(WriteLeaseAccounting::new(
            limits.command_capacity,
            limits.max_write_lease_retained_bytes_per_lease,
        ));
        Self::new_with_write_lease_accounting(limits, write_lease_accounting)
    }

    pub(crate) fn new_with_write_lease_accounting(
        limits: RuntimeLimits, write_lease_accounting: Arc<WriteLeaseAccounting>,
    ) -> Self {
        Self {
            limits: RuntimeLimits {
                max_session_work_per_callback: limits
                    .max_session_work_per_callback
                    .max(1),
                ..limits
            },
            write_lease_accounting,
            sessions: BTreeMap::new(),
            pending_streams: BTreeMap::new(),
            pending_by_session: BTreeMap::new(),
            stream_sessions: BTreeMap::new(),
            opening_streams: BTreeMap::new(),
            opening_order: VecDeque::new(),
            opening_by_session: BTreeMap::new(),
            readable_waiters: BTreeMap::new(),
            writable_waiters: BTreeMap::new(),
            datagram_readable_waiters: BTreeMap::new(),
            datagram_send_waiters: BTreeMap::new(),
            datagrams: BTreeMap::new(),
            provisional_deadlines: BTreeSet::new(),
            legacy_sessions: VecDeque::new(),
            legacy_session_set: BTreeSet::new(),
            pending_datagram_count: 0,
            pending_datagram_bytes: 0,
            pending_datagram_allocation_bytes: 0,
            datagram_stats: WebTransportDatagramStats::default(),
            non_session_requests: BTreeSet::new(),
            work: VecDeque::new(),
            deferred_responses: BTreeSet::new(),
            maintenance_cursor: None,
            #[cfg(test)]
            commit_errors: VecDeque::new(),
        }
    }

    pub(crate) fn observe_request(
        &mut self, session_id: u64, is_webtransport: bool,
    ) -> RequestObservation {
        self.observe_request_with_visibility(session_id, is_webtransport, true)
    }

    pub(crate) fn observe_deferred_request(
        &mut self, session_id: u64,
    ) -> RequestObservation {
        self.observe_request_with_visibility(session_id, true, false)
    }

    fn observe_request_with_visibility(
        &mut self, session_id: u64, is_webtransport: bool,
        application_visible: bool,
    ) -> RequestObservation {
        if !is_webtransport {
            self.non_session_requests.insert(session_id);
            self.reject_orphaned_pending(session_id);
            self.release_provisional_to_legacy(session_id);
            return RequestObservation::Observed(Vec::new());
        }

        if self.sessions.contains_key(&session_id) {
            return RequestObservation::Observed(Vec::new());
        }

        if !self.can_start_session() {
            self.reject_unadmitted_request(session_id);
            return RequestObservation::Excessive;
        }

        self.sessions
            .insert(session_id, Session::pending(application_visible));
        let events = application_visible
            .then_some(WebTransportSessionEvent::Pending { session_id })
            .into_iter()
            .collect();
        RequestObservation::Observed(events)
    }

    pub(crate) fn can_start_session(&self) -> bool {
        self.sessions
            .values()
            .all(|session| matches!(session.phase, SessionPhase::Terminal))
    }

    pub(crate) fn make_application_visible(
        &mut self, session_id: u64,
    ) -> Vec<WebTransportSessionEvent> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Vec::new();
        };
        if session.phase != SessionPhase::Pending || session.application_visible {
            return Vec::new();
        }
        session.application_visible = true;
        vec![WebTransportSessionEvent::Pending { session_id }]
    }

    pub(crate) fn reject_unadmitted_request(&mut self, session_id: u64) {
        self.reject_orphaned_pending(session_id);
        self.release_datagrams(session_id);
    }

    pub(crate) fn capsule_read_mode(&self, session_id: u64) -> CapsuleReadMode {
        match self.sessions.get(&session_id) {
            Some(session) if session.phase == SessionPhase::Pending =>
                CapsuleReadMode::Defer,
            Some(session) if session.capsules_negotiated =>
                CapsuleReadMode::Parse,
            Some(_) => CapsuleReadMode::Discard,
            None => CapsuleReadMode::Regular,
        }
    }

    pub(crate) fn activate(
        &mut self, session_id: u64,
    ) -> Vec<WebTransportSessionEvent> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Vec::new();
        };
        if session.phase != SessionPhase::Pending {
            return Vec::new();
        }
        let application_visible = session.application_visible;
        session.phase = SessionPhase::Active;
        session.capsules_negotiated = true;
        self.remove_provisional_deadline(session_id);
        if self.pending_by_session.contains_key(&session_id) {
            self.work.push_back(SessionWork::Admit(session_id));
        }
        application_visible
            .then_some(WebTransportSessionEvent::Accepted { session_id })
            .into_iter()
            .collect()
    }

    pub(crate) fn reject(
        &mut self, session_id: u64, status: u16,
    ) -> Vec<WebTransportSessionEvent> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Vec::new();
        };
        if session.phase != SessionPhase::Pending {
            return Vec::new();
        }
        let application_visible = session.application_visible;
        session.phase = SessionPhase::Terminal;
        session.terminal_stream_error = WT_BUFFERED_STREAM_REJECTED;
        self.work.push_back(SessionWork::Terminate {
            session_id,
            error_code: WT_BUFFERED_STREAM_REJECTED,
        });
        self.cancel_openings(
            session_id,
            WT_BUFFERED_STREAM_REJECTED,
            WebTransportSelectionError::TerminalSession,
        );
        self.reject_session_waiters(
            session_id,
            WebTransportSelectionError::TerminalSession,
        );
        self.release_datagrams(session_id);
        application_visible
            .then_some(WebTransportSessionEvent::Rejected { session_id, status })
            .into_iter()
            .collect()
    }

    pub(crate) fn response_accepted(
        &mut self, session_id: u64, status: u16,
    ) -> Vec<WebTransportSessionEvent> {
        if (100..200).contains(&status) {
            return Vec::new();
        }
        if (200..300).contains(&status) {
            return self.activate(session_id);
        }
        self.reject(session_id, status)
    }

    pub(crate) fn admission_failed(
        &mut self, session_id: u64,
    ) -> Vec<WebTransportSessionEvent> {
        if !self
            .sessions
            .get(&session_id)
            .is_some_and(|session| session.phase == SessionPhase::Pending)
        {
            return Vec::new();
        }
        self.terminate(
            session_id,
            WebTransportSessionCloseReason::AdmissionFailed,
        )
    }

    pub(crate) fn begin_local_close(
        &mut self, session_id: u64, close: CloseCapsule,
    ) -> bool {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return false;
        };
        if session.phase != SessionPhase::Active {
            return false;
        }
        session.phase = SessionPhase::Closing {
            close,
            output_queued: false,
        };
        self.cancel_openings(
            session_id,
            WT_SESSION_GONE,
            WebTransportSelectionError::ClosingSession,
        );
        self.reject_session_waiters(
            session_id,
            WebTransportSelectionError::ClosingSession,
        );
        self.release_datagrams(session_id);
        true
    }

    pub(crate) fn take_local_close_output(
        &mut self, session_id: u64,
    ) -> Option<Bytes> {
        let session = self.sessions.get_mut(&session_id)?;
        let SessionPhase::Closing {
            close,
            output_queued,
        } = &mut session.phase
        else {
            return None;
        };
        if *output_queued {
            return None;
        }
        *output_queued = true;
        Some(close.encode())
    }

    pub(crate) fn local_close_waiting(&self, session_id: u64) -> bool {
        self.sessions.get(&session_id).is_some_and(|session| {
            matches!(session.phase, SessionPhase::Closing {
                output_queued: false,
                ..
            })
        })
    }

    pub(crate) fn take_peer_close_fin(&mut self, session_id: u64) -> bool {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return false;
        };
        std::mem::take(&mut session.peer_close_fin_pending)
    }

    pub(crate) fn has_peer_close_fin(&self, session_id: u64) -> bool {
        self.sessions
            .get(&session_id)
            .is_some_and(|session| session.peer_close_fin_pending)
    }

    pub(crate) fn local_close_committed(
        &mut self, session_id: u64,
    ) -> Vec<WebTransportSessionEvent> {
        let Some(session) = self.sessions.get(&session_id) else {
            return Vec::new();
        };
        let SessionPhase::Closing { close, .. } = &session.phase else {
            return Vec::new();
        };
        let reason = WebTransportSessionCloseReason::Local {
            error_code: close.error_code,
            message: close.message.clone(),
        };
        let events = self.terminate(session_id, reason);
        self.mark_connect_send_closed(session_id);
        events
    }

    pub(crate) fn terminate(
        &mut self, session_id: u64, reason: WebTransportSessionCloseReason,
    ) -> Vec<WebTransportSessionEvent> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Vec::new();
        };
        if session.phase == SessionPhase::Terminal {
            return Vec::new();
        }
        let application_visible = session.application_visible;
        let error_code = if session.phase == SessionPhase::Pending {
            WT_BUFFERED_STREAM_REJECTED
        } else {
            WT_SESSION_GONE
        };
        session.peer_close_received =
            matches!(reason, WebTransportSessionCloseReason::Peer { .. });
        session.phase = SessionPhase::Terminal;
        session.terminal_stream_error = error_code;
        self.deferred_responses.remove(&session_id);
        self.work.push_back(SessionWork::Terminate {
            session_id,
            error_code,
        });
        self.cancel_openings(
            session_id,
            error_code,
            WebTransportSelectionError::TerminalSession,
        );
        self.reject_session_waiters(
            session_id,
            WebTransportSelectionError::TerminalSession,
        );
        self.release_datagrams(session_id);
        application_visible
            .then_some(WebTransportSessionEvent::Terminated {
                session_id,
                reason,
            })
            .into_iter()
            .collect()
    }

    pub(crate) fn classify(
        &mut self, stream: AssociatedStream, qconn: &mut QuicheConnection,
    ) -> Vec<WebTransportSessionEvent> {
        if self.pending_streams.contains_key(&stream.stream_id) ||
            self.stream_sessions.contains_key(&stream.stream_id)
        {
            return Vec::new();
        }

        match self.sessions.get(&stream.session_id).map(|s| &s.phase) {
            Some(SessionPhase::Active) => {
                self.admit_stream(stream);
                vec![associated_event(stream)]
            },
            Some(SessionPhase::Pending) => {
                if self.can_buffer(stream.session_id) {
                    self.buffer_stream(stream);
                } else {
                    shutdown_stream(qconn, stream, WT_BUFFERED_STREAM_REJECTED);
                }
                Vec::new()
            },
            Some(SessionPhase::Closing { .. } | SessionPhase::Terminal) => {
                shutdown_stream(qconn, stream, WT_SESSION_GONE);
                Vec::new()
            },
            None => {
                if !self.non_session_requests.contains(&stream.session_id) &&
                    !qconn.stream_closed(stream.session_id) &&
                    self.can_buffer(stream.session_id)
                {
                    self.buffer_stream(stream);
                } else {
                    shutdown_stream(qconn, stream, WT_BUFFERED_STREAM_REJECTED);
                }
                Vec::new()
            },
        }
    }

    fn can_buffer(&self, session_id: u64) -> bool {
        self.provisional_stream_count() < self.limits.max_pending_streams &&
            self.provisional_stream_count_for_session(session_id) <
                self.limits.max_pending_streams_per_session
    }

    fn provisional_stream_count(&self) -> usize {
        self.pending_streams
            .len()
            .saturating_add(self.opening_streams.len())
    }

    fn provisional_stream_count_for_session(&self, session_id: u64) -> usize {
        self.pending_by_session
            .get(&session_id)
            .map_or(0, BTreeSet::len)
            .saturating_add(
                self.opening_by_session
                    .get(&session_id)
                    .map_or(0, BTreeSet::len),
            )
    }

    fn buffer_stream(&mut self, stream: AssociatedStream) {
        self.pending_streams.insert(stream.stream_id, stream);
        self.pending_by_session
            .entry(stream.session_id)
            .or_default()
            .insert(stream.stream_id);
    }

    fn admit_stream(&mut self, stream: AssociatedStream) {
        self.stream_sessions.insert(stream.stream_id, OwnedStream {
            session_id: stream.session_id,
            direction: stream.direction,
            local_prefix_len: 0,
            locally_initiated: false,
        });
        if let Some(session) = self.sessions.get_mut(&stream.session_id) {
            session.streams.insert(stream.stream_id);
        }
    }

    fn reject_orphaned_pending(&mut self, session_id: u64) {
        if self.pending_by_session.contains_key(&session_id) {
            self.work.push_back(SessionWork::Terminate {
                session_id,
                error_code: WT_BUFFERED_STREAM_REJECTED,
            });
        }
    }

    pub(crate) fn parser_mut(
        &mut self, session_id: u64,
    ) -> Option<&mut CapsuleParser> {
        self.sessions.get_mut(&session_id).map(|s| &mut s.parser)
    }

    pub(crate) fn capsules_negotiated(&self, session_id: u64) -> bool {
        self.sessions
            .get(&session_id)
            .is_some_and(|session| session.capsules_negotiated)
    }

    pub(crate) fn mark_connect_recv_closed(
        &mut self, session_id: u64,
    ) -> Vec<WebTransportSessionEvent> {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Vec::new();
        };
        session.connect_recv_closed = true;
        if session.phase == SessionPhase::Terminal {
            session.peer_close_fin_pending = session.peer_close_received;
            self.work.push_back(SessionWork::Terminate {
                session_id,
                error_code: session.terminal_stream_error,
            });
            return Vec::new();
        }
        self.terminate(session_id, WebTransportSessionCloseReason::Clean)
    }

    pub(crate) fn cancel_peer_close_fin(&mut self, session_id: u64) {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return;
        };
        session.peer_close_received = false;
        session.peer_close_fin_pending = false;
    }

    pub(crate) fn mark_connect_send_closed(&mut self, session_id: u64) {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return;
        };
        session.connect_send_closed = true;
        if session.phase == SessionPhase::Terminal {
            self.work.push_back(SessionWork::Terminate {
                session_id,
                error_code: session.terminal_stream_error,
            });
        }
    }

    pub(crate) fn forget_non_session_request(&mut self, stream_id: u64) {
        self.non_session_requests.remove(&stream_id);
    }

    pub(crate) fn output_failed(
        &mut self, session_id: u64,
    ) -> Vec<WebTransportSessionEvent> {
        let Some(session) = self.sessions.get(&session_id) else {
            return Vec::new();
        };
        let reason = if session.phase == SessionPhase::Pending {
            WebTransportSessionCloseReason::AdmissionFailed
        } else {
            WebTransportSessionCloseReason::OutputFailed
        };
        self.terminate(session_id, reason)
    }

    pub(crate) fn is_session(&self, stream_id: u64) -> bool {
        self.sessions.contains_key(&stream_id)
    }

    pub(crate) fn is_active(&self, session_id: u64) -> bool {
        self.sessions
            .get(&session_id)
            .is_some_and(|s| s.phase == SessionPhase::Active)
    }

    pub(crate) fn is_pending(&self, session_id: u64) -> bool {
        self.sessions
            .get(&session_id)
            .is_some_and(|session| session.phase == SessionPhase::Pending)
    }

    #[cfg(test)]
    pub(crate) fn is_closing(&self, session_id: u64) -> bool {
        self.sessions.get(&session_id).is_some_and(|session| {
            matches!(session.phase, SessionPhase::Closing { .. })
        })
    }

    fn selection_error(
        &self, session_id: u64, qconn: &QuicheConnection,
    ) -> Option<WebTransportSelectionError> {
        match self.sessions.get(&session_id).map(|session| &session.phase) {
            Some(SessionPhase::Active) => None,
            Some(SessionPhase::Pending) =>
                Some(WebTransportSelectionError::PendingSession),
            Some(SessionPhase::Closing { .. }) =>
                Some(WebTransportSelectionError::ClosingSession),
            Some(SessionPhase::Terminal) =>
                Some(WebTransportSelectionError::TerminalSession),
            None if qconn.stream_closed(session_id) =>
                Some(WebTransportSelectionError::StaleSession),
            None => Some(WebTransportSelectionError::UnknownSession),
        }
    }

    fn datagram_error(
        &self, session_id: u64, qconn: &QuicheConnection,
    ) -> Option<WebTransportDatagramError> {
        self.selection_error(session_id, qconn)
            .map(|error| match error {
                WebTransportSelectionError::UnknownSession =>
                    WebTransportDatagramError::UnknownSession,
                WebTransportSelectionError::StaleSession =>
                    WebTransportDatagramError::StaleSession,
                WebTransportSelectionError::PendingSession =>
                    WebTransportDatagramError::PendingSession,
                WebTransportSelectionError::ClosingSession =>
                    WebTransportDatagramError::ClosingSession,
                WebTransportSelectionError::TerminalSession =>
                    WebTransportDatagramError::TerminalSession,
                WebTransportSelectionError::Unsupported =>
                    WebTransportDatagramError::Unsupported,
                WebTransportSelectionError::ConnectionClosed =>
                    WebTransportDatagramError::ConnectionClosed,
                _ => WebTransportDatagramError::UnknownSession,
            })
    }

    fn select_stream(
        &self, session_id: u64, stream_id: u64, write: bool,
        qconn: &QuicheConnection,
    ) -> Result<OwnedStream, WebTransportSelectionError> {
        if let Some(error) = self.selection_error(session_id, qconn) {
            return Err(error);
        }

        let Some(stream) = self.stream_sessions.get(&stream_id).copied() else {
            return Err(if qconn.stream_closed(stream_id) {
                WebTransportSelectionError::StaleStream
            } else {
                WebTransportSelectionError::UnknownStream
            });
        };
        if stream.session_id != session_id {
            return Err(WebTransportSelectionError::ForeignStream {
                owner_session_id: stream.session_id,
            });
        }

        let direction_allowed = stream.direction ==
            WebTransportStreamDirection::Bidi ||
            stream.locally_initiated == write;
        if !direction_allowed {
            return Err(WebTransportSelectionError::WrongDirection);
        }
        Ok(stream)
    }

    pub(crate) fn handle_command(
        &mut self, conn: &mut quiche::h3::Connection,
        qconn: &mut QuicheConnection, command: WebTransportCommand,
        queued_command_items: usize,
    ) {
        match command {
            WebTransportCommand::Open {
                session_id,
                direction,
                response,
            } => self.open_stream(conn, qconn, session_id, direction, response),
            WebTransportCommand::WriteLease(command) =>
                command.execute(self, qconn),
            WebTransportCommand::Read {
                session_id,
                stream_id,
                max_bytes,
                response,
            } => self
                .read_stream(qconn, session_id, stream_id, max_bytes, response),
            WebTransportCommand::Wait {
                session_id,
                stream_id,
                write,
                response,
            } => self.wait_stream(qconn, session_id, stream_id, write, response),
            WebTransportCommand::Reset {
                session_id,
                stream_id,
                error_code,
                response,
            } => self.control_stream(
                qconn, session_id, stream_id, error_code, true, response,
            ),
            WebTransportCommand::Stop {
                session_id,
                stream_id,
                error_code,
                response,
            } => self.control_stream(
                qconn, session_id, stream_id, error_code, false, response,
            ),
            WebTransportCommand::SendDatagram {
                session_id,
                datagram,
                response,
            } => self.send_datagram(qconn, session_id, datagram, response),
            WebTransportCommand::ReceiveDatagram {
                session_id,
                response,
            } => self.receive_datagram(qconn, session_id, response),
            WebTransportCommand::WaitDatagram {
                session_id,
                send,
                response,
            } => self.wait_datagram(qconn, session_id, send, response),
            WebTransportCommand::MaxDatagramPayload {
                session_id,
                response,
            } => {
                let _ =
                    response.send(self.max_datagram_payload(qconn, session_id));
            },
            WebTransportCommand::DatagramStats { response } => {
                let _ = response.send(Ok(self.datagram_stats()));
            },
            WebTransportCommand::RetentionStats { response } => {
                let _ = response
                    .send(Ok(self.retention_stats(qconn, queued_command_items)));
            },
        }
    }

    fn open_stream(
        &mut self, conn: &mut quiche::h3::Connection,
        qconn: &mut QuicheConnection, session_id: u64,
        direction: WebTransportStreamDirection,
        response: oneshot::Sender<WebTransportOpenStreamOutcome>,
    ) {
        if response.is_closed() {
            return;
        }
        if let Some(error) = self.selection_error(session_id, qconn) {
            let _ = response.send(WebTransportOpenStreamOutcome::Rejected(error));
            return;
        }
        if self.provisional_stream_count() >= self.limits.max_pending_streams ||
            self.provisional_stream_count_for_session(session_id) >=
                self.limits.max_pending_streams_per_session
        {
            let _ = response.send(WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            ));
            return;
        }

        let core_direction = match direction {
            WebTransportStreamDirection::Bidi =>
                quiche::h3::WebTransportStreamDirection::Bidirectional,
            WebTransportStreamDirection::Uni =>
                quiche::h3::WebTransportStreamDirection::Unidirectional,
        };
        let reservation = match conn.reserve_webtransport_stream(
            qconn,
            session_id,
            core_direction,
        ) {
            Ok(reservation) => reservation,
            Err(quiche::h3::Error::SettingsError) => {
                let _ = response.send(WebTransportOpenStreamOutcome::Rejected(
                    WebTransportSelectionError::Unsupported,
                ));
                return;
            },
            Err(quiche::h3::Error::TransportError(
                quiche::Error::StreamLimit,
            )) => {
                let _ = response.send(WebTransportOpenStreamOutcome::Rejected(
                    WebTransportSelectionError::ResourceLimit,
                ));
                return;
            },
            Err(_) => {
                let _ = response.send(WebTransportOpenStreamOutcome::Rejected(
                    WebTransportSelectionError::ConnectionClosed,
                ));
                return;
            },
        };
        let stream_id = reservation.stream_id();
        self.opening_streams.insert(stream_id, OpeningStream {
            reservation,
            prefix_offset: 0,
            reset_after_prefix: None,
            response: Some(response),
        });
        self.opening_order.push_back(stream_id);
        self.opening_by_session
            .entry(session_id)
            .or_default()
            .insert(stream_id);
    }

    pub(crate) fn process_opening_streams(
        &mut self, conn: &mut quiche::h3::Connection,
        qconn: &mut QuicheConnection, max_work: usize,
    ) -> usize {
        let mut work = 0;
        while work < max_work {
            let Some(stream_id) = self.opening_order.pop_front() else {
                break;
            };
            let Some(mut opening) = self.opening_streams.remove(&stream_id)
            else {
                continue;
            };
            work += 1;

            let session_id = opening.reservation.session_id();
            if opening
                .response
                .as_ref()
                .is_some_and(oneshot::Sender::is_closed)
            {
                opening.response = None;
                opening.reset_after_prefix = Some(WT_SESSION_GONE);
            }
            if !self.is_active(session_id) {
                if let Some(response) = opening.response.take() {
                    let _ =
                        response.send(WebTransportOpenStreamOutcome::Rejected(
                            WebTransportSelectionError::TerminalSession,
                        ));
                }
                opening.reset_after_prefix = Some(WT_SESSION_GONE);
            }

            let prefix = opening.reservation.prefix();
            if opening.prefix_offset < prefix.len() {
                match qconn.stream_send(
                    stream_id,
                    &prefix[opening.prefix_offset..],
                    false,
                ) {
                    Ok(written) => opening.prefix_offset += written,
                    Err(quiche::Error::Done | quiche::Error::StreamLimit) => {
                        self.requeue_opening(stream_id, opening);
                        continue;
                    },
                    Err(quiche::Error::StreamStopped(error_code)) => {
                        if let Some(response) = opening.response.take() {
                            let _ = response.send(
                                WebTransportOpenStreamOutcome::ResetRequired {
                                    wire_error_code: error_code,
                                    application_error_code:
                                        webtransport_error_from_http3(error_code),
                                },
                            );
                        }
                        shutdown_opening_stream(
                            qconn,
                            &opening.reservation,
                            error_code,
                        );
                        self.finish_opening(session_id, stream_id);
                        continue;
                    },
                    Err(_) => {
                        if let Some(response) = opening.response.take() {
                            let _ =
                                response
                                    .send(WebTransportOpenStreamOutcome::Rejected(
                                    WebTransportSelectionError::ConnectionClosed,
                                ));
                        }
                        self.finish_opening(session_id, stream_id);
                        continue;
                    },
                }
            }

            if opening.prefix_offset != prefix.len() {
                self.requeue_opening(stream_id, opening);
                continue;
            }
            match self.commit_opening(conn, qconn, &opening.reservation) {
                Ok(()) => {},
                Err(error) if commit_error_is_retryable(error) => {
                    self.requeue_opening(stream_id, opening);
                    continue;
                },
                Err(_) => {
                    if let Some(response) = opening.response.take() {
                        let _ = response.send(
                            WebTransportOpenStreamOutcome::Rejected(
                                WebTransportSelectionError::InternalFailure,
                            ),
                        );
                    }
                    shutdown_opening_stream(
                        qconn,
                        &opening.reservation,
                        WT_SESSION_GONE,
                    );
                    self.finish_opening(session_id, stream_id);
                    continue;
                },
            }

            if let Ok(quiche::StreamSendStatus::Stopped(error_code)) =
                qconn.stream_send_status(stream_id)
            {
                if let Some(response) = opening.response.take() {
                    let _ = response.send(
                        WebTransportOpenStreamOutcome::ResetRequired {
                            wire_error_code: error_code,
                            application_error_code: webtransport_error_from_http3(
                                error_code,
                            ),
                        },
                    );
                }
                shutdown_opening_stream(qconn, &opening.reservation, error_code);
                self.finish_opening(session_id, stream_id);
                continue;
            }

            if let Some(error_code) = opening.reset_after_prefix {
                shutdown_opening_stream(qconn, &opening.reservation, error_code);
                self.finish_opening(session_id, stream_id);
                continue;
            }

            let owned = OwnedStream {
                session_id,
                direction: match opening.reservation.direction() {
                    quiche::h3::WebTransportStreamDirection::Bidirectional =>
                        WebTransportStreamDirection::Bidi,
                    quiche::h3::WebTransportStreamDirection::Unidirectional =>
                        WebTransportStreamDirection::Uni,
                },
                local_prefix_len: opening.reservation.prefix_len() as u64,
                locally_initiated: true,
            };
            self.stream_sessions.insert(stream_id, owned);
            if let Some(session) = self.sessions.get_mut(&session_id) {
                session.streams.insert(stream_id);
            }
            let delivered = opening.response.take().is_some_and(|response| {
                response
                    .send(WebTransportOpenStreamOutcome::Opened { stream_id })
                    .is_ok()
            });
            if !delivered {
                self.stream_sessions.remove(&stream_id);
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    session.streams.remove(&stream_id);
                }
                shutdown_owned_stream(qconn, stream_id, owned, WT_SESSION_GONE);
            }
            self.finish_opening(session_id, stream_id);
        }
        work
    }

    fn requeue_opening(&mut self, stream_id: u64, opening: OpeningStream) {
        self.opening_streams.insert(stream_id, opening);
        self.opening_order.push_back(stream_id);
    }

    fn commit_opening(
        &mut self, conn: &mut quiche::h3::Connection,
        qconn: &mut QuicheConnection,
        reservation: &quiche::h3::WebTransportStreamReservation,
    ) -> quiche::h3::Result<()> {
        #[cfg(test)]
        if let Some(error) = self.commit_errors.pop_front() {
            return Err(error);
        }
        conn.commit_webtransport_stream(qconn, reservation)
    }

    fn finish_opening(&mut self, session_id: u64, stream_id: u64) {
        if let Some(streams) = self.opening_by_session.get_mut(&session_id) {
            streams.remove(&stream_id);
            if streams.is_empty() {
                self.opening_by_session.remove(&session_id);
            }
        }
    }

    fn wait_stream(
        &mut self, qconn: &QuicheConnection, session_id: u64, stream_id: u64,
        write: bool, response: oneshot::Sender<WebTransportStreamReadyOutcome>,
    ) {
        if response.is_closed() {
            return;
        }
        if let Some(outcome) =
            self.stream_ready_outcome(qconn, session_id, stream_id, write)
        {
            let _ = response.send(outcome);
            return;
        }

        let waiter_count = self
            .readable_waiters
            .len()
            .saturating_add(self.writable_waiters.len());
        let duplicate = if write {
            self.writable_waiters.contains_key(&stream_id)
        } else {
            self.readable_waiters.contains_key(&stream_id)
        };
        if waiter_count >= self.limits.max_stream_waiters || duplicate {
            let _ = response.send(WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            ));
            return;
        }
        let waiters = if write {
            &mut self.writable_waiters
        } else {
            &mut self.readable_waiters
        };
        waiters.insert(stream_id, response);
    }

    fn stream_ready_outcome(
        &self, qconn: &QuicheConnection, session_id: u64, stream_id: u64,
        write: bool,
    ) -> Option<WebTransportStreamReadyOutcome> {
        if let Err(error) =
            self.select_stream(session_id, stream_id, write, qconn)
        {
            return Some(WebTransportStreamReadyOutcome::Rejected(error));
        }

        if !write {
            if qconn.stream_readable(stream_id) {
                return Some(WebTransportStreamReadyOutcome::Ready);
            }
            return (qconn.stream_finished(stream_id) ||
                qconn.stream_closed(stream_id))
            .then_some(WebTransportStreamReadyOutcome::Closed);
        }

        match qconn.stream_send_status(stream_id) {
            Ok(quiche::StreamSendStatus::Writable(_)) =>
                Some(WebTransportStreamReadyOutcome::Ready),
            Ok(quiche::StreamSendStatus::Blocked) => None,
            Ok(quiche::StreamSendStatus::Stopped(error_code)) =>
                Some(WebTransportStreamReadyOutcome::ResetRequired {
                    wire_error_code: error_code,
                    application_error_code: webtransport_error_from_http3(
                        error_code,
                    ),
                }),
            Ok(quiche::StreamSendStatus::Closed) | Err(_) =>
                Some(WebTransportStreamReadyOutcome::Closed),
        }
    }

    fn wake_stream_waiter(
        &mut self, qconn: &QuicheConnection, stream_id: u64, write: bool,
    ) {
        let Some(stream) = self.stream_sessions.get(&stream_id).copied() else {
            return;
        };
        let Some(outcome) =
            self.stream_ready_outcome(qconn, stream.session_id, stream_id, write)
        else {
            return;
        };
        let response = if write {
            self.writable_waiters.remove(&stream_id)
        } else {
            self.readable_waiters.remove(&stream_id)
        };
        if let Some(response) = response {
            let _ = response.send(outcome);
        }
    }

    fn reject_stream_waiters(
        &mut self, stream_id: u64, error: WebTransportSelectionError,
    ) {
        let outcome = WebTransportStreamReadyOutcome::Rejected(error);
        if let Some(response) = self.readable_waiters.remove(&stream_id) {
            let _ = response.send(outcome);
        }
        if let Some(response) = self.writable_waiters.remove(&stream_id) {
            let _ = response.send(outcome);
        }
    }

    fn close_stream_waiters(&mut self, stream_id: u64) {
        if let Some(response) = self.readable_waiters.remove(&stream_id) {
            let _ = response.send(WebTransportStreamReadyOutcome::Closed);
        }
        if let Some(response) = self.writable_waiters.remove(&stream_id) {
            let _ = response.send(WebTransportStreamReadyOutcome::Closed);
        }
    }

    fn reject_session_waiters(
        &mut self, session_id: u64, error: WebTransportSelectionError,
    ) {
        let stream_ids: Vec<_> = self
            .sessions
            .get(&session_id)
            .into_iter()
            .flat_map(|session| session.streams.iter().copied())
            .collect();
        for stream_id in stream_ids {
            self.reject_stream_waiters(stream_id, error);
        }

        let datagram_error = datagram_error_from_selection(error);
        let outcome = WebTransportDatagramReadyOutcome::Rejected(datagram_error);
        if let Some(response) = self.datagram_readable_waiters.remove(&session_id)
        {
            let _ = response.send(outcome);
        }
        if let Some(response) = self.datagram_send_waiters.remove(&session_id) {
            let _ = response.send(outcome);
        }
    }

    pub(crate) fn process_owned_readable(
        &mut self, qconn: &QuicheConnection, stream_id: u64,
    ) -> bool {
        if !self.owns_stream(stream_id) {
            return false;
        }
        self.wake_stream_waiter(qconn, stream_id, false);
        true
    }

    fn cancel_openings(
        &mut self, session_id: u64, error_code: u64,
        selection_error: WebTransportSelectionError,
    ) {
        let stream_ids: Vec<_> = self
            .opening_by_session
            .get(&session_id)
            .into_iter()
            .flatten()
            .copied()
            .collect();
        for stream_id in stream_ids {
            let Some(opening) = self.opening_streams.get_mut(&stream_id) else {
                continue;
            };
            if let Some(response) = opening.response.take() {
                let _ = response.send(WebTransportOpenStreamOutcome::Rejected(
                    selection_error,
                ));
            }
            opening.reset_after_prefix = Some(error_code);
        }
    }

    fn release_datagrams(&mut self, session_id: u64) {
        self.remove_provisional_deadline(session_id);
        let Some(datagrams) = self.datagrams.remove(&session_id) else {
            return;
        };
        self.datagram_stats.terminal_datagrams = self
            .datagram_stats
            .terminal_datagrams
            .saturating_add(datagrams.queue.len() as u64);
        self.datagram_stats.terminal_bytes = self
            .datagram_stats
            .terminal_bytes
            .saturating_add(datagrams.bytes as u64);
        self.pending_datagram_count = self
            .pending_datagram_count
            .saturating_sub(datagrams.queue.len());
        self.pending_datagram_bytes =
            self.pending_datagram_bytes.saturating_sub(datagrams.bytes);
        self.pending_datagram_allocation_bytes = self
            .pending_datagram_allocation_bytes
            .saturating_sub(datagrams.allocation_bytes);
    }

    fn release_provisional_to_legacy(&mut self, session_id: u64) {
        self.remove_provisional_deadline(session_id);
        let ready = self
            .datagrams
            .get(&session_id)
            .is_some_and(|datagrams| !datagrams.queue.is_empty());
        if ready && self.legacy_session_set.insert(session_id) {
            self.legacy_sessions.push_back(session_id);
        }
    }

    fn remove_provisional_deadline(&mut self, session_id: u64) {
        let Some(received_at) = self
            .datagrams
            .get(&session_id)
            .and_then(|queue| queue.queue.front())
            .map(|queued| queued.received_at)
        else {
            return;
        };
        let deadline = received_at
            .checked_add(self.limits.max_pending_datagram_age)
            .unwrap_or(received_at);
        self.provisional_deadlines.remove(&(deadline, session_id));
    }

    fn index_provisional_deadline(&mut self, session_id: u64) {
        let Some(received_at) = self
            .datagrams
            .get(&session_id)
            .and_then(|queue| queue.queue.front())
            .map(|queued| queued.received_at)
        else {
            return;
        };
        let deadline = received_at
            .checked_add(self.limits.max_pending_datagram_age)
            .unwrap_or(received_at);
        self.provisional_deadlines.insert((deadline, session_id));
    }

    fn read_stream(
        &self, qconn: &mut QuicheConnection, session_id: u64, stream_id: u64,
        max_bytes: usize,
        response: oneshot::Sender<WebTransportStreamReadOutcome>,
    ) {
        if response.is_closed() {
            return;
        }
        if let Err(error) =
            self.select_stream(session_id, stream_id, false, qconn)
        {
            let _ = response.send(WebTransportStreamReadOutcome::Rejected(error));
            return;
        }

        let mut output = Vec::with_capacity(max_bytes).limit(max_bytes);
        let outcome = match qconn.stream_recv_buf(stream_id, &mut output) {
            Ok((_, fin)) => WebTransportStreamReadOutcome::Data {
                data: Bytes::from(output.into_inner()),
                fin,
            },
            Err(quiche::Error::Done) => WebTransportStreamReadOutcome::Blocked,
            Err(quiche::Error::StreamReset(error_code)) =>
                WebTransportStreamReadOutcome::Reset {
                    wire_error_code: error_code,
                    application_error_code: webtransport_error_from_http3(
                        error_code,
                    ),
                },
            Err(_) => WebTransportStreamReadOutcome::Rejected(
                WebTransportSelectionError::StaleStream,
            ),
        };
        let _ = response.send(outcome);
    }

    fn control_stream(
        &self, qconn: &mut QuicheConnection, session_id: u64, stream_id: u64,
        error_code: u32, reset: bool,
        response: oneshot::Sender<WebTransportStreamControlOutcome>,
    ) {
        if response.is_closed() {
            return;
        }
        let stream = match self.select_stream(session_id, stream_id, reset, qconn)
        {
            Ok(stream) => stream,
            Err(error) => {
                let _ = response
                    .send(WebTransportStreamControlOutcome::Rejected(error));
                return;
            },
        };
        let wire_error = webtransport_error_to_http3(error_code);
        let result = if reset {
            qconn.stream_shutdown_at(
                stream_id,
                wire_error,
                stream.local_prefix_len,
            )
        } else {
            qconn.stream_shutdown(stream_id, quiche::Shutdown::Read, wire_error)
        };
        let outcome = match result {
            Ok(()) => WebTransportStreamControlOutcome::Applied,
            Err(quiche::Error::Done | quiche::Error::InvalidStreamState(_)) =>
                WebTransportStreamControlOutcome::Closed,
            Err(_) => WebTransportStreamControlOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            ),
        };
        let _ = response.send(outcome);
    }

    fn max_datagram_payload(
        &self, qconn: &QuicheConnection, session_id: u64,
    ) -> Result<usize, WebTransportDatagramError> {
        if let Some(error) = self.datagram_error(session_id, qconn) {
            return Err(error);
        }
        super::datagram::max_h3_dgram_payload(qconn, session_id / 4)
            .ok_or(WebTransportDatagramError::Unsupported)
    }

    fn send_datagram(
        &self, qconn: &mut QuicheConnection, session_id: u64,
        datagram: DgramBuffer,
        response: oneshot::Sender<WebTransportDatagramSendOutcome>,
    ) {
        if response.is_closed() {
            return;
        }
        let max = match self.max_datagram_payload(qconn, session_id) {
            Ok(max) => max,
            Err(error) => {
                let _ =
                    response.send(WebTransportDatagramSendOutcome::Rejected {
                        error,
                        datagram,
                    });
                return;
            },
        };
        if datagram.as_slice().len() > max {
            let _ = response.send(WebTransportDatagramSendOutcome::TooLarge {
                max,
                datagram,
            });
            return;
        }
        let outcome = match super::datagram::send_h3_dgram_unicast(
            qconn,
            session_id / 4,
            datagram,
        ) {
            Ok(()) => WebTransportDatagramSendOutcome::Accepted,
            Err((quiche::Error::Done, datagram)) =>
                WebTransportDatagramSendOutcome::Blocked(datagram),
            Err((quiche::Error::BufferTooShort, datagram)) =>
                WebTransportDatagramSendOutcome::TooLarge { max, datagram },
            Err((_, datagram)) => WebTransportDatagramSendOutcome::Rejected {
                error: WebTransportDatagramError::ConnectionClosed,
                datagram,
            },
        };
        let _ = response.send(outcome);
    }

    fn receive_datagram(
        &mut self, qconn: &QuicheConnection, session_id: u64,
        response: oneshot::Sender<WebTransportDatagramReadOutcome>,
    ) {
        if response.is_closed() {
            return;
        }
        if let Some(error) = self.datagram_error(session_id, qconn) {
            let _ =
                response.send(WebTransportDatagramReadOutcome::Rejected(error));
            return;
        }
        let queue = self.datagrams.entry(session_id).or_default();
        let outcome = if queue.dropped_datagrams != 0 {
            WebTransportDatagramReadOutcome::Overflow {
                datagrams: std::mem::take(&mut queue.dropped_datagrams),
                bytes: std::mem::take(&mut queue.dropped_bytes),
            }
        } else if let Some(queued) = queue.queue.pop_front() {
            let len = queued.datagram.as_slice().len();
            let allocation = queued.datagram.allocated_capacity();
            queue.bytes = queue.bytes.saturating_sub(len);
            queue.allocation_bytes =
                queue.allocation_bytes.saturating_sub(allocation);
            self.pending_datagram_count =
                self.pending_datagram_count.saturating_sub(1);
            self.pending_datagram_bytes =
                self.pending_datagram_bytes.saturating_sub(len);
            self.pending_datagram_allocation_bytes = self
                .pending_datagram_allocation_bytes
                .saturating_sub(allocation);
            WebTransportDatagramReadOutcome::Datagram(queued.datagram)
        } else {
            WebTransportDatagramReadOutcome::Blocked
        };
        let _ = response.send(outcome);
    }

    fn wake_datagram_readable(
        &mut self, qconn: &QuicheConnection, session_id: u64,
    ) {
        let Some(outcome) = self.datagram_ready_outcome(qconn, session_id, false)
        else {
            return;
        };
        if let Some(response) = self.datagram_readable_waiters.remove(&session_id)
        {
            let _ = response.send(outcome);
        }
    }

    fn wait_datagram(
        &mut self, qconn: &QuicheConnection, session_id: u64, send: bool,
        response: oneshot::Sender<WebTransportDatagramReadyOutcome>,
    ) {
        if response.is_closed() {
            return;
        }
        if let Some(outcome) =
            self.datagram_ready_outcome(qconn, session_id, send)
        {
            let _ = response.send(outcome);
            return;
        }

        let waiter_count = self
            .datagram_readable_waiters
            .len()
            .saturating_add(self.datagram_send_waiters.len());
        let duplicate = if send {
            self.datagram_send_waiters.contains_key(&session_id)
        } else {
            self.datagram_readable_waiters.contains_key(&session_id)
        };
        if waiter_count >= self.limits.max_datagram_waiters || duplicate {
            let _ =
                response.send(WebTransportDatagramReadyOutcome::ResourceLimit);
            return;
        }
        let waiters = if send {
            &mut self.datagram_send_waiters
        } else {
            &mut self.datagram_readable_waiters
        };
        waiters.insert(session_id, response);
    }

    fn datagram_ready_outcome(
        &self, qconn: &QuicheConnection, session_id: u64, send: bool,
    ) -> Option<WebTransportDatagramReadyOutcome> {
        if let Some(error) = self.datagram_error(session_id, qconn) {
            return Some(WebTransportDatagramReadyOutcome::Rejected(error));
        }

        let ready = if send {
            self.max_datagram_payload(qconn, session_id).is_ok() &&
                !qconn.is_dgram_send_queue_full()
        } else {
            self.datagrams.get(&session_id).is_some_and(|queue| {
                queue.dropped_datagrams != 0 || !queue.queue.is_empty()
            })
        };
        ready.then_some(WebTransportDatagramReadyOutcome::Ready)
    }

    pub(crate) fn has_ready_datagram_waiter(
        &self, qconn: &QuicheConnection,
    ) -> bool {
        self.datagram_readable_waiters.keys().any(|session_id| {
            self.datagram_ready_outcome(qconn, *session_id, false)
                .is_some()
        }) || self.datagram_send_waiters.keys().any(|session_id| {
            self.datagram_ready_outcome(qconn, *session_id, true)
                .is_some()
        })
    }

    pub(crate) fn process_datagram_waiters(&mut self, qconn: &QuicheConnection) {
        let readable: Vec<_> =
            self.datagram_readable_waiters.keys().copied().collect();
        for session_id in readable {
            let Some(outcome) =
                self.datagram_ready_outcome(qconn, session_id, false)
            else {
                continue;
            };
            if let Some(response) =
                self.datagram_readable_waiters.remove(&session_id)
            {
                let _ = response.send(outcome);
            }
        }

        let writable: Vec<_> =
            self.datagram_send_waiters.keys().copied().collect();
        for session_id in writable {
            let Some(outcome) =
                self.datagram_ready_outcome(qconn, session_id, true)
            else {
                continue;
            };
            if let Some(response) = self.datagram_send_waiters.remove(&session_id)
            {
                let _ = response.send(outcome);
            }
        }
    }

    pub(crate) fn route_datagram(
        &mut self, qconn: &QuicheConnection, session_id: u64,
        datagram: DgramBuffer,
    ) -> Option<DgramBuffer> {
        self.route_datagram_at(qconn, session_id, datagram, Instant::now())
    }

    fn route_datagram_at(
        &mut self, qconn: &QuicheConnection, session_id: u64,
        datagram: DgramBuffer, received_at: Instant,
    ) -> Option<DgramBuffer> {
        if self.non_session_requests.contains(&session_id) {
            return Some(datagram);
        }
        let provisional = match self.sessions.get(&session_id) {
            Some(session) if session.phase == SessionPhase::Active => false,
            Some(session) if session.phase == SessionPhase::Pending => true,
            Some(_) => {
                self.record_terminal_datagram(&datagram);
                return None;
            },
            None if qconn.stream_closed(session_id) => {
                self.record_terminal_datagram(&datagram);
                return None;
            },
            None => true,
        };

        let len = datagram.as_slice().len();
        let allocation = datagram.allocated_capacity();
        let (session_datagrams, session_bytes, session_allocation_bytes) =
            self.datagrams.get(&session_id).map_or((0, 0, 0), |queue| {
                (queue.queue.len(), queue.bytes, queue.allocation_bytes)
            });
        let full = self.pending_datagram_count >=
            self.limits.max_pending_datagrams ||
            session_datagrams >= self.limits.max_pending_datagrams_per_session ||
            self.pending_datagram_bytes.saturating_add(len) >
                self.limits.max_pending_datagram_bytes ||
            session_bytes.saturating_add(len) >
                self.limits.max_pending_datagram_bytes_per_session ||
            self.pending_datagram_allocation_bytes
                .saturating_add(allocation) >
                self.limits.max_pending_datagram_allocation_bytes ||
            session_allocation_bytes.saturating_add(allocation) >
                self.limits
                    .max_pending_datagram_allocation_bytes_per_session;
        if full {
            if let Some(queue) = self.datagrams.get_mut(&session_id) {
                queue.dropped_datagrams =
                    queue.dropped_datagrams.saturating_add(1);
                queue.dropped_bytes =
                    queue.dropped_bytes.saturating_add(len as u64);
            } else if self.sessions.contains_key(&session_id) {
                let queue = self.datagrams.entry(session_id).or_default();
                queue.dropped_datagrams = 1;
                queue.dropped_bytes = len as u64;
            }
            self.datagram_stats.overflow_datagrams =
                self.datagram_stats.overflow_datagrams.saturating_add(1);
            self.datagram_stats.overflow_bytes = self
                .datagram_stats
                .overflow_bytes
                .saturating_add(len as u64);
            self.wake_datagram_readable(qconn, session_id);
            return None;
        }

        let queue = self.datagrams.entry(session_id).or_default();
        let index_deadline = provisional && queue.queue.is_empty();
        queue.queue.push_back(QueuedDatagram {
            received_at,
            datagram,
        });
        queue.bytes += len;
        queue.allocation_bytes += allocation;
        self.pending_datagram_count += 1;
        self.pending_datagram_bytes += len;
        self.pending_datagram_allocation_bytes += allocation;
        if index_deadline {
            self.index_provisional_deadline(session_id);
        }
        self.wake_datagram_readable(qconn, session_id);
        None
    }

    fn record_terminal_datagram(&mut self, datagram: &DgramBuffer) {
        self.datagram_stats.terminal_datagrams =
            self.datagram_stats.terminal_datagrams.saturating_add(1);
        self.datagram_stats.terminal_bytes = self
            .datagram_stats
            .terminal_bytes
            .saturating_add(datagram.as_slice().len() as u64);
    }

    pub(crate) fn expire_provisional_datagrams(
        &mut self, now: Instant, max_work: usize,
    ) -> usize {
        let mut work = 0;
        while work < max_work {
            let Some(&(deadline, session_id)) =
                self.provisional_deadlines.first()
            else {
                break;
            };
            if deadline > now {
                break;
            }
            self.provisional_deadlines.remove(&(deadline, session_id));

            let Some(queue) = self.datagrams.get_mut(&session_id) else {
                continue;
            };
            let Some(queued) = queue.queue.pop_front() else {
                continue;
            };
            let len = queued.datagram.as_slice().len();
            let allocation = queued.datagram.allocated_capacity();
            queue.bytes = queue.bytes.saturating_sub(len);
            queue.allocation_bytes =
                queue.allocation_bytes.saturating_sub(allocation);
            self.pending_datagram_count =
                self.pending_datagram_count.saturating_sub(1);
            self.pending_datagram_bytes =
                self.pending_datagram_bytes.saturating_sub(len);
            self.pending_datagram_allocation_bytes = self
                .pending_datagram_allocation_bytes
                .saturating_sub(allocation);
            self.datagram_stats.expired_datagrams =
                self.datagram_stats.expired_datagrams.saturating_add(1);
            self.datagram_stats.expired_bytes =
                self.datagram_stats.expired_bytes.saturating_add(len as u64);
            work += 1;

            if queue.queue.is_empty() {
                self.datagrams.remove(&session_id);
            } else {
                self.index_provisional_deadline(session_id);
            }
        }
        work
    }

    pub(crate) fn next_provisional_datagram_deadline(&self) -> Option<Instant> {
        self.provisional_deadlines
            .first()
            .map(|(deadline, _)| *deadline)
    }

    pub(crate) fn pop_legacy_datagram(&mut self) -> Option<(u64, DgramBuffer)> {
        let session_id = self.legacy_sessions.pop_front()?;
        self.legacy_session_set.remove(&session_id);
        let queue = self
            .datagrams
            .get_mut(&session_id)
            .expect("legacy session index references retained Datagrams");
        let queued = queue
            .queue
            .pop_front()
            .expect("legacy session index references a non-empty queue");
        let datagram = queued.datagram;
        let len = datagram.as_slice().len();
        let allocation = datagram.allocated_capacity();
        queue.bytes = queue.bytes.saturating_sub(len);
        queue.allocation_bytes =
            queue.allocation_bytes.saturating_sub(allocation);
        self.pending_datagram_count =
            self.pending_datagram_count.saturating_sub(1);
        self.pending_datagram_bytes =
            self.pending_datagram_bytes.saturating_sub(len);
        self.pending_datagram_allocation_bytes = self
            .pending_datagram_allocation_bytes
            .saturating_sub(allocation);
        if queue.queue.is_empty() {
            self.datagrams.remove(&session_id);
        } else {
            self.legacy_session_set.insert(session_id);
            self.legacy_sessions.push_back(session_id);
        }
        self.datagram_stats.legacy_datagrams =
            self.datagram_stats.legacy_datagrams.saturating_add(1);
        self.datagram_stats.legacy_bytes =
            self.datagram_stats.legacy_bytes.saturating_add(len as u64);
        Some((session_id / 4, datagram))
    }

    pub(crate) fn has_legacy_datagrams(&self) -> bool {
        !self.legacy_sessions.is_empty()
    }

    pub(crate) fn defer_response(&mut self, session_id: u64) {
        self.deferred_responses.insert(session_id);
    }

    pub(crate) fn take_deferred_responses(&mut self) -> Vec<u64> {
        let ids: Vec<_> = self
            .deferred_responses
            .iter()
            .take(self.limits.max_session_work_per_callback)
            .copied()
            .collect();
        for id in &ids {
            self.deferred_responses.remove(id);
        }
        ids
    }

    pub(crate) fn has_deferred_responses(&self) -> bool {
        !self.deferred_responses.is_empty()
    }

    pub(crate) fn owns_stream(&self, stream_id: u64) -> bool {
        self.pending_streams.contains_key(&stream_id) ||
            self.stream_sessions.contains_key(&stream_id) ||
            self.opening_streams.contains_key(&stream_id)
    }

    pub(crate) fn work_limit(&self) -> usize {
        self.limits.max_session_work_per_callback
    }

    pub(crate) fn process_owned_writable(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> bool {
        if !self.owns_stream(stream_id) {
            return false;
        }

        let Some(stream) = self.pending_streams.get(&stream_id).copied() else {
            // Active and locally opening streams must leave StreamStopped
            // observable for the selected-I/O command that owns the send side.
            self.wake_stream_waiter(qconn, stream_id, true);
            return true;
        };
        if matches!(
            qconn.stream_capacity(stream_id),
            Err(quiche::Error::StreamStopped(_))
        ) {
            let _ = self.remove_pending(stream.session_id, stream_id);
            shutdown_stream(qconn, stream, WT_BUFFERED_STREAM_REJECTED);
        }
        true
    }

    pub(crate) fn has_work(&self) -> bool {
        !self.work.is_empty()
    }

    pub(crate) fn process_work(
        &mut self, qconn: &mut QuicheConnection,
    ) -> Vec<WebTransportSessionEvent> {
        let mut events = Vec::new();
        let mut remaining = self.limits.max_session_work_per_callback;
        while remaining != 0 {
            let Some(work) = self.work.pop_front() else {
                break;
            };
            remaining -= 1;
            match work {
                SessionWork::Admit(session_id) => {
                    let Some(stream_id) = self
                        .pending_by_session
                        .get(&session_id)
                        .and_then(|ids| ids.first().copied())
                    else {
                        self.pending_by_session.remove(&session_id);
                        continue;
                    };
                    let stream = self
                        .remove_pending(session_id, stream_id)
                        .expect("pending indexes stay synchronized");
                    if self.is_active(session_id) {
                        self.admit_stream(stream);
                        events.push(associated_event(stream));
                    } else {
                        shutdown_stream(qconn, stream, WT_SESSION_GONE);
                    }
                    if self.pending_by_session.contains_key(&session_id) {
                        self.work.push_back(work);
                    }
                },
                SessionWork::Terminate {
                    session_id,
                    error_code,
                } => {
                    if let Some(stream_id) = self
                        .pending_by_session
                        .get(&session_id)
                        .and_then(|ids| ids.first().copied())
                    {
                        let stream = self
                            .remove_pending(session_id, stream_id)
                            .expect("pending indexes stay synchronized");
                        shutdown_stream(qconn, stream, error_code);
                        let more =
                            self.pending_by_session.contains_key(&session_id) ||
                                self.sessions.get(&session_id).is_some_and(
                                    |session| !session.streams.is_empty(),
                                );
                        if more {
                            self.work.push_back(work);
                        } else {
                            self.remove_terminal_if_closed(session_id);
                        }
                        continue;
                    }

                    let owned = self
                        .sessions
                        .get(&session_id)
                        .and_then(|session| session.streams.first().copied())
                        .and_then(|stream_id| {
                            self.stream_sessions
                                .get(&stream_id)
                                .copied()
                                .map(|stream| (stream_id, stream))
                        });
                    if let Some((stream_id, stream)) = owned {
                        shutdown_owned_stream(
                            qconn, stream_id, stream, error_code,
                        );
                        self.stream_sessions.remove(&stream_id);
                        if let Some(session) = self.sessions.get_mut(&session_id)
                        {
                            session.streams.remove(&stream_id);
                        }
                        if self
                            .sessions
                            .get(&session_id)
                            .is_some_and(|session| !session.streams.is_empty())
                        {
                            self.work.push_back(work);
                        } else {
                            self.remove_terminal_if_closed(session_id);
                        }
                        continue;
                    }

                    self.remove_terminal_if_closed(session_id);
                },
            }
        }
        self.collect_closed_streams(qconn, remaining);
        events
    }

    fn collect_closed_streams(
        &mut self, qconn: &QuicheConnection, mut remaining: usize,
    ) {
        let to_scan = remaining
            .min(self.pending_streams.len() + self.stream_sessions.len());
        let mut scanned = 0;
        while scanned < to_scan && remaining != 0 {
            let next_pending = next_key_strictly_after(
                &self.pending_streams,
                self.maintenance_cursor,
            );
            let next_active = next_key_strictly_after(
                &self.stream_sessions,
                self.maintenance_cursor,
            );
            let stream_id = match (next_pending, next_active) {
                (Some(a), Some(b)) => a.min(b),
                (Some(id), None) | (None, Some(id)) => id,
                (None, None) => match (
                    self.pending_streams.first_key_value(),
                    self.stream_sessions.first_key_value(),
                ) {
                    (Some((&a, _)), Some((&b, _))) => a.min(b),
                    (Some((&id, _)), None) | (None, Some((&id, _))) => id,
                    (None, None) => break,
                },
            };
            self.maintenance_cursor = Some(stream_id);
            scanned += 1;
            remaining -= 1;

            if !qconn.stream_closed(stream_id) {
                continue;
            }
            if let Some(stream) = self.pending_streams.get(&stream_id).copied() {
                let _ = self.remove_pending(stream.session_id, stream_id);
                continue;
            }
            if let Some(stream) = self.stream_sessions.remove(&stream_id) {
                self.close_stream_waiters(stream_id);
                if let Some(session) = self.sessions.get_mut(&stream.session_id) {
                    session.streams.remove(&stream_id);
                }
            }
        }
    }

    fn remove_pending(
        &mut self, session_id: u64, stream_id: u64,
    ) -> Option<AssociatedStream> {
        let stream = self.pending_streams.remove(&stream_id)?;
        if let Some(ids) = self.pending_by_session.get_mut(&session_id) {
            ids.remove(&stream_id);
            if ids.is_empty() {
                self.pending_by_session.remove(&session_id);
            }
        }
        Some(stream)
    }

    fn remove_terminal_if_closed(&mut self, session_id: u64) {
        let remove = self.sessions.get(&session_id).is_some_and(|session| {
            session.phase == SessionPhase::Terminal &&
                session.connect_recv_closed &&
                session.connect_send_closed
        });
        if remove {
            self.sessions.remove(&session_id);
            self.release_datagrams(session_id);
        }
    }

    #[cfg(test)]
    pub(crate) fn pending_stream_count(&self) -> usize {
        self.pending_streams.len()
    }

    #[cfg(test)]
    pub(crate) fn active_stream_count(&self) -> usize {
        self.stream_sessions.len()
    }

    #[cfg(test)]
    pub(crate) fn first_opening_stream_id(&self) -> Option<u64> {
        self.opening_streams
            .first_key_value()
            .map(|(&stream_id, _)| stream_id)
    }

    #[cfg(test)]
    pub(crate) fn inject_commit_error(&mut self, error: quiche::h3::Error) {
        self.commit_errors.push_back(error);
    }

    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.len()
    }

    #[cfg(test)]
    pub(crate) fn pending_datagram_usage(&self) -> (usize, usize) {
        (self.pending_datagram_count, self.pending_datagram_bytes)
    }

    fn datagram_stats(&self) -> WebTransportDatagramStats {
        WebTransportDatagramStats {
            retained_datagrams: self.pending_datagram_count,
            retained_payload_bytes: self.pending_datagram_bytes,
            retained_allocation_bytes: self.pending_datagram_allocation_bytes,
            max_retained_datagrams: self.limits.max_pending_datagrams,
            max_retained_payload_bytes: self.limits.max_pending_datagram_bytes,
            max_retained_allocation_bytes: self
                .limits
                .max_pending_datagram_allocation_bytes,
            ..self.datagram_stats
        }
    }

    fn retention_stats(
        &self, qconn: &QuicheConnection, queued_command_items: usize,
    ) -> WebTransportRetentionStats {
        let associated_streams = self.stream_sessions.len();
        let provisional_streams = self
            .pending_streams
            .len()
            .saturating_add(self.opening_streams.len());
        let waiters = self
            .readable_waiters
            .len()
            .saturating_add(self.writable_waiters.len())
            .saturating_add(self.datagram_readable_waiters.len())
            .saturating_add(self.datagram_send_waiters.len());

        // Count each retained index entry. Nested per-session stream sets have
        // one entry per corresponding aggregate stream map entry.
        let metadata_index_entries = self
            .sessions
            .len()
            .saturating_add(self.pending_streams.len().saturating_mul(2))
            .saturating_add(self.pending_by_session.len())
            .saturating_add(self.stream_sessions.len().saturating_mul(2))
            .saturating_add(self.opening_streams.len().saturating_mul(2))
            .saturating_add(self.opening_order.len())
            .saturating_add(self.opening_by_session.len())
            .saturating_add(waiters)
            .saturating_add(self.datagrams.len())
            .saturating_add(self.pending_datagram_count)
            .saturating_add(self.provisional_deadlines.len())
            .saturating_add(self.legacy_sessions.len())
            .saturating_add(self.legacy_session_set.len())
            .saturating_add(self.non_session_requests.len())
            .saturating_add(self.work.len())
            .saturating_add(self.deferred_responses.len());
        let queued_commands =
            queued_command_items.min(self.limits.command_capacity);
        let write_leases = self.write_lease_accounting.snapshot();

        WebTransportRetentionStats {
            sessions: self.sessions.len(),
            associated_streams,
            provisional_streams,
            waiters,
            metadata_index_entries,
            pending_datagrams: self.pending_datagram_count,
            pending_datagram_payload_bytes: self.pending_datagram_bytes,
            pending_datagram_allocation_bytes: self
                .pending_datagram_allocation_bytes,
            command_capacity: self.limits.command_capacity,
            queued_commands,
            queued_command_payload_bytes_upper_bound: queued_commands
                .saturating_mul(self.limits.max_command_payload_bytes),
            write_leases: write_leases.current,
            write_lease_retained_bytes: write_leases.retained_bytes,
            max_write_leases: write_leases.max_count,
            max_write_lease_retained_bytes: write_leases.max_retained_bytes,
            write_lease_admitted_total: write_leases.admitted_total,
            write_lease_queue_full_total: write_leases.queue_full_total,
            write_lease_resource_limit_total: write_leases.resource_limit_total,
            write_lease_too_large_total: write_leases.too_large_total,
            write_lease_abandoned_unexposed_total: write_leases
                .abandoned_unexposed_total,
            write_lease_abandoned_zero_total: write_leases.abandoned_zero_total,
            write_lease_abandoned_unknown_total: write_leases
                .abandoned_unknown_total,
            transport_stream_send_bytes: qconn.stream_send_queue_byte_size(),
            transport_stream_receive_bytes: qconn.stream_recv_queue_byte_size(),
            transport_datagram_send_bytes: qconn.dgram_send_queue_byte_size(),
            transport_datagram_receive_bytes: qconn.dgram_recv_queue_byte_size(),
        }
    }

    pub(crate) fn clear(&mut self) -> Vec<WebTransportSessionEvent> {
        let events = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                session.application_visible &&
                    session.phase != SessionPhase::Terminal
            })
            .map(|(&session_id, _)| WebTransportSessionEvent::Terminated {
                session_id,
                reason: WebTransportSessionCloseReason::ConnectionClosed,
            })
            .collect();
        for opening in self.opening_streams.values_mut() {
            if let Some(response) = opening.response.take() {
                let _ = response.send(WebTransportOpenStreamOutcome::Rejected(
                    WebTransportSelectionError::ConnectionClosed,
                ));
            }
        }
        for (_, response) in std::mem::take(&mut self.readable_waiters) {
            let _ = response.send(WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            ));
        }
        for (_, response) in std::mem::take(&mut self.writable_waiters) {
            let _ = response.send(WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            ));
        }
        for (_, response) in std::mem::take(&mut self.datagram_readable_waiters) {
            let _ = response.send(WebTransportDatagramReadyOutcome::Rejected(
                WebTransportDatagramError::ConnectionClosed,
            ));
        }
        for (_, response) in std::mem::take(&mut self.datagram_send_waiters) {
            let _ = response.send(WebTransportDatagramReadyOutcome::Rejected(
                WebTransportDatagramError::ConnectionClosed,
            ));
        }
        self.sessions.clear();
        self.pending_streams.clear();
        self.pending_by_session.clear();
        self.stream_sessions.clear();
        self.opening_streams.clear();
        self.opening_order.clear();
        self.opening_by_session.clear();
        self.datagram_stats.terminal_datagrams = self
            .datagram_stats
            .terminal_datagrams
            .saturating_add(self.pending_datagram_count as u64);
        self.datagram_stats.terminal_bytes = self
            .datagram_stats
            .terminal_bytes
            .saturating_add(self.pending_datagram_bytes as u64);
        self.datagrams.clear();
        self.provisional_deadlines.clear();
        self.legacy_sessions.clear();
        self.legacy_session_set.clear();
        self.pending_datagram_count = 0;
        self.pending_datagram_bytes = 0;
        self.pending_datagram_allocation_bytes = 0;
        self.non_session_requests.clear();
        self.work.clear();
        self.deferred_responses.clear();
        self.maintenance_cursor = None;
        events
    }
}

fn next_key_strictly_after<V>(
    map: &BTreeMap<u64, V>, cursor: Option<u64>,
) -> Option<u64> {
    use std::ops::Bound;

    match cursor {
        Some(cursor) => map
            .range((Bound::Excluded(cursor), Bound::Unbounded))
            .next()
            .map(|(&id, _)| id),
        None => map.first_key_value().map(|(&id, _)| id),
    }
}

fn datagram_error_from_selection(
    error: WebTransportSelectionError,
) -> WebTransportDatagramError {
    match error {
        WebTransportSelectionError::UnknownSession =>
            WebTransportDatagramError::UnknownSession,
        WebTransportSelectionError::StaleSession =>
            WebTransportDatagramError::StaleSession,
        WebTransportSelectionError::PendingSession =>
            WebTransportDatagramError::PendingSession,
        WebTransportSelectionError::ClosingSession =>
            WebTransportDatagramError::ClosingSession,
        WebTransportSelectionError::TerminalSession =>
            WebTransportDatagramError::TerminalSession,
        WebTransportSelectionError::Unsupported =>
            WebTransportDatagramError::Unsupported,
        WebTransportSelectionError::ConnectionClosed =>
            WebTransportDatagramError::ConnectionClosed,
        _ => WebTransportDatagramError::UnknownSession,
    }
}

fn commit_error_is_retryable(error: quiche::h3::Error) -> bool {
    matches!(
        error,
        quiche::h3::Error::Done |
            quiche::h3::Error::StreamBlocked |
            quiche::h3::Error::TransportError(quiche::Error::Done)
    )
}

fn associated_event(stream: AssociatedStream) -> WebTransportSessionEvent {
    WebTransportSessionEvent::AssociatedStream {
        session_id: stream.session_id,
        stream_id: stream.stream_id,
        direction: stream.direction,
        prefix_len: stream.prefix_len,
    }
}

fn shutdown_stream(
    qconn: &mut QuicheConnection, stream: AssociatedStream, error_code: u64,
) {
    let _ = qconn.stream_shutdown(
        stream.stream_id,
        quiche::Shutdown::Read,
        error_code,
    );
    if stream.direction == WebTransportStreamDirection::Bidi {
        let _ = qconn.stream_shutdown(
            stream.stream_id,
            quiche::Shutdown::Write,
            error_code,
        );
    }
}

fn stop_opening_receive_side(
    qconn: &mut QuicheConnection,
    reservation: &quiche::h3::WebTransportStreamReservation, error_code: u64,
) {
    if reservation.direction() ==
        quiche::h3::WebTransportStreamDirection::Bidirectional
    {
        let _ = qconn.stream_shutdown(
            reservation.stream_id(),
            quiche::Shutdown::Read,
            error_code,
        );
    }
}

fn shutdown_opening_stream(
    qconn: &mut QuicheConnection,
    reservation: &quiche::h3::WebTransportStreamReservation, error_code: u64,
) {
    stop_opening_receive_side(qconn, reservation, error_code);
    let _ = qconn.stream_shutdown_at(
        reservation.stream_id(),
        error_code,
        reservation.prefix_len() as u64,
    );
}

fn shutdown_owned_stream(
    qconn: &mut QuicheConnection, stream_id: u64, stream: OwnedStream,
    error_code: u64,
) {
    if stream.direction == WebTransportStreamDirection::Bidi ||
        !stream.locally_initiated
    {
        let _ =
            qconn.stream_shutdown(stream_id, quiche::Shutdown::Read, error_code);
    }
    if stream.direction == WebTransportStreamDirection::Bidi ||
        stream.locally_initiated
    {
        let _ = qconn.stream_shutdown_at(
            stream_id,
            error_code,
            stream.local_prefix_len,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type DriverPipe = quiche::test_utils::Pipe<crate::buf_factory::BufFactory>;

    fn runtime_limits(
        global: usize, per_session: usize, work: usize,
    ) -> RuntimeLimits {
        RuntimeLimits {
            max_pending_streams: global,
            max_pending_streams_per_session: per_session,
            max_stream_waiters: global,
            max_datagram_waiters: 2,
            max_pending_datagrams: 256,
            max_pending_datagrams_per_session: 64,
            max_pending_datagram_bytes: 1024 * 1024,
            max_pending_datagram_bytes_per_session: 256 * 1024,
            max_pending_datagram_allocation_bytes: 1024 * 1024,
            max_pending_datagram_allocation_bytes_per_session: 256 * 1024,
            max_pending_datagram_age: Duration::from_secs(5),
            command_capacity: 256,
            max_command_payload_bytes: 64 * 1024,
            max_write_lease_retained_bytes_per_lease: 64 * 1024,
            max_session_work_per_callback: work,
        }
    }

    fn pipe() -> DriverPipe {
        let mut config =
            crate::http3::driver::test_utils::default_quiche_config();
        let mut pipe = DriverPipe::with_config_and_buf(&mut config).unwrap();
        pipe.handshake().unwrap();
        pipe
    }

    fn stream(session_id: u64, stream_id: u64) -> AssociatedStream {
        AssociatedStream {
            session_id,
            stream_id,
            direction: WebTransportStreamDirection::Bidi,
            prefix_len: 2,
        }
    }

    fn datagram(data: &[u8]) -> DgramBuffer {
        <crate::buf_factory::BufFactory as quiche::BufFactory>::dgram_buf_from_slice(
            data,
        )
    }

    fn close_bytes(code: u32, message: &str) -> Bytes {
        CloseCapsule::new(code, message.to_string())
            .unwrap()
            .encode()
    }

    #[test]
    fn close_capsule_parses_at_every_fragment_boundary() {
        let encoded = close_bytes(0x1020_3040, "goodbye");
        for split in 0..=encoded.len() {
            let mut parser = CapsuleParser::default();
            let first = parser.consume(&encoded[..split]).unwrap();
            let close = if first.is_some() {
                first
            } else {
                parser.consume(&encoded[split..]).unwrap()
            };
            assert_eq!(
                close,
                Some(CloseCapsule {
                    error_code: 0x1020_3040,
                    message: "goodbye".to_string(),
                })
            );
            assert_eq!(parser.finish(), Ok(()));
        }
    }

    #[test]
    fn application_error_mapping_round_trips_and_rejects_grease() {
        for error_code in [0, 1, 29, 30, 31, u32::MAX - 1, u32::MAX] {
            let wire = webtransport_error_to_http3(error_code);
            assert_eq!(webtransport_error_from_http3(wire), Some(error_code));
        }

        let first_grease = webtransport_error_to_http3(29) + 1;
        assert_eq!(webtransport_error_from_http3(first_grease), None);
        assert_eq!(
            webtransport_error_from_http3(WT_APPLICATION_ERROR_FIRST - 1),
            None
        );
        assert_eq!(
            webtransport_error_from_http3(WT_APPLICATION_ERROR_LAST + 1),
            None
        );
    }

    #[test]
    fn commit_errors_retry_only_transport_backpressure() {
        for error in [
            quiche::h3::Error::Done,
            quiche::h3::Error::StreamBlocked,
            quiche::h3::Error::TransportError(quiche::Error::Done),
        ] {
            assert!(commit_error_is_retryable(error));
        }
        for error in [
            quiche::h3::Error::IdError,
            quiche::h3::Error::SettingsError,
            quiche::h3::Error::InternalError,
            quiche::h3::Error::TransportError(quiche::Error::InvalidState),
        ] {
            assert!(!commit_error_is_retryable(error));
        }
    }

    #[test]
    fn provisional_datagrams_resolve_native_legacy_expiry_and_rejection_once() {
        let pipe = pipe();
        let mut limits = runtime_limits(8, 8, 2);
        limits.max_pending_datagram_age = Duration::from_millis(10);
        limits.max_pending_datagrams = 4;
        limits.max_pending_datagrams_per_session = 2;
        limits.max_pending_datagram_bytes = 16;
        limits.max_pending_datagram_bytes_per_session = 8;
        let mut runtime = Runtime::new(limits);
        let now = Instant::now();

        assert!(runtime
            .route_datagram_at(&pipe.server, 0, datagram(b"native"), now)
            .is_none());
        assert_eq!(runtime.pending_datagram_usage(), (1, 6));
        assert!(matches!(
            runtime.observe_request(0, true),
            RequestObservation::Observed(events)
                if events == vec![WebTransportSessionEvent::Pending {
                    session_id: 0,
                }]
        ));
        assert_eq!(runtime.activate(0), vec![
            WebTransportSessionEvent::Accepted { session_id: 0 }
        ]);
        assert_eq!(
            runtime.datagrams[&0]
                .queue
                .front()
                .unwrap()
                .datagram
                .as_slice(),
            b"native",
        );

        assert!(runtime
            .route_datagram_at(&pipe.server, 4, datagram(b"legacy"), now)
            .is_none());
        assert!(matches!(
            runtime.observe_request(4, false),
            RequestObservation::Observed(events) if events.is_empty()
        ));
        let (flow_id, legacy) = runtime.pop_legacy_datagram().unwrap();
        assert_eq!(flow_id, 1);
        assert_eq!(legacy.as_slice(), b"legacy");
        assert!(runtime.pop_legacy_datagram().is_none());

        assert!(runtime
            .route_datagram_at(&pipe.server, 8, datagram(b"expire"), now)
            .is_none());
        assert_eq!(
            runtime.expire_provisional_datagrams(
                now + Duration::from_millis(10),
                1,
            ),
            1,
        );

        let mut reject_runtime = Runtime::new(limits);
        assert!(reject_runtime
            .route_datagram_at(&pipe.server, 12, datagram(b"reject"), now)
            .is_none());
        assert!(matches!(
            reject_runtime.observe_request(12, true),
            RequestObservation::Observed(events)
                if events == vec![WebTransportSessionEvent::Pending {
                    session_id: 12,
                }]
        ));
        assert_eq!(reject_runtime.reject(12, 403), vec![
            WebTransportSessionEvent::Rejected {
                session_id: 12,
                status: 403,
            }
        ]);

        assert_eq!(runtime.pending_datagram_usage(), (1, 6));
        assert_eq!(runtime.datagram_stats, WebTransportDatagramStats {
            expired_datagrams: 1,
            expired_bytes: 6,
            legacy_datagrams: 1,
            legacy_bytes: 6,
            ..WebTransportDatagramStats::default()
        });
        assert_eq!(reject_runtime.pending_datagram_usage(), (0, 0));
        assert_eq!(reject_runtime.datagram_stats, WebTransportDatagramStats {
            terminal_datagrams: 1,
            terminal_bytes: 6,
            ..WebTransportDatagramStats::default()
        });
    }

    #[test]
    fn provisional_datagram_caps_and_expiry_work_are_hard_bounds() {
        let pipe = pipe();
        let now = Instant::now();
        let mut limits = runtime_limits(8, 8, 1);
        limits.max_pending_datagram_age = Duration::from_millis(1);
        limits.max_pending_datagrams = 3;
        limits.max_pending_datagrams_per_session = 1;
        limits.max_pending_datagram_bytes = 3;
        limits.max_pending_datagram_bytes_per_session = 1;
        let mut runtime = Runtime::new(limits);

        for session_id in [0, 4, 8] {
            assert!(runtime
                .route_datagram_at(
                    &pipe.server,
                    session_id,
                    datagram(&[session_id as u8]),
                    now,
                )
                .is_none());
        }
        for session_id in (12..4012).step_by(4) {
            assert!(runtime
                .route_datagram_at(&pipe.server, session_id, datagram(b"x"), now,)
                .is_none());
        }
        assert_eq!(runtime.pending_datagram_usage(), (3, 3));
        assert_eq!(runtime.datagrams.len(), 3);
        assert_eq!(runtime.provisional_deadlines.len(), 3);
        assert_eq!(runtime.datagram_stats.overflow_datagrams, 1000);

        assert_eq!(
            runtime
                .expire_provisional_datagrams(now + Duration::from_millis(1), 2,),
            2,
        );
        assert_eq!(runtime.pending_datagram_usage(), (1, 1));
        assert_eq!(runtime.datagram_stats.expired_datagrams, 2);
        assert_eq!(
            runtime
                .expire_provisional_datagrams(now + Duration::from_millis(1), 2,),
            1,
        );
        assert_eq!(runtime.pending_datagram_usage(), (0, 0));
    }

    #[test]
    fn datagram_physical_allocation_limit_is_independent_of_payload() {
        let pipe = pipe();
        let mut limits = runtime_limits(8, 8, 8);
        limits.max_pending_datagram_allocation_bytes = 8;
        limits.max_pending_datagram_allocation_bytes_per_session = 8;
        let mut runtime = Runtime::new(limits);

        let mut backing = Vec::with_capacity(9);
        backing.push(1);
        let allocation = backing.capacity();
        assert!(allocation > 8);
        assert!(runtime
            .route_datagram(&pipe.server, 0, DgramBuffer::from(backing),)
            .is_none());
        let stats = runtime.datagram_stats();
        assert_eq!(stats.retained_datagrams, 0);
        assert_eq!(stats.retained_payload_bytes, 0);
        assert_eq!(stats.retained_allocation_bytes, 0);
        assert_eq!(stats.max_retained_allocation_bytes, 8);
        assert_eq!(stats.overflow_datagrams, 1);
        assert_eq!(stats.overflow_bytes, 1);

        let accepted = DgramBuffer::from_slice(&[1]);
        assert!(accepted.allocated_capacity() <= 8);
        assert!(runtime.route_datagram(&pipe.server, 0, accepted).is_none());
        let stats = runtime.datagram_stats();
        assert_eq!(stats.retained_datagrams, 1);
        assert_eq!(stats.retained_payload_bytes, 1);
        assert!(stats.retained_allocation_bytes <= 8);
    }

    #[test]
    fn legacy_datagram_release_is_one_item_per_fair_work_unit() {
        let pipe = pipe();
        let now = Instant::now();
        let mut runtime = Runtime::new(runtime_limits(8, 8, 1));

        for (session_id, payload) in
            [(0, b"a1".as_slice()), (0, b"a2"), (4, b"b1"), (4, b"b2")]
        {
            assert!(runtime
                .route_datagram_at(
                    &pipe.server,
                    session_id,
                    datagram(payload),
                    now,
                )
                .is_none());
        }
        assert!(matches!(
            runtime.observe_request(0, false),
            RequestObservation::Observed(events) if events.is_empty()
        ));
        assert!(matches!(
            runtime.observe_request(4, false),
            RequestObservation::Observed(events) if events.is_empty()
        ));
        assert_eq!(runtime.pending_datagram_usage(), (4, 8));
        assert_eq!(runtime.legacy_sessions.len(), 2);

        for (remaining, expected) in [
            (3, (0, b"a1".as_slice())),
            (2, (1, b"b1".as_slice())),
            (1, (0, b"a2".as_slice())),
            (0, (1, b"b2".as_slice())),
        ] {
            let (flow_id, datagram) = runtime.pop_legacy_datagram().unwrap();
            assert_eq!(flow_id, expected.0);
            assert_eq!(datagram.as_slice(), expected.1);
            assert_eq!(runtime.pending_datagram_usage().0, remaining);
        }
        assert!(!runtime.has_legacy_datagrams());
        assert!(runtime.datagrams.is_empty());
    }

    #[test]
    fn unknown_capsule_is_skipped_without_payload_retention() {
        let mut encoded = BytesMut::new();
        put_varint(&mut encoded, 0x1234);
        put_varint(&mut encoded, 4096);
        encoded.resize(encoded.len() + 4096, 0xa5);
        encoded.extend_from_slice(&close_bytes(7, "done"));

        let mut parser = CapsuleParser::default();
        let mut close = None;
        for chunk in encoded.chunks(17) {
            close = parser.consume(chunk).unwrap().or(close);
        }
        assert_eq!(close.unwrap().error_code, 7);
        assert_eq!(parser.finish(), Ok(()));
    }

    #[test]
    fn v2_profile_ignores_all_flow_control_capsules() {
        let mut encoded = BytesMut::new();
        for capsule_type in [
            0x190b_4d3d, // WT_MAX_DATA
            0x190b_4d3f, // WT_MAX_STREAMS_BIDI
            0x190b_4d40, // WT_MAX_STREAMS_UNI
            0x190b_4d41, // WT_DATA_BLOCKED
            0x190b_4d43, // WT_STREAMS_BLOCKED_BIDI
            0x190b_4d44, // WT_STREAMS_BLOCKED_UNI
        ] {
            put_varint(&mut encoded, capsule_type);
            put_varint(&mut encoded, 1);
            encoded.put_u8(0);
        }
        encoded.extend_from_slice(&close_bytes(7, "done"));

        let mut parser = CapsuleParser::default();
        assert_eq!(parser.consume(&encoded).unwrap().unwrap().error_code, 7);
        assert_eq!(parser.finish(), Ok(()));
    }

    #[test]
    fn malformed_close_capsules_fail_closed() {
        for length in [0, 1, 3, 1029] {
            let mut encoded = BytesMut::new();
            put_varint(&mut encoded, WT_CLOSE_SESSION);
            put_varint(&mut encoded, length);
            encoded.resize(encoded.len() + length as usize, 0);
            assert_eq!(
                CapsuleParser::default().consume(&encoded),
                Err(CapsuleError::InvalidLength)
            );
        }

        let mut invalid_utf8 = BytesMut::new();
        put_varint(&mut invalid_utf8, WT_CLOSE_SESSION);
        put_varint(&mut invalid_utf8, 5);
        invalid_utf8.put_u32(1);
        invalid_utf8.put_u8(0xff);
        assert_eq!(
            CapsuleParser::default().consume(&invalid_utf8),
            Err(CapsuleError::InvalidUtf8)
        );
    }

    #[test]
    fn truncated_and_post_close_data_are_rejected() {
        let encoded = close_bytes(0, "");
        for end in 1..encoded.len() {
            let mut parser = CapsuleParser::default();
            assert_eq!(parser.consume(&encoded[..end]), Ok(None));
            assert_eq!(parser.finish(), Err(CapsuleError::Truncated));
        }

        let mut parser = CapsuleParser::default();
        assert!(parser.consume(&encoded).unwrap().is_some());
        assert_eq!(parser.consume(b"after"), Err(CapsuleError::DataAfterClose));
    }

    #[test]
    fn optimistic_stream_limits_bound_both_indexes_and_reject_overflow() {
        let mut pipe = pipe();
        for stream_id in [4, 8, 12, 16] {
            pipe.client.stream_send(stream_id, b"x", false).unwrap();
        }
        pipe.advance().unwrap();

        let mut runtime = Runtime::new(runtime_limits(2, 1, 8));
        assert!(runtime.classify(stream(0, 4), &mut pipe.server).is_empty());
        assert!(runtime.classify(stream(0, 8), &mut pipe.server).is_empty());
        assert!(runtime.classify(stream(4, 12), &mut pipe.server).is_empty());
        assert!(runtime.classify(stream(8, 16), &mut pipe.server).is_empty());

        assert_eq!(runtime.pending_stream_count(), 2);
        assert_eq!(runtime.active_stream_count(), 0);

        pipe.advance().unwrap();
        assert_eq!(
            pipe.client.stream_capacity(8),
            Err(quiche::Error::StreamStopped(WT_BUFFERED_STREAM_REJECTED))
        );
        assert_eq!(
            pipe.client.stream_capacity(16),
            Err(quiche::Error::StreamStopped(WT_BUFFERED_STREAM_REJECTED))
        );
    }

    #[test]
    fn admission_and_teardown_continue_at_one_stream_per_callback() {
        let mut pipe = pipe();
        for stream_id in [4, 8, 12] {
            pipe.client.stream_send(stream_id, b"x", false).unwrap();
        }
        pipe.advance().unwrap();

        let mut runtime = Runtime::new(runtime_limits(3, 3, 1));
        for stream_id in [4, 8, 12] {
            assert!(runtime
                .classify(stream(0, stream_id), &mut pipe.server)
                .is_empty());
        }
        assert_eq!(runtime.pending_stream_count(), 3);
        assert!(matches!(
            runtime.observe_request(0, true),
            RequestObservation::Observed(events)
                if events == vec![WebTransportSessionEvent::Pending {
                    session_id: 0,
                }]
        ));
        assert_eq!(runtime.activate(0), vec![
            WebTransportSessionEvent::Accepted { session_id: 0 }
        ]);

        for admitted in 1..=3 {
            let events = runtime.process_work(&mut pipe.server);
            assert_eq!(events.len(), 1);
            assert_eq!(runtime.active_stream_count(), admitted);
            assert_eq!(runtime.pending_stream_count(), 3 - admitted);
        }
        assert!(!runtime.has_work());

        assert_eq!(
            runtime
                .terminate(0, WebTransportSessionCloseReason::ConnectionClosed,),
            vec![WebTransportSessionEvent::Terminated {
                session_id: 0,
                reason: WebTransportSessionCloseReason::ConnectionClosed,
            }]
        );
        for remaining in (0..3).rev() {
            assert!(runtime.process_work(&mut pipe.server).is_empty());
            assert_eq!(runtime.active_stream_count(), remaining);
        }
        assert!(!runtime.has_work());

        assert!(runtime.mark_connect_recv_closed(0).is_empty());
        runtime.mark_connect_send_closed(0);
        assert!(runtime.process_work(&mut pipe.server).is_empty());
        assert_eq!(runtime.session_count(), 0);
    }
}
