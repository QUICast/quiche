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
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectProtocol {
    Draft16,
    LegacyBrowser,
}

fn connect_protocol(headers: &[quiche::h3::Header]) -> Option<ConnectProtocol> {
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

    if method != Some(b"CONNECT".as_slice()) ||
        scheme != Some(b"https".as_slice()) ||
        authority.is_none_or(|value| value.is_empty()) ||
        path.is_none_or(|value| value.is_empty())
    {
        return None;
    }

    match protocol {
        Some(b"webtransport-h3") => Some(ConnectProtocol::Draft16),
        Some(b"webtransport") => Some(ConnectProtocol::LegacyBrowser),
        _ => None,
    }
}

pub(crate) fn is_connect(headers: &[quiche::h3::Header]) -> bool {
    connect_protocol(headers) == Some(ConnectProtocol::Draft16)
}

pub(crate) fn is_legacy_connect(headers: &[quiche::h3::Header]) -> bool {
    connect_protocol(headers) == Some(ConnectProtocol::LegacyBrowser)
}

pub(crate) fn is_connect_for_profile(
    headers: &[quiche::h3::Header],
    profile: quiche::h3::WebTransportHandshakeProfile,
) -> bool {
    matches!(
        (connect_protocol(headers), profile),
        (
            Some(ConnectProtocol::Draft16),
            quiche::h3::WebTransportHandshakeProfile::Draft16
        ) | (
            Some(ConnectProtocol::LegacyBrowser),
            quiche::h3::WebTransportHandshakeProfile::Draft07 |
                quiche::h3::WebTransportHandshakeProfile::Draft02
        )
    )
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

/// Level-triggered terminal result for one exact WebTransport session.
///
/// Each wait operation resolves once, but observing a result does not consume
/// the terminal fact. A later wait returns the same result while the session
/// remains in the native registry. Once the session is collected, later waits
/// return [`Self::StaleSession`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebTransportSessionTerminalOutcome {
    /// The session terminated with its exact existing close reason.
    Terminated {
        /// CONNECT stream ID and WebTransport Session ID.
        session_id: u64,
        /// Terminal close reason retained by the session registry.
        reason: WebTransportSessionCloseReason,
    },
    /// A pending CONNECT received a final non-successful response.
    SessionRejected {
        /// CONNECT stream ID and WebTransport Session ID.
        session_id: u64,
        /// Final HTTP response status.
        status: u16,
    },
    /// The Session ID has never identified a native session on this connection.
    UnknownSession {
        /// Requested Session ID.
        session_id: u64,
    },
    /// The session existed but its registry entry has been collected.
    StaleSession {
        /// Requested Session ID.
        session_id: u64,
    },
    /// The configured connection or per-session waiter bound is full.
    ResourceLimit {
        /// Requested Session ID.
        session_id: u64,
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
    /// A one-use retry token belongs to another controller connection.
    ForeignController,
    /// The requested operation is invalid for this stream direction.
    WrongDirection,
    /// A configured local ownership bound was reached.
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
    /// Transport capacity currently prevents any progress.
    ///
    /// This `Bytes` compatibility outcome omits the exact reasons. Use the
    /// generic write-lease API when authoritative block evidence is required.
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
    /// The concrete owner would make the transport-owned operation allocation
    /// exceed its configured inline-size bound.
    OwnerBytes,
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

/// One-use retry context for an exact zero-progress selected-stream write.
///
/// The value is intentionally neither cloneable nor constructible by callers.
/// Passing it to [`WebTransportController::wait_stream_writable()`] binds the
/// wait to the exact controller turn that returned the owner, even when other
/// writes target the same physical stream. The token privately retains one
/// zero-byte slot in the bounded write-lease accounting envelope until it is
/// consumed or dropped.
pub struct WebTransportStreamWriteRetry {
    session_id: u64,
    stream_id: u64,
    reasons: quiche::StreamSendBlockReasons,
    disposition: quiche::StreamSendRetryDisposition,
    reservation: WriteLeaseAccountingGuard,
}

impl fmt::Debug for WebTransportStreamWriteRetry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebTransportStreamWriteRetry")
            .field("session_id", &self.session_id)
            .field("stream_id", &self.stream_id)
            .field("reasons", &self.reasons)
            .field("disposition", &self.disposition)
            .finish()
    }
}

impl WebTransportStreamWriteRetry {
    /// Returns the exact WebTransport Session ID.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Returns the exact physical QUIC stream ID.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Returns every simultaneous cause from the blocked write turn.
    pub fn reasons(&self) -> quiche::StreamSendBlockReasons {
        self.reasons
    }

    /// Returns the safe retry disposition for the complete cause set.
    pub fn disposition(&self) -> quiche::StreamSendRetryDisposition {
        self.disposition
    }

    fn belongs_to(&self, accounting: &Arc<WriteLeaseAccounting>) -> bool {
        Arc::ptr_eq(&self.reservation.accounting, accounting)
    }
}

fn stream_send_state_change_reasons(
    reasons: quiche::StreamSendBlockReasons,
) -> quiche::StreamSendBlockReasons {
    quiche::StreamSendBlockReasons {
        active_path_unavailable: reasons.active_path_unavailable,
        send_capacity_factor: reasons.send_capacity_factor,
        stream_send_retention: reasons.stream_send_retention,
        ..quiche::StreamSendBlockReasons::default()
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
    /// Transport capacity prevented progress after one payload exposure.
    Blocked {
        /// The exact original owner.
        lease: L,
        /// Whether FIN remains requested.
        fin: bool,
        /// Exact simultaneous causes reported by the core transport turn.
        reasons: quiche::StreamSendBlockReasons,
        /// One-use context for an exact, attempt-bound writable wait.
        retry: WebTransportStreamWriteRetry,
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
    /// STOP_SENDING made the send side terminal and requires reset settlement.
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

/// Terminal receive fact retained for one selected associated stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportStreamReceiveTerminal {
    /// The peer's final offset was reached without a reset.
    Fin,
    /// RESET_STREAM became visible after any reliable prefix was released.
    Reset {
        /// HTTP/3 wire error carried by RESET_STREAM or RESET_STREAM_AT.
        wire_error_code: u64,
        /// Decoded 32-bit WebTransport application error, when valid.
        application_error_code: Option<u32>,
    },
}

#[derive(Debug)]
struct ReceiveTerminalReadShared {
    session_id: u64,
    stream_id: u64,
    data: Bytes,
    terminal: WebTransportStreamReceiveTerminal,
    allocation_bytes: usize,
    leased: AtomicBool,
    _terminal_retention: TerminalReceiveRetentionGuard,
}

/// Non-cloneable ownership of one selected stream's terminal receive result.
///
/// The runtime retains the same backing allocation until
/// [`WebTransportController::retire_stream_receive_terminal()`] succeeds.
/// Dropping this lease without retirement makes the exact result available to
/// a later read without copying it. While one lease is outstanding, another
/// read of the same terminal result is rejected with
/// [`WebTransportSelectionError::ResourceLimit`].
pub struct WebTransportStreamReceiveTerminalRead {
    shared: Arc<ReceiveTerminalReadShared>,
}

impl WebTransportStreamReceiveTerminalRead {
    fn try_acquire(shared: &Arc<ReceiveTerminalReadShared>) -> Option<Self> {
        shared
            .leased
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(Self {
            shared: Arc::clone(shared),
        })
    }

    /// Returns the CONNECT stream ID identifying the owning session.
    pub fn session_id(&self) -> u64 {
        self.shared.session_id
    }

    /// Returns the exact physical QUIC stream ID.
    pub fn stream_id(&self) -> u64 {
        self.shared.stream_id
    }

    /// Returns payload bytes delivered with the terminal fact.
    pub fn data(&self) -> &[u8] {
        &self.shared.data
    }

    /// Returns the exact graceful-FIN or reset fact.
    pub fn terminal(&self) -> WebTransportStreamReceiveTerminal {
        self.shared.terminal
    }
}

impl fmt::Debug for WebTransportStreamReceiveTerminalRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransportStreamReceiveTerminalRead")
            .field("session_id", &self.session_id())
            .field("stream_id", &self.stream_id())
            .field("data", &self.shared.data)
            .field("terminal", &self.terminal())
            .finish()
    }
}

impl PartialEq for WebTransportStreamReceiveTerminalRead {
    fn eq(&self, other: &Self) -> bool {
        self.session_id() == other.session_id() &&
            self.stream_id() == other.stream_id() &&
            self.shared.data == other.shared.data &&
            self.terminal() == other.terminal()
    }
}

impl Eq for WebTransportStreamReceiveTerminalRead {}

impl Drop for WebTransportStreamReceiveTerminalRead {
    fn drop(&mut self) {
        self.shared.leased.store(false, Ordering::Release);
    }
}

/// Outcome of one bounded selected-stream read.
#[derive(Debug, Eq, PartialEq)]
pub enum WebTransportStreamReadOutcome {
    /// Non-terminal payload bytes were read.
    Data {
        /// Payload bytes after the WebTransport stream prefix.
        data: Bytes,
        /// This remains false; terminal payload is returned through
        /// [`Self::Terminal`] so cancellation cannot lose FIN ownership.
        fin: bool,
    },
    /// Payload and the exact receive-terminal fact are retained in one lease.
    Terminal(WebTransportStreamReceiveTerminalRead),
    /// No payload or terminal signal is currently readable.
    Blocked,
    /// Compatibility-only unleased RESET result.
    ///
    /// Selected reads now return RESET through [`Self::Terminal`] so the exact
    /// fact remains owned across cancellation and explicit retirement.
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

/// Settlement of selected receive-terminal observation ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportStreamReceiveTerminalRetirementOutcome {
    /// The exact terminal fact was retired without changing the QUIC stream.
    Retired {
        /// CONNECT stream ID identifying the WebTransport session.
        session_id: u64,
        /// Exact physical QUIC stream ID.
        stream_id: u64,
    },
    /// No FIN or RESET has been delivered yet, so retirement was not applied.
    NotObserved {
        /// CONNECT stream ID identifying the WebTransport session.
        session_id: u64,
        /// Exact physical QUIC stream ID.
        stream_id: u64,
    },
    /// The terminal-read lease must be dropped before retirement can reclaim
    /// its retained backing allocation.
    OutstandingRead {
        /// CONNECT stream ID identifying the WebTransport session.
        session_id: u64,
        /// Exact physical QUIC stream ID.
        stream_id: u64,
    },
    /// The owning session terminated before retirement was processed.
    SessionTerminated {
        /// CONNECT stream ID identifying the WebTransport session.
        session_id: u64,
        /// Exact physical QUIC stream ID.
        stream_id: u64,
    },
    /// The enclosing connection terminated before retirement was processed.
    ConnectionTerminated {
        /// CONNECT stream ID identifying the WebTransport session.
        session_id: u64,
        /// Exact physical QUIC stream ID.
        stream_id: u64,
    },
    /// Session or associated-stream validation failed.
    Rejected(WebTransportSelectionError),
}

/// Outcome of resetting or stopping a selected stream direction.
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
    /// The transport causes from the last blocked write have produced an exact
    /// writable wake.
    ///
    /// This is permission to retry, not proof of write progress. A later write
    /// can still expose a newly relevant local cause.
    WriteTransportWake {
        /// Exact simultaneous causes from the blocked write.
        reasons: quiche::StreamSendBlockReasons,
    },
    /// The last write had a local or otherwise non-waitable blocking cause.
    WriteStateChangeRequired {
        /// Exact simultaneous causes from the blocked write turn.
        blocked_reasons: quiche::StreamSendBlockReasons,
        /// Only non-waitable causes that require an independently observed
        /// state change before an unchanged retry is safe.
        state_change_reasons: quiche::StreamSendBlockReasons,
    },
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

/// Latched terminal state of one selected stream's local send direction.
///
/// STOP_SENDING and local send closure are level-triggered: once observed,
/// repeated waits return the same first terminal state until the owning
/// WebTransport session is retired. Dropping a pending wait does not consume
/// the terminal fact. Configured terminal-fact saturation is reported as
/// [`WebTransportSelectionError::ResourceLimit`] rather than guessing a fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportStreamSendTerminalOutcome {
    /// The peer sent STOP_SENDING.
    Stopped {
        /// Exact physical QUIC stream ID.
        stream_id: u64,
        /// Exact HTTP/3 wire error carried by STOP_SENDING.
        wire_error_code: u64,
        /// Draft-16-decoded WebTransport application error, when valid.
        application_error_code: Option<u32>,
    },
    /// FIN or a local reset closed the send direction.
    Closed {
        /// Exact physical QUIC stream ID.
        stream_id: u64,
    },
    /// Selected-API observation ownership was explicitly retired.
    Retired {
        /// CONNECT stream ID identifying the WebTransport session.
        session_id: u64,
        /// Exact physical QUIC stream ID.
        stream_id: u64,
    },
    /// The owning WebTransport session terminated before the send direction.
    SessionTerminated {
        /// CONNECT stream ID identifying the WebTransport session.
        session_id: u64,
        /// Exact physical QUIC stream ID.
        stream_id: u64,
    },
    /// The enclosing QUIC connection terminated while the wait was admitted.
    ConnectionTerminated {
        /// CONNECT stream ID identifying the WebTransport session.
        session_id: u64,
        /// Exact physical QUIC stream ID.
        stream_id: u64,
    },
    /// Session or associated-stream validation failed before registration.
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
    /// Inbound, credit-waiting, or locally opening streams awaiting completed
    /// association.
    pub provisional_streams: usize,
    /// Local stream opens waiting for peer MAX_STREAMS credit.
    pub stream_open_waiters: usize,
    /// Configured aggregate pending/opening stream bound.
    pub max_stream_open_waiters: usize,
    /// Configured per-session pending/opening stream bound.
    pub max_stream_open_waiters_per_session: usize,
    /// Pending-open entries examined because credit or cancellation was ready.
    pub stream_open_waiter_work_total: u64,
    /// Open requests rejected by configured aggregate or per-session bounds.
    pub stream_open_waiter_saturation_total: u64,
    /// Pending exact-session terminal registrations.
    pub session_terminal_waiters: usize,
    /// Configured aggregate session-terminal waiter bound.
    pub max_session_terminal_waiters: usize,
    /// Configured per-session terminal waiter bound.
    pub max_session_terminal_waiters_per_session: usize,
    /// Terminal delivery and cancellation-pruning work performed.
    pub session_terminal_waiter_work_total: u64,
    /// Registrations rejected by aggregate or per-session bounds.
    pub session_terminal_waiter_saturation_total: u64,
    /// Pending local opens plus one-shot stream and Datagram registrations.
    pub waiters: usize,
    /// Pending selected-stream send-terminal registrations.
    pub send_terminal_waiters: usize,
    /// Retained first-terminal send-direction facts.
    pub send_terminal_states: usize,
    /// Configured aggregate waiter and retained-fact bound.
    pub max_send_terminal_waiters: usize,
    /// Configured per-session waiter and retained-fact bound.
    pub max_send_terminal_waiters_per_session: usize,
    /// Sessions whose terminal-fact retention bound was exhausted.
    pub send_terminal_overloaded_sessions: usize,
    /// Registration, terminal observation, and teardown-wake work performed.
    pub send_terminal_waiter_work_total: u64,
    /// Wait registrations rejected by global, per-session, or duplicate bounds.
    pub send_terminal_waiter_saturation_total: u64,
    /// Terminal facts rejected by the retained-state bound.
    pub send_terminal_state_saturation_total: u64,
    /// Receive-capable streams retaining terminal-observation ownership.
    pub receive_terminal_observations: usize,
    /// Latched FIN or RESET results awaiting explicit retirement.
    pub receive_terminal_states: usize,
    /// Pending readable waits for receive-capable streams.
    pub receive_terminal_waiters: usize,
    /// Terminal-read leases currently held outside the runtime.
    pub receive_terminal_leases: usize,
    /// Physical payload backing retained with terminal reads.
    pub receive_terminal_bytes: usize,
    /// Configured aggregate receive-terminal observation/fact bound.
    pub max_receive_terminal_states: usize,
    /// Configured per-session receive-terminal observation/fact bound.
    pub max_receive_terminal_states_per_session: usize,
    /// Configured aggregate receive-terminal waiter bound.
    pub max_receive_terminal_waiters: usize,
    /// Configured per-session receive-terminal waiter bound.
    pub max_receive_terminal_waiters_per_session: usize,
    /// Configured aggregate terminal-read backing-byte bound.
    pub max_receive_terminal_bytes: usize,
    /// Configured per-session terminal-read backing-byte bound.
    pub max_receive_terminal_bytes_per_session: usize,
    /// Peak receive-terminal observation ownership.
    pub receive_terminal_observations_high_water: usize,
    /// Peak retained receive-terminal facts.
    pub receive_terminal_states_high_water: usize,
    /// Peak retained terminal-read backing bytes.
    pub receive_terminal_bytes_high_water: usize,
    /// Peak pending receive-terminal/readable waiters.
    pub receive_terminal_waiters_high_water: usize,
    /// Streams rejected because terminal-observation capacity was full.
    pub receive_terminal_state_saturation_total: u64,
    /// Reads rejected before mutation because terminal-byte capacity was full.
    pub receive_terminal_byte_saturation_total: u64,
    /// Readable waits rejected by aggregate, per-session, or duplicate bounds.
    pub receive_terminal_waiter_saturation_total: u64,
    /// Bounded-client CONNECT stream owners currently retained outside the
    /// generic H3 event value.
    pub bounded_client_connect_owners: usize,
    /// Configured bounded-client CONNECT owner limit.
    pub max_bounded_client_connect_owners: usize,
    /// Bounded-client CONNECT owners installed after a successful response.
    pub bounded_client_connect_owner_installed_total: u64,
    /// CONNECT owners released after the authoritative session terminal fact.
    pub bounded_client_connect_owner_terminal_release_total: u64,
    /// CONNECT owners released by deterministic controller/driver teardown.
    pub bounded_client_connect_owner_teardown_release_total: u64,
    /// Successful responses delivered only after termination or teardown had
    /// already closed the owner slot.
    pub bounded_client_connect_owner_late_install_total: u64,
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
    /// Command-independent terminal-accounting waiters currently registered.
    pub terminal_retention_waiters: usize,
    /// Intrinsic command-independent terminal-accounting waiter bound.
    pub max_terminal_retention_waiters: usize,
    /// Waits rejected because the single terminal-accounting slot was full.
    pub terminal_retention_waiter_saturation_total: u64,
    /// Registered terminal-accounting waits cancelled before completion.
    pub terminal_retention_waiter_cancellation_total: u64,
    /// Selected-I/O commands queued behind this snapshot command.
    pub queued_commands: usize,
    /// Conservative logical payload bound for those queued commands.
    pub queued_command_payload_bytes_upper_bound: usize,
    /// Outstanding generic write leases in commands or unconsumed results,
    /// plus one-use retry tokens retaining a zero-byte accounting slot.
    pub write_leases: usize,
    /// Owner-declared bytes retained while write owners are runtime-owned.
    /// Returned owners are removed from this value before a retry token is
    /// exposed.
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

    fn settle_terminal(
        &mut self, write_leases: Option<WriteLeaseAccountingSnapshot>,
    ) {
        self.sessions = 0;
        self.associated_streams = 0;
        self.provisional_streams = 0;
        self.stream_open_waiters = 0;
        self.session_terminal_waiters = 0;
        self.waiters = 0;
        self.send_terminal_waiters = 0;
        self.send_terminal_states = 0;
        self.send_terminal_overloaded_sessions = 0;
        self.receive_terminal_observations = 0;
        self.receive_terminal_states = 0;
        self.receive_terminal_waiters = 0;
        self.receive_terminal_leases = 0;
        self.receive_terminal_bytes = 0;
        self.bounded_client_connect_owners = 0;
        self.metadata_index_entries = 0;
        self.pending_datagrams = 0;
        self.pending_datagram_payload_bytes = 0;
        self.pending_datagram_allocation_bytes = 0;
        self.terminal_retention_waiters = 0;
        self.queued_commands = 0;
        self.queued_command_payload_bytes_upper_bound = 0;
        self.write_leases = 0;
        self.write_lease_retained_bytes = 0;
        self.transport_stream_send_bytes = 0;
        self.transport_stream_receive_bytes = 0;
        self.transport_datagram_send_bytes = 0;
        self.transport_datagram_receive_bytes = 0;

        if let Some(write_leases) = write_leases {
            self.max_write_leases = write_leases.max_count;
            self.max_write_lease_retained_bytes = write_leases.max_retained_bytes;
            self.write_lease_admitted_total = write_leases.admitted_total;
            self.write_lease_queue_full_total = write_leases.queue_full_total;
            self.write_lease_resource_limit_total =
                write_leases.resource_limit_total;
            self.write_lease_too_large_total = write_leases.too_large_total;
            self.write_lease_abandoned_unexposed_total =
                write_leases.abandoned_unexposed_total;
            self.write_lease_abandoned_zero_total =
                write_leases.abandoned_zero_total;
            self.write_lease_abandoned_unknown_total =
                write_leases.abandoned_unknown_total;
        }
    }
}

/// Exact unresolved ownership preventing terminal retention accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WebTransportTerminalRetentionPending {
    /// Whether the selected command lane and runtime have settled.
    pub runtime_settled: bool,
    /// Whether a worker installed the core-connection destruction hook.
    pub connection_owner_attached: bool,
    /// Whether the worker-owned core connection has been destroyed.
    pub connection_owner_dropped: bool,
    /// Outstanding write operations or one-use retry permissions.
    pub write_leases: usize,
    /// Owner-declared bytes still retained by outstanding write operations.
    pub write_lease_retained_bytes: usize,
    /// Terminal receive results still held outside the cleared runtime.
    pub receive_terminal_leases: usize,
    /// Payload backing held by outstanding terminal receive results.
    pub receive_terminal_bytes: usize,
}

/// Result of taking one controller's authoritative terminal accounting.
#[derive(Debug, Eq, PartialEq)]
pub enum WebTransportTerminalRetentionOutcome {
    /// The take succeeded and consumed the only authoritative snapshot.
    Taken(Box<WebTransportRetentionStats>),
    /// Teardown or external ownership has not settled yet.
    Early(WebTransportTerminalRetentionPending),
    /// Another clone already consumed the authoritative snapshot.
    AlreadyTaken,
    /// The claim belongs to an independently constructed controller.
    ForeignController,
    /// The caller explicitly cancelled its pending wait.
    Cancelled,
    /// Another terminal-accounting waiter already occupies the bounded slot.
    WaiterUnavailable,
    /// No exact core-owner lifecycle hook was attached before teardown.
    Unavailable,
}

/// Opaque capability binding a terminal-accounting take to one controller.
#[derive(Clone)]
pub struct WebTransportTerminalRetentionClaim {
    state: Arc<TerminalRetentionState>,
}

impl fmt::Debug for WebTransportTerminalRetentionClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebTransportTerminalRetentionClaim")
            .finish_non_exhaustive()
    }
}

/// One bounded, cancellation-safe terminal-accounting wait operation.
pub struct WebTransportTerminalRetentionOperation {
    state: Arc<TerminalRetentionState>,
    immediate: Option<WebTransportTerminalRetentionOutcome>,
    registered: bool,
    completed: bool,
}

impl fmt::Debug for WebTransportTerminalRetentionOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebTransportTerminalRetentionOperation")
            .field("registered", &self.registered)
            .field("completed", &self.completed)
            .finish_non_exhaustive()
    }
}

impl WebTransportTerminalRetentionOperation {
    /// Cancels this wait without consuming the eventual terminal result.
    pub fn cancel(mut self) -> WebTransportTerminalRetentionOutcome {
        if self.registered {
            self.state.cancel_waiter();
            self.registered = false;
        }
        self.completed = true;
        WebTransportTerminalRetentionOutcome::Cancelled
    }
}

impl Future for WebTransportTerminalRetentionOperation {
    type Output = WebTransportTerminalRetentionOutcome;

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        if let Some(outcome) = self.immediate.take() {
            self.completed = true;
            return Poll::Ready(outcome);
        }

        let (outcome, registered) = self.state.poll_take(cx, self.registered);
        self.registered = registered;
        if outcome.is_ready() {
            self.completed = true;
        }
        outcome
    }
}

impl Drop for WebTransportTerminalRetentionOperation {
    fn drop(&mut self) {
        if !self.completed && self.registered {
            self.state.cancel_waiter();
        }
    }
}

#[derive(Debug)]
struct TerminalRetentionInner {
    runtime_stats: Option<Box<WebTransportRetentionStats>>,
    runtime_settled: bool,
    write_lease_accounting: Option<Arc<WriteLeaseAccounting>>,
    connection_owner_attached: bool,
    connection_owner_dropped: bool,
    receive_terminal_leases: usize,
    receive_terminal_bytes: usize,
    waiter: Option<Waker>,
    waiter_saturation_total: u64,
    waiter_cancellation_total: u64,
    taken: bool,
    unavailable: bool,
}

impl Default for TerminalRetentionInner {
    fn default() -> Self {
        Self {
            runtime_stats: Some(Box::default()),
            runtime_settled: false,
            write_lease_accounting: None,
            connection_owner_attached: false,
            connection_owner_dropped: false,
            receive_terminal_leases: 0,
            receive_terminal_bytes: 0,
            waiter: None,
            waiter_saturation_total: 0,
            waiter_cancellation_total: 0,
            taken: false,
            unavailable: false,
        }
    }
}

#[derive(Debug)]
pub(super) struct TerminalRetentionState {
    inner: Mutex<TerminalRetentionInner>,
}

impl TerminalRetentionState {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(TerminalRetentionInner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TerminalRetentionInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn bind_write_lease_accounting(
        &self, accounting: &Arc<WriteLeaseAccounting>,
    ) {
        self.lock().write_lease_accounting = Some(Arc::clone(accounting));
    }

    fn write_lease_snapshot(
        inner: &TerminalRetentionInner,
    ) -> Option<WriteLeaseAccountingSnapshot> {
        inner
            .write_lease_accounting
            .as_ref()
            .map(|accounting| accounting.snapshot())
    }

    fn pending(
        inner: &TerminalRetentionInner,
        write_leases: Option<WriteLeaseAccountingSnapshot>,
    ) -> WebTransportTerminalRetentionPending {
        let write_leases = write_leases.unwrap_or_default();
        WebTransportTerminalRetentionPending {
            runtime_settled: inner.runtime_settled,
            connection_owner_attached: inner.connection_owner_attached,
            connection_owner_dropped: inner.connection_owner_dropped,
            write_leases: write_leases.current,
            write_lease_retained_bytes: write_leases.retained_bytes,
            receive_terminal_leases: inner.receive_terminal_leases,
            receive_terminal_bytes: inner.receive_terminal_bytes,
        }
    }

    fn take_locked(
        inner: &mut TerminalRetentionInner,
        write_leases: Option<WriteLeaseAccountingSnapshot>,
    ) -> WebTransportTerminalRetentionOutcome {
        if inner.taken {
            return WebTransportTerminalRetentionOutcome::AlreadyTaken;
        }
        if inner.unavailable {
            return WebTransportTerminalRetentionOutcome::Unavailable;
        }

        let settled = inner.runtime_settled &&
            inner.connection_owner_dropped &&
            inner.receive_terminal_leases == 0 &&
            write_leases.is_none_or(|snapshot| snapshot.current == 0);
        if !settled {
            return WebTransportTerminalRetentionOutcome::Early(Self::pending(
                inner,
                write_leases,
            ));
        }

        let mut stats = inner
            .runtime_stats
            .take()
            .expect("terminal accounting preallocates one snapshot");
        stats.settle_terminal(write_leases);
        stats.terminal_retention_waiters = 0;
        stats.max_terminal_retention_waiters = 1;
        stats.terminal_retention_waiter_saturation_total =
            inner.waiter_saturation_total;
        stats.terminal_retention_waiter_cancellation_total =
            inner.waiter_cancellation_total;
        inner.write_lease_accounting = None;
        inner.taken = true;
        WebTransportTerminalRetentionOutcome::Taken(stats)
    }

    fn try_take(&self) -> WebTransportTerminalRetentionOutcome {
        let mut inner = self.lock();
        let write_leases = Self::write_lease_snapshot(&inner);
        let outcome = Self::take_locked(&mut inner, write_leases);
        let waiter = outcome.is_terminal().then(|| inner.waiter.take()).flatten();
        drop(inner);
        if let Some(waiter) = waiter {
            waiter.wake();
        }
        outcome
    }

    fn poll_take(
        &self, cx: &mut Context<'_>, registered: bool,
    ) -> (Poll<WebTransportTerminalRetentionOutcome>, bool) {
        let mut inner = self.lock();
        let write_leases = Self::write_lease_snapshot(&inner);
        let outcome = Self::take_locked(&mut inner, write_leases);
        if !matches!(outcome, WebTransportTerminalRetentionOutcome::Early(_)) {
            inner.waiter = None;
            return (Poll::Ready(outcome), false);
        }
        if !registered && inner.waiter.is_some() {
            inner.waiter_saturation_total =
                inner.waiter_saturation_total.saturating_add(1);
            return (
                Poll::Ready(
                    WebTransportTerminalRetentionOutcome::WaiterUnavailable,
                ),
                false,
            );
        }
        inner.waiter = Some(cx.waker().clone());
        (Poll::Pending, true)
    }

    fn cancel_waiter(&self) {
        let mut inner = self.lock();
        if inner.waiter.take().is_some() {
            inner.waiter_cancellation_total =
                inner.waiter_cancellation_total.saturating_add(1);
        }
    }

    fn wake_if_terminal(&self) {
        let waiter = {
            let mut inner = self.lock();
            let write_leases = Self::write_lease_snapshot(&inner);
            let terminal = inner.unavailable ||
                inner.taken ||
                (inner.runtime_settled &&
                    inner.connection_owner_dropped &&
                    inner.receive_terminal_leases == 0 &&
                    write_leases
                        .is_none_or(|snapshot| snapshot.current == 0));
            terminal.then(|| inner.waiter.take()).flatten()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    pub(super) fn mark_connection_owner_attached(&self) {
        self.lock().connection_owner_attached = true;
    }

    pub(super) fn mark_connection_owner_dropped(&self) {
        self.lock().connection_owner_dropped = true;
        self.wake_if_terminal();
    }

    pub(super) fn mark_runtime_settled(&self, stats: WebTransportRetentionStats) {
        let mut inner = self.lock();
        if !inner.runtime_settled && !inner.unavailable {
            **inner
                .runtime_stats
                .as_mut()
                .expect("terminal accounting preallocates one snapshot") = stats;
            inner.runtime_settled = true;
        }
        drop(inner);
        self.wake_if_terminal();
    }

    pub(super) fn mark_driver_dropped(&self) {
        let mut inner = self.lock();
        if !inner.connection_owner_attached {
            inner.unavailable = true;
            inner.runtime_stats = None;
            inner.write_lease_accounting = None;
        }
        drop(inner);
        self.wake_if_terminal();
    }

    pub(super) fn augment_stats(&self, stats: &mut WebTransportRetentionStats) {
        let inner = self.lock();
        stats.terminal_retention_waiters = usize::from(inner.waiter.is_some());
        stats.max_terminal_retention_waiters = 1;
        stats.terminal_retention_waiter_saturation_total =
            inner.waiter_saturation_total;
        stats.terminal_retention_waiter_cancellation_total =
            inner.waiter_cancellation_total;
    }

    fn retain_receive_terminal(
        self: &Arc<Self>, bytes: usize,
    ) -> TerminalReceiveRetentionGuard {
        let mut inner = self.lock();
        inner.receive_terminal_leases =
            inner.receive_terminal_leases.saturating_add(1);
        inner.receive_terminal_bytes =
            inner.receive_terminal_bytes.saturating_add(bytes);
        TerminalReceiveRetentionGuard {
            state: Arc::clone(self),
            bytes,
        }
    }
}

trait TerminalRetentionOutcomeExt {
    fn is_terminal(&self) -> bool;
}

impl TerminalRetentionOutcomeExt for WebTransportTerminalRetentionOutcome {
    fn is_terminal(&self) -> bool {
        !matches!(self, Self::Early(_))
    }
}

#[derive(Debug)]
struct TerminalReceiveRetentionGuard {
    state: Arc<TerminalRetentionState>,
    bytes: usize,
}

impl Drop for TerminalReceiveRetentionGuard {
    fn drop(&mut self) {
        let mut inner = self.state.lock();
        inner.receive_terminal_leases =
            inner.receive_terminal_leases.saturating_sub(1);
        inner.receive_terminal_bytes =
            inner.receive_terminal_bytes.saturating_sub(self.bytes);
        drop(inner);
        self.state.wake_if_terminal();
    }
}

#[derive(Debug, Default)]
struct WriteLeaseAccountingState {
    closed: bool,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteLeaseAdmissionError {
    Closed,
    ResourceLimit,
}

#[derive(Debug)]
pub(crate) struct WriteLeaseAccounting {
    // This allocation also scopes retry tokens to one driver construction.
    // Independent drivers must never share it.
    max_count: usize,
    max_retained_bytes: usize,
    state: Mutex<WriteLeaseAccountingState>,
    terminal_retention: Weak<TerminalRetentionState>,
}

impl WriteLeaseAccounting {
    pub(super) fn new(
        max_count: usize, max_retained_bytes_per_lease: usize,
        terminal_retention: Weak<TerminalRetentionState>,
    ) -> Self {
        let max_count = max_count.max(1);
        Self {
            max_count,
            max_retained_bytes: max_count
                .saturating_mul(max_retained_bytes_per_lease),
            state: Mutex::new(WriteLeaseAccountingState::default()),
            terminal_retention,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WriteLeaseAccountingState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn try_admit(
        self: &Arc<Self>, retained_bytes: usize,
    ) -> Result<WriteLeaseAccountingGuard, WriteLeaseAdmissionError> {
        let mut state = self.lock();
        if state.closed {
            return Err(WriteLeaseAdmissionError::Closed);
        }
        let Some(next_bytes) = state.retained_bytes.checked_add(retained_bytes)
        else {
            state.resource_limit_total =
                state.resource_limit_total.saturating_add(1);
            return Err(WriteLeaseAdmissionError::ResourceLimit);
        };
        if state.current >= self.max_count || next_bytes > self.max_retained_bytes
        {
            state.resource_limit_total =
                state.resource_limit_total.saturating_add(1);
            return Err(WriteLeaseAdmissionError::ResourceLimit);
        }

        state.current += 1;
        state.retained_bytes = next_bytes;
        state.admitted_total = state.admitted_total.saturating_add(1);
        drop(state);
        Ok(WriteLeaseAccountingGuard {
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

    fn close(&self) {
        self.lock().closed = true;
    }

    fn notify_terminal_retention(&self) {
        if let Some(terminal_retention) = self.terminal_retention.upgrade() {
            terminal_retention.wake_if_terminal();
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
        drop(state);
        self.accounting.notify_terminal_retention();
    }
}

impl WriteLeaseAccountingGuard {
    fn release_retained_bytes(&mut self) {
        let mut state = self.accounting.lock();
        state.retained_bytes =
            state.retained_bytes.saturating_sub(self.retained_bytes);
        self.retained_bytes = 0;
    }
}

enum WriteLeaseCompletion<E> {
    Accepted {
        accepted: usize,
        complete: bool,
        fin_accepted: bool,
    },
    Blocked(quiche::StreamSendBlockReasons),
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

    fn take_retry_reservation(&mut self) -> WriteLeaseAccountingGuard {
        let mut accounting = self
            .accounting
            .take()
            .expect("admitted blocked write must retain its accounting slot");
        accounting.release_retained_bytes();
        accounting
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
    session_id: u64,
    stream_id: u64,
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
        let retry_reservation =
            matches!(&completion, WriteLeaseCompletion::Blocked(_))
                .then(|| self.owner.take_retry_reservation());
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
            WriteLeaseCompletion::Blocked(reasons) =>
                WebTransportStreamWriteLeaseOutcome::Blocked {
                    lease,
                    fin: self.fin,
                    reasons,
                    retry: WebTransportStreamWriteRetry {
                        session_id: self.session_id,
                        stream_id: self.stream_id,
                        reasons,
                        disposition: reasons.retry_disposition(),
                        reservation: retry_reservation.expect(
                            "blocked write must transfer its accounting slot",
                        ),
                    },
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
            ..
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
/// only a negotiated reliable association prefix. Standard-reset cancellation
/// settles immediately instead of retrying the prefix. Payload writes and
/// Datagrams make one transport admission attempt and return unaccepted
/// ownership to the caller. Connection teardown resolves every admitted command
/// with a terminal outcome.
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
    cancellation_pending: Arc<AtomicBool>,
    max_stream_write_bytes: usize,
    max_stream_write_lease_retained_bytes: usize,
    max_stream_write_lease_owner_bytes: usize,
    max_stream_read_bytes: usize,
    max_datagram_send_bytes: usize,
    max_datagram_send_allocation_bytes: usize,
    max_datagram_prefixed_allocation_bytes: usize,
    write_lease_accounting: Arc<WriteLeaseAccounting>,
    terminal_retention: Arc<TerminalRetentionState>,
}

pub(crate) struct WebTransportControllerLimits {
    pub(crate) max_stream_write_bytes: usize,
    pub(crate) max_stream_write_lease_retained_bytes: usize,
    pub(crate) max_stream_write_lease_owner_bytes: usize,
    pub(crate) max_stream_read_bytes: usize,
    pub(crate) max_datagram_send_allocation_bytes: usize,
    pub(crate) max_datagram_prefixed_allocation_bytes: usize,
}

impl WebTransportController {
    pub(super) fn new(
        sender: mpsc::Sender<WebTransportCommand>,
        limits: WebTransportControllerLimits,
        write_lease_accounting: Arc<WriteLeaseAccounting>,
        cancellation_pending: Arc<AtomicBool>,
        terminal_retention: Arc<TerminalRetentionState>,
    ) -> Self {
        Self {
            sender,
            cancellation_pending,
            max_stream_write_bytes: limits.max_stream_write_bytes,
            max_stream_write_lease_retained_bytes: limits
                .max_stream_write_lease_retained_bytes,
            max_stream_write_lease_owner_bytes: limits
                .max_stream_write_lease_owner_bytes,
            max_stream_read_bytes: limits.max_stream_read_bytes,
            max_datagram_send_bytes: datagram_socket::MAX_DATAGRAM_SIZE,
            max_datagram_send_allocation_bytes: limits
                .max_datagram_send_allocation_bytes,
            max_datagram_prefixed_allocation_bytes: limits
                .max_datagram_prefixed_allocation_bytes,
            write_lease_accounting,
            terminal_retention,
        }
    }

    /// Returns an opaque claim for this controller's terminal accounting.
    ///
    /// Claims contain no diagnostic identity and can be created before or
    /// after connection teardown. A claim is accepted by clones of this
    /// controller and rejected by independently constructed controllers.
    pub fn terminal_retention_claim(&self) -> WebTransportTerminalRetentionClaim {
        WebTransportTerminalRetentionClaim {
            state: Arc::clone(&self.terminal_retention),
        }
    }

    /// Attempts to consume the take-once terminal accounting result.
    ///
    /// [`WebTransportTerminalRetentionOutcome::Early`] reports exact external
    /// ownership still preventing completion. This method never registers a
    /// waiter and never uses the selected command lane.
    pub fn try_take_terminal_retention(
        &self, claim: &WebTransportTerminalRetentionClaim,
    ) -> WebTransportTerminalRetentionOutcome {
        if !Arc::ptr_eq(&self.terminal_retention, &claim.state) {
            return WebTransportTerminalRetentionOutcome::ForeignController;
        }
        self.terminal_retention.try_take()
    }

    /// Waits without the selected command lane for terminal accounting.
    ///
    /// Exactly one operation can wait at a time. Dropping or explicitly
    /// cancelling the operation releases that slot without consuming the
    /// eventual result.
    pub fn wait_terminal_retention(
        &self, claim: WebTransportTerminalRetentionClaim,
    ) -> WebTransportTerminalRetentionOperation {
        let immediate = (!Arc::ptr_eq(&self.terminal_retention, &claim.state))
            .then_some(WebTransportTerminalRetentionOutcome::ForeignController);
        WebTransportTerminalRetentionOperation {
            state: claim.state,
            immediate,
            registered: false,
            completed: false,
        }
    }

    /// Waits for one exact native WebTransport session to become terminal.
    ///
    /// This operation consumes no QUIC stream credit and is level-triggered:
    /// dropping a pending future does not consume the eventual terminal fact,
    /// and a later registration observes a retained fact immediately. The
    /// session registry retains that fact only until normal session collection.
    pub async fn wait_session_terminal(
        &self, session_id: u64,
    ) -> WebTransportSessionTerminalOutcome {
        let connection_closed =
            || WebTransportSessionTerminalOutcome::Terminated {
                session_id,
                reason: WebTransportSessionCloseReason::ConnectionClosed,
            };
        let Ok(permit) = self.sender.reserve().await else {
            return connection_closed();
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::WaitSessionTerminal {
            session_id,
            response,
        });
        let mut cancellation = CancellationWake::new(
            self.sender.clone(),
            Arc::clone(&self.cancellation_pending),
        );
        let outcome = recv.await.unwrap_or_else(|_| connection_closed());
        cancellation.disarm();
        outcome
    }

    fn prefixed_datagram_allocation(
        &self, datagram: &DgramBuffer,
    ) -> Option<usize> {
        datagram.required_capacity_with_headroom(
            crate::buf_factory::BufFactory::DGRAM_HEADROOM,
        )
    }

    /// Opens a bidirectional stream for an exact active Session ID.
    ///
    /// The result contains the physical QUIC stream ID after the complete
    /// WebTransport association prefix has been accepted exactly once.
    /// Temporary peer
    /// MAX_STREAMS exhaustion keeps this future pending without polling;
    /// [`WebTransportSelectionError::ResourceLimit`] means a configured local
    /// pending/opening bound was reached instead. Cancellation releases the
    /// retained request through the bounded driver command lane.
    pub async fn open_bidirectional_stream(
        &self, session_id: u64,
    ) -> WebTransportOpenStreamOutcome {
        self.open_stream(session_id, WebTransportStreamDirection::Bidi)
            .await
    }

    /// Opens a unidirectional stream for an exact active Session ID.
    ///
    /// The result contains the physical QUIC stream ID after the complete
    /// WebTransport association prefix has been accepted exactly once.
    /// Temporary peer
    /// MAX_STREAMS exhaustion keeps this future pending without polling;
    /// [`WebTransportSelectionError::ResourceLimit`] means a configured local
    /// pending/opening bound was reached instead. Requests are FIFO within one
    /// direction and work rotates across directions.
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
        let mut cancellation = CancellationWake::new(
            self.sender.clone(),
            Arc::clone(&self.cancellation_pending),
        );
        let outcome =
            recv.await
                .unwrap_or(WebTransportOpenStreamOutcome::Rejected(
                    WebTransportSelectionError::ConnectionClosed,
                ));
        cancellation.disarm();
        outcome
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
        let accounting =
            match self.write_lease_accounting.try_admit(retained_bytes) {
                Ok(accounting) => accounting,
                Err(WriteLeaseAdmissionError::Closed) =>
                    return WebTransportStreamWriteLeaseOutcome::Rejected {
                        error: WebTransportSelectionError::ConnectionClosed,
                        lease: owner.take(),
                        fin,
                    },
                Err(WriteLeaseAdmissionError::ResourceLimit) =>
                    return WebTransportStreamWriteLeaseOutcome::ResourceLimit {
                        lease: owner.take(),
                        fin,
                    },
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
        let accounting = match self
            .write_lease_accounting
            .try_admit(retained_bytes)
        {
            Ok(accounting) => accounting,
            Err(WriteLeaseAdmissionError::Closed) =>
                return Err(WebTransportStreamWriteLeaseOutcome::Rejected {
                    error: WebTransportSelectionError::ConnectionClosed,
                    lease,
                    fin,
                }),
            Err(WriteLeaseAdmissionError::ResourceLimit) =>
                return Err(WebTransportStreamWriteLeaseOutcome::ResourceLimit {
                    lease,
                    fin,
                }),
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
        let owner_bytes = std::mem::size_of::<L>();
        if owner_bytes > self.max_stream_write_lease_owner_bytes {
            self.write_lease_accounting.record_too_large();
            return Err((
                WebTransportStreamWriteLeaseLimit::OwnerBytes,
                self.max_stream_write_lease_owner_bytes,
                owner_bytes,
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
            session_id,
            stream_id,
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
        self.wait_stream(session_id, stream_id, false, None).await
    }

    /// Waits without polling after one exact selected-stream write blocked.
    ///
    /// The one-use context binds readiness to the exact controller turn that
    /// returned it. Transport-only causes can produce
    /// [`WebTransportStreamReadyOutcome::WriteTransportWake`]. Local or
    /// unavailable-path causes instead return
    /// [`WebTransportStreamReadyOutcome::WriteStateChangeRequired`]. Consuming
    /// the context prevents repeated wake loops without a new write attempt.
    pub async fn wait_stream_writable(
        &self, retry: WebTransportStreamWriteRetry,
    ) -> WebTransportStreamReadyOutcome {
        if !retry.belongs_to(&self.write_lease_accounting) {
            return WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ForeignController,
            );
        }
        self.wait_stream(retry.session_id, retry.stream_id, true, Some(retry))
            .await
    }

    /// Waits for one exact selected stream's local send direction to terminate.
    ///
    /// Ordinary writability and flow-control blocking do not complete this
    /// wait. STOP_SENDING and local send closure are retained as one
    /// level-triggered first-terminal fact, so registration after transport
    /// delivery and re-registration after cancellation remain race-free.
    /// Configured waiter or retained-fact saturation returns
    /// [`WebTransportSelectionError::ResourceLimit`].
    pub async fn wait_stream_send_terminal(
        &self, session_id: u64, stream_id: u64,
    ) -> WebTransportStreamSendTerminalOutcome {
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            );
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::WaitSendTerminal {
            session_id,
            stream_id,
            response,
        });
        recv.await.unwrap_or(
            WebTransportStreamSendTerminalOutcome::ConnectionTerminated {
                session_id,
                stream_id,
            },
        )
    }

    /// Retires selected-API observation of one stream's local send direction.
    ///
    /// This is idempotent while the selected stream remains owned. It settles a
    /// pending terminal wait with
    /// [`WebTransportStreamSendTerminalOutcome::Retired`] and removes
    /// retained terminal state, waiter accounting, and overload accounting
    /// without changing the QUIC stream. Later terminal callbacks are ignored
    /// for this observation lifetime. After the underlying selected stream is
    /// collected, the existing stale-stream result replaces idempotence so no
    /// permanent stream-ID tombstone is retained.
    pub async fn retire_stream_send_terminal(
        &self, session_id: u64, stream_id: u64,
    ) -> WebTransportStreamSendTerminalOutcome {
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            );
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::RetireSendTerminal {
            session_id,
            stream_id,
            response,
        });
        recv.await.unwrap_or(
            WebTransportStreamSendTerminalOutcome::ConnectionTerminated {
                session_id,
                stream_id,
            },
        )
    }

    /// Retires a delivered FIN or RESET for one selected receive direction.
    ///
    /// Until this succeeds, the exact terminal fact and any payload delivered
    /// with it remain level-triggered and prevent selected-stream collection.
    /// Calling this before a terminal read returns
    /// [`WebTransportStreamReceiveTerminalRetirementOutcome::NotObserved`]
    /// without changing the stream or its future receive ownership. The
    /// terminal-read lease must be dropped first; an outstanding lease returns
    /// [`WebTransportStreamReceiveTerminalRetirementOutcome::OutstandingRead`]
    /// so its backing bytes cannot escape the configured retention accounting.
    pub async fn retire_stream_receive_terminal(
        &self, session_id: u64, stream_id: u64,
    ) -> WebTransportStreamReceiveTerminalRetirementOutcome {
        let Ok(permit) = self.sender.reserve().await else {
            return WebTransportStreamReceiveTerminalRetirementOutcome::Rejected(
                WebTransportSelectionError::ConnectionClosed,
            );
        };
        let (response, recv) = oneshot::channel();
        permit.send(WebTransportCommand::RetireReceiveTerminal {
            session_id,
            stream_id,
            response,
        });
        recv.await.unwrap_or(
            WebTransportStreamReceiveTerminalRetirementOutcome::ConnectionTerminated {
                session_id,
                stream_id,
            },
        )
    }

    async fn wait_stream(
        &self, session_id: u64, stream_id: u64, write: bool,
        retry: Option<WebTransportStreamWriteRetry>,
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
            retry,
            response,
        });
        let mut cancellation = CancellationWake::new(
            self.sender.clone(),
            Arc::clone(&self.cancellation_pending),
        );
        let outcome =
            recv.await
                .unwrap_or(WebTransportStreamReadyOutcome::Rejected(
                    WebTransportSelectionError::ConnectionClosed,
                ));
        cancellation.disarm();
        outcome
    }

    /// Resets the stream using the negotiated reset mode and error mapping.
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
        let prefixed_allocation = self
            .prefixed_datagram_allocation(&datagram)
            .unwrap_or(usize::MAX);
        if prefixed_allocation > self.max_datagram_prefixed_allocation_bytes {
            return WebTransportDatagramSendOutcome::AllocationTooLarge {
                max: self.max_datagram_prefixed_allocation_bytes,
                allocated: prefixed_allocation,
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
        let prefixed_allocation = self
            .prefixed_datagram_allocation(&datagram)
            .unwrap_or(usize::MAX);
        if prefixed_allocation > self.max_datagram_prefixed_allocation_bytes {
            return Err(WebTransportDatagramSendOutcome::AllocationTooLarge {
                max: self.max_datagram_prefixed_allocation_bytes,
                allocated: prefixed_allocation,
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
        let mut stats = recv
            .await
            .unwrap_or(Err(WebTransportDatagramError::ConnectionClosed))?;
        self.terminal_retention.augment_stats(&mut stats);
        Ok(stats)
    }
}

struct CancellationWake {
    sender: mpsc::Sender<WebTransportCommand>,
    pending: Arc<AtomicBool>,
    armed: bool,
}

impl CancellationWake {
    fn new(
        sender: mpsc::Sender<WebTransportCommand>, pending: Arc<AtomicBool>,
    ) -> Self {
        Self {
            sender,
            pending,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancellationWake {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.pending.store(true, Ordering::Release);
        let _ = self
            .sender
            .try_send(WebTransportCommand::PruneCancelledWaiters);
    }
}

pub(crate) trait ErasedWriteLeaseCommand: Send {
    fn execute(
        self: Box<Self>, runtime: &mut Runtime, qconn: &mut QuicheConnection,
    );

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
        mut self: Box<Self>, runtime: &mut Runtime, qconn: &mut QuicheConnection,
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
                        qconn.stream_send_detailed(self.stream_id, data, fin),
                    )),
                    Err(error) => Err((
                        WriteLeaseCompletion::LeaseError(error),
                        WebTransportStreamWriteLeaseProgress::NeverExposed,
                    )),
                }
            };

            match result {
                Err(result) => result,
                Ok((
                    actual,
                    Ok(quiche::StreamSendOutcome::Accepted(accepted)),
                )) => {
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
                Ok((_, Ok(quiche::StreamSendOutcome::Blocked(reasons)))) => (
                    WriteLeaseCompletion::Blocked(reasons),
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
        runtime.observe_send_terminal(qconn, self.stream_id);
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
    WaitSessionTerminal {
        session_id: u64,
        response: oneshot::Sender<WebTransportSessionTerminalOutcome>,
    },
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
        retry: Option<WebTransportStreamWriteRetry>,
        response: oneshot::Sender<WebTransportStreamReadyOutcome>,
    },
    WaitSendTerminal {
        session_id: u64,
        stream_id: u64,
        response: oneshot::Sender<WebTransportStreamSendTerminalOutcome>,
    },
    RetireSendTerminal {
        session_id: u64,
        stream_id: u64,
        response: oneshot::Sender<WebTransportStreamSendTerminalOutcome>,
    },
    RetireReceiveTerminal {
        session_id: u64,
        stream_id: u64,
        response:
            oneshot::Sender<WebTransportStreamReceiveTerminalRetirementOutcome>,
    },
    PruneCancelledWaiters,
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
            Self::WaitSessionTerminal {
                session_id,
                response,
            } => {
                let _ = response.send(
                    WebTransportSessionTerminalOutcome::Terminated {
                        session_id,
                        reason: WebTransportSessionCloseReason::ConnectionClosed,
                    },
                );
            },
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
            Self::WaitSendTerminal {
                session_id,
                stream_id,
                response,
            } => {
                let _ = response.send(
                    WebTransportStreamSendTerminalOutcome::ConnectionTerminated {
                        session_id,
                        stream_id,
                    },
                );
            },
            Self::RetireSendTerminal {
                session_id,
                stream_id,
                response,
            } => {
                let _ = response.send(
                    WebTransportStreamSendTerminalOutcome::ConnectionTerminated {
                        session_id,
                        stream_id,
                    },
                );
            },
            Self::RetireReceiveTerminal {
                session_id,
                stream_id,
                response,
            } => {
                let _ = response.send(
                    WebTransportStreamReceiveTerminalRetirementOutcome::ConnectionTerminated {
                        session_id,
                        stream_id,
                    },
                );
            },
            Self::PruneCancelledWaiters => {},
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
    pub(crate) max_active_streams: usize,
    pub(crate) max_active_streams_per_session: usize,
    pub(crate) max_stream_waiters: usize,
    pub(crate) max_session_terminal_waiters: usize,
    pub(crate) max_session_terminal_waiters_per_session: usize,
    pub(crate) max_send_terminal_waiters: usize,
    pub(crate) max_send_terminal_waiters_per_session: usize,
    pub(crate) max_receive_terminal_states: usize,
    pub(crate) max_receive_terminal_states_per_session: usize,
    pub(crate) max_receive_terminal_waiters: usize,
    pub(crate) max_receive_terminal_waiters_per_session: usize,
    pub(crate) max_receive_terminal_bytes: usize,
    pub(crate) max_receive_terminal_bytes_per_session: usize,
    pub(crate) max_datagram_waiters: usize,
    pub(crate) max_pending_datagrams: usize,
    pub(crate) max_pending_datagrams_per_session: usize,
    pub(crate) max_pending_datagram_bytes: usize,
    pub(crate) max_pending_datagram_bytes_per_session: usize,
    pub(crate) max_pending_datagram_allocation_bytes: usize,
    pub(crate) max_pending_datagram_allocation_bytes_per_session: usize,
    pub(crate) max_pending_datagram_age: Duration,
    pub(crate) max_datagram_prefixed_allocation_bytes: usize,
    pub(crate) command_capacity: usize,
    pub(crate) max_command_payload_bytes: usize,
    pub(crate) max_write_lease_retained_bytes_per_lease: usize,
    pub(crate) max_session_work_per_callback: usize,
}

pub(super) fn runtime_metadata_upper_bound(
    max_pending_streams: usize, max_active_streams: usize,
    max_stream_waiters: usize, max_send_terminal_waiters: usize,
    max_receive_terminal_states: usize, max_receive_terminal_waiters: usize,
    max_session_terminal_waiters: usize,
) -> Option<usize> {
    let pending_value_bytes = std::mem::size_of::<AssociatedStream>()
        .checked_add(std::mem::size_of::<OpeningStream>())?
        .checked_add(std::mem::size_of::<PendingOpen>())?
        .checked_add(std::mem::size_of::<u64>() * 4)?;
    let active_value_bytes = std::mem::size_of::<OwnedStream>()
        .checked_add(std::mem::size_of::<u64>() * 2)?;
    let waiter_value_bytes = std::mem::size_of::<StreamReadyWaiter>()
        .checked_add(std::mem::size_of::<u64>() * 2)?;
    let terminal_value_bytes = std::mem::size_of::<SendTerminalWaiter>()
        .checked_add(std::mem::size_of::<LatchedSendTerminal>())?
        .checked_add(std::mem::size_of::<u64>() * 3)?;
    let receive_terminal_value_bytes =
        std::mem::size_of::<Arc<ReceiveTerminalReadShared>>()
            .checked_add(std::mem::size_of::<ReceiveTerminalReadShared>())?
            .checked_add(std::mem::size_of::<usize>() * 2)?
            .checked_add(std::mem::size_of::<u64>() * 3)?;
    let session_terminal_value_bytes = std::mem::size_of::<
        oneshot::Sender<WebTransportSessionTerminalOutcome>,
    >()
    .checked_add(std::mem::size_of::<WebTransportSessionTerminalOutcome>())?
    .checked_add(MAX_CLOSE_MESSAGE_LEN)?
    .checked_add(std::mem::size_of::<u64>())?;
    let fixed_session_bytes = std::mem::size_of::<Session>()
        .checked_add(std::mem::size_of::<SessionWork>())?
        .checked_add(MAX_CLOSE_MESSAGE_LEN)?
        .checked_add(std::mem::size_of::<TerminalRetentionState>())?
        .checked_add(std::mem::size_of::<WebTransportRetentionStats>())?;

    max_pending_streams
        .checked_mul(pending_value_bytes)?
        .checked_add(max_active_streams.checked_mul(active_value_bytes)?)?
        .checked_add(max_stream_waiters.checked_mul(waiter_value_bytes)?)?
        .checked_add(
            max_send_terminal_waiters.checked_mul(terminal_value_bytes)?,
        )?
        .checked_add(
            max_receive_terminal_states
                .checked_mul(receive_terminal_value_bytes)?,
        )?
        .checked_add(
            max_receive_terminal_waiters.checked_mul(waiter_value_bytes)?,
        )?
        .checked_add(
            max_session_terminal_waiters
                .checked_mul(session_terminal_value_bytes)?,
        )?
        .checked_add(fixed_session_bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnedStream {
    session_id: u64,
    direction: WebTransportStreamDirection,
    local_prefix_len: u64,
    reset_mode: quiche::h3::WebTransportStreamResetMode,
    locally_initiated: bool,
    send_terminal_observation: SendTerminalObservation,
    receive_terminal_observation: ReceiveTerminalObservation,
}

impl OwnedStream {
    fn new(
        session_id: u64, direction: WebTransportStreamDirection,
        local_prefix_len: u64, locally_initiated: bool,
    ) -> Self {
        Self::new_with_reset_mode(
            session_id,
            direction,
            local_prefix_len,
            locally_initiated,
            quiche::h3::WebTransportStreamResetMode::ReliablePrefixReset,
        )
    }

    fn new_with_reset_mode(
        session_id: u64, direction: WebTransportStreamDirection,
        local_prefix_len: u64, locally_initiated: bool,
        reset_mode: quiche::h3::WebTransportStreamResetMode,
    ) -> Self {
        let send_terminal_observation = if direction ==
            WebTransportStreamDirection::Bidi ||
            locally_initiated
        {
            SendTerminalObservation::Active
        } else {
            SendTerminalObservation::NotApplicable
        };
        let receive_terminal_observation = if direction ==
            WebTransportStreamDirection::Bidi ||
            !locally_initiated
        {
            ReceiveTerminalObservation::Active
        } else {
            ReceiveTerminalObservation::NotApplicable
        };
        Self {
            session_id,
            direction,
            local_prefix_len,
            reset_mode,
            locally_initiated,
            send_terminal_observation,
            receive_terminal_observation,
        }
    }

    fn has_receive_direction(self) -> bool {
        self.receive_terminal_observation !=
            ReceiveTerminalObservation::NotApplicable
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendTerminalObservation {
    NotApplicable,
    Active,
    Overloaded,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiveTerminalObservation {
    NotApplicable,
    Active,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendTerminalState {
    Stopped {
        wire_error_code: u64,
        application_error_code: Option<u32>,
    },
    Closed,
}

impl SendTerminalState {
    fn outcome(self, stream_id: u64) -> WebTransportStreamSendTerminalOutcome {
        match self {
            Self::Stopped {
                wire_error_code,
                application_error_code,
            } => WebTransportStreamSendTerminalOutcome::Stopped {
                stream_id,
                wire_error_code,
                application_error_code,
            },
            Self::Closed =>
                WebTransportStreamSendTerminalOutcome::Closed { stream_id },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LatchedSendTerminal {
    session_id: u64,
    state: SendTerminalState,
}

#[derive(Debug)]
struct SendTerminalWaiter {
    session_id: u64,
    response: oneshot::Sender<WebTransportStreamSendTerminalOutcome>,
}

#[derive(Debug)]
struct StreamReadyWaiter {
    session_id: u64,
    retry: Option<WebTransportStreamWriteRetry>,
    response: oneshot::Sender<WebTransportStreamReadyOutcome>,
}

#[derive(Debug)]
struct OpeningStream {
    reservation: quiche::h3::WebTransportStreamReservation,
    prefix_offset: usize,
    reset_after_prefix: Option<u64>,
    response: Option<oneshot::Sender<WebTransportOpenStreamOutcome>>,
}

#[derive(Debug)]
struct PendingOpen {
    session_id: u64,
    direction: WebTransportStreamDirection,
    response: oneshot::Sender<WebTransportOpenStreamOutcome>,
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
enum SessionTerminalFact {
    Terminated(WebTransportSessionCloseReason),
    Rejected { status: u16 },
}

impl SessionTerminalFact {
    fn outcome(&self, session_id: u64) -> WebTransportSessionTerminalOutcome {
        match self {
            Self::Terminated(reason) =>
                WebTransportSessionTerminalOutcome::Terminated {
                    session_id,
                    reason: reason.clone(),
                },
            Self::Rejected { status } =>
                WebTransportSessionTerminalOutcome::SessionRejected {
                    session_id,
                    status: *status,
                },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SessionPhase {
    Pending,
    Active,
    Closing {
        close: CloseCapsule,
        output_queued: bool,
    },
    Terminal(SessionTerminalFact),
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
    reset_mode: quiche::h3::WebTransportStreamResetMode,
    write_lease_accounting: Arc<WriteLeaseAccounting>,
    terminal_retention: Arc<TerminalRetentionState>,
    sessions: BTreeMap<u64, Session>,
    pending_streams: BTreeMap<u64, AssociatedStream>,
    pending_by_session: BTreeMap<u64, BTreeSet<u64>>,
    stream_sessions: BTreeMap<u64, OwnedStream>,
    opening_streams: BTreeMap<u64, OpeningStream>,
    opening_order: VecDeque<u64>,
    opening_by_session: BTreeMap<u64, BTreeSet<u64>>,
    pending_bidi_opens: VecDeque<PendingOpen>,
    pending_uni_opens: VecDeque<PendingOpen>,
    pending_opens_per_session: BTreeMap<u64, usize>,
    bidi_open_credit_ready: bool,
    uni_open_credit_ready: bool,
    pending_open_turn_bidi: bool,
    open_work_pending_turn: bool,
    cancellation_pending: Arc<AtomicBool>,
    stream_open_waiter_work_total: u64,
    stream_open_waiter_saturation_total: u64,
    session_terminal_waiters:
        BTreeMap<u64, Vec<oneshot::Sender<WebTransportSessionTerminalOutcome>>>,
    session_terminal_waiter_count: usize,
    session_terminal_waiter_work_total: u64,
    session_terminal_waiter_saturation_total: u64,
    readable_waiters: BTreeMap<u64, StreamReadyWaiter>,
    readable_waiters_per_session: BTreeMap<u64, usize>,
    writable_waiters: BTreeMap<u64, StreamReadyWaiter>,
    send_terminal_waiters: BTreeMap<u64, SendTerminalWaiter>,
    send_terminal_waiters_per_session: BTreeMap<u64, usize>,
    send_terminal_states: BTreeMap<u64, LatchedSendTerminal>,
    send_terminal_states_per_session: BTreeMap<u64, usize>,
    send_terminal_overloaded_sessions: BTreeMap<u64, usize>,
    send_terminal_waiter_work_total: u64,
    send_terminal_waiter_saturation_total: u64,
    send_terminal_state_saturation_total: u64,
    receive_terminal_observations: usize,
    receive_terminal_observations_per_session: BTreeMap<u64, usize>,
    receive_terminal_states: BTreeMap<u64, Arc<ReceiveTerminalReadShared>>,
    receive_terminal_states_per_session: BTreeMap<u64, usize>,
    receive_terminal_bytes: usize,
    receive_terminal_bytes_per_session: BTreeMap<u64, usize>,
    receive_terminal_observations_high_water: usize,
    receive_terminal_states_high_water: usize,
    receive_terminal_bytes_high_water: usize,
    receive_terminal_waiters_high_water: usize,
    receive_terminal_state_saturation_total: u64,
    receive_terminal_byte_saturation_total: u64,
    receive_terminal_waiter_saturation_total: u64,
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
        let terminal_retention = Arc::new(TerminalRetentionState::new());
        let write_lease_accounting = Arc::new(WriteLeaseAccounting::new(
            limits.command_capacity,
            limits.max_write_lease_retained_bytes_per_lease,
            Arc::downgrade(&terminal_retention),
        ));
        terminal_retention.bind_write_lease_accounting(&write_lease_accounting);
        Self::new_with_write_lease_accounting(
            limits,
            write_lease_accounting,
            Arc::new(AtomicBool::new(false)),
            terminal_retention,
        )
    }

    pub(super) fn new_with_write_lease_accounting(
        limits: RuntimeLimits, write_lease_accounting: Arc<WriteLeaseAccounting>,
        cancellation_pending: Arc<AtomicBool>,
        terminal_retention: Arc<TerminalRetentionState>,
    ) -> Self {
        Self {
            limits: RuntimeLimits {
                max_session_work_per_callback: limits
                    .max_session_work_per_callback
                    .max(1),
                max_send_terminal_waiters: limits
                    .max_send_terminal_waiters
                    .max(1),
                max_send_terminal_waiters_per_session: limits
                    .max_send_terminal_waiters_per_session
                    .max(1),
                max_receive_terminal_states: limits
                    .max_receive_terminal_states
                    .max(1),
                max_receive_terminal_states_per_session: limits
                    .max_receive_terminal_states_per_session
                    .max(1),
                max_receive_terminal_waiters: limits
                    .max_receive_terminal_waiters
                    .max(1),
                max_receive_terminal_waiters_per_session: limits
                    .max_receive_terminal_waiters_per_session
                    .max(1),
                max_session_terminal_waiters: limits
                    .max_session_terminal_waiters
                    .max(1),
                max_session_terminal_waiters_per_session: limits
                    .max_session_terminal_waiters_per_session
                    .max(1),
                ..limits
            },
            reset_mode:
                quiche::h3::WebTransportStreamResetMode::ReliablePrefixReset,
            write_lease_accounting,
            terminal_retention,
            sessions: BTreeMap::new(),
            pending_streams: BTreeMap::new(),
            pending_by_session: BTreeMap::new(),
            stream_sessions: BTreeMap::new(),
            opening_streams: BTreeMap::new(),
            opening_order: VecDeque::new(),
            opening_by_session: BTreeMap::new(),
            pending_bidi_opens: VecDeque::new(),
            pending_uni_opens: VecDeque::new(),
            pending_opens_per_session: BTreeMap::new(),
            bidi_open_credit_ready: false,
            uni_open_credit_ready: false,
            pending_open_turn_bidi: true,
            open_work_pending_turn: true,
            cancellation_pending,
            stream_open_waiter_work_total: 0,
            stream_open_waiter_saturation_total: 0,
            session_terminal_waiters: BTreeMap::new(),
            session_terminal_waiter_count: 0,
            session_terminal_waiter_work_total: 0,
            session_terminal_waiter_saturation_total: 0,
            readable_waiters: BTreeMap::new(),
            readable_waiters_per_session: BTreeMap::new(),
            writable_waiters: BTreeMap::new(),
            send_terminal_waiters: BTreeMap::new(),
            send_terminal_waiters_per_session: BTreeMap::new(),
            send_terminal_states: BTreeMap::new(),
            send_terminal_states_per_session: BTreeMap::new(),
            send_terminal_overloaded_sessions: BTreeMap::new(),
            send_terminal_waiter_work_total: 0,
            send_terminal_waiter_saturation_total: 0,
            send_terminal_state_saturation_total: 0,
            receive_terminal_observations: 0,
            receive_terminal_observations_per_session: BTreeMap::new(),
            receive_terminal_states: BTreeMap::new(),
            receive_terminal_states_per_session: BTreeMap::new(),
            receive_terminal_bytes: 0,
            receive_terminal_bytes_per_session: BTreeMap::new(),
            receive_terminal_observations_high_water: 0,
            receive_terminal_states_high_water: 0,
            receive_terminal_bytes_high_water: 0,
            receive_terminal_waiters_high_water: 0,
            receive_terminal_state_saturation_total: 0,
            receive_terminal_byte_saturation_total: 0,
            receive_terminal_waiter_saturation_total: 0,
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

    pub(crate) fn set_reset_mode(
        &mut self, reset_mode: quiche::h3::WebTransportStreamResetMode,
    ) {
        debug_assert!(self.opening_streams.is_empty());
        debug_assert!(self.stream_sessions.is_empty());
        self.reset_mode = reset_mode;
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
            .all(|session| matches!(session.phase, SessionPhase::Terminal(_)))
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
        let terminal = SessionTerminalFact::Rejected { status };
        session.phase = SessionPhase::Terminal(terminal.clone());
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
        self.finish_session_terminal_waiters(session_id, &terminal);
        self.finish_send_terminal_session(session_id);
        self.finish_receive_terminal_session(session_id);
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
        if matches!(session.phase, SessionPhase::Terminal(_)) {
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
        let terminal = SessionTerminalFact::Terminated(reason.clone());
        session.phase = SessionPhase::Terminal(terminal.clone());
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
        self.finish_session_terminal_waiters(session_id, &terminal);
        self.finish_send_terminal_session(session_id);
        self.finish_receive_terminal_session(session_id);
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
                if self.can_admit_associated_stream(stream) {
                    self.admit_stream(stream);
                    vec![associated_event(stream)]
                } else {
                    shutdown_stream(qconn, stream, WT_BUFFERED_STREAM_REJECTED);
                    Vec::new()
                }
            },
            Some(SessionPhase::Pending) => {
                if self.can_buffer(stream.session_id) {
                    self.buffer_stream(stream);
                } else {
                    shutdown_stream(qconn, stream, WT_BUFFERED_STREAM_REJECTED);
                }
                Vec::new()
            },
            Some(SessionPhase::Closing { .. } | SessionPhase::Terminal(_)) => {
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
                self.limits.max_pending_streams_per_session &&
            self.active_and_provisional_stream_count() <
                self.limits.max_active_streams &&
            self.active_and_provisional_stream_count_for_session(session_id) <
                self.limits.max_active_streams_per_session
    }

    fn can_admit_associated_stream(&mut self, stream: AssociatedStream) -> bool {
        self.can_admit_owned_stream(OwnedStream::new(
            stream.session_id,
            stream.direction,
            0,
            false,
        ))
    }

    fn can_admit_owned_stream(&mut self, stream: OwnedStream) -> bool {
        if self.stream_sessions.len() >= self.limits.max_active_streams ||
            self.active_stream_count_for_session(stream.session_id) >=
                self.limits.max_active_streams_per_session
        {
            return false;
        }
        if !stream.has_receive_direction() {
            return true;
        }
        let available = self.receive_terminal_observations <
            self.limits.max_receive_terminal_states &&
            self.receive_terminal_observations_per_session
                .get(&stream.session_id)
                .copied()
                .unwrap_or(0) <
                self.limits.max_receive_terminal_states_per_session;
        if !available {
            self.receive_terminal_state_saturation_total = self
                .receive_terminal_state_saturation_total
                .saturating_add(1);
        }
        available
    }

    fn active_and_provisional_stream_count(&self) -> usize {
        self.stream_sessions
            .len()
            .saturating_add(self.provisional_stream_count())
    }

    fn active_and_provisional_stream_count_for_session(
        &self, session_id: u64,
    ) -> usize {
        self.active_stream_count_for_session(session_id)
            .saturating_add(self.provisional_stream_count_for_session(session_id))
    }

    fn active_stream_count_for_session(&self, session_id: u64) -> usize {
        self.sessions
            .get(&session_id)
            .map_or(0, |session| session.streams.len())
    }

    fn provisional_stream_count(&self) -> usize {
        self.pending_streams
            .len()
            .saturating_add(self.opening_streams.len())
            .saturating_add(self.pending_open_count())
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
            .saturating_add(
                self.pending_opens_per_session
                    .get(&session_id)
                    .copied()
                    .unwrap_or(0),
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
        let owned = OwnedStream::new_with_reset_mode(
            stream.session_id,
            stream.direction,
            0,
            false,
            self.reset_mode,
        );
        self.insert_owned_stream(stream.stream_id, owned);
        if let Some(session) = self.sessions.get_mut(&stream.session_id) {
            session.streams.insert(stream.stream_id);
        }
    }

    fn insert_owned_stream(&mut self, stream_id: u64, stream: OwnedStream) {
        if stream.has_receive_direction() {
            self.receive_terminal_observations =
                self.receive_terminal_observations.saturating_add(1);
            let count = self
                .receive_terminal_observations_per_session
                .entry(stream.session_id)
                .or_default();
            *count = count.saturating_add(1);
            self.receive_terminal_observations_high_water = self
                .receive_terminal_observations_high_water
                .max(self.receive_terminal_observations);
        }
        self.stream_sessions.insert(stream_id, stream);
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
        if matches!(session.phase, SessionPhase::Terminal(_)) {
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
        if matches!(session.phase, SessionPhase::Terminal(_)) {
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

    pub(crate) fn is_terminal(&self, session_id: u64) -> bool {
        self.sessions.get(&session_id).is_some_and(|session| {
            matches!(session.phase, SessionPhase::Terminal(_))
        })
    }

    fn wait_session_terminal(
        &mut self, qconn: &QuicheConnection, session_id: u64,
        response: oneshot::Sender<WebTransportSessionTerminalOutcome>,
    ) {
        if response.is_closed() {
            return;
        }
        let Some(session) = self.sessions.get(&session_id) else {
            let outcome = if qconn.stream_closed(session_id) {
                WebTransportSessionTerminalOutcome::StaleSession { session_id }
            } else {
                WebTransportSessionTerminalOutcome::UnknownSession { session_id }
            };
            let _ = response.send(outcome);
            return;
        };
        if let SessionPhase::Terminal(terminal) = &session.phase {
            let _ = response.send(terminal.outcome(session_id));
            self.session_terminal_waiter_work_total =
                self.session_terminal_waiter_work_total.saturating_add(1);
            return;
        }

        let session_waiters = self
            .session_terminal_waiters
            .get(&session_id)
            .map_or(0, Vec::len);
        if self.session_terminal_waiter_count >=
            self.limits.max_session_terminal_waiters ||
            session_waiters >=
                self.limits.max_session_terminal_waiters_per_session
        {
            self.session_terminal_waiter_saturation_total = self
                .session_terminal_waiter_saturation_total
                .saturating_add(1);
            let _ = response.send(
                WebTransportSessionTerminalOutcome::ResourceLimit { session_id },
            );
            return;
        }

        self.session_terminal_waiters
            .entry(session_id)
            .or_default()
            .push(response);
        self.session_terminal_waiter_count += 1;
    }

    fn finish_session_terminal_waiters(
        &mut self, session_id: u64, terminal: &SessionTerminalFact,
    ) {
        let Some(waiters) = self.session_terminal_waiters.remove(&session_id)
        else {
            return;
        };
        self.session_terminal_waiter_count = self
            .session_terminal_waiter_count
            .saturating_sub(waiters.len());
        self.session_terminal_waiter_work_total = self
            .session_terminal_waiter_work_total
            .saturating_add(waiters.len() as u64);
        for response in waiters {
            let _ = response.send(terminal.outcome(session_id));
        }
    }

    fn prune_cancelled_session_terminal_waiters(&mut self) {
        let mut removed = 0usize;
        self.session_terminal_waiters.retain(|_, waiters| {
            let before = waiters.len();
            waiters.retain(|response| !response.is_closed());
            removed = removed.saturating_add(before - waiters.len());
            !waiters.is_empty()
        });
        self.session_terminal_waiter_count =
            self.session_terminal_waiter_count.saturating_sub(removed);
        self.session_terminal_waiter_work_total = self
            .session_terminal_waiter_work_total
            .saturating_add(removed as u64);
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
            Some(SessionPhase::Terminal(_)) =>
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
        if !write &&
            stream.receive_terminal_observation ==
                ReceiveTerminalObservation::Retired
        {
            return Err(WebTransportSelectionError::StaleStream);
        }
        Ok(stream)
    }

    pub(crate) fn handle_command(
        &mut self, conn: &mut quiche::h3::Connection,
        qconn: &mut QuicheConnection, command: WebTransportCommand,
        queued_command_items: usize,
    ) {
        if self.cancellation_pending.swap(false, Ordering::AcqRel) {
            self.prune_cancelled_pending_opens();
            self.prune_cancelled_session_terminal_waiters();
            self.prune_cancelled_stream_waiters();
            self.prune_cancelled_send_terminal_waiters();
        }
        match command {
            WebTransportCommand::WaitSessionTerminal {
                session_id,
                response,
            } => self.wait_session_terminal(qconn, session_id, response),
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
                retry,
                response,
            } => self.wait_stream(
                qconn, session_id, stream_id, write, retry, response,
            ),
            WebTransportCommand::WaitSendTerminal {
                session_id,
                stream_id,
                response,
            } => self.wait_stream_send_terminal(
                qconn, session_id, stream_id, response,
            ),
            WebTransportCommand::RetireSendTerminal {
                session_id,
                stream_id,
                response,
            } => self.retire_stream_send_terminal(
                qconn, session_id, stream_id, response,
            ),
            WebTransportCommand::RetireReceiveTerminal {
                session_id,
                stream_id,
                response,
            } => self.retire_stream_receive_terminal(
                qconn, session_id, stream_id, response,
            ),
            WebTransportCommand::PruneCancelledWaiters => {
                self.prune_cancelled_pending_opens();
                self.prune_cancelled_session_terminal_waiters();
                self.prune_cancelled_stream_waiters();
                self.prune_cancelled_send_terminal_waiters();
            },
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
                let _ =
                    response
                        .send(Ok(self
                            .retention_stats(Some(qconn), queued_command_items)));
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
        self.prune_cancelled_pending_opens();
        if self.provisional_stream_count() >= self.limits.max_pending_streams ||
            self.provisional_stream_count_for_session(session_id) >=
                self.limits.max_pending_streams_per_session ||
            self.active_and_provisional_stream_count() >=
                self.limits.max_active_streams ||
            self.active_and_provisional_stream_count_for_session(session_id) >=
                self.limits.max_active_streams_per_session
        {
            self.stream_open_waiter_saturation_total =
                self.stream_open_waiter_saturation_total.saturating_add(1);
            let _ = response.send(WebTransportOpenStreamOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            ));
            return;
        }

        let request = PendingOpen {
            session_id,
            direction,
            response,
        };
        if let Some(request) = self.start_open_request(conn, qconn, request) {
            self.set_open_credit_ready(direction, false);
            self.queue_pending_open(request, false);
        }
    }

    fn start_open_request(
        &mut self, conn: &mut quiche::h3::Connection,
        qconn: &mut QuicheConnection, request: PendingOpen,
    ) -> Option<PendingOpen> {
        let core_direction = match request.direction {
            WebTransportStreamDirection::Bidi =>
                quiche::h3::WebTransportStreamDirection::Bidirectional,
            WebTransportStreamDirection::Uni =>
                quiche::h3::WebTransportStreamDirection::Unidirectional,
        };
        let reservation = match conn.reserve_webtransport_stream_with_reset_mode(
            qconn,
            request.session_id,
            core_direction,
            self.reset_mode,
        ) {
            Ok(reservation) => reservation,
            Err(quiche::h3::Error::SettingsError) => {
                let _ = request.response.send(
                    WebTransportOpenStreamOutcome::Rejected(
                        WebTransportSelectionError::Unsupported,
                    ),
                );
                return None;
            },
            Err(quiche::h3::Error::TransportError(
                quiche::Error::StreamLimit,
            )) => return Some(request),
            Err(_) => {
                let _ = request.response.send(
                    WebTransportOpenStreamOutcome::Rejected(
                        WebTransportSelectionError::ConnectionClosed,
                    ),
                );
                return None;
            },
        };
        let stream_id = reservation.stream_id();
        self.opening_streams.insert(stream_id, OpeningStream {
            reservation,
            prefix_offset: 0,
            reset_after_prefix: None,
            response: Some(request.response),
        });
        self.opening_order.push_back(stream_id);
        self.opening_by_session
            .entry(request.session_id)
            .or_default()
            .insert(stream_id);
        None
    }

    pub(crate) fn stream_credit_available(
        &mut self, direction: quiche::StreamCreditDirection,
    ) {
        match direction {
            quiche::StreamCreditDirection::Bidirectional => {
                if !self.pending_bidi_opens.is_empty() {
                    self.bidi_open_credit_ready = true;
                }
            },
            quiche::StreamCreditDirection::Unidirectional => {
                if !self.pending_uni_opens.is_empty() {
                    self.uni_open_credit_ready = true;
                }
            },
        }
    }

    pub(crate) fn process_open_work(
        &mut self, conn: &mut quiche::h3::Connection,
        qconn: &mut QuicheConnection, max_work: usize,
    ) -> usize {
        let mut work = 0;
        while work < max_work {
            let pending_first = self.open_work_pending_turn;
            let progressed = if pending_first {
                self.process_pending_open(conn, qconn) ||
                    self.process_opening_streams(conn, qconn, 1) != 0
            } else {
                self.process_opening_streams(conn, qconn, 1) != 0 ||
                    self.process_pending_open(conn, qconn)
            };
            if !progressed {
                break;
            }
            work += 1;
            self.open_work_pending_turn = !pending_first;
        }
        work
    }

    fn process_pending_open(
        &mut self, conn: &mut quiche::h3::Connection,
        qconn: &mut QuicheConnection,
    ) -> bool {
        let bidi_ready =
            self.bidi_open_credit_ready && !self.pending_bidi_opens.is_empty();
        let uni_ready =
            self.uni_open_credit_ready && !self.pending_uni_opens.is_empty();
        let direction = match (bidi_ready, uni_ready) {
            (true, true) if self.pending_open_turn_bidi =>
                WebTransportStreamDirection::Bidi,
            (true, true) => WebTransportStreamDirection::Uni,
            (true, false) => WebTransportStreamDirection::Bidi,
            (false, true) => WebTransportStreamDirection::Uni,
            (false, false) => return false,
        };
        self.pending_open_turn_bidi =
            direction == WebTransportStreamDirection::Uni;
        let Some(request) = self.pop_pending_open(direction) else {
            self.set_open_credit_ready(direction, false);
            return false;
        };
        self.stream_open_waiter_work_total =
            self.stream_open_waiter_work_total.saturating_add(1);
        if request.response.is_closed() {
            self.refresh_open_credit(qconn, direction);
            return true;
        }
        if !self.is_active(request.session_id) {
            let _ =
                request
                    .response
                    .send(WebTransportOpenStreamOutcome::Rejected(
                        WebTransportSelectionError::TerminalSession,
                    ));
            self.refresh_open_credit(qconn, direction);
            return true;
        }

        if let Some(request) = self.start_open_request(conn, qconn, request) {
            self.queue_pending_open(request, true);
            self.set_open_credit_ready(direction, false);
        } else {
            self.refresh_open_credit(qconn, direction);
        }
        true
    }

    fn pending_open_count(&self) -> usize {
        self.pending_bidi_opens
            .len()
            .saturating_add(self.pending_uni_opens.len())
    }

    fn queue_pending_open(&mut self, request: PendingOpen, front: bool) {
        let session_id = request.session_id;
        let queue = match request.direction {
            WebTransportStreamDirection::Bidi => &mut self.pending_bidi_opens,
            WebTransportStreamDirection::Uni => &mut self.pending_uni_opens,
        };
        if front {
            queue.push_front(request);
        } else {
            queue.push_back(request);
        }
        let count = self
            .pending_opens_per_session
            .entry(session_id)
            .or_default();
        *count = count.saturating_add(1);
    }

    fn pop_pending_open(
        &mut self, direction: WebTransportStreamDirection,
    ) -> Option<PendingOpen> {
        let request = match direction {
            WebTransportStreamDirection::Bidi =>
                self.pending_bidi_opens.pop_front(),
            WebTransportStreamDirection::Uni =>
                self.pending_uni_opens.pop_front(),
        }?;
        decrement_session_count(
            &mut self.pending_opens_per_session,
            request.session_id,
        );
        Some(request)
    }

    fn set_open_credit_ready(
        &mut self, direction: WebTransportStreamDirection, ready: bool,
    ) {
        match direction {
            WebTransportStreamDirection::Bidi =>
                self.bidi_open_credit_ready = ready,
            WebTransportStreamDirection::Uni =>
                self.uni_open_credit_ready = ready,
        }
    }

    fn refresh_open_credit(
        &mut self, qconn: &QuicheConnection,
        direction: WebTransportStreamDirection,
    ) {
        let has_waiter = match direction {
            WebTransportStreamDirection::Bidi =>
                !self.pending_bidi_opens.is_empty(),
            WebTransportStreamDirection::Uni =>
                !self.pending_uni_opens.is_empty(),
        };
        let has_credit = match direction {
            WebTransportStreamDirection::Bidi =>
                qconn.peer_streams_left_bidi() != 0,
            WebTransportStreamDirection::Uni =>
                qconn.peer_streams_left_uni() != 0,
        };
        self.set_open_credit_ready(direction, has_waiter && has_credit);
    }

    fn prune_cancelled_pending_opens(&mut self) {
        for direction in [
            WebTransportStreamDirection::Bidi,
            WebTransportStreamDirection::Uni,
        ] {
            let count = match direction {
                WebTransportStreamDirection::Bidi =>
                    self.pending_bidi_opens.len(),
                WebTransportStreamDirection::Uni => self.pending_uni_opens.len(),
            };
            for _ in 0..count {
                let Some(request) = self.pop_pending_open(direction) else {
                    break;
                };
                if !request.response.is_closed() {
                    self.queue_pending_open(request, false);
                }
            }
        }
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

            if let Some(error_code) = opening.reset_after_prefix.filter(|_| {
                opening.reservation.reset_mode() ==
                    quiche::h3::WebTransportStreamResetMode::StandardReset
            }) {
                shutdown_opening_stream(qconn, &opening.reservation, error_code);
                self.finish_opening(session_id, stream_id);
                continue;
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

            let owned = OwnedStream::new_with_reset_mode(
                session_id,
                match opening.reservation.direction() {
                    quiche::h3::WebTransportStreamDirection::Bidirectional =>
                        WebTransportStreamDirection::Bidi,
                    quiche::h3::WebTransportStreamDirection::Unidirectional =>
                        WebTransportStreamDirection::Uni,
                },
                opening.reservation.prefix_len() as u64,
                true,
                opening.reservation.reset_mode(),
            );
            if !self.can_admit_owned_stream(owned) {
                if let Some(response) = opening.response.take() {
                    let _ =
                        response.send(WebTransportOpenStreamOutcome::Rejected(
                            WebTransportSelectionError::ResourceLimit,
                        ));
                }
                shutdown_opening_stream(
                    qconn,
                    &opening.reservation,
                    WT_BUFFERED_STREAM_REJECTED,
                );
                self.finish_opening(session_id, stream_id);
                continue;
            }

            self.insert_owned_stream(stream_id, owned);
            if let Some(session) = self.sessions.get_mut(&session_id) {
                session.streams.insert(stream_id);
            }
            let delivered = opening.response.take().is_some_and(|response| {
                response
                    .send(WebTransportOpenStreamOutcome::Opened { stream_id })
                    .is_ok()
            });
            if !delivered {
                self.remove_owned_stream(stream_id);
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
        write: bool, retry: Option<WebTransportStreamWriteRetry>,
        response: oneshot::Sender<WebTransportStreamReadyOutcome>,
    ) {
        if response.is_closed() {
            return;
        }
        if write != retry.is_some() {
            let _ = response.send(WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::InternalFailure,
            ));
            return;
        }
        if retry
            .as_ref()
            .is_some_and(|retry| !retry.belongs_to(&self.write_lease_accounting))
        {
            let _ = response.send(WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ForeignController,
            ));
            return;
        }
        if let Some(outcome) = self.stream_ready_outcome(
            qconn,
            session_id,
            stream_id,
            write,
            retry.as_ref(),
        ) {
            let _ = response.send(outcome);
            return;
        }

        let cancelled_duplicate = if write {
            self.writable_waiters
                .get(&stream_id)
                .is_some_and(|waiter| waiter.response.is_closed())
        } else {
            self.readable_waiters
                .get(&stream_id)
                .is_some_and(|waiter| waiter.response.is_closed())
        };
        if cancelled_duplicate {
            self.remove_stream_waiter(stream_id, write);
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
        let receive_waiters = self.readable_waiters.len();
        let session_receive_waiters = self
            .readable_waiters_per_session
            .get(&session_id)
            .copied()
            .unwrap_or(0);
        let receive_full = !write &&
            (receive_waiters >= self.limits.max_receive_terminal_waiters ||
                session_receive_waiters >=
                    self.limits
                        .max_receive_terminal_waiters_per_session);
        if waiter_count >= self.limits.max_stream_waiters ||
            receive_full ||
            duplicate
        {
            if !write {
                self.receive_terminal_waiter_saturation_total = self
                    .receive_terminal_waiter_saturation_total
                    .saturating_add(1);
            }
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
        waiters.insert(stream_id, StreamReadyWaiter {
            session_id,
            retry,
            response,
        });
        if !write {
            let count = self
                .readable_waiters_per_session
                .entry(session_id)
                .or_default();
            *count = count.saturating_add(1);
            self.receive_terminal_waiters_high_water = self
                .receive_terminal_waiters_high_water
                .max(self.readable_waiters.len());
        }
    }

    fn stream_ready_outcome(
        &self, qconn: &QuicheConnection, session_id: u64, stream_id: u64,
        write: bool, retry: Option<&WebTransportStreamWriteRetry>,
    ) -> Option<WebTransportStreamReadyOutcome> {
        if let Err(error) =
            self.select_stream(session_id, stream_id, write, qconn)
        {
            return Some(WebTransportStreamReadyOutcome::Rejected(error));
        }

        if !write {
            if self.receive_terminal_states.contains_key(&stream_id) {
                return Some(WebTransportStreamReadyOutcome::Ready);
            }
            if qconn.stream_readable(stream_id) {
                return Some(WebTransportStreamReadyOutcome::Ready);
            }
            return (qconn.stream_finished(stream_id) ||
                qconn.stream_closed(stream_id))
            .then_some(WebTransportStreamReadyOutcome::Ready);
        }

        let status = match qconn.stream_send_status(stream_id) {
            Ok(quiche::StreamSendStatus::Stopped(error_code)) =>
                return Some(WebTransportStreamReadyOutcome::ResetRequired {
                    wire_error_code: error_code,
                    application_error_code: webtransport_error_from_http3(
                        error_code,
                    ),
                }),
            Ok(quiche::StreamSendStatus::Closed) | Err(_) =>
                return Some(WebTransportStreamReadyOutcome::Closed),
            Ok(status) => status,
        };

        let Some(retry) = retry else {
            return Some(WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::InternalFailure,
            ));
        };
        debug_assert_eq!(retry.session_id, session_id);
        debug_assert_eq!(retry.stream_id, stream_id);

        if retry.disposition ==
            quiche::StreamSendRetryDisposition::StateChangeRequired
        {
            return Some(
                WebTransportStreamReadyOutcome::WriteStateChangeRequired {
                    blocked_reasons: retry.reasons,
                    state_change_reasons: stream_send_state_change_reasons(
                        retry.reasons,
                    ),
                },
            );
        }

        match status {
            quiche::StreamSendStatus::Writable(_) =>
                Some(WebTransportStreamReadyOutcome::WriteTransportWake {
                    reasons: retry.reasons,
                }),
            quiche::StreamSendStatus::Blocked(reasons)
                if reasons.retry_disposition() ==
                    quiche::StreamSendRetryDisposition::StateChangeRequired =>
                Some(WebTransportStreamReadyOutcome::WriteStateChangeRequired {
                    blocked_reasons: retry.reasons,
                    state_change_reasons: stream_send_state_change_reasons(
                        reasons,
                    ),
                }),
            quiche::StreamSendStatus::Blocked(_) => None,
            quiche::StreamSendStatus::Stopped(_) |
            quiche::StreamSendStatus::Closed => unreachable!(
                "selected write terminal status handled before readiness"
            ),
        }
    }

    fn wait_stream_send_terminal(
        &mut self, qconn: &QuicheConnection, session_id: u64, stream_id: u64,
        response: oneshot::Sender<WebTransportStreamSendTerminalOutcome>,
    ) {
        self.send_terminal_waiter_work_total =
            self.send_terminal_waiter_work_total.saturating_add(1);
        if response.is_closed() {
            return;
        }
        if let Some(error) = self.selection_error(session_id, qconn) {
            let _ = response
                .send(WebTransportStreamSendTerminalOutcome::Rejected(error));
            return;
        }
        if let Some(terminal) = self.send_terminal_states.get(&stream_id) {
            let outcome = if terminal.session_id == session_id {
                terminal.state.outcome(stream_id)
            } else {
                WebTransportStreamSendTerminalOutcome::Rejected(
                    WebTransportSelectionError::ForeignStream {
                        owner_session_id: terminal.session_id,
                    },
                )
            };
            let _ = response.send(outcome);
            return;
        }
        let stream = match self.select_stream(session_id, stream_id, true, qconn)
        {
            Ok(stream) => stream,
            Err(error) => {
                let _ = response
                    .send(WebTransportStreamSendTerminalOutcome::Rejected(error));
                return;
            },
        };
        match stream.send_terminal_observation {
            SendTerminalObservation::NotApplicable => {
                let _ = response.send(
                    WebTransportStreamSendTerminalOutcome::Rejected(
                        WebTransportSelectionError::WrongDirection,
                    ),
                );
                return;
            },
            SendTerminalObservation::Retired => {
                let _ = response.send(
                    WebTransportStreamSendTerminalOutcome::Retired {
                        session_id,
                        stream_id,
                    },
                );
                return;
            },
            SendTerminalObservation::Overloaded => {
                let _ = response.send(
                    WebTransportStreamSendTerminalOutcome::Rejected(
                        WebTransportSelectionError::ResourceLimit,
                    ),
                );
                return;
            },
            SendTerminalObservation::Active => {},
        }
        if self
            .send_terminal_overloaded_sessions
            .contains_key(&session_id)
        {
            let _ =
                response.send(WebTransportStreamSendTerminalOutcome::Rejected(
                    WebTransportSelectionError::ResourceLimit,
                ));
            return;
        }

        let terminal = match qconn.stream_send_status(stream_id) {
            Ok(quiche::StreamSendStatus::Stopped(wire_error_code)) =>
                Some(SendTerminalState::Stopped {
                    wire_error_code,
                    application_error_code: webtransport_error_from_http3(
                        wire_error_code,
                    ),
                }),
            Ok(quiche::StreamSendStatus::Closed) | Err(_) =>
                Some(SendTerminalState::Closed),
            Ok(
                quiche::StreamSendStatus::Writable(_) |
                quiche::StreamSendStatus::Blocked(_),
            ) => None,
        };
        if let Some(terminal) = terminal {
            let terminal =
                self.latch_send_terminal(session_id, stream_id, terminal);
            let _ = response.send(terminal.outcome(stream_id));
            return;
        }

        if self
            .send_terminal_waiters
            .get(&stream_id)
            .is_some_and(|waiter| waiter.response.is_closed())
        {
            self.remove_send_terminal_waiter(stream_id);
        }
        let mut session_waiters = self
            .send_terminal_waiters_per_session
            .get(&session_id)
            .copied()
            .unwrap_or(0);
        if self.send_terminal_waiters.len() >=
            self.limits.max_send_terminal_waiters ||
            session_waiters >=
                self.limits.max_send_terminal_waiters_per_session
        {
            self.prune_cancelled_send_terminal_waiters();
            session_waiters = self
                .send_terminal_waiters_per_session
                .get(&session_id)
                .copied()
                .unwrap_or(0);
        }
        if self.send_terminal_waiters.contains_key(&stream_id) ||
            self.send_terminal_waiters.len() >=
                self.limits.max_send_terminal_waiters ||
            session_waiters >=
                self.limits.max_send_terminal_waiters_per_session
        {
            self.send_terminal_waiter_saturation_total =
                self.send_terminal_waiter_saturation_total.saturating_add(1);
            let _ =
                response.send(WebTransportStreamSendTerminalOutcome::Rejected(
                    WebTransportSelectionError::ResourceLimit,
                ));
            return;
        }

        self.send_terminal_waiters
            .insert(stream_id, SendTerminalWaiter {
                session_id,
                response,
            });
        let count = self
            .send_terminal_waiters_per_session
            .entry(session_id)
            .or_default();
        *count = count.saturating_add(1);
    }

    fn observe_send_terminal(
        &mut self, qconn: &QuicheConnection, stream_id: u64,
    ) {
        let Some(stream) = self.stream_sessions.get(&stream_id).copied() else {
            return;
        };
        if stream.send_terminal_observation != SendTerminalObservation::Active {
            return;
        }
        let state = match qconn.stream_send_status(stream_id) {
            Ok(quiche::StreamSendStatus::Stopped(wire_error_code)) =>
                SendTerminalState::Stopped {
                    wire_error_code,
                    application_error_code: webtransport_error_from_http3(
                        wire_error_code,
                    ),
                },
            Ok(quiche::StreamSendStatus::Closed) | Err(_) =>
                SendTerminalState::Closed,
            Ok(
                quiche::StreamSendStatus::Writable(_) |
                quiche::StreamSendStatus::Blocked(_),
            ) => return,
        };
        self.send_terminal_waiter_work_total =
            self.send_terminal_waiter_work_total.saturating_add(1);
        self.latch_send_terminal(stream.session_id, stream_id, state);
    }

    fn latch_send_terminal(
        &mut self, session_id: u64, stream_id: u64, state: SendTerminalState,
    ) -> SendTerminalState {
        if let Some(terminal) = self.send_terminal_states.get(&stream_id) {
            return terminal.state;
        }

        let session_states = self
            .send_terminal_states_per_session
            .get(&session_id)
            .copied()
            .unwrap_or(0);
        if self.send_terminal_states.len() >=
            self.limits.max_send_terminal_waiters ||
            session_states >= self.limits.max_send_terminal_waiters_per_session
        {
            self.send_terminal_state_saturation_total =
                self.send_terminal_state_saturation_total.saturating_add(1);
            let mark_overloaded = self
                .stream_sessions
                .get_mut(&stream_id)
                .is_some_and(|stream| {
                    if stream.send_terminal_observation !=
                        SendTerminalObservation::Active
                    {
                        return false;
                    }
                    stream.send_terminal_observation =
                        SendTerminalObservation::Overloaded;
                    true
                });
            if mark_overloaded {
                let count = self
                    .send_terminal_overloaded_sessions
                    .entry(session_id)
                    .or_default();
                *count = count.saturating_add(1);
            }
        } else {
            self.send_terminal_states
                .insert(stream_id, LatchedSendTerminal { session_id, state });
            let count = self
                .send_terminal_states_per_session
                .entry(session_id)
                .or_default();
            *count = count.saturating_add(1);
        }

        if let Some(waiter) = self.remove_send_terminal_waiter(stream_id) {
            let _ = waiter.response.send(state.outcome(stream_id));
        }
        state
    }

    fn retire_stream_send_terminal(
        &mut self, qconn: &QuicheConnection, session_id: u64, stream_id: u64,
        response: oneshot::Sender<WebTransportStreamSendTerminalOutcome>,
    ) {
        if let Some(error) = self.selection_error(session_id, qconn) {
            let _ = response
                .send(WebTransportStreamSendTerminalOutcome::Rejected(error));
            return;
        }

        let latched_owner = self
            .send_terminal_states
            .get(&stream_id)
            .map(|terminal| terminal.session_id);
        let selected = self.stream_sessions.get(&stream_id).copied();
        let owner = selected.map(|stream| stream.session_id).or(latched_owner);
        let Some(owner_session_id) = owner else {
            let error = if qconn.stream_closed(stream_id) {
                WebTransportSelectionError::StaleStream
            } else {
                WebTransportSelectionError::UnknownStream
            };
            let _ = response
                .send(WebTransportStreamSendTerminalOutcome::Rejected(error));
            return;
        };
        if owner_session_id != session_id {
            let _ =
                response.send(WebTransportStreamSendTerminalOutcome::Rejected(
                    WebTransportSelectionError::ForeignStream {
                        owner_session_id,
                    },
                ));
            return;
        }
        if let Some(stream) = selected {
            let direction_allowed = stream.direction ==
                WebTransportStreamDirection::Bidi ||
                stream.locally_initiated;
            if !direction_allowed {
                let _ = response.send(
                    WebTransportStreamSendTerminalOutcome::Rejected(
                        WebTransportSelectionError::WrongDirection,
                    ),
                );
                return;
            }
            self.retire_send_terminal_observation(stream_id, stream);
        }

        self.remove_send_terminal_state(stream_id);
        let outcome = WebTransportStreamSendTerminalOutcome::Retired {
            session_id,
            stream_id,
        };
        if let Some(waiter) = self.remove_send_terminal_waiter(stream_id) {
            let _ = waiter.response.send(outcome);
        }
        let _ = response.send(outcome);
    }

    fn retire_send_terminal_observation(
        &mut self, stream_id: u64, stream: OwnedStream,
    ) {
        if stream.send_terminal_observation == SendTerminalObservation::Retired {
            return;
        }
        if stream.send_terminal_observation == SendTerminalObservation::Overloaded
        {
            decrement_session_count(
                &mut self.send_terminal_overloaded_sessions,
                stream.session_id,
            );
        }
        if let Some(stream) = self.stream_sessions.get_mut(&stream_id) {
            stream.send_terminal_observation = SendTerminalObservation::Retired;
        }
    }

    fn remove_send_terminal_state(
        &mut self, stream_id: u64,
    ) -> Option<LatchedSendTerminal> {
        let terminal = self.send_terminal_states.remove(&stream_id)?;
        decrement_session_count(
            &mut self.send_terminal_states_per_session,
            terminal.session_id,
        );
        Some(terminal)
    }

    fn remove_send_terminal_waiter(
        &mut self, stream_id: u64,
    ) -> Option<SendTerminalWaiter> {
        let waiter = self.send_terminal_waiters.remove(&stream_id)?;
        decrement_session_count(
            &mut self.send_terminal_waiters_per_session,
            waiter.session_id,
        );
        Some(waiter)
    }

    fn prune_cancelled_send_terminal_waiters(&mut self) {
        let cancelled: Vec<_> = self
            .send_terminal_waiters
            .iter()
            .filter_map(|(&stream_id, waiter)| {
                waiter.response.is_closed().then_some(stream_id)
            })
            .collect();
        for stream_id in cancelled {
            self.remove_send_terminal_waiter(stream_id);
        }
    }

    fn finish_send_terminal_session(&mut self, session_id: u64) {
        let waiter_ids: Vec<_> = self
            .send_terminal_waiters
            .iter()
            .filter_map(|(&stream_id, waiter)| {
                (waiter.session_id == session_id).then_some(stream_id)
            })
            .collect();
        for stream_id in waiter_ids {
            let Some(waiter) = self.remove_send_terminal_waiter(stream_id) else {
                continue;
            };
            let outcome = self.send_terminal_states.get(&stream_id).map_or(
                WebTransportStreamSendTerminalOutcome::SessionTerminated {
                    session_id,
                    stream_id,
                },
                |terminal| terminal.state.outcome(stream_id),
            );
            let _ = waiter.response.send(outcome);
            self.send_terminal_waiter_work_total =
                self.send_terminal_waiter_work_total.saturating_add(1);
        }

        let terminal_ids: Vec<_> = self
            .send_terminal_states
            .iter()
            .filter_map(|(&stream_id, terminal)| {
                (terminal.session_id == session_id).then_some(stream_id)
            })
            .collect();
        for stream_id in terminal_ids {
            self.remove_send_terminal_state(stream_id);
        }
        self.send_terminal_overloaded_sessions.remove(&session_id);
    }

    fn finish_receive_terminal_session(&mut self, session_id: u64) {
        let terminal_ids: Vec<_> = self
            .receive_terminal_states
            .iter()
            .filter_map(|(&stream_id, terminal)| {
                (terminal.session_id == session_id).then_some(stream_id)
            })
            .collect();
        for stream_id in terminal_ids {
            self.remove_receive_terminal_state(stream_id);
        }
    }

    fn wake_stream_waiter(
        &mut self, qconn: &QuicheConnection, stream_id: u64, write: bool,
    ) {
        let waiter = if write {
            self.writable_waiters.get(&stream_id)
        } else {
            self.readable_waiters.get(&stream_id)
        };
        let Some(waiter) = waiter else {
            return;
        };
        let Some(outcome) = self.stream_ready_outcome(
            qconn,
            waiter.session_id,
            stream_id,
            write,
            waiter.retry.as_ref(),
        ) else {
            return;
        };
        if let Some(waiter) = self.remove_stream_waiter(stream_id, write) {
            let _ = waiter.response.send(outcome);
        }
    }

    fn remove_stream_waiter(
        &mut self, stream_id: u64, write: bool,
    ) -> Option<StreamReadyWaiter> {
        let waiter = if write {
            self.writable_waiters.remove(&stream_id)?
        } else {
            self.readable_waiters.remove(&stream_id)?
        };
        if !write {
            decrement_session_count(
                &mut self.readable_waiters_per_session,
                waiter.session_id,
            );
        }
        Some(waiter)
    }

    fn prune_cancelled_stream_waiters(&mut self) {
        let readable: Vec<_> = self
            .readable_waiters
            .iter()
            .filter_map(|(&stream_id, waiter)| {
                waiter.response.is_closed().then_some(stream_id)
            })
            .collect();
        for stream_id in readable {
            self.remove_stream_waiter(stream_id, false);
        }
        let writable: Vec<_> = self
            .writable_waiters
            .iter()
            .filter_map(|(&stream_id, waiter)| {
                waiter.response.is_closed().then_some(stream_id)
            })
            .collect();
        for stream_id in writable {
            self.remove_stream_waiter(stream_id, true);
        }
    }

    fn reject_stream_waiters(
        &mut self, stream_id: u64, error: WebTransportSelectionError,
    ) {
        let outcome = WebTransportStreamReadyOutcome::Rejected(error);
        if let Some(waiter) = self.remove_stream_waiter(stream_id, false) {
            let _ = waiter.response.send(outcome);
        }
        if let Some(waiter) = self.remove_stream_waiter(stream_id, true) {
            let _ = waiter.response.send(outcome);
        }
    }

    fn close_stream_waiters(&mut self, stream_id: u64) {
        if let Some(waiter) = self.remove_stream_waiter(stream_id, false) {
            let _ = waiter.response.send(WebTransportStreamReadyOutcome::Closed);
        }
        if let Some(waiter) = self.remove_stream_waiter(stream_id, true) {
            let _ = waiter.response.send(WebTransportStreamReadyOutcome::Closed);
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
        self.reject_pending_open_requests(session_id, selection_error);
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

    fn reject_pending_open_requests(
        &mut self, session_id: u64, error: WebTransportSelectionError,
    ) {
        for direction in [
            WebTransportStreamDirection::Bidi,
            WebTransportStreamDirection::Uni,
        ] {
            let count = match direction {
                WebTransportStreamDirection::Bidi =>
                    self.pending_bidi_opens.len(),
                WebTransportStreamDirection::Uni => self.pending_uni_opens.len(),
            };
            for _ in 0..count {
                let Some(request) = self.pop_pending_open(direction) else {
                    break;
                };
                if request.session_id == session_id {
                    let _ = request
                        .response
                        .send(WebTransportOpenStreamOutcome::Rejected(error));
                } else {
                    self.queue_pending_open(request, false);
                }
            }
            let empty = match direction {
                WebTransportStreamDirection::Bidi =>
                    self.pending_bidi_opens.is_empty(),
                WebTransportStreamDirection::Uni =>
                    self.pending_uni_opens.is_empty(),
            };
            if empty {
                self.set_open_credit_ready(direction, false);
            }
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
        &mut self, qconn: &mut QuicheConnection, session_id: u64, stream_id: u64,
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

        if let Some(shared) = self.receive_terminal_states.get(&stream_id) {
            let outcome =
                WebTransportStreamReceiveTerminalRead::try_acquire(shared)
                    .map_or_else(
                        || {
                            WebTransportStreamReadOutcome::Rejected(
                                WebTransportSelectionError::ResourceLimit,
                            )
                        },
                        WebTransportStreamReadOutcome::Terminal,
                    );
            let _ = response.send(outcome);
            return;
        }

        let allocation_bytes =
            qconn.stream_readable_len(stream_id).min(max_bytes);
        let session_bytes = self
            .receive_terminal_bytes_per_session
            .get(&session_id)
            .copied()
            .unwrap_or(0);
        let bytes_fit = self
            .receive_terminal_bytes
            .checked_add(allocation_bytes)
            .is_some_and(|bytes| bytes <= self.limits.max_receive_terminal_bytes) &&
            session_bytes
                .checked_add(allocation_bytes)
                .is_some_and(|bytes| {
                    bytes <= self.limits.max_receive_terminal_bytes_per_session
                });
        if !bytes_fit {
            self.receive_terminal_byte_saturation_total = self
                .receive_terminal_byte_saturation_total
                .saturating_add(1);
            let _ = response.send(WebTransportStreamReadOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            ));
            return;
        }

        let mut output = vec![0; allocation_bytes].into_boxed_slice();
        let outcome = match qconn.stream_recv(stream_id, &mut output) {
            Ok((read, fin)) => {
                let mut output = output.into_vec();
                output.truncate(read);
                let data = Bytes::from(output);
                if fin {
                    self.latch_receive_terminal(
                        session_id,
                        stream_id,
                        data,
                        allocation_bytes,
                        WebTransportStreamReceiveTerminal::Fin,
                    )
                } else {
                    WebTransportStreamReadOutcome::Data { data, fin: false }
                }
            },
            Err(quiche::Error::Done) => WebTransportStreamReadOutcome::Blocked,
            Err(quiche::Error::StreamReset(error_code)) => self
                .latch_receive_terminal(
                    session_id,
                    stream_id,
                    Bytes::new(),
                    0,
                    WebTransportStreamReceiveTerminal::Reset {
                        wire_error_code: error_code,
                        application_error_code: webtransport_error_from_http3(
                            error_code,
                        ),
                    },
                ),
            Err(_) => WebTransportStreamReadOutcome::Rejected(
                WebTransportSelectionError::StaleStream,
            ),
        };
        let _ = response.send(outcome);
    }

    fn latch_receive_terminal(
        &mut self, session_id: u64, stream_id: u64, data: Bytes,
        allocation_bytes: usize, terminal: WebTransportStreamReceiveTerminal,
    ) -> WebTransportStreamReadOutcome {
        if let Some(shared) = self.receive_terminal_states.get(&stream_id) {
            return WebTransportStreamReceiveTerminalRead::try_acquire(shared)
                .map_or_else(
                    || {
                        WebTransportStreamReadOutcome::Rejected(
                            WebTransportSelectionError::ResourceLimit,
                        )
                    },
                    WebTransportStreamReadOutcome::Terminal,
                );
        }

        let session_states = self
            .receive_terminal_states_per_session
            .get(&session_id)
            .copied()
            .unwrap_or(0);
        debug_assert!(
            self.receive_terminal_states.len() <
                self.limits.max_receive_terminal_states &&
                session_states <
                    self.limits.max_receive_terminal_states_per_session,
            "receive-terminal admission must reserve fact capacity"
        );
        let shared = Arc::new(ReceiveTerminalReadShared {
            session_id,
            stream_id,
            data,
            terminal,
            allocation_bytes,
            leased: AtomicBool::new(false),
            _terminal_retention: self
                .terminal_retention
                .retain_receive_terminal(allocation_bytes),
        });
        self.receive_terminal_states
            .insert(stream_id, Arc::clone(&shared));
        let count = self
            .receive_terminal_states_per_session
            .entry(session_id)
            .or_default();
        *count = count.saturating_add(1);
        self.receive_terminal_bytes =
            self.receive_terminal_bytes.saturating_add(allocation_bytes);
        let bytes = self
            .receive_terminal_bytes_per_session
            .entry(session_id)
            .or_default();
        *bytes = bytes.saturating_add(allocation_bytes);
        self.receive_terminal_states_high_water = self
            .receive_terminal_states_high_water
            .max(self.receive_terminal_states.len());
        self.receive_terminal_bytes_high_water = self
            .receive_terminal_bytes_high_water
            .max(self.receive_terminal_bytes);

        WebTransportStreamReadOutcome::Terminal(
            WebTransportStreamReceiveTerminalRead::try_acquire(&shared)
                .expect("a newly retained terminal result is unleased"),
        )
    }

    fn retire_stream_receive_terminal(
        &mut self, qconn: &QuicheConnection, session_id: u64, stream_id: u64,
        response: oneshot::Sender<
            WebTransportStreamReceiveTerminalRetirementOutcome,
        >,
    ) {
        if let Some(error) = self.selection_error(session_id, qconn) {
            let outcome = match error {
                WebTransportSelectionError::TerminalSession =>
                    WebTransportStreamReceiveTerminalRetirementOutcome::SessionTerminated {
                        session_id,
                        stream_id,
                    },
                WebTransportSelectionError::ConnectionClosed =>
                    WebTransportStreamReceiveTerminalRetirementOutcome::ConnectionTerminated {
                        session_id,
                        stream_id,
                    },
                _ =>
                    WebTransportStreamReceiveTerminalRetirementOutcome::Rejected(
                        error,
                    ),
            };
            let _ = response.send(outcome);
            return;
        }

        let retained_owner = self
            .receive_terminal_states
            .get(&stream_id)
            .map(|terminal| terminal.session_id);
        let selected = self.stream_sessions.get(&stream_id).copied();
        let owner = selected.map(|stream| stream.session_id).or(retained_owner);
        let Some(owner_session_id) = owner else {
            let error = if qconn.stream_closed(stream_id) {
                WebTransportSelectionError::StaleStream
            } else {
                WebTransportSelectionError::UnknownStream
            };
            let _ = response.send(
                WebTransportStreamReceiveTerminalRetirementOutcome::Rejected(
                    error,
                ),
            );
            return;
        };
        if owner_session_id != session_id {
            let _ = response.send(
                WebTransportStreamReceiveTerminalRetirementOutcome::Rejected(
                    WebTransportSelectionError::ForeignStream {
                        owner_session_id,
                    },
                ),
            );
            return;
        }
        let Some(stream) = selected else {
            let _ = response.send(
                WebTransportStreamReceiveTerminalRetirementOutcome::Rejected(
                    WebTransportSelectionError::StaleStream,
                ),
            );
            return;
        };
        if !stream.has_receive_direction() {
            let _ = response.send(
                WebTransportStreamReceiveTerminalRetirementOutcome::Rejected(
                    WebTransportSelectionError::WrongDirection,
                ),
            );
            return;
        }
        if stream.receive_terminal_observation ==
            ReceiveTerminalObservation::Retired
        {
            let _ = response.send(
                WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                    session_id,
                    stream_id,
                },
            );
            return;
        }
        if !self.receive_terminal_states.contains_key(&stream_id) {
            let _ = response.send(
                WebTransportStreamReceiveTerminalRetirementOutcome::NotObserved {
                    session_id,
                    stream_id,
                },
            );
            return;
        }
        if self
            .receive_terminal_states
            .get(&stream_id)
            .is_some_and(|terminal| terminal.leased.load(Ordering::Acquire))
        {
            let _ = response.send(
                WebTransportStreamReceiveTerminalRetirementOutcome::OutstandingRead {
                    session_id,
                    stream_id,
                },
            );
            return;
        }

        self.remove_receive_terminal_state(stream_id);
        self.retire_receive_terminal_observation(stream_id, stream);
        if let Some(waiter) = self.remove_stream_waiter(stream_id, false) {
            let _ = waiter.response.send(WebTransportStreamReadyOutcome::Closed);
        }
        let _ = response.send(
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id,
                stream_id,
            },
        );
    }

    fn retire_receive_terminal_observation(
        &mut self, stream_id: u64, stream: OwnedStream,
    ) {
        if stream.receive_terminal_observation !=
            ReceiveTerminalObservation::Active
        {
            return;
        }
        self.receive_terminal_observations =
            self.receive_terminal_observations.saturating_sub(1);
        decrement_session_count(
            &mut self.receive_terminal_observations_per_session,
            stream.session_id,
        );
        if let Some(stream) = self.stream_sessions.get_mut(&stream_id) {
            stream.receive_terminal_observation =
                ReceiveTerminalObservation::Retired;
        }
    }

    fn remove_receive_terminal_state(
        &mut self, stream_id: u64,
    ) -> Option<Arc<ReceiveTerminalReadShared>> {
        let terminal = self.receive_terminal_states.remove(&stream_id)?;
        decrement_session_count(
            &mut self.receive_terminal_states_per_session,
            terminal.session_id,
        );
        self.receive_terminal_bytes = self
            .receive_terminal_bytes
            .saturating_sub(terminal.allocation_bytes);
        if let Some(bytes) = self
            .receive_terminal_bytes_per_session
            .get_mut(&terminal.session_id)
        {
            *bytes = bytes.saturating_sub(terminal.allocation_bytes);
            if *bytes == 0 {
                self.receive_terminal_bytes_per_session
                    .remove(&terminal.session_id);
            }
        }
        Some(terminal)
    }

    fn control_stream(
        &mut self, qconn: &mut QuicheConnection, session_id: u64, stream_id: u64,
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
            shutdown_stream_send_direction(
                qconn,
                stream_id,
                wire_error,
                stream.local_prefix_len,
                stream.reset_mode,
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
        if reset {
            self.observe_send_terminal(qconn, stream_id);
        }
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
            self.limits.max_datagram_prefixed_allocation_bytes,
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
            self.observe_send_terminal(qconn, stream_id);
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
        !self.work.is_empty() || self.has_ready_pending_open()
    }

    fn has_ready_pending_open(&self) -> bool {
        (self.bidi_open_credit_ready && !self.pending_bidi_opens.is_empty()) ||
            (self.uni_open_credit_ready && !self.pending_uni_opens.is_empty())
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
                        if self.can_admit_associated_stream(stream) {
                            self.admit_stream(stream);
                            events.push(associated_event(stream));
                        } else {
                            shutdown_stream(
                                qconn,
                                stream,
                                WT_BUFFERED_STREAM_REJECTED,
                            );
                        }
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
                        self.remove_owned_stream(stream_id);
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
            if self.stream_sessions.contains_key(&stream_id) {
                self.observe_send_terminal(qconn, stream_id);
            }
            if self.stream_sessions.get(&stream_id).copied().is_some_and(
                |stream| {
                    matches!(
                        stream.send_terminal_observation,
                        SendTerminalObservation::NotApplicable |
                            SendTerminalObservation::Retired
                    ) && matches!(
                        stream.receive_terminal_observation,
                        ReceiveTerminalObservation::NotApplicable |
                            ReceiveTerminalObservation::Retired
                    ) && !self.receive_terminal_states.contains_key(&stream_id) &&
                        !self.readable_waiters.contains_key(&stream_id) &&
                        !self.writable_waiters.contains_key(&stream_id) &&
                        !self.send_terminal_waiters.contains_key(&stream_id) &&
                        !self.send_terminal_states.contains_key(&stream_id)
                },
            ) {
                self.remove_owned_stream(stream_id);
            }
        }
    }

    fn remove_owned_stream(&mut self, stream_id: u64) -> Option<OwnedStream> {
        let stream = self.stream_sessions.remove(&stream_id)?;
        if stream.send_terminal_observation == SendTerminalObservation::Overloaded
        {
            decrement_session_count(
                &mut self.send_terminal_overloaded_sessions,
                stream.session_id,
            );
        }
        if stream.receive_terminal_observation ==
            ReceiveTerminalObservation::Active
        {
            self.receive_terminal_observations =
                self.receive_terminal_observations.saturating_sub(1);
            decrement_session_count(
                &mut self.receive_terminal_observations_per_session,
                stream.session_id,
            );
        }
        self.remove_receive_terminal_state(stream_id);
        self.close_stream_waiters(stream_id);
        if let Some(session) = self.sessions.get_mut(&stream.session_id) {
            session.streams.remove(&stream_id);
        }
        Some(stream)
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
            matches!(session.phase, SessionPhase::Terminal(_)) &&
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

    pub(super) fn retention_stats(
        &self, qconn: Option<&QuicheConnection>, queued_command_items: usize,
    ) -> WebTransportRetentionStats {
        let associated_streams = self.stream_sessions.len();
        let provisional_streams = self
            .pending_streams
            .len()
            .saturating_add(self.opening_streams.len())
            .saturating_add(self.pending_open_count());
        let waiters = self
            .readable_waiters
            .len()
            .saturating_add(self.writable_waiters.len())
            .saturating_add(self.session_terminal_waiter_count)
            .saturating_add(self.send_terminal_waiters.len())
            .saturating_add(self.pending_open_count())
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
            .saturating_add(self.pending_open_count())
            .saturating_add(self.pending_opens_per_session.len())
            .saturating_add(waiters)
            .saturating_add(self.session_terminal_waiters.len())
            .saturating_add(self.send_terminal_waiters_per_session.len())
            .saturating_add(self.send_terminal_states.len())
            .saturating_add(self.send_terminal_states_per_session.len())
            .saturating_add(self.send_terminal_overloaded_sessions.len())
            .saturating_add(self.readable_waiters_per_session.len())
            .saturating_add(self.receive_terminal_observations_per_session.len())
            .saturating_add(self.receive_terminal_states.len())
            .saturating_add(self.receive_terminal_states_per_session.len())
            .saturating_add(self.receive_terminal_bytes_per_session.len())
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
            stream_open_waiters: self.pending_open_count(),
            max_stream_open_waiters: self.limits.max_pending_streams,
            max_stream_open_waiters_per_session: self
                .limits
                .max_pending_streams_per_session,
            stream_open_waiter_work_total: self.stream_open_waiter_work_total,
            stream_open_waiter_saturation_total: self
                .stream_open_waiter_saturation_total,
            session_terminal_waiters: self.session_terminal_waiter_count,
            max_session_terminal_waiters: self
                .limits
                .max_session_terminal_waiters,
            max_session_terminal_waiters_per_session: self
                .limits
                .max_session_terminal_waiters_per_session,
            session_terminal_waiter_work_total: self
                .session_terminal_waiter_work_total,
            session_terminal_waiter_saturation_total: self
                .session_terminal_waiter_saturation_total,
            waiters,
            send_terminal_waiters: self.send_terminal_waiters.len(),
            send_terminal_states: self.send_terminal_states.len(),
            max_send_terminal_waiters: self.limits.max_send_terminal_waiters,
            max_send_terminal_waiters_per_session: self
                .limits
                .max_send_terminal_waiters_per_session,
            send_terminal_overloaded_sessions: self
                .send_terminal_overloaded_sessions
                .len(),
            send_terminal_waiter_work_total: self.send_terminal_waiter_work_total,
            send_terminal_waiter_saturation_total: self
                .send_terminal_waiter_saturation_total,
            send_terminal_state_saturation_total: self
                .send_terminal_state_saturation_total,
            receive_terminal_observations: self.receive_terminal_observations,
            receive_terminal_states: self.receive_terminal_states.len(),
            receive_terminal_waiters: self.readable_waiters.len(),
            receive_terminal_leases: self
                .receive_terminal_states
                .values()
                .filter(|terminal| terminal.leased.load(Ordering::Acquire))
                .count(),
            receive_terminal_bytes: self.receive_terminal_bytes,
            max_receive_terminal_states: self.limits.max_receive_terminal_states,
            max_receive_terminal_states_per_session: self
                .limits
                .max_receive_terminal_states_per_session,
            max_receive_terminal_waiters: self
                .limits
                .max_receive_terminal_waiters,
            max_receive_terminal_waiters_per_session: self
                .limits
                .max_receive_terminal_waiters_per_session,
            max_receive_terminal_bytes: self.limits.max_receive_terminal_bytes,
            max_receive_terminal_bytes_per_session: self
                .limits
                .max_receive_terminal_bytes_per_session,
            receive_terminal_observations_high_water: self
                .receive_terminal_observations_high_water,
            receive_terminal_states_high_water: self
                .receive_terminal_states_high_water,
            receive_terminal_bytes_high_water: self
                .receive_terminal_bytes_high_water,
            receive_terminal_waiters_high_water: self
                .receive_terminal_waiters_high_water,
            receive_terminal_state_saturation_total: self
                .receive_terminal_state_saturation_total,
            receive_terminal_byte_saturation_total: self
                .receive_terminal_byte_saturation_total,
            receive_terminal_waiter_saturation_total: self
                .receive_terminal_waiter_saturation_total,
            bounded_client_connect_owners: 0,
            max_bounded_client_connect_owners: 0,
            bounded_client_connect_owner_installed_total: 0,
            bounded_client_connect_owner_terminal_release_total: 0,
            bounded_client_connect_owner_teardown_release_total: 0,
            bounded_client_connect_owner_late_install_total: 0,
            metadata_index_entries,
            pending_datagrams: self.pending_datagram_count,
            pending_datagram_payload_bytes: self.pending_datagram_bytes,
            pending_datagram_allocation_bytes: self
                .pending_datagram_allocation_bytes,
            command_capacity: self.limits.command_capacity,
            terminal_retention_waiters: 0,
            max_terminal_retention_waiters: 1,
            terminal_retention_waiter_saturation_total: 0,
            terminal_retention_waiter_cancellation_total: 0,
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
            transport_stream_send_bytes: qconn
                .map_or(0, QuicheConnection::stream_send_queue_byte_size),
            transport_stream_receive_bytes: qconn
                .map_or(0, QuicheConnection::stream_recv_queue_byte_size),
            transport_datagram_send_bytes: qconn
                .map_or(0, QuicheConnection::dgram_send_queue_byte_size),
            transport_datagram_receive_bytes: qconn
                .map_or(0, QuicheConnection::dgram_recv_queue_byte_size),
        }
    }

    pub(super) fn close_write_lease_admission(&self) {
        self.write_lease_accounting.close();
    }

    pub(crate) fn settle_command_on_connection_close(
        &self, command: WebTransportCommand,
    ) {
        let WebTransportCommand::WaitSessionTerminal {
            session_id,
            response,
        } = command
        else {
            command.reject_connection_closed();
            return;
        };
        let outcome = self
            .sessions
            .get(&session_id)
            .and_then(|session| match &session.phase {
                SessionPhase::Terminal(terminal) =>
                    Some(terminal.outcome(session_id)),
                _ => None,
            })
            .unwrap_or(WebTransportSessionTerminalOutcome::Terminated {
                session_id,
                reason: WebTransportSessionCloseReason::ConnectionClosed,
            });
        let _ = response.send(outcome);
    }

    pub(crate) fn clear(&mut self) -> Vec<WebTransportSessionEvent> {
        let events = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                session.application_visible &&
                    !matches!(session.phase, SessionPhase::Terminal(_))
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
        let pending_bidi = std::mem::take(&mut self.pending_bidi_opens);
        let pending_uni = std::mem::take(&mut self.pending_uni_opens);
        for request in pending_bidi.into_iter().chain(pending_uni) {
            let _ =
                request
                    .response
                    .send(WebTransportOpenStreamOutcome::Rejected(
                        WebTransportSelectionError::ConnectionClosed,
                    ));
        }
        for (_, waiter) in std::mem::take(&mut self.readable_waiters) {
            let _ =
                waiter
                    .response
                    .send(WebTransportStreamReadyOutcome::Rejected(
                        WebTransportSelectionError::ConnectionClosed,
                    ));
        }
        for (_, waiter) in std::mem::take(&mut self.writable_waiters) {
            let _ =
                waiter
                    .response
                    .send(WebTransportStreamReadyOutcome::Rejected(
                        WebTransportSelectionError::ConnectionClosed,
                    ));
        }
        for (session_id, waiters) in
            std::mem::take(&mut self.session_terminal_waiters)
        {
            for response in waiters {
                let _ = response.send(
                    WebTransportSessionTerminalOutcome::Terminated {
                        session_id,
                        reason: WebTransportSessionCloseReason::ConnectionClosed,
                    },
                );
            }
        }
        self.session_terminal_waiter_count = 0;
        for (stream_id, waiter) in std::mem::take(&mut self.send_terminal_waiters)
        {
            let outcome = self.send_terminal_states.get(&stream_id).map_or(
                WebTransportStreamSendTerminalOutcome::ConnectionTerminated {
                    session_id: waiter.session_id,
                    stream_id,
                },
                |terminal| terminal.state.outcome(stream_id),
            );
            let _ = waiter.response.send(outcome);
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
        self.readable_waiters_per_session.clear();
        self.send_terminal_waiters_per_session.clear();
        self.send_terminal_states.clear();
        self.send_terminal_states_per_session.clear();
        self.send_terminal_overloaded_sessions.clear();
        self.receive_terminal_observations = 0;
        self.receive_terminal_observations_per_session.clear();
        self.receive_terminal_states.clear();
        self.receive_terminal_states_per_session.clear();
        self.receive_terminal_bytes = 0;
        self.receive_terminal_bytes_per_session.clear();
        self.opening_streams.clear();
        self.opening_order.clear();
        self.opening_by_session.clear();
        self.pending_opens_per_session.clear();
        self.bidi_open_credit_ready = false;
        self.uni_open_credit_ready = false;
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

fn decrement_session_count(counts: &mut BTreeMap<u64, usize>, session_id: u64) {
    let Some(count) = counts.get_mut(&session_id) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        counts.remove(&session_id);
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
    let _ = shutdown_stream_send_direction(
        qconn,
        reservation.stream_id(),
        error_code,
        reservation.prefix_len() as u64,
        reservation.reset_mode(),
    );
}

fn shutdown_stream_send_direction(
    qconn: &mut QuicheConnection, stream_id: u64, error_code: u64,
    reliable_size: u64, reset_mode: quiche::h3::WebTransportStreamResetMode,
) -> quiche::Result<()> {
    match reset_mode {
        quiche::h3::WebTransportStreamResetMode::ReliablePrefixReset =>
            qconn.stream_shutdown_at(stream_id, error_code, reliable_size),
        quiche::h3::WebTransportStreamResetMode::StandardReset =>
            qconn.stream_shutdown(stream_id, quiche::Shutdown::Write, error_code),
    }
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
        let _ = shutdown_stream_send_direction(
            qconn,
            stream_id,
            error_code,
            stream.local_prefix_len,
            stream.reset_mode,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    type DriverPipe = quiche::test_utils::Pipe<crate::buf_factory::BufFactory>;

    fn runtime_limits(
        global: usize, per_session: usize, work: usize,
    ) -> RuntimeLimits {
        RuntimeLimits {
            max_pending_streams: global,
            max_pending_streams_per_session: per_session,
            max_active_streams: global,
            max_active_streams_per_session: per_session,
            max_stream_waiters: global,
            max_session_terminal_waiters: global,
            max_session_terminal_waiters_per_session: per_session,
            max_send_terminal_waiters: global,
            max_send_terminal_waiters_per_session: per_session,
            max_receive_terminal_states: global,
            max_receive_terminal_states_per_session: per_session,
            max_receive_terminal_waiters: global,
            max_receive_terminal_waiters_per_session: per_session,
            max_receive_terminal_bytes: global.saturating_mul(64 * 1024),
            max_receive_terminal_bytes_per_session: per_session
                .saturating_mul(64 * 1024),
            max_datagram_waiters: 2,
            max_pending_datagrams: 256,
            max_pending_datagrams_per_session: 64,
            max_pending_datagram_bytes: 1024 * 1024,
            max_pending_datagram_bytes_per_session: 256 * 1024,
            max_pending_datagram_allocation_bytes: 1024 * 1024,
            max_pending_datagram_allocation_bytes_per_session: 256 * 1024,
            max_pending_datagram_age: Duration::from_secs(5),
            max_datagram_prefixed_allocation_bytes: 64 * 1024 + 16,
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

    fn terminal_controller() -> (
        WebTransportController,
        mpsc::Receiver<WebTransportCommand>,
        Arc<TerminalRetentionState>,
        Arc<WriteLeaseAccounting>,
    ) {
        let (sender, recv) = mpsc::channel(2);
        let terminal_retention = Arc::new(TerminalRetentionState::new());
        let write_lease_accounting = Arc::new(WriteLeaseAccounting::new(
            2,
            64,
            Arc::downgrade(&terminal_retention),
        ));
        terminal_retention.bind_write_lease_accounting(&write_lease_accounting);
        let controller = WebTransportController::new(
            sender,
            WebTransportControllerLimits {
                max_stream_write_bytes: 64,
                max_stream_write_lease_retained_bytes: 64,
                max_stream_write_lease_owner_bytes: 64,
                max_stream_read_bytes: 64,
                max_datagram_send_allocation_bytes: 0,
                max_datagram_prefixed_allocation_bytes: 0,
            },
            Arc::clone(&write_lease_accounting),
            Arc::new(AtomicBool::new(false)),
            Arc::clone(&terminal_retention),
        );
        (controller, recv, terminal_retention, write_lease_accounting)
    }

    #[test]
    fn terminal_retention_is_controller_bound_bounded_and_take_once() {
        let (controller, _recv, state, _write_leases) = terminal_controller();
        let clone = controller.clone();
        let claim = controller.terminal_retention_claim();
        assert_eq!(
            clone.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::Early(
                WebTransportTerminalRetentionPending::default()
            )
        );

        let (foreign, _recv, _state, _write_leases) = terminal_controller();
        assert_eq!(
            foreign.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::ForeignController
        );
        assert_matches!(
            futures::executor::block_on(
                foreign.wait_terminal_retention(claim.clone())
            ),
            WebTransportTerminalRetentionOutcome::ForeignController
        );

        let mut first = controller.wait_terminal_retention(claim.clone());
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(Future::poll(Pin::new(&mut first), &mut context).is_pending());
        assert_eq!(
            futures::executor::block_on(
                clone.wait_terminal_retention(claim.clone())
            ),
            WebTransportTerminalRetentionOutcome::WaiterUnavailable
        );
        assert_eq!(
            first.cancel(),
            WebTransportTerminalRetentionOutcome::Cancelled
        );

        let mut stats = WebTransportRetentionStats {
            sessions: 1,
            metadata_index_entries: 4,
            command_capacity: 2,
            receive_terminal_states_high_water: 3,
            ..WebTransportRetentionStats::default()
        };
        stats.transport_stream_send_bytes = 128;
        state.mark_connection_owner_attached();
        state.mark_runtime_settled(stats);
        state.mark_connection_owner_dropped();

        let taken = assert_matches!(
            futures::executor::block_on(
                clone.wait_terminal_retention(claim.clone())
            ),
            WebTransportTerminalRetentionOutcome::Taken(stats) => stats
        );
        assert_eq!(taken.sessions, 0);
        assert_eq!(taken.metadata_index_entries, 0);
        assert_eq!(taken.transport_stream_send_bytes, 0);
        assert_eq!(taken.command_capacity, 2);
        assert_eq!(taken.receive_terminal_states_high_water, 3);
        assert_eq!(taken.terminal_retention_waiters, 0);
        assert_eq!(taken.max_terminal_retention_waiters, 1);
        assert_eq!(taken.terminal_retention_waiter_saturation_total, 1);
        assert_eq!(taken.terminal_retention_waiter_cancellation_total, 1);
        assert_eq!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::AlreadyTaken
        );
        let inner = state.lock();
        assert!(inner.runtime_stats.is_none());
        assert!(inner.waiter.is_none());
    }

    #[test]
    fn terminal_retention_waits_for_external_write_and_receive_owners() {
        let (controller, _recv, state, write_leases) = terminal_controller();
        let claim = controller.terminal_retention_claim();
        let write = write_leases.try_admit(9).unwrap();
        let receive = state.retain_receive_terminal(11);
        state.mark_connection_owner_attached();
        state.mark_runtime_settled(WebTransportRetentionStats {
            receive_terminal_states_high_water: 1,
            receive_terminal_bytes_high_water: 11,
            ..WebTransportRetentionStats::default()
        });
        state.mark_connection_owner_dropped();

        assert_eq!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::Early(
                WebTransportTerminalRetentionPending {
                    runtime_settled: true,
                    connection_owner_attached: true,
                    connection_owner_dropped: true,
                    write_leases: 1,
                    write_lease_retained_bytes: 9,
                    receive_terminal_leases: 1,
                    receive_terminal_bytes: 11,
                }
            )
        );
        drop(write);
        let pending = assert_matches!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::Early(pending) => pending
        );
        assert_eq!(pending.write_leases, 0);
        assert_eq!(pending.receive_terminal_leases, 1);
        drop(receive);

        let stats = assert_matches!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::Taken(stats) => stats
        );
        assert_eq!(stats.write_leases, 0);
        assert_eq!(stats.write_lease_retained_bytes, 0);
        assert_eq!(stats.write_lease_admitted_total, 1);
        assert_eq!(stats.receive_terminal_states, 0);
        assert_eq!(stats.receive_terminal_leases, 0);
        assert_eq!(stats.receive_terminal_bytes, 0);
        assert_eq!(stats.receive_terminal_states_high_water, 1);
        assert_eq!(stats.receive_terminal_bytes_high_water, 11);
    }

    #[test]
    fn terminal_retention_preserves_late_write_cumulative_totals() {
        let (controller, _recv, state, write_leases) = terminal_controller();
        let write = write_leases.try_admit(9).unwrap();
        state.mark_connection_owner_attached();
        state.mark_runtime_settled(WebTransportRetentionStats::default());
        state.mark_connection_owner_dropped();

        let claim = controller.terminal_retention_claim();
        let mut wait = controller.wait_terminal_retention(claim);
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(Future::poll(Pin::new(&mut wait), &mut context).is_pending());
        drop(controller);
        drop(write_leases);

        write.accounting.record_abandonment(
            WebTransportStreamWriteLeaseProgress::NeverExposed,
        );
        drop(write);

        let stats = assert_matches!(
            futures::executor::block_on(wait),
            WebTransportTerminalRetentionOutcome::Taken(stats) => stats
        );
        assert_eq!(stats.write_lease_admitted_total, 1);
        assert_eq!(stats.write_lease_abandoned_unexposed_total, 1);
        assert!(state.lock().write_lease_accounting.is_none());
    }

    #[test]
    fn terminal_retention_reports_unavailable_without_owner_hook() {
        let (controller, _recv, state, _write_leases) = terminal_controller();
        let claim = controller.terminal_retention_claim();
        state.mark_runtime_settled(WebTransportRetentionStats::default());
        state.mark_driver_dropped();
        assert_eq!(
            controller.try_take_terminal_retention(&claim),
            WebTransportTerminalRetentionOutcome::Unavailable
        );
    }

    #[test]
    fn closed_terminal_admission_returns_owner_without_limit_rejection() {
        let (controller, _recv, _state, write_leases) = terminal_controller();
        write_leases.close();

        let outcome = futures::executor::block_on(controller.write_stream_lease(
            0,
            0,
            BytesWriteLease(Bytes::from_static(b"owned")),
            false,
        ));
        let lease = match outcome {
            WebTransportStreamWriteLeaseOutcome::Rejected {
                error: WebTransportSelectionError::ConnectionClosed,
                lease,
                fin: false,
            } => lease,
            _ => panic!("closed admission returned an unexpected outcome"),
        };
        assert_eq!(lease.0, Bytes::from_static(b"owned"));
        let accounting = write_leases.snapshot();
        assert_eq!(accounting.current, 0);
        assert_eq!(accounting.resource_limit_total, 0);
    }

    #[test]
    fn terminal_retention_tracks_an_actual_receive_terminal_lease() {
        let mut pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(8, 8, 8));
        activate_session(&mut runtime, 0);
        own_stream(&mut runtime, 0, 2, WebTransportStreamDirection::Uni, false);
        pipe.client.stream_send(2, b"final", true).unwrap();
        pipe.advance().unwrap();
        let terminal = assert_matches!(
            read_stream(&mut runtime, &mut pipe.server, 0, 2, 64),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        let terminal_retention = Arc::clone(&runtime.terminal_retention);
        runtime.close_write_lease_admission();
        runtime.clear();
        let stats = runtime.retention_stats(Some(&pipe.server), 0);
        terminal_retention.mark_connection_owner_attached();
        terminal_retention.mark_runtime_settled(stats);
        drop(pipe);
        terminal_retention.mark_connection_owner_dropped();

        let pending = assert_matches!(
            terminal_retention.try_take(),
            WebTransportTerminalRetentionOutcome::Early(pending) => pending
        );
        assert_eq!(pending.receive_terminal_leases, 1);
        assert!(pending.receive_terminal_bytes >= terminal.data().len());
        drop(terminal);

        let stats = assert_matches!(
            terminal_retention.try_take(),
            WebTransportTerminalRetentionOutcome::Taken(stats) => stats
        );
        assert_eq!(stats.receive_terminal_leases, 0);
        assert_eq!(stats.receive_terminal_bytes, 0);
        assert_eq!(stats.receive_terminal_states_high_water, 1);
        assert!(stats.receive_terminal_bytes_high_water >= 5);
    }

    fn activate_session(runtime: &mut Runtime, session_id: u64) {
        let mut session = Session::pending(false);
        session.phase = SessionPhase::Active;
        runtime.sessions.insert(session_id, session);
    }

    fn own_stream(
        runtime: &mut Runtime, session_id: u64, stream_id: u64,
        direction: WebTransportStreamDirection, locally_initiated: bool,
    ) {
        let stream =
            OwnedStream::new(session_id, direction, 0, locally_initiated);
        assert!(runtime.can_admit_owned_stream(stream));
        runtime.insert_owned_stream(stream_id, stream);
        runtime
            .sessions
            .get_mut(&session_id)
            .unwrap()
            .streams
            .insert(stream_id);
    }

    fn read_stream(
        runtime: &mut Runtime, qconn: &mut QuicheConnection, session_id: u64,
        stream_id: u64, max_bytes: usize,
    ) -> WebTransportStreamReadOutcome {
        let (response, mut outcome) = oneshot::channel();
        runtime.read_stream(qconn, session_id, stream_id, max_bytes, response);
        outcome.try_recv().unwrap()
    }

    fn retire_receive_terminal(
        runtime: &mut Runtime, qconn: &QuicheConnection, session_id: u64,
        stream_id: u64,
    ) -> WebTransportStreamReceiveTerminalRetirementOutcome {
        let (response, mut outcome) = oneshot::channel();
        runtime.retire_stream_receive_terminal(
            qconn, session_id, stream_id, response,
        );
        outcome.try_recv().unwrap()
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
    fn session_terminal_wait_is_level_triggered_across_live_phases() {
        let mut pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(8, 8, 8));
        assert_matches!(
            runtime.observe_request(0, true),
            RequestObservation::Observed(_)
        );

        let (response, mut waited) = oneshot::channel();
        runtime.wait_session_terminal(&pipe.server, 0, response);
        assert_matches!(
            waited.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        assert_eq!(runtime.session_terminal_waiter_count, 1);

        runtime.activate(0);
        let idle_work = runtime.session_terminal_waiter_work_total;
        for _ in 0..128 {
            runtime.process_work(&mut pipe.server);
        }
        assert_eq!(runtime.session_terminal_waiter_work_total, idle_work);
        assert_matches!(
            waited.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        assert!(runtime.begin_local_close(
            0,
            CloseCapsule::new(17, "closing".to_string()).unwrap(),
        ));
        assert_matches!(
            waited.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );

        let reason = WebTransportSessionCloseReason::Local {
            error_code: 17,
            message: "closing".to_string(),
        };
        assert_eq!(runtime.terminate(0, reason.clone()), vec![
            WebTransportSessionEvent::Terminated {
                session_id: 0,
                reason: reason.clone(),
            }
        ]);
        assert_eq!(
            waited.try_recv().unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id: 0,
                reason: reason.clone(),
            }
        );
        assert_eq!(runtime.session_terminal_waiter_count, 0);
        assert!(runtime
            .terminate(0, WebTransportSessionCloseReason::ProtocolError)
            .is_empty());

        let (late_response, mut late) = oneshot::channel();
        runtime.wait_session_terminal(&pipe.server, 0, late_response);
        assert_eq!(
            late.try_recv().unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id: 0,
                reason,
            }
        );
        assert!(runtime.pending_bidi_opens.is_empty());
        assert!(runtime.pending_uni_opens.is_empty());
        assert!(runtime.opening_streams.is_empty());
    }

    #[test]
    fn session_terminal_wait_cancellation_and_bounds_are_exact() {
        let pipe = pipe();
        let mut limits = runtime_limits(8, 8, 8);
        limits.max_session_terminal_waiters = 2;
        limits.max_session_terminal_waiters_per_session = 2;
        let mut runtime = Runtime::new(limits);
        assert_matches!(
            runtime.observe_request(0, true),
            RequestObservation::Observed(_)
        );

        let (first_response, first) = oneshot::channel();
        runtime.wait_session_terminal(&pipe.server, 0, first_response);
        let (second_response, mut second) = oneshot::channel();
        runtime.wait_session_terminal(&pipe.server, 0, second_response);
        let (full_response, mut full) = oneshot::channel();
        runtime.wait_session_terminal(&pipe.server, 0, full_response);
        assert_eq!(
            full.try_recv().unwrap(),
            WebTransportSessionTerminalOutcome::ResourceLimit { session_id: 0 }
        );
        assert_eq!(runtime.session_terminal_waiter_count, 2);

        drop(first);
        runtime.prune_cancelled_session_terminal_waiters();
        assert_eq!(runtime.session_terminal_waiter_count, 1);

        let (replacement_response, mut replacement) = oneshot::channel();
        runtime.wait_session_terminal(&pipe.server, 0, replacement_response);
        assert_eq!(runtime.session_terminal_waiter_count, 2);
        runtime.terminate(0, WebTransportSessionCloseReason::Clean);
        assert_eq!(
            second.try_recv().unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id: 0,
                reason: WebTransportSessionCloseReason::Clean,
            }
        );
        assert_eq!(
            replacement.try_recv().unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id: 0,
                reason: WebTransportSessionCloseReason::Clean,
            }
        );
        assert_eq!(runtime.session_terminal_waiter_count, 0);
        assert_eq!(runtime.session_terminal_waiter_saturation_total, 1);

        let mut per_session_limits = runtime_limits(8, 8, 8);
        per_session_limits.max_session_terminal_waiters = 2;
        per_session_limits.max_session_terminal_waiters_per_session = 1;
        let mut per_session = Runtime::new(per_session_limits);
        per_session.observe_request(0, true);
        let (admitted_response, admitted) = oneshot::channel();
        per_session.wait_session_terminal(&pipe.server, 0, admitted_response);
        let (limited_response, mut limited) = oneshot::channel();
        per_session.wait_session_terminal(&pipe.server, 0, limited_response);
        assert_eq!(
            limited.try_recv().unwrap(),
            WebTransportSessionTerminalOutcome::ResourceLimit { session_id: 0 }
        );
        drop(admitted);
        per_session.prune_cancelled_session_terminal_waiters();
        assert_eq!(per_session.session_terminal_waiter_count, 0);
        assert_eq!(per_session.session_terminal_waiter_saturation_total, 1);
    }

    #[test]
    fn session_terminal_wait_reports_rejection_unknown_and_connection_close() {
        let pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(8, 8, 8));

        let (unknown_response, mut unknown) = oneshot::channel();
        runtime.wait_session_terminal(&pipe.server, 4000, unknown_response);
        assert_eq!(
            unknown.try_recv().unwrap(),
            WebTransportSessionTerminalOutcome::UnknownSession {
                session_id: 4000,
            }
        );

        runtime.observe_request(0, true);
        let (rejected_response, mut rejected) = oneshot::channel();
        runtime.wait_session_terminal(&pipe.server, 0, rejected_response);
        runtime.reject(0, 403);
        assert_eq!(
            rejected.try_recv().unwrap(),
            WebTransportSessionTerminalOutcome::SessionRejected {
                session_id: 0,
                status: 403,
            }
        );

        runtime.observe_request(4, true);
        let (closed_response, mut closed) = oneshot::channel();
        runtime.wait_session_terminal(&pipe.server, 4, closed_response);
        runtime.clear();
        assert_eq!(
            closed.try_recv().unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id: 4,
                reason: WebTransportSessionCloseReason::ConnectionClosed,
            }
        );
        assert_eq!(runtime.session_terminal_waiter_count, 0);
        assert!(runtime.session_terminal_waiters.is_empty());

        // Keep the mutable pipe live to exercise Runtime::clear() with a real
        // established connection rather than a detached fixture.
        assert!(!pipe.server.is_closed());
    }

    #[test]
    fn session_terminal_waiter_state_is_reclaimed_across_turnover() {
        let mut pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(2, 2, 8));

        for ordinal in 0..4096 {
            let session_id = ordinal * 4;
            runtime.observe_request(session_id, true);
            let (response, mut waited) = oneshot::channel();
            runtime.wait_session_terminal(&pipe.server, session_id, response);
            runtime.terminate(session_id, WebTransportSessionCloseReason::Clean);
            assert_eq!(
                waited.try_recv().unwrap(),
                WebTransportSessionTerminalOutcome::Terminated {
                    session_id,
                    reason: WebTransportSessionCloseReason::Clean,
                }
            );
            runtime.mark_connect_recv_closed(session_id);
            runtime.mark_connect_send_closed(session_id);
            runtime.process_work(&mut pipe.server);
            assert!(!runtime.sessions.contains_key(&session_id));
            assert_eq!(runtime.session_terminal_waiter_count, 0);
            assert!(runtime.session_terminal_waiters.is_empty());
        }

        assert_eq!(runtime.session_terminal_waiter_saturation_total, 0);
    }

    #[test]
    fn send_terminal_rejects_a_stream_owned_by_another_active_session() {
        let pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(8, 8, 8));
        for session_id in [0, 4] {
            let mut session = Session::pending(false);
            session.phase = SessionPhase::Active;
            runtime.sessions.insert(session_id, session);
        }
        runtime.stream_sessions.insert(
            8,
            OwnedStream::new(0, WebTransportStreamDirection::Uni, 3, true),
        );

        let (response, mut outcome) = oneshot::channel();
        runtime.wait_stream_send_terminal(&pipe.server, 4, 8, response);
        assert_eq!(
            outcome.try_recv().unwrap(),
            WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::ForeignStream {
                    owner_session_id: 0,
                },
            )
        );
        assert!(runtime.send_terminal_waiters.is_empty());
    }

    #[test]
    fn send_terminal_retirement_reuses_bounded_fact_capacity() {
        let pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(256, 64, 8));
        let mut session = Session::pending(false);
        session.phase = SessionPhase::Active;
        runtime.sessions.insert(0, session);

        for ordinal in 0..4_096 {
            let stream_id = ordinal * 4 + 1;
            runtime.stream_sessions.insert(
                stream_id,
                OwnedStream::new(0, WebTransportStreamDirection::Uni, 3, true),
            );
            runtime
                .sessions
                .get_mut(&0)
                .unwrap()
                .streams
                .insert(stream_id);

            let (wait_response, mut waited) = oneshot::channel();
            runtime.wait_stream_send_terminal(
                &pipe.server,
                0,
                stream_id,
                wait_response,
            );
            assert_eq!(
                waited.try_recv().unwrap(),
                WebTransportStreamSendTerminalOutcome::Closed { stream_id }
            );
            assert_eq!(runtime.send_terminal_states.len(), 1);

            let (retire_response, mut retired) = oneshot::channel();
            runtime.retire_stream_send_terminal(
                &pipe.server,
                0,
                stream_id,
                retire_response,
            );
            assert_eq!(
                retired.try_recv().unwrap(),
                WebTransportStreamSendTerminalOutcome::Retired {
                    session_id: 0,
                    stream_id,
                }
            );
            assert!(runtime.send_terminal_states.is_empty());
            assert!(runtime.send_terminal_states_per_session.is_empty());
            assert!(runtime.send_terminal_waiters.is_empty());
            assert!(runtime.send_terminal_waiters_per_session.is_empty());
            assert!(runtime.send_terminal_overloaded_sessions.is_empty());

            runtime.stream_sessions.remove(&stream_id);
            runtime
                .sessions
                .get_mut(&0)
                .unwrap()
                .streams
                .remove(&stream_id);
        }

        assert_eq!(runtime.send_terminal_state_saturation_total, 0);
        assert_eq!(runtime.send_terminal_waiter_saturation_total, 0);
    }

    #[test]
    fn receive_terminal_separate_fin_survives_closed_stream_collection() {
        let mut pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(8, 8, 8));
        activate_session(&mut runtime, 0);
        own_stream(&mut runtime, 0, 2, WebTransportStreamDirection::Uni, false);

        pipe.client.stream_send(2, b"last payload", false).unwrap();
        pipe.advance().unwrap();
        let (payload_response, mut payload) = oneshot::channel();
        runtime.read_stream(&mut pipe.server, 0, 2, 64, payload_response);
        assert_eq!(
            payload.try_recv().unwrap(),
            WebTransportStreamReadOutcome::Data {
                data: Bytes::from_static(b"last payload"),
                fin: false,
            }
        );
        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 0, 2),
            WebTransportStreamReceiveTerminalRetirementOutcome::NotObserved {
                session_id: 0,
                stream_id: 2,
            }
        );

        pipe.client.stream_send(2, b"", true).unwrap();
        pipe.advance().unwrap();
        let (ready_response, mut ready) = oneshot::channel();
        runtime.wait_stream(&pipe.server, 0, 2, false, None, ready_response);
        assert_eq!(
            ready.try_recv().unwrap(),
            WebTransportStreamReadyOutcome::Ready
        );

        runtime.process_work(&mut pipe.server);
        let (terminal_response, mut terminal) = oneshot::channel();
        runtime.read_stream(&mut pipe.server, 0, 2, 64, terminal_response);
        let terminal = assert_matches!(
            terminal.try_recv().unwrap(),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert!(terminal.data().is_empty());
        assert_eq!(terminal.terminal(), WebTransportStreamReceiveTerminal::Fin);
        drop(terminal);

        let (retire_response, mut retired) = oneshot::channel();
        runtime.retire_stream_receive_terminal(
            &pipe.server,
            0,
            2,
            retire_response,
        );
        assert_eq!(
            retired.try_recv().unwrap(),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id: 0,
                stream_id: 2,
            }
        );
        runtime.process_work(&mut pipe.server);
        assert!(!runtime.stream_sessions.contains_key(&2));
    }

    #[test]
    fn receive_terminal_fin_shapes_replay_without_copy_until_retired() {
        let mut pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(8, 8, 8));
        activate_session(&mut runtime, 0);
        own_stream(&mut runtime, 0, 2, WebTransportStreamDirection::Uni, false);

        pipe.client.stream_send(2, b"final", true).unwrap();
        pipe.advance().unwrap();
        let terminal = assert_matches!(
            read_stream(&mut runtime, &mut pipe.server, 0, 2, 64),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert_eq!(terminal.session_id(), 0);
        assert_eq!(terminal.stream_id(), 2);
        assert_eq!(terminal.data(), b"final");
        assert_eq!(terminal.terminal(), WebTransportStreamReceiveTerminal::Fin);
        let retained_ptr = terminal.data().as_ptr();
        assert_eq!(runtime.receive_terminal_states.len(), 1);
        assert_eq!(runtime.receive_terminal_bytes, 5);
        assert_eq!(runtime.receive_terminal_observations, 1);
        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 0, 2),
            WebTransportStreamReceiveTerminalRetirementOutcome::OutstandingRead {
                session_id: 0,
                stream_id: 2,
            }
        );
        assert_eq!(runtime.receive_terminal_states.len(), 1);
        assert_eq!(runtime.receive_terminal_bytes, 5);
        drop(terminal);

        let replayed = assert_matches!(
            read_stream(&mut runtime, &mut pipe.server, 0, 2, 64),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert_eq!(replayed.data().as_ptr(), retained_ptr);
        assert_eq!(replayed.data(), b"final");
        assert_eq!(replayed.terminal(), WebTransportStreamReceiveTerminal::Fin);
        drop(replayed);

        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 0, 2),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id: 0,
                stream_id: 2,
            }
        );
        assert_eq!(runtime.receive_terminal_states.len(), 0);
        assert_eq!(runtime.receive_terminal_bytes, 0);
        assert_eq!(runtime.receive_terminal_observations, 0);
        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 0, 2),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id: 0,
                stream_id: 2,
            }
        );
        runtime.process_work(&mut pipe.server);
        assert_eq!(
            read_stream(&mut runtime, &mut pipe.server, 0, 2, 64),
            WebTransportStreamReadOutcome::Rejected(
                WebTransportSelectionError::StaleStream,
            )
        );

        own_stream(&mut runtime, 0, 6, WebTransportStreamDirection::Uni, false);
        pipe.client.stream_send(6, b"", true).unwrap();
        pipe.advance().unwrap();
        let empty = assert_matches!(
            read_stream(&mut runtime, &mut pipe.server, 0, 6, 64),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert!(empty.data().is_empty());
        assert_eq!(empty.terminal(), WebTransportStreamReceiveTerminal::Fin);
        assert_eq!(runtime.receive_terminal_bytes, 0);
        drop(empty);
        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 0, 6),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id: 0,
                stream_id: 6,
            }
        );
    }

    #[test]
    fn receive_terminal_reset_survives_wait_and_read_cancellation() {
        let mut pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(8, 8, 8));
        activate_session(&mut runtime, 0);
        pipe.client.stream_send(0, b"x", false).unwrap();
        pipe.advance().unwrap();
        let mut opened = [0; 1];
        assert_eq!(pipe.server.stream_recv(0, &mut opened), Ok((1, false)));
        own_stream(&mut runtime, 0, 0, WebTransportStreamDirection::Bidi, false);

        let (cancelled_wait, cancelled) = oneshot::channel();
        runtime.wait_stream(&pipe.server, 0, 0, false, None, cancelled_wait);
        assert_eq!(runtime.readable_waiters.len(), 1);
        drop(cancelled);
        runtime.prune_cancelled_stream_waiters();
        assert!(runtime.readable_waiters.is_empty());
        assert!(runtime.readable_waiters_per_session.is_empty());

        let (wait_response, mut waited) = oneshot::channel();
        runtime.wait_stream(&pipe.server, 0, 0, false, None, wait_response);
        let wire_error_code = webtransport_error_to_http3(73);
        pipe.client
            .stream_shutdown(0, quiche::Shutdown::Write, wire_error_code)
            .unwrap();
        pipe.advance().unwrap();
        assert!(runtime.process_owned_readable(&pipe.server, 0));
        assert_eq!(
            waited.try_recv().unwrap(),
            WebTransportStreamReadyOutcome::Ready
        );

        let (late_wait_response, mut late_wait) = oneshot::channel();
        runtime.wait_stream(&pipe.server, 0, 0, false, None, late_wait_response);
        assert_eq!(
            late_wait.try_recv().unwrap(),
            WebTransportStreamReadyOutcome::Ready
        );

        let (cancelled_read, cancelled) = oneshot::channel();
        drop(cancelled);
        runtime.read_stream(&mut pipe.server, 0, 0, 64, cancelled_read);
        assert!(runtime.receive_terminal_states.is_empty());

        let (raced_response, raced) = oneshot::channel();
        runtime.read_stream(&mut pipe.server, 0, 0, 64, raced_response);
        assert_eq!(runtime.receive_terminal_states.len(), 1);
        assert!(runtime
            .receive_terminal_states
            .get(&0)
            .unwrap()
            .leased
            .load(Ordering::Acquire));
        drop(raced);
        assert!(!runtime
            .receive_terminal_states
            .get(&0)
            .unwrap()
            .leased
            .load(Ordering::Acquire));

        let terminal = assert_matches!(
            read_stream(&mut runtime, &mut pipe.server, 0, 0, 64),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert!(terminal.data().is_empty());
        assert_eq!(
            terminal.terminal(),
            WebTransportStreamReceiveTerminal::Reset {
                wire_error_code,
                application_error_code: Some(73),
            }
        );
        drop(terminal);
        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 0, 0),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id: 0,
                stream_id: 0,
            }
        );

        own_stream(&mut runtime, 0, 4, WebTransportStreamDirection::Bidi, false);
        pipe.client.stream_send(4, b"prefix", false).unwrap();
        pipe.advance().unwrap();
        assert_eq!(
            read_stream(&mut runtime, &mut pipe.server, 0, 4, 64),
            WebTransportStreamReadOutcome::Data {
                data: Bytes::from_static(b"prefix"),
                fin: false,
            }
        );
        let second_wire_error = WT_APPLICATION_ERROR_FIRST - 1;
        pipe.client
            .stream_shutdown(4, quiche::Shutdown::Write, second_wire_error)
            .unwrap();
        pipe.advance().unwrap();
        let terminal = assert_matches!(
            read_stream(&mut runtime, &mut pipe.server, 0, 4, 64),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert_eq!(
            terminal.terminal(),
            WebTransportStreamReceiveTerminal::Reset {
                wire_error_code: second_wire_error,
                application_error_code: None,
            }
        );
        drop(terminal);
        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 0, 4),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id: 0,
                stream_id: 4,
            }
        );
    }

    #[test]
    fn receive_terminal_bounds_reject_before_mutation_and_reclaim_capacity() {
        let mut pipe = pipe();
        let mut limits = runtime_limits(3, 3, 8);
        limits.max_receive_terminal_states = 2;
        limits.max_receive_terminal_states_per_session = 2;
        limits.max_receive_terminal_waiters = 1;
        limits.max_receive_terminal_waiters_per_session = 1;
        limits.max_receive_terminal_bytes = 4;
        limits.max_receive_terminal_bytes_per_session = 4;
        let mut runtime = Runtime::new(limits);
        activate_session(&mut runtime, 0);
        for stream_id in [2, 6] {
            own_stream(
                &mut runtime,
                0,
                stream_id,
                WebTransportStreamDirection::Uni,
                false,
            );
        }
        assert!(!runtime.can_admit_owned_stream(OwnedStream::new(
            0,
            WebTransportStreamDirection::Uni,
            0,
            false,
        )));
        assert_eq!(runtime.receive_terminal_state_saturation_total, 1);

        pipe.client.stream_send(2, b"12345", true).unwrap();
        pipe.advance().unwrap();
        assert_eq!(pipe.server.stream_readable_len(2), 5);
        assert_eq!(
            read_stream(&mut runtime, &mut pipe.server, 0, 2, 64),
            WebTransportStreamReadOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            )
        );
        assert_eq!(pipe.server.stream_readable_len(2), 5);
        assert_eq!(runtime.receive_terminal_states.len(), 0);
        assert_eq!(runtime.receive_terminal_bytes, 0);
        assert_eq!(runtime.receive_terminal_byte_saturation_total, 1);

        assert_eq!(
            read_stream(&mut runtime, &mut pipe.server, 0, 2, 4),
            WebTransportStreamReadOutcome::Data {
                data: Bytes::from_static(b"1234"),
                fin: false,
            }
        );
        let terminal = assert_matches!(
            read_stream(&mut runtime, &mut pipe.server, 0, 2, 4),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert_eq!(terminal.data(), b"5");
        assert_eq!(runtime.receive_terminal_bytes, 1);
        assert_eq!(runtime.receive_terminal_states.len(), 1);
        drop(terminal);
        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 0, 2),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id: 0,
                stream_id: 2,
            }
        );
        assert!(runtime.can_admit_owned_stream(OwnedStream::new(
            0,
            WebTransportStreamDirection::Uni,
            0,
            false,
        )));

        pipe.client.stream_send(6, b"x", false).unwrap();
        pipe.advance().unwrap();
        let mut opened = [0; 1];
        assert_eq!(pipe.server.stream_recv(6, &mut opened), Ok((1, false)));
        let (first_response, first) = oneshot::channel();
        runtime.wait_stream(&pipe.server, 0, 6, false, None, first_response);
        let (full_response, mut full) = oneshot::channel();
        runtime.wait_stream(&pipe.server, 0, 6, false, None, full_response);
        assert_eq!(
            full.try_recv().unwrap(),
            WebTransportStreamReadyOutcome::Rejected(
                WebTransportSelectionError::ResourceLimit,
            )
        );
        assert_eq!(runtime.receive_terminal_waiter_saturation_total, 1);
        drop(first);
        runtime.prune_cancelled_stream_waiters();
        assert!(runtime.readable_waiters.is_empty());
        assert!(runtime.readable_waiters_per_session.is_empty());

        let (replacement_response, mut replacement) = oneshot::channel();
        runtime.wait_stream(
            &pipe.server,
            0,
            6,
            false,
            None,
            replacement_response,
        );
        pipe.client.stream_send(6, b"", true).unwrap();
        pipe.advance().unwrap();
        assert!(runtime.process_owned_readable(&pipe.server, 6));
        assert_eq!(
            replacement.try_recv().unwrap(),
            WebTransportStreamReadyOutcome::Ready
        );
        assert!(runtime.readable_waiters.is_empty());
        assert!(runtime.readable_waiters_per_session.is_empty());
    }

    #[test]
    fn receive_terminal_directional_half_closes_are_independent() {
        let mut pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(8, 8, 8));
        activate_session(&mut runtime, 4);
        own_stream(&mut runtime, 4, 0, WebTransportStreamDirection::Bidi, false);
        own_stream(&mut runtime, 4, 2, WebTransportStreamDirection::Uni, false);
        own_stream(&mut runtime, 4, 3, WebTransportStreamDirection::Uni, true);

        assert_eq!(
            read_stream(&mut runtime, &mut pipe.server, 4, 3, 16),
            WebTransportStreamReadOutcome::Rejected(
                WebTransportSelectionError::WrongDirection,
            )
        );
        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 4, 3),
            WebTransportStreamReceiveTerminalRetirementOutcome::Rejected(
                WebTransportSelectionError::WrongDirection,
            )
        );
        let (send_response, mut send) = oneshot::channel();
        runtime.wait_stream_send_terminal(&pipe.server, 4, 2, send_response);
        assert_eq!(
            send.try_recv().unwrap(),
            WebTransportStreamSendTerminalOutcome::Rejected(
                WebTransportSelectionError::WrongDirection,
            )
        );

        pipe.client.stream_send(0, b"request", true).unwrap();
        pipe.advance().unwrap();
        let (write_response, mut write_waiter) = oneshot::channel();
        runtime.writable_waiters.insert(0, StreamReadyWaiter {
            session_id: 4,
            retry: None,
            response: write_response,
        });
        let terminal = assert_matches!(
            read_stream(&mut runtime, &mut pipe.server, 4, 0, 64),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        assert_eq!(terminal.data(), b"request");
        drop(terminal);
        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 4, 0),
            WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                session_id: 4,
                stream_id: 0,
            }
        );
        assert_matches!(
            write_waiter.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        assert!(runtime.writable_waiters.contains_key(&0));
        runtime.process_work(&mut pipe.server);
        assert!(runtime.stream_sessions.contains_key(&0));

        pipe.server.stream_send(0, b"", true).unwrap();
        assert!(runtime.process_owned_writable(&mut pipe.server, 0));
        assert_eq!(
            write_waiter.try_recv().unwrap(),
            WebTransportStreamReadyOutcome::Closed
        );
        let (send_response, mut send) = oneshot::channel();
        runtime.wait_stream_send_terminal(&pipe.server, 4, 0, send_response);
        assert_eq!(
            send.try_recv().unwrap(),
            WebTransportStreamSendTerminalOutcome::Closed { stream_id: 0 }
        );
        let (retire_response, mut retired) = oneshot::channel();
        runtime.retire_stream_send_terminal(&pipe.server, 4, 0, retire_response);
        assert_eq!(
            retired.try_recv().unwrap(),
            WebTransportStreamSendTerminalOutcome::Retired {
                session_id: 4,
                stream_id: 0,
            }
        );
        runtime.process_work(&mut pipe.server);
        assert!(!runtime.stream_sessions.contains_key(&0));
    }

    #[test]
    fn receive_terminal_teardown_preserves_first_session_reason() {
        let mut pipe = pipe();
        let mut runtime = Runtime::new(runtime_limits(8, 8, 8));
        activate_session(&mut runtime, 0);
        own_stream(&mut runtime, 0, 2, WebTransportStreamDirection::Uni, false);
        pipe.client.stream_send(2, b"terminal", true).unwrap();
        pipe.advance().unwrap();
        let terminal = assert_matches!(
            read_stream(&mut runtime, &mut pipe.server, 0, 2, 64),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        let reason = WebTransportSessionCloseReason::Peer {
            error_code: 27,
            message: "first".to_string(),
        };
        assert_eq!(runtime.terminate(0, reason.clone()), Vec::new());
        assert!(runtime
            .terminate(0, WebTransportSessionCloseReason::ProtocolError)
            .is_empty());
        assert!(runtime.receive_terminal_states.is_empty());
        assert_eq!(runtime.receive_terminal_bytes, 0);
        assert_eq!(terminal.data(), b"terminal");
        assert_eq!(terminal.terminal(), WebTransportStreamReceiveTerminal::Fin);

        let (wait_response, mut waited) = oneshot::channel();
        runtime.wait_session_terminal(&pipe.server, 0, wait_response);
        assert_eq!(
            waited.try_recv().unwrap(),
            WebTransportSessionTerminalOutcome::Terminated {
                session_id: 0,
                reason: reason.clone(),
            }
        );
        assert_eq!(
            retire_receive_terminal(&mut runtime, &pipe.server, 0, 2),
            WebTransportStreamReceiveTerminalRetirementOutcome::SessionTerminated {
                session_id: 0,
                stream_id: 2,
            }
        );
        drop(terminal);
        runtime.process_work(&mut pipe.server);
        assert_eq!(runtime.receive_terminal_observations, 0);

        let mut closed_runtime = Runtime::new(runtime_limits(8, 8, 8));
        activate_session(&mut closed_runtime, 4);
        closed_runtime
            .sessions
            .get_mut(&4)
            .unwrap()
            .application_visible = true;
        own_stream(
            &mut closed_runtime,
            4,
            6,
            WebTransportStreamDirection::Uni,
            false,
        );
        let terminal = assert_matches!(
            closed_runtime.latch_receive_terminal(
                4,
                6,
                Bytes::from_static(b"closed"),
                6,
                WebTransportStreamReceiveTerminal::Fin,
            ),
            WebTransportStreamReadOutcome::Terminal(terminal) => terminal
        );
        let events = closed_runtime.clear();
        assert_eq!(events, vec![WebTransportSessionEvent::Terminated {
            session_id: 4,
            reason: WebTransportSessionCloseReason::ConnectionClosed,
        }]);
        assert!(closed_runtime.receive_terminal_states.is_empty());
        assert_eq!(closed_runtime.receive_terminal_observations, 0);
        assert_eq!(closed_runtime.receive_terminal_bytes, 0);
        assert_eq!(terminal.data(), b"closed");
    }

    #[test]
    fn receive_terminal_turnover_reclaims_all_bounded_state() {
        let pipe = pipe();
        let mut limits = runtime_limits(1, 1, 8);
        limits.max_receive_terminal_bytes = 7;
        limits.max_receive_terminal_bytes_per_session = 7;
        let mut runtime = Runtime::new(limits);
        activate_session(&mut runtime, 0);

        for ordinal in 0..4_096 {
            let stream_id = ordinal * 4 + 2;
            own_stream(
                &mut runtime,
                0,
                stream_id,
                WebTransportStreamDirection::Uni,
                false,
            );
            let terminal = assert_matches!(
                runtime.latch_receive_terminal(
                    0,
                    stream_id,
                    Bytes::from_static(b"turnover"),
                    7,
                    WebTransportStreamReceiveTerminal::Fin,
                ),
                WebTransportStreamReadOutcome::Terminal(terminal) => terminal
            );
            drop(terminal);
            assert_eq!(
                retire_receive_terminal(&mut runtime, &pipe.server, 0, stream_id,),
                WebTransportStreamReceiveTerminalRetirementOutcome::Retired {
                    session_id: 0,
                    stream_id,
                }
            );
            runtime.remove_owned_stream(stream_id);
            assert_eq!(runtime.receive_terminal_observations, 0);
            assert!(runtime.receive_terminal_observations_per_session.is_empty());
            assert!(runtime.receive_terminal_states.is_empty());
            assert!(runtime.receive_terminal_states_per_session.is_empty());
            assert_eq!(runtime.receive_terminal_bytes, 0);
            assert!(runtime.receive_terminal_bytes_per_session.is_empty());
            assert!(runtime.readable_waiters.is_empty());
            assert!(runtime.readable_waiters_per_session.is_empty());
        }

        assert_eq!(runtime.receive_terminal_observations_high_water, 1);
        assert_eq!(runtime.receive_terminal_states_high_water, 1);
        assert_eq!(runtime.receive_terminal_bytes_high_water, 7);
        assert_eq!(runtime.receive_terminal_state_saturation_total, 0);
        assert_eq!(runtime.receive_terminal_byte_saturation_total, 0);
        assert_eq!(runtime.receive_terminal_waiter_saturation_total, 0);
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
