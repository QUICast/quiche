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

mod bounded;
mod client;
/// Wrapper for running HTTP/3 connections.
pub mod connection;
mod datagram;
// `DriverHooks` must stay private to prevent users from creating their own
// H3Drivers.
mod hooks;
mod server;
mod streams;
#[cfg(test)]
pub mod test_utils;
#[cfg(test)]
mod tests;
mod webtransport;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use bytes::BufMut as _;
use bytes::Bytes;
use bytes::BytesMut;
use datagram_socket::DgramBuffer;
use datagram_socket::StreamClosureKind;
use foundations::telemetry::log;
use futures::FutureExt;
use futures_util::stream::FuturesUnordered;
use quiche::h3;
use quiche::h3::NameValue as _;
use quiche::h3::WireErrorCode;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::error::TrySendError;
use tokio_stream::StreamExt;
use tokio_util::sync::PollSender;

use self::bounded::BoundedClientConnectOwnership;
use self::bounded::PreparedBoundedProfile;
use self::hooks::DriverHooks;
use self::hooks::InboundHeaders;
use self::streams::FlowCtx;
use self::streams::HaveUpstreamCapacity;
use self::streams::ReceivedDownstreamData;
use self::streams::StreamCtx;
use self::streams::StreamReady;
use self::streams::WaitForDownstreamData;
use self::streams::WaitForStream;
use self::streams::WaitForUpstreamCapacity;
use self::webtransport::AssociatedStream;
use self::webtransport::CapsuleError;
use self::webtransport::CapsuleReadMode;
use self::webtransport::CloseCapsule;
use self::webtransport::Runtime as WebTransportRuntime;
use self::webtransport::RuntimeLimits as WebTransportRuntimeLimits;
use self::webtransport::WebTransportCommand;
use self::webtransport::WT_SESSION_GONE;
use crate::buf_factory::BufFactory;
use crate::http3::settings::Http3Settings;
use crate::http3::H3AuditStats;
use crate::metrics::Metrics;
use crate::quic::HandshakeInfo;
use crate::quic::QuicCommand;
use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

pub use self::bounded::AppliedBoundedWebTransportProfile;
pub use self::bounded::BoundedClientWebTransportController;
pub use self::bounded::BoundedClientWebTransportEvent;
pub use self::bounded::BoundedConnectAdmissionError;
pub use self::bounded::BoundedConnectHeaderError;
pub use self::bounded::BoundedConnectHeaderLimits;
pub use self::bounded::BoundedConnectHeaders;
pub use self::bounded::BoundedConnectResponseError;
pub use self::bounded::BoundedDynamicMemoryComponents;
pub use self::bounded::BoundedFixedPoolCeilings;
pub use self::bounded::BoundedMemoryEnvelope;
pub use self::bounded::BoundedProfileError;
pub use self::bounded::BoundedSelectedWebTransportController;
pub use self::bounded::BoundedSelectedWebTransportLimits;
pub use self::bounded::BoundedSelectedWebTransportSettings;
pub use self::bounded::BoundedServerConnectResponder;
pub use self::bounded::BoundedServerWebTransportController;
pub use self::bounded::BoundedServerWebTransportEvent;
pub use self::bounded::BoundedWebTransportDatagrams;
pub use self::bounded::BoundedWebTransportEndpoint;
pub use self::bounded::BoundedWebTransportHandshakeProfile;
pub use self::bounded::BoundedWebTransportIoSettings;
pub use self::bounded::BoundedWebTransportQuicSettings;
pub use self::bounded::BoundedWebTransportRevision;
pub use self::bounded::H3ConnectionMode;
pub use self::client::ClientEventStream;
pub use self::client::ClientH3Command;
pub use self::client::ClientH3Controller;
pub use self::client::ClientH3Driver;
pub use self::client::ClientH3Event;
pub use self::client::ClientRequestSender;
pub use self::client::NewClientRequest;
pub use self::server::IsInEarlyData;
pub use self::server::RawPriorityValue;
pub use self::server::ServerEventStream;
pub use self::server::ServerH3Command;
pub use self::server::ServerH3Controller;
pub use self::server::ServerH3Driver;
pub use self::server::ServerH3Event;
pub use self::webtransport::webtransport_error_from_http3;
pub use self::webtransport::webtransport_error_to_http3;
pub use self::webtransport::WebTransportController;
pub use self::webtransport::WebTransportDatagramError;
pub use self::webtransport::WebTransportDatagramReadOutcome;
pub use self::webtransport::WebTransportDatagramReadyOutcome;
pub use self::webtransport::WebTransportDatagramSendOperation;
pub use self::webtransport::WebTransportDatagramSendOutcome;
pub use self::webtransport::WebTransportDatagramStats;
pub use self::webtransport::WebTransportOpenStreamOutcome;
pub use self::webtransport::WebTransportRetentionStats;
pub use self::webtransport::WebTransportSelectionError;
pub use self::webtransport::WebTransportSessionCloseError;
pub use self::webtransport::WebTransportSessionCloseReason;
pub use self::webtransport::WebTransportSessionEvent;
pub use self::webtransport::WebTransportSessionTerminalOutcome;
pub use self::webtransport::WebTransportStreamControlOutcome;
pub use self::webtransport::WebTransportStreamReadOutcome;
pub use self::webtransport::WebTransportStreamReadyOutcome;
pub use self::webtransport::WebTransportStreamReceiveTerminal;
pub use self::webtransport::WebTransportStreamReceiveTerminalRead;
pub use self::webtransport::WebTransportStreamReceiveTerminalRetirementOutcome;
pub use self::webtransport::WebTransportStreamSendTerminalOutcome;
pub use self::webtransport::WebTransportStreamWriteLease;
pub use self::webtransport::WebTransportStreamWriteLeaseLimit;
pub use self::webtransport::WebTransportStreamWriteLeaseOperation;
pub use self::webtransport::WebTransportStreamWriteLeaseOutcome;
pub use self::webtransport::WebTransportStreamWriteLeaseProgress;
pub use self::webtransport::WebTransportStreamWriteOperation;
pub use self::webtransport::WebTransportStreamWriteOutcome;

/// Direction of a WebTransport stream carried over HTTP/3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportStreamDirection {
    /// A bidirectional WebTransport stream.
    Bidi,
    /// A unidirectional WebTransport stream.
    Uni,
}

/// Rare WebTransport/H3 handshake diagnostic event kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportDiagnosticKind {
    /// A WebTransport CONNECT stream was registered as a session.
    ConnectSessionRegistered,
    /// H3 response headers were successfully handed to QUIC for flushing.
    H3HeadersFlushedToQuic,
    /// A candidate WebTransport stream ended before a full prefix was read.
    StreamEndedBeforePrefix,
    /// A candidate stream prefix did not match a registered WebTransport
    /// session.
    StreamPrefixMismatch,
    /// A WebTransport stream prefix was accepted and classified.
    StreamPrefixAccepted,
}

/// Diagnostic details for rare WebTransport/H3 handshake events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebTransportDiagnostic {
    /// Diagnostic event kind.
    pub kind: WebTransportDiagnosticKind,
    /// QUIC stream ID associated with the diagnostic, when applicable.
    pub stream_id: Option<u64>,
    /// WebTransport session ID associated with the diagnostic, when known.
    pub session_id: Option<u64>,
    /// WebTransport stream direction, when known.
    pub direction: Option<WebTransportStreamDirection>,
    /// Byte count associated with the diagnostic, when applicable.
    pub bytes: Option<usize>,
    /// FIN flag associated with the diagnostic, when applicable.
    pub fin: Option<bool>,
    /// Whether flushed H3 headers were initial headers, when applicable.
    pub initial_headers: Option<bool>,
    /// Number of flushed H3 headers, when applicable.
    pub header_count: Option<usize>,
    /// WebTransport stream type parsed from the prefix, when known.
    pub stream_type: Option<u64>,
    /// Expected WebTransport stream type for the stream direction, when known.
    pub expected_stream_type: Option<u64>,
}

impl WebTransportDiagnostic {
    pub(crate) const fn new(kind: WebTransportDiagnosticKind) -> Self {
        Self {
            kind,
            stream_id: None,
            session_id: None,
            direction: None,
            bytes: None,
            fin: None,
            initial_headers: None,
            header_count: None,
            stream_type: None,
            expected_stream_type: None,
        }
    }
}

// The default priority for HTTP/3 responses if the application didn't provide
// one.
const DEFAULT_PRIO: h3::Priority = h3::Priority::new(3, true);

// For a stream use a channel with 16 entries, which works out to 16 * 64KB =
// 1MB of max buffered data.
#[cfg(not(any(test, debug_assertions)))]
const STREAM_CAPACITY: usize = 16;
#[cfg(any(test, debug_assertions))]
const STREAM_CAPACITY: usize = 1; // Set to 1 to stress write_pending under test conditions

// For *all* flows use a shared channel with 2048 entries, which works out
// to 3MB of max buffered data at 1500 bytes per datagram.
const FLOW_CAPACITY: usize = 2048;

// Floor for the lazily-allocated body receive buffer. The buffer is sized to
// the amount currently readable on the stream (see [`process_h3_data`]), but we
// never allocate below this floor, for two reasons:
//
// - A `Limit<BytesMut>` with a zero limit reports no remaining capacity and
//   would make `recv_body_buf` a no-op.
// - Sizing strictly to the readable length defeats allocation amortization: a
//   body that trickles in a few bytes at a time (e.g. one byte per read) would
//   reallocate the buffer on every read. Allocating at least this many bytes
//   lets a single allocation absorb many small reads (each `split()` off)
//   before it is exhausted and reallocated.
const MIN_BODY_RECV_BUF_SIZE: usize = 1024;

/// Computes the capacity to use for the body receive buffer given the number of
/// bytes currently readable on the stream.
///
/// The result is clamped to `[MIN_BODY_RECV_BUF_SIZE, MAX_BUF_SIZE]`: reads
/// below the floor still allocate the floor (so a trickle of tiny reads reuses
/// one allocation instead of reallocating each time), while a single
/// (potentially adversarial) read never allocates more than `MAX_BUF_SIZE`.
fn body_recv_buf_size(readable: usize) -> usize {
    readable.clamp(MIN_BODY_RECV_BUF_SIZE, BufFactory::MAX_BUF_SIZE)
}

async fn receive_webtransport_command(
    recv: &mut Option<mpsc::Receiver<WebTransportCommand>>,
) -> Option<WebTransportCommand> {
    match recv {
        Some(recv) => recv.recv().await,
        None => std::future::pending().await,
    }
}

async fn wait_for_webtransport_datagram_deadline(
    deadline: Option<std::time::Instant>,
) {
    match deadline {
        Some(deadline) =>
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline))
                .await,
        None => std::future::pending().await,
    }
}

fn response_status(headers: &[h3::Header]) -> Option<u16> {
    let value = headers
        .iter()
        .find(|header| header.name() == b":status")?
        .value();
    if value.len() != 3 || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

fn validate_bounded_outbound_frame(
    frame: &OutboundFrame, limits: BoundedConnectHeaderLimits,
) -> H3ConnectionResult<()> {
    let allowed = match frame {
        OutboundFrame::Headers(headers, priority) =>
            priority.is_none() &&
                limits.validate(headers).is_ok() &&
                response_status(headers).is_some_and(|status| status >= 200),
        OutboundFrame::Body(data, fin) => data.is_empty() && *fin,
        OutboundFrame::WebTransportClose { .. } => true,
        OutboundFrame::Datagram(..) |
        OutboundFrame::Trailers(..) |
        OutboundFrame::PeerStreamError |
        OutboundFrame::FlowShutdown { .. } => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(H3ConnectionError::BoundedProfile(
            BoundedProfileError::ForbiddenOperation("legacy OutboundFrame"),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebTransportRequirements {
    Pending,
    Met(h3::WebTransportHandshakeProfile),
    Failed,
}

fn webtransport_requirements(
    conn: &h3::Connection, qconn: &QuicheConnection,
) -> WebTransportRequirements {
    if conn.peer_settings_raw().is_none() {
        return WebTransportRequirements::Pending;
    }

    let Some(profile) = conn.webtransport_handshake_profile_by_peer() else {
        return WebTransportRequirements::Failed;
    };
    let endpoint_settings_met = if qconn.is_server() {
        true
    } else {
        conn.extended_connect_enabled_by_peer()
    };
    let transport_met = qconn.dgram_enabled() &&
        conn.webtransport_dgram_enabled_by_peer(qconn) &&
        qconn.reset_stream_at_enabled();

    if endpoint_settings_met && transport_met {
        WebTransportRequirements::Met(profile)
    } else {
        WebTransportRequirements::Failed
    }
}

fn webtransport_connect_requirements(
    conn: &h3::Connection, qconn: &QuicheConnection, headers: &[h3::Header],
) -> WebTransportRequirements {
    match webtransport_requirements(conn, qconn) {
        WebTransportRequirements::Met(profile)
            if webtransport::is_connect_for_profile(headers, profile) =>
            WebTransportRequirements::Met(profile),

        WebTransportRequirements::Met(_) => WebTransportRequirements::Failed,
        other => other,
    }
}

/// Used by a local task to send [`OutboundFrame`]s to a peer on the
/// stream or flow associated with this channel.
pub type OutboundFrameSender = PollSender<OutboundFrame>;

/// Used internally to receive [`OutboundFrame`]s which should be sent to a peer
/// on the stream or flow associated with this channel.
type OutboundFrameStream = mpsc::Receiver<OutboundFrame>;

/// Used internally to send [`InboundFrame`]s (data) from the peer to a local
/// task on the stream or flow associated with this channel.
type InboundFrameSender = PollSender<InboundFrame>;

/// Used by a local task to receive [`InboundFrame`]s (data) on the stream or
/// flow associated with this channel.
pub type InboundFrameStream = mpsc::Receiver<InboundFrame>;

/// The error type used internally in [H3Driver].
///
/// Note that [`ApplicationOverQuic`] errors are not exposed to users at this
/// time. The type is public to document the failure modes in [H3Driver].
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum H3ConnectionError {
    /// The controller task was shut down and is no longer listening.
    ControllerWentAway,
    /// Other error at the connection, but not stream level.
    H3(h3::Error),
    /// Received data for a stream that was closed or never opened.
    NonexistentStream,
    /// The server's post-accept timeout was hit.
    /// The timeout can be configured in [`Http3Settings`].
    PostAcceptTimeout,
    /// The bounded application event lane was saturated.
    EventQueueOverloaded,
    /// The live connection did not match its immutable bounded profile.
    BoundedProfile(BoundedProfileError),
}

impl From<h3::Error> for H3ConnectionError {
    fn from(err: h3::Error) -> Self {
        H3ConnectionError::H3(err)
    }
}

impl From<quiche::Error> for H3ConnectionError {
    fn from(err: quiche::Error) -> Self {
        H3ConnectionError::H3(h3::Error::TransportError(err))
    }
}

impl Error for H3ConnectionError {}

impl fmt::Display for H3ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s: &dyn fmt::Display = match self {
            Self::ControllerWentAway => &"controller went away",
            Self::H3(e) => e,
            Self::NonexistentStream => &"nonexistent stream",
            Self::PostAcceptTimeout => &"post accept timeout hit",
            Self::EventQueueOverloaded => &"H3 event queue overloaded",
            Self::BoundedProfile(error) => error,
        };

        write!(f, "H3ConnectionError: {s}")
    }
}

type H3ConnectionResult<T> = Result<T, H3ConnectionError>;

/// Monotonic accounting for the bounded HTTP/3 application event lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H3EventQueueStats {
    /// Configured maximum queued event count.
    pub capacity: usize,
    /// Events admitted since driver construction.
    pub admitted_total: u64,
    /// Events rejected because the lane was full.
    pub overload_total: u64,
    /// Events rejected because the receiver was closed.
    pub receiver_closed_total: u64,
    /// Whether saturation has latched terminal connection overload.
    pub overloaded: bool,
}

struct H3EventLaneState {
    capacity: usize,
    admitted_total: AtomicU64,
    overload_total: AtomicU64,
    receiver_closed_total: AtomicU64,
    overloaded: AtomicBool,
}

impl H3EventLaneState {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            admitted_total: AtomicU64::new(0),
            overload_total: AtomicU64::new(0),
            receiver_closed_total: AtomicU64::new(0),
            overloaded: AtomicBool::new(false),
        }
    }

    fn stats(&self) -> H3EventQueueStats {
        H3EventQueueStats {
            capacity: self.capacity,
            admitted_total: self.admitted_total.load(Ordering::Relaxed),
            overload_total: self.overload_total.load(Ordering::Relaxed),
            receiver_closed_total: self
                .receiver_closed_total
                .load(Ordering::Relaxed),
            overloaded: self.overloaded.load(Ordering::Acquire),
        }
    }
}

struct H3EventSender<E> {
    sender: mpsc::Sender<E>,
    state: Arc<H3EventLaneState>,
    bounded_client_connect_ownership: Option<Arc<BoundedClientConnectOwnership>>,
}

impl<E> Clone for H3EventSender<E> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
            bounded_client_connect_ownership: self
                .bounded_client_connect_ownership
                .as_ref()
                .map(Arc::clone),
        }
    }
}

impl<E> H3EventSender<E> {
    fn send(&self, event: E) -> H3ConnectionResult<()> {
        match self.sender.try_send(event) {
            Ok(()) => {
                self.state.admitted_total.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.state.overload_total.fetch_add(1, Ordering::Relaxed);
                self.state.overloaded.store(true, Ordering::Release);
                Err(H3ConnectionError::EventQueueOverloaded)
            },
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.state
                    .receiver_closed_total
                    .fetch_add(1, Ordering::Relaxed);
                Err(H3ConnectionError::ControllerWentAway)
            },
        }
    }

    async fn closed(&self) {
        self.sender.closed().await;
    }

    fn overloaded(&self) -> bool {
        self.state.overloaded.load(Ordering::Acquire)
    }

    fn observe_webtransport_event(&self, event: &WebTransportSessionEvent) {
        if let Some(ownership) = &self.bounded_client_connect_ownership {
            ownership.observe_event(event);
        }
    }
}

/// HTTP/3 headers that were received on a stream.
///
/// `recv` is used to read the message body, while `send` is used to transmit
/// data back to the peer.
pub struct IncomingH3Headers {
    /// Stream ID of the frame.
    pub stream_id: u64,
    /// The actual [`h3::Header`]s which were received.
    pub headers: Vec<h3::Header>,
    /// An [`OutboundFrameSender`] for streaming body data to the peer. For
    /// [ClientH3Driver], note that the request body can also be passed a
    /// cloned sender via [`NewClientRequest`].
    pub send: OutboundFrameSender,
    /// An [`InboundFrameStream`] of body data received from the peer.
    pub recv: InboundFrameStream,
    /// Whether there is a body associated with the incoming headers.
    pub read_fin: bool,
    /// Handle to the [`H3AuditStats`] for the message's stream.
    pub h3_audit_stats: Arc<H3AuditStats>,
}

impl fmt::Debug for IncomingH3Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingH3Headers")
            .field("stream_id", &self.stream_id)
            .field("headers", &self.headers)
            .field("read_fin", &self.read_fin)
            .field("h3_audit_stats", &self.h3_audit_stats)
            .finish()
    }
}

/// [`H3Event`]s are produced by an [H3Driver] to describe HTTP/3 state updates.
///
/// Both [ServerH3Driver] and [ClientH3Driver] may extend this enum with
/// endpoint-specific variants. The events must be consumed by users of the
/// drivers, like a higher-level `Server` or `Client` controller.
#[derive(Debug)]
pub enum H3Event {
    /// A SETTINGS frame was received.
    IncomingSettings {
        /// Raw HTTP/3 setting pairs, in the order received from the peer.
        settings: Vec<(u64, u64)>,
    },

    /// A HEADERS frame was received on the given stream. This is either a
    /// request or a response depending on the perspective of the [`H3Event`]
    /// receiver.
    IncomingHeaders(IncomingH3Headers),

    /// A DATAGRAM flow was created and associated with the given `flow_id`.
    /// This event is fired before a HEADERS event for CONNECT[-UDP] requests.
    NewFlow {
        /// Flow ID of the new flow.
        flow_id: u64,
        /// An [`OutboundFrameSender`] for transmitting datagrams to the peer.
        send: OutboundFrameSender,
        /// An [`InboundFrameStream`] for receiving datagrams from the peer.
        recv: InboundFrameStream,
    },
    /// A RST_STREAM frame was seen on the given `stream_id`. The user of the
    /// driver should clean up any state allocated for this stream.
    ResetStream { stream_id: u64 },
    /// The connection has irrecoverably errored and is shutting down.
    ConnectionError(h3::Error),
    /// The connection has been shutdown, optionally due to an
    /// [`H3ConnectionError`].
    ConnectionShutdown(Option<H3ConnectionError>),
    /// Body data has been received over a stream.
    BodyBytesReceived {
        /// Stream ID of the body data.
        stream_id: u64,
        /// Number of bytes received.
        num_bytes: u64,
        /// Whether the stream is finished and won't yield any more data.
        fin: bool,
    },
    /// Raw QUIC stream data was received on a stream that the driver is not
    /// treating as HTTP/3.
    RawStreamData {
        /// QUIC stream ID carrying raw bytes.
        stream_id: u64,
        /// Bytes read from the QUIC stream.
        data: Bytes,
        /// Whether the stream is finished and won't yield any more data.
        fin: bool,
    },
    /// WebTransport stream data received after a successful CONNECT session.
    WebTransportStreamData {
        /// CONNECT request stream ID that identifies the WebTransport session.
        session_id: u64,
        /// QUIC stream ID carrying WebTransport data.
        stream_id: u64,
        /// Whether this is a bidirectional or unidirectional WT stream.
        direction: WebTransportStreamDirection,
        /// WebTransport payload bytes after the stream prefix.
        data: Bytes,
        /// Whether the stream is finished and won't yield any more data.
        fin: bool,
    },
    /// Rare WebTransport/H3 handshake diagnostic.
    WebTransportDiagnostic(WebTransportDiagnostic),
    /// A native WebTransport session or associated-stream lifecycle update.
    WebTransportSession(WebTransportSessionEvent),
    /// The stream has been closed. This is used to signal stream closures that
    /// don't result from RST_STREAM frames, unlike the
    /// [`H3Event::ResetStream`] variant.
    StreamClosed { stream_id: u64 },
    /// A GOAWAY frame was received from the peer containing `id`,
    /// as described in
    /// <https://datatracker.ietf.org/doc/html/rfc9114#section-5.2>.
    GoAway { id: u64 },
}

impl H3Event {
    /// Generates an event from an applicable [`H3ConnectionError`].
    fn from_error(err: &H3ConnectionError) -> Option<Self> {
        Some(match err {
            H3ConnectionError::H3(e) => Self::ConnectionError(*e),
            H3ConnectionError::PostAcceptTimeout => Self::ConnectionShutdown(
                Some(H3ConnectionError::PostAcceptTimeout),
            ),
            _ => return None,
        })
    }
}

/// An [`OutboundFrame`] is a data frame that should be sent from a local task
/// to a peer over a [`quiche::h3::Connection`].
///
/// This is used, for example, to send response body data to a peer, or proxied
/// UDP datagrams.
#[derive(Debug)]
pub enum OutboundFrame {
    /// Response headers to be sent to the peer, with optional priority.
    Headers(Vec<h3::Header>, Option<quiche::h3::Priority>),
    /// Response body/CONNECT downstream data plus FIN flag.
    Body(Bytes, bool),
    /// CONNECT-UDP (DATAGRAM) downstream data plus flow ID.
    Datagram(DgramBuffer, u64),
    /// Close the stream with a trailers, with optional priority.
    Trailers(Vec<h3::Header>, Option<quiche::h3::Priority>),
    /// An error encountered when serving the request. Stream should be closed.
    PeerStreamError,
    /// DATAGRAM flow explicitly closed.
    FlowShutdown { flow_id: u64, stream_id: u64 },
    /// Driver-owned WT_CLOSE_SESSION capsule plus CONNECT-stream FIN.
    #[doc(hidden)]
    WebTransportClose {
        /// Encoded capsule bytes not yet accepted by H3.
        capsule: Bytes,
    },
}

/// An [`InboundFrame`] is a data frame that was received from the peer over a
/// [`quiche::h3::Connection`]. This is used by peers to send body or datagrams
/// to the local task.
#[derive(Debug)]
pub enum InboundFrame {
    /// Request body/CONNECT upstream data plus FIN flag.
    Body(BytesMut, bool),
    /// CONNECT-UDP (DATAGRAM) upstream data.
    Datagram(DgramBuffer),
}

/// A ready-made [`ApplicationOverQuic`] which can handle HTTP/3 and MASQUE.
/// Depending on the `DriverHooks` in use, it powers either a client or a
/// server.
///
/// Use the [ClientH3Driver] and [ServerH3Driver] aliases to access the
/// respective driver types. The driver is passed into an I/O loop and
/// communicates with the driver's user (e.g., an HTTP client or a server) via
/// its associated [H3Controller]. The controller allows the application to both
/// listen for [`H3Event`]s of note and send [`H3Command`]s into the I/O loop.
pub struct H3Driver<H: DriverHooks> {
    /// Configuration used to initialize `conn`. Created from [`Http3Settings`]
    /// in the constructor.
    h3_config: h3::Config,
    /// Optional MCQUIC channel ID used for HTTP/3 DATAGRAM unicast fallback.
    multicast_datagram_channel_id: Option<Vec<u8>>,
    /// The underlying HTTP/3 connection. Initialized in
    /// `ApplicationOverQuic::on_conn_established`.
    conn: Option<h3::Connection>,
    /// State required by the client/server hooks.
    hooks: H,
    /// Sends [`H3Event`]s to the [H3Controller] paired with this driver.
    h3_event_sender: H3EventSender<H::Event>,
    /// Receives [`H3Command`]s from the [H3Controller] paired with this driver.
    cmd_recv: mpsc::Receiver<H::Command>,
    /// A sender that feeds back into `cmd_recv`. Used by hooks that need to
    /// re-queue commands (e.g. retrying blocked requests) without access to
    /// the [H3Controller]'s copy of the sender.
    cmd_sender: mpsc::Sender<H::Command>,

    /// A map of stream IDs to their [StreamCtx]. This is mainly used to
    /// retrieve the internal Tokio channels associated with the stream.
    stream_map: BTreeMap<u64, StreamCtx>,
    /// A map of flow IDs to their [FlowCtx]. This is mainly used to retrieve
    /// the internal Tokio channels associated with the flow.
    flow_map: BTreeMap<u64, FlowCtx>,
    /// Set of [`WaitForStream`] futures. A stream is added to this set if
    /// we need to send to it and its channel is at capacity, or if we need
    /// data from its channel and the channel is empty.
    waiting_streams: FuturesUnordered<WaitForStream>,

    /// Receives [`OutboundFrame`]s from all datagram flows on the connection.
    dgram_recv: OutboundFrameStream,
    /// Keeps the datagram channel open such that datagram flows can be created.
    dgram_send: OutboundFrameSender,
    /// A buffer to receive H3 body data from quiche. Lazily allocated on the
    /// first body read and released once no streams remain, so idle
    /// connections hold no receive buffer. We `split()` off filled parts until
    /// we need to reallocate.
    body_recv_buf: Option<bytes::buf::Limit<BytesMut>>,
    /// Streams that have been claimed as raw QUIC streams rather than HTTP/3.
    raw_streams: BTreeSet<u64>,
    /// Scratch space for receiving raw QUIC stream data.
    raw_stream_recv_buf: Vec<u8>,
    /// Immutable opt-in bounded profile verified at establishment.
    bounded_profile: Option<PreparedBoundedProfile>,
    /// Native draft-16 session owner, present only when explicitly enabled.
    webtransport: Option<WebTransportRuntime>,
    /// Bounded native WebTransport selected-I/O command receiver.
    webtransport_cmd_recv: Option<mpsc::Receiver<WebTransportCommand>>,
    /// Rotates priority between selected-I/O commands and opening prefixes.
    webtransport_command_turn: bool,
    /// Rotates native Datagram work across ingress, legacy release, and expiry.
    webtransport_datagram_turn: u8,
    /// CONNECT streams whose optimistic capsule bytes await final admission.
    deferred_webtransport_capsule_reads: BTreeSet<u64>,
    /// Deferred CONNECT FINs that arrived before draft-version SETTINGS.
    deferred_webtransport_fins: BTreeSet<u64>,

    /// The maximum HTTP/3 stream ID seen on this connection.
    max_stream_seen: u64,

    /// Tracks whether we have forwarded the HTTP/3 SETTINGS frame
    /// to the [H3Controller] once.
    settings_received_and_forwarded: bool,
    /// Tracks whether the H3 event receiver has been dropped.
    /// Used to avoid busy-looping on `h3_event_sender.closed()`.
    h3_event_receiver_dropped: bool,
}

impl<H: DriverHooks> H3Driver<H> {
    /// Builds a new [H3Driver] and an associated [H3Controller].
    ///
    /// The driver should then be passed to
    /// [`InitialQuicConnection`](crate::InitialQuicConnection)'s `start`
    /// method.
    pub fn new(http3_settings: Http3Settings) -> (Self, H3Controller<H>) {
        Self::new_inner(http3_settings, None)
    }

    /// Returns the immutable operating mode selected at construction.
    pub fn mode(&self) -> H3ConnectionMode {
        if self.bounded_profile.is_some() {
            H3ConnectionMode::BoundedSelectedWebTransport
        } else {
            H3ConnectionMode::GeneralH3
        }
    }

    fn new_inner(
        http3_settings: Http3Settings,
        bounded_profile: Option<PreparedBoundedProfile>,
    ) -> (Self, H3Controller<H>) {
        let bounded = bounded_profile.is_some();
        let mut h3_config = (&http3_settings).into();
        if let Some(profile) = bounded_profile.as_ref() {
            profile.configure_h3(&mut h3_config);
        }
        let dgram_capacity = if bounded { 1 } else { FLOW_CAPACITY };
        let (dgram_send, dgram_recv) = mpsc::channel(dgram_capacity);
        let command_capacity = http3_settings.command_capacity.max(1);
        let event_capacity = http3_settings.event_capacity.max(1);
        let (cmd_sender, cmd_recv) = mpsc::channel(command_capacity);
        let (event_sender, h3_event_recv) = mpsc::channel(event_capacity);
        let h3_event_state = Arc::new(H3EventLaneState::new(event_capacity));
        let bounded_client_connect_ownership = bounded_profile
            .as_ref()
            .and_then(|profile| profile.client_connect_ownership.as_ref())
            .map(Arc::clone);
        let h3_event_sender = H3EventSender {
            sender: event_sender,
            state: Arc::clone(&h3_event_state),
            bounded_client_connect_ownership,
        };
        let multicast_datagram_channel_id =
            http3_settings.multicast_datagram_channel_id.clone();
        let (webtransport, webtransport_cmd_recv, webtransport_controller) =
            if http3_settings.enable_webtransport {
                let (sender, recv) = mpsc::channel(
                    http3_settings.webtransport_command_capacity.max(1),
                );
                let write_lease_accounting =
                    Arc::new(webtransport::WriteLeaseAccounting::new(
                        http3_settings.webtransport_command_capacity,
                        http3_settings
                            .webtransport_max_stream_write_lease_retained_bytes,
                    ));
                let cancellation_pending =
                    Arc::new(std::sync::atomic::AtomicBool::new(false));
                (
                    Some(WebTransportRuntime::new_with_write_lease_accounting(
                        WebTransportRuntimeLimits {
                            max_pending_streams: http3_settings
                                .webtransport_max_pending_streams,
                            max_pending_streams_per_session: http3_settings
                                .webtransport_max_pending_streams_per_session,
                            max_active_streams: http3_settings
                                .webtransport_max_active_streams,
                            max_active_streams_per_session: http3_settings
                                .webtransport_max_active_streams_per_session,
                            max_stream_waiters: http3_settings
                                .webtransport_max_stream_waiters,
                            max_session_terminal_waiters: http3_settings
                                .webtransport_max_session_terminal_waiters,
                            max_session_terminal_waiters_per_session:
                                http3_settings
                                    .webtransport_max_session_terminal_waiters_per_session,
                            max_send_terminal_waiters: http3_settings
                                .webtransport_max_send_terminal_waiters,
                            max_send_terminal_waiters_per_session: http3_settings
                                .webtransport_max_send_terminal_waiters_per_session,
                            max_receive_terminal_states: http3_settings
                                .webtransport_max_receive_terminal_states,
                            max_receive_terminal_states_per_session:
                                http3_settings
                                    .webtransport_max_receive_terminal_states_per_session,
                            max_receive_terminal_waiters: http3_settings
                                .webtransport_max_receive_terminal_waiters,
                            max_receive_terminal_waiters_per_session:
                                http3_settings
                                    .webtransport_max_receive_terminal_waiters_per_session,
                            max_receive_terminal_bytes: http3_settings
                                .webtransport_max_receive_terminal_bytes,
                            max_receive_terminal_bytes_per_session:
                                http3_settings
                                    .webtransport_max_receive_terminal_bytes_per_session,
                            max_datagram_waiters: http3_settings
                                .webtransport_max_datagram_waiters,
                            max_pending_datagrams: http3_settings
                                .webtransport_max_pending_datagrams,
                            max_pending_datagrams_per_session: http3_settings
                                .webtransport_max_pending_datagrams_per_session,
                            max_pending_datagram_bytes: http3_settings
                                .webtransport_max_pending_datagram_bytes,
                            max_pending_datagram_bytes_per_session:
                                http3_settings
                                    .webtransport_max_pending_datagram_bytes_per_session,
                            max_pending_datagram_allocation_bytes:
                                http3_settings
                                    .webtransport_max_pending_datagram_allocation_bytes,
                            max_pending_datagram_allocation_bytes_per_session:
                                http3_settings
                                    .webtransport_max_pending_datagram_allocation_bytes_per_session,
                            max_pending_datagram_age: http3_settings
                                .webtransport_max_pending_datagram_age,
                            max_datagram_prefixed_allocation_bytes:
                                http3_settings
                                    .webtransport_max_datagram_prefixed_allocation_bytes,
                            command_capacity: http3_settings
                                .webtransport_command_capacity
                                .max(1),
                            max_command_payload_bytes: http3_settings
                                .webtransport_max_stream_write_bytes
                                .max(
                                    http3_settings
                                        .webtransport_max_stream_write_lease_retained_bytes,
                                )
                                .max(
                                    http3_settings
                                        .webtransport_max_datagram_send_allocation_bytes,
                                )
                                .max(webtransport::MAX_CLOSE_MESSAGE_LEN),
                            max_write_lease_retained_bytes_per_lease:
                                http3_settings
                                    .webtransport_max_stream_write_lease_retained_bytes,
                            max_session_work_per_callback: http3_settings
                                .webtransport_max_session_work_per_callback,
                        },
                        Arc::clone(&write_lease_accounting),
                        Arc::clone(&cancellation_pending),
                    )),
                    Some(recv),
                    Some(WebTransportController::new(
                        sender,
                        webtransport::WebTransportControllerLimits {
                            max_stream_write_bytes: http3_settings
                                .webtransport_max_stream_write_bytes,
                            max_stream_write_lease_retained_bytes: http3_settings
                                .webtransport_max_stream_write_lease_retained_bytes,
                            max_stream_write_lease_owner_bytes: http3_settings
                                .webtransport_max_stream_write_lease_owner_bytes,
                            max_stream_read_bytes: http3_settings
                                .webtransport_max_stream_read_bytes,
                            max_datagram_send_allocation_bytes: http3_settings
                                .webtransport_max_datagram_send_allocation_bytes,
                            max_datagram_prefixed_allocation_bytes: http3_settings
                                .webtransport_max_datagram_prefixed_allocation_bytes,
                        },
                        write_lease_accounting,
                        cancellation_pending,
                    )),
                )
            } else {
                (None, None, None)
            };

        (
            H3Driver {
                h3_config,
                multicast_datagram_channel_id,
                conn: None,
                hooks: H::new(&http3_settings),
                h3_event_sender,
                cmd_recv,
                cmd_sender: cmd_sender.clone(),

                stream_map: BTreeMap::new(),
                flow_map: BTreeMap::new(),

                dgram_recv,
                dgram_send: PollSender::new(dgram_send),
                max_stream_seen: 0,
                body_recv_buf: None,
                raw_streams: BTreeSet::new(),
                raw_stream_recv_buf: if bounded {
                    Vec::new()
                } else {
                    vec![0u8; BufFactory::MAX_BUF_SIZE]
                },
                bounded_profile,
                webtransport,
                webtransport_cmd_recv,
                webtransport_command_turn: true,
                webtransport_datagram_turn: 0,
                deferred_webtransport_capsule_reads: BTreeSet::new(),
                deferred_webtransport_fins: BTreeSet::new(),

                waiting_streams: FuturesUnordered::new(),

                settings_received_and_forwarded: false,
                h3_event_receiver_dropped: false,
            },
            H3Controller {
                cmd_sender,
                h3_event_recv: Some(h3_event_recv),
                h3_event_state,
                webtransport: webtransport_controller,
            },
        )
    }

    /// Returns a sender that feeds back into this driver's own `cmd_recv`.
    ///
    /// Hooks that need to re-queue commands (e.g. retrying a request that
    /// was temporarily blocked) can use this sender without needing access
    /// to the paired [H3Controller].
    pub(crate) fn self_cmd_sender(&self) -> &mpsc::Sender<H::Command> {
        &self.cmd_sender
    }

    pub(crate) fn bounded_connect_header_limits(
        &self,
    ) -> Option<BoundedConnectHeaderLimits> {
        self.bounded_profile
            .as_ref()
            .map(|profile| profile.applied.connect_headers)
    }

    pub(crate) fn is_webtransport_connect_candidate(
        &self, headers: &[h3::Header],
    ) -> bool {
        if webtransport::is_connect(headers) {
            return true;
        }

        self.bounded_profile.as_ref().is_some_and(|profile| {
            profile.applied.handshake_profile ==
                BoundedWebTransportHandshakeProfile::BrowserInteroperable &&
                webtransport::is_legacy_connect(headers)
        })
    }

    pub(crate) fn stream_channel_capacity(&self) -> usize {
        if self.bounded_profile.is_some() {
            1
        } else {
            STREAM_CAPACITY
        }
    }

    fn ensure_event_lane_available(&self) -> H3ConnectionResult<()> {
        if self.h3_event_sender.overloaded() {
            return Err(H3ConnectionError::EventQueueOverloaded);
        }
        Ok(())
    }

    /// Retrieve the [FlowCtx] associated with the given `flow_id`. If no
    /// context is found, a new one will be created.
    fn get_or_insert_flow(
        &mut self, flow_id: u64,
    ) -> H3ConnectionResult<&mut FlowCtx> {
        use std::collections::btree_map::Entry;
        Ok(match self.flow_map.entry(flow_id) {
            Entry::Vacant(e) => {
                // This is a datagram for a new flow we haven't seen before
                let (flow, recv) = FlowCtx::new(FLOW_CAPACITY);
                let flow_req = H3Event::NewFlow {
                    flow_id,
                    recv,
                    send: self.dgram_send.clone(),
                };
                self.h3_event_sender.send(flow_req.into())?;
                e.insert(flow)
            },
            Entry::Occupied(e) => e.into_mut(),
        })
    }

    /// Adds a [StreamCtx] to the stream map with the given `stream_id`.
    fn insert_stream(&mut self, stream_id: u64, ctx: StreamCtx) {
        self.stream_map.insert(stream_id, ctx);
        self.max_stream_seen = self.max_stream_seen.max(stream_id);
    }

    /// Fetches body chunks from the [`quiche::h3::Connection`] and forwards
    /// them to the stream's associated [`InboundFrameStream`].
    fn process_h3_data(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        let mode = self
            .webtransport
            .as_ref()
            .map_or(CapsuleReadMode::Regular, |runtime| {
                runtime.capsule_read_mode(stream_id)
            });
        match mode {
            CapsuleReadMode::Regular =>
                self.process_regular_h3_data(qconn, stream_id),
            CapsuleReadMode::Defer => {
                self.deferred_webtransport_capsule_reads.insert(stream_id);
                Ok(())
            },
            CapsuleReadMode::Parse =>
                self.process_webtransport_capsules(qconn, stream_id),
            CapsuleReadMode::Discard =>
                self.discard_webtransport_capsules(qconn, stream_id),
        }
    }

    fn process_deferred_webtransport_capsules(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        let stream_ids: Vec<_> = self
            .deferred_webtransport_capsule_reads
            .iter()
            .copied()
            .collect();
        for stream_id in stream_ids {
            let mode = self
                .webtransport
                .as_ref()
                .map_or(CapsuleReadMode::Discard, |runtime| {
                    runtime.capsule_read_mode(stream_id)
                });
            match mode {
                CapsuleReadMode::Defer => continue,
                CapsuleReadMode::Parse => {
                    self.deferred_webtransport_capsule_reads.remove(&stream_id);
                    self.process_webtransport_capsules(qconn, stream_id)?;
                    if self.deferred_webtransport_fins.remove(&stream_id) &&
                        self.stream_map.contains_key(&stream_id)
                    {
                        self.process_h3_fin(qconn, stream_id)?;
                    }
                },
                CapsuleReadMode::Regular | CapsuleReadMode::Discard => {
                    self.deferred_webtransport_capsule_reads.remove(&stream_id);
                    self.discard_webtransport_capsules(qconn, stream_id)?;
                    if self.deferred_webtransport_fins.remove(&stream_id) &&
                        self.stream_map.contains_key(&stream_id)
                    {
                        self.process_h3_fin(qconn, stream_id)?;
                    }
                },
            }
        }
        Ok(())
    }

    fn discard_webtransport_capsules(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        let mut buf = [0; 4096];
        loop {
            match self.conn_mut()?.recv_body(qconn, stream_id, &mut buf) {
                Ok(0) | Err(h3::Error::Done) => break,
                Ok(_) => {},
                Err(h3::Error::TransportError(
                    quiche::Error::StreamReset(_) |
                    quiche::Error::InvalidStreamState(_),
                )) => break,
                Err(error) => return Err(H3ConnectionError::from(error)),
            }
        }
        Ok(())
    }

    fn process_webtransport_capsules(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        let mut buf = [0; 4096];

        loop {
            let recv = self.conn_mut()?.recv_body(qconn, stream_id, &mut buf);
            match recv {
                Ok(read) => {
                    if read == 0 {
                        break;
                    }
                    if let Some(ctx) = self.stream_map.get(&stream_id) {
                        ctx.audit_stats.add_downstream_bytes_recvd(read as u64);
                    }
                    let parsed = self
                        .webtransport
                        .as_mut()
                        .and_then(|runtime| runtime.parser_mut(stream_id))
                        .ok_or(H3ConnectionError::NonexistentStream)?
                        .consume(&buf[..read]);
                    match parsed {
                        Ok(Some(close)) => {
                            let events = self
                                .webtransport
                                .as_mut()
                                .expect("capsule owner was checked above")
                                .terminate(
                                    stream_id,
                                    WebTransportSessionCloseReason::Peer {
                                        error_code: close.error_code,
                                        message: close.message,
                                    },
                                );
                            Self::emit_webtransport_events(
                                &self.h3_event_sender,
                                events,
                            )?;
                        },
                        Ok(None) => {},
                        Err(err) =>
                            return self.fail_webtransport_capsules(
                                qconn, stream_id, err,
                            ),
                    }
                },
                Err(h3::Error::Done) => break,
                Err(h3::Error::TransportError(quiche::Error::StreamReset(
                    error_code,
                ))) => {
                    let runtime = self
                        .webtransport
                        .as_mut()
                        .expect("capsule owner was checked above");
                    let mut events = runtime.terminate(
                        stream_id,
                        WebTransportSessionCloseReason::ConnectReset {
                            error_code,
                        },
                    );
                    events.extend(runtime.mark_connect_recv_closed(stream_id));
                    Self::emit_webtransport_events(
                        &self.h3_event_sender,
                        events,
                    )?;
                    if let Some(ctx) = self.stream_map.get_mut(&stream_id) {
                        ctx.handle_recvd_reset(error_code);
                    }
                    self.h3_event_sender
                        .send(H3Event::ResetStream { stream_id }.into())?;
                    return Ok(());
                },
                Err(err) => return Err(H3ConnectionError::from(err)),
            }
        }
        Ok(())
    }

    fn fail_webtransport_capsules(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
        _error: CapsuleError,
    ) -> H3ConnectionResult<()> {
        let runtime = self
            .webtransport
            .as_mut()
            .expect("capsule owner was checked above");
        runtime.cancel_peer_close_fin(stream_id);
        let mut events = runtime
            .terminate(stream_id, WebTransportSessionCloseReason::ProtocolError);
        events.extend(runtime.mark_connect_recv_closed(stream_id));
        Self::emit_webtransport_events(&self.h3_event_sender, events)?;
        self.shutdown_stream(qconn, stream_id, StreamShutdown::Both {
            read_error_code: WireErrorCode::MessageError as u64,
            write_error_code: WireErrorCode::MessageError as u64,
        })
    }

    fn process_regular_h3_data(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        // Split self borrow between conn and stream_map
        let conn = self.conn.as_mut().ok_or(Self::connection_not_present())?;
        let ctx = self
            .stream_map
            .get_mut(&stream_id)
            .ok_or(H3ConnectionError::NonexistentStream)?;

        enum StreamStatus {
            Done { close: bool },
            Reset { wire_err_code: u64 },
            Blocked,
        }

        let status = loop {
            let Some(sender) = ctx.send.as_ref().and_then(PollSender::get_ref)
            else {
                // already waiting for capacity
                break StreamStatus::Done { close: false };
            };

            let try_reserve_result = sender.try_reserve();
            let permit = match try_reserve_result {
                Ok(permit) => permit,
                Err(TrySendError::Closed(())) => {
                    // The channel has closed before we delivered a fin or reset
                    // to the application.
                    if !ctx.fin_or_reset_recv &&
                        ctx.associated_dgram_flow_id.is_none()
                    // The channel might be closed if the stream was used to
                    // initiate a datagram exchange.
                    // TODO: ideally, the application would still shut down the
                    // stream properly. Once applications code
                    // is fixed, we can remove this check.
                    {
                        let err = h3::WireErrorCode::RequestCancelled as u64;
                        let _ = qconn.stream_shutdown(
                            stream_id,
                            quiche::Shutdown::Read,
                            err,
                        );
                        drop(try_reserve_result); // needed to drop the borrow on ctx.
                        ctx.handle_sent_stop_sending(err);
                        // TODO: should we send an H3Event event to
                        // h3_event_sender? We can only get here if the app
                        // actively closed or dropped
                        // the channel so any event we send would be more for
                        // logging or auditing
                    }
                    break StreamStatus::Done {
                        close: ctx.both_directions_done(),
                    };
                },
                Err(TrySendError::Full(())) => {
                    if ctx.fin_or_reset_recv || qconn.stream_readable(stream_id) {
                        break StreamStatus::Blocked;
                    }
                    break StreamStatus::Done { close: false };
                },
            };

            if ctx.fin_or_reset_recv {
                // Signal end-of-body to upstream
                permit.send(InboundFrame::Body(Default::default(), true));
                break StreamStatus::Done {
                    close: ctx.fin_or_reset_sent,
                };
            }

            // Size the receive buffer to the amount of data currently readable
            // on the stream, capped at `MAX_BUF_SIZE`, so small or idle bodies
            // don't pay for a full 64 KiB allocation. `stream_readable_len`
            // returns the contiguous, in-order bytes available to read now (it
            // includes H3 framing overhead but never counts data behind a gap),
            // so the buffer is sized to what a single drain can actually read.
            // The floor (`MIN_BODY_RECV_BUF_SIZE`) keeps the allocation non-zero
            // and large enough that a trickle of tiny reads reuses a single
            // allocation instead of reallocating each time.
            let want = body_recv_buf_size(qconn.stream_readable_len(stream_id));
            // Lazily allocate the receive buffer on first use; idle
            // connections never receive body bytes and never allocate it.
            let body_recv_buf = self
                .body_recv_buf
                .get_or_insert_with(|| BytesMut::with_capacity(want).limit(want));
            // NOTE: `body_recv_buf` is `Limit<BytesMut>` so `remaining_mut()`
            // reports the space left until the *limit* is reached. (A plain
            // `BytesMut` can reallocate and would always report space available.)
            //
            // Reallocate whenever the room left is smaller than what we want for
            // this read. This covers an exhausted buffer, but also grows a
            // buffer that was previously sized to a smaller readable length so a
            // later, larger read is not throttled by leftover capacity. Capacity
            // is kept equal to the limit so the `split()` invariant asserted
            // below (spare capacity == remaining_mut) continues to hold.
            if body_recv_buf.remaining_mut() < want {
                *body_recv_buf = BytesMut::with_capacity(want).limit(want);
            }
            match conn.recv_body_buf(qconn, stream_id, &mut *body_recv_buf) {
                Ok(n) => {
                    ctx.audit_stats.add_downstream_bytes_recvd(n as u64);
                    let event = H3Event::BodyBytesReceived {
                        stream_id,
                        num_bytes: n as u64,
                        fin: false,
                    };
                    let _ = self.h3_event_sender.send(event.into());
                    // Take the filled part, leave the remaining capacity
                    let filled_body = body_recv_buf.get_mut().split();
                    // Sanity check: the remaining spare capacity should equal
                    // the limit.
                    debug_assert_eq!(
                        body_recv_buf.get_mut().spare_capacity_mut().len(),
                        body_recv_buf.remaining_mut()
                    );
                    // A full split leaves only an empty shared handle, so let
                    // the forwarded frame own the allocation.
                    if !body_recv_buf.has_remaining_mut() {
                        self.body_recv_buf = None;
                    }
                    permit.send(InboundFrame::Body(filled_body, false));
                },
                Err(h3::Error::Done) =>
                    break StreamStatus::Done { close: false },
                Err(h3::Error::TransportError(quiche::Error::StreamReset(
                    code,
                ))) => {
                    break StreamStatus::Reset {
                        wire_err_code: code,
                    };
                },
                Err(_) => break StreamStatus::Done { close: true },
            }
        };

        match status {
            StreamStatus::Done { close } => {
                if close {
                    return self.cleanup_stream(qconn, stream_id);
                }

                // The QUIC stream is finished, manually invoke `process_h3_fin`
                // in case `h3::poll()` is never called again.
                //
                // Note that this case will not conflict with StreamStatus::Done
                // being returned due to the body channel being
                // blocked. qconn.stream_finished() will guarantee
                // that we've fully parsed the body as it only returns true
                // if we've seen a Fin for the read half of the stream.
                if !ctx.fin_or_reset_recv && qconn.stream_finished(stream_id) {
                    return self.process_h3_fin(qconn, stream_id);
                }
            },
            StreamStatus::Reset { wire_err_code } => {
                debug_assert!(ctx.send.is_some());
                ctx.handle_recvd_reset(wire_err_code);
                self.h3_event_sender
                    .send(H3Event::ResetStream { stream_id }.into())?;
                if ctx.both_directions_done() {
                    return self.cleanup_stream(qconn, stream_id);
                }
            },
            StreamStatus::Blocked => {
                self.waiting_streams.push(ctx.wait_for_send(stream_id));
            },
        }

        Ok(())
    }

    /// Processes an end-of-stream event from the [`quiche::h3::Connection`].
    fn process_h3_fin(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        if self
            .webtransport
            .as_ref()
            .is_some_and(|runtime| runtime.is_session(stream_id))
        {
            let finish = if self
                .webtransport
                .as_ref()
                .is_some_and(|runtime| runtime.capsules_negotiated(stream_id))
            {
                self.webtransport
                    .as_mut()
                    .and_then(|runtime| runtime.parser_mut(stream_id))
                    .expect("session parser exists")
                    .finish()
            } else {
                Ok(())
            };
            if let Err(error) = finish {
                return self.fail_webtransport_capsules(qconn, stream_id, error);
            }
            let events = self
                .webtransport
                .as_mut()
                .expect("session owner was checked above")
                .mark_connect_recv_closed(stream_id);
            Self::emit_webtransport_events(&self.h3_event_sender, events)?;
        }

        let ctx = self
            .stream_map
            .get_mut(&stream_id)
            .filter(|c| !c.fin_or_reset_recv);
        let Some(ctx) = ctx else {
            // Stream is already finished, nothing to do
            return Ok(());
        };

        ctx.fin_or_reset_recv = true;
        ctx.audit_stats
            .set_recvd_stream_fin(StreamClosureKind::Explicit);

        // It's important to send this H3Event before process_h3_data so that
        // a server can (potentially) generate the control response before the
        // corresponding receiver drops.
        let event = H3Event::BodyBytesReceived {
            stream_id,
            num_bytes: 0,
            fin: true,
        };
        let _ = self.h3_event_sender.send(event.into());

        // Communicate fin to upstream. Since `ctx.fin_recv` is true now,
        // there can't be a recursive loop.
        self.process_h3_data(qconn, stream_id)?;
        if self
            .webtransport
            .as_ref()
            .is_some_and(|runtime| runtime.has_peer_close_fin(stream_id))
        {
            self.process_writable_stream(qconn, stream_id)?;
        }
        Ok(())
    }

    /// Processes a single [`quiche::h3::Event`] received from the underlying
    /// [`quiche::h3::Connection`]. Some events are dispatched to helper
    /// methods.
    fn process_read_event(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64, event: h3::Event,
    ) -> H3ConnectionResult<()> {
        self.forward_settings(qconn)?;

        match event {
            // Requests/responses are exclusively handled by hooks.
            h3::Event::Headers { list, more_frames } =>
                H::headers_received(self, qconn, InboundHeaders {
                    stream_id,
                    headers: list,
                    has_body: more_frames,
                }),

            h3::Event::Data => self.process_h3_data(qconn, stream_id),
            h3::Event::Finished => {
                let deferred = !self.stream_map.contains_key(&stream_id) &&
                    self.webtransport.as_ref().is_some_and(|runtime| {
                        runtime.capsule_read_mode(stream_id) ==
                            CapsuleReadMode::Defer
                    });
                if deferred {
                    self.deferred_webtransport_capsule_reads.insert(stream_id);
                    self.deferred_webtransport_fins.insert(stream_id);
                    return Ok(());
                }
                self.process_h3_fin(qconn, stream_id)
            },

            h3::Event::Reset(code) => {
                let application_visible =
                    self.stream_map.contains_key(&stream_id);
                if self
                    .webtransport
                    .as_ref()
                    .is_some_and(|runtime| runtime.is_session(stream_id))
                {
                    let runtime = self
                        .webtransport
                        .as_mut()
                        .expect("session owner was checked above");
                    let mut events = runtime.terminate(
                        stream_id,
                        WebTransportSessionCloseReason::ConnectReset {
                            error_code: code,
                        },
                    );
                    events.extend(runtime.mark_connect_recv_closed(stream_id));
                    if application_visible {
                        Self::emit_webtransport_events(
                            &self.h3_event_sender,
                            events,
                        )?;
                    }
                }
                self.deferred_webtransport_capsule_reads.remove(&stream_id);
                self.deferred_webtransport_fins.remove(&stream_id);
                if let Some(ctx) = self.stream_map.get_mut(&stream_id) {
                    ctx.handle_recvd_reset(code);
                    // See if we are waiting on this stream and close the channel
                    // if we are. If we are not waiting, `handle_recvd_reset()`
                    // will have taken care of closing.
                    for pending in self.waiting_streams.iter_mut() {
                        match pending {
                            WaitForStream::Upstream(
                                WaitForUpstreamCapacity {
                                    stream_id: id,
                                    chan: Some(chan),
                                },
                            ) if stream_id == *id => {
                                chan.close();
                            },
                            _ => {},
                        }
                    }

                    self.h3_event_sender
                        .send(H3Event::ResetStream { stream_id }.into())?;
                    if ctx.both_directions_done() {
                        return self.cleanup_stream(qconn, stream_id);
                    }
                }

                // TODO: if we don't have the stream in our map: should we
                // send the H3Event::ResetStream?
                Ok(())
            },

            h3::Event::PriorityUpdate => Ok(()),
            h3::Event::WebTransportStream {
                session_id,
                direction,
                prefix_len,
            } => {
                let direction = match direction {
                    h3::WebTransportStreamDirection::Bidirectional =>
                        WebTransportStreamDirection::Bidi,
                    h3::WebTransportStreamDirection::Unidirectional =>
                        WebTransportStreamDirection::Uni,
                };
                let Some(runtime) = self.webtransport.as_mut() else {
                    return Err(H3ConnectionError::H3(h3::Error::InternalError));
                };
                let events = runtime.classify(
                    AssociatedStream {
                        session_id,
                        stream_id,
                        direction,
                        prefix_len,
                    },
                    qconn,
                );
                Self::emit_webtransport_events(&self.h3_event_sender, events)
            },
            h3::Event::GoAway => {
                self.h3_event_sender
                    .send(H3Event::GoAway { id: stream_id }.into())?;
                Ok(())
            },
        }
    }

    /// The SETTINGS frame can be received at any point, so we
    /// need to check `peer_settings_raw` to decide if we've received it.
    ///
    /// Settings should only be sent once, so we generate a single event
    /// when `peer_settings_raw` transitions from None to Some.
    fn forward_settings(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        if self.settings_received_and_forwarded {
            return Ok(());
        }

        let Some(settings) =
            self.conn_mut()?.peer_settings_raw().map(<[_]>::to_vec)
        else {
            return Ok(());
        };

        if self.bounded_profile.is_none() {
            let incoming_settings = H3Event::IncomingSettings { settings };
            self.h3_event_sender.send(incoming_settings.into())?;
        }

        if let Some(profile) = self.bounded_profile.as_ref() {
            let negotiated = match webtransport_requirements(
                self.conn
                    .as_ref()
                    .ok_or_else(Self::connection_not_present)?,
                qconn,
            ) {
                WebTransportRequirements::Met(negotiated) => negotiated,
                WebTransportRequirements::Pending => return Ok(()),
                WebTransportRequirements::Failed => {
                    let error =
                        BoundedProfileError::PeerHandshakeRequirementsNotMet;
                    profile.record_live(Err(error.clone()));
                    return Err(H3ConnectionError::BoundedProfile(error));
                },
            };
            profile.record_live(Ok(profile.negotiated_applied(negotiated)));
        }

        self.settings_received_and_forwarded = true;
        H::settings_received(self, qconn)?;
        Ok(())
    }

    /// Send an individual frame to the underlying [`quiche::h3::Connection`] to
    /// be flushed at a later time.
    ///
    /// `Self::process_writes` will iterate over all writable streams and call
    /// this method in a loop for each stream to send all writable packets.
    fn process_write_frame(
        conn: &mut h3::Connection, qconn: &mut QuicheConnection,
        ctx: &mut StreamCtx, h3_event_sender: &H3EventSender<H::Event>,
        emit_h3_headers_flushed: bool,
        mut webtransport: Option<&mut WebTransportRuntime>,
    ) -> H3ConnectionResult<()> {
        let Some(frame) = &mut ctx.queued_frame else {
            return Ok(());
        };

        let audit_stats = &ctx.audit_stats;
        let stream_id = audit_stats.stream_id();

        match frame {
            OutboundFrame::Headers(headers, priority) => {
                let prio = priority.as_ref().unwrap_or(&DEFAULT_PRIO);
                let initial_headers = !ctx.initial_headers_sent;
                let status = response_status(headers);

                if qconn.is_server() &&
                    status.is_some_and(|status| status >= 200) &&
                    webtransport
                        .as_deref()
                        .is_some_and(|runtime| runtime.is_pending(stream_id))
                {
                    match webtransport_requirements(conn, qconn) {
                        WebTransportRequirements::Pending => {
                            webtransport
                                .as_deref_mut()
                                .expect("pending session has a runtime")
                                .defer_response(stream_id);
                            return Err(H3ConnectionError::H3(
                                h3::Error::StreamBlocked,
                            ));
                        },
                        WebTransportRequirements::Failed => {
                            let events = webtransport
                                .as_deref_mut()
                                .expect("pending session has a runtime")
                                .admission_failed(stream_id);
                            Self::emit_webtransport_events(
                                h3_event_sender,
                                events,
                            )?;
                            return Err(H3ConnectionError::H3(
                                h3::Error::MessageError,
                            ));
                        },
                        WebTransportRequirements::Met(_) => {},
                    }
                }

                let res = if ctx.initial_headers_sent {
                    // Initial headers were already sent, send additional
                    // headers now.
                    conn.send_additional_headers_with_priority(
                        qconn, stream_id, headers, prio, false, false,
                    )
                } else {
                    // Send initial headers.
                    conn.send_response_with_priority(
                        qconn, stream_id, headers, prio, false,
                    )
                    .inspect(|_| ctx.initial_headers_sent = true)
                };

                if let Err(h3::Error::StreamBlocked) = res {
                    ctx.first_full_headers_flush_fail_time
                        .get_or_insert(Instant::now());
                }

                if res.is_ok() {
                    if emit_h3_headers_flushed {
                        log::info!(
                            "H3 headers flushed to QUIC";
                            "stream_id" => stream_id,
                            "initial_headers" => initial_headers,
                            "header_count" => headers.len()
                        );

                        let mut diagnostic = WebTransportDiagnostic::new(
                            WebTransportDiagnosticKind::H3HeadersFlushedToQuic,
                        );
                        diagnostic.stream_id = Some(stream_id);
                        diagnostic.initial_headers = Some(initial_headers);
                        diagnostic.header_count = Some(headers.len());

                        let _ = h3_event_sender.send(
                            H3Event::WebTransportDiagnostic(diagnostic).into(),
                        );
                    }

                    if let Some(first) =
                        ctx.first_full_headers_flush_fail_time.take()
                    {
                        ctx.audit_stats.add_header_flush_duration(
                            Instant::now().duration_since(first),
                        );
                    }

                    if let Some(status) = status {
                        let events = webtransport.as_deref_mut().map_or_else(
                            Vec::new,
                            |runtime| {
                                runtime.response_accepted(stream_id, status)
                            },
                        );
                        Self::emit_webtransport_events(h3_event_sender, events)?;
                    }
                }

                res.map_err(H3ConnectionError::from)
            },

            OutboundFrame::Body(body, fin) => {
                let len = body.len();
                if len == 0 && !*fin {
                    // quiche doesn't allow sending an empty body when the fin
                    // flag is not set
                    return Ok(());
                }
                if *fin {
                    // If this is the last body frame, drop the receiver in the
                    // stream map to signal that we shouldn't receive any more
                    // frames. NOTE: we can't use `mpsc::Receiver::close()`
                    // due to an inconsistency in how tokio handles reading
                    // from a closed mpsc channel https://github.com/tokio-rs/tokio/issues/7631
                    ctx.recv = None;
                }
                let n = conn.send_body_zc(qconn, stream_id, body, *fin)?;

                audit_stats.add_downstream_bytes_sent(n as _);
                if n != len {
                    // Couldn't write the entire body, `send_body_zc` will
                    // have trimmed `body` accordingly. The driver keeps
                    // the remainder of the body to send in the future.
                    debug_assert_eq!(
                        n + body.len(),
                        len,
                        "send_body_zc() should have trimmed body but did not"
                    );
                    Err(h3::Error::StreamBlocked)
                } else {
                    if *fin {
                        let fin_result = Self::on_fin_sent(ctx);
                        let events = webtransport.as_deref_mut().map_or_else(
                            Vec::new,
                            |runtime| {
                                runtime.terminate(
                                    stream_id,
                                    WebTransportSessionCloseReason::Clean,
                                )
                            },
                        );
                        Self::emit_webtransport_events(h3_event_sender, events)?;
                        if let Some(runtime) = webtransport.as_deref_mut() {
                            runtime.mark_connect_send_closed(stream_id);
                        }
                        fin_result?;
                    }
                    Ok(())
                }
                .map_err(H3ConnectionError::from)
            },

            OutboundFrame::Trailers(headers, priority) => {
                let prio = priority.as_ref().unwrap_or(&DEFAULT_PRIO);

                // trailers always set fin=true
                let res = conn.send_additional_headers_with_priority(
                    qconn, stream_id, headers, prio, true, true,
                );

                if res.is_ok() {
                    let fin_result = Self::on_fin_sent(ctx);
                    let events = webtransport.as_deref_mut().map_or_else(
                        Vec::new,
                        |runtime| {
                            runtime.terminate(
                                stream_id,
                                WebTransportSessionCloseReason::Clean,
                            )
                        },
                    );
                    Self::emit_webtransport_events(h3_event_sender, events)?;
                    if let Some(runtime) = webtransport.as_deref_mut() {
                        runtime.mark_connect_send_closed(stream_id);
                    }
                    fin_result?;
                }
                res.map_err(H3ConnectionError::from)
            },

            OutboundFrame::PeerStreamError =>
                Err(H3ConnectionError::H3(h3::Error::MessageError)),

            OutboundFrame::FlowShutdown { .. } => {
                unreachable!("Only flows send shutdowns")
            },

            OutboundFrame::Datagram(..) => {
                unreachable!("Only flows send datagrams")
            },

            OutboundFrame::WebTransportClose { capsule } => {
                let len = capsule.len();
                let n = conn.send_body_zc(qconn, stream_id, capsule, true)?;
                audit_stats.add_downstream_bytes_sent(n as _);
                if n != len {
                    debug_assert_eq!(n + capsule.len(), len);
                    return Err(H3ConnectionError::H3(h3::Error::StreamBlocked));
                }

                let fin_result = Self::on_fin_sent(ctx);
                let events = webtransport.map_or_else(Vec::new, |runtime| {
                    runtime.local_close_committed(stream_id)
                });
                Self::emit_webtransport_events(h3_event_sender, events)?;
                fin_result.map_err(H3ConnectionError::from)
            },
        }
    }

    fn emit_webtransport_events(
        sender: &H3EventSender<H::Event>, events: Vec<WebTransportSessionEvent>,
    ) -> H3ConnectionResult<()> {
        for event in events {
            sender.observe_webtransport_event(&event);
            sender.send(H3Event::WebTransportSession(event).into())?;
        }
        Ok(())
    }

    fn on_fin_sent(ctx: &mut StreamCtx) -> h3::Result<()> {
        ctx.recv = None;
        ctx.fin_or_reset_sent = true;
        ctx.audit_stats
            .set_sent_stream_fin(StreamClosureKind::Explicit);
        if ctx.fin_or_reset_recv {
            // Return a TransportError to trigger stream cleanup
            // instead of h3::Error::Done
            Err(h3::Error::TransportError(quiche::Error::Done))
        } else {
            Ok(())
        }
    }

    /// Resumes reads or writes to the connection when a stream channel becomes
    /// unblocked.
    ///
    /// If we were waiting for more data from a channel, we resume writing to
    /// the connection. Otherwise, we were blocked on channel capacity and
    /// continue reading from the connection. `Upstream` in this context is
    /// the consumer of the stream.
    fn upstream_ready(
        &mut self, qconn: &mut QuicheConnection, ready: StreamReady,
    ) -> H3ConnectionResult<()> {
        match ready {
            StreamReady::Downstream(r) => self.upstream_read_ready(qconn, r),
            StreamReady::Upstream(r) => self.upstream_write_ready(qconn, r),
        }
    }

    fn upstream_read_ready(
        &mut self, qconn: &mut QuicheConnection,
        read_ready: ReceivedDownstreamData,
    ) -> H3ConnectionResult<()> {
        let ReceivedDownstreamData {
            stream_id,
            chan,
            data,
        } = read_ready;

        match self.stream_map.get_mut(&stream_id) {
            None => Ok(()),
            Some(stream) => {
                stream.recv = Some(chan);
                stream.queued_frame = data;
                self.process_writable_stream(qconn, stream_id)
            },
        }
    }

    fn upstream_write_ready(
        &mut self, qconn: &mut QuicheConnection,
        write_ready: HaveUpstreamCapacity,
    ) -> H3ConnectionResult<()> {
        let HaveUpstreamCapacity {
            stream_id,
            mut chan,
        } = write_ready;

        match self.stream_map.get_mut(&stream_id) {
            None => Ok(()),
            Some(stream) => {
                chan.abort_send(); // Have to do it to release the associated permit
                stream.send = Some(chan);
                self.process_h3_data(qconn, stream_id)
            },
        }
    }

    /// Processes all queued outbound datagrams from the `dgram_recv` channel.
    fn dgram_ready(
        &mut self, qconn: &mut QuicheConnection, frame: OutboundFrame,
    ) -> H3ConnectionResult<()> {
        let mut frame = Ok(frame);

        loop {
            match frame {
                Ok(OutboundFrame::Datagram(dgram, flow_id)) => {
                    // Drop datagrams if there is no capacity
                    let _ = if let Some(channel_id) =
                        self.multicast_datagram_channel_id.as_deref()
                    {
                        datagram::send_h3_dgram_on_multicast_channel(
                            qconn, channel_id, flow_id, dgram,
                        )
                    } else {
                        datagram::send_h3_dgram(qconn, flow_id, dgram)
                    };
                },
                Ok(OutboundFrame::FlowShutdown { flow_id, stream_id }) => {
                    self.shutdown_stream(
                        qconn,
                        stream_id,
                        StreamShutdown::Both {
                            read_error_code: WireErrorCode::NoError as u64,
                            write_error_code: WireErrorCode::NoError as u64,
                        },
                    )?;
                    self.flow_map.remove(&flow_id);
                    self.close_if_idle(qconn);
                    break;
                },
                Ok(_) => unreachable!("Flows can't send frame of other types"),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) =>
                    return Err(H3ConnectionError::ControllerWentAway),
            }

            frame = self.dgram_recv.try_recv();
        }

        Ok(())
    }

    /// Return a mutable reference to the driver's HTTP/3 connection.
    ///
    /// If the connection doesn't exist yet, this function returns
    /// a `Self::connection_not_present()` error.
    fn conn_mut(&mut self) -> H3ConnectionResult<&mut h3::Connection> {
        self.conn.as_mut().ok_or(Self::connection_not_present())
    }

    /// Alias for [`quiche::Error::TlsFail`], which is used in the case where
    /// this driver doesn't have an established HTTP/3 connection attached
    /// to it yet.
    const fn connection_not_present() -> H3ConnectionError {
        H3ConnectionError::H3(h3::Error::TransportError(quiche::Error::TlsFail))
    }

    /// Cleans up internal state for the indicated HTTP/3 stream.
    ///
    /// This function removes the stream from the stream map, closes any pending
    /// futures, removes associated DATAGRAM flows, and sends a
    /// [`H3Event::StreamClosed`] event (for servers).
    fn cleanup_stream(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        let Some(stream_ctx) = self.stream_map.remove(&stream_id) else {
            return Ok(());
        };

        // Find if the stream also has any pending futures associated with it
        for pending in self.waiting_streams.iter_mut() {
            match pending {
                WaitForStream::Downstream(WaitForDownstreamData {
                    stream_id: id,
                    chan: Some(chan),
                }) if stream_id == *id => {
                    chan.close();
                },
                WaitForStream::Upstream(WaitForUpstreamCapacity {
                    stream_id: id,
                    chan: Some(chan),
                }) if stream_id == *id => {
                    chan.close();
                },
                _ => {},
            }
        }

        // Close any DATAGRAM-proxying channels when we close the stream, if they
        // exist
        if let Some(mapped_flow_id) = stream_ctx.associated_dgram_flow_id {
            self.flow_map.remove(&mapped_flow_id);
        }

        if let Some(runtime) = self.webtransport.as_mut() {
            runtime.forget_non_session_request(stream_id);
        }

        if qconn.is_server() {
            // Signal the server to remove the stream from its map
            let _ = self
                .h3_event_sender
                .send(H3Event::StreamClosed { stream_id }.into());
        }

        self.close_if_idle(qconn);

        Ok(())
    }

    /// Handles connection cleanup once no streams or flows remain.
    ///
    /// Releases the body receive buffer (it is reallocated lazily on the next
    /// body read; body bytes only flow on active streams, so an empty stream
    /// map means it is unused) and closes the connection with `NoError` if the
    /// H3 event receiver has been dropped.
    fn close_if_idle(&mut self, qconn: &mut QuicheConnection) {
        if self.stream_map.is_empty() && self.flow_map.is_empty() {
            self.body_recv_buf = None;

            if self.h3_event_receiver_dropped {
                let _ = qconn.close(
                    true,
                    quiche::h3::WireErrorCode::NoError as u64,
                    &[],
                );
            }
        }
    }

    /// Shuts down the indicated HTTP/3 stream by sending frames and cleaning
    /// up then cleans up internal state by calling
    /// [`Self::cleanup_stream`].
    fn shutdown_stream(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
        shutdown: StreamShutdown,
    ) -> H3ConnectionResult<()> {
        let Some(stream_ctx) = self.stream_map.get(&stream_id) else {
            return Ok(());
        };

        let audit_stats = &stream_ctx.audit_stats;

        match shutdown {
            StreamShutdown::Read { error_code } => {
                audit_stats.set_sent_stop_sending_error_code(error_code as _);
                let _ = qconn.stream_shutdown(
                    stream_id,
                    quiche::Shutdown::Read,
                    error_code,
                );
            },
            StreamShutdown::Write { error_code } => {
                audit_stats.set_sent_reset_stream_error_code(error_code as _);
                let _ = qconn.stream_shutdown(
                    stream_id,
                    quiche::Shutdown::Write,
                    error_code,
                );
            },
            StreamShutdown::Both {
                read_error_code,
                write_error_code,
            } => {
                audit_stats
                    .set_sent_stop_sending_error_code(read_error_code as _);
                let _ = qconn.stream_shutdown(
                    stream_id,
                    quiche::Shutdown::Read,
                    read_error_code,
                );
                audit_stats
                    .set_sent_reset_stream_error_code(write_error_code as _);
                let _ = qconn.stream_shutdown(
                    stream_id,
                    quiche::Shutdown::Write,
                    write_error_code,
                );
            },
        }

        if let Some(runtime) = self.webtransport.as_mut() {
            let events = match shutdown {
                StreamShutdown::Read { .. } | StreamShutdown::Both { .. } =>
                    runtime.mark_connect_recv_closed(stream_id),
                StreamShutdown::Write { .. } => Vec::new(),
            };
            if matches!(
                shutdown,
                StreamShutdown::Write { .. } | StreamShutdown::Both { .. }
            ) {
                runtime.mark_connect_send_closed(stream_id);
            }
            Self::emit_webtransport_events(&self.h3_event_sender, events)?;
        }

        self.cleanup_stream(qconn, stream_id)
    }

    /// Handles a regular [`H3Command`]. May be called internally by
    /// [DriverHooks] for non-endpoint-specific [`H3Command`]s.
    fn handle_core_command(
        &mut self, qconn: &mut QuicheConnection, cmd: H3Command,
    ) -> H3ConnectionResult<()> {
        if self.bounded_profile.is_some() &&
            !matches!(&cmd, H3Command::CloseWebTransportSession { .. })
        {
            return Err(H3ConnectionError::BoundedProfile(
                BoundedProfileError::ForbiddenOperation("generic H3 command"),
            ));
        }
        match cmd {
            H3Command::QuicCmd(cmd) => cmd.execute(qconn),
            H3Command::GoAway => {
                let max_id = self.max_stream_seen;
                self.conn_mut()
                    .expect("connection should be established")
                    .send_goaway(qconn, max_id)?;
            },
            H3Command::ShutdownStream {
                stream_id,
                shutdown,
            } => {
                if self
                    .webtransport
                    .as_ref()
                    .is_some_and(|runtime| runtime.is_session(stream_id))
                {
                    let events = self
                        .webtransport
                        .as_mut()
                        .expect("session owner was checked above")
                        .output_failed(stream_id);
                    Self::emit_webtransport_events(
                        &self.h3_event_sender,
                        events,
                    )?;
                }
                self.shutdown_stream(qconn, stream_id, shutdown)?;
            },
            H3Command::CloseWebTransportSession {
                session_id,
                error_code,
                message,
            } => {
                let close =
                    CloseCapsule::new(error_code, message).map_err(|_| {
                        H3ConnectionError::H3(h3::Error::MessageError)
                    })?;
                if !self.stream_map.contains_key(&session_id) {
                    return Ok(());
                }
                let Some(webtransport) = self.webtransport.as_mut() else {
                    return Ok(());
                };
                if !webtransport.begin_local_close(session_id, close.clone()) {
                    return Ok(());
                }
                self.process_writable_stream(qconn, session_id)?;
            },
        }
        Ok(())
    }
}

impl<H: DriverHooks> H3Driver<H> {
    /// Reads streams that have been explicitly claimed by the endpoint hooks as
    /// raw QUIC streams rather than HTTP/3 streams.
    fn process_raw_stream_reads(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        let readable = qconn.readable().collect::<Vec<_>>();

        for stream_id in readable {
            if self
                .webtransport
                .as_ref()
                .is_some_and(|runtime| runtime.owns_stream(stream_id))
            {
                continue;
            }
            if !self.raw_streams.contains(&stream_id) &&
                !H::should_intercept_raw_stream(self, stream_id)
            {
                continue;
            }

            self.raw_streams.insert(stream_id);

            loop {
                match qconn.stream_recv(stream_id, &mut self.raw_stream_recv_buf)
                {
                    Ok((read, fin)) => {
                        if read != 0 || fin {
                            let data = Bytes::copy_from_slice(
                                &self.raw_stream_recv_buf[..read],
                            );
                            for event in H::raw_stream_data_received(
                                self, stream_id, data, fin,
                            )? {
                                self.h3_event_sender.send(event.into())?;
                            }
                        }

                        if read == 0 || fin {
                            if fin {
                                self.raw_streams.remove(&stream_id);
                            }
                            break;
                        }
                    },
                    Err(quiche::Error::Done) => break,
                    Err(quiche::Error::InvalidStreamState(_)) => {
                        self.raw_streams.remove(&stream_id);
                        break;
                    },
                    Err(err) => return Err(H3ConnectionError::from(err)),
                }
            }
        }

        Ok(())
    }

    fn handle_webtransport_command(
        &mut self, qconn: &mut QuicheConnection, command: WebTransportCommand,
    ) -> H3ConnectionResult<()> {
        let queued_command_items = self
            .webtransport_cmd_recv
            .as_ref()
            .map_or(0, mpsc::Receiver::len);
        let conn = self.conn.as_mut().ok_or(Self::connection_not_present())?;
        let runtime = self
            .webtransport
            .as_mut()
            .ok_or(H3ConnectionError::H3(h3::Error::InternalError))?;
        runtime.handle_command(conn, qconn, command, queued_command_items);
        Ok(())
    }

    fn try_webtransport_command(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<bool> {
        let command = match self.webtransport_cmd_recv.as_mut() {
            Some(recv) => match recv.try_recv() {
                Ok(command) => command,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) =>
                    return Ok(false),
            },
            None => return Ok(false),
        };
        self.handle_webtransport_command(qconn, command)?;
        Ok(true)
    }

    fn try_webtransport_opening(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<bool> {
        let conn = self.conn.as_mut().ok_or(Self::connection_not_present())?;
        let Some(runtime) = self.webtransport.as_mut() else {
            return Ok(false);
        };
        Ok(runtime.process_open_work(conn, qconn, 1) != 0)
    }

    fn process_webtransport_stream_credit_updates(
        &mut self, qconn: &mut QuicheConnection,
    ) {
        let Some(runtime) = self.webtransport.as_mut() else {
            return;
        };
        while let Some(direction) = qconn.stream_credit_next() {
            runtime.stream_credit_available(direction);
        }
    }

    fn process_webtransport_io(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        let Some(limit) = self
            .webtransport
            .as_ref()
            .map(WebTransportRuntime::work_limit)
        else {
            return Ok(());
        };

        for _ in 0..limit {
            let command_first = self.webtransport_command_turn;
            let progressed = if command_first {
                self.try_webtransport_command(qconn)? ||
                    self.try_webtransport_opening(qconn)?
            } else {
                self.try_webtransport_opening(qconn)? ||
                    self.try_webtransport_command(qconn)?
            };
            if !progressed {
                break;
            }
            self.webtransport_command_turn = !command_first;
        }
        Ok(())
    }

    fn close_webtransport_command_lane(&mut self) {
        let Some(recv) = self.webtransport_cmd_recv.as_mut() else {
            return;
        };
        recv.close();
        while let Ok(command) = recv.try_recv() {
            if let Some(runtime) = self.webtransport.as_ref() {
                runtime.settle_command_on_connection_close(command);
            } else {
                command.reject_connection_closed();
            }
        }
    }

    /// Reads all buffered datagrams out of `qconn` and distributes them to
    /// their flow channels.
    fn process_available_dgrams(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        let max_work = self
            .webtransport
            .as_ref()
            .map_or(usize::MAX, WebTransportRuntime::work_limit);
        for _ in 0..max_work {
            let start = self.webtransport_datagram_turn;
            let mut progressed = false;
            for delta in 0..3 {
                let class = (start + delta) % 3;
                progressed = match class {
                    0 => self.try_process_inbound_dgram(qconn)?,
                    1 => self.try_process_legacy_dgram(qconn)?,
                    2 => self.webtransport.as_mut().is_some_and(|runtime| {
                        runtime.expire_provisional_datagrams(
                            std::time::Instant::now(),
                            1,
                        ) != 0
                    }),
                    _ => unreachable!("Datagram work class is modulo three"),
                };
                if progressed {
                    self.webtransport_datagram_turn = (class + 1) % 3;
                    break;
                }
            }
            if !progressed {
                break;
            }
        }
        Ok(())
    }

    fn try_process_inbound_dgram(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<bool> {
        let (flow_id, frame) = match datagram::receive_h3_dgram(qconn) {
            Ok(frame) => frame,
            Err(quiche::Error::Done) => return Ok(false),
            Err(error) => return Err(H3ConnectionError::from(error)),
        };
        let InboundFrame::Datagram(dgram) = frame else {
            unreachable!("H3 Datagram decoder only returns Datagrams");
        };
        let dgram = match (flow_id.checked_mul(4), self.webtransport.as_mut()) {
            (Some(session_id), Some(runtime)) => {
                let Some(dgram) =
                    runtime.route_datagram(qconn, session_id, dgram)
                else {
                    return Ok(true);
                };
                dgram
            },
            _ => dgram,
        };
        self.deliver_legacy_dgram(qconn, flow_id, dgram)?;
        Ok(true)
    }

    fn try_process_legacy_dgram(
        &mut self, qconn: &QuicheConnection,
    ) -> H3ConnectionResult<bool> {
        let Some((flow_id, datagram)) = self
            .webtransport
            .as_mut()
            .and_then(WebTransportRuntime::pop_legacy_datagram)
        else {
            return Ok(false);
        };
        self.deliver_legacy_dgram(qconn, flow_id, datagram)?;
        Ok(true)
    }

    fn deliver_legacy_dgram(
        &mut self, qconn: &QuicheConnection, flow_id: u64, dgram: DgramBuffer,
    ) -> H3ConnectionResult<()> {
        if !qconn.is_server() || self.hooks.extended_connect_enabled() {
            self.get_or_insert_flow(flow_id)?
                .send_best_effort(InboundFrame::Datagram(dgram));
        }
        Ok(())
    }

    fn process_webtransport_readable_wakes(&mut self, qconn: &QuicheConnection) {
        let Some(runtime) = self.webtransport.as_mut() else {
            return;
        };
        for stream_id in qconn.readable() {
            runtime.process_owned_readable(qconn, stream_id);
        }
    }

    /// Flushes any queued-up frames for `stream_id` into `qconn` until either
    /// there is no more capacity in `qconn` or no more frames to send.
    fn process_writable_stream(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        let bounded_connect_headers = self.bounded_connect_header_limits();
        let emit_h3_headers_flushed =
            H::should_emit_h3_headers_flushed(self, stream_id);
        let h3_event_sender = self.h3_event_sender.clone();
        // Split self borrow between conn and stream_map
        let conn = self.conn.as_mut().ok_or(Self::connection_not_present())?;
        let Some(ctx) = self.stream_map.get_mut(&stream_id) else {
            return Ok(()); // Unknown stream_id
        };

        loop {
            if let (Some(limits), Some(frame)) =
                (bounded_connect_headers, ctx.queued_frame.as_ref())
            {
                validate_bounded_outbound_frame(frame, limits)?;
            }
            // Process each writable frame, queue the next frame for processing
            // and shut down any errored streams.
            match Self::process_write_frame(
                conn,
                qconn,
                ctx,
                &h3_event_sender,
                emit_h3_headers_flushed,
                self.webtransport.as_mut(),
            ) {
                Ok(()) => ctx.queued_frame = None,
                Err(H3ConnectionError::H3(
                    h3::Error::StreamBlocked | h3::Error::Done,
                )) => break,
                Err(H3ConnectionError::H3(h3::Error::MessageError)) => {
                    let events = self
                        .webtransport
                        .as_mut()
                        .map_or_else(Vec::new, |runtime| {
                            runtime.output_failed(stream_id)
                        });
                    Self::emit_webtransport_events(
                        &self.h3_event_sender,
                        events,
                    )?;
                    return self.shutdown_stream(
                        qconn,
                        stream_id,
                        StreamShutdown::Both {
                            read_error_code: WireErrorCode::MessageError as u64,
                            write_error_code: WireErrorCode::MessageError as u64,
                        },
                    );
                },
                Err(H3ConnectionError::H3(h3::Error::TransportError(
                    quiche::Error::StreamStopped(e),
                ))) => {
                    if self
                        .webtransport
                        .as_ref()
                        .is_some_and(|runtime| runtime.is_session(stream_id))
                    {
                        let runtime = self
                            .webtransport
                            .as_mut()
                            .expect("session owner was checked above");
                        let mut events = runtime.terminate(
                            stream_id,
                            WebTransportSessionCloseReason::ConnectStopped {
                                error_code: e,
                            },
                        );
                        events
                            .extend(runtime.mark_connect_recv_closed(stream_id));
                        Self::emit_webtransport_events(
                            &self.h3_event_sender,
                            events,
                        )?;
                        return self.shutdown_stream(
                            qconn,
                            stream_id,
                            StreamShutdown::Both {
                                read_error_code: WT_SESSION_GONE,
                                write_error_code: WT_SESSION_GONE,
                            },
                        );
                    }
                    ctx.handle_recvd_stop_sending(e);
                    if ctx.both_directions_done() {
                        return self.cleanup_stream(qconn, stream_id);
                    } else {
                        return Ok(());
                    }
                },
                Err(H3ConnectionError::H3(h3::Error::TransportError(
                    quiche::Error::InvalidStreamState(stream),
                ))) => {
                    return self.cleanup_stream(qconn, stream);
                },
                Err(H3ConnectionError::H3(_)) => {
                    let events = self
                        .webtransport
                        .as_mut()
                        .map_or_else(Vec::new, |runtime| {
                            runtime.output_failed(stream_id)
                        });
                    Self::emit_webtransport_events(
                        &self.h3_event_sender,
                        events,
                    )?;
                    return self.cleanup_stream(qconn, stream_id);
                },
                Err(err) => return Err(err),
            }

            if ctx.queued_frame.is_none() {
                let local_close_waiting =
                    self.webtransport.as_ref().is_some_and(|runtime| {
                        runtime.local_close_waiting(stream_id)
                    });
                if local_close_waiting {
                    if let Some(recv) = ctx.recv.as_mut() {
                        recv.close();
                        if let Ok(frame) = recv.try_recv() {
                            ctx.queued_frame = Some(frame);
                            continue;
                        }
                    }
                }
                if let Some(capsule) =
                    self.webtransport.as_mut().and_then(|runtime| {
                        runtime.take_local_close_output(stream_id)
                    })
                {
                    ctx.recv = None;
                    ctx.queued_frame =
                        Some(OutboundFrame::WebTransportClose { capsule });
                    continue;
                }
                if self
                    .webtransport
                    .as_mut()
                    .is_some_and(|runtime| runtime.take_peer_close_fin(stream_id))
                {
                    ctx.recv = None;
                    ctx.queued_frame =
                        Some(OutboundFrame::Body(Bytes::new(), true));
                    continue;
                }
            }

            let Some(recv) = ctx.recv.as_mut() else {
                // This stream is already waiting for data or we wrote a fin and
                // closed the channel.
                debug_assert!(
                    ctx.queued_frame.is_none(),
                    "We MUST NOT have a queued frame if we are already waiting on 
                    more data from the channel"
                );
                return Ok(());
            };

            // Attempt to queue the next frame for processing. The corresponding
            // sender is created at the same time as the `StreamCtx`
            // and ultimately ends up in an `H3Body`. The body then
            // determines which frames to send to the peer via
            // this processing loop.
            match recv.try_recv() {
                Ok(frame) => ctx.queued_frame = Some(frame),
                Err(TryRecvError::Disconnected) => {
                    let bounded_terminal_connect =
                        self.bounded_profile.as_ref().is_some_and(|profile| {
                            profile.client_connect_ownership.is_some()
                        }) && self.webtransport.as_ref().is_some_and(|runtime| {
                            runtime.is_terminal(stream_id)
                        });
                    if bounded_terminal_connect {
                        if !ctx.fin_or_reset_sent {
                            ctx.queued_frame =
                                Some(OutboundFrame::Body(Bytes::new(), true));
                            continue;
                        }
                        ctx.recv = None;
                        break;
                    }
                    if !ctx.fin_or_reset_sent &&
                        ctx.associated_dgram_flow_id.is_none()
                    // The channel might be closed if the stream was used to
                    // initiate a datagram exchange.
                    // TODO: ideally, the application would still shut down the
                    // stream properly. Once applications code
                    // is fixed, we can remove this check.
                    {
                        // The channel closed without having written a fin. Send a
                        // RESET_STREAM to indicate we won't be writing anything
                        // else
                        let err = h3::WireErrorCode::RequestCancelled as u64;
                        let _ = qconn.stream_shutdown(
                            stream_id,
                            quiche::Shutdown::Write,
                            err,
                        );
                        ctx.handle_sent_reset(err);
                        if ctx.both_directions_done() {
                            return self.cleanup_stream(qconn, stream_id);
                        }
                    }
                    break;
                },
                Err(TryRecvError::Empty) => {
                    self.waiting_streams.push(ctx.wait_for_recv(stream_id));
                    break;
                },
            }
        }

        Ok(())
    }

    /// Tests `qconn` for either a local or peer error and increments
    /// the associated HTTP/3 or QUIC error counter.
    fn record_quiche_error(qconn: &mut QuicheConnection, metrics: &impl Metrics) {
        // split metrics between local/peer and QUIC/HTTP/3 level errors
        if let Some(err) = qconn.local_error() {
            if err.is_app {
                metrics.local_h3_conn_close_error_count(err.error_code.into())
            } else {
                metrics.local_quic_conn_close_error_count(err.error_code.into())
            }
            .inc();
        } else if let Some(err) = qconn.peer_error() {
            if err.is_app {
                metrics.peer_h3_conn_close_error_count(err.error_code.into())
            } else {
                metrics.peer_quic_conn_close_error_count(err.error_code.into())
            }
            .inc();
        }
    }
}

impl<H: DriverHooks> ApplicationOverQuic for H3Driver<H> {
    fn on_conn_established(
        &mut self, quiche_conn: &mut QuicheConnection,
        handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        if let Some(profile) = self.bounded_profile.as_ref() {
            match profile.verify_live(quiche_conn, handshake_info) {
                Ok(_) => {},
                Err(error) => {
                    profile.record_live(Err(error.clone()));
                    return Err(H3ConnectionError::BoundedProfile(error).into());
                },
            }
        }
        let conn = h3::Connection::with_transport(quiche_conn, &self.h3_config)?;
        self.conn = Some(conn);

        H::conn_established(self, quiche_conn, handshake_info)?;
        self.ensure_event_lane_available()?;
        Ok(())
    }

    #[inline]
    fn should_act(&self) -> bool {
        self.conn.is_some()
    }

    /// Poll the underlying [`quiche::h3::Connection`] for
    /// [`quiche::h3::Event`]s and DATAGRAMs, delegating processing to
    /// `Self::process_read_event`.
    ///
    /// If a DATAGRAM is found, it is sent to the receiver on its channel.
    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.ensure_event_lane_available()?;
        self.process_raw_stream_reads(qconn)?;

        loop {
            match self.conn_mut()?.poll(qconn) {
                Ok((stream_id, event)) =>
                    self.process_read_event(qconn, stream_id, event)?,
                Err(h3::Error::Done) => break,
                Err(err) => {
                    // Don't bubble error up, instead keep the worker loop going
                    // until quiche reports the connection is
                    // closed.
                    log::debug!("connection closed due to h3 protocol error"; "error"=>?err);
                    return Ok(());
                },
            };
        }

        // SETTINGS can be consumed entirely on the peer control stream without
        // producing an application event. Synchronize after the poll pass so a
        // client CONNECT waiting on negotiation cannot deadlock.
        self.forward_settings(qconn)?;
        self.process_webtransport_stream_credit_updates(qconn);
        self.process_webtransport_readable_wakes(qconn);
        self.process_deferred_webtransport_capsules(qconn)?;
        self.process_available_dgrams(qconn)?;
        if let Some(runtime) = self.webtransport.as_mut() {
            runtime.process_datagram_waiters(qconn);
        }
        self.ensure_event_lane_available()?;
        Ok(())
    }

    /// Write as much data as possible into the [`quiche::h3::Connection`] from
    /// all sources. This will attempt to write any queued frames into their
    /// respective streams, if writable.
    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.ensure_event_lane_available()?;
        if let Some(runtime) = self.webtransport.as_mut() {
            runtime.process_datagram_waiters(qconn);
        }

        let retry_deferred = self
            .webtransport
            .as_ref()
            .is_some_and(WebTransportRuntime::has_deferred_responses) &&
            self.conn.as_ref().is_some_and(|conn| {
                webtransport_requirements(conn, qconn) !=
                    WebTransportRequirements::Pending
            });
        if retry_deferred {
            let deferred = self
                .webtransport
                .as_mut()
                .expect("deferred responses require a runtime")
                .take_deferred_responses();
            for stream_id in deferred {
                self.process_writable_stream(qconn, stream_id)?;
            }
        }

        self.process_webtransport_io(qconn)?;

        if let Some(runtime) = self.webtransport.as_mut() {
            let events = runtime.process_work(qconn);
            Self::emit_webtransport_events(&self.h3_event_sender, events)?;
        }

        while let Some(stream_id) = qconn.stream_writable_next() {
            if self.webtransport.as_mut().is_some_and(|runtime| {
                runtime.process_owned_writable(qconn, stream_id)
            }) {
                continue;
            }
            self.process_writable_stream(qconn, stream_id)?;
        }

        // Also optimistically check for any ready streams
        while let Some(Some(ready)) = self.waiting_streams.next().now_or_never() {
            self.upstream_ready(qconn, ready)?;
        }

        self.process_deferred_webtransport_capsules(qconn)?;
        if let Some(runtime) = self.webtransport.as_mut() {
            runtime.process_datagram_waiters(qconn);
        }

        self.ensure_event_lane_available()?;
        Ok(())
    }

    /// Reports connection-level error metrics and forwards
    /// IOWorker errors to the associated [H3Controller].
    fn on_conn_close<M: Metrics>(
        &mut self, quiche_conn: &mut QuicheConnection, metrics: &M,
        work_loop_result: &QuicResult<()>,
    ) {
        let max_stream_seen = self.max_stream_seen;
        metrics
            .maximum_writable_streams()
            .observe(max_stream_seen as f64);

        Self::record_quiche_error(quiche_conn, metrics);

        self.close_webtransport_command_lane();
        if let Some(runtime) = self.webtransport.as_mut() {
            let events = runtime.clear();
            let _ = Self::emit_webtransport_events(&self.h3_event_sender, events);
        }

        if self.h3_event_sender.overloaded() {
            let _ = quiche_conn.close(
                true,
                WireErrorCode::ExcessiveLoad as u64,
                b"H3 application event queue overloaded",
            );
            return;
        }

        let Err(work_loop_error) = work_loop_result else {
            return;
        };

        let Some(h3_err) = work_loop_error.downcast_ref::<H3ConnectionError>()
        else {
            log::error!("Found non-H3ConnectionError"; "error" => %work_loop_error);
            return;
        };

        if matches!(h3_err, H3ConnectionError::ControllerWentAway) {
            // Inform client that we won't (can't) respond anymore
            let _ = quiche_conn.close(true, WireErrorCode::NoError as u64, &[]);
            return;
        }

        if let Some(ev) = H3Event::from_error(h3_err) {
            let _ = self.h3_event_sender.send(ev.into());
            #[expect(clippy::needless_return)]
            return; // avoid accidental fallthrough in the future
        }
    }

    /// Wait for incoming data from the [H3Controller]. The next iteration of
    /// the I/O loop commences when one of the `select!`ed futures triggers.
    #[inline]
    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        let webtransport_work =
            self.webtransport.as_ref().is_some_and(|runtime| {
                runtime.has_work() ||
                    runtime.has_legacy_datagrams() ||
                    runtime.has_ready_datagram_waiter(qconn) ||
                    (runtime.has_deferred_responses() &&
                        self.conn.as_ref().is_some_and(|conn| {
                            webtransport_requirements(conn, qconn) !=
                                WebTransportRequirements::Pending
                        }))
            }) || (self.webtransport.is_some() &&
                qconn.dgram_recv_queue_len() != 0);
        let webtransport_datagram_deadline = self
            .webtransport
            .as_ref()
            .and_then(WebTransportRuntime::next_provisional_datagram_deadline);
        select! {
            biased;
            _ = std::future::ready(()), if self.h3_event_sender.overloaded() => {
                Err(H3ConnectionError::EventQueueOverloaded)
            },
            _ = std::future::ready(()), if webtransport_work => Ok(()),
            Some(ready) = self.waiting_streams.next() => self.upstream_ready(qconn, ready),
            Some(dgram) = self.dgram_recv.recv() => self.dgram_ready(qconn, dgram),
            Some(command) = receive_webtransport_command(&mut self.webtransport_cmd_recv) => {
                self.handle_webtransport_command(qconn, command)
            },
            _ = wait_for_webtransport_datagram_deadline(webtransport_datagram_deadline) => Ok(()),
            Some(cmd) = self.cmd_recv.recv() => H::conn_command(self, qconn, cmd),
            r = self.hooks.wait_for_action(qconn), if H::has_wait_action(self) => r,
            _ = self.h3_event_sender.closed(), if !self.h3_event_receiver_dropped => {
                self.h3_event_receiver_dropped = true;
                self.close_if_idle(qconn);
                Ok(())
            }
        }?;

        // Make sure controller is not starved, but also not prioritized in the
        // biased select. So poll it last, however also perform a try_recv
        // each iteration.
        if let Ok(cmd) = self.cmd_recv.try_recv() {
            H::conn_command(self, qconn, cmd)?;
        }

        Ok(())
    }
}

impl<H: DriverHooks> Drop for H3Driver<H> {
    fn drop(&mut self) {
        self.close_webtransport_command_lane();
        if let Some(runtime) = self.webtransport.as_mut() {
            let _ = runtime.clear();
        }
        if let Some(ownership) = self
            .bounded_profile
            .as_ref()
            .and_then(|profile| profile.client_connect_ownership.as_ref())
        {
            ownership.clear();
        }
        for stream in self.stream_map.values() {
            stream
                .audit_stats
                .set_recvd_stream_fin(StreamClosureKind::Implicit);
        }
    }
}

/// [`H3Command`]s are sent by the [H3Controller] to alter the [H3Driver]'s
/// state.
///
/// Both [ServerH3Driver] and [ClientH3Driver] may extend this enum with
/// endpoint-specific variants.
#[derive(Debug)]
pub enum H3Command {
    /// A connection-level command that executes directly on the
    /// [`quiche::Connection`].
    QuicCmd(QuicCommand),
    /// Send a GOAWAY frame to the peer to initiate a graceful connection
    /// shutdown.
    GoAway,
    /// Shuts down a stream in the specified direction(s) and removes it from
    /// local state.
    ///
    /// This removes the stream from local state and sends a `RESET_STREAM`
    /// frame (for write direction) and/or a `STOP_SENDING` frame (for read
    /// direction) to the peer. See [`quiche::Connection::stream_shutdown`]
    /// for details.
    ShutdownStream {
        stream_id: u64,
        shutdown: StreamShutdown,
    },
    /// Sends WT_CLOSE_SESSION and FIN on one active CONNECT stream.
    CloseWebTransportSession {
        /// CONNECT stream ID and WebTransport Session ID.
        session_id: u64,
        /// Application-defined 32-bit close code.
        error_code: u32,
        /// UTF-8 close message, limited to 1024 encoded bytes.
        message: String,
    },
}

/// Result of admitting a non-buffer-bearing command to the H3 driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H3CommandAdmission {
    /// The command was admitted to the bounded queue.
    Accepted,
    /// The bounded command queue has no capacity.
    QueueFull,
    /// The paired H3 driver is no longer accepting commands.
    DriverGone,
}

/// Specifies which direction(s) of a stream to shut down.
///
/// Used with [`H3Controller::shutdown_stream`] and the internal
/// `shutdown_stream` function to control whether to send a `STOP_SENDING` frame
/// (read direction), and/or a `RESET_STREAM` frame (write direction)
///
/// Note: Despite its name, "shutdown" here refers to signaling the peer about
/// stream termination, not sending a FIN flag. `STOP_SENDING` asks the peer to
/// stop sending data, while `RESET_STREAM` abruptly terminates the write side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamShutdown {
    /// Shut down only the read direction (sends `STOP_SENDING` frame with the
    /// given error code).
    Read { error_code: u64 },
    /// Shut down only the write direction (sends `RESET_STREAM` frame with the
    /// given error code).
    Write { error_code: u64 },
    /// Shut down both directions (sends both `STOP_SENDING` and `RESET_STREAM`
    /// frames).
    Both {
        read_error_code: u64,
        write_error_code: u64,
    },
}

/// Sends [`H3Command`]s to an [H3Driver]. The sender is typed and internally
/// wraps instances of `T` in the appropriate `H3Command` variant.
pub struct RequestSender<C, T> {
    sender: mpsc::Sender<C>,
    // Required to work around dangling type parameter
    _r: PhantomData<fn() -> T>,
}

impl<C, T: Into<C>> RequestSender<C, T> {
    /// Attempts to admit a request without waiting.
    ///
    /// A full or closed lane returns the converted command and all ownership
    /// it contains.
    #[inline(always)]
    pub fn send(&self, v: T) -> Result<(), mpsc::error::TrySendError<C>> {
        self.sender.try_send(v.into())
    }
}

impl<C, T> Clone for RequestSender<C, T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            _r: Default::default(),
        }
    }
}

/// Interface to communicate with a paired [H3Driver].
///
/// An [H3Controller] receives [`H3Event`]s from its driver, which must be
/// consumed by the application built on top of the driver to react to incoming
/// events. The controller also allows the application to send ad-hoc
/// [`H3Command`]s to the driver, which will be processed when the driver waits
/// for incoming data.
pub struct H3Controller<H: DriverHooks> {
    /// Sends [`H3Command`]s to the [H3Driver], like [`QuicCommand`]s or
    /// outbound HTTP requests.
    cmd_sender: mpsc::Sender<H::Command>,
    /// Receives [`H3Event`]s from the [H3Driver]. Can be extracted and
    /// used independently of the [H3Controller].
    h3_event_recv: Option<mpsc::Receiver<H::Event>>,
    h3_event_state: Arc<H3EventLaneState>,
    /// Native selected-I/O controller when draft-16 support is enabled.
    webtransport: Option<WebTransportController>,
}

impl<H: DriverHooks> H3Controller<H> {
    /// Returns a clone of the native draft-16 selected-I/O controller.
    ///
    /// This is `None` unless [`Http3Settings::enable_webtransport`] was set
    /// when the paired driver was constructed. Peer negotiation and exact
    /// Session ID lifecycle are validated when each operation is processed.
    pub fn webtransport_controller(&self) -> Option<WebTransportController> {
        self.webtransport.clone()
    }

    /// Gets a mut reference to the [`H3Event`] receiver for the paired
    /// [H3Driver].
    pub fn event_receiver_mut(&mut self) -> &mut mpsc::Receiver<H::Event> {
        self.h3_event_recv
            .as_mut()
            .expect("No event receiver on H3Controller")
    }

    /// Takes the [`H3Event`] receiver for the paired [H3Driver].
    pub fn take_event_receiver(&mut self) -> mpsc::Receiver<H::Event> {
        self.h3_event_recv
            .take()
            .expect("No event receiver on H3Controller")
    }

    /// Returns monotonic bounded-event-lane accounting.
    pub fn event_queue_stats(&self) -> H3EventQueueStats {
        self.h3_event_state.stats()
    }

    /// Creates a [`QuicCommand`] sender for the paired [H3Driver].
    pub fn cmd_sender(&self) -> RequestSender<H::Command, QuicCommand> {
        RequestSender {
            sender: self.cmd_sender.clone(),
            _r: Default::default(),
        }
    }

    /// Sends a GOAWAY frame to initiate a graceful connection shutdown.
    pub fn send_goaway(&self) -> H3CommandAdmission {
        match self.cmd_sender.try_reserve() {
            Ok(permit) => {
                permit.send(H3Command::GoAway.into());
                H3CommandAdmission::Accepted
            },
            Err(mpsc::error::TrySendError::Full(())) =>
                H3CommandAdmission::QueueFull,
            Err(mpsc::error::TrySendError::Closed(())) =>
                H3CommandAdmission::DriverGone,
        }
    }

    /// Creates an [`H3Command`] sender for the paired [H3Driver].
    pub fn h3_cmd_sender(&self) -> RequestSender<H::Command, H3Command> {
        RequestSender {
            sender: self.cmd_sender.clone(),
            _r: Default::default(),
        }
    }

    /// Shuts down a stream in the specified direction(s) and removes it from
    /// local state.
    ///
    /// This removes the stream from local state and sends a `RESET_STREAM`
    /// frame (for write direction) and/or a `STOP_SENDING` frame (for read
    /// direction) to the peer, depending on the [`StreamShutdown`] variant.
    pub fn shutdown_stream(
        &self, stream_id: u64, shutdown: StreamShutdown,
    ) -> H3CommandAdmission {
        match self.cmd_sender.try_reserve() {
            Ok(permit) => {
                permit.send(
                    H3Command::ShutdownStream {
                        stream_id,
                        shutdown,
                    }
                    .into(),
                );
                H3CommandAdmission::Accepted
            },
            Err(mpsc::error::TrySendError::Full(())) =>
                H3CommandAdmission::QueueFull,
            Err(mpsc::error::TrySendError::Closed(())) =>
                H3CommandAdmission::DriverGone,
        }
    }

    /// Queues WT_CLOSE_SESSION followed by FIN for an active session.
    ///
    /// The session becomes terminal only after H3 accepts the complete capsule
    /// and FIN. Duplicate, unknown, pending, or already-terminal session IDs
    /// are ignored by the driver.
    pub fn close_webtransport_session(
        &self, session_id: u64, error_code: u32, message: String,
    ) -> Result<(), WebTransportSessionCloseError> {
        if message.len() > webtransport::MAX_CLOSE_MESSAGE_LEN {
            return Err(WebTransportSessionCloseError::MessageTooLong {
                len: message.len(),
                message,
            });
        }
        match self.cmd_sender.try_reserve() {
            Ok(permit) => {
                // `into_boxed_str()` discards caller over-capacity before the
                // accepted command can retain the message.
                let message = message.into_boxed_str().into_string();
                permit.send(
                    H3Command::CloseWebTransportSession {
                        session_id,
                        error_code,
                        message,
                    }
                    .into(),
                );
                Ok(())
            },
            Err(mpsc::error::TrySendError::Full(())) =>
                Err(WebTransportSessionCloseError::QueueFull {
                    session_id,
                    error_code,
                    message,
                }),
            Err(mpsc::error::TrySendError::Closed(())) =>
                Err(WebTransportSessionCloseError::DriverGone {
                    session_id,
                    error_code,
                    message,
                }),
        }
    }
}
