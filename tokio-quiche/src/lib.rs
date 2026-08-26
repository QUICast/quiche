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

#![allow(clippy::collapsible_match)]

//! Bridging the gap between [quiche] and [tokio].
//!
//! tokio-quiche connects [quiche::Connection]s and [quiche::h3::Connection]s to
//! tokio's event loop. Users have the choice between implementing their own,
//! custom [`ApplicationOverQuic`] or using the ready-made
//! [H3Driver](crate::http3::driver::H3Driver) for HTTP/3 clients and servers.
//!
//! # Starting an HTTP/3 Server
//!
//! A server [`listen`]s on a UDP socket for QUIC connections and spawns a new
//! tokio task to handle each individual connection.
//!
//! ```
//! use futures::stream::StreamExt;
//! use tokio_quiche::http3::settings::Http3Settings;
//! use tokio_quiche::listen;
//! use tokio_quiche::metrics::DefaultMetrics;
//! use tokio_quiche::quic::SimpleConnectionIdGenerator;
//! use tokio_quiche::ConnectionParams;
//! use tokio_quiche::ServerH3Driver;
//!
//! # async fn example() -> tokio_quiche::QuicResult<()> {
//! let socket = tokio::net::UdpSocket::bind("0.0.0.0:443").await?;
//! let mut listeners =
//!     listen([socket], ConnectionParams::default(), DefaultMetrics)?;
//! let mut accept_stream = &mut listeners[0];
//!
//! while let Some(conn) = accept_stream.next().await {
//!     let (driver, mut controller) =
//!         ServerH3Driver::new(Http3Settings::default());
//!     conn?.start(driver);
//!
//!     tokio::spawn(async move {
//!         // `controller` is the handle to our established HTTP/3 connection.
//!         // For example, inbound requests are available as H3Events via:
//!         let event = controller.event_receiver_mut().recv().await;
//!     });
//! }
//! # Ok(())
//! # }
//! ```
//!
//! For client-side use cases, check out our [`connect`](crate::quic::connect)
//! API.
//!
//! # Feature Flags
//!
//! tokio-quiche supports a number of feature flags to enable experimental
//! features, performance enhancements, and additional telemetry.
//!
//! Enabled by default:
//!
//! - `qlog-gzip`: Forwards to the `qlog` crate's `gzip` feature so QLOG output
//!   can be emitted as `.sqlog.gz` via `flate2`.
//! - `qlog-zstd`: Forwards to the `qlog` crate's `zstd` feature so QLOG output
//!   can be emitted as `.sqlog.zst`. Pulls in the `zstd` crate (C dependency
//!   via `zstd-sys`).
//!
//! Both compression features may be enabled together; the algorithm
//! is selected per connection at runtime via
//! [`settings::QuicSettings::qlog_compression`]. Disable both with
//! `default-features = false` to opt out of the extra dependencies;
//! the default `QlogCompression::None` keeps writing raw `.sqlog`
//! files in that configuration.
//!
//! Off by default:
//!
//! - `rpk`: Support for raw public keys (RPK) in QUIC handshakes (via
//!   [boring]).
//! - `gcongestion`: Replace quiche's original congestion control implementation
//!   with one adapted from google/quiche.
//! - `zero-copy`: Deprecated. Zero-copy sends are now always enabled. This
//!   feature is kept for backwards compatibility and only enables
//!   `gcongestion`.
//! - `perf-quic-listener-metrics`: Extra telemetry for QUIC handshake
//!   durations, including protocol overhead and network delays.
//! - `tokio-task-metrics`: Scheduling & poll duration histograms for tokio
//!   tasks.
//! - `multicast`: IPv4-first multicast client receive and server send
//!   integration backed by `mcrx-core` and `mctx-core`.
//!
//! Other parts of the crate are enabled by separate build flags instead, to be
//! controlled by the final binary:
//!
//! - `--cfg capture_keylogs`: Optional `SSLKEYLOGFILE` capturing for QUIC
//!   connections.

pub extern crate quiche;

pub mod buf_factory;
pub mod http3;
pub mod metrics;
#[cfg(feature = "multicast")]
pub mod multicast;
pub mod quic;
mod result;
pub mod settings;
pub mod socket;

pub use datagram_socket;

use foundations::telemetry::settings::LogVerbosity;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Once;
use std::task::Context;
use std::task::Poll;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio_stream::Stream;

use crate::metrics::Metrics;
use crate::socket::QuicListener;

pub use crate::http3::driver::ClientH3Controller;
pub use crate::http3::driver::ClientH3Driver;
pub use crate::http3::driver::ServerH3Controller;
pub use crate::http3::driver::ServerH3Driver;
pub use crate::http3::ClientH3Connection;
pub use crate::http3::ServerH3Connection;
pub use crate::quic::connection::ApplicationOverQuic;
pub use crate::quic::connection::ConnectionIdGenerator;
#[doc(hidden)]
pub use crate::quic::connection::ConnectionOwnerDropHook;
pub use crate::quic::connection::InitialQuicConnection;
pub use crate::quic::connection::QuicConnection;
pub use crate::quic::QuicListenerCompletion;
pub use crate::quic::QuicListenerFailure;
pub use crate::quic::QuicListenerTerminal;
pub use crate::quic::QuicListenerTerminalOutcome;
pub use crate::quic::QuicListenerTerminalWait;
pub use crate::result::BoxError;
pub use crate::result::QuicResult;
pub use crate::settings::ConnectionParams;

#[doc(hidden)]
pub use crate::result::QuicResultExt;

/// One rejected QUIC Initial observed while the listener backlog was full.
///
/// Events retain only the latest address sample. `rejected_total` is an exact,
/// monotonically increasing count, so coalescing never hides how many Initials
/// were rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialBacklogOverflow {
    /// Local listener address that received the rejected Initial.
    pub local_addr: SocketAddr,
    /// Peer address that sent the rejected Initial.
    pub peer_addr: SocketAddr,
    /// Exact cumulative overflow rejection count for this listener.
    pub rejected_total: u64,
    /// Configured accepted-connection backlog capacity.
    pub backlog_capacity: usize,
}

/// Bounded latest-only receiver for listener-backlog overflow events.
///
/// Each receiver observes a level-triggered latest event. If several rejections
/// occur before it polls, the newest event carries their exact cumulative
/// total.
#[derive(Debug)]
pub struct InitialBacklogOverflowEvents {
    receiver: watch::Receiver<Option<InitialBacklogOverflow>>,
    last_seen_total: u64,
}

impl InitialBacklogOverflowEvents {
    fn new(receiver: watch::Receiver<Option<InitialBacklogOverflow>>) -> Self {
        Self {
            receiver,
            last_seen_total: 0,
        }
    }

    /// Receives the next unseen cumulative overflow event.
    pub async fn recv(&mut self) -> Option<InitialBacklogOverflow> {
        loop {
            if let Some(event) = self.try_recv() {
                return Some(event);
            }
            if self.receiver.changed().await.is_err() {
                return self.try_recv();
            }
        }
    }

    /// Returns the latest event when its cumulative total has not been seen.
    pub fn try_recv(&mut self) -> Option<InitialBacklogOverflow> {
        let event = *self.receiver.borrow();
        let event =
            event.filter(|event| event.rejected_total > self.last_seen_total)?;
        self.last_seen_total = event.rejected_total;
        self.receiver.borrow_and_update();
        Some(event)
    }

    /// Returns the latest retained event without marking it observed.
    pub fn latest(&self) -> Option<InitialBacklogOverflow> {
        *self.receiver.borrow()
    }
}

/// A stream of accepted [`InitialQuicConnection`]s from a [`listen`] call.
///
/// Errors from processing the client's QUIC initials can also be emitted on
/// this stream. These do not indicate that the listener itself has failed.
/// Retain [`QuicConnectionStream::listener_terminal`] before closing or
/// dropping the stream when authoritative listener cleanup must be observed.
pub struct QuicConnectionStream<M: Metrics> {
    connections: mpsc::Receiver<io::Result<InitialQuicConnection<UdpSocket, M>>>,
    overflow_events: watch::Receiver<Option<InitialBacklogOverflow>>,
    listener_terminal: QuicListenerTerminal,
    listener_shutdown: Option<oneshot::Sender<()>>,
}

impl<M: Metrics> QuicConnectionStream<M> {
    pub(crate) fn new(
        connections: mpsc::Receiver<
            io::Result<InitialQuicConnection<UdpSocket, M>>,
        >,
        overflow_events: watch::Receiver<Option<InitialBacklogOverflow>>,
        listener_terminal: QuicListenerTerminal,
        listener_shutdown: oneshot::Sender<()>,
    ) -> Self {
        Self {
            connections,
            overflow_events,
            listener_terminal,
            listener_shutdown: Some(listener_shutdown),
        }
    }

    /// Receives the next accepted connection or Initial-processing error.
    pub async fn recv(
        &mut self,
    ) -> Option<io::Result<InitialQuicConnection<UdpSocket, M>>> {
        self.connections.recv().await
    }

    /// Attempts to receive an accepted connection without waiting.
    pub fn try_recv(
        &mut self,
    ) -> Result<
        io::Result<InitialQuicConnection<UdpSocket, M>>,
        mpsc::error::TryRecvError,
    > {
        self.connections.try_recv()
    }

    /// Closes the accepted-connection lane and asks the listener to shut down.
    pub fn close(&mut self) {
        self.connections.close();
        drop(self.listener_shutdown.take());
    }

    /// Returns the bounded terminal capability for this listener.
    ///
    /// Retain this capability before dropping the accepted-connection stream
    /// to observe when the listener task and all listener-owned resources have
    /// actually been released. Clones compete for one terminal result and do
    /// not keep the listener alive.
    pub fn listener_terminal(&self) -> QuicListenerTerminal {
        self.listener_terminal.clone()
    }

    /// Returns an independently consumable bounded overflow-event receiver.
    pub fn initial_backlog_overflows(&self) -> InitialBacklogOverflowEvents {
        InitialBacklogOverflowEvents::new(self.overflow_events.clone())
    }

    /// Returns the latest overflow event without consuming it.
    pub fn latest_initial_backlog_overflow(
        &self,
    ) -> Option<InitialBacklogOverflow> {
        *self.overflow_events.borrow()
    }
}

impl<M: Metrics> Drop for QuicConnectionStream<M> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<M: Metrics> Stream for QuicConnectionStream<M> {
    type Item = io::Result<InitialQuicConnection<UdpSocket, M>>;

    fn poll_next(
        self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.get_mut().connections.poll_recv(cx)
    }
}

/// Starts listening for inbound QUIC connections on the given
/// [`QuicListener`]s.
///
/// Each socket starts a separate tokio task to process and route inbound
/// packets. This task emits connections on the respective
/// [`QuicConnectionStream`] after receiving the client's QUIC initial and
/// (optionally) validating its IP address.
///
/// The task shuts down when the returned stream is closed (or dropped) and all
/// previously-yielded connections are closed. A stream's
/// [`QuicConnectionStream::listener_terminal`] capability distinguishes clean
/// completion from listener failure after all listener-owned resources have
/// been released.
pub fn listen_with_capabilities<M>(
    sockets: impl IntoIterator<Item = QuicListener>, params: ConnectionParams,
    metrics: M,
) -> io::Result<Vec<QuicConnectionStream<M>>>
where
    M: Metrics,
{
    if params.settings.capture_quiche_logs {
        capture_quiche_logs();
    }

    sockets
        .into_iter()
        .map(|s| crate::quic::start_listener(s, &params, metrics.clone()))
        .collect()
}

/// Starts listening for inbound QUIC connections on the given `sockets`.
///
/// Each socket is converted into a [`QuicListener`] with defaulted socket
/// parameters. The listeners are then passed to [`listen_with_capabilities`].
pub fn listen<S, M>(
    sockets: impl IntoIterator<Item = S>, params: ConnectionParams, metrics: M,
) -> io::Result<Vec<QuicConnectionStream<M>>>
where
    S: TryInto<QuicListener, Error = io::Error>,
    M: Metrics,
{
    let quic_sockets: Vec<QuicListener> = sockets
        .into_iter()
        .map(|s| {
            #[cfg_attr(not(target_os = "linux"), expect(unused_mut))]
            let mut socket = s.try_into()?;
            #[cfg(target_os = "linux")]
            socket.apply_max_capabilities();
            Ok(socket)
        })
        .collect::<io::Result<_>>()?;

    listen_with_capabilities(quic_sockets, params, metrics)
}

static GLOBAL_LOGGER_ONCE: Once = Once::new();

/// Forward Quiche logs into the slog::Drain currently used by Foundations
///
/// # Warning
///
/// This should **only be used for local debugging**. Quiche can potentially
/// emit lots (and lots, and lots) of logs (the TRACE level emits a log record
/// on every packet and frame) and you can very easily overwhelm your logging
/// pipeline.
///
/// # Note
///
/// Quiche uses the `env_logger` crate, which uses `log` under the hood. `log`
/// requires that you only set the global logger once. That means that we have
/// to register the logger at `listen()` time for servers - for clients, we
/// should register loggers when the `quiche::Connection` is established.
pub(crate) fn capture_quiche_logs() {
    GLOBAL_LOGGER_ONCE.call_once(|| {
        use foundations::telemetry::log as foundations_log;
        use log::Level as std_level;

        let curr_logger =
            Arc::clone(&foundations_log::slog_logger()).read().clone();
        let scope_guard = slog_scope::set_global_logger(curr_logger);

        // Convert slog::Level from Foundations settings to log::Level
        let normalized_level = match foundations_log::verbosity() {
            LogVerbosity::Critical | LogVerbosity::Error => std_level::Error,
            LogVerbosity::Warning => std_level::Warn,
            LogVerbosity::Info => std_level::Info,
            LogVerbosity::Debug => std_level::Debug,
            LogVerbosity::Trace => std_level::Trace,
        };

        slog_stdlog::init_with_level(normalized_level).unwrap();

        // The slog Drain becomes `slog::Discard` when the scope_guard is dropped,
        // and you can't set the global logger again because of a mandate
        // in the `log` crate. We have to retain the scope guard so that the
        // logger remains registered for the duration of the process.
        let _scope_guard = std::mem::ManuallyDrop::new(scope_guard);
    });
}
