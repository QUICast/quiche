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

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;

use futures::task::AtomicWaker;
use pin_project::pin_project;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::metrics::Metrics;
use crate::QuicConnectionStream;

pub(crate) fn spawn_router<M, F>(
    metrics: M, router: F, release: Arc<ReleaseState>,
) -> QuicListenerTerminal
where
    M: Metrics,
    F: Future<Output = io::Result<()>> + Send + 'static,
{
    let task = crate::metrics::tokio_task::spawn_catching(
        "quic_udp_listener",
        metrics,
        async move {
            match router.await {
                Ok(()) => QuicListenerCompletion::Clean,
                Err(error) => {
                    let failure = if error.get_ref().is_some_and(|e| {
                        e.is::<super::router::ConnectionMapLaneSaturated>()
                    }) {
                        QuicListenerFailure::ConnectionMapCommandLaneSaturated
                    } else {
                        QuicListenerFailure::RouterIo { kind: error.kind() }
                    };
                    foundations::telemetry::log::error!("incoming packet router failed"; "error"=>error);
                    QuicListenerCompletion::Failed(failure)
                },
            }
        },
    );
    QuicListenerTerminal::new(task, release)
}

/// Why the listener router did not finish gracefully. No peer data is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicListenerFailure {
    /// The bounded Connection-ID command lane saturated (existing fail-stop).
    ConnectionMapCommandLaneSaturated,
    /// A terminal router error, reduced to its finite I/O category.
    RouterIo {
        /// The error category, without its text or platform payload.
        kind: io::ErrorKind,
    },
    /// The runtime cancelled the task, including runtime shutdown.
    TaskCancelled,
    /// The router task panicked. The public result contains no panic payload.
    TaskPanicked,
    /// An auxiliary send or backlog destructor was interrupted. Destruction
    /// has finished, but successful delivery/cleanup is not claimed.
    AncillaryTaskInterrupted,
}

/// Result of joining one router, after its task future has been destroyed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicListenerCompletion {
    /// Admission stopped, all Initial/worker shutdown guards were released,
    /// and the router destroyed its socket references, configuration, maps,
    /// buffers and lane endpoints. The accept receiver and auxiliary replies
    /// were also destroyed. This is not connection/application accounting.
    Clean,
    /// The router task, accept receiver and auxiliary replies were destroyed
    /// without graceful completion. Delivered connections remain separately
    /// owned; this result does not claim their release or success.
    Failed(QuicListenerFailure),
}

/// Take-once observation of a listener task's terminal disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicListenerTerminalOutcome {
    /// No authoritative task completion is available yet.
    Pending,
    /// The sole terminal result, consumed by this observation.
    Taken(QuicListenerCompletion),
    /// The terminal result has already been consumed.
    AlreadyTaken,
}

/// Independent, take-once completion capability for one listener router.
///
/// This is not a shutdown command and cannot abort the router. It holds the
/// existing task's join capability, not socket/map/connection references or a
/// second task. Exclusive borrowing bounds observation to one waiter. Dropping
/// it detaches observation, without preventing cleanup or stopping routing.
/// Once lost, completion cannot be recovered; loss is never evidence of zero.
/// Caller-retained handles/results and executor metadata need caller budgeting.
/// The release barrier also tracks existing auxiliary sends, but does not
/// impose a bound on their population. A stalled send can delay completion
/// indefinitely. This capability proves neither all helper tasks joined nor
/// all application/reporting tasks gone.
#[must_use = "retain the terminal capability until listener cleanup is observed"]
pub struct QuicListenerTerminal {
    task: Option<JoinHandle<Result<QuicListenerCompletion, ()>>>,
    joined: Option<QuicListenerCompletion>,
    release: Arc<ReleaseState>,
    wake: Waker,
    taken: bool,
}

impl std::fmt::Debug for QuicListenerTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicListenerTerminal")
            .finish_non_exhaustive()
    }
}

impl QuicListenerTerminal {
    pub(crate) fn new(
        task: JoinHandle<Result<QuicListenerCompletion, ()>>,
        release: Arc<ReleaseState>,
    ) -> Self {
        Self {
            task: Some(task),
            joined: None,
            wake: Waker::from(Arc::clone(&release)),
            release,
            taken: false,
        }
    }

    /// Waits without polling timers or sending commands. Cancelling this
    /// borrowed future (including an external timeout) preserves the result
    /// and permits another wait. Timeout is not a completion outcome.
    pub fn wait(&mut self) -> QuicListenerTerminalWait<'_> {
        QuicListenerTerminalWait { terminal: self }
    }

    /// Makes one nonblocking observation, returning `Pending` if still alive.
    /// This is not intended for periodic polling; use [`Self::wait`].
    pub fn try_take(&mut self) -> QuicListenerTerminalOutcome {
        match self.poll_take(&mut Context::from_waker(std::task::Waker::noop())) {
            Poll::Pending => QuicListenerTerminalOutcome::Pending,
            Poll::Ready(result) => result,
        }
    }

    fn poll_take(
        &mut self, cx: &mut Context<'_>,
    ) -> Poll<QuicListenerTerminalOutcome> {
        if self.taken {
            return Poll::Ready(QuicListenerTerminalOutcome::AlreadyTaken);
        }
        self.release.waiter.register(cx.waker());
        if let Some(task) = self.task.as_mut() {
            let result = std::task::ready!(
                Pin::new(task).poll(&mut Context::from_waker(&self.wake))
            );
            // Tokio joins only after destruction of the complete task future,
            // including the router and instrumentation. No pre-drop zero sample.
            drop(self.task.take());
            self.joined = Some(
                result
                    .unwrap_or_else(|error| {
                        Ok(QuicListenerCompletion::Failed(if error.is_panic() {
                            QuicListenerFailure::TaskPanicked
                        } else {
                            QuicListenerFailure::TaskCancelled
                        }))
                    })
                    .unwrap_or(QuicListenerCompletion::Failed(
                        QuicListenerFailure::TaskPanicked,
                    )),
            );
        }
        if self.release.owners.load(Ordering::Acquire) != 0 {
            return Poll::Pending;
        }
        let mut completion = self.joined.take().expect("joined before release");
        if completion == QuicListenerCompletion::Clean &&
            self.release.interrupted.load(Ordering::Acquire)
        {
            completion = QuicListenerCompletion::Failed(
                QuicListenerFailure::AncillaryTaskInterrupted,
            );
        }
        self.release.waiter.take();
        self.taken = true;
        Poll::Ready(QuicListenerTerminalOutcome::Taken(completion))
    }
}

/// Exclusive, allocation-free completion wait. Drop deregisters the caller
/// without consuming a joined result or affecting listener resource ownership.
#[must_use = "futures must be polled or awaited"]
pub struct QuicListenerTerminalWait<'a> {
    terminal: &'a mut QuicListenerTerminal,
}

impl Future for QuicListenerTerminalWait<'_> {
    type Output = QuicListenerTerminalOutcome;

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        self.terminal.poll_take(cx)
    }
}

impl Drop for QuicListenerTerminalWait<'_> {
    fn drop(&mut self) {
        self.terminal.release.waiter.take();
    }
}

impl Drop for QuicListenerTerminal {
    fn drop(&mut self) {
        self.release.waiter.take();
    }
}

/// Admission stream and independent router completion returned together.
///
/// Close `incoming` to stop admission, then drop it to retire its backlog.
/// Settle delivered connections separately, then join `terminal`. The router
/// continues serving delivered connections during graceful admission shutdown.
pub struct QuicListenerEndpoint<M: Metrics> {
    /// Accepted Initials; closing this does not abort delivered connections.
    pub incoming: QuicConnectionStream<M>,
    /// Independently retainable router completion, established before return.
    pub terminal: QuicListenerTerminal,
}

impl<M: Metrics> std::fmt::Debug for QuicListenerEndpoint<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicListenerEndpoint")
            .finish_non_exhaustive()
    }
}

/// Partial startup failure with cleanup authority for every earlier endpoint.
///
/// Earlier streams are already closed for admission, but queued Initials must
/// be drained/dropped and delivered connections settled. Use
/// [`Self::into_parts`] to retain each terminal capability before dropping its
/// stream. Dropping this error requests cleanup, but forfeits observation; it
/// does not prove cleanup.
pub struct QuicListenerStartupError<M: Metrics> {
    pub(crate) error: io::Error,
    pub(crate) started: Vec<QuicListenerEndpoint<M>>,
    pub(crate) failure: QuicListenerStartupFailure,
}

/// Finite startup classification, distinct from earlier routers' completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicListenerStartupFailure {
    /// Socket conversion or listener construction failed normally.
    Io(io::ErrorKind),
    /// No Tokio runtime was available; no endpoint was started.
    RuntimeUnavailable,
    /// An iterator, socket conversion or construction hook panicked.
    /// Its payload is discarded; earlier endpoint cleanup authority is
    /// returned.
    Panicked,
}

impl<M: Metrics> std::fmt::Debug for QuicListenerStartupError<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicListenerStartupError")
            .field("error", &self.error)
            .field("started", &self.started.len())
            .finish()
    }
}

impl<M: Metrics> QuicListenerStartupError<M> {
    /// Finite failure classification, without a panic payload.
    pub fn failure(&self) -> QuicListenerStartupFailure {
        self.failure
    }

    /// The startup failure. Existing router results are observed separately.
    pub fn error(&self) -> &io::Error {
        &self.error
    }

    /// Returns the failure and earlier endpoints, in input order. The number
    /// of endpoints is bounded by the supplied socket collection, not traffic.
    pub fn into_parts(self) -> (io::Error, Vec<QuicListenerEndpoint<M>>) {
        (self.error, self.started)
    }
}

impl<M: Metrics> std::fmt::Display for QuicListenerStartupError<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "listener startup failed: {}", self.error)
    }
}

impl<M: Metrics> std::error::Error for QuicListenerStartupError<M> {}

/// Receiver closure must actively wake an idle router. Register-before-check
/// in the router pairs with close-before-wake here to avoid lost wakeups.
pub(crate) struct AcceptReceiver<T> {
    receiver: Option<mpsc::Receiver<T>>,
    wake: Arc<AtomicWaker>,
    release: Option<ReleaseToken>,
}

impl<T> AcceptReceiver<T> {
    pub(crate) fn new(
        receiver: mpsc::Receiver<T>, wake: Arc<AtomicWaker>,
    ) -> Self {
        Self {
            receiver: Some(receiver),
            wake,
            release: None,
        }
    }

    pub(crate) fn track_release(&mut self, token: ReleaseToken) {
        self.release = Some(token);
    }

    pub(crate) async fn recv(&mut self) -> Option<T> {
        self.receiver.as_mut().unwrap().recv().await
    }

    pub(crate) fn try_recv(&mut self) -> Result<T, mpsc::error::TryRecvError> {
        self.receiver.as_mut().unwrap().try_recv()
    }

    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.receiver.as_mut().unwrap().poll_recv(cx)
    }

    pub(crate) fn close(&mut self) {
        self.receiver.as_mut().unwrap().close();
        self.wake.wake();
    }
}

impl<T> Drop for AcceptReceiver<T> {
    fn drop(&mut self) {
        self.close();
        // Initial shutdown senders drop before their core/socket fields.
        // Acknowledge only AFTER destruction of the complete backlog.
        drop(self.receiver.take());
        if let Some(token) = &mut self.release {
            token.finished = true;
        }
    }
}

/// Fixed values added per managed endpoint. Executor/task/allocator metadata
/// remains in the implementation margin, as for existing router tasks.
pub(crate) const fn completion_metadata_bytes() -> usize {
    std::mem::size_of::<AtomicWaker>() +
        2 * std::mem::size_of::<usize>() +
        2 * std::mem::size_of::<Arc<AtomicWaker>>() +
        std::mem::size_of::<QuicListenerTerminal>() +
        std::mem::size_of::<QuicListenerCompletion>() +
        std::mem::size_of::<ReleaseState>() +
        2 * std::mem::size_of::<usize>() +
        3 * std::mem::size_of::<Option<ReleaseToken>>() +
        std::mem::size_of::<Option<Pin<Box<()>>>>()
}

pub(crate) const fn auxiliary_tracking_bytes() -> usize {
    std::mem::size_of::<Option<ReleaseToken>>()
}

pub(crate) struct ReleaseState {
    owners: AtomicUsize,
    interrupted: AtomicBool,
    waiter: AtomicWaker,
}

impl Wake for ReleaseState {
    fn wake(self: Arc<Self>) {
        self.waiter.wake();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.waiter.wake();
    }
}

pub(crate) struct ReleaseToken {
    state: Arc<ReleaseState>,
    finished: bool,
}

impl ReleaseToken {
    pub(crate) fn mark_container(&mut self) {
        self.finished = true;
    }

    pub(crate) fn new() -> (Self, Arc<ReleaseState>) {
        let state = Arc::new(ReleaseState {
            owners: AtomicUsize::new(1),
            interrupted: AtomicBool::new(false),
            waiter: AtomicWaker::new(),
        });
        (
            Self {
                state: Arc::clone(&state),
                finished: true,
            },
            state,
        )
    }

    pub(crate) fn child(&self) -> Self {
        self.state
            .owners
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(1)
            })
            .expect("listener owner count overflow");
        Self {
            state: Arc::clone(&self.state),
            finished: false,
        }
    }

    pub(crate) fn hold<F: Future>(
        token: Option<Self>, future: F,
    ) -> ReleaseTask<F> {
        ReleaseTask { future, token }
    }
}

impl Drop for ReleaseToken {
    fn drop(&mut self) {
        if !self.finished || std::thread::panicking() {
            self.state.interrupted.store(true, Ordering::Release);
        }
        if self.state.owners.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.state.waiter.wake();
        }
    }
}

// Field order is essential: destroy captured resources BEFORE the token, on
// normal completion, panic, cancellation, and unpolled drop.
#[pin_project]
pub(crate) struct ReleaseTask<F> {
    #[pin]
    future: F,
    token: Option<ReleaseToken>,
}

impl<F: Future> Future for ReleaseTask<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let result = std::task::ready!(this.future.poll(cx));
        if let Some(token) = this.token {
            token.finished = true;
        }
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::DefaultMetrics;
    use futures::FutureExt;
    use tokio::sync::oneshot;

    const CLEAN: QuicListenerTerminalOutcome =
        QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Clean);

    fn params() -> crate::ConnectionParams<'static> {
        crate::ConnectionParams::new_server(
            crate::settings::QuicSettings::default(),
            crate::settings::TlsCertificatePaths {
                cert: concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../quiche/examples/cert.crt"
                ),
                private_key: concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../quiche/examples/cert.key"
                ),
                kind: crate::settings::CertificateKind::X509,
            },
            crate::settings::Hooks::default(),
        )
    }

    #[tokio::test]
    async fn listener_completion_public_idle_and_independent_endpoints() {
        let sockets = [
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        ];
        let mut endpoints =
            crate::listen_with_completion(sockets, params(), DefaultMetrics)
                .unwrap();
        let mut first = endpoints.remove(0);
        let mut second = endpoints.remove(0);
        first.incoming.close();
        first.incoming.close();
        // Closure is only admission stop; the stream still owns its backlog.
        assert_eq!(
            first.terminal.try_take(),
            QuicListenerTerminalOutcome::Pending
        );
        drop(first.incoming);
        assert_eq!(first.terminal.wait().await, CLEAN);
        assert_eq!(
            second.terminal.try_take(),
            QuicListenerTerminalOutcome::Pending
        );
        assert!(tokio::time::timeout(
            std::time::Duration::ZERO,
            second.terminal.wait()
        )
        .await
        .is_err());
        assert!(second.terminal.release.waiter.take().is_none());
        drop(second.incoming);
        assert_eq!(second.terminal.wait().await, CLEAN);
    }

    #[tokio::test]
    async fn listener_completion_partial_bind_failure_retains_earlier_authority()
    {
        struct Bind(std::net::SocketAddr);
        impl TryFrom<Bind> for crate::socket::QuicListener {
            type Error = io::Error;

            fn try_from(bind: Bind) -> io::Result<Self> {
                std::net::UdpSocket::bind(bind.0)?.try_into()
            }
        }
        let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let error = crate::listen_with_completion(
            [
                Bind("127.0.0.1:0".parse().unwrap()),
                Bind(occupied.local_addr().unwrap()),
            ],
            params(),
            DefaultMetrics,
        )
        .unwrap_err();
        assert_eq!(error.error().kind(), io::ErrorKind::AddrInUse);
        assert_eq!(
            error.failure(),
            QuicListenerStartupFailure::Io(io::ErrorKind::AddrInUse)
        );
        let (error, mut started) = error.into_parts();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(started.len(), 1);
        let mut first = started.remove(0);
        assert_eq!(
            first.terminal.try_take(),
            QuicListenerTerminalOutcome::Pending
        );
        assert!(first.incoming.try_recv().is_err());
        drop(first.incoming);
        assert_eq!(first.terminal.wait().await, CLEAN);
    }

    #[test]
    fn listener_completion_missing_runtime_is_typed_startup_failure() {
        let error = crate::listen_with_completion(
            Vec::<std::net::UdpSocket>::new(),
            params(),
            DefaultMetrics,
        )
        .unwrap_err();
        assert_eq!(
            error.failure(),
            QuicListenerStartupFailure::RuntimeUnavailable
        );
        assert!(error.into_parts().1.is_empty());
    }

    #[tokio::test]
    async fn listener_completion_partial_startup_panic_keeps_authority() {
        let mut attempt = 0;
        let sockets = std::iter::from_fn(move || {
            attempt += 1;
            if attempt == 2 {
                panic!("second startup");
            }
            Some(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        });
        let error =
            crate::listen_with_completion(sockets, params(), DefaultMetrics)
                .unwrap_err();
        assert_eq!(error.failure(), QuicListenerStartupFailure::Panicked);
        let (_, mut started) = error.into_parts();
        assert_eq!(started.len(), 1);
        let mut endpoint = started.remove(0);
        drop(endpoint.incoming);
        assert_eq!(endpoint.terminal.wait().await, CLEAN);
    }

    #[test]
    fn listener_completion_metadata_requirements_are_endpoint_scoped() {
        use crate::http3::driver::BoundedSelectedWebTransportSettings;
        use crate::http3::driver::BoundedWebTransportEndpoint;
        let envelope = BoundedSelectedWebTransportSettings::default()
            .checked_memory_envelope(BoundedWebTransportEndpoint::Server)
            .unwrap();
        assert_eq!(
            envelope.fixed_pools.listener_completion_metadata_bytes,
            completion_metadata_bytes()
        );
        assert_eq!(
            envelope.fixed_pools.listener_auxiliary_task_tracking_bytes,
            std::mem::size_of::<Option<ReleaseToken>>()
        );
        let mut before = envelope;
        before.fixed_pools.listener_completion_metadata_bytes = 0;
        for connections in [0, 1, 1024] {
            assert_eq!(
                envelope.fixed_egress_bytes(4, connections).unwrap() -
                    before.fixed_egress_bytes(4, connections).unwrap(),
                completion_metadata_bytes()
            );
        }
        assert!(envelope.fixed_egress_bytes(usize::MAX, usize::MAX).is_err());
        eprintln!(
            "LISTENER_COMPLETION_METADATA fixed={} per_auxiliary_inline={}",
            completion_metadata_bytes(),
            auxiliary_tracking_bytes()
        );
    }

    #[tokio::test]
    async fn listener_completion_destructor_panic_is_finite() {
        struct PanicsOnDrop;
        impl Drop for PanicsOnDrop {
            fn drop(&mut self) {
                std::panic::panic_any(vec![1u8; 1024]);
            }
        }
        let (root, release) = ReleaseToken::new();
        let mut terminal = spawn_router(
            DefaultMetrics,
            async move {
                let _owned = (root, PanicsOnDrop);
                Ok(())
            },
            release,
        );
        assert_eq!(
            terminal.wait().await,
            QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Failed(
                QuicListenerFailure::TaskPanicked
            ))
        );
        assert_eq!(terminal.release.owners.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn listener_completion_catcher_drops_ready_pending_and_unpolled_futures(
    ) {
        struct DestructorPanic {
            _root: ReleaseToken,
            ready: bool,
            entered: Option<oneshot::Sender<()>>,
            payload_dropped: Arc<AtomicBool>,
        }
        impl Future for DestructorPanic {
            type Output = QuicListenerCompletion;

            fn poll(
                mut self: Pin<&mut Self>, _cx: &mut Context<'_>,
            ) -> Poll<Self::Output> {
                if let Some(entered) = self.entered.take() {
                    entered.send(()).unwrap();
                }
                if self.ready {
                    Poll::Ready(QuicListenerCompletion::Clean)
                } else {
                    Poll::Pending
                }
            }
        }
        impl Drop for DestructorPanic {
            fn drop(&mut self) {
                // Unlike an async-body local, this field survives Poll::Ready
                // until CatchingTask explicitly destroys the future.
                std::panic::panic_any(DropFlag(Arc::clone(
                    &self.payload_dropped,
                )));
            }
        }
        for disposition in 0..3 {
            let (root, release) = ReleaseToken::new();
            let (entered, enter) = oneshot::channel();
            let dropped = Arc::new(AtomicBool::new(false));
            let task = crate::metrics::tokio_task::spawn_catching(
                "listener_test",
                DefaultMetrics,
                DestructorPanic {
                    _root: root,
                    ready: disposition == 0,
                    entered: Some(entered),
                    payload_dropped: Arc::clone(&dropped),
                },
            );
            let mut terminal = QuicListenerTerminal::new(task, release);
            if disposition == 1 {
                enter.await.unwrap();
            }
            if disposition != 0 {
                terminal.task.as_ref().unwrap().abort();
            }
            assert_eq!(
                terminal.wait().await,
                QuicListenerTerminalOutcome::Taken(
                    QuicListenerCompletion::Failed(if disposition == 0 {
                        QuicListenerFailure::TaskPanicked
                    } else {
                        QuicListenerFailure::TaskCancelled
                    })
                )
            );
            assert!(dropped.load(Ordering::Acquire));
            assert_eq!(terminal.release.owners.load(Ordering::Acquire), 0);
        }
    }

    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn listener_completion_take_once_cancellation_and_observer_loss() {
        let (root, release) = ReleaseToken::new();
        let weak = Arc::downgrade(&release);
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = DropFlag(Arc::clone(&dropped));
        let (tx, rx) = oneshot::channel();
        let mut terminal = spawn_router(
            DefaultMetrics,
            async move {
                let _owned = (root, flag);
                rx.await.unwrap();
                Ok(())
            },
            release,
        );
        assert_eq!(terminal.try_take(), QuicListenerTerminalOutcome::Pending);
        {
            let wait = terminal.wait();
            tokio::pin!(wait);
            assert!(futures::poll!(&mut wait).is_pending());
        }
        assert!(terminal.release.waiter.take().is_none());
        tx.send(()).unwrap();
        assert_eq!(terminal.wait().await, CLEAN);
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(terminal.release.owners.load(Ordering::Acquire), 0);
        assert_eq!(
            terminal.try_take(),
            QuicListenerTerminalOutcome::AlreadyTaken
        );
        assert_eq!(
            terminal.wait().await,
            QuicListenerTerminalOutcome::AlreadyTaken
        );
        drop(terminal);
        assert!(weak.upgrade().is_none());

        let (root, release) = ReleaseToken::new();
        let weak = Arc::downgrade(&release);
        let (tx, rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let terminal = spawn_router(
            DefaultMetrics,
            async move {
                rx.await.unwrap();
                drop(root);
                done_tx.send(()).unwrap();
                Ok(())
            },
            release,
        );
        drop(terminal);
        tx.send(()).unwrap();
        done_rx.await.unwrap();
        // Observer loss never holds the router or its state alive.
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn listener_completion_after_exit_and_cancellation_between_join_and_release(
    ) {
        let (root, release) = ReleaseToken::new();
        let mut held = root.child();
        let mut terminal = spawn_router(
            DefaultMetrics,
            async move {
                drop(root);
                Ok(())
            },
            release,
        );
        // Observe the real join without consuming the release-gated result.
        std::future::poll_fn(|cx| {
            assert!(terminal.poll_take(cx).is_pending());
            if terminal.joined.is_some() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        assert!(terminal.task.is_none());
        {
            let wait = terminal.wait();
            tokio::pin!(wait);
            assert!(futures::poll!(&mut wait).is_pending());
        }
        assert!(terminal.release.waiter.take().is_none());
        held.finished = true;
        drop(held);
        assert_eq!(terminal.try_take(), CLEAN);
        assert_eq!(
            terminal.try_take(),
            QuicListenerTerminalOutcome::AlreadyTaken
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn listener_completion_waits_for_backlog_destructor_not_early_guard() {
        struct HeldDestructor {
            early: Option<oneshot::Sender<()>>,
            entered: Option<oneshot::Sender<()>>,
            resume: std::sync::mpsc::Receiver<()>,
            flag: DropFlag,
        }
        impl Drop for HeldDestructor {
            fn drop(&mut self) {
                // Models Initial's shutdown guard dropping before core/socket.
                drop(self.early.take());
                self.entered.take().unwrap().send(()).unwrap();
                self.resume.recv().unwrap();
                assert!(!self.flag.0.load(Ordering::Acquire));
            }
        }
        let (root, release) = ReleaseToken::new();
        let (sender, receiver) = mpsc::channel(1);
        let mut accepted =
            AcceptReceiver::new(receiver, Arc::new(AtomicWaker::new()));
        accepted.track_release(root.child());
        let dropped = Arc::new(AtomicBool::new(false));
        let (early, early_rx) = oneshot::channel();
        let (entered, entered_rx) = oneshot::channel();
        let (resume, resume_rx) = std::sync::mpsc::channel();
        assert!(sender
            .try_send(HeldDestructor {
                early: Some(early),
                entered: Some(entered),
                resume: resume_rx,
                flag: DropFlag(Arc::clone(&dropped))
            })
            .is_ok());
        let mut terminal = spawn_router(
            DefaultMetrics,
            async move {
                assert!(early_rx.await.is_err());
                drop((root, sender));
                Ok(())
            },
            release,
        );
        let dropping = std::thread::spawn(move || drop(accepted));
        entered_rx.await.unwrap();
        std::future::poll_fn(|cx| {
            assert!(terminal.poll_take(cx).is_pending());
            if terminal.joined.is_some() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        assert!(!dropped.load(Ordering::Acquire));
        resume.send(()).unwrap();
        assert_eq!(terminal.wait().await, CLEAN);
        dropping.join().unwrap();
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn listener_completion_auxiliary_abort_and_first_router_failure() {
        for fail_router in [false, true] {
            let (root, release) = ReleaseToken::new();
            let dropped = Arc::new(AtomicBool::new(false));
            let flag = DropFlag(Arc::clone(&dropped));
            let auxiliary = tokio::spawn(ReleaseToken::hold(
                Some(root.child()),
                async move {
                    let _flag = flag;
                    std::future::pending::<()>().await;
                },
            ));
            let mut terminal = spawn_router(
                DefaultMetrics,
                async move {
                    drop(root);
                    if fail_router {
                        Err(io::Error::other(
                            super::super::router::ConnectionMapLaneSaturated,
                        ))
                    } else {
                        Ok(())
                    }
                },
                release,
            );
            std::future::poll_fn(|cx| {
                assert!(terminal.poll_take(cx).is_pending());
                if terminal.joined.is_some() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            auxiliary.abort();
            assert!(auxiliary.await.unwrap_err().is_cancelled());
            assert_eq!(
                terminal.wait().await,
                QuicListenerTerminalOutcome::Taken(
                    QuicListenerCompletion::Failed(if fail_router {
                        QuicListenerFailure::ConnectionMapCommandLaneSaturated
                    } else {
                        QuicListenerFailure::AncillaryTaskInterrupted
                    })
                )
            );
            assert!(dropped.load(Ordering::Acquire));
            assert_eq!(terminal.release.owners.load(Ordering::Acquire), 0);
        }
    }

    #[tokio::test]
    async fn listener_completion_task_cancel_panic_and_finite_io_failure() {
        for disposition in 0..3 {
            let (root, release) = ReleaseToken::new();
            let dropped = Arc::new(AtomicBool::new(false));
            let flag = DropFlag(Arc::clone(&dropped));
            let mut terminal = spawn_router(
                DefaultMetrics,
                async move {
                    let _owned = (root, flag);
                    match disposition {
                        0 => std::future::pending().await,
                        1 => std::panic::panic_any(vec![0u8; 1024]),
                        _ =>
                            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
                    }
                },
                release,
            );
            if disposition == 0 {
                terminal.task.as_ref().unwrap().abort();
            }
            let failure = match disposition {
                0 => QuicListenerFailure::TaskCancelled,
                1 => QuicListenerFailure::TaskPanicked,
                _ => QuicListenerFailure::RouterIo {
                    kind: io::ErrorKind::PermissionDenied,
                },
            };
            assert_eq!(
                terminal.wait().await,
                QuicListenerTerminalOutcome::Taken(
                    QuicListenerCompletion::Failed(failure)
                )
            );
            assert!(dropped.load(Ordering::Acquire));
            assert_eq!(terminal.release.owners.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn listener_completion_runtime_shutdown_of_unpolled_task() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let (root, release) = ReleaseToken::new();
        let mut terminal = {
            let _entered = runtime.enter();
            spawn_router(
                DefaultMetrics,
                async move {
                    let _owned = root;
                    std::future::pending::<io::Result<()>>().await
                },
                release,
            )
        };
        drop(runtime);
        assert_eq!(
            terminal.wait().now_or_never(),
            Some(QuicListenerTerminalOutcome::Taken(
                QuicListenerCompletion::Failed(
                    QuicListenerFailure::TaskCancelled
                )
            ))
        );
        assert_eq!(terminal.release.owners.load(Ordering::Acquire), 0);
    }
}
