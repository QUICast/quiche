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

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use tokio::task::JoinHandle;

use super::router::is_connection_map_command_lane_saturation;
use crate::metrics::tokio_task;
use crate::metrics::Metrics;

/// Why a QUIC listener terminated unsuccessfully.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicListenerFailure {
    /// The configured bounded Connection-ID map command lane saturated.
    ConnectionMapCommandLaneSaturated,

    /// The listener packet router returned an I/O failure.
    RouterIo {
        /// Stable I/O error category. Error text and platform payloads are not
        /// retained by the terminal capability.
        kind: io::ErrorKind,
    },

    /// The listener task was cancelled or panicked before normal completion.
    TaskAborted,
}

/// Authoritative completion of one QUIC listener.
///
/// This becomes observable only after the listener task has terminated and its
/// router, socket ownership, accepted-connection sender, Connection-ID map
/// lane, map entries, and listener-side connection references have been
/// released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicListenerCompletion {
    /// The accepted-connection stream was closed or dropped and all accepted
    /// connections released their listener shutdown ownership.
    Clean,

    /// The listener stopped because of a finite typed failure.
    Failed(QuicListenerFailure),
}

/// Result of observing a [`QuicListenerTerminal`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicListenerTerminalOutcome {
    /// The listener has not completed yet.
    Pending,

    /// This caller consumed the listener's one terminal result.
    Taken(QuicListenerCompletion),

    /// Another caller already consumed the terminal result.
    AlreadyTaken,

    /// The single bounded asynchronous waiter slot is occupied.
    WaiterInUse,
}

/// Bounded, take-once terminal capability for one QUIC listener.
///
/// Clones identify the same listener and compete for one terminal result. The
/// capability owns only preallocated terminal state; it does not retain the
/// listener task, socket, packet router, accepted-connection lane, Connection-
/// ID map, or any connection.
#[derive(Clone)]
pub struct QuicListenerTerminal {
    state: Arc<QuicListenerTerminalState>,
}

impl std::fmt::Debug for QuicListenerTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicListenerTerminal")
            .finish_non_exhaustive()
    }
}

impl QuicListenerTerminal {
    pub(crate) fn new_pair() -> (Self, Arc<QuicListenerTerminalState>) {
        let state = Arc::new(QuicListenerTerminalState::default());
        (
            Self {
                state: Arc::clone(&state),
            },
            state,
        )
    }

    /// Attempts to consume the authoritative terminal result without waiting.
    pub fn try_take(&self) -> QuicListenerTerminalOutcome {
        self.state.try_take()
    }

    /// Waits for and attempts to consume the authoritative terminal result.
    ///
    /// At most one wait future may be registered. Dropping a pending future
    /// releases that slot without consuming the eventual result or affecting
    /// listener shutdown.
    pub fn wait(&self) -> QuicListenerTerminalWait {
        QuicListenerTerminalWait {
            state: Arc::clone(&self.state),
            registered: false,
            finished: false,
        }
    }
}

/// Cancellation-safe bounded wait for a [`QuicListenerTerminal`].
#[must_use = "futures do nothing unless polled or awaited"]
pub struct QuicListenerTerminalWait {
    state: Arc<QuicListenerTerminalState>,
    registered: bool,
    finished: bool,
}

impl std::fmt::Debug for QuicListenerTerminalWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicListenerTerminalWait")
            .field("registered", &self.registered)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Future for QuicListenerTerminalWait {
    type Output = QuicListenerTerminalOutcome;

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        let mut inner = self.state.inner.lock().unwrap();
        if let Some(outcome) = inner.take_terminal() {
            inner.waiter = None;
            drop(inner);
            self.registered = false;
            self.finished = true;
            return Poll::Ready(outcome);
        }

        if !self.registered {
            if inner.waiter.is_some() {
                drop(inner);
                self.finished = true;
                return Poll::Ready(QuicListenerTerminalOutcome::WaiterInUse);
            }
            inner.waiter = Some(cx.waker().clone());
            drop(inner);
            self.registered = true;
            return Poll::Pending;
        }

        if inner
            .waiter
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(cx.waker()))
        {
            inner.waiter = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl Drop for QuicListenerTerminalWait {
    fn drop(&mut self) {
        if self.registered && !self.finished {
            self.state.inner.lock().unwrap().waiter = None;
        }
    }
}

#[derive(Default)]
pub(crate) struct QuicListenerTerminalState {
    inner: Mutex<QuicListenerTerminalInner>,
}

#[derive(Default)]
struct QuicListenerTerminalInner {
    completion: Option<QuicListenerCompletion>,
    joined_completion: Option<QuicListenerCompletion>,
    resources_released: bool,
    observer_aborted: bool,
    taken: bool,
    waiter: Option<Waker>,
}

impl QuicListenerTerminalInner {
    fn take_terminal(&mut self) -> Option<QuicListenerTerminalOutcome> {
        if self.taken {
            return Some(QuicListenerTerminalOutcome::AlreadyTaken);
        }
        let completion = self.completion.take()?;
        self.taken = true;
        self.joined_completion = None;
        Some(QuicListenerTerminalOutcome::Taken(completion))
    }

    fn settle_if_ready(&mut self) -> Option<Waker> {
        if self.taken || self.completion.is_some() || !self.resources_released {
            return None;
        }
        let completion = self.joined_completion.or_else(|| {
            self.observer_aborted
                .then_some(QuicListenerCompletion::Failed(
                    QuicListenerFailure::TaskAborted,
                ))
        })?;
        self.completion = Some(completion);
        self.waiter.take()
    }
}

impl QuicListenerTerminalState {
    fn try_take(&self) -> QuicListenerTerminalOutcome {
        self.inner
            .lock()
            .unwrap()
            .take_terminal()
            .unwrap_or(QuicListenerTerminalOutcome::Pending)
    }

    fn mark_resources_released(&self) {
        let waker = {
            let mut inner = self.inner.lock().unwrap();
            if inner.taken {
                return;
            }
            inner.resources_released = true;
            inner.settle_if_ready()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn mark_joined(&self, completion: QuicListenerCompletion) {
        let waker = {
            let mut inner = self.inner.lock().unwrap();
            if inner.taken {
                return;
            }
            if inner.joined_completion.is_none() {
                inner.joined_completion = Some(completion);
            }
            inner.settle_if_ready()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn mark_observer_aborted(&self) {
        let waker = {
            let mut inner = self.inner.lock().unwrap();
            if inner.taken {
                return;
            }
            inner.observer_aborted = true;
            inner.settle_if_ready()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

pub(crate) fn completion_from_router_result(
    result: io::Result<()>,
) -> QuicListenerCompletion {
    match result {
        Ok(()) => QuicListenerCompletion::Clean,
        Err(error) if is_connection_map_command_lane_saturation(&error) =>
            QuicListenerCompletion::Failed(
                QuicListenerFailure::ConnectionMapCommandLaneSaturated,
            ),
        Err(error) =>
            QuicListenerCompletion::Failed(QuicListenerFailure::RouterIo {
                kind: error.kind(),
            }),
    }
}

struct ListenerOwnedTask<F> {
    future: Option<Pin<Box<F>>>,
    terminal: Arc<QuicListenerTerminalState>,
    resources_released: bool,
}

impl<F> ListenerOwnedTask<F> {
    fn new(future: F, terminal: Arc<QuicListenerTerminalState>) -> Self {
        Self {
            future: Some(Box::pin(future)),
            terminal,
            resources_released: false,
        }
    }

    fn release_resources(&mut self) {
        if self.resources_released {
            return;
        }
        drop(self.future.take());
        self.resources_released = true;
        self.terminal.mark_resources_released();
    }
}

impl<F> Future for ListenerOwnedTask<F>
where
    F: Future<Output = QuicListenerCompletion>,
{
    type Output = QuicListenerCompletion;

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        let completion = match self.future.as_mut() {
            Some(future) => match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(completion) => completion,
            },
            None =>
                return Poll::Ready(QuicListenerCompletion::Failed(
                    QuicListenerFailure::TaskAborted,
                )),
        };
        self.release_resources();
        Poll::Ready(completion)
    }
}

impl<F> Drop for ListenerOwnedTask<F> {
    fn drop(&mut self) {
        self.release_resources();
    }
}

struct ListenerTaskObserver {
    listener: Option<JoinHandle<QuicListenerCompletion>>,
    terminal: Arc<QuicListenerTerminalState>,
    finished: bool,
}

impl ListenerTaskObserver {
    fn new(
        listener: JoinHandle<QuicListenerCompletion>,
        terminal: Arc<QuicListenerTerminalState>,
    ) -> Self {
        Self {
            listener: Some(listener),
            terminal,
            finished: false,
        }
    }
}

impl Future for ListenerTaskObserver {
    type Output = ();

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        let joined = match self.listener.as_mut() {
            Some(listener) => match Pin::new(listener).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(joined) => joined,
            },
            None => return Poll::Ready(()),
        };
        drop(self.listener.take());
        let completion = joined.unwrap_or(QuicListenerCompletion::Failed(
            QuicListenerFailure::TaskAborted,
        ));
        self.terminal.mark_joined(completion);
        self.finished = true;
        Poll::Ready(())
    }
}

impl Drop for ListenerTaskObserver {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(listener) = self.listener.take() {
            listener.abort();
        }
        self.terminal.mark_observer_aborted();
    }
}

pub(crate) fn spawn_listener_task<M, F>(
    metrics: M, future: F, terminal: Arc<QuicListenerTerminalState>,
) -> JoinHandle<()>
where
    M: Metrics,
    F: Future<Output = QuicListenerCompletion> + Send + 'static,
{
    let listener = tokio_task::spawn(
        "quic_udp_listener",
        metrics.clone(),
        ListenerOwnedTask::new(future, Arc::clone(&terminal)),
    );
    tokio_task::spawn(
        "quic_udp_listener_terminal",
        metrics,
        ListenerTaskObserver::new(listener, terminal),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    use crate::metrics::DefaultMetrics;

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn terminal_requires_resource_release_and_join_and_is_take_once() {
        let (terminal, state) = QuicListenerTerminal::new_pair();

        state.mark_joined(QuicListenerCompletion::Clean);
        assert_eq!(terminal.try_take(), QuicListenerTerminalOutcome::Pending);

        state.mark_resources_released();
        assert_eq!(
            terminal.try_take(),
            QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Clean)
        );
        assert_eq!(
            terminal.try_take(),
            QuicListenerTerminalOutcome::AlreadyTaken
        );

        state.mark_joined(QuicListenerCompletion::Failed(
            QuicListenerFailure::TaskAborted,
        ));
        assert_eq!(
            terminal.try_take(),
            QuicListenerTerminalOutcome::AlreadyTaken
        );
        let inner = state.inner.lock().unwrap();
        assert!(inner.completion.is_none());
        assert!(inner.joined_completion.is_none());
    }

    #[tokio::test]
    async fn waiter_registered_after_task_exit_observes_retained_completion() {
        let (terminal, state) = QuicListenerTerminal::new_pair();
        state.mark_resources_released();
        state.mark_joined(QuicListenerCompletion::Clean);

        assert_eq!(
            terminal.wait().await,
            QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Clean)
        );
    }

    #[test]
    fn first_failure_wins_over_late_completion() {
        let (terminal, state) = QuicListenerTerminal::new_pair();
        let failure =
            QuicListenerCompletion::Failed(QuicListenerFailure::RouterIo {
                kind: io::ErrorKind::BrokenPipe,
            });
        state.mark_joined(failure);
        state.mark_joined(QuicListenerCompletion::Clean);
        state.mark_resources_released();

        assert_eq!(
            terminal.try_take(),
            QuicListenerTerminalOutcome::Taken(failure)
        );
    }

    #[tokio::test]
    async fn waiter_is_bounded_and_cancellation_releases_its_slot() {
        let (terminal, state) = QuicListenerTerminal::new_pair();
        let mut first = Box::pin(terminal.wait());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(first.as_mut().poll(&mut cx).is_pending());

        assert_eq!(
            terminal.wait().await,
            QuicListenerTerminalOutcome::WaiterInUse
        );
        drop(first);

        let replacement = terminal.wait();
        state.mark_resources_released();
        state.mark_joined(QuicListenerCompletion::Failed(
            QuicListenerFailure::RouterIo {
                kind: io::ErrorKind::ConnectionReset,
            },
        ));
        assert_eq!(
            replacement.await,
            QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Failed(
                QuicListenerFailure::RouterIo {
                    kind: io::ErrorKind::ConnectionReset,
                }
            ))
        );
    }

    #[tokio::test]
    async fn listener_resources_drop_before_completion_is_observable() {
        let (terminal, state) = QuicListenerTerminal::new_pair();
        let dropped = Arc::new(AtomicBool::new(false));
        let (release, released) = tokio::sync::oneshot::channel();
        let listener_dropped = Arc::clone(&dropped);
        let listener = async move {
            let _drop_flag = DropFlag(listener_dropped);
            let _ = released.await;
            QuicListenerCompletion::Clean
        };
        let observer = spawn_listener_task(DefaultMetrics, listener, state);

        assert_eq!(terminal.try_take(), QuicListenerTerminalOutcome::Pending);
        release.send(()).unwrap();
        assert_eq!(
            terminal.wait().await,
            QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Clean)
        );
        assert!(dropped.load(Ordering::Acquire));
        observer.await.unwrap();
    }

    #[tokio::test]
    async fn observer_abort_cancels_listener_and_reports_task_aborted() {
        let (terminal, state) = QuicListenerTerminal::new_pair();
        let dropped = Arc::new(AtomicBool::new(false));
        let listener_dropped = Arc::clone(&dropped);
        let listener = async move {
            let _drop_flag = DropFlag(listener_dropped);
            std::future::pending::<QuicListenerCompletion>().await
        };
        let observer = spawn_listener_task(DefaultMetrics, listener, state);
        tokio::task::yield_now().await;

        observer.abort();
        assert!(observer.await.unwrap_err().is_cancelled());
        assert_eq!(
            terminal.wait().await,
            QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Failed(
                QuicListenerFailure::TaskAborted
            ))
        );
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn router_error_projection_is_finite_and_address_free() {
        assert_eq!(
            completion_from_router_result(Err(io::Error::from(
                io::ErrorKind::PermissionDenied
            ))),
            QuicListenerCompletion::Failed(QuicListenerFailure::RouterIo {
                kind: io::ErrorKind::PermissionDenied,
            })
        );
    }
}
