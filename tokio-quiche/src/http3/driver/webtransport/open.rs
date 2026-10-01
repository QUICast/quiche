// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

use super::*;

/// Refusal before an open obligation is registered. No stream was reserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebTransportOpenAdmissionError {
    /// The bounded selected command lane has no slot.
    QueueFull,
    /// Outstanding open operations/results fill the independent owner bound.
    RegistrationFull,
    /// The connection's selected command lane has closed.
    DriverGone,
}

/// Transport exposure of one exact opening, including failed openings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WebTransportOpenExposure {
    /// No QUIC stream ID or reliable prefix has been reserved.
    #[default]
    Unreserved,
    /// A physical ID is reserved. Cancellation cannot roll it back; the
    /// provider owns prefix/reset cleanup, including accepted prefix bytes.
    Reserved {
        /// Exact physical QUIC stream ID, not an application-owned stream.
        stream_id: u64,
        /// Prefix bytes actually accepted by QUIC at the time of observation.
        prefix_bytes_accepted: usize,
    },
}

/// Terminal refusal of a registered open obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebTransportOpenFailure {
    /// Existing exact selection/STOP outcome; never `Opened`.
    pub outcome: WebTransportOpenStreamOutcome,
    /// Whether the provider must settle a reserved or exposed stream.
    pub exposure: WebTransportOpenExposure,
}

/// A bounded open obligation. It waits for local ownership and peer credit,
/// not a timer. Dropping it cancels, even after success has been queued.
///
/// Success is an affine offer, not yet application ownership. Call
/// [`WebTransportOpenedStream::accept`] to take that ownership.
#[must_use]
pub struct WebTransportOpenOperation {
    shared: Option<Arc<OpenShared>>,
}

impl WebTransportOpenOperation {
    #[cfg(test)]
    pub(crate) fn pause_after_progress(
        &self, prefix: bool,
    ) -> Arc<std::sync::Barrier> {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        *self
            .shared
            .as_ref()
            .unwrap()
            .progress_barrier
            .lock()
            .unwrap() = Some((prefix, Arc::clone(&barrier)));
        barrier
    }

    /// Cancels and returns the exact exposure at cancellation. This is not
    /// settlement: a reserved reliable prefix can still require completion
    /// and reset traffic, and remains charged until its core state is freed.
    pub fn cancel(mut self) -> WebTransportOpenExposure {
        self.shared
            .take()
            .map_or(WebTransportOpenExposure::Unreserved, |shared| {
                shared.cancel()
            })
    }
}

impl Future for WebTransportOpenOperation {
    type Output = Result<WebTransportOpenedStream, WebTransportOpenFailure>;

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        let Some(shared) = self.shared.as_ref() else {
            return Poll::Pending;
        };
        let result = {
            let mut state = shared.lock();
            match state.result {
                None => {
                    state.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                },
                Some(WebTransportOpenStreamOutcome::Opened { .. }) => Ok(()),
                Some(outcome) => Err(WebTransportOpenFailure {
                    outcome,
                    exposure: state.exposure,
                }),
            }
        };
        let shared = self.shared.take().expect("operation owns its result");
        Poll::Ready(result.map(|()| WebTransportOpenedStream { shared }))
    }
}

impl Drop for WebTransportOpenOperation {
    fn drop(&mut self) {
        if let Some(shared) = &self.shared {
            shared.cancel();
        }
    }
}

/// An opened stream still owned by the provider until explicit acceptance.
///
/// This value is non-cloneable. Dropping it without accepting settles the
/// exposed stream through the existing reset/terminal cleanup. A session or
/// connection close before acceptance invalidates the offer. Keeping an offer
/// retains one charged registration, including after driver teardown.
#[must_use]
pub struct WebTransportOpenedStream {
    shared: Arc<OpenShared>,
}

impl std::fmt::Debug for WebTransportOpenedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebTransportOpenedStream")
            .field("session_id", &self.shared.session_id)
            .field("direction", &self.shared.direction)
            .finish_non_exhaustive()
    }
}

impl WebTransportOpenedStream {
    /// Atomically accepts the physical ID and its directional obligations.
    /// A concurrent terminal transition wins if recorded before this call;
    /// otherwise ordinary selected-stream terminal APIs report later closure.
    pub fn accept(self) -> Result<u64, WebTransportOpenFailure> {
        let result = {
            let mut state = self.shared.lock();
            match state.result.expect("offer follows a completed opening") {
                WebTransportOpenStreamOutcome::Opened { stream_id } => {
                    state.accepted = true;
                    Ok(stream_id)
                },
                outcome => Err(WebTransportOpenFailure {
                    outcome,
                    exposure: state.exposure,
                }),
            }
        };
        self.shared.wake_driver();
        result
    }
}

impl Drop for WebTransportOpenedStream {
    fn drop(&mut self) {
        self.shared.cancel();
    }
}

#[derive(Debug, Default)]
struct OpenState {
    exposure: WebTransportOpenExposure,
    result: Option<WebTransportOpenStreamOutcome>,
    accepted: bool,
    cancelled: bool,
    cleanup_started: bool,
    waker: Option<Waker>,
}

#[derive(Debug)]
pub(crate) struct OpenShared {
    pub(super) session_id: u64,
    pub(super) direction: WebTransportStreamDirection,
    state: Mutex<OpenState>,
    terminal: Arc<TerminalRetentionState>,
    sender: mpsc::Sender<WebTransportCommand>,
    cancellation_pending: Arc<AtomicBool>,
    #[cfg(test)]
    progress_barrier: Mutex<Option<(bool, Arc<std::sync::Barrier>)>>,
}

impl OpenShared {
    #[cfg(test)]
    fn after_progress(&self, prefix: bool) {
        let mut barrier = self.progress_barrier.lock().unwrap();
        if barrier.as_ref().is_some_and(|(kind, _)| *kind == prefix) {
            barrier.take().unwrap().1.wait();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OpenState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.lock().cancelled
    }

    pub(super) fn is_accepted(&self) -> bool {
        self.lock().accepted
    }

    fn start_cleanup(&self) -> bool {
        let mut state = self.lock();
        if state.cleanup_started || state.accepted {
            return false;
        }
        state.cleanup_started = true;
        true
    }

    pub(super) fn write_prefix(
        &self, qconn: &mut QuicheConnection, stream_id: u64, prefix: &[u8],
        offset: usize,
    ) -> quiche::Result<usize> {
        let mut state = self.lock();
        let written = qconn.stream_send(stream_id, &prefix[offset..], false)?;
        #[cfg(test)]
        self.after_progress(true);
        state.exposure = WebTransportOpenExposure::Reserved {
            stream_id,
            prefix_bytes_accepted: offset + written,
        };
        Ok(written)
    }

    pub(super) fn finish(&self, outcome: WebTransportOpenStreamOutcome) -> bool {
        let mut state = self.lock();
        if state.cancelled || state.accepted {
            return !state.cancelled;
        }
        // A queued offer is revocable until caller acceptance; a recorded
        // failure is not replaced by a later teardown cause.
        if state.result.is_none() ||
            matches!(
                state.result,
                Some(WebTransportOpenStreamOutcome::Opened { .. })
            )
        {
            state.result = Some(outcome);
        }
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }

    fn cancel(&self) -> WebTransportOpenExposure {
        let mut state = self.lock();
        let exposure = state.exposure;
        if state.accepted || state.cancelled {
            return exposure;
        }
        state.cancelled = true;
        state.waker = None;
        drop(state);
        self.wake_driver();
        exposure
    }

    fn wake_driver(&self) {
        self.cancellation_pending.store(true, Ordering::Release);
        let _ = self
            .sender
            .try_send(WebTransportCommand::PruneCancelledWaiters);
    }
}

impl Drop for OpenShared {
    fn drop(&mut self) {
        let mut inner = self.terminal.lock();
        inner.open_obligations -= 1;
        decrement_session_count(
            &mut inner.open_obligations_per_session,
            self.session_id,
        );
        drop(inner);
        self.terminal.wake_if_terminal();
    }
}

#[derive(Debug)]
pub(super) enum OpenResponse {
    Legacy(oneshot::Sender<WebTransportOpenStreamOutcome>),
    Obligation(Arc<OpenShared>),
}

impl OpenResponse {
    pub(super) fn is_closed(&self) -> bool {
        match self {
            Self::Legacy(response) => response.is_closed(),
            Self::Obligation(shared) => shared.is_cancelled(),
        }
    }

    pub(super) fn send(
        self, outcome: WebTransportOpenStreamOutcome,
    ) -> Result<(), WebTransportOpenStreamOutcome> {
        match self {
            Self::Legacy(response) => response.send(outcome),
            Self::Obligation(shared) =>
                shared.finish(outcome).then_some(()).ok_or(outcome),
        }
    }

    pub(super) fn reserve(
        &self, conn: &mut quiche::h3::Connection, qconn: &mut QuicheConnection,
        session_id: u64, direction: quiche::h3::WebTransportStreamDirection,
        mode: quiche::h3::WebTransportStreamResetMode,
    ) -> Option<quiche::h3::Result<quiche::h3::WebTransportStreamReservation>>
    {
        let mut state = match self {
            Self::Obligation(shared) => Some(shared.lock()),
            Self::Legacy(_) => None,
        };
        if state.as_ref().is_some_and(|state| state.cancelled) {
            return None;
        }
        let result = conn.reserve_webtransport_stream_with_reset_mode(
            qconn, session_id, direction, mode,
        );
        #[cfg(test)]
        if result.is_ok() {
            if let Self::Obligation(shared) = self {
                shared.after_progress(false);
            }
        }
        if let (Some(state), Ok(reservation)) = (&mut state, &result) {
            state.exposure = WebTransportOpenExposure::Reserved {
                stream_id: reservation.stream_id(),
                prefix_bytes_accepted: 0,
            };
        }
        Some(result)
    }
}

impl WebTransportController {
    /// Registers one cancellation-safe stream-open obligation without waiting
    /// for lane admission. Registration saturation is distinct from recoverable
    /// local stream capacity, which keeps the admitted operation pending.
    ///
    /// Registration uses at most `command_capacity` outstanding owners globally
    /// and `max_pending_streams_per_session` per session, independently of the
    /// stream slots it awaits. The owner stays charged through offer acceptance
    /// or cancellation cleanup. No transport ID is consumed on refusal.
    pub fn try_open_stream_obligation(
        &self, session_id: u64, direction: WebTransportStreamDirection,
    ) -> Result<WebTransportOpenOperation, WebTransportOpenAdmissionError> {
        let permit = self.sender.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) =>
                WebTransportOpenAdmissionError::QueueFull,
            mpsc::error::TrySendError::Closed(_) =>
                WebTransportOpenAdmissionError::DriverGone,
        })?;
        let mut inner = self.terminal_retention.lock();
        if inner.open_admission_closed {
            return Err(WebTransportOpenAdmissionError::DriverGone);
        }
        let count = inner
            .open_obligations_per_session
            .get(&session_id)
            .copied()
            .unwrap_or(0);
        if inner.open_obligations >= inner.max_open_obligations ||
            count >= inner.max_open_obligations_per_session
        {
            inner.open_obligation_saturation_total =
                inner.open_obligation_saturation_total.saturating_add(1);
            return Err(WebTransportOpenAdmissionError::RegistrationFull);
        }
        inner.open_obligations += 1;
        *inner
            .open_obligations_per_session
            .entry(session_id)
            .or_default() += 1;
        inner.open_obligations_high_water = inner
            .open_obligations_high_water
            .max(inner.open_obligations);
        inner.open_obligation_admitted_total =
            inner.open_obligation_admitted_total.saturating_add(1);
        let shared = Arc::new(OpenShared {
            session_id,
            direction,
            state: Mutex::new(OpenState::default()),
            terminal: Arc::clone(&self.terminal_retention),
            sender: self.sender.clone(),
            cancellation_pending: Arc::clone(&self.cancellation_pending),
            #[cfg(test)]
            progress_barrier: Mutex::new(None),
        });
        permit.send(WebTransportCommand::OpenObligation(Arc::clone(&shared)));
        // Lane closure takes this same lock before draining. Publication must
        // precede closure, not just the admission counter increment.
        drop(inner);
        Ok(WebTransportOpenOperation {
            shared: Some(shared),
        })
    }
}

impl Runtime {
    pub(crate) fn schedule_open_collection(&mut self) {
        if !self.capacity_opens.is_empty() || !self.open_offers.is_empty() {
            self.open_collection_work =
                self.stream_sessions.len() + self.pending_streams.len();
        }
    }

    pub(super) fn schedule_open_obligation_work(&mut self) {
        self.capacity_open_work = self.capacity_opens.len();
        self.open_offer_work = self.open_offers.len();
        self.schedule_open_collection();
    }

    pub(super) fn process_capacity_open(
        &mut self, conn: &mut quiche::h3::Connection,
        qconn: &mut QuicheConnection,
    ) -> bool {
        if self.capacity_open_work == 0 {
            return false;
        }
        self.capacity_open_work -= 1;
        let Some(request) = self.capacity_opens.pop_front() else {
            self.capacity_open_work = 0;
            return false;
        };
        self.stream_open_waiter_work_total =
            self.stream_open_waiter_work_total.saturating_add(1);
        if request.response.is_closed() {
            return true;
        }
        if let Some(error) = self.selection_error(request.session_id, qconn) {
            let _ = request
                .response
                .send(WebTransportOpenStreamOutcome::Rejected(error));
            return true;
        }
        let credit = match request.direction {
            WebTransportStreamDirection::Bidi => qconn.peer_streams_left_bidi(),
            WebTransportStreamDirection::Uni => qconn.peer_streams_left_uni(),
        };
        let receive_capacity = request.direction !=
            WebTransportStreamDirection::Bidi ||
            (self.receive_terminal_observations + self.reserved_bidi_opens <
                self.limits.max_receive_terminal_states &&
                self.receive_terminal_observations_per_session
                    .get(&request.session_id)
                    .copied()
                    .unwrap_or(0) +
                    self.reserved_bidi_opens_per_session
                        .get(&request.session_id)
                        .copied()
                        .unwrap_or(0) <
                    self.limits.max_receive_terminal_states_per_session);
        if credit == 0 ||
            !self.can_buffer(request.session_id) ||
            !receive_capacity
        {
            self.capacity_opens.push_back(request);
        } else if let Some(request) =
            self.start_open_request(conn, qconn, request)
        {
            self.capacity_opens.push_back(request);
        }
        true
    }

    pub(super) fn process_open_offer(&mut self, qconn: &mut QuicheConnection) {
        self.open_offer_work = self.open_offer_work.saturating_sub(1);
        let Some(stream_id) =
            next_key_strictly_after(&self.open_offers, self.open_offer_cursor)
                .or_else(|| {
                    self.open_offers.first_key_value().map(|(&id, _)| id)
                })
        else {
            return;
        };
        self.open_offer_cursor = Some(stream_id);
        let offer = Arc::clone(&self.open_offers[&stream_id]);
        if offer.is_accepted() {
            self.open_offers.remove(&stream_id);
        } else if offer.is_cancelled() &&
            !self.associated_teardown_waiting_for_peer(offer.session_id)
        {
            self.abandon_open_offer(qconn, stream_id);
        }
    }

    pub(super) fn abandon_open_offer(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) {
        let Some(owned) = self.stream_sessions.get(&stream_id).copied() else {
            return;
        };
        if !self
            .open_offers
            .get(&stream_id)
            .is_some_and(|offer| offer.start_cleanup())
        {
            return;
        }
        shutdown_owned_stream(qconn, stream_id, owned, WT_SESSION_GONE);
        consume_unaccepted_stop(qconn, stream_id);
        self.schedule_open_collection();
        // These observations have never been accepted by the application.
        // End their provider ownership, but keep the stream slot through ACK
        // and real core collection. No externally acquired owner is retired.
        self.remove_receive_terminal_state(stream_id);
        self.remove_send_terminal_state(stream_id);
        self.retire_send_terminal_observation(stream_id, owned);
        self.close_stream_waiters(stream_id);
        if owned.receive_terminal_observation ==
            ReceiveTerminalObservation::Active
        {
            self.receive_terminal_observations -= 1;
            decrement_session_count(
                &mut self.receive_terminal_observations_per_session,
                owned.session_id,
            );
        }
        if let Some(stream) = self.stream_sessions.get_mut(&stream_id) {
            if stream.has_receive_direction() {
                stream.receive_terminal_observation =
                    ReceiveTerminalObservation::Retired;
            }
        }
    }
}

pub(crate) fn metadata_upper_bound(count: usize) -> Option<usize> {
    // One shared owner plus its Arc counters. The capacity-wait queue reserves
    // exactly the global registration bound at construction and never grows.
    let entry = std::mem::size_of::<OpenShared>()
        .checked_add(2 * std::mem::size_of::<usize>())?
        .checked_add(std::mem::size_of::<PendingOpen>())?;
    // Rust 1.94 BTreeMap has 11 values and 12 edges per internal node.
    // Charge a full node per live entry, for each of the five new maps,
    // plus an aligned header (parent pointer/index, len, and child edges).
    let node = |value: usize| {
        value
            .checked_mul(11)?
            .checked_add(16 * std::mem::size_of::<usize>())
    };
    let maps = node(std::mem::size_of::<(u64, Arc<OpenShared>)>())?
        .checked_add(node(std::mem::size_of::<(u64, OwnedStream)>())?)?
        .checked_add(
            node(std::mem::size_of::<(u64, usize)>())?.checked_mul(3)?,
        )?;
    count.checked_mul(entry.checked_add(maps)?)
}
