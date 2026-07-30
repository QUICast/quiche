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
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::collections::VecDeque;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::Notify;

/// Item and logical-byte bounds for one Tokio multicast runtime queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedQueueLimits {
    /// Maximum retained queue items, including items staged by the runtime.
    pub max_items: usize,

    /// Maximum retained logical bytes.
    pub max_retained_bytes: usize,
}

impl RetainedQueueLimits {
    pub(super) fn validate(
        self, name: &'static str,
    ) -> Result<Self, RetainedQueueConfigError> {
        if self.max_items == 0 {
            return Err(RetainedQueueConfigError::ZeroItemCapacity(name));
        }
        if self.max_retained_bytes == 0 {
            return Err(RetainedQueueConfigError::ZeroByteCapacity(name));
        }

        Ok(self)
    }
}

/// Invalid retained runtime queue configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RetainedQueueConfigError {
    /// The queue could never retain an item.
    #[error("{0} queue item capacity must be greater than zero")]
    ZeroItemCapacity(&'static str),

    /// The queue could never retain an item with nonzero logical size.
    #[error("{0} queue byte capacity must be greater than zero")]
    ZeroByteCapacity(&'static str),
}

/// Point-in-time counters for one retained runtime queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedQueueStats {
    /// Configured maximum retained items.
    pub max_items: usize,

    /// Configured maximum retained logical bytes.
    pub max_retained_bytes: usize,

    /// Items currently retained by the channel or runtime staging.
    pub retained_items: usize,

    /// Logical bytes currently retained.
    pub retained_bytes: usize,

    /// Peak retained item count.
    pub peak_retained_items: usize,

    /// Peak retained logical bytes.
    pub peak_retained_bytes: usize,

    /// Items admitted since queue creation.
    pub admitted_items_total: u64,

    /// Admission attempts rejected by an item or byte bound.
    pub saturations_total: u64,

    /// Admission attempts rejected because one item exceeded the byte bound.
    pub oversized_items_total: u64,

    /// Admission attempts rejected after the receiver closed.
    pub closed_sends_total: u64,
}

pub(super) trait RetainedSize {
    fn retained_size(&self) -> usize;
}

#[derive(Default)]
struct QueueState {
    retained_items: usize,
    retained_bytes: usize,
    peak_retained_items: usize,
    peak_retained_bytes: usize,
    admitted_items_total: u64,
    saturations_total: u64,
    oversized_items_total: u64,
    closed_sends_total: u64,
}

struct QueueShared {
    limits: RetainedQueueLimits,
    state: Mutex<QueueState>,
    capacity_available: Notify,
}

impl QueueShared {
    fn stats(&self) -> RetainedQueueStats {
        let state = self.state.lock().expect("retained queue mutex poisoned");
        RetainedQueueStats {
            max_items: self.limits.max_items,
            max_retained_bytes: self.limits.max_retained_bytes,
            retained_items: state.retained_items,
            retained_bytes: state.retained_bytes,
            peak_retained_items: state.peak_retained_items,
            peak_retained_bytes: state.peak_retained_bytes,
            admitted_items_total: state.admitted_items_total,
            saturations_total: state.saturations_total,
            oversized_items_total: state.oversized_items_total,
            closed_sends_total: state.closed_sends_total,
        }
    }
}

#[derive(Clone, Copy)]
enum ReserveError {
    Full,
    Oversized,
}

struct QueuePermit {
    retained_bytes: usize,
    shared: Arc<QueueShared>,
}

impl Drop for QueuePermit {
    fn drop(&mut self) {
        {
            let mut state = self
                .shared
                .state
                .lock()
                .expect("retained queue mutex poisoned");
            state.retained_items = state.retained_items.saturating_sub(1);
            state.retained_bytes =
                state.retained_bytes.saturating_sub(self.retained_bytes);
        }
        self.shared.capacity_available.notify_one();
    }
}

pub(super) struct Queued<T> {
    value: Option<T>,
    _permit: QueuePermit,
}

impl<T> Queued<T> {
    pub(super) fn as_ref(&self) -> &T {
        self.value.as_ref().expect("queued value is present")
    }

    pub(super) fn take(&mut self) -> T {
        self.value.take().expect("queued value is present")
    }

    pub(super) fn restore(&mut self, value: T) {
        assert!(self.value.replace(value).is_none());
    }

    pub(super) fn into_inner(mut self) -> T {
        self.value.take().expect("queued value is present")
    }
}

/// Nonblocking retained-queue admission failure.
#[derive(Debug)]
pub(super) enum QueueSendError<T> {
    Full(T),
    Oversized(T),
    Closed(T),
}

impl<T> QueueSendError<T> {
    pub(super) fn into_inner(self) -> T {
        match self {
            Self::Full(value) | Self::Oversized(value) | Self::Closed(value) =>
                value,
        }
    }

    pub(super) fn map<U>(self, map: impl FnOnce(T) -> U) -> QueueSendError<U> {
        match self {
            Self::Full(value) => QueueSendError::Full(map(value)),
            Self::Oversized(value) => QueueSendError::Oversized(map(value)),
            Self::Closed(value) => QueueSendError::Closed(map(value)),
        }
    }
}

pub(super) struct BoundedSender<T> {
    sender: mpsc::Sender<Queued<T>>,
    shared: Arc<QueueShared>,
}

impl<T> Clone for BoundedSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T: RetainedSize> BoundedSender<T> {
    pub(super) fn try_send(&self, value: T) -> Result<(), QueueSendError<T>> {
        let queued = self.wrap(value)?;
        match self.sender.try_send(queued) {
            Ok(()) => Ok(()),

            Err(mpsc::error::TrySendError::Full(queued)) =>
                Err(QueueSendError::Full(queued.into_inner())),

            Err(mpsc::error::TrySendError::Closed(queued)) => {
                let value = queued.into_inner();
                self.record_closed_send();
                Err(QueueSendError::Closed(value))
            },
        }
    }

    pub(super) async fn send(&self, value: T) -> Result<(), QueueSendError<T>> {
        let mut value = value;
        loop {
            // Create the notification before checking capacity so a release
            // between the check and await leaves a stored permit.
            let capacity_available = self.shared.capacity_available.notified();
            match self.wrap(value) {
                Ok(queued) =>
                    return match self.sender.send(queued).await {
                        Ok(()) => Ok(()),

                        Err(error) => {
                            let value = error.0.into_inner();
                            self.record_closed_send();
                            Err(QueueSendError::Closed(value))
                        },
                    },

                Err(QueueSendError::Full(returned)) => {
                    value = returned;
                    tokio::select! {
                        _ = capacity_available => (),

                        _ = self.sender.closed() => {
                            self.record_closed_send();
                            return Err(QueueSendError::Closed(value));
                        },
                    }
                },

                Err(error @ QueueSendError::Oversized(..)) |
                Err(error @ QueueSendError::Closed(..)) => return Err(error),
            }
        }
    }

    pub(super) fn wrap(&self, value: T) -> Result<Queued<T>, QueueSendError<T>> {
        wrap(&self.shared, value)
    }

    pub(super) fn same_channel(&self, other: &Self) -> bool {
        self.sender.same_channel(&other.sender)
    }

    pub(super) fn limits(&self) -> RetainedQueueLimits {
        self.shared.limits
    }

    fn record_closed_send(&self) {
        let mut state = self
            .shared
            .state
            .lock()
            .expect("retained queue mutex poisoned");
        state.closed_sends_total = state.closed_sends_total.saturating_add(1);
    }
}

pub(super) struct BoundedReceiver<T> {
    receiver: mpsc::Receiver<Queued<T>>,
    shared: Arc<QueueShared>,
}

impl<T> BoundedReceiver<T> {
    pub(super) async fn recv(&mut self) -> Option<Queued<T>> {
        self.receiver.recv().await
    }

    pub(super) fn try_recv(&mut self) -> Result<Queued<T>, TryRecvError> {
        self.receiver.try_recv()
    }

    pub(super) fn close(&mut self) {
        self.receiver.close();
        self.shared.capacity_available.notify_waiters();
    }

    pub(super) fn budget(&self) -> RetainedQueueBudget<T> {
        RetainedQueueBudget {
            shared: Arc::clone(&self.shared),
            event: PhantomData,
        }
    }
}

impl<T> Drop for BoundedReceiver<T> {
    fn drop(&mut self) {
        self.receiver.close();
        self.shared.capacity_available.notify_waiters();
    }
}

pub(super) struct RetainedQueueBudget<T> {
    shared: Arc<QueueShared>,
    event: PhantomData<fn(T)>,
}

impl<T> Clone for RetainedQueueBudget<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            event: PhantomData,
        }
    }
}

impl<T> RetainedQueueBudget<T> {
    pub(super) fn cast<U>(&self) -> RetainedQueueBudget<U> {
        RetainedQueueBudget {
            shared: Arc::clone(&self.shared),
            event: PhantomData,
        }
    }
}

impl<T: RetainedSize> RetainedQueueBudget<T> {
    pub(super) fn wrap(&self, value: T) -> Result<Queued<T>, QueueSendError<T>> {
        wrap(&self.shared, value)
    }
}

pub(super) struct RetainedQueueObserver {
    shared: Arc<QueueShared>,
}

impl Clone for RetainedQueueObserver {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl RetainedQueueObserver {
    pub(super) fn stats(&self) -> RetainedQueueStats {
        self.shared.stats()
    }
}

pub(super) struct RetainedDeque<T> {
    queue: VecDeque<Queued<T>>,
    budget: RetainedQueueBudget<T>,
    observer: RetainedQueueObserver,
}

impl<T: RetainedSize> RetainedDeque<T> {
    pub(super) fn new(limits: RetainedQueueLimits) -> Self {
        let shared = Arc::new(QueueShared {
            limits,
            state: Mutex::new(QueueState::default()),
            capacity_available: Notify::new(),
        });
        Self {
            queue: VecDeque::new(),
            budget: RetainedQueueBudget {
                shared: Arc::clone(&shared),
                event: PhantomData,
            },
            observer: RetainedQueueObserver { shared },
        }
    }

    pub(super) fn push_back(
        &mut self, value: T,
    ) -> Result<(), QueueSendError<T>> {
        self.queue.push_back(self.budget.wrap(value)?);
        Ok(())
    }

    pub(super) fn push_front(
        &mut self, value: T,
    ) -> Result<(), QueueSendError<T>> {
        self.queue.push_front(self.budget.wrap(value)?);
        Ok(())
    }

    pub(super) fn pop_front(&mut self) -> Option<T> {
        self.queue.pop_front().map(Queued::into_inner)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub(super) fn clear(&mut self) {
        self.queue.clear();
    }

    pub(super) fn observer(&self) -> RetainedQueueObserver {
        self.observer.clone()
    }
}

pub(super) fn retained_queue_budget<T>(
    limits: RetainedQueueLimits,
) -> (RetainedQueueBudget<T>, RetainedQueueObserver) {
    let shared = Arc::new(QueueShared {
        limits,
        state: Mutex::new(QueueState::default()),
        capacity_available: Notify::new(),
    });
    (
        RetainedQueueBudget {
            shared: Arc::clone(&shared),
            event: PhantomData,
        },
        RetainedQueueObserver { shared },
    )
}

pub(super) fn bounded_channel<T>(
    limits: RetainedQueueLimits,
) -> (BoundedSender<T>, BoundedReceiver<T>, RetainedQueueObserver) {
    let (sender, receiver) = mpsc::channel(limits.max_items);
    let shared = Arc::new(QueueShared {
        limits,
        state: Mutex::new(QueueState::default()),
        capacity_available: Notify::new(),
    });

    (
        BoundedSender {
            sender,
            shared: Arc::clone(&shared),
        },
        BoundedReceiver {
            receiver,
            shared: Arc::clone(&shared),
        },
        RetainedQueueObserver { shared },
    )
}

fn reserve(
    shared: &Arc<QueueShared>, retained_bytes: usize,
) -> Result<QueuePermit, ReserveError> {
    let mut state = shared.state.lock().expect("retained queue mutex poisoned");
    if retained_bytes > shared.limits.max_retained_bytes {
        state.saturations_total = state.saturations_total.saturating_add(1);
        state.oversized_items_total =
            state.oversized_items_total.saturating_add(1);
        return Err(ReserveError::Oversized);
    }
    if state.retained_items >= shared.limits.max_items ||
        state.retained_bytes.saturating_add(retained_bytes) >
            shared.limits.max_retained_bytes
    {
        state.saturations_total = state.saturations_total.saturating_add(1);
        return Err(ReserveError::Full);
    }

    state.retained_items = state.retained_items.saturating_add(1);
    state.retained_bytes = state.retained_bytes.saturating_add(retained_bytes);
    state.peak_retained_items =
        state.peak_retained_items.max(state.retained_items);
    state.peak_retained_bytes =
        state.peak_retained_bytes.max(state.retained_bytes);
    state.admitted_items_total = state.admitted_items_total.saturating_add(1);

    Ok(QueuePermit {
        retained_bytes,
        shared: Arc::clone(shared),
    })
}

fn wrap<T: RetainedSize>(
    shared: &Arc<QueueShared>, value: T,
) -> Result<Queued<T>, QueueSendError<T>> {
    let retained_bytes = value.retained_size();
    let permit = match reserve(shared, retained_bytes) {
        Ok(permit) => permit,
        Err(ReserveError::Full) => return Err(QueueSendError::Full(value)),
        Err(ReserveError::Oversized) =>
            return Err(QueueSendError::Oversized(value)),
    };

    Ok(Queued {
        value: Some(value),
        _permit: permit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct TestItem(Vec<u8>);

    impl RetainedSize for TestItem {
        fn retained_size(&self) -> usize {
            self.0.len()
        }
    }

    #[test]
    fn retained_permit_follows_item_into_runtime_staging() {
        let limits = RetainedQueueLimits {
            max_items: 1,
            max_retained_bytes: 8,
        };
        let (sender, mut receiver, observer) = bounded_channel(limits);

        sender.try_send(TestItem(vec![1; 4])).unwrap();
        let staged = receiver.try_recv().unwrap();
        assert!(matches!(
            sender.try_send(TestItem(vec![2; 4])),
            Err(QueueSendError::Full(..))
        ));
        assert_eq!(observer.stats().retained_items, 1);
        assert_eq!(observer.stats().retained_bytes, 4);

        assert_eq!(staged.into_inner(), TestItem(vec![1; 4]));
        assert_eq!(observer.stats().retained_items, 0);
        sender.try_send(TestItem(vec![2; 4])).unwrap();
    }

    #[test]
    fn retained_queue_enforces_item_and_byte_bounds() {
        let limits = RetainedQueueLimits {
            max_items: 2,
            max_retained_bytes: 5,
        };
        let (sender, _receiver, observer) = bounded_channel(limits);

        sender.try_send(TestItem(vec![1; 3])).unwrap();
        assert!(matches!(
            sender.try_send(TestItem(vec![2; 3])),
            Err(QueueSendError::Full(..))
        ));
        assert!(matches!(
            sender.try_send(TestItem(vec![3; 6])),
            Err(QueueSendError::Oversized(..))
        ));

        let stats = observer.stats();
        assert_eq!(stats.retained_items, 1);
        assert_eq!(stats.retained_bytes, 3);
        assert_eq!(stats.peak_retained_items, 1);
        assert_eq!(stats.peak_retained_bytes, 3);
        assert_eq!(stats.saturations_total, 2);
        assert_eq!(stats.oversized_items_total, 1);
    }

    #[tokio::test]
    async fn async_send_waits_for_staged_item_capacity() {
        let limits = RetainedQueueLimits {
            max_items: 1,
            max_retained_bytes: 8,
        };
        let (sender, mut receiver, observer) = bounded_channel(limits);

        sender.try_send(TestItem(vec![1; 4])).unwrap();
        let staged = receiver.try_recv().unwrap();
        let blocked_sender = sender.clone();
        let blocked = tokio::spawn(async move {
            blocked_sender.send(TestItem(vec![2; 4])).await
        });

        tokio::task::yield_now().await;
        assert!(!blocked.is_finished());
        assert_eq!(observer.stats().retained_items, 1);

        drop(staged);
        blocked.await.unwrap().unwrap();
        assert_eq!(
            receiver.recv().await.unwrap().into_inner(),
            TestItem(vec![2; 4])
        );
    }

    #[tokio::test]
    async fn async_send_waits_for_logical_byte_capacity() {
        let limits = RetainedQueueLimits {
            max_items: 2,
            max_retained_bytes: 4,
        };
        let (sender, mut receiver, observer) = bounded_channel(limits);

        sender.try_send(TestItem(vec![1; 4])).unwrap();
        let blocked_sender = sender.clone();
        let blocked =
            tokio::spawn(
                async move { blocked_sender.send(TestItem(vec![2])).await },
            );

        tokio::task::yield_now().await;
        assert!(!blocked.is_finished());
        assert_eq!(observer.stats().retained_bytes, 4);

        drop(receiver.recv().await.unwrap());
        blocked.await.unwrap().unwrap();
        assert_eq!(
            receiver.recv().await.unwrap().into_inner(),
            TestItem(vec![2])
        );
    }

    #[tokio::test]
    async fn receiver_close_wakes_blocked_async_sender() {
        let limits = RetainedQueueLimits {
            max_items: 1,
            max_retained_bytes: 8,
        };
        let (sender, mut receiver, _) = bounded_channel(limits);

        sender.try_send(TestItem(vec![1; 4])).unwrap();
        let staged = receiver.try_recv().unwrap();
        let blocked_sender = sender.clone();
        let blocked = tokio::spawn(async move {
            blocked_sender.send(TestItem(vec![2; 4])).await
        });

        tokio::task::yield_now().await;
        receiver.close();
        assert!(matches!(
            blocked.await.unwrap(),
            Err(QueueSendError::Closed(TestItem(value))) if value == vec![2; 4]
        ));
        drop(staged);
    }

    #[tokio::test]
    async fn cancelling_blocked_send_does_not_leak_capacity() {
        let limits = RetainedQueueLimits {
            max_items: 1,
            max_retained_bytes: 8,
        };
        let (sender, mut receiver, observer) = bounded_channel(limits);

        sender.try_send(TestItem(vec![1; 4])).unwrap();
        let staged = receiver.try_recv().unwrap();
        let blocked_sender = sender.clone();
        let blocked = tokio::spawn(async move {
            blocked_sender.send(TestItem(vec![2; 4])).await
        });

        tokio::task::yield_now().await;
        blocked.abort();
        let _ = blocked.await;
        drop(staged);

        assert_eq!(observer.stats().retained_items, 0);
        sender.try_send(TestItem(vec![3; 4])).unwrap();
    }
}
