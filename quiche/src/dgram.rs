// Copyright (C) 2020, Cloudflare, Inc.
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

use crate::BufFactory;
use crate::Error;
use crate::Result;

use std::collections::VecDeque;

/// Hard retained-storage limits for one QUIC Datagram queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramQueueLimits {
    /// Maximum queued Datagram count.
    pub max_items: usize,

    /// Maximum readable payload bytes retained by the queue.
    pub max_bytes: usize,

    /// Maximum requested backing allocation retained by the queue.
    pub max_allocation_bytes: usize,
}

impl DatagramQueueLimits {
    pub(crate) const fn unbounded(max_items: usize) -> Self {
        Self {
            max_items,
            max_bytes: usize::MAX,
            max_allocation_bytes: usize::MAX,
        }
    }
}

/// Current physical and logical Datagram queue retention.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DatagramQueueStats {
    /// Queued Datagram count.
    pub items: usize,

    /// Readable payload bytes.
    pub bytes: usize,

    /// Requested backing allocation retained by queued Datagrams.
    pub allocation_bytes: usize,

    /// Highest queued Datagram count observed.
    pub high_water_items: usize,

    /// Highest readable payload-byte count observed.
    pub high_water_bytes: usize,

    /// Highest requested backing allocation observed.
    pub high_water_allocation_bytes: usize,
}

/// Keeps track of DATAGRAM frames.
#[derive(Default)]
pub struct DatagramQueue<F: BufFactory> {
    queue: VecDeque<QueuedDatagram<F::DgramBuf>>,
    queue_max_len: usize,
    queue_max_bytes: usize,
    queue_max_allocation_bytes: usize,
    queue_bytes_size: usize,
    queue_allocation_bytes: usize,
    high_water_len: usize,
    high_water_bytes: usize,
    high_water_allocation_bytes: usize,
}

struct QueuedDatagram<B> {
    data: B,
    allocation_bytes: usize,
}

impl<F: BufFactory> DatagramQueue<F> {
    pub fn with_queue_limits(limits: DatagramQueueLimits) -> Self {
        DatagramQueue {
            queue: VecDeque::new(),
            queue_bytes_size: 0,
            queue_allocation_bytes: 0,
            queue_max_len: limits.max_items,
            queue_max_bytes: limits.max_bytes,
            queue_max_allocation_bytes: limits.max_allocation_bytes,
            high_water_len: 0,
            high_water_bytes: 0,
            high_water_allocation_bytes: 0,
        }
    }

    pub fn set_limits(&mut self, limits: DatagramQueueLimits) -> Result<()> {
        self.can_set_limits(limits)?;
        self.queue_max_len = limits.max_items;
        self.queue_max_bytes = limits.max_bytes;
        self.queue_max_allocation_bytes = limits.max_allocation_bytes;
        Ok(())
    }

    pub fn can_set_limits(&self, limits: DatagramQueueLimits) -> Result<()> {
        if self.len() > limits.max_items ||
            self.queue_bytes_size > limits.max_bytes ||
            (limits.max_allocation_bytes != usize::MAX &&
                self.queue.iter().any(|item| {
                    F::dgram_buf_capacity(&item.data).is_none()
                })) ||
            self.queue_allocation_bytes > limits.max_allocation_bytes
        {
            return Err(Error::Done);
        }
        Ok(())
    }

    pub fn try_push(
        &mut self, data: F::DgramBuf,
    ) -> std::result::Result<(), (Error, F::DgramBuf)> {
        let len = data.as_ref().len();
        let allocation_bytes = match F::dgram_buf_capacity(&data) {
            Some(capacity) => capacity,
            None if self.queue_max_allocation_bytes == usize::MAX => 0,
            None => return Err((Error::InvalidState, data)),
        };
        let (next_bytes, next_allocation_bytes) =
            match self.can_push(len, allocation_bytes) {
                Ok(next) => next,
                Err(error) => return Err((error, data)),
            };

        let next_len = self.len() + 1;
        if next_len > self.queue_max_len {
            return Err((Error::Done, data));
        }

        self.queue_bytes_size = next_bytes;
        self.queue_allocation_bytes = next_allocation_bytes;
        self.queue.push_back(QueuedDatagram {
            data,
            allocation_bytes,
        });
        self.high_water_len = self.high_water_len.max(next_len);
        self.high_water_bytes = self.high_water_bytes.max(next_bytes);
        self.high_water_allocation_bytes =
            self.high_water_allocation_bytes.max(next_allocation_bytes);

        Ok(())
    }

    pub fn try_push_drop_oldest(
        &mut self, data: F::DgramBuf,
    ) -> std::result::Result<(), (Error, F::DgramBuf)> {
        let len = data.as_ref().len();
        let allocation_bytes = match F::dgram_buf_capacity(&data) {
            Some(capacity) => capacity,
            None if !self.has_finite_allocation_limit() => 0,
            None => return Err((Error::InvalidState, data)),
        };

        if !self.is_full() {
            return self.try_push(data);
        }

        let Some(front) = self.queue.front() else {
            return Err((Error::Done, data));
        };
        let retained_bytes = self
            .queue_bytes_size
            .saturating_sub(front.data.as_ref().len());
        let retained_allocation_bytes = self
            .queue_allocation_bytes
            .saturating_sub(front.allocation_bytes);
        let Some(next_bytes) = retained_bytes.checked_add(len) else {
            return Err((Error::Done, data));
        };
        let Some(next_allocation_bytes) =
            retained_allocation_bytes.checked_add(allocation_bytes)
        else {
            return Err((Error::Done, data));
        };

        if self.queue_max_len == 0 ||
            next_bytes > self.queue_max_bytes ||
            next_allocation_bytes > self.queue_max_allocation_bytes
        {
            return Err((Error::Done, data));
        }

        self.pop();
        self.try_push(data)
    }

    pub fn can_push(
        &self, len: usize, allocation_bytes: usize,
    ) -> Result<(usize, usize)> {
        let next_len = self.len().checked_add(1).ok_or(Error::Done)?;
        let next_bytes =
            self.queue_bytes_size.checked_add(len).ok_or(Error::Done)?;
        let next_allocation_bytes = self
            .queue_allocation_bytes
            .checked_add(allocation_bytes)
            .ok_or(Error::Done)?;

        if next_len > self.queue_max_len ||
            next_bytes > self.queue_max_bytes ||
            next_allocation_bytes > self.queue_max_allocation_bytes
        {
            return Err(Error::Done);
        }

        Ok((next_bytes, next_allocation_bytes))
    }

    pub fn has_finite_allocation_limit(&self) -> bool {
        self.queue_max_allocation_bytes != usize::MAX
    }

    pub fn peek_front_len(&self) -> Option<usize> {
        self.queue.front().map(|d| d.data.as_ref().len())
    }

    pub fn peek_front_bytes(&self, buf: &mut [u8], len: usize) -> Result<usize> {
        match self.queue.front() {
            Some(d) => {
                let len = std::cmp::min(len, d.data.as_ref().len());
                if buf.len() < len {
                    return Err(Error::BufferTooShort);
                }

                buf[..len].copy_from_slice(&d.data.as_ref()[..len]);
                Ok(len)
            },

            None => Err(Error::Done),
        }
    }

    pub fn pop(&mut self) -> Option<F::DgramBuf> {
        if let Some(d) = self.queue.pop_front() {
            self.queue_bytes_size =
                self.queue_bytes_size.saturating_sub(d.data.as_ref().len());
            self.queue_allocation_bytes = self
                .queue_allocation_bytes
                .saturating_sub(d.allocation_bytes);
            return Some(d.data);
        }

        None
    }

    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    pub fn purge<FN: Fn(&[u8]) -> bool>(&mut self, f: FN) {
        self.queue.retain(|d| !f(d.data.as_ref()));
        self.queue_bytes_size = self
            .queue
            .iter()
            .fold(0, |total, d| total + d.data.as_ref().len());
        self.queue_allocation_bytes = self
            .queue
            .iter()
            .fold(0, |total, d| total + d.allocation_bytes);
    }

    pub fn is_full(&self) -> bool {
        self.len() >= self.queue_max_len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn byte_size(&self) -> usize {
        self.queue_bytes_size
    }

    pub fn allocation_size(&self) -> usize {
        self.queue_allocation_bytes
    }

    pub fn limits(&self) -> DatagramQueueLimits {
        DatagramQueueLimits {
            max_items: self.queue_max_len,
            max_bytes: self.queue_max_bytes,
            max_allocation_bytes: self.queue_max_allocation_bytes,
        }
    }

    pub fn stats(&self) -> DatagramQueueStats {
        DatagramQueueStats {
            items: self.len(),
            bytes: self.byte_size(),
            allocation_bytes: self.allocation_size(),
            high_water_items: self.high_water_len,
            high_water_bytes: self.high_water_bytes,
            high_water_allocation_bytes: self.high_water_allocation_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffers::DefaultBufFactory;

    fn exact_vec(data: &[u8]) -> Vec<u8> {
        data.to_vec().into_boxed_slice().into_vec()
    }

    #[test]
    fn item_byte_and_allocation_caps_are_transactional() {
        let limits = DatagramQueueLimits {
            max_items: 1,
            max_bytes: 4,
            max_allocation_bytes: 4,
        };
        let mut queue =
            DatagramQueue::<DefaultBufFactory>::with_queue_limits(limits);

        let oversized = exact_vec(b"12345");
        assert_eq!(oversized.capacity(), 5);
        let (error, oversized) = queue.try_push(oversized).unwrap_err();
        assert_eq!(error, Error::Done);
        assert_eq!(oversized.as_slice(), b"12345");
        assert_eq!(queue.stats(), DatagramQueueStats::default());

        let exact = exact_vec(b"1234");
        assert_eq!(exact.capacity(), 4);
        queue.try_push(exact).unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.byte_size(), 4);
        assert_eq!(queue.allocation_size(), 4);

        let second = exact_vec(b"x");
        let (error, second) = queue.try_push(second).unwrap_err();
        assert_eq!(error, Error::Done);
        assert_eq!(second.as_slice(), b"x");
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pop().unwrap().as_slice(), b"1234");
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.byte_size(), 0);
        assert_eq!(queue.allocation_size(), 0);
    }

    #[test]
    fn lowering_limits_below_retention_does_not_mutate_queue() {
        let mut queue = DatagramQueue::<DefaultBufFactory>::with_queue_limits(
            DatagramQueueLimits {
                max_items: 2,
                max_bytes: 8,
                max_allocation_bytes: 8,
            },
        );
        queue.try_push(exact_vec(b"1234")).unwrap();
        let before = queue.stats();
        assert_eq!(
            queue.set_limits(DatagramQueueLimits {
                max_items: 0,
                max_bytes: 3,
                max_allocation_bytes: 3,
            }),
            Err(Error::Done)
        );
        assert_eq!(queue.stats(), before);
        assert_eq!(queue.limits(), DatagramQueueLimits {
            max_items: 2,
            max_bytes: 8,
            max_allocation_bytes: 8,
        });
    }
}
