// Copyright (C) 2023, Cloudflare, Inc.
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

use std::cmp;

use std::collections::VecDeque;
use std::mem::size_of;
use std::sync::Arc;
use std::sync::Mutex;

use crate::buffers::BufSplit;
use crate::range_buf::RangeBuf;
use crate::BufFactory;
use crate::Error;
use crate::Result;

use crate::buffers::DefaultBufFactory;
use crate::ranges;

use super::StreamReset;

#[cfg(test)]
const SEND_BUFFER_SIZE: usize = 5;

#[cfg(not(test))]
const SEND_BUFFER_SIZE: usize = 4096;

/// Hard allocation bounds for retained stream-send data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamSendRetentionLimits {
    /// Maximum requested backing capacity retained by copied stream chunks.
    pub max_bytes: usize,

    /// Maximum retained copied or externally-backed stream chunks.
    pub max_chunks: usize,
}

impl Default for StreamSendRetentionLimits {
    fn default() -> Self {
        Self {
            max_bytes: usize::MAX,
            max_chunks: usize::MAX,
        }
    }
}

/// Current and high-water stream-send retention accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StreamSendRetentionStats {
    /// Requested backing capacity currently retained by copied chunks.
    pub retained_bytes: usize,

    /// Copied or externally-backed chunks currently retained.
    pub retained_chunks: usize,

    /// Largest observed retained copied backing capacity.
    pub high_water_bytes: usize,

    /// Largest observed retained chunk count.
    pub high_water_chunks: usize,
}

#[derive(Debug, Default)]
struct StreamSendRetentionState {
    limits: StreamSendRetentionLimits,
    retained_bytes: usize,
    retained_chunks: usize,
    high_water_bytes: usize,
    high_water_chunks: usize,
}

/// Connection-scoped retention accounting shared by every send buffer.
#[derive(Debug, Default)]
pub(crate) struct StreamSendRetention {
    state: Mutex<StreamSendRetentionState>,
}

impl StreamSendRetention {
    pub(crate) fn new(limits: StreamSendRetentionLimits) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(StreamSendRetentionState {
                limits,
                ..StreamSendRetentionState::default()
            }),
        })
    }

    fn is_bounded(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .limits !=
            StreamSendRetentionLimits::default()
    }

    fn try_reserve(
        self: &Arc<Self>, bytes: usize, chunks: usize,
    ) -> Result<StreamSendReservation> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next_bytes =
            state.retained_bytes.checked_add(bytes).ok_or(Error::Done)?;
        let next_chunks = state
            .retained_chunks
            .checked_add(chunks)
            .ok_or(Error::Done)?;
        if next_bytes > state.limits.max_bytes ||
            next_chunks > state.limits.max_chunks
        {
            return Err(Error::Done);
        }

        state.retained_bytes = next_bytes;
        state.retained_chunks = next_chunks;
        state.high_water_bytes = state.high_water_bytes.max(next_bytes);
        state.high_water_chunks = state.high_water_chunks.max(next_chunks);
        drop(state);

        Ok(StreamSendReservation {
            accounting: Arc::clone(self),
            remaining_bytes: bytes,
            remaining_chunks: chunks,
        })
    }

    fn release(&self, bytes: usize, chunks: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(state.retained_bytes >= bytes);
        debug_assert!(state.retained_chunks >= chunks);
        state.retained_bytes = state.retained_bytes.saturating_sub(bytes);
        state.retained_chunks = state.retained_chunks.saturating_sub(chunks);
    }

    pub(crate) fn stats(&self) -> StreamSendRetentionStats {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        StreamSendRetentionStats {
            retained_bytes: state.retained_bytes,
            retained_chunks: state.retained_chunks,
            high_water_bytes: state.high_water_bytes,
            high_water_chunks: state.high_water_chunks,
        }
    }

    pub(crate) fn limits(&self) -> StreamSendRetentionLimits {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .limits
    }

    pub(crate) fn set_limits(
        &self, limits: StreamSendRetentionLimits,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.retained_bytes > limits.max_bytes ||
            state.retained_chunks > limits.max_chunks
        {
            return Err(Error::Done);
        }
        state.limits = limits;
        Ok(())
    }
}

pub(crate) struct StreamSendReservation {
    accounting: Arc<StreamSendRetention>,
    remaining_bytes: usize,
    remaining_chunks: usize,
}

impl StreamSendReservation {
    pub(crate) fn charge(
        &mut self, bytes: usize, chunks: usize,
    ) -> Arc<StreamSendCharge> {
        debug_assert!(bytes <= self.remaining_bytes);
        debug_assert!(chunks <= self.remaining_chunks);
        self.remaining_bytes = self.remaining_bytes.saturating_sub(bytes);
        self.remaining_chunks = self.remaining_chunks.saturating_sub(chunks);
        Arc::new(StreamSendCharge {
            accounting: Arc::clone(&self.accounting),
            bytes,
            chunks,
        })
    }
}

impl Drop for StreamSendReservation {
    fn drop(&mut self) {
        self.accounting
            .release(self.remaining_bytes, self.remaining_chunks);
    }
}

#[derive(Debug)]
pub(crate) struct StreamSendCharge {
    accounting: Arc<StreamSendRetention>,
    bytes: usize,
    chunks: usize,
}

impl Drop for StreamSendCharge {
    fn drop(&mut self) {
        self.accounting.release(self.bytes, self.chunks);
    }
}

impl StreamSendCharge {
    pub(crate) fn try_reserve_sibling(&self) -> Result<Arc<StreamSendCharge>> {
        let mut reservation = self.accounting.try_reserve(0, 1)?;
        Ok(reservation.charge(0, 1))
    }
}

pub(super) const fn retained_chunk_metadata_size<F: BufFactory>() -> usize {
    size_of::<RangeBuf<F>>() +
        size_of::<StreamSendCharge>() +
        4 * size_of::<usize>()
}

struct SendReserve<'a, F: BufFactory> {
    inner: &'a mut SendBuf<F>,
    reserved: usize,
    fin: bool,
}

impl<F: BufFactory> SendReserve<'_, F> {
    fn append_buf(
        &mut self, buf: F::Buf, charge: Arc<StreamSendCharge>,
    ) -> Result<()> {
        let len = buf.as_ref().len();
        let inner = &mut self.inner;

        if len > self.reserved {
            return Err(Error::BufferTooShort);
        }

        let fin: bool = self.reserved == len && self.fin;

        let buf = RangeBuf::from_raw_retained(buf, inner.off, fin, charge);

        // The new data can simply be appended at the end of the send buffer.
        inner.data.push_back(buf);

        inner.off += len as u64;
        inner.buffered_bytes += len as u64;
        self.reserved -= len;

        Ok(())
    }
}

impl<F: BufFactory> Drop for SendReserve<'_, F> {
    fn drop(&mut self) {
        assert_eq!(self.reserved, 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SendResetState {
    frame: StreamReset,
    acked: bool,
}

impl SendResetState {
    fn error_code(self) -> u64 {
        match self.frame {
            StreamReset::Reset { error_code, .. } |
            StreamReset::ResetAt { error_code, .. } => error_code,
        }
    }

    fn final_size(self) -> u64 {
        match self.frame {
            StreamReset::Reset { final_size, .. } |
            StreamReset::ResetAt { final_size, .. } => final_size,
        }
    }

    fn reliable_size(self) -> u64 {
        match self.frame {
            StreamReset::Reset { .. } => 0,
            StreamReset::ResetAt { reliable_size, .. } => reliable_size,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SendResetOutcome {
    pub(crate) final_size: u64,
    pub(crate) dropped_tx_data: u64,
    pub(crate) dropped_buffered: usize,
    pub(crate) changed: bool,
}

/// Send-side stream buffer.
///
/// Stream data scheduled to be sent to the peer is buffered in a list of data
/// chunks ordered by offset in ascending order. Contiguous data can then be
/// read into a slice.
///
/// By default, new data is appended at the end of the stream, but data can be
/// inserted at the start of the buffer (this is to allow data that needs to be
/// retransmitted to be re-buffered).
#[derive(Debug, Default)]
pub struct SendBuf<F = DefaultBufFactory>
where
    F: BufFactory,
{
    /// Chunks of data to be sent, ordered by offset.
    data: VecDeque<RangeBuf<F>>,

    /// The index of the buffer that needs to be sent next.
    pos: usize,

    /// The maximum offset of data buffered in the stream.
    off: u64,

    /// The maximum offset of data sent to the peer, regardless of
    /// retransmissions.
    emit_off: u64,

    /// The number of bytes buffered and ready to be emitted to the peer.
    ///
    /// This includes fresh data that has not yet been sent, as well as data
    /// marked for retransmission. It excludes data that has been emitted but
    /// not yet acknowledged (in-flight data).
    buffered_bytes: u64,

    /// The maximum offset we are allowed to send to the peer.
    max_data: u64,

    /// The last offset the stream was blocked at, if any.
    blocked_at: Option<u64>,

    /// The final stream offset written to the stream, if any.
    fin_off: Option<u64>,

    /// Whether an ordinary STREAM frame conveying the final size was acked.
    fin_acked: bool,

    /// Whether the stream's send-side has been shut down.
    shutdown: bool,

    /// Locally generated stream termination, when one is outstanding.
    reset: Option<SendResetState>,

    /// Ranges of data offsets that have been acked.
    acked: ranges::RangeSet,

    /// The error code received via STOP_SENDING.
    error: Option<u64>,

    /// Connection-scoped hard retention accounting.
    retention: Arc<StreamSendRetention>,
}

impl<F: BufFactory> SendBuf<F> {
    /// Creates a new send buffer.
    #[cfg(test)]
    pub fn new(max_data: u64) -> SendBuf<F> {
        Self::new_with_retention(
            max_data,
            StreamSendRetention::new(StreamSendRetentionLimits::default()),
        )
    }

    pub(crate) fn new_with_retention(
        max_data: u64, retention: Arc<StreamSendRetention>,
    ) -> SendBuf<F> {
        SendBuf {
            max_data,
            retention,
            ..SendBuf::default()
        }
    }

    /// Try to reserve the required number of bytes to be sent
    fn reserve_for_write(
        &mut self, mut len: usize, mut fin: bool,
    ) -> Result<SendReserve<'_, F>> {
        if self.shutdown {
            return Err(Error::FinalSize);
        }

        let max_off = self.off + len as u64;

        // Get the stream send capacity. This will return an error if the stream
        // was stopped.
        if len > self.cap()? {
            len = self.cap()?;
            fin = false;
        }

        if let Some(fin_off) = self.fin_off {
            // Can't write past final offset.
            if max_off > fin_off {
                return Err(Error::FinalSize);
            }

            // Can't "undo" final offset.
            if max_off == fin_off && !fin {
                return Err(Error::FinalSize);
            }
        }

        if fin {
            self.fin_off = Some(max_off);
            self.fin_acked = false;
        }

        // Don't queue data that was already fully acked.
        if self.ack_off() >= max_off {
            return Ok(SendReserve {
                inner: self,
                reserved: 0,
                fin,
            });
        }

        Ok(SendReserve {
            inner: self,
            reserved: len,
            fin,
        })
    }

    /// Inserts the given slice of data at the end of the buffer.
    ///
    /// The number of bytes that were actually stored in the buffer is returned
    /// (this may be lower than the size of the input buffer, in case of partial
    /// writes).
    pub fn write(&mut self, data: &[u8], fin: bool) -> Result<usize> {
        let writable = self.preflight_write_len(data.len(), fin)?;
        let chunks = writable.div_ceil(SEND_BUFFER_SIZE);
        let retained_bytes = data[..writable].chunks(SEND_BUFFER_SIZE).try_fold(
            0usize,
            |total, chunk| {
                let capacity = F::buf_from_slice_capacity(chunk.len())
                    .or_else(|| (!self.retention.is_bounded()).then_some(0))
                    .ok_or(Error::InvalidState)?;
                total.checked_add(capacity).ok_or(Error::Done)
            },
        )?;
        let mut retention = self.retention.try_reserve(retained_bytes, chunks)?;
        let mut reserve = self.reserve_for_write(data.len(), fin)?;

        if reserve.reserved == 0 {
            return Ok(0);
        }

        let ret = reserve.reserved;

        // Split the remaining input data into consistently-sized buffers to
        // avoid fragmentation.
        for chunk in data[..reserve.reserved].chunks(SEND_BUFFER_SIZE) {
            let capacity = F::buf_from_slice_capacity(chunk.len()).unwrap_or(0);
            reserve.append_buf(
                F::buf_from_slice(chunk),
                retention.charge(capacity, 1),
            )?;
        }

        Ok(ret)
    }

    /// Inserts the given buffer of data at the end of the buffer.
    ///
    /// The number of bytes that were actually stored in the buffer is returned
    /// (this may be lower than the size of the input buffer, in case of partial
    /// writes, in which case the unwritten buffer is also returned).
    pub fn append_buf(
        &mut self, mut data: F::Buf, cap: usize, fin: bool,
    ) -> Result<(usize, Option<F::Buf>)>
    where
        F::Buf: BufSplit,
    {
        let len = data.as_ref().len();
        let writable = self.preflight_write_len(cap.min(len), fin)?;
        let mut retention =
            self.retention.try_reserve(0, usize::from(writable > 0))?;
        let mut reserve = self.reserve_for_write(cap.min(len), fin)?;

        if reserve.reserved == 0 {
            return Ok((0, Some(data)));
        }

        let remainder =
            (reserve.reserved < len).then(|| data.split_at(reserve.reserved));

        let ret = reserve.reserved;

        reserve.append_buf(data, retention.charge(0, 1))?;

        Ok((ret, remainder))
    }

    /// Retains data at the current stream offset for multicast delivery.
    ///
    /// When `transmit` is false, the bytes remain available for later
    /// retransmission but are initially treated as already emitted. This lets a
    /// multicast sender release the exact range over unicast if channel
    /// delivery later fails.
    pub(crate) fn write_at(
        &mut self, data: F::Buf, offset: u64, fin: bool, transmit: bool,
    ) -> Result<usize> {
        if self.shutdown {
            return Err(Error::Done);
        }

        if let Some(error) = self.error {
            return Err(Error::StreamStopped(error));
        }

        if offset != self.off {
            return Err(Error::InvalidState);
        }

        let len = data.as_ref().len();
        let max_off =
            offset.checked_add(len as u64).ok_or(Error::InvalidState)?;

        if max_off > self.max_data {
            return Err(Error::Done);
        }

        if let Some(fin_off) = self.fin_off {
            if max_off > fin_off || (fin && max_off != fin_off) {
                return Err(Error::FinalSize);
            }

            if max_off == fin_off && !fin {
                return Err(Error::FinalSize);
            }
        }

        let mut retention =
            self.retention.try_reserve(0, usize::from(len > 0))?;

        if fin {
            self.fin_off = Some(max_off);
            self.fin_acked = false;
        }

        if len > 0 {
            let mut buf = RangeBuf::from_raw_retained(
                data,
                offset,
                fin,
                retention.charge(0, 1),
            );

            if !transmit {
                buf.consume(len);
            }

            self.data.push_back(buf);
        }

        self.off = max_off;

        if transmit {
            self.buffered_bytes += len as u64;
        }

        Ok(len)
    }

    fn preflight_write_len(&self, mut len: usize, fin: bool) -> Result<usize> {
        if self.shutdown {
            return Err(Error::FinalSize);
        }

        let max_off = self.off.checked_add(len as u64).ok_or(Error::FinalSize)?;
        len = len.min(self.cap()?);

        if let Some(fin_off) = self.fin_off {
            if max_off > fin_off || (max_off == fin_off && !fin) {
                return Err(Error::FinalSize);
            }
        }

        if self.ack_off() >= max_off {
            return Ok(0);
        }

        Ok(len)
    }

    /// Writes data from the send buffer into the given output buffer.
    pub fn emit(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut out_len = out.len();
        let out_off = self.off_front();

        let mut next_off = out_off;

        while out_len > 0 {
            let off_front = self.off_front();

            if self.is_empty() ||
                off_front >= self.off ||
                off_front != next_off ||
                off_front >= self.max_data
            {
                break;
            }

            let buf = match self.data.get_mut(self.pos) {
                Some(v) => v,

                None => break,
            };

            if buf.is_empty() {
                self.pos += 1;
                continue;
            }

            let buf_len = cmp::min(buf.len(), out_len);
            let partial = buf_len < buf.len();

            // Copy data to the output buffer.
            let out_pos = (next_off - out_off) as usize;
            out[out_pos..out_pos + buf_len].copy_from_slice(&buf[..buf_len]);

            self.buffered_bytes -= buf_len as u64;

            out_len -= buf_len;

            next_off = buf.off() + buf_len as u64;

            buf.consume(buf_len);

            if partial {
                // We reached the maximum capacity, so end here.
                break;
            }

            self.pos += 1;
        }

        // Override the `fin` flag set for the output buffer by matching the
        // buffer's maximum offset against the stream's final offset (if known).
        //
        // This is more efficient than tracking `fin` using the range buffers
        // themselves, and lets us avoid queueing empty buffers just so we can
        // propagate the final size.
        let fin = self.fin_off == Some(next_off);

        // Record the largest offset that has been sent so we can accurately
        // report final_size
        self.emit_off = cmp::max(self.emit_off, next_off);

        Ok((out.len() - out_len, fin))
    }

    /// Updates the max_data limit to the given value.
    pub fn update_max_data(&mut self, max_data: u64) {
        self.max_data = cmp::max(self.max_data, max_data);
    }

    /// Updates the last offset the stream was blocked at, if any.
    pub fn update_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.blocked_at = blocked_at;
    }

    /// The last offset the stream was blocked at, if any.
    pub fn blocked_at(&self) -> Option<u64> {
        self.blocked_at
    }

    /// Increments the acked data offset.
    pub fn ack(&mut self, off: u64, len: usize) {
        self.acked.insert(off..off + len as u64);
    }

    pub fn ack_and_drop(&mut self, off: u64, len: usize) -> usize {
        self.ack(off, len);

        let ack_off = self.ack_off();

        if self.data.is_empty() {
            return 0;
        }

        if off > ack_off {
            return 0;
        }

        let mut drop_until = None;

        // Drop contiguously acked data from the front of the buffer.
        for (i, buf) in self.data.iter_mut().enumerate() {
            // Newly acked range is past highest contiguous acked range, so we
            // can't drop it.
            if buf.off >= ack_off {
                break;
            }

            // Highest contiguous acked range falls within newly acked range,
            // so we can't drop it.
            if buf.off < ack_off && ack_off < buf.max_off() {
                break;
            }

            // Newly acked range can be dropped.
            drop_until = Some(i);
        }

        if let Some(drop) = drop_until {
            // Calculate the total length of buffers being dropped and subtract
            // from buffered_bytes.
            let dropped_len: u64 =
                (0..=drop).map(|i| self.data[i].len() as u64).sum();
            self.buffered_bytes = self.buffered_bytes.saturating_sub(dropped_len);

            self.data.drain(..=drop);

            // When a buffer is marked for retransmission, but then acked before
            // it could be retransmitted, we might end up decreasing the SendBuf
            // position too much, so make sure that doesn't happen.
            self.pos = self.pos.saturating_sub(drop + 1);

            dropped_len as usize
        } else {
            0
        }
    }

    /// Marks the frame carrying the stream's final size as acknowledged.
    pub(crate) fn ack_fin(&mut self, final_size: u64) {
        if self.fin_off == Some(final_size) {
            self.fin_acked = true;
        }
    }

    pub fn retransmit(&mut self, off: u64, len: usize) -> usize {
        let max_off = off.saturating_add(len as u64);
        let max_off = self
            .reset
            .map_or(max_off, |reset| max_off.min(reset.reliable_size()));
        let ack_off = self.ack_off();

        if self.data.is_empty() || off >= max_off {
            return 0;
        }

        if max_off <= ack_off {
            return 0;
        }

        let mut total_retransmitted = 0;

        for i in 0..self.data.len() {
            let buf = &mut self.data[i];

            if buf.off >= max_off {
                break;
            }

            if off > buf.max_off() {
                continue;
            }

            // Split the buffer into 2 if the retransmit range ends before the
            // buffer's final offset.
            let new_buf = if buf.off < max_off && max_off < buf.max_off() {
                // If metadata capacity is exhausted, retransmitting the
                // containing suffix is conservative and avoids growing state.
                buf.try_split_off_retained((max_off - buf.off) as usize)
                    .ok()
            } else {
                None
            };

            let prev_pos = buf.pos;

            // Reduce the buffer's position (expand the buffer) if the retransmit
            // range is past the buffer's starting offset.
            buf.pos = if off > buf.off && off <= buf.max_off() {
                cmp::min(buf.pos, buf.start + (off - buf.off) as usize)
            } else {
                buf.start
            };

            self.pos = cmp::min(self.pos, i);

            let retransmitted = (prev_pos - buf.pos) as u64;
            self.buffered_bytes += retransmitted;
            total_retransmitted += retransmitted;

            if let Some(b) = new_buf {
                self.data.insert(i + 1, b);
            }
        }

        total_retransmitted as usize
    }

    fn retained_covers(&self, end: u64) -> bool {
        if end == 0 {
            return true;
        }

        if end > self.off {
            return false;
        }

        let mut acked_ranges = self.acked.iter().peekable();
        let mut retained = self
            .data
            .iter()
            .map(|buf| buf.off..buf.off.saturating_add(buf.len as u64))
            .filter(|range| !range.is_empty())
            .peekable();
        let mut covered = 0;

        while covered < end {
            let next = match (acked_ranges.peek(), retained.peek()) {
                (Some(acked), Some(retained))
                    if acked.start <= retained.start =>
                    acked_ranges.next(),

                (Some(_), Some(_)) => retained.next(),

                (Some(_), None) => acked_ranges.next(),

                (None, Some(_)) => retained.next(),

                (None, None) => return false,
            };

            let Some(range) = next else {
                return false;
            };

            if range.start > covered {
                return false;
            }

            covered = covered.max(range.end);
        }

        true
    }

    fn discard_after(&mut self, end: u64) -> usize {
        let mut dropped_buffered = 0_u64;
        let mut truncate_at = self.data.len();

        for i in 0..self.data.len() {
            let buf = &mut self.data[i];
            let buf_start = buf.off;
            let buf_end = buf.off.saturating_add(buf.len as u64);

            if buf_start >= end {
                truncate_at = i;
                break;
            }

            if end < buf_end {
                let split_at = usize::try_from(end - buf_start)
                    .expect("range length is already represented as usize");
                dropped_buffered = dropped_buffered
                    .saturating_add(buf.truncate_total(split_at) as u64);
                truncate_at = i + 1;
                break;
            }
        }

        for buf in self.data.iter().skip(truncate_at) {
            dropped_buffered = dropped_buffered.saturating_add(buf.len() as u64);
        }
        self.data.truncate(truncate_at);
        self.pos = self.pos.min(self.data.len());
        self.buffered_bytes =
            self.buffered_bytes.saturating_sub(dropped_buffered);

        usize::try_from(dropped_buffered).unwrap_or(usize::MAX)
    }

    fn terminate(&mut self, frame: StreamReset) -> Result<SendResetOutcome> {
        let next = SendResetState {
            frame,
            acked: false,
        };
        let final_size = next.final_size();
        let reliable_size = next.reliable_size();

        if reliable_size > final_size {
            return Err(Error::FinalSize);
        }

        if let Some(fin_off) = self.fin_off {
            if fin_off != final_size {
                return Err(Error::InvalidState);
            }
        }

        if let Some(current) = self.reset {
            if current.error_code() != next.error_code() ||
                current.final_size() != final_size ||
                reliable_size > current.reliable_size()
            {
                return Err(Error::InvalidState);
            }

            if reliable_size == current.reliable_size() {
                return Ok(SendResetOutcome {
                    final_size,
                    dropped_tx_data: 0,
                    dropped_buffered: 0,
                    changed: false,
                });
            }
        }

        if !self.retained_covers(reliable_size) {
            return Err(Error::InvalidState);
        }

        let dropped_tx_data = if self.reset.is_none() {
            self.off.saturating_sub(final_size)
        } else {
            0
        };
        let dropped_buffered = self.discard_after(reliable_size);

        self.off = final_size;
        self.fin_off = Some(final_size);
        self.blocked_at = None;
        self.reset = Some(next);

        Ok(SendResetOutcome {
            final_size,
            dropped_tx_data,
            dropped_buffered,
            changed: true,
        })
    }

    /// Resets the streams and records the received error code.
    ///
    /// Calling this again after the first time has no effect.
    pub(crate) fn stop(
        &mut self, error_code: u64, final_size: u64, reliable_size: Option<u64>,
    ) -> Result<SendResetOutcome> {
        if self.error.is_some() {
            return Err(Error::Done);
        }

        let outcome = if let Some(reset) = self.reset {
            SendResetOutcome {
                final_size: reset.final_size(),
                dropped_tx_data: 0,
                dropped_buffered: 0,
                changed: false,
            }
        } else {
            let reset = match reliable_size {
                Some(reliable_size) => StreamReset::ResetAt {
                    error_code,
                    final_size,
                    reliable_size,
                },
                None => StreamReset::Reset {
                    error_code,
                    final_size,
                },
            };
            self.terminate(reset)?
        };

        self.error = Some(error_code);

        Ok(outcome)
    }

    /// Shuts down sending data.
    pub(crate) fn shutdown(
        &mut self, error_code: u64, final_size: u64,
    ) -> Result<SendResetOutcome> {
        if self.reset.is_some() && self.is_complete() {
            return Err(Error::Done);
        }

        if self.shutdown &&
            self.reset.is_none_or(|reset| reset.reliable_size() == 0)
        {
            return Err(Error::Done);
        }

        let outcome = self.terminate(StreamReset::Reset {
            error_code,
            final_size,
        })?;
        self.shutdown = true;

        Ok(outcome)
    }

    /// Shuts down sending while retaining a reliably delivered prefix.
    pub(crate) fn shutdown_at(
        &mut self, error_code: u64, final_size: u64, reliable_size: u64,
    ) -> Result<SendResetOutcome> {
        if self.is_complete() {
            return Err(Error::Done);
        }

        let outcome = self.terminate(StreamReset::ResetAt {
            error_code,
            final_size,
            reliable_size,
        })?;
        self.shutdown = true;

        Ok(outcome)
    }

    /// Returns the final size for an ordinary locally generated reset.
    pub(crate) fn ordinary_reset_final_size(&self) -> u64 {
        self.reset.map_or_else(
            || self.fin_off.unwrap_or(self.emit_off),
            SendResetState::final_size,
        )
    }

    /// Returns the final size for a locally generated reliable reset.
    pub(crate) fn reliable_reset_final_size(&self) -> u64 {
        self.reset.map_or_else(
            || self.fin_off.unwrap_or(self.off),
            SendResetState::final_size,
        )
    }

    /// Returns the current reset frame while it still needs acknowledgement.
    pub(crate) fn pending_reset(&self) -> Option<StreamReset> {
        self.reset
            .filter(|reset| !reset.acked)
            .map(|reset| reset.frame)
    }

    /// Marks an exact current reset frame as acknowledged.
    pub(crate) fn ack_reset(&mut self, frame: StreamReset) -> bool {
        let Some(reset) = self.reset.as_mut() else {
            return false;
        };

        if reset.frame != frame {
            return false;
        }

        reset.acked = true;
        true
    }

    /// Returns whether a reliable or ordinary reset has been initiated.
    pub(crate) fn is_reset(&self) -> bool {
        self.reset.is_some()
    }

    /// Returns whether buffered data is still eligible for transmission.
    pub(crate) fn can_send_buffered(&self) -> bool {
        self.reset.map_or_else(
            || !self.is_stopped(),
            |reset| self.ack_off() < reset.reliable_size(),
        )
    }

    /// Returns the largest offset of data buffered.
    pub fn off_back(&self) -> u64 {
        self.off
    }

    /// Returns the lowest offset of data buffered.
    pub fn off_front(&self) -> u64 {
        let mut pos = self.pos;

        // Skip empty buffers from the start of the queue.
        while let Some(b) = self.data.get(pos) {
            if !b.is_empty() {
                return b.off();
            }

            pos += 1;
        }

        self.off
    }

    /// The maximum offset we are allowed to send to the peer.
    pub fn max_off(&self) -> u64 {
        self.max_data
    }

    /// Returns true if all data in the stream has been sent.
    ///
    /// This happens when the stream's send final size is known, and the
    /// application has already written data up to that point.
    pub fn is_fin(&self) -> bool {
        if self.fin_off == Some(self.off) {
            return true;
        }

        false
    }

    /// Returns true if the send-side of the stream is complete.
    ///
    /// This happens when the stream's send final size is known, the peer has
    /// acked all stream data up to that point, and the STREAM frame carrying
    /// FIN has also been acknowledged. A reset stream instead completes when
    /// its current reset frame and every byte through Reliable Size are
    /// acknowledged.
    pub fn is_complete(&self) -> bool {
        if let Some(reset) = self.reset {
            return reset.acked && self.ack_off() >= reset.reliable_size();
        }

        if let Some(fin_off) = self.fin_off {
            if self.fin_acked && self.acked == (0..fin_off) {
                return true;
            }
        }

        false
    }

    /// Returns true if the stream was stopped before completion.
    pub fn is_stopped(&self) -> bool {
        self.error.is_some()
    }

    /// Returns true if the stream was shut down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Returns true if there is no data.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the highest contiguously acked offset.
    pub fn ack_off(&self) -> u64 {
        match self.acked.iter().next() {
            // Only consider the initial range if it contiguously covers the
            // start of the stream (i.e. from offset 0).
            Some(std::ops::Range { start: 0, end }) => end,

            Some(_) | None => 0,
        }
    }

    /// Returns the outgoing flow control capacity.
    pub fn cap(&self) -> Result<usize> {
        // The stream was stopped, so return the error code instead.
        if let Some(e) = self.error {
            return Err(Error::StreamStopped(e));
        }

        Ok((self.max_data - self.off) as usize)
    }

    /// Returns the number of separate buffers stored.
    #[allow(dead_code)]
    pub fn bufs_count(&self) -> usize {
        self.data.len()
    }

    /// Returns the number of bytes ready to be emitted to the peer.
    ///
    /// This includes fresh data that has not yet been sent, as well as data
    /// marked for retransmission. It excludes data that has been emitted but
    /// not yet acknowledged (in-flight data).
    pub fn buffered_bytes(&self) -> u64 {
        self.buffered_bytes
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct CountingBufFactory;

    thread_local! {
        static COPIED_ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    }

    impl BufFactory for CountingBufFactory {
        type Buf = Arc<[u8]>;
        type DgramBuf = Vec<u8>;

        fn buf_from_slice(buf: &[u8]) -> Self::Buf {
            COPIED_ALLOCATIONS.set(COPIED_ALLOCATIONS.get() + 1);
            Arc::from(buf)
        }

        fn buf_from_slice_capacity(len: usize) -> Option<usize> {
            Some(len)
        }

        fn dgram_buf_from_slice(buf: &[u8]) -> Self::DgramBuf {
            buf.to_vec()
        }

        fn dgram_buf_from_slice_capacity(len: usize) -> Option<usize> {
            Some(len)
        }

        fn dgram_buf_capacity(buf: &Self::DgramBuf) -> Option<usize> {
            Some(buf.capacity())
        }
    }

    #[test]
    fn empty_write() {
        let mut buf = [0; 5];

        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);

        let (written, fin) = send.emit(&mut buf).unwrap();
        assert_eq!(written, 0);
        assert!(!fin);
    }

    #[test]
    fn multi_write() {
        let mut buf = [0; 128];

        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.buffered_bytes, 9);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.buffered_bytes, 19);

        let (written, fin) = send.emit(&mut buf[..128]).unwrap();
        assert_eq!(written, 19);
        assert!(fin);
        assert_eq!(&buf[..written], b"somethinghelloworld");
        assert_eq!(send.buffered_bytes, 0);
    }

    #[test]
    fn split_write() {
        let mut buf = [0; 10];

        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.buffered_bytes, 9);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.buffered_bytes, 19);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 10);
        assert!(!fin);
        assert_eq!(&buf[..written], b"somethingh");
        assert_eq!(send.buffered_bytes, 9);

        assert_eq!(send.off_front(), 10);

        let (written, fin) = send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"ellow");
        assert_eq!(send.buffered_bytes, 4);

        assert_eq!(send.off_front(), 15);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 4);
        assert!(fin);
        assert_eq!(&buf[..written], b"orld");
        assert_eq!(send.buffered_bytes, 0);

        assert_eq!(send.off_front(), 19);
    }

    #[test]
    fn resend() {
        let mut buf = [0; 15];

        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);
        assert_eq!(send.off_front(), 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.off_front(), 0);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.off_front(), 0);

        assert_eq!(send.buffered_bytes, 19);

        let (written, fin) = send.emit(&mut buf[..4]).unwrap();
        assert_eq!(written, 4);
        assert!(!fin);
        assert_eq!(&buf[..written], b"some");
        assert_eq!(send.buffered_bytes, 15);
        assert_eq!(send.off_front(), 4);

        let (written, fin) = send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"thing");
        assert_eq!(send.buffered_bytes, 10);
        assert_eq!(send.off_front(), 9);

        let (written, fin) = send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"hello");
        assert_eq!(send.buffered_bytes, 5);
        assert_eq!(send.off_front(), 14);

        send.retransmit(4, 5);
        assert_eq!(send.buffered_bytes, 10);
        assert_eq!(send.off_front(), 4);

        send.retransmit(0, 4);
        assert_eq!(send.buffered_bytes, 14);
        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..11]).unwrap();
        assert_eq!(written, 9);
        assert!(!fin);
        assert_eq!(&buf[..written], b"something");
        assert_eq!(send.buffered_bytes, 5);
        assert_eq!(send.off_front(), 14);

        let (written, fin) = send.emit(&mut buf[..11]).unwrap();
        assert_eq!(written, 5);
        assert!(fin);
        assert_eq!(&buf[..written], b"world");
        assert_eq!(send.buffered_bytes, 0);
        assert_eq!(send.off_front(), 19);
    }

    #[test]
    fn write_blocked_by_off() {
        let mut buf = [0; 10];

        let mut send = <SendBuf>::default();
        assert_eq!(send.buffered_bytes, 0);

        let first = b"something";
        let second = b"helloworld";

        assert_eq!(send.write(first, false), Ok(0));
        assert_eq!(send.buffered_bytes, 0);

        assert_eq!(send.write(second, true), Ok(0));
        assert_eq!(send.buffered_bytes, 0);

        send.update_max_data(5);

        assert_eq!(send.write(first, false), Ok(5));
        assert_eq!(send.buffered_bytes, 5);

        assert_eq!(send.write(second, true), Ok(0));
        assert_eq!(send.buffered_bytes, 5);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"somet");
        assert_eq!(send.buffered_bytes, 0);

        assert_eq!(send.off_front(), 5);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 0);
        assert!(!fin);
        assert_eq!(&buf[..written], b"");
        assert_eq!(send.buffered_bytes, 0);

        send.update_max_data(15);

        assert_eq!(send.write(&first[5..], false), Ok(4));
        assert_eq!(send.buffered_bytes, 4);

        assert_eq!(send.write(second, true), Ok(6));
        assert_eq!(send.buffered_bytes, 10);

        assert_eq!(send.off_front(), 5);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 10);
        assert!(!fin);
        assert_eq!(&buf[..10], b"hinghellow");
        assert_eq!(send.buffered_bytes, 0);

        send.update_max_data(25);

        assert_eq!(send.write(&second[6..], true), Ok(4));
        assert_eq!(send.buffered_bytes, 4);

        assert_eq!(send.off_front(), 15);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 4);
        assert!(fin);
        assert_eq!(&buf[..written], b"orld");
        assert_eq!(send.buffered_bytes, 0);
    }

    #[test]
    fn zero_len_write() {
        let mut buf = [0; 10];

        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);

        let first = b"something";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.buffered_bytes, 9);

        assert!(send.write(&[], true).is_ok());
        assert_eq!(send.buffered_bytes, 9);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 9);
        assert!(fin);
        assert_eq!(&buf[..written], b"something");
        assert_eq!(send.buffered_bytes, 0);
    }

    /// Check SendBuf::len calculation on a retransmit case
    #[test]
    fn send_buf_len_on_retransmit() {
        let mut buf = [0; 15];

        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);
        assert_eq!(send.off_front(), 0);

        let first = b"something";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.off_front(), 0);

        assert_eq!(send.buffered_bytes, 9);

        let (written, fin) = send.emit(&mut buf[..4]).unwrap();
        assert_eq!(written, 4);
        assert!(!fin);
        assert_eq!(&buf[..written], b"some");
        assert_eq!(send.buffered_bytes, 5);
        assert_eq!(send.off_front(), 4);

        send.retransmit(3, 5);
        assert_eq!(send.buffered_bytes, 6);
        assert_eq!(send.off_front(), 3);
    }

    #[test]
    fn send_buf_final_size_retransmit() {
        let mut buf = [0; 50];
        let mut send = <SendBuf>::new(u64::MAX);

        send.write(&buf, false).unwrap();
        assert_eq!(send.off_front(), 0);

        // Emit the whole buffer
        let (written, _fin) = send.emit(&mut buf).unwrap();
        assert_eq!(written, buf.len());
        assert_eq!(send.off_front(), buf.len() as u64);

        // Server decides to retransmit the last 10 bytes. It's possible
        // it's not actually lost and that the client did receive it.
        send.retransmit(40, 10);

        // Server receives STOP_SENDING from client. The final_size we
        // send in the RESET_STREAM should be 50. If we send anything less,
        // it's a FINAL_SIZE_ERROR.
        let outcome = send.stop(0, 50, None).unwrap();
        assert_eq!(outcome.final_size, 50);
        assert_eq!(outcome.dropped_tx_data, 0);
    }

    #[test]
    fn reset_stream_at_retains_only_required_prefix() {
        let mut send = <SendBuf>::new(u64::MAX);
        send.write(b"abcdefghij", false).unwrap();

        let mut emitted = [0; 4];
        assert_eq!(send.emit(&mut emitted), Ok((4, false)));
        assert_eq!(&emitted, b"abcd");

        let outcome = send.shutdown_at(42, 10, 6).unwrap();
        assert_eq!(outcome, SendResetOutcome {
            final_size: 10,
            dropped_tx_data: 0,
            dropped_buffered: 4,
            changed: true,
        });
        assert_eq!(send.buffered_bytes(), 2);
        assert_eq!(send.off_back(), 10);
        assert_eq!(
            send.pending_reset(),
            Some(StreamReset::ResetAt {
                error_code: 42,
                final_size: 10,
                reliable_size: 6,
            })
        );
        assert_eq!(send.write(b"x", false), Err(Error::FinalSize));
        assert_eq!(send.write(b"", true), Err(Error::FinalSize));

        assert_eq!(send.retransmit(0, 4), 4);
        let mut prefix = [0; 6];
        assert_eq!(send.emit(&mut prefix), Ok((6, false)));
        assert_eq!(&prefix, b"abcdef");

        send.ack_and_drop(0, 3);
        assert!(send.can_send_buffered());
        assert!(!send.is_complete());
        send.ack_and_drop(3, 3);
        assert!(!send.can_send_buffered());
        assert!(!send.is_complete());

        assert!(send.ack_reset(StreamReset::ResetAt {
            error_code: 42,
            final_size: 10,
            reliable_size: 6,
        }));
        assert!(send.is_complete());
        assert_eq!(send.buffered_bytes(), 0);
        assert_eq!(send.bufs_count(), 0);
    }

    #[test]
    fn reset_stream_at_reduction_is_monotonic_and_exactly_acked() {
        let mut send = <SendBuf>::new(u64::MAX);
        send.write(b"abcdefghij", false).unwrap();

        assert!(send.shutdown_at(7, 10, 8).unwrap().changed);
        assert!(
            !send
                .shutdown_at(7, 10, 8)
                .expect("exact duplicate is idempotent")
                .changed
        );
        assert!(send.shutdown_at(7, 10, 5).unwrap().changed);

        let current = StreamReset::ResetAt {
            error_code: 7,
            final_size: 10,
            reliable_size: 5,
        };
        assert_eq!(send.pending_reset(), Some(current));
        assert!(!send.ack_reset(StreamReset::ResetAt {
            error_code: 7,
            final_size: 10,
            reliable_size: 8,
        }));
        assert_eq!(send.pending_reset(), Some(current));

        let buffered = send.buffered_bytes();
        assert_eq!(send.shutdown_at(7, 10, 6), Err(Error::InvalidState));
        assert_eq!(send.shutdown_at(8, 10, 4), Err(Error::InvalidState));
        assert_eq!(send.shutdown_at(7, 9, 4), Err(Error::InvalidState));
        assert_eq!(send.buffered_bytes(), buffered);
        assert_eq!(send.pending_reset(), Some(current));

        // STOP_SENDING makes application writes fail, but it cannot prevent a
        // valid reduction of an already established reliable reset.
        assert!(!send.stop(99, 10, None).unwrap().changed);
        assert!(send.shutdown_at(7, 10, 4).unwrap().changed);

        assert!(send.shutdown(7, 10).unwrap().changed);
        assert_eq!(
            send.pending_reset(),
            Some(StreamReset::Reset {
                error_code: 7,
                final_size: 10,
            })
        );
    }

    #[test]
    fn reset_stream_at_rejects_missing_prefix_transactionally() {
        let mut send = <SendBuf>::new(u64::MAX);
        send.write(b"abcdefghij", false).unwrap();
        let mut out = [0; 10];
        assert_eq!(send.emit(&mut out), Ok((10, false)));

        // Simulate a violated external-retention contract: these bytes are
        // neither acknowledged nor available for retransmission.
        send.data.clear();
        let before = (
            send.off,
            send.emit_off,
            send.fin_off,
            send.shutdown,
            send.reset,
            send.buffered_bytes,
        );

        assert_eq!(send.shutdown_at(42, 10, 5), Err(Error::InvalidState));
        assert_eq!(
            (
                send.off,
                send.emit_off,
                send.fin_off,
                send.shutdown,
                send.reset,
                send.buffered_bytes,
            ),
            before
        );
    }

    #[test]
    fn reset_stream_at_after_fin_waits_for_frame_and_prefix_ack() {
        let mut send = <SendBuf>::new(u64::MAX);
        send.write(b"hello", true).unwrap();
        let mut out = [0; 5];
        assert_eq!(send.emit(&mut out), Ok((5, true)));

        send.shutdown_at(9, 5, 5).unwrap();
        send.ack_fin(5);
        send.ack_and_drop(0, 5);
        assert!(!send.is_complete());

        assert!(send.ack_reset(StreamReset::ResetAt {
            error_code: 9,
            final_size: 5,
            reliable_size: 5,
        }));
        assert!(send.is_complete());
        assert_eq!(send.shutdown_at(9, 5, 4), Err(Error::Done));
        assert_eq!(send.shutdown(9, 5), Err(Error::Done));
    }

    #[test]
    fn retention_cap_rejects_before_copy_and_releases_on_ack() {
        COPIED_ALLOCATIONS.set(0);
        let retention = StreamSendRetention::new(StreamSendRetentionLimits {
            max_bytes: 5,
            max_chunks: 1,
        });
        let mut send = SendBuf::<CountingBufFactory>::new_with_retention(
            u64::MAX,
            Arc::clone(&retention),
        );

        assert_eq!(send.write(b"123456", false), Err(Error::Done));
        assert_eq!(COPIED_ALLOCATIONS.get(), 0);
        assert_eq!(retention.stats(), StreamSendRetentionStats::default());

        assert_eq!(send.write(b"12345", false), Ok(5));
        assert_eq!(COPIED_ALLOCATIONS.get(), 1);
        assert_eq!(retention.stats().retained_bytes, 5);
        assert_eq!(retention.stats().retained_chunks, 1);

        let mut out = [0; 5];
        assert_eq!(send.emit(&mut out), Ok((5, false)));
        assert_eq!(send.retransmit(0, 5), 5);
        assert_eq!(retention.stats().retained_bytes, 5);
        assert_eq!(retention.stats().retained_chunks, 1);
        assert_eq!(send.ack_and_drop(0, 5), 5);
        assert_eq!(retention.stats().retained_bytes, 0);
        assert_eq!(retention.stats().retained_chunks, 0);
    }

    #[test]
    fn retention_cap_releases_on_stop_and_accepts_followup_stream() {
        let retention = StreamSendRetention::new(StreamSendRetentionLimits {
            max_bytes: 5,
            max_chunks: 1,
        });
        let mut stopped = SendBuf::<CountingBufFactory>::new_with_retention(
            u64::MAX,
            Arc::clone(&retention),
        );
        assert_eq!(stopped.write(b"12345", false), Ok(5));
        stopped.stop(42, 5, None).unwrap();
        assert_eq!(retention.stats().retained_bytes, 0);
        assert_eq!(retention.stats().retained_chunks, 0);

        let mut followup = SendBuf::<CountingBufFactory>::new_with_retention(
            u64::MAX,
            Arc::clone(&retention),
        );
        assert_eq!(followup.write(b"abcde", true), Ok(5));
        assert_eq!(retention.stats().retained_bytes, 5);
        drop(followup);
        assert_eq!(retention.stats().retained_bytes, 0);
        assert_eq!(retention.stats().retained_chunks, 0);
    }
}
