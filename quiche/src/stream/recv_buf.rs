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

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::mem::size_of;

use std::time::Duration;
use std::time::Instant;

use crate::stream::RecvAction;
use crate::stream::RecvBufResetReturn;
use crate::Error;
use crate::Result;

use crate::flowcontrol;

use crate::range_buf::RangeBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecvResetState {
    error_code: u64,
    final_size: u64,
    reliable_size: u64,
    reliable_semantics: bool,
    delivered: bool,
}

/// Receive-side stream buffer.
///
/// Stream data received by the peer is buffered in a list of data chunks
/// ordered by offset in ascending order. Contiguous data can then be read
/// into a slice.
#[derive(Debug, Default)]
pub struct RecvBuf {
    /// Chunks of data received from the peer that have not yet been read by
    /// the application, ordered by offset.
    data: BTreeMap<u64, RangeBuf>,

    /// The lowest data offset that has yet to be read by the application.
    off: u64,

    /// The total length of data received on this stream.
    len: u64,

    /// Receiver flow controller.
    flow_control: flowcontrol::FlowControl,

    /// The final stream offset received from the peer, if any.
    fin_off: Option<u64>,

    /// Reliable-prefix reset state established by RESET_STREAM[_AT].
    reset: Option<RecvResetState>,

    /// Whether incoming data is validated but not buffered.
    drain: bool,
}

impl RecvBuf {
    /// Creates a new receive buffer.
    pub fn new(max_data: u64, initial_window: u64, max_window: u64) -> RecvBuf {
        RecvBuf {
            flow_control: flowcontrol::FlowControl::new(
                max_data,
                initial_window,
                max_window,
            ),
            ..RecvBuf::default()
        }
    }

    /// Inserts the given chunk of data in the buffer.
    ///
    /// This also takes care of enforcing stream flow control limits, as well
    /// as handling incoming data that overlaps data that is already in the
    /// buffer.
    pub fn write(&mut self, mut buf: RangeBuf) -> Result<()> {
        if buf.max_off() > self.max_data() {
            return Err(Error::FlowControl);
        }

        if let Some(fin_off) = self.fin_off {
            // Stream's size is known, forbid data beyond that point.
            if buf.max_off() > fin_off {
                return Err(Error::FinalSize);
            }

            // Stream's size is already known, forbid changing it.
            if buf.fin() && fin_off != buf.max_off() {
                return Err(Error::FinalSize);
            }
        }

        // Stream's known size is lower than data already received.
        if buf.fin() && buf.max_off() < self.len {
            return Err(Error::FinalSize);
        }

        // We already saved the final offset, so there's nothing else we
        // need to keep from the RangeBuf if it's empty.
        if self.fin_off.is_some() && buf.is_empty() {
            return Ok(());
        }

        if buf.fin() {
            self.fin_off = Some(buf.max_off());
        }

        if let Some(reset) = self.reset {
            if reset.delivered || self.drain || buf.off() >= reset.reliable_size {
                return Ok(());
            }

            if buf.max_off() > reset.reliable_size {
                let keep = usize::try_from(reset.reliable_size - buf.off())
                    .expect("the incoming range length is represented as usize");
                buf.truncate_unread(keep);
            }
        }

        // No need to store empty buffer that doesn't carry the fin flag.
        if !buf.fin() && buf.is_empty() {
            return Ok(());
        }

        // Check if data is fully duplicate, that is the buffer's max offset is
        // lower or equal to the offset already stored in the recv buffer.
        if self.off >= buf.max_off() {
            // An exception is applied to empty range buffers, because an empty
            // buffer's max offset matches the max offset of the recv buffer.
            //
            // By this point all spurious empty buffers should have already been
            // discarded, so allowing empty buffers here should be safe.
            if !buf.is_empty() {
                return Ok(());
            }
        }

        let mut tmp_bufs = VecDeque::with_capacity(2);
        tmp_bufs.push_back(buf);

        'tmp: while let Some(mut buf) = tmp_bufs.pop_front() {
            // Discard incoming data below current stream offset. Bytes up to
            // `self.off` have already been received so we should not buffer
            // them again. This is also important to make sure `ready()` doesn't
            // get stuck when a buffer with lower offset than the stream's is
            // buffered.
            if self.off_front() > buf.off() {
                buf = buf.split_off((self.off_front() - buf.off()) as usize);
            }

            // Handle overlapping data. If the incoming data's starting offset
            // is above the previous maximum received offset, there is clearly
            // no overlap so this logic can be skipped. However do still try to
            // merge an empty final buffer (i.e. an empty buffer with the fin
            // flag set, which is the only kind of empty buffer that should
            // reach this point).
            if buf.off() < self.max_off() || buf.is_empty() {
                for (_, b) in self.data.range(buf.off()..) {
                    let off = buf.off();

                    // We are past the current buffer.
                    if b.off() > buf.max_off() {
                        break;
                    }

                    // New buffer is fully contained in existing buffer.
                    if off >= b.off() && buf.max_off() <= b.max_off() {
                        continue 'tmp;
                    }

                    // New buffer's start overlaps existing buffer.
                    if off >= b.off() && off < b.max_off() {
                        buf = buf.split_off((b.max_off() - off) as usize);
                    }

                    // New buffer's end overlaps existing buffer.
                    if off < b.off() && buf.max_off() > b.off() {
                        tmp_bufs
                            .push_back(buf.split_off((b.off() - off) as usize));
                    }
                }
            }

            self.len = cmp::max(self.len, buf.max_off());

            if !self.drain {
                self.data.insert(buf.max_off(), buf);
            } else {
                // we are not storing any data, off == len
                self.off = self.len;
            }
        }

        Ok(())
    }

    /// Reads contiguous data from the receive buffer.
    ///
    /// Data is written into the given `out` buffer, up to the length of `out`.
    ///
    /// Only contiguous data is removed, starting from offset 0. The offset is
    /// incremented as data is taken out of the receive buffer. If there is no
    /// data at the expected read offset, the `Done` error is returned.
    ///
    /// On success the amount of data read and a flag indicating
    /// if there is no more data in the buffer, are returned as a tuple.
    #[inline]
    pub fn emit(&mut self, mut out: &mut [u8]) -> Result<(usize, bool)> {
        self.emit_or_discard(RecvAction::Emit { out: &mut out })
    }

    /// Reads or discards contiguous data from the receive buffer.
    ///
    /// Passing an `action` of `StreamRecvAction::Emit` results in data being
    /// written into the provided buffer, up to its length.
    ///
    /// Passing an `action` of `StreamRecvAction::Discard` results in up to
    /// the indicated number of bytes being discarded without copying.
    ///
    /// Only contiguous data is removed, starting from offset 0. The offset is
    /// incremented as data is taken out of the receive buffer. If there is no
    /// data at the expected read offset, the `Done` error is returned.
    ///
    /// On success the amount of data read or discarded, and a flag indicating
    /// if there is no more data in the buffer, are returned as a tuple.
    pub fn emit_or_discard<B: bytes::BufMut>(
        &mut self, mut action: RecvAction<B>,
    ) -> Result<(usize, bool)> {
        let mut len = 0;
        let mut cap = match &action {
            RecvAction::Emit { out } => out.remaining_mut(),
            RecvAction::Discard { len } => *len,
        };

        if !self.ready() {
            return Err(Error::Done);
        }

        if self.reset_is_ready() {
            return Err(Error::StreamReset(self.deliver_reset()));
        }

        while cap > 0 && self.data_is_ready() {
            let mut entry = match self.data.first_entry() {
                Some(entry) => entry,
                None => break,
            };

            let buf = entry.get_mut();

            let buf_len = cmp::min(buf.len(), cap);

            // Only copy data if we're emitting, not discarding.
            if let RecvAction::Emit { ref mut out } = action {
                // Note: `BufMut::remaining_mut()` cannot "shrink", but BufMut
                // impls are allowed to grow the buffer, so we
                // check here that we still have at least
                // `cap` bytes, but we can't require equality
                debug_assert!(
                    cap <= out.remaining_mut(),
                    "We updated `cap` incorrectly"
                );
                out.put_slice(&buf[..buf_len])
            }

            self.off += buf_len as u64;

            len += buf_len;
            cap -= buf_len;

            if buf_len < buf.len() {
                buf.consume(buf_len);

                // We reached the maximum capacity, so end here.
                break;
            }

            entry.remove();
        }

        // Update consumed bytes for flow control.
        self.flow_control.add_consumed(len as u64);

        Ok((len, self.is_fin()))
    }

    /// Resets the stream without retaining a reliably delivered prefix.
    pub fn reset(
        &mut self, error_code: u64, final_size: u64,
    ) -> Result<RecvBufResetReturn> {
        self.reset_inner(error_code, final_size, 0, false)
    }

    /// Resets the stream while retaining data through `reliable_size`.
    pub fn reset_at(
        &mut self, error_code: u64, final_size: u64, reliable_size: u64,
    ) -> Result<RecvBufResetReturn> {
        self.reset_inner(error_code, final_size, reliable_size, true)
    }

    fn reset_inner(
        &mut self, error_code: u64, final_size: u64, reliable_size: u64,
        reliable_semantics: bool,
    ) -> Result<RecvBufResetReturn> {
        if reliable_size > final_size {
            return Err(Error::InvalidFrame);
        }

        if final_size > self.max_data() {
            return Err(Error::FlowControl);
        }

        // A FIN or earlier reset fixes Final Size. draft-09 uses
        // FINAL_SIZE_ERROR when a later termination signal changes it.
        if let Some(fin_off) = self.fin_off {
            if fin_off != final_size {
                return Err(Error::FinalSize);
            }
        }

        // Stream's known size is lower than data already received.
        if final_size < self.len {
            return Err(Error::FinalSize);
        }

        if let Some(current) = self.reset {
            let enforce_tuple = reliable_semantics || current.reliable_semantics;
            if enforce_tuple && current.error_code != error_code {
                return Err(Error::InvalidState);
            }
            if enforce_tuple && current.final_size != final_size {
                return Err(Error::FinalSize);
            }

            if !enforce_tuple {
                return Ok(RecvBufResetReturn::zero());
            }

            // A reordered larger Reliable Size cannot restore an obligation
            // that a smaller reset already removed.
            if reliable_size >= current.reliable_size {
                if reliable_semantics && !current.reliable_semantics {
                    self.reset = Some(RecvResetState {
                        reliable_semantics: true,
                        ..current
                    });
                }
                return Ok(RecvBufResetReturn::zero());
            }

            let consumed_flowcontrol = if self.drain || current.delivered {
                0
            } else {
                current
                    .reliable_size
                    .max(self.off)
                    .saturating_sub(reliable_size.max(self.off))
            };

            self.reset = Some(RecvResetState {
                reliable_size,
                reliable_semantics: enforce_tuple,
                ..current
            });
            self.discard_after(reliable_size);

            return Ok(RecvBufResetReturn {
                max_data_delta: 0,
                consumed_flowcontrol,
            });
        }

        let previous_len = self.len;
        let consumed_flowcontrol = if self.drain {
            final_size.saturating_sub(self.off)
        } else {
            final_size.saturating_sub(reliable_size.max(self.off))
        };

        let result = RecvBufResetReturn {
            max_data_delta: final_size - previous_len,
            consumed_flowcontrol,
        };

        self.fin_off = Some(final_size);
        self.len = final_size;
        self.reset = Some(RecvResetState {
            error_code,
            final_size,
            reliable_size,
            reliable_semantics,
            delivered: self.drain,
        });
        self.discard_after(reliable_size);

        if self.drain {
            self.off = final_size;
        }

        Ok(result)
    }

    fn discard_after(&mut self, end: u64) {
        let mut retained = BTreeMap::new();

        for (_, mut buf) in std::mem::take(&mut self.data) {
            if buf.off() >= end {
                continue;
            }

            if buf.max_off() > end {
                let keep = usize::try_from(end - buf.off())
                    .expect("the buffered range length is represented as usize");
                buf.truncate_unread(keep);
            }

            retained.insert(buf.max_off(), buf);
        }

        self.data = retained;
    }

    fn reset_is_ready(&self) -> bool {
        self.reset.is_some_and(|reset| {
            !reset.delivered && self.off >= reset.reliable_size
        })
    }

    fn deliver_reset(&mut self) -> u64 {
        let reset = self
            .reset
            .as_mut()
            .expect("a ready reset is present when it is delivered");
        reset.delivered = true;
        self.off = reset.final_size;
        self.data.clear();
        reset.error_code
    }

    fn data_is_ready(&self) -> bool {
        self.data
            .first_key_value()
            .is_some_and(|(_, buf)| buf.off() == self.off)
    }

    /// Commits the new max_data limit.
    pub fn update_max_data(&mut self, now: Instant) {
        self.flow_control.update_max_data(now);
    }

    /// Return the new max_data limit.
    pub fn max_data_next(&mut self) -> u64 {
        self.flow_control.max_data_next()
    }

    /// Return the current flow control limit.
    pub fn max_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Return the current window.
    pub fn window(&self) -> u64 {
        self.flow_control.window()
    }

    /// Autotune the window size.
    pub fn autotune_window(&mut self, now: Instant, rtt: Duration) {
        self.flow_control.autotune_window(now, rtt);
    }

    /// Shuts down receiving data and returns the number of bytes
    /// that should be returned to the connection level flow
    /// control
    pub fn shutdown(&mut self) -> Result<u64> {
        if self.drain {
            return Err(Error::Done);
        }

        self.drain = true;

        self.data.clear();

        let consumed = self.reset.map_or_else(
            || self.max_off() - self.off,
            |reset| reset.reliable_size.saturating_sub(self.off),
        );
        self.off = self.max_off();
        if let Some(reset) = self.reset.as_mut() {
            reset.delivered = true;
        }

        Ok(consumed)
    }

    /// Returns the lowest offset of data buffered.
    pub fn off_front(&self) -> u64 {
        self.off
    }

    /// Returns true if we need to update the local flow control limit.
    pub fn almost_full(&self) -> bool {
        self.fin_off.is_none() && self.flow_control.should_update_max_data()
    }

    /// Returns the largest offset ever received.
    pub fn max_off(&self) -> u64 {
        self.len
    }

    /// Returns true if the receive-side of the stream is complete.
    ///
    /// This happens when the stream's receive final size is known, and the
    /// application has read all data from the stream.
    pub fn is_fin(&self) -> bool {
        if let Some(reset) = self.reset {
            // Preserve RESET_STREAM's immediate terminal indication while the
            // queued reset remains readable by the application. A non-zero
            // reliable prefix cannot become terminal until it is consumed.
            return reset.delivered || reset.reliable_size == 0;
        }

        if self.fin_off == Some(self.off) {
            return true;
        }

        false
    }

    /// Returns true if the stream is not storing incoming data.
    pub fn is_draining(&self) -> bool {
        self.drain
    }

    /// Returns true if a RESET_STREAM or RESET_STREAM_AT was received.
    pub(crate) fn is_reset(&self) -> bool {
        self.reset.is_some()
    }

    /// Returns true if the stream has data to be read.
    pub fn ready(&self) -> bool {
        self.reset_is_ready() || self.data_is_ready()
    }

    /// Returns the number of bytes that can be read contiguously from the
    /// current read offset.
    ///
    /// This is the amount of in-order data available to read right now, up to
    /// 64 KiB. Data buffered behind a gap (received out of order) is not
    /// counted, so this never reports bytes that are not yet readable. The cost
    /// is proportional to the number of contiguous buffered chunks at the front
    /// of the buffer, up to 64 KiB; no data is copied.
    pub fn readable_len(&self) -> usize {
        const MAX_READABLE_LEN: usize = 64 * 1024;

        if self.reset_is_ready() {
            return 0;
        }

        let mut contiguous = 0;
        let mut next_off = self.off;
        let reliable_size =
            self.reset.map_or(u64::MAX, |reset| reset.reliable_size);

        // `data` is ordered by offset, so walk from the front and stop at the
        // first gap (a chunk that does not start where the contiguous run so
        // far leaves off).
        for buf in self.data.values() {
            if buf.off() != next_off {
                break;
            }

            let readable = buf.max_off().min(reliable_size) - buf.off();
            contiguous = (contiguous +
                usize::try_from(readable).unwrap_or(usize::MAX))
            .min(MAX_READABLE_LEN);
            next_off = buf.max_off().min(reliable_size);

            if contiguous == MAX_READABLE_LEN || next_off == reliable_size {
                break;
            }
        }

        contiguous
    }

    #[cfg(test)]
    pub(crate) fn flow_control_for_tests(&self) -> &flowcontrol::FlowControl {
        &self.flow_control
    }
}

pub(super) const fn retained_fragment_metadata_size() -> usize {
    // One map key/value, one Arc allocation header, and a conservative ordered
    // collection node/link allowance. Allocator size-class rounding is kept in
    // the embedding profile's explicit implementation margin.
    size_of::<u64>() + size_of::<RangeBuf>() + 12 * size_of::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default size of the receiver stream flow control window.
    const DEFAULT_STREAM_WINDOW: u64 = 32 * 1024;
    use bytes::BufMut as _;
    use rstest::rstest;

    // Helper function for testing either buffer emit or discard.
    //
    // The `emit` parameter controls whether data is emitted or discarded from
    // `recv`.
    //
    // The `target_len` parameter controls the maximum amount of bytes that
    // could be read, up to the capacity of `recv`. The `result_len` is the
    // actual number of bytes that were taken out of `recv`. An assert is
    // performed on `result_len` to ensure the number of bytes read meets the
    // caller expectations.
    //
    // The `is_fin` parameter relates to the buffer's finished status. An assert
    // is performed on it to ensure the status meet the caller expectations.
    //
    // The `test_bytes` parameter carries an optional slice of bytes. Is set, an
    // assert is performed against the bytes that were read out of the buffer,
    // to ensure caller expectations are met.
    fn assert_emit_discard(
        recv: &mut RecvBuf, emit: bool, target_len: usize, result_len: usize,
        is_fin: bool, test_bytes: Option<&[u8]>,
    ) {
        let mut buf = Vec::<u8>::with_capacity(512).limit(target_len);
        let action = if emit {
            RecvAction::Emit { out: &mut buf }
        } else {
            RecvAction::Discard { len: target_len }
        };

        let (read, fin) = recv.emit_or_discard(action).unwrap();

        let buf = buf.into_inner();
        if emit {
            assert_eq!(buf.len(), read);
            if let Some(v) = test_bytes {
                assert_eq!(&buf, v);
            }
        }

        assert_eq!(read, result_len);
        assert_eq!(is_fin, fin);
    }

    // Helper function for testing buffer status for either emit or discard.
    fn assert_emit_discard_done(recv: &mut RecvBuf, emit: bool) {
        let mut buf = [0u8; 32];
        let action = if emit {
            RecvAction::Emit {
                out: &mut buf.as_mut_slice(),
            }
        } else {
            RecvAction::Discard { len: 32 }
        };
        assert_eq!(recv.emit_or_discard(action), Err(Error::Done));
    }

    #[rstest]
    fn empty_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn empty_stream_frame(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(15, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let buf = RangeBuf::from(b"hello", 0, false);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert_emit_discard(&mut recv, emit, 32, 5, false, None);

        // Don't store non-fin empty buffer.
        let buf = RangeBuf::from(b"", 10, false);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 0);

        // Check flow control for empty buffer.
        let buf = RangeBuf::from(b"", 16, false);
        assert_eq!(recv.write(buf), Err(Error::FlowControl));

        // Store fin empty buffer.
        let buf = RangeBuf::from(b"", 5, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Don't store additional fin empty buffers.
        let buf = RangeBuf::from(b"", 5, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Don't store additional fin non-empty buffers.
        let buf = RangeBuf::from(b"aa", 3, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Validate final size with fin empty buffers.
        let buf = RangeBuf::from(b"", 6, true);
        assert_eq!(recv.write(buf), Err(Error::FinalSize));
        let buf = RangeBuf::from(b"", 4, true);
        assert_eq!(recv.write(buf), Err(Error::FinalSize));

        assert_emit_discard(&mut recv, emit, 32, 0, true, None);
    }

    #[rstest]
    fn ordered_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);

        assert_emit_discard_done(&mut recv, emit);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard_done(&mut recv, emit);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard(
            &mut recv,
            emit,
            32,
            19,
            true,
            Some(b"helloworldsomething"),
        );
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[test]
    /// `readable_len` counts only contiguous in-order data, ignoring bytes
    /// buffered behind a gap.
    fn readable_len() {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);

        // Empty buffer: nothing readable.
        assert_eq!(recv.readable_len(), 0);

        // Contiguous data at the front is readable.
        assert!(recv.write(RangeBuf::from(b"hello", 0, false)).is_ok());
        assert_eq!(recv.readable_len(), 5);

        // Data buffered behind a gap ([5, 10) is missing) is NOT counted, even
        // though `max_off` has advanced to 19.
        assert!(recv.write(RangeBuf::from(b"something", 10, false)).is_ok());
        assert_eq!(recv.max_off(), 19);
        assert_eq!(recv.readable_len(), 5);

        // Filling the gap makes the whole range contiguous and readable.
        assert!(recv.write(RangeBuf::from(b"world", 5, false)).is_ok());
        assert_eq!(recv.readable_len(), 19);

        // Reading part of the data shrinks the readable count accordingly.
        let mut buf = [0; 4];
        assert_eq!(recv.emit(&mut buf), Ok((4, false)));
        assert_eq!(recv.readable_len(), 15);

        // Traversal stops at the maximum body receive buffer size.
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert!(recv
            .write(RangeBuf::from(&[0; 64 * 1024], 0, false))
            .is_ok());
        assert!(recv.write(RangeBuf::from(&[0], 64 * 1024, false)).is_ok());
        assert_eq!(recv.readable_len(), 64 * 1024);
    }

    #[test]
    fn reset_stream_at_waits_for_gap_and_delivers_prefix() {
        let mut recv =
            RecvBuf::new(20, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        recv.write(RangeBuf::from(b"cde", 2, false)).unwrap();

        assert_eq!(
            recv.reset_at(42, 8, 5),
            Ok(RecvBufResetReturn {
                max_data_delta: 3,
                consumed_flowcontrol: 3,
            })
        );
        assert!(!recv.ready());

        recv.write(RangeBuf::from(b"ab", 0, false)).unwrap();
        assert!(recv.ready());

        let mut first = [0; 2];
        assert_eq!(recv.emit(&mut first), Ok((2, false)));
        assert_eq!(&first, b"ab");

        let mut second = [0; 8];
        assert_eq!(recv.emit(&mut second), Ok((3, false)));
        assert_eq!(&second[..3], b"cde");
        assert!(recv.ready());
        assert_eq!(recv.readable_len(), 0);
        assert_eq!(recv.emit(&mut second), Err(Error::StreamReset(42)));
        assert!(recv.is_fin());
        assert_eq!(recv.off_front(), 8);
        assert!(recv.data.is_empty());
    }

    #[test]
    fn reset_stream_at_after_consumed_prefix_is_immediately_observable() {
        let mut recv =
            RecvBuf::new(20, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        recv.write(RangeBuf::from(b"hello", 0, false)).unwrap();

        let mut out = [0; 5];
        assert_eq!(recv.emit(&mut out), Ok((5, false)));
        assert_eq!(
            recv.reset_at(7, 8, 5),
            Ok(RecvBufResetReturn {
                max_data_delta: 3,
                consumed_flowcontrol: 3,
            })
        );
        assert!(recv.ready());
        assert_eq!(recv.emit(&mut out), Err(Error::StreamReset(7)));
    }

    #[test]
    fn reset_stream_at_decreases_without_double_credit() {
        let mut recv =
            RecvBuf::new(20, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        recv.write(RangeBuf::from(b"abcdefghij", 0, false)).unwrap();

        assert_eq!(
            recv.reset_at(3, 10, 8),
            Ok(RecvBufResetReturn {
                max_data_delta: 0,
                consumed_flowcontrol: 2,
            })
        );
        assert_eq!(recv.reset_at(3, 10, 8), Ok(RecvBufResetReturn::zero()));
        assert_eq!(
            recv.reset_at(3, 10, 5),
            Ok(RecvBufResetReturn {
                max_data_delta: 0,
                consumed_flowcontrol: 3,
            })
        );
        assert_eq!(recv.readable_len(), 5);

        // A reordered larger commitment is ignored and cannot restore data.
        assert_eq!(recv.reset_at(3, 10, 7), Ok(RecvBufResetReturn::zero()));
        assert_eq!(recv.readable_len(), 5);
        assert_eq!(recv.reset_at(4, 10, 4), Err(Error::InvalidState));

        assert_eq!(
            recv.reset(3, 10),
            Ok(RecvBufResetReturn {
                max_data_delta: 0,
                consumed_flowcontrol: 5,
            })
        );
        assert_eq!(recv.emit(&mut [0; 1]), Err(Error::StreamReset(3)));
    }

    #[test]
    fn reset_stream_at_conflicting_termination_signals_fail() {
        let mut recv =
            RecvBuf::new(20, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        recv.write(RangeBuf::from(b"hello", 0, true)).unwrap();
        assert_eq!(recv.reset_at(1, 6, 5), Err(Error::FinalSize));

        let mut recv =
            RecvBuf::new(20, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        recv.reset_at(1, 5, 3).unwrap();
        assert_eq!(
            recv.write(RangeBuf::from(b"x", 3, true)),
            Err(Error::FinalSize)
        );
        assert_eq!(
            recv.write(RangeBuf::from(b"xxxx", 3, true)),
            Err(Error::FinalSize)
        );
        assert_eq!(recv.reset_at(2, 5, 2), Err(Error::InvalidState));
        assert_eq!(recv.reset_at(1, 4, 2), Err(Error::FinalSize));

        let mut recv =
            RecvBuf::new(20, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        recv.write(RangeBuf::from(b"abcdef", 0, false)).unwrap();
        assert_eq!(recv.reset_at(1, 5, 5), Err(Error::FinalSize));
    }

    #[test]
    fn reset_stream_at_accepts_reordered_matching_fin() {
        let mut recv =
            RecvBuf::new(20, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(
            recv.reset_at(6, 5, 3),
            Ok(RecvBufResetReturn {
                max_data_delta: 5,
                consumed_flowcontrol: 2,
            })
        );

        // The matching FIN can arrive after RESET_STREAM_AT. Its suffix is
        // validated against Final Size but is not retained beyond the prefix.
        assert_eq!(recv.write(RangeBuf::from(b"de", 3, true)), Ok(()));
        assert!(!recv.ready());
        assert_eq!(recv.write(RangeBuf::from(b"abc", 0, false)), Ok(()));

        let mut out = [0; 8];
        assert_eq!(recv.emit(&mut out), Ok((3, false)));
        assert_eq!(&out[..3], b"abc");
        assert_eq!(recv.emit(&mut out), Err(Error::StreamReset(6)));
    }

    #[test]
    fn reset_stream_at_shutdown_credits_only_remaining_prefix() {
        let mut recv =
            RecvBuf::new(20, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        recv.write(RangeBuf::from(b"abcdefgh", 0, false)).unwrap();
        assert_eq!(
            recv.reset_at(1, 10, 8),
            Ok(RecvBufResetReturn {
                max_data_delta: 2,
                consumed_flowcontrol: 2,
            })
        );

        let mut out = [0; 3];
        assert_eq!(recv.emit(&mut out), Ok((3, false)));
        assert_eq!(recv.shutdown(), Ok(5));
        assert!(recv.is_fin());
        assert!(!recv.ready());
    }

    /// Test shutdown behavior
    #[rstest]
    fn shutdown(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);

        assert_emit_discard_done(&mut recv, emit);

        // shutdown the buffer. Buffer is dropped.
        assert_eq!(recv.shutdown(), Ok(10));
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 10);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);

        // subsequent writes are validated but not added to the buffer
        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 10);
        assert_eq!(recv.data.len(), 0);

        // the max offset of received data can increase and
        // the recv.off must increase with it
        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
        assert_eq!(recv.data.len(), 0);

        // Send a reset
        assert_emit_discard_done(&mut recv, emit);
        assert_eq!(
            recv.reset(42, 123),
            Ok(RecvBufResetReturn {
                max_data_delta: 104,
                consumed_flowcontrol: 104,
            })
        );
        assert_eq!(recv.len, 123);
        assert_eq!(recv.off, 123);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn split_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard(&mut recv, emit, 10, 10, false, Some(b"somethingh"));
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 10);

        assert_emit_discard(&mut recv, emit, 5, 5, false, Some(b"ellow"));
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 15);

        assert_emit_discard(&mut recv, emit, 5, 4, true, Some(b"orld"));
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[test]
    fn split_read_incremental_buf() {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let mut buf = Vec::new().limit(10);
        assert_eq!(
            recv.emit_or_discard(RecvAction::Emit { out: &mut buf }),
            Ok((10, false))
        );
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 10);
        assert_eq!(buf.get_ref().len(), 10);
        assert_eq!(buf.get_ref().as_slice(), b"somethingh");

        buf.set_limit(5);
        assert_eq!(
            recv.emit_or_discard(RecvAction::Emit { out: &mut buf }),
            Ok((5, false))
        );
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 15);
        assert_eq!(buf.get_ref().len(), 15);
        assert_eq!(buf.get_ref().as_slice(), b"somethinghellow");

        buf.set_limit(42);
        assert_eq!(
            recv.emit_or_discard(RecvAction::Emit { out: &mut buf }),
            Ok((4, true))
        );
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
        assert_eq!(buf.get_ref().len(), 19);
        assert_eq!(buf.get_ref().as_slice(), b"somethinghelloworld");
    }

    #[rstest]
    fn incomplete_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0u8; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let action = if emit {
            RecvAction::Emit {
                out: &mut buf.as_mut_slice(),
            }
        } else {
            RecvAction::Discard { len: 32 }
        };
        assert_eq!(recv.emit_or_discard(action), Err(Error::Done));

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard(
            &mut recv,
            emit,
            32,
            19,
            true,
            Some(b"somethinghelloworld"),
        );
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[rstest]
    fn zero_len_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"", 9, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert_emit_discard(&mut recv, emit, 32, 9, true, Some(b"something"));
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
    }

    #[rstest]
    fn past_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let third = RangeBuf::from(b"ello", 4, true);
        let fourth = RangeBuf::from(b"ello", 5, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert_emit_discard(&mut recv, emit, 32, 9, false, Some(b"something"));
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.write(third), Err(Error::FinalSize));

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn fully_overlapping_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 4, false);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert_emit_discard(&mut recv, emit, 32, 9, false, Some(b"something"));
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn fully_overlapping_read2(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 4, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert_emit_discard(&mut recv, emit, 32, 9, false, Some(b"somehello"));
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn fully_overlapping_read3(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert_emit_discard(&mut recv, emit, 32, 9, false, Some(b"somhellog"));
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn fully_overlapping_read_multi(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"somethingsomething", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let third = RangeBuf::from(b"hello", 12, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 17);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 18);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        assert_emit_discard(
            &mut recv,
            emit,
            32,
            18,
            false,
            Some(b"somhellogsomhellog"),
        );
        assert_eq!(recv.len, 18);
        assert_eq!(recv.off, 18);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn overlapping_start_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 8, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert_emit_discard(
            &mut recv,
            emit,
            32,
            13,
            true,
            Some(b"somethingello"),
        );

        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 13);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn overlapping_end_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"something", 3, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert_emit_discard(&mut recv, emit, 32, 12, true, Some(b"helsomething"));
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 12);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn overlapping_end_twice_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"he", 0, false);
        let second = RangeBuf::from(b"ow", 4, false);
        let third = RangeBuf::from(b"rl", 7, false);
        let fourth = RangeBuf::from(b"helloworld", 0, true);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 6);

        assert_emit_discard(&mut recv, emit, 32, 10, true, Some(b"helloworld"));
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 10);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn overlapping_end_twice_and_contained_read(
        #[values(true, false)] emit: bool,
    ) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"hellow", 0, false);
        let second = RangeBuf::from(b"barfoo", 10, true);
        let third = RangeBuf::from(b"rl", 7, false);
        let fourth = RangeBuf::from(b"elloworldbarfoo", 1, true);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        assert_emit_discard(
            &mut recv,
            emit,
            32,
            16,
            true,
            Some(b"helloworldbarfoo"),
        );
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 16);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn partially_multi_overlapping_reordered_read(
        #[values(true, false)] emit: bool,
    ) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"hello", 8, false);
        let second = RangeBuf::from(b"something", 0, false);
        let third = RangeBuf::from(b"moar", 11, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 15);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert_emit_discard(
            &mut recv,
            emit,
            32,
            15,
            true,
            Some(b"somethinhelloar"),
        );
        assert_eq!(recv.len, 15);
        assert_eq!(recv.off, 15);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn partially_multi_overlapping_reordered_read2(
        #[values(true, false)] emit: bool,
    ) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"aaa", 0, false);
        let second = RangeBuf::from(b"bbb", 2, false);
        let third = RangeBuf::from(b"ccc", 4, false);
        let fourth = RangeBuf::from(b"ddd", 6, false);
        let fifth = RangeBuf::from(b"eee", 9, false);
        let sixth = RangeBuf::from(b"fff", 11, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 4);

        assert!(recv.write(sixth).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        assert!(recv.write(fifth).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 6);

        assert_emit_discard(
            &mut recv,
            emit,
            32,
            14,
            false,
            Some(b"aabbbcdddeefff"),
        );
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 14);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[test]
    fn mixed_read_actions() {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);

        assert_emit_discard_done(&mut recv, true);
        assert_emit_discard_done(&mut recv, false);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard_done(&mut recv, true);
        assert_emit_discard_done(&mut recv, false);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard(&mut recv, true, 5, 5, false, Some(b"hello"));
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 5);

        assert_emit_discard(&mut recv, false, 5, 5, false, None);
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 10);

        assert_emit_discard(&mut recv, true, 9, 9, true, Some(b"something"));
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);

        assert_emit_discard_done(&mut recv, true);
        assert_emit_discard_done(&mut recv, false);
    }
}
