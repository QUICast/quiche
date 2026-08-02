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

use std::cmp;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;

use crate::buffers::BufFactory;
use crate::buffers::DefaultBufFactory;
use crate::stream::StreamSendCharge;
use crate::Result;

/// Buffer holding data at a specific offset.
///
/// The data is stored in a `Vec<u8>` in such a way that it can be shared
/// between multiple `RangeBuf` objects.
///
/// Each `RangeBuf` will have its own view of that buffer, where the `start`
/// value indicates the initial offset within the `Vec`, and `len` indicates the
/// number of bytes, starting from `start` that are included.
///
/// In addition, `pos` indicates the current offset within the `Vec`, starting
/// from the very beginning of the `Vec`.
///
/// Finally, `off` is the starting offset for the specific `RangeBuf` within the
/// stream the buffer belongs to.
#[derive(Clone, Debug, Default)]
pub struct RangeBuf<F = DefaultBufFactory>
where
    F: BufFactory,
{
    /// The internal buffer holding the data.
    ///
    /// To avoid needless allocations when a RangeBuf is split, this field
    /// should be reference-counted so it can be shared between multiple
    /// RangeBuf objects, and sliced using the `start` and `len` values.
    pub(crate) data: F::Buf,

    /// The initial offset within the internal buffer.
    pub(crate) start: usize,

    /// The current offset within the internal buffer.
    pub(crate) pos: usize,

    /// The number of bytes in the buffer, from the initial offset.
    pub(crate) len: usize,

    /// The offset of the buffer within a stream.
    pub(crate) off: u64,

    /// Whether this contains the final byte in the stream.
    pub(crate) fin: bool,

    /// Retention charge shared by views of one send-buffer chunk.
    pub(crate) retention: Option<Arc<StreamSendCharge>>,

    _bf: PhantomData<F>,
}

impl<F: BufFactory> RangeBuf<F>
where
    F::Buf: Clone,
{
    /// Creates a new `RangeBuf` from the given slice.
    pub fn from(buf: &[u8], off: u64, fin: bool) -> RangeBuf<F> {
        Self::from_raw(F::buf_from_slice(buf), off, fin)
    }

    pub fn from_raw(data: F::Buf, off: u64, fin: bool) -> RangeBuf<F> {
        RangeBuf {
            len: data.as_ref().len(),
            data,
            start: 0,
            pos: 0,
            off,
            fin,
            retention: None,
            _bf: Default::default(),
        }
    }

    pub(crate) fn from_raw_retained(
        data: F::Buf, off: u64, fin: bool, retention: Arc<StreamSendCharge>,
    ) -> RangeBuf<F> {
        let mut buf = Self::from_raw(data, off, fin);
        buf.retention = Some(retention);
        buf
    }

    /// Returns whether `self` holds the final offset in the stream.
    pub fn fin(&self) -> bool {
        self.fin
    }

    /// Returns the starting offset of `self`.
    pub fn off(&self) -> u64 {
        (self.off - self.start as u64) + self.pos as u64
    }

    /// Returns the final offset of `self`.
    pub fn max_off(&self) -> u64 {
        self.off() + self.len() as u64
    }

    /// Returns the length of `self`.
    pub fn len(&self) -> usize {
        self.len - (self.pos - self.start)
    }

    /// Returns true if `self` has a length of zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Consumes the starting `count` bytes of `self`.
    pub fn consume(&mut self, count: usize) {
        self.pos += count;
    }

    /// Splits the buffer into two at the given index.
    pub fn split_off(&mut self, at: usize) -> RangeBuf<F>
    where
        F::Buf: Clone + AsRef<[u8]>,
    {
        assert!(
            at <= self.len,
            "`at` split index (is {}) should be <= len (is {})",
            at,
            self.len
        );

        let buf = RangeBuf {
            data: self.data.clone(),
            start: self.start + at,
            pos: cmp::max(self.pos, self.start + at),
            len: self.len - at,
            off: self.off + at as u64,
            _bf: Default::default(),
            fin: self.fin,
            retention: self.retention.clone(),
        };

        self.pos = cmp::min(self.pos, self.start + at);
        self.len = at;
        self.fin = false;

        buf
    }

    pub(crate) fn try_split_off_retained(
        &mut self, at: usize,
    ) -> Result<RangeBuf<F>>
    where
        F::Buf: Clone + AsRef<[u8]>,
    {
        let sibling = self
            .retention
            .as_ref()
            .map(|charge| charge.try_reserve_sibling())
            .transpose()?;
        let mut buf = self.split_off(at);
        if let Some(sibling) = sibling {
            buf.retention = Some(sibling);
        }
        Ok(buf)
    }

    pub(crate) fn truncate_total(&mut self, at: usize) -> usize {
        assert!(at <= self.len);
        let before = self.len();
        self.pos = cmp::min(self.pos, self.start + at);
        self.len = at;
        self.fin = false;
        before.saturating_sub(self.len())
    }

    /// Truncates the unread portion to at most `len` bytes.
    pub(crate) fn truncate_unread(&mut self, len: usize)
    where
        F::Buf: Clone + AsRef<[u8]>,
    {
        if len >= self.len() {
            return;
        }

        let consumed = self.pos - self.start;
        let _ = self.split_off(consumed + len);
    }
}

impl<F: BufFactory> Deref for RangeBuf<F> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data.as_ref()[self.pos..self.start + self.len]
    }
}

impl<F: BufFactory> Ord for RangeBuf<F> {
    fn cmp(&self, other: &RangeBuf<F>) -> cmp::Ordering {
        // Invert ordering to implement min-heap.
        self.off.cmp(&other.off).reverse()
    }
}

impl<F: BufFactory> PartialOrd for RangeBuf<F> {
    fn partial_cmp(&self, other: &RangeBuf<F>) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: BufFactory> Eq for RangeBuf<F> {}

impl<F: BufFactory> PartialEq for RangeBuf<F> {
    fn eq(&self, other: &RangeBuf<F>) -> bool {
        self.off == other.off
    }
}
