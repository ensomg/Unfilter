//! Zero-copy, allocation-free parsers for the opening payload of a flow.
//!
//! Each parser borrows into the packet buffer and returns slices; nothing is
//! copied. All bounds are checked, so a malformed packet yields an [`Err`] (the
//! engine then passes the packet through unchanged) rather than panicking.

pub mod http;
pub mod tls;

use crate::error::{Error, Result};

/// A forward-only cursor over a byte slice with checked reads. The building
/// block for every parser here: no indexing can panic, and a short read is a
/// clean [`Error::Truncated`].
pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }

    /// Read a 24-bit big-endian integer (TLS handshake lengths).
    pub(crate) fn u24(&mut self) -> Result<u32> {
        let a = self.u8()? as u32;
        let b = self.u8()? as u32;
        let c = self.u8()? as u32;
        Ok((a << 16) | (b << 8) | c)
    }

    /// Borrow the next `n` bytes, advancing the cursor.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::OutOfBounds)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Skip `n` bytes.
    pub(crate) fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }
}
