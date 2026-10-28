//! Parse the frames in a decrypted Initial payload and reassemble the CRYPTO
//! stream into the TLS handshake bytes (the ClientHello). Only the frame types
//! an Initial can carry are handled; anything else is an error (the caller then
//! treats the flow as opaque). Pure and bounds-checked.

use crate::error::{Error, Result};

/// Read a QUIC varint at `pos`, returning the value and its length.
fn varint(buf: &[u8], pos: usize) -> Result<(u64, usize)> {
    let first = *buf.get(pos).ok_or(Error::Truncated)?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(pos..pos + len).ok_or(Error::Truncated)?;
    let mut v = (first & 0x3F) as u64;
    for &b in &bytes[1..] {
        v = (v << 8) | b as u64;
    }
    Ok((v, len))
}

/// Reassemble the CRYPTO stream (offset-ordered) from a decrypted Initial
/// payload. PADDING/PING/ACK frames are skipped; CONNECTION_CLOSE ends parsing.
/// Returns the contiguous handshake bytes starting at CRYPTO offset 0.
pub fn reassemble_crypto(payload: &[u8]) -> Result<Vec<u8>> {
    // (offset, data) pieces, then stitched; Initial ClientHellos are small.
    let mut pieces: Vec<(u64, &[u8])> = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let ty = payload[pos];
        pos += 1;
        match ty {
            0x00 => {} // PADDING (single byte)
            0x01 => {} // PING
            0x02 | 0x03 => pos = skip_ack(payload, pos, ty == 0x03)?,
            0x06 => {
                // CRYPTO: offset, length, data.
                let (offset, n) = varint(payload, pos)?;
                pos += n;
                let (length, n) = varint(payload, pos)?;
                pos += n;
                let length = length as usize;
                let data = payload.get(pos..pos + length).ok_or(Error::Truncated)?;
                pos += length;
                pieces.push((offset, data));
            }
            0x1c | 0x1d => break, // CONNECTION_CLOSE
            _ => return Err(Error::Malformed),
        }
    }

    pieces.sort_by_key(|(off, _)| *off);
    let mut out = Vec::new();
    for (off, data) in pieces {
        let off = off as usize;
        // A gap means the ClientHello is incomplete in this packet.
        if off > out.len() {
            return Err(Error::Truncated);
        }
        // Append only the bytes that extend past what we already have
        // (overlapping retransmissions are ignored).
        if off + data.len() > out.len() {
            out.extend_from_slice(&data[out.len() - off..]);
        }
    }
    if out.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(out)
}

/// Skip an ACK frame's variable-length body (RFC 9000 §19.3), returning the new
/// position. `ecn` is true for the ACK_ECN variant (0x03), which appends three
/// ECN counts.
fn skip_ack(buf: &[u8], mut pos: usize, ecn: bool) -> Result<usize> {
    // largest_ack, ack_delay.
    for _ in 0..2 {
        let (_, n) = varint(buf, pos)?;
        pos += n;
    }
    // ack_range_count, then first_ack_range.
    let (range_count, n) = varint(buf, pos)?;
    pos += n;
    let (_first, n) = varint(buf, pos)?;
    pos += n;
    // Each range: gap, ack_range_length.
    for _ in 0..range_count {
        let (_, n) = varint(buf, pos)?;
        pos += n;
        let (_, n) = varint(buf, pos)?;
        pos += n;
    }
    if ecn {
        for _ in 0..3 {
            let (_, n) = varint(buf, pos)?;
            pos += n;
        }
    }
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06];
        f.push(offset as u8); // offset (1-byte varint, <64)
        f.push(data.len() as u8); // length (1-byte varint, <64)
        f.extend_from_slice(data);
        f
    }

    #[test]
    fn reassembles_single_crypto_frame() {
        let mut payload = vec![0x00, 0x00]; // leading PADDING
        payload.extend_from_slice(&crypto_frame(0, b"hello-clienthello"));
        let out = reassemble_crypto(&payload).unwrap();
        assert_eq!(out, b"hello-clienthello");
    }

    #[test]
    fn reassembles_two_in_order_frames() {
        let mut payload = crypto_frame(0, b"abcd");
        payload.extend_from_slice(&crypto_frame(4, b"efgh"));
        let out = reassemble_crypto(&payload).unwrap();
        assert_eq!(out, b"abcdefgh");
    }

    #[test]
    fn ping_and_padding_are_skipped() {
        let mut payload = vec![0x01, 0x00, 0x00]; // PING + PADDING
        payload.extend_from_slice(&crypto_frame(0, b"x"));
        assert_eq!(reassemble_crypto(&payload).unwrap(), b"x");
    }

    #[test]
    fn gap_is_truncated() {
        let payload = crypto_frame(4, b"efgh"); // starts at offset 4, no 0..4
        assert_eq!(reassemble_crypto(&payload), Err(Error::Truncated));
    }

    #[test]
    fn unknown_frame_is_malformed() {
        let payload = vec![0x42];
        assert_eq!(reassemble_crypto(&payload), Err(Error::Malformed));
    }

    #[test]
    fn empty_is_malformed() {
        assert_eq!(reassemble_crypto(&[]), Err(Error::Malformed));
    }
}
