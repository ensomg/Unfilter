//! QUIC long-header (Initial) public parsing — everything readable before any
//! decryption. Bounds-checked; never panics on malformed input.
//!
//! Covers QUIC v1 (RFC 9000/9001, version `0x0000_0001`) and v2 (RFC 9369,
//! version `0x6b33_43cf`). The two differ only in the Initial salt and the
//! header-protection/key labels (see `crypto`); their wire layout is identical.

use crate::error::{Error, Result};

/// QUIC v1 version number.
pub const VERSION_V1: u32 = 0x0000_0001;
/// QUIC v2 version number (RFC 9369).
pub const VERSION_V2: u32 = 0x6b33_43cf;

/// Which QUIC version an Initial packet uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// RFC 9000/9001.
    V1,
    /// RFC 9369.
    V2,
}

impl Version {
    /// Map a raw version number to a known version, if supported.
    pub fn from_raw(v: u32) -> Option<Version> {
        match v {
            VERSION_V1 => Some(Version::V1),
            VERSION_V2 => Some(Version::V2),
            _ => None,
        }
    }
}

/// Is the Initial long-header packet-type for this version. v1 uses type bits
/// `0b00`; v2 remaps Initial to `0b01` (RFC 9369 §3.2).
fn is_initial(first_byte: u8, version: Version) -> bool {
    // Long header has the high bit set and the fixed bit set.
    if first_byte & 0x80 == 0 {
        return false;
    }
    let type_bits = (first_byte & 0x30) >> 4;
    match version {
        Version::V1 => type_bits == 0b00,
        Version::V2 => type_bits == 0b01,
    }
}

/// The parsed public fields of an Initial packet, with the offsets a decryptor
/// needs: where the (still protected) packet number begins and where the payload
/// (protected packet number + ciphertext + tag) ends.
#[derive(Debug, Clone)]
pub struct InitialHeader<'a> {
    /// QUIC version.
    pub version: Version,
    /// Destination Connection ID (the HKDF input for Initial keys).
    pub dcid: &'a [u8],
    /// Source Connection ID.
    pub scid: &'a [u8],
    /// Token (empty for a client's first Initial).
    pub token: &'a [u8],
    /// Offset of the first protected byte (the packet number) in the datagram.
    pub pn_offset: usize,
    /// Offset one past the end of this packet's payload (start of any coalesced
    /// packet).
    pub end: usize,
}

/// Read a QUIC variable-length integer; returns the value and its byte length.
fn read_varint(buf: &[u8], pos: usize) -> Result<(u64, usize)> {
    let first = *buf.get(pos).ok_or(Error::Truncated)?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(pos..pos + len).ok_or(Error::Truncated)?;
    let mut v = (first & 0x3F) as u64;
    for &b in &bytes[1..] {
        v = (v << 8) | b as u64;
    }
    Ok((v, len))
}

/// Parse the public header of the Initial packet at the start of `datagram`.
/// A connection ID longer than 20 bytes, a non-Initial packet, or any length
/// running past the datagram is rejected.
pub fn parse_initial(datagram: &[u8]) -> Result<InitialHeader<'_>> {
    let first = *datagram.first().ok_or(Error::Truncated)?;
    if first & 0x80 == 0 {
        return Err(Error::NotInitial); // short header
    }
    let raw_ver = u32::from_be_bytes([
        *datagram.get(1).ok_or(Error::Truncated)?,
        *datagram.get(2).ok_or(Error::Truncated)?,
        *datagram.get(3).ok_or(Error::Truncated)?,
        *datagram.get(4).ok_or(Error::Truncated)?,
    ]);
    let version = Version::from_raw(raw_ver).ok_or(Error::UnsupportedVersion)?;
    if !is_initial(first, version) {
        return Err(Error::NotInitial);
    }

    let mut pos = 5;
    let read_cid = |buf: &[u8], pos: &mut usize| -> Result<(usize, usize)> {
        let len = *buf.get(*pos).ok_or(Error::Truncated)? as usize;
        if len > 20 {
            return Err(Error::Malformed);
        }
        let start = *pos + 1;
        buf.get(start..start + len).ok_or(Error::Truncated)?;
        *pos = start + len;
        Ok((start, len))
    };
    let (dcid_start, dcid_len) = read_cid(datagram, &mut pos)?;
    let (scid_start, scid_len) = read_cid(datagram, &mut pos)?;

    let (token_len, tl_bytes) = read_varint(datagram, pos)?;
    pos += tl_bytes;
    let token_start = pos;
    let token_len = token_len as usize;
    datagram
        .get(token_start..token_start + token_len)
        .ok_or(Error::Truncated)?;
    pos += token_len;

    let (length, len_bytes) = read_varint(datagram, pos)?;
    pos += len_bytes;
    let pn_offset = pos;
    let end = pn_offset
        .checked_add(length as usize)
        .ok_or(Error::OutOfBounds)?;
    if end > datagram.len() {
        return Err(Error::Truncated);
    }

    Ok(InitialHeader {
        version,
        dcid: &datagram[dcid_start..dcid_start + dcid_len],
        scid: &datagram[scid_start..scid_start + scid_len],
        token: &datagram[token_start..token_start + token_len],
        pn_offset,
        end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_header() {
        assert_eq!(parse_initial(&[0x40, 0, 0]).unwrap_err(), Error::NotInitial);
    }

    #[test]
    fn rejects_unknown_version() {
        // Long header, fixed bit, version 0xdeadbeef.
        let pkt = [0xC0, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00];
        assert_eq!(parse_initial(&pkt).unwrap_err(), Error::UnsupportedVersion);
    }

    #[test]
    fn parses_minimal_v1_initial() {
        // first byte C0 (long, initial, pn_len bits 0), version 1,
        // dcid len 4 + 4 bytes, scid len 0, token len 0, length=5 (1-byte varint).
        let mut p = vec![0xC0, 0x00, 0x00, 0x00, 0x01];
        p.push(4);
        p.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        p.push(0); // scid len
        p.push(0); // token len (varint 0)
        p.push(0x05); // length varint = 5
        p.extend_from_slice(&[1, 2, 3, 4, 5]); // payload region
        let h = parse_initial(&p).unwrap();
        assert_eq!(h.version, Version::V1);
        assert_eq!(h.dcid, &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(h.scid.is_empty());
        assert!(h.token.is_empty());
        assert_eq!(h.end, p.len());
    }

    #[test]
    fn truncated_never_panics() {
        let mut p = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 4];
        p.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0x05, 1, 2, 3, 4, 5]);
        for n in 0..p.len() {
            let _ = parse_initial(&p[..n]);
        }
    }

    #[test]
    fn rejects_oversized_cid() {
        let p = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 21];
        assert_eq!(parse_initial(&p).unwrap_err(), Error::Malformed);
    }

    #[test]
    fn v2_initial_type_bits() {
        // v2 Initial uses type bits 0b01 -> first byte 0xD0.
        let mut p = vec![0xD0, 0x6B, 0x33, 0x43, 0xCF, 0];
        p.push(0); // scid
        p.push(0); // token
        p.push(0x02);
        p.extend_from_slice(&[0, 0]);
        let h = parse_initial(&p).unwrap();
        assert_eq!(h.version, Version::V2);
    }
}
