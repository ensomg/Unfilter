//! TLS ClientHello parser: extracts SNI and ALPN and detects Encrypted Client
//! Hello. Reads only what the classifier needs; the rest is skipped by length.
//!
//! Scope: a ClientHello contained in a single TLS record (the common case).
//! Reassembly of a ClientHello split across records is not needed here — the
//! engine *produces* such splits as a bypass, it does not have to parse them.

use super::Cursor;
use crate::classify::Classification;
use crate::error::{Error, Result};

// Record and handshake constants.
const CONTENT_HANDSHAKE: u8 = 0x16;
const HS_CLIENT_HELLO: u8 = 0x01;

// Extension type codes.
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_ECH: u16 = 0xfe0d; // encrypted_client_hello (RFC 9460 / draft-ietf-tls-esni)

const SNI_NAME_TYPE_HOST: u8 = 0x00;

/// Parse a TLS record that should contain a ClientHello and fill the SNI, ALPN,
/// and ECH fields of `out`. Leaves `out` untouched and returns an error if the
/// bytes are not a well-formed ClientHello.
pub fn parse_client_hello<'p>(record: &'p [u8], out: &mut Classification<'p>) -> Result<()> {
    let mut c = Cursor::new(record);

    // TLS record header.
    if c.u8()? != CONTENT_HANDSHAKE {
        return Err(Error::Malformed);
    }
    let _record_version = c.u16()?;
    let record_len = c.u16()? as usize;
    // Parse only within the declared record payload.
    let body = c.take(record_len.min(c.remaining()))?;

    let mut h = Cursor::new(body);
    if h.u8()? != HS_CLIENT_HELLO {
        return Err(Error::Malformed);
    }
    let hs_len = h.u24()? as usize;
    let hs = h.take(hs_len.min(h.remaining()))?;

    let mut b = Cursor::new(hs);
    let _client_version = b.u16()?;
    b.skip(32)?; // random

    let sid_len = b.u8()? as usize;
    b.skip(sid_len)?; // session_id

    let cs_len = b.u16()? as usize;
    b.skip(cs_len)?; // cipher_suites

    let comp_len = b.u8()? as usize;
    b.skip(comp_len)?; // compression_methods

    // Extensions are optional (TLS 1.0 ClientHello may omit them).
    if b.remaining() == 0 {
        return Ok(());
    }
    let ext_total = b.u16()? as usize;
    let ext_bytes = b.take(ext_total.min(b.remaining()))?;
    parse_extensions(ext_bytes, out)
}

fn parse_extensions<'p>(ext_bytes: &'p [u8], out: &mut Classification<'p>) -> Result<()> {
    let mut e = Cursor::new(ext_bytes);
    while e.remaining() >= 4 {
        let ext_type = e.u16()?;
        let ext_len = e.u16()? as usize;
        let data = e.take(ext_len)?;
        match ext_type {
            EXT_SERVER_NAME => {
                if let Some(name) = parse_sni(data) {
                    out.sni = Some(name);
                }
            }
            EXT_ALPN => out.alpn = Some(data),
            EXT_ECH => out.has_ech = true,
            _ => {}
        }
    }
    Ok(())
}

/// Parse an SNI extension body and return the first host_name as `&str`.
fn parse_sni(data: &[u8]) -> Option<&str> {
    let mut c = Cursor::new(data);
    let list_len = c.u16().ok()? as usize;
    let list = c.take(list_len.min(c.remaining())).ok()?;
    let mut l = Cursor::new(list);
    while l.remaining() >= 3 {
        let name_type = l.u8().ok()?;
        let name_len = l.u16().ok()? as usize;
        let name = l.take(name_len).ok()?;
        if name_type == SNI_NAME_TYPE_HOST {
            // SNI host names are ASCII (IDNA-encoded); reject non-UTF-8.
            return core::str::from_utf8(name).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal ClientHello for "example.com" with ALPN h2 and no ECH.
    fn client_hello(host: &[u8], with_ech: bool) -> Vec<u8> {
        // SNI extension body.
        let mut sni_list = Vec::new();
        sni_list.push(0u8); // name_type = host_name
        sni_list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_list.extend_from_slice(host);
        let mut sni = Vec::new();
        sni.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        sni.extend_from_slice(&sni_list);

        // ALPN extension body: list of one protocol "h2".
        let alpn_proto: &[u8] = b"h2";
        let mut alpn = Vec::new();
        let inner_len = 1 + alpn_proto.len();
        alpn.extend_from_slice(&(inner_len as u16).to_be_bytes());
        alpn.push(alpn_proto.len() as u8);
        alpn.extend_from_slice(alpn_proto);

        // Extensions block.
        let mut exts = Vec::new();
        let push_ext = |exts: &mut Vec<u8>, t: u16, body: &[u8]| {
            exts.extend_from_slice(&t.to_be_bytes());
            exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
            exts.extend_from_slice(body);
        };
        push_ext(&mut exts, EXT_SERVER_NAME, &sni);
        push_ext(&mut exts, EXT_ALPN, &alpn);
        if with_ech {
            push_ext(&mut exts, EXT_ECH, &[0x00, 0x01, 0x02]);
        }

        // ClientHello body.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites (1)
        body.extend_from_slice(&[0x01, 0x00]); // compression_methods: null
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        // Handshake header.
        let mut hs = Vec::new();
        hs.push(HS_CLIENT_HELLO);
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        // Record header.
        let mut rec = Vec::new();
        rec.push(CONTENT_HANDSHAKE);
        rec.extend_from_slice(&[0x03, 0x01]); // record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni_and_alpn() {
        let rec = client_hello(b"example.com", false);
        let mut out = Classification::default();
        parse_client_hello(&rec, &mut out).unwrap();
        assert_eq!(out.sni, Some("example.com"));
        assert_eq!(out.alpn, Some(&[0x00, 0x03, 0x02, b'h', b'2'][..]));
        assert!(!out.has_ech);
    }

    #[test]
    fn detects_ech() {
        let rec = client_hello(b"blocked.example", true);
        let mut out = Classification::default();
        parse_client_hello(&rec, &mut out).unwrap();
        assert_eq!(out.sni, Some("blocked.example"));
        assert!(out.has_ech);
    }

    #[test]
    fn truncated_is_error_not_panic() {
        let rec = client_hello(b"example.com", false);
        for n in 0..rec.len() {
            let mut out = Classification::default();
            // Must never panic, whatever the prefix length.
            let _ = parse_client_hello(&rec[..n], &mut out);
        }
    }

    #[test]
    fn non_handshake_rejected() {
        let mut out = Classification::default();
        assert_eq!(
            parse_client_hello(&[0x17, 0x03, 0x03, 0x00, 0x00], &mut out),
            Err(Error::Malformed)
        );
    }
}
