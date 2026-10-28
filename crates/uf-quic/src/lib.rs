//! QUIC Initial handling: read the public header of a client's Initial packet
//! and, with the `decrypt` feature, recover the SNI from its ClientHello.
//!
//! QUIC Initial packets are encrypted, but with a key derived from the
//! Destination Connection ID that is in the packet itself (RFC 9001 §5.2), so a
//! client-side tool can read its own handshake. This crate does exactly that
//! and no more: it never forges or injects QUIC — the engine uses the recovered
//! SNI to choose a strategy, the same way it uses a TLS ClientHello's SNI.
//!
//! Layers:
//! - [`header`]: public long-header parsing (v1 and v2), allocation-free.
//! - [`crypto`] (`decrypt`): Initial key derivation + header-protection removal
//!   + AES-128-GCM payload decryption, on ring.
//! - [`frames`]: reassemble the CRYPTO stream into the TLS handshake bytes.
//! - [`extract_sni`]: the end-to-end helper the engine calls.

pub mod error;
pub mod frames;
pub mod header;

#[cfg(feature = "decrypt")]
pub mod crypto;

pub use error::{Error, Result};
pub use header::{InitialHeader, Version, parse_initial};

/// Recover the SNI from a QUIC client Initial datagram, or `None` if it is not a
/// readable Initial or carries no SNI. Available with the `decrypt` feature.
///
/// Steps: parse the public header, derive the Initial keys from the DCID,
/// decrypt the payload, reassemble the CRYPTO stream into the ClientHello, and
/// run the shared TLS parser over it.
#[cfg(feature = "decrypt")]
pub fn extract_sni(datagram: &[u8]) -> Option<String> {
    let header = parse_initial(datagram).ok()?;
    let payload = crypto::decrypt_initial(datagram, &header).ok()?;
    let handshake = frames::reassemble_crypto(&payload).ok()?;
    sni_from_handshake(&handshake)
}

/// Parse a TLS handshake message (a bare ClientHello, as QUIC CRYPTO carries it
/// — no TLS record framing) and return its SNI. Done by wrapping the handshake
/// in a synthetic TLS record and reusing the shared, tested TLS parser.
#[cfg(feature = "decrypt")]
fn sni_from_handshake(handshake: &[u8]) -> Option<String> {
    use uf_core::classify::Classification;
    // The handshake must start with ClientHello (type 0x01). Wrap it in a TLS
    // record: content_type=handshake(0x16), version TLS 1.0, 2-byte length.
    if handshake.first() != Some(&0x01) {
        return None;
    }
    let len = u16::try_from(handshake.len()).ok()?;
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(handshake);

    let mut out = Classification::default();
    uf_core::parse::tls::parse_client_hello(&record, &mut out).ok()?;
    out.sni.map(|s| s.to_string())
}

#[cfg(all(test, feature = "decrypt"))]
mod tests {
    use super::*;

    fn client_hello_handshake(host: &[u8]) -> Vec<u8> {
        let mut sni_list = vec![0u8];
        sni_list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_list.extend_from_slice(host);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&((sni_list.len() + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_list);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01];
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);
        hs
    }

    /// End-to-end: build a real client Initial carrying a ClientHello for
    /// "example.com", then run the public parse → decrypt → reassemble → TLS
    /// parse pipeline and recover the SNI. Exercises header offsets, the HP
    /// mask, the AEAD nonce/AAD and CRYPTO reassembly together.
    #[test]
    fn roundtrip_initial_yields_sni() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let hs = client_hello_handshake(b"example.com");
        // Wrap the handshake in a CRYPTO frame (offset 0).
        let mut frames = vec![0x06, 0x00]; // type, offset varint 0
        frames.extend_from_slice(&[0x40 | (hs.len() >> 8) as u8, hs.len() as u8]); // len varint
        frames.extend_from_slice(&hs);

        let pkt = crypto::seal_initial_for_test(&dcid, &frames);
        assert_eq!(extract_sni(&pkt).as_deref(), Some("example.com"));
    }

    #[test]
    fn non_initial_returns_none() {
        assert_eq!(extract_sni(&[0x40, 0, 0, 0]), None);
    }

    #[test]
    fn sni_from_handshake_wraps_and_parses() {
        // Build a ClientHello handshake message (no record header) for
        // "test.example" and confirm the wrapper + TLS parser recover it.
        let host = b"test.example";
        let mut sni_list = vec![0u8];
        sni_list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_list.extend_from_slice(host);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&((sni_list.len() + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_list);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01];
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        assert_eq!(sni_from_handshake(&hs).as_deref(), Some("test.example"));
    }
}
