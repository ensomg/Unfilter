//! Initial-packet decryption: derive the client Initial keys from the DCID
//! (RFC 9001 §5.2 for v1, RFC 9369 §3.3 for v2), remove header protection, and
//! decrypt the AES-128-GCM payload. Uses ring's QUIC/AEAD primitives only.
//!
//! Only client Initial keys are derived — that is all the engine needs to read
//! the ClientHello's SNI.

use ring::aead::quic::{AES_128, HeaderProtectionKey};
use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};

use crate::error::{Error, Result};
use crate::header::{InitialHeader, Version};

/// RFC 9001 §5.2 initial salt (QUIC v1).
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9369 §3.3.1 initial salt (QUIC v2).
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Per-version key/iv/hp derivation labels. v2 renames key/iv/hp (RFC 9369);
/// the "client in" label is unchanged.
struct Labels {
    key: &'static [u8],
    iv: &'static [u8],
    hp: &'static [u8],
}

fn labels(v: Version) -> (&'static [u8; 20], Labels) {
    match v {
        Version::V1 => (
            &SALT_V1,
            Labels {
                key: b"quic key",
                iv: b"quic iv",
                hp: b"quic hp",
            },
        ),
        Version::V2 => (
            &SALT_V2,
            Labels {
                key: b"quicv2 key",
                iv: b"quicv2 iv",
                hp: b"quicv2 hp",
            },
        ),
    }
}

/// The client Initial secrets a decryptor needs.
pub struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

/// A length for ring's HKDF expand.
struct Len(usize);
impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand-Label (TLS 1.3 / RFC 8446 §7.1) with an empty context.
fn expand_label(prk: &Prk, label: &[u8], out: &mut [u8]) -> Result<()> {
    let mut full = Vec::with_capacity(6 + label.len());
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label);
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(0); // zero-length context
    let components = [info.as_slice()];
    let okm = prk
        .expand(&components, Len(out.len()))
        .map_err(|_| Error::Crypto)?;
    okm.fill(out).map_err(|_| Error::Crypto)
}

/// Derive the client Initial key/iv/hp from the Destination Connection ID.
pub fn client_initial_keys(version: Version, dcid: &[u8]) -> Result<InitialKeys> {
    let (salt, lab) = labels(version);
    let salt_key = Salt::new(HKDF_SHA256, salt);
    let initial_secret = salt_key.extract(dcid);
    let mut client_secret = [0u8; 32];
    expand_label(&initial_secret, b"client in", &mut client_secret)?;
    let cs = Prk::new_less_safe(HKDF_SHA256, &client_secret);

    let mut keys = InitialKeys {
        key: [0u8; 16],
        iv: [0u8; 12],
        hp: [0u8; 16],
    };
    expand_label(&cs, lab.key, &mut keys.key)?;
    expand_label(&cs, lab.iv, &mut keys.iv)?;
    expand_label(&cs, lab.hp, &mut keys.hp)?;
    Ok(keys)
}

/// Remove header protection and decrypt the Initial payload, returning the
/// plaintext QUIC frames. The datagram must start at this Initial packet;
/// `header.end` bounds it (coalesced packets after `end` are ignored).
pub fn decrypt_initial(datagram: &[u8], header: &InitialHeader<'_>) -> Result<Vec<u8>> {
    let keys = client_initial_keys(header.version, header.dcid)?;

    // Header protection sample: 4 bytes after pn_offset, 16 bytes long.
    let sample_off = header.pn_offset + 4;
    let sample = datagram
        .get(sample_off..sample_off + 16)
        .ok_or(Error::Truncated)?;
    let hp = HeaderProtectionKey::new(&AES_128, &keys.hp).map_err(|_| Error::Crypto)?;
    let mask = hp.new_mask(sample).map_err(|_| Error::Crypto)?;

    // Unmask the first byte (long header: low 4 bits) and learn the pn length.
    let first = datagram[0] ^ (mask[0] & 0x0f);
    let pn_len = (first & 0x03) as usize + 1;
    if header.pn_offset + pn_len > header.end {
        return Err(Error::Truncated);
    }

    // Unmask the packet number and decode it.
    let mut header_bytes = datagram[..header.pn_offset + pn_len].to_vec();
    header_bytes[0] = first;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        let b = datagram[header.pn_offset + i] ^ mask[1 + i];
        header_bytes[header.pn_offset + i] = b;
        pn = (pn << 8) | b as u64;
    }

    // Nonce = iv XOR left-padded packet number.
    let mut nonce = keys.iv;
    let pnb = pn.to_be_bytes(); // 8 bytes
    for i in 0..8 {
        nonce[12 - 8 + i] ^= pnb[i];
    }

    // Ciphertext (including the 16-byte GCM tag) is from the end of the packet
    // number to the end of this packet.
    let ct_start = header.pn_offset + pn_len;
    let mut buf = datagram
        .get(ct_start..header.end)
        .ok_or(Error::Truncated)?
        .to_vec();
    if buf.len() < 16 {
        return Err(Error::Truncated);
    }

    let key =
        LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &keys.key).map_err(|_| Error::Crypto)?);
    let nonce = Nonce::assume_unique_for_key(nonce);
    let plain = key
        .open_in_place(nonce, Aad::from(&header_bytes), &mut buf)
        .map_err(|_| Error::Crypto)?;
    Ok(plain.to_vec())
}

/// Build a real client Initial packet carrying `plaintext` frames, for tests
/// and round-trip verification of the decrypt path. v1 only; 2-byte packet
/// number 0; empty SCID/token.
#[cfg(test)]
pub(crate) fn seal_initial_for_test(dcid: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let keys = client_initial_keys(Version::V1, dcid).unwrap();

    let pn_len = 2usize;
    let mut pkt = vec![0xC0 | (pn_len as u8 - 1)]; // long, Initial, pn_len=2
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(dcid);
    pkt.push(0); // scid len
    pkt.push(0); // token len (varint 0)
    let body_len = pn_len + plaintext.len() + 16; // pn + ciphertext + tag
    pkt.extend_from_slice(&[0x40 | (body_len >> 8) as u8, body_len as u8]); // 2-byte varint
    let pn_offset = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]); // packet number 0

    // AAD is the header through the packet number (unprotected).
    let aad = pkt.clone();
    let mut buf = plaintext.to_vec();
    let nonce = keys.iv; // pn = 0 -> nonce == iv
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &keys.key).unwrap());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&aad),
        &mut buf,
    )
    .unwrap();
    pkt.extend_from_slice(&buf);

    // Apply header protection using the sample at pn_offset + 4.
    let sample: [u8; 16] = pkt[pn_offset + 4..pn_offset + 20].try_into().unwrap();
    let hp = HeaderProtectionKey::new(&AES_128, &keys.hp).unwrap();
    let mask = hp.new_mask(&sample).unwrap();
    pkt[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        pkt[pn_offset + i] ^= mask[1 + i];
    }
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9001 Appendix A.1/A.2 test vectors (QUIC v1).
    const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn client_initial_keys_match_rfc9001() {
        let k = client_initial_keys(Version::V1, &DCID).unwrap();
        assert_eq!(k.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(k.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(k.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn header_protection_mask_matches_rfc9001() {
        let k = client_initial_keys(Version::V1, &DCID).unwrap();
        let hp = HeaderProtectionKey::new(&AES_128, &k.hp).unwrap();
        // RFC 9001 A.2 sample and expected mask.
        let sample = hex("d1b1c98dd7689fb8ec11d242b123dc9b");
        let mask = hp.new_mask(&sample).unwrap();
        // The first mask byte and the packet-number mask bytes.
        assert_eq!(&mask[..], &hex("437b9aec36")[..]);
    }
}
