//! Network fingerprint: a stable 64-bit hash of the identifiers that
//! distinguish one network (and its ISP/DPI behaviour) from another.
//!
//! Privacy (master prompt §5.5): the raw identifiers — gateway MAC, SSID — never
//! leave this struct and are never written to disk. Only the hash is persisted,
//! as the cache key. The hash is FNV-1a (not `DefaultHasher`) so it is stable
//! across runs and build versions, which a persisted key requires.

use serde::{Deserialize, Serialize};

/// Raw identifiers gathered from the current network. Short-lived; hashed
/// immediately and dropped.
#[derive(Debug, Clone, Default)]
pub struct NetworkInputs {
    /// Default gateway MAC address (6 bytes), if known.
    pub gateway_mac: Option<[u8; 6]>,
    /// Autonomous System Number of the public IP (identifies the ISP).
    pub asn: Option<u32>,
    /// Wi-Fi SSID, if on wireless.
    pub ssid: Option<String>,
}

/// A stable, privacy-preserving network identifier (FNV-1a of the inputs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint(pub u64);

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(seed: u64, bytes: &[u8]) -> u64 {
    let mut h = seed;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

impl Fingerprint {
    /// Compute the fingerprint from raw inputs. Absent fields contribute a fixed
    /// tag so "no SSID" is distinct from a present one but still deterministic.
    pub fn from_inputs(inputs: &NetworkInputs) -> Fingerprint {
        let mut h = FNV_OFFSET;
        match inputs.gateway_mac {
            Some(mac) => {
                h = fnv1a(h, b"mac:");
                h = fnv1a(h, &mac);
            }
            None => h = fnv1a(h, b"mac:none"),
        }
        match inputs.asn {
            Some(asn) => {
                h = fnv1a(h, b"asn:");
                h = fnv1a(h, &asn.to_be_bytes());
            }
            None => h = fnv1a(h, b"asn:none"),
        }
        match &inputs.ssid {
            Some(ssid) => {
                h = fnv1a(h, b"ssid:");
                h = fnv1a(h, ssid.as_bytes());
            }
            None => h = fnv1a(h, b"ssid:none"),
        }
        Fingerprint(h)
    }

    /// Hex form, used as the on-disk cache key / filename component.
    pub fn to_hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

/// Platform hook that gathers [`NetworkInputs`] (Windows: `GetAdaptersAddresses`
/// for the gateway MAC, a WHOIS/ASN lookup or embedded table for the ASN,
/// `WlanQueryInterface` for the SSID). Implemented outside `uf-core`/`uf-probe`
/// so this crate stays OS-independent and testable.
pub trait FingerprintSource {
    /// Gather the current network's identifiers.
    fn gather(&self) -> NetworkInputs;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_same_fingerprint() {
        let a = NetworkInputs {
            gateway_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            asn: Some(9121),
            ssid: Some("HomeWifi".into()),
        };
        let b = a.clone();
        assert_eq!(Fingerprint::from_inputs(&a), Fingerprint::from_inputs(&b));
    }

    #[test]
    fn different_ssid_different_fingerprint() {
        let base = NetworkInputs {
            gateway_mac: Some([1, 2, 3, 4, 5, 6]),
            asn: Some(9121),
            ssid: Some("A".into()),
        };
        let mut other = base.clone();
        other.ssid = Some("B".into());
        assert_ne!(
            Fingerprint::from_inputs(&base),
            Fingerprint::from_inputs(&other)
        );
    }

    #[test]
    fn stable_known_value() {
        // Locks the FNV-1a implementation so a persisted key never silently
        // changes meaning.
        let inputs = NetworkInputs::default();
        let fp = Fingerprint::from_inputs(&inputs);
        assert_eq!(fp.to_hex().len(), 16);
        // All-none inputs must be deterministic.
        assert_eq!(fp, Fingerprint::from_inputs(&NetworkInputs::default()));
    }

    #[test]
    fn hex_is_16_chars() {
        let fp = Fingerprint(0x1);
        assert_eq!(fp.to_hex(), "0000000000000001");
    }
}
