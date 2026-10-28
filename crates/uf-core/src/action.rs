//! Desync actions — the data model for the evasion techniques the engine can
//! apply to a flow.
//!
//! These types are pure *data*: a strategy is a list of [`DesyncAction`]s loaded
//! from config (JSON/TOML), never hard-coded. Adding a technique means adding a
//! variant here and a match arm in the phase-2 applier — the engine itself does
//! not change (master prompt §3, §4).
//!
//! The techniques are the standard client-side set used by open tools such as
//! GoodbyeDPI and zapret: they reshape *this host's own outbound handshake* so a
//! censorship middlebox fails to match it, while the destination server still
//! receives a valid stream. They do not attack any server.

use serde::{Deserialize, Serialize};

/// Where to cut a ClientHello / HTTP request when splitting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitPos {
    /// A fixed byte offset from the start of the TLS record payload.
    Offset(u16),
    /// The middle of the SNI value (splits the hostname the DPI matches on).
    SniMid,
    /// Just before the SNI value starts.
    SniStart,
    /// After the HTTP `Host:` header name (for plain HTTP).
    HostHeader,
}

/// Time-to-live for an injected fake packet.
///
/// A fake packet is crafted to reach the ISP's DPI box but *not* the real
/// server: the DPI acts on it and desynchronises, while the server never sees it
/// (or discards it as invalid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtlSpec {
    /// A fixed hop count.
    Fixed(u8),
    /// Automatically chosen as `hops_to_dpi + delta`, discovered by probing,
    /// so the fake dies between the DPI and the server.
    Auto {
        /// Hops added to the measured distance to the DPI.
        delta: i8,
    },
}

/// What kind of fake packet to inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FakeKind {
    /// A TLS ClientHello carrying a decoy SNI (e.g. a permitted domain).
    TlsClientHelloFakeSni,
    /// A fake plain-HTTP request.
    HttpFake,
    /// A fake QUIC Initial.
    QuicInitialFake,
    /// Random padding bytes.
    Random,
}

/// Techniques that make an injected fake packet look valid to the DPI but get
/// dropped before or by the real server. Represented as a bitset so several can
/// combine. Serialises as an array of names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fooling(u8);

impl Fooling {
    /// No fooling technique.
    pub const NONE: Fooling = Fooling(0);
    /// Invalid TCP/IP checksum: the server drops it, the DPI (often not
    /// re-checking) does not.
    pub const BADSUM: Fooling = Fooling(1 << 0);
    /// Out-of-window sequence number.
    pub const BADSEQ: Fooling = Fooling(1 << 1);
    /// A bogus TCP MD5 signature option.
    pub const MD5SIG: Fooling = Fooling(1 << 2);
    /// Payload sent without the ACK flag.
    pub const DATANOACK: Fooling = Fooling(1 << 3);
    /// Decrement the TCP timestamp option.
    pub const TS_DECREMENT: Fooling = Fooling(1 << 4);

    /// Whether `other`'s bits are all set in `self`.
    pub fn contains(self, other: Fooling) -> bool {
        (self.0 & other.0) == other.0
    }

    /// The union of two sets.
    pub fn union(self, other: Fooling) -> Fooling {
        Fooling(self.0 | other.0)
    }

    /// Raw bits (for tests and golden comparisons).
    pub fn bits(self) -> u8 {
        self.0
    }
}

impl core::ops::BitOr for Fooling {
    type Output = Fooling;
    fn bitor(self, rhs: Fooling) -> Fooling {
        self.union(rhs)
    }
}

// Serialises as a list of lowercase technique names, e.g. ["badsum","badseq"].
const FOOLING_NAMES: [(Fooling, &str); 5] = [
    (Fooling::BADSUM, "badsum"),
    (Fooling::BADSEQ, "badseq"),
    (Fooling::MD5SIG, "md5sig"),
    (Fooling::DATANOACK, "datanoack"),
    (Fooling::TS_DECREMENT, "ts_decrement"),
];

impl Serialize for Fooling {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let count = FOOLING_NAMES
            .iter()
            .filter(|(f, _)| self.contains(*f))
            .count();
        let mut seq = s.serialize_seq(Some(count))?;
        for (flag, name) in FOOLING_NAMES {
            if self.contains(flag) {
                seq.serialize_element(name)?;
            }
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Fooling {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Fooling, D::Error> {
        let names: Vec<String> = Vec::deserialize(d)?;
        let mut acc = Fooling::NONE;
        for name in names {
            let found = FOOLING_NAMES
                .iter()
                .find(|(_, n)| *n == name)
                .map(|(f, _)| *f)
                .ok_or_else(|| serde::de::Error::custom(format!("unknown fooling: {name}")))?;
            acc = acc.union(found);
        }
        Ok(acc)
    }
}

/// One desync action. A [`StrategySpec`](crate::strategy::StrategySpec) is an
/// ordered list of these, applied in sequence to a flow's handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DesyncAction {
    /// Split the ClientHello / request into pieces at the given position.
    Split {
        /// Where to cut.
        at: SplitPos,
    },
    /// Send already-split pieces in reverse order.
    Disorder,
    /// Inject a fake packet before the real one.
    Fake {
        /// What the fake packet contains.
        kind: FakeKind,
        /// TTL so the fake dies before the real server.
        ttl: TtlSpec,
        /// Techniques that invalidate the fake for the server but not the DPI.
        #[serde(default)]
        fooling: Fooling,
    },
    /// Send one byte out-of-band (TCP urgent pointer).
    Oob,
    /// Split at the TLS *record* layer, independent of TCP segmentation.
    TlsRecordSplit {
        /// Record-payload offset to split at.
        at: u16,
    },
    /// Advertise a small TCP window to force the peer into small segments.
    TcpWindowTrick {
        /// Window size to advertise.
        window: u16,
    },
    /// Vary the case / whitespace / line endings of the HTTP `Host` header.
    HttpCaseMangle,
    /// Detect and drop fake RST/redirect packets the ISP's DPI injects, by
    /// their TTL / IP-ID anomaly relative to the real server's packets.
    DropRstFromDpi,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fooling_bitset() {
        let f = Fooling::BADSUM | Fooling::BADSEQ;
        assert!(f.contains(Fooling::BADSUM));
        assert!(f.contains(Fooling::BADSEQ));
        assert!(!f.contains(Fooling::MD5SIG));
        assert_eq!(f.bits(), 0b11);
    }

    #[test]
    fn fooling_serde_is_name_list() {
        let f = Fooling::BADSUM | Fooling::TS_DECREMENT;
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"["badsum","ts_decrement"]"#);
        let back: Fooling = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn action_tagged_roundtrip() {
        let actions = vec![
            DesyncAction::Split {
                at: SplitPos::SniMid,
            },
            DesyncAction::Disorder,
            DesyncAction::Fake {
                kind: FakeKind::TlsClientHelloFakeSni,
                ttl: TtlSpec::Auto { delta: -1 },
                fooling: Fooling::BADSUM,
            },
            DesyncAction::DropRstFromDpi,
        ];
        let json = serde_json::to_string(&actions).unwrap();
        let back: Vec<DesyncAction> = serde_json::from_str(&json).unwrap();
        assert_eq!(actions, back);
    }

    #[test]
    fn fake_fooling_defaults_to_none() {
        let json = r#"{"action":"fake","kind":"http_fake","ttl":{"fixed":4}}"#;
        let a: DesyncAction = serde_json::from_str(json).unwrap();
        match a {
            DesyncAction::Fake { fooling, .. } => assert_eq!(fooling, Fooling::NONE),
            _ => panic!("expected fake"),
        }
    }
}
