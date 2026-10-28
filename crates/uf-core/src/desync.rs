//! The desync applier: turns a [`StrategySpec`] (a list of [`DesyncAction`]s)
//! into the concrete packets the engine injects for a flow's opening segment.
//!
//! This is the phase-2 piece the earlier phases left as data behind the
//! [`Strategy`] trait. The techniques are the standard client-side set used by
//! open tools such as GoodbyeDPI and zapret: they reshape *this host's own*
//! outbound TLS/HTTP handshake so a censorship middlebox fails to match it,
//! while the destination server still receives a valid byte stream. They never
//! touch any server or anyone else's traffic.
//!
//! Design split for testability:
//! - [`plan`] is pure: `(payload, classification, actions) → `[`DesyncPlan`].
//!   It decides *what* bytes go in which segment and which fakes precede them.
//!   Every reshape of the real data preserves the byte stream the server sees
//!   (concatenating the real segments in sequence-number order reproduces the
//!   original payload), so a server behind no DPI is unaffected.
//! - [`DataStrategy`] wraps `plan` with packet reconstruction (sequence
//!   numbers, lengths, TTL, checksums) and drives the [`Emitter`].
//!
//! Scope (v1): TCP flows (TLS 443, HTTP 80). The applier only acts on the first
//! payload-bearing segment of a flow; later segments pass through. UDP/QUIC
//! desync (a produced fake QUIC Initial) is out of this applier.

use crate::action::{DesyncAction, FakeKind, Fooling, SplitPos, TtlSpec};
use crate::classify::Classification;
use crate::net::TcpPacket;
use crate::strategy::{Emitter, FlowCtx, Strategy, StrategyId, StrategySpec, Verdict};

/// Default hop count assumed for an [`TtlSpec::Auto`] fake until the live prober
/// measures the real distance to the DPI. Kept low so the fake dies well before
/// a typical server.
pub const DEFAULT_AUTO_HOPS: u8 = 8;

/// How a single fake (decoy) packet should be built and sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeSpec {
    /// The fake's payload bytes.
    pub payload: Vec<u8>,
    /// TTL / hop limit to send it with (so it dies before the real server).
    pub ttl: u8,
    /// Fooling techniques to apply (currently `badsum` and `badseq`).
    pub fooling: Fooling,
}

/// One real-data segment: a slice of the original payload plus its offset from
/// the payload start (which becomes `base_seq + offset`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Offset of these bytes within the original payload.
    pub offset: usize,
    /// The bytes.
    pub data: Vec<u8>,
}

/// The output of planning: fakes to send first, then the real segments in send
/// order, plus optional TCP tweaks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesyncPlan {
    /// Decoy packets injected before the real data.
    pub fakes: Vec<FakeSpec>,
    /// Real-data segments, in the order they should be injected.
    pub segments: Vec<Segment>,
    /// Advertised window override, if any ([`DesyncAction::TcpWindowTrick`]).
    pub window: Option<u16>,
    /// Send the first real segment with the URG flag ([`DesyncAction::Oob`]).
    pub urgent: bool,
}

impl DesyncPlan {
    /// Whether this plan actually changes anything. A plan that is one segment
    /// at offset 0 with no fakes, window or urgent is a no-op; the engine then
    /// passes the original packet through unchanged.
    pub fn is_noop(&self) -> bool {
        self.fakes.is_empty()
            && self.window.is_none()
            && !self.urgent
            && matches!(self.segments.as_slice(), [s] if s.offset == 0)
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Resolve a [`SplitPos`] to a byte offset strictly inside `1..payload.len()`,
/// or `None` if it cannot be placed (the action is then skipped).
fn resolve_split(pos: SplitPos, payload: &[u8], cls: &Classification<'_>) -> Option<usize> {
    let len = payload.len();
    let clamp = |o: usize| if o >= 1 && o < len { Some(o) } else { None };
    match pos {
        SplitPos::Offset(o) => clamp(o as usize),
        SplitPos::SniStart => {
            let name = cls.server_name()?;
            clamp(find(payload, name.as_bytes())?)
        }
        SplitPos::SniMid => {
            let name = cls.server_name()?;
            let at = find(payload, name.as_bytes())?;
            clamp(at + name.len() / 2)
        }
        SplitPos::HostHeader => {
            // Just after the "Host:" field name, case-insensitively.
            let lower: Vec<u8> = payload.iter().map(u8::to_ascii_lowercase).collect();
            let at = find(&lower, b"host:")?;
            clamp(at + 5)
        }
    }
}

/// Split a TLS record at `at` bytes into its fragment into two records of the
/// same type and version (record-layer split, independent of TCP). Returns the
/// rebuilt payload, or `None` if the payload is not a single TLS record that can
/// be split there.
fn tls_record_split(payload: &[u8], at: usize) -> Option<Vec<u8>> {
    if payload.len() < 5 {
        return None;
    }
    let ctype = payload[0];
    let ver = [payload[1], payload[2]];
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let body = payload.get(5..5 + rec_len)?;
    if at == 0 || at >= body.len() {
        return None;
    }
    let (a, b) = body.split_at(at);
    let mut out = Vec::with_capacity(payload.len() + 5);
    let mut push = |frag: &[u8]| {
        out.push(ctype);
        out.extend_from_slice(&ver);
        out.extend_from_slice(&(frag.len() as u16).to_be_bytes());
        out.extend_from_slice(frag);
    };
    push(a);
    push(b);
    // Keep anything after the first record (rare for a ClientHello) verbatim.
    out.extend_from_slice(&payload[5 + rec_len..]);
    Some(out)
}

/// Mangle the case of the HTTP `Host` header name (`Host:` → `hOsT:`) so a DPI
/// matching the literal header misses it, while HTTP keeps header names
/// case-insensitive. Returns the rewritten payload if a Host header was found.
fn http_case_mangle(payload: &[u8]) -> Option<Vec<u8>> {
    let lower: Vec<u8> = payload.iter().map(u8::to_ascii_lowercase).collect();
    let at = find(&lower, b"host:")?;
    let mut out = payload.to_vec();
    for (i, b) in out[at..at + 4].iter_mut().enumerate() {
        *b = if i % 2 == 0 {
            b.to_ascii_uppercase()
        } else {
            b.to_ascii_lowercase()
        };
    }
    Some(out)
}

/// A small, fixed decoy ClientHello carrying an innocuous SNI, used by
/// [`FakeKind::TlsClientHelloFakeSni`]. Only the DPI is meant to see it.
fn fake_client_hello(decoy_sni: &[u8]) -> Vec<u8> {
    // SNI extension.
    let mut sni_list = vec![0u8];
    sni_list.extend_from_slice(&(decoy_sni.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(decoy_sni);
    let mut ext = Vec::new();
    ext.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
    ext.extend_from_slice(&((sni_list.len() + 2) as u16).to_be_bytes());
    ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni_list);
    // ClientHello body.
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0u8; 32]);
    body.push(0); // session id len
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
    body.extend_from_slice(&[0x01, 0x00]); // compression
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    // Handshake + record headers.
    let mut hs = vec![0x01];
    let l = body.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn fake_payload(kind: FakeKind, real_len: usize) -> Option<Vec<u8>> {
    match kind {
        FakeKind::TlsClientHelloFakeSni => Some(fake_client_hello(b"www.example.com")),
        FakeKind::HttpFake => Some(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n".to_vec()),
        // A block of bytes the size of the real segment, so the DPI sees a
        // plausible record length. Deterministic (no RNG on the hot path).
        FakeKind::Random => Some(vec![0x20u8; real_len.clamp(16, 512)]),
        // A fake QUIC Initial belongs on the UDP path, not this TCP applier.
        FakeKind::QuicInitialFake => None,
    }
}

fn resolve_ttl(ttl: TtlSpec) -> u8 {
    match ttl {
        TtlSpec::Fixed(n) => n.max(1),
        TtlSpec::Auto { delta } => (DEFAULT_AUTO_HOPS as i16 + delta as i16).clamp(1, 255) as u8,
    }
}

/// Plan the output for one payload. Pure and allocation-explicit so it can be
/// golden-tested without any packet machinery.
pub fn plan(payload: &[u8], cls: &Classification<'_>, actions: &[DesyncAction]) -> DesyncPlan {
    let mut plan = DesyncPlan::default();
    if payload.is_empty() {
        plan.segments.push(Segment {
            offset: 0,
            data: Vec::new(),
        });
        return plan;
    }

    // 1. Byte-level rewrites that change the payload itself, in order.
    let mut data = payload.to_vec();
    for a in actions {
        match a {
            DesyncAction::HttpCaseMangle => {
                if let Some(m) = http_case_mangle(&data) {
                    data = m;
                }
            }
            DesyncAction::TlsRecordSplit { at } => {
                if let Some(m) = tls_record_split(&data, *at as usize) {
                    data = m;
                }
            }
            _ => {}
        }
    }

    // 2. Collect TCP split boundaries (resolved against the *rewritten* data).
    let mut cuts: Vec<usize> = Vec::new();
    let mut disorder = false;
    for a in actions {
        match a {
            DesyncAction::Split { at } => {
                if let Some(o) = resolve_split(*at, &data, cls) {
                    cuts.push(o);
                }
            }
            DesyncAction::Disorder => {
                // Disorder implies a split; if none was given, cut in the middle.
                disorder = true;
            }
            DesyncAction::TcpWindowTrick { window } => plan.window = Some(*window),
            DesyncAction::Oob => plan.urgent = true,
            _ => {}
        }
    }
    if disorder && cuts.is_empty() && data.len() >= 2 {
        cuts.push(data.len() / 2);
    }
    cuts.retain(|&o| o >= 1 && o < data.len());
    cuts.sort_unstable();
    cuts.dedup();

    // 3. Build contiguous segments from the cut points.
    let mut bounds = vec![0usize];
    bounds.extend_from_slice(&cuts);
    bounds.push(data.len());
    for w in bounds.windows(2) {
        plan.segments.push(Segment {
            offset: w[0],
            data: data[w[0]..w[1]].to_vec(),
        });
    }
    if disorder {
        plan.segments.reverse();
    }

    // 4. Fakes, emitted before the real data.
    for a in actions {
        if let DesyncAction::Fake { kind, ttl, fooling } = a {
            if let Some(p) = fake_payload(*kind, data.len()) {
                plan.fakes.push(FakeSpec {
                    payload: p,
                    ttl: resolve_ttl(*ttl),
                    fooling: *fooling,
                });
            }
        }
    }

    plan
}

/// A strategy built from a [`StrategySpec`], driving [`plan`] and reconstructing
/// packets. One instance per active strategy; cheap to clone.
#[derive(Debug, Clone)]
pub struct DataStrategy {
    id: StrategyId,
    actions: Vec<DesyncAction>,
}

impl DataStrategy {
    /// Build a strategy from its spec and id.
    pub fn new(id: StrategyId, spec: &StrategySpec) -> Self {
        DataStrategy {
            id,
            actions: spec.actions.clone(),
        }
    }

    /// The actions this strategy applies.
    pub fn actions(&self) -> &[DesyncAction] {
        &self.actions
    }
}

impl Strategy for DataStrategy {
    fn id(&self) -> StrategyId {
        self.id
    }

    fn apply(&self, ctx: &FlowCtx<'_>, packet: &[u8], out: &mut Emitter) -> Verdict {
        // Only the first payload-bearing segment of a flow is reshaped.
        if ctx.payload_index != 0 {
            return Verdict::Pass;
        }
        let base = match TcpPacket::parse(packet) {
            Ok(p) => p,
            Err(_) => return Verdict::Pass, // not IPv4/IPv6 TCP: leave it alone
        };
        if base.payload().is_empty() {
            return Verdict::Pass;
        }

        let cls = crate::classify::classify(base.payload(), dst_port(&base, ctx));
        let p = plan(base.payload(), &cls, &self.actions);
        if p.is_noop() {
            return Verdict::Pass;
        }

        let base_seq = base.seq();
        out.reset();

        // Fakes first.
        for fake in &p.fakes {
            let mut fk = base.clone();
            fk.set_payload(&fake.payload);
            fk.set_ttl(fake.ttl);
            if fake.fooling.contains(Fooling::BADSEQ) {
                fk.set_seq(base_seq.wrapping_sub(0x1000_0000));
            }
            let mut meta = *ctx.meta;
            if fake.fooling.contains(Fooling::BADSUM) {
                fk.corrupt_tcp_checksum();
                // Keep the deliberately wrong checksum: tell the backend not to
                // repair it.
                meta.checksums_valid = true;
            } else {
                meta.checksums_valid = false;
            }
            if !out.emit(fk.bytes(), meta) {
                return Verdict::Pass; // emitter full: fail-open
            }
        }

        // Real segments, in planned order.
        for (i, seg) in p.segments.iter().enumerate() {
            let mut pk = base.clone();
            pk.set_payload(&seg.data);
            pk.set_seq(base_seq.wrapping_add(seg.offset as u32));
            if let Some(w) = p.window {
                pk.set_window(w);
            }
            if p.urgent && i == 0 {
                pk.set_urgent(seg.data.len() as u16);
            }
            let mut meta = *ctx.meta;
            meta.checksums_valid = false;
            if !out.emit(pk.bytes(), meta) {
                return Verdict::Pass;
            }
        }
        Verdict::Emitted
    }
}

/// Best-effort destination port for classification: derived from the TCP header
/// of the packet being processed. Falls back to 443.
fn dst_port(pkt: &TcpPacket, _ctx: &FlowCtx<'_>) -> u16 {
    let l = pkt.layout();
    let off = l.tcp_off() + 2;
    pkt.bytes()
        .get(off..off + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .filter(|&p| p != 0)
        .unwrap_or(443)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{FakeKind, TtlSpec};

    fn cls_for<'a>(payload: &'a [u8], port: u16) -> Classification<'a> {
        crate::classify::classify(payload, port)
    }

    #[test]
    fn empty_actions_is_noop() {
        let payload = b"hello";
        let p = plan(payload, &cls_for(payload, 443), &[]);
        assert!(p.is_noop());
        assert_eq!(p.segments.len(), 1);
    }

    #[test]
    fn split_at_offset_preserves_stream() {
        let payload = b"abcdefghij";
        let p = plan(
            payload,
            &cls_for(payload, 80),
            &[DesyncAction::Split {
                at: SplitPos::Offset(4),
            }],
        );
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.segments[0], seg(0, b"abcd"));
        assert_eq!(p.segments[1], seg(4, b"efghij"));
        assert_eq!(reassemble(&p), payload);
    }

    #[test]
    fn disorder_reverses_but_keeps_offsets() {
        let payload = b"abcdefghij";
        let p = plan(
            payload,
            &cls_for(payload, 80),
            &[
                DesyncAction::Split {
                    at: SplitPos::Offset(4),
                },
                DesyncAction::Disorder,
            ],
        );
        assert_eq!(p.segments[0], seg(4, b"efghij"));
        assert_eq!(p.segments[1], seg(0, b"abcd"));
        assert_eq!(reassemble(&p), payload);
    }

    #[test]
    fn disorder_alone_cuts_in_the_middle() {
        let payload = b"abcdef";
        let p = plan(payload, &cls_for(payload, 80), &[DesyncAction::Disorder]);
        assert_eq!(p.segments.len(), 2);
        assert_eq!(reassemble(&p), payload);
    }

    #[test]
    fn split_at_sni_mid_lands_inside_hostname() {
        // Build a real ClientHello for blocked.example and split at SNI mid.
        let ch = client_hello(b"blocked.example");
        let cls = cls_for(&ch, 443);
        assert_eq!(cls.sni, Some("blocked.example"));
        let p = plan(
            &ch,
            &cls,
            &[DesyncAction::Split {
                at: SplitPos::SniMid,
            }],
        );
        assert_eq!(p.segments.len(), 2);
        let cut = p.segments[1].offset;
        let host_at = find(&ch, b"blocked.example").unwrap();
        assert!(cut > host_at && cut < host_at + "blocked.example".len());
        assert_eq!(reassemble(&p), ch);
    }

    #[test]
    fn http_case_mangle_changes_host_case_only() {
        let payload = b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n";
        let p = plan(
            payload,
            &cls_for(payload, 80),
            &[DesyncAction::HttpCaseMangle],
        );
        let out = reassemble(&p);
        assert_eq!(out.len(), payload.len());
        // The header name is no longer the literal "Host" a DPI matches, but is
        // still a case-insensitive "host".
        assert!(!out.windows(4).any(|w| w == b"Host"));
        let name_at = find(&out, b": a.example").unwrap() - 4;
        assert!(out[name_at..name_at + 4].eq_ignore_ascii_case(b"host"));
        // Everything except the header name is unchanged.
        assert!(out.windows(9).any(|w| w == b"a.example"));
    }

    #[test]
    fn tls_record_split_produces_two_records() {
        // One TLS record with a 10-byte body.
        let mut rec = vec![0x16, 0x03, 0x01, 0x00, 0x0A];
        rec.extend_from_slice(b"0123456789");
        let p = plan(
            &rec,
            &cls_for(&rec, 443),
            &[DesyncAction::TlsRecordSplit { at: 4 }],
        );
        let out = reassemble(&p);
        // Two records: header(5)+4 then header(5)+6.
        assert_eq!(out.len(), 5 + 4 + 5 + 6);
        assert_eq!(&out[0..3], &[0x16, 0x03, 0x01]);
        assert_eq!(u16::from_be_bytes([out[3], out[4]]), 4);
        // Second record header starts at 5 + 4 = 9; its length field at 12..14.
        assert_eq!(&out[9..12], &[0x16, 0x03, 0x01]);
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 6);
    }

    #[test]
    fn fake_badsum_is_planned_with_low_ttl() {
        let payload = b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n";
        let p = plan(
            payload,
            &cls_for(payload, 80),
            &[DesyncAction::Fake {
                kind: FakeKind::HttpFake,
                ttl: TtlSpec::Fixed(4),
                fooling: Fooling::BADSUM,
            }],
        );
        assert_eq!(p.fakes.len(), 1);
        assert_eq!(p.fakes[0].ttl, 4);
        assert!(p.fakes[0].fooling.contains(Fooling::BADSUM));
        assert!(p.fakes[0].payload.starts_with(b"GET "));
    }

    #[test]
    fn quic_fake_is_skipped_on_tcp_path() {
        let payload = b"data";
        let p = plan(
            payload,
            &cls_for(payload, 443),
            &[DesyncAction::Fake {
                kind: FakeKind::QuicInitialFake,
                ttl: TtlSpec::Fixed(4),
                fooling: Fooling::NONE,
            }],
        );
        assert!(p.fakes.is_empty());
    }

    #[test]
    fn window_and_oob_recorded() {
        let payload = b"abcdef";
        let p = plan(
            payload,
            &cls_for(payload, 443),
            &[
                DesyncAction::TcpWindowTrick { window: 4 },
                DesyncAction::Oob,
            ],
        );
        assert_eq!(p.window, Some(4));
        assert!(p.urgent);
        assert!(!p.is_noop());
    }

    // --- helpers ---

    fn seg(offset: usize, data: &[u8]) -> Segment {
        Segment {
            offset,
            data: data.to_vec(),
        }
    }

    fn reassemble(p: &DesyncPlan) -> Vec<u8> {
        let mut segs = p.segments.clone();
        segs.sort_by_key(|s| s.offset);
        let mut out = Vec::new();
        for s in segs {
            out.extend_from_slice(&s.data);
        }
        out
    }

    fn client_hello(host: &[u8]) -> Vec<u8> {
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
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }
}
