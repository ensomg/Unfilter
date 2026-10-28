//! Flow table: a fixed-capacity, TTL'd LRU keyed on the connection 5-tuple.
//!
//! Sized once at start-up (default 65 536 entries). When full, the
//! least-recently-used entry is evicted; an evicted flow simply restarts in the
//! [`Observe`](FlowPhase::Observe) phase, so the worst case is that one flow
//! misses its bypass — traffic still passes.

use std::collections::HashMap;
use std::net::IpAddr;

/// Default maximum number of tracked flows (master prompt §3).
pub const DEFAULT_CAPACITY: usize = 65_536;

/// Transport protocol of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// TCP (ports 80/443 in v1).
    Tcp,
    /// UDP (443 for QUIC, 53 for DNS, Discord voice range).
    Udp,
}

/// Connection identity: source and destination address/port plus protocol.
///
/// Works for both IPv4 and IPv6 via [`IpAddr`]. Hashable so it can key the
/// table directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Transport protocol.
    pub protocol: Protocol,
    /// Local address.
    pub src_ip: IpAddr,
    /// Remote address.
    pub dst_ip: IpAddr,
    /// Local port.
    pub src_port: u16,
    /// Remote port.
    pub dst_port: u16,
}

/// Where a flow is in the `Observe → Classify → Apply → Verify` state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowPhase {
    /// Waiting for the first L7 payload (ClientHello / request line / Initial).
    Observe,
    /// Payload seen; deciding whether the target is blocked and which strategy.
    Classify,
    /// A strategy is actively rewriting this flow's packets.
    Apply,
    /// Watching the server's response to confirm the bypass worked.
    Verify,
    /// Terminal: pass every packet through untouched (unblocked or given up).
    Pass,
}

/// Per-flow state stored in the table.
#[derive(Debug, Clone)]
pub struct FlowEntry {
    /// Current phase.
    pub phase: FlowPhase,
    /// Strategy chosen for this flow, if any (index into the active strategy set).
    pub strategy: Option<u16>,
    /// Count of payload-bearing packets seen (classification happens on the first).
    pub payload_packets: u32,
    /// Last time this flow was touched, in the table clock's nanoseconds.
    pub last_seen_nanos: u64,
}

impl FlowEntry {
    fn fresh(now: u64) -> Self {
        FlowEntry {
            phase: FlowPhase::Observe,
            strategy: None,
            payload_packets: 0,
            last_seen_nanos: now,
        }
    }
}

/// A monotonic clock, abstracted so tests can drive time deterministically.
pub trait Clock {
    /// Nanoseconds since an arbitrary fixed epoch. Must be monotonic.
    fn now_nanos(&self) -> u64;
}

/// Fixed-capacity flow table with TTL-based expiry and LRU eviction.
///
/// Phase 0 uses a `HashMap` plus a scalar LRU scan on eviction to lock in the
/// public API and semantics; phase 1 replaces the internals with an
/// open-addressed table and an intrusive LRU list (ADR-referenced) without
/// changing this surface.
pub struct FlowTable {
    map: HashMap<FlowKey, FlowEntry>,
    capacity: usize,
    ttl_nanos: u64,
}

impl FlowTable {
    /// Create a table holding at most `capacity` flows, expiring entries idle
    /// for longer than `ttl_nanos`.
    pub fn new(capacity: usize, ttl_nanos: u64) -> Self {
        FlowTable {
            map: HashMap::with_capacity(capacity),
            capacity,
            ttl_nanos,
        }
    }

    /// Number of live flows.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Look up a flow, refreshing its last-seen time.
    pub fn get_mut(&mut self, key: &FlowKey, now: u64) -> Option<&mut FlowEntry> {
        if let Some(entry) = self.map.get_mut(key) {
            entry.last_seen_nanos = now;
            Some(entry)
        } else {
            None
        }
    }

    /// Get the entry for `key`, inserting a fresh [`Observe`](FlowPhase::Observe)
    /// flow if absent. Evicts the least-recently-used flow first if full.
    pub fn get_or_insert(&mut self, key: FlowKey, now: u64) -> &mut FlowEntry {
        if !self.map.contains_key(&key) {
            if self.map.len() >= self.capacity {
                self.evict_lru();
            }
            self.map.insert(key, FlowEntry::fresh(now));
        }
        let entry = self.map.get_mut(&key).expect("just inserted");
        entry.last_seen_nanos = now;
        entry
    }

    /// Drop every flow idle for longer than the TTL. Called periodically off the
    /// hot path.
    pub fn expire(&mut self, now: u64) {
        let ttl = self.ttl_nanos;
        self.map
            .retain(|_, e| now.saturating_sub(e.last_seen_nanos) <= ttl);
    }

    fn evict_lru(&mut self) {
        if let Some(oldest) = self
            .map
            .iter()
            .min_by_key(|(_, e)| e.last_seen_nanos)
            .map(|(k, _)| *k)
        {
            self.map.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(dst_port: u16) -> FlowKey {
        FlowKey {
            protocol: Protocol::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            src_port: 50000,
            dst_port,
        }
    }

    #[test]
    fn insert_and_lookup() {
        let mut t = FlowTable::new(4, 1_000);
        let e = t.get_or_insert(key(443), 10);
        assert_eq!(e.phase, FlowPhase::Observe);
        e.phase = FlowPhase::Apply;
        assert_eq!(t.get_mut(&key(443), 20).unwrap().phase, FlowPhase::Apply);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn evicts_least_recently_used_when_full() {
        let mut t = FlowTable::new(2, 1_000_000);
        t.get_or_insert(key(1), 10);
        t.get_or_insert(key(2), 20);
        // Touch key(1) so key(2) is now the LRU.
        t.get_mut(&key(1), 30);
        t.get_or_insert(key(3), 40); // forces eviction of key(2)
        assert_eq!(t.len(), 2);
        assert!(t.get_mut(&key(2), 50).is_none());
        assert!(t.get_mut(&key(1), 50).is_some());
        assert!(t.get_mut(&key(3), 50).is_some());
    }

    #[test]
    fn expire_drops_idle_flows() {
        let mut t = FlowTable::new(8, 100);
        t.get_or_insert(key(1), 0);
        t.get_or_insert(key(2), 90);
        t.expire(150); // key(1) idle 150 > 100, key(2) idle 60 <= 100
        assert!(t.get_mut(&key(1), 160).is_none());
        assert!(t.get_mut(&key(2), 160).is_some());
    }
}
