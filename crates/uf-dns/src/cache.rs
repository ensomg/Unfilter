//! A small in-memory DNS cache with TTL and negative (NXDOMAIN) caching.
//!
//! Keyed on `(name, qtype)`. Positive entries expire at the answer's min TTL;
//! negative entries use a separate, shorter negative TTL. Time is supplied by
//! the caller (seconds from a monotonic clock) so it is deterministic in tests.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::message::QType;

/// A cached answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    /// Resolved addresses (empty for a negative entry).
    pub addrs: Vec<IpAddr>,
    /// Whether this is a negative (NXDOMAIN / empty) answer.
    pub negative: bool,
    /// Absolute expiry, in the cache clock's seconds.
    pub expires_at: u64,
}

/// Bounded DNS cache.
pub struct Cache {
    map: HashMap<(String, u16), CacheEntry>,
    capacity: usize,
    negative_ttl: u32,
}

impl Cache {
    /// A cache holding at most `capacity` entries, with `negative_ttl` seconds
    /// for negative answers.
    pub fn new(capacity: usize, negative_ttl: u32) -> Self {
        Cache {
            map: HashMap::new(),
            capacity,
            negative_ttl,
        }
    }

    fn key(name: &str, qtype: QType) -> (String, u16) {
        (name.to_ascii_lowercase(), qtype.code())
    }

    /// Look up a live entry. Expired entries are removed and reported as a miss.
    pub fn get(&mut self, name: &str, qtype: QType, now: u64) -> Option<&CacheEntry> {
        let key = Self::key(name, qtype);
        if let Some(e) = self.map.get(&key) {
            if e.expires_at <= now {
                self.map.remove(&key);
                return None;
            }
            return self.map.get(&key);
        }
        None
    }

    /// Insert a positive answer, expiring `ttl` seconds from `now`.
    pub fn put_positive(
        &mut self,
        name: &str,
        qtype: QType,
        addrs: Vec<IpAddr>,
        ttl: u32,
        now: u64,
    ) {
        self.insert(
            name,
            qtype,
            CacheEntry {
                addrs,
                negative: false,
                expires_at: now + ttl as u64,
            },
        );
    }

    /// Insert a negative (NXDOMAIN / empty) answer using the negative TTL.
    pub fn put_negative(&mut self, name: &str, qtype: QType, now: u64) {
        self.insert(
            name,
            qtype,
            CacheEntry {
                addrs: Vec::new(),
                negative: true,
                expires_at: now + self.negative_ttl as u64,
            },
        );
    }

    fn insert(&mut self, name: &str, qtype: QType, entry: CacheEntry) {
        if self.map.len() >= self.capacity && !self.map.contains_key(&Self::key(name, qtype)) {
            self.evict_soonest();
        }
        self.map.insert(Self::key(name, qtype), entry);
    }

    fn evict_soonest(&mut self) {
        if let Some(k) = self
            .map
            .iter()
            .min_by_key(|(_, e)| e.expires_at)
            .map(|(k, _)| k.clone())
        {
            self.map.remove(&k);
        }
    }

    /// Number of entries currently stored (including not-yet-pruned expired).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn hit_then_expire() {
        let mut c = Cache::new(16, 30);
        c.put_positive("example.com", QType::A, vec![ip("1.2.3.4")], 100, 1000);
        assert_eq!(
            c.get("example.com", QType::A, 1050).unwrap().addrs,
            vec![ip("1.2.3.4")]
        );
        // At expiry it is a miss and gets pruned.
        assert!(c.get("example.com", QType::A, 1100).is_none());
        assert!(c.is_empty());
    }

    #[test]
    fn case_insensitive_key() {
        let mut c = Cache::new(16, 30);
        c.put_positive("Example.COM", QType::A, vec![ip("1.1.1.1")], 100, 0);
        assert!(c.get("example.com", QType::A, 10).is_some());
    }

    #[test]
    fn negative_uses_negative_ttl() {
        let mut c = Cache::new(16, 30);
        c.put_negative("nope.example", QType::A, 0);
        assert!(c.get("nope.example", QType::A, 29).unwrap().negative);
        assert!(c.get("nope.example", QType::A, 31).is_none());
    }

    #[test]
    fn evicts_when_full() {
        let mut c = Cache::new(2, 30);
        c.put_positive("a.example", QType::A, vec![ip("1.1.1.1")], 10, 0);
        c.put_positive("b.example", QType::A, vec![ip("2.2.2.2")], 100, 0);
        c.put_positive("c.example", QType::A, vec![ip("3.3.3.3")], 100, 0);
        // a.example had the soonest expiry and should be gone.
        assert_eq!(c.len(), 2);
        assert!(c.get("a.example", QType::A, 1).is_none());
        assert!(c.get("c.example", QType::A, 1).is_some());
    }
}
