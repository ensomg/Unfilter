//! Test helpers: an in-memory [`PacketIO`] so the engine can be exercised with
//! no OS backend. Available to other crates via the `testing` feature.

use crate::error::{Error, Result};
use crate::io::{PacketBuf, PacketIO, PacketMeta};
use std::collections::VecDeque;

/// A [`PacketIO`] backed by two in-memory queues: packets queued on `inbox` are
/// handed to the engine via `recv`, and everything the engine injects lands in
/// `sent` for inspection.
pub struct MockPacketIO {
    inbox: VecDeque<(Vec<u8>, PacketMeta)>,
    /// Every packet the engine injected, in order.
    pub sent: Vec<(Vec<u8>, PacketMeta)>,
    shutdown: bool,
}

impl Default for MockPacketIO {
    fn default() -> Self {
        MockPacketIO::new()
    }
}

impl MockPacketIO {
    /// An empty mock.
    pub fn new() -> Self {
        MockPacketIO {
            inbox: VecDeque::new(),
            sent: Vec::new(),
            shutdown: false,
        }
    }

    /// Queue a packet to be delivered to the engine.
    pub fn push_inbound(&mut self, bytes: Vec<u8>, meta: PacketMeta) {
        self.inbox.push_back((bytes, meta));
    }
}

impl PacketIO for MockPacketIO {
    fn recv(&mut self, buf: &mut PacketBuf) -> Result<PacketMeta> {
        match self.inbox.pop_front() {
            Some((bytes, meta)) => {
                buf.set(&bytes)?;
                Ok(meta)
            }
            None => {
                self.shutdown = true;
                Err(Error::Shutdown)
            }
        }
    }

    fn send(&mut self, pkt: &[u8], meta: &PacketMeta) -> Result<()> {
        self.sent.push((pkt.to_vec(), *meta));
        Ok(())
    }

    fn shutdown(&mut self) {
        self.shutdown = true;
        self.inbox.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::io::{Direction, MAX_PACKET};

    // Small deterministic PRNG (xorshift64*) so the passthrough test needs no
    // external rand dependency.
    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn fill(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                *b = (self.next_u64() & 0xFF) as u8;
            }
        }
    }

    #[test]
    fn passthrough_is_bit_for_bit_identical() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut io = MockPacketIO::new();

        let mut expected: Vec<Vec<u8>> = Vec::new();
        for _ in 0..1000 {
            // 1..=MAX_PACKET random bytes.
            let len = 1 + (rng.next_u64() as usize % MAX_PACKET);
            let mut bytes = vec![0u8; len];
            rng.fill(&mut bytes);
            expected.push(bytes.clone());
            io.push_inbound(bytes, PacketMeta::outbound(7));
        }

        let mut engine = Engine::new(io);
        engine.run();
        let io = engine.into_io();

        assert_eq!(io.sent.len(), expected.len());
        for (i, (sent, exp)) in io.sent.iter().zip(expected.iter()).enumerate() {
            assert_eq!(&sent.0, exp, "packet {i} differs");
            assert_eq!(sent.1.direction, Direction::Outbound);
            assert_eq!(sent.1.if_index, 7);
        }
    }

    #[test]
    fn stats_count_passthrough() {
        let mut io = MockPacketIO::new();
        io.push_inbound(vec![1, 2, 3], PacketMeta::outbound(1));
        io.push_inbound(vec![4, 5], PacketMeta::outbound(1));
        let mut engine = Engine::new(io);
        engine.run();
        let s = engine.stats();
        assert_eq!(s.seen, 2);
        assert_eq!(s.passed, 2);
        assert_eq!(s.failed_open, 0);
        assert_eq!(s.rewritten, 0);
    }
}
