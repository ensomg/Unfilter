//! Motor sınırı entegrasyon iskelesi — passthrough + fail-open (master prompt
//! §6/§7, docs/perf-budget.md kısıt #10).
//!
//! `uf-core::testing::MockPacketIO` (feature `testing`) ile motoru OS backend'i
//! olmadan sürer. Faz 0'daki birim testi bit-bit passthrough'u motor *içinden*
//! doğrular; bu dosya aynı garantiyi dış (entegrasyon) sınırdan doğrular ve
//! backend düşünce döngünün temiz bittiğini (fail-open) ekler.
//!
//! Koşum: `cargo test -p uf-core --features testing`
//! (feature olmadan `cargo test --workspace` altında atlanır; bkz. Cargo.toml.)

use uf_core::testing::MockPacketIO;
use uf_core::{Direction, Engine, Error, PacketBuf, PacketIO, PacketMeta, Result};

/// Deterministik xorshift64* — harici `rand` bağımlılığı olmadan gövde üretimi.
struct Rng(u64);
impl Rng {
    fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            *b = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) & 0xFF) as u8;
        }
    }
}

/// Motorun enjekte ettiği baytlar, yakalananla bit-bit aynı ve meta korunuyor.
#[test]
fn passthrough_is_bit_for_bit_at_engine_boundary() {
    let mut rng = Rng(0xDEAD_BEEF_1234_5678);
    let mut io = MockPacketIO::new();

    let mut expected: Vec<Vec<u8>> = Vec::new();
    for i in 0..256 {
        let len = 1 + (i * 7) % 1400;
        let mut bytes = vec![0u8; len];
        rng.fill(&mut bytes);
        expected.push(bytes.clone());
        io.push_inbound(bytes, PacketMeta::outbound(42));
    }

    let mut engine = Engine::new(io);
    engine.run();
    let stats = engine.stats();
    let io = engine.into_io();

    assert_eq!(io.sent.len(), expected.len());
    for (i, (sent, exp)) in io.sent.iter().zip(&expected).enumerate() {
        assert_eq!(&sent.0, exp, "paket {i} bit-bit aynı değil");
        assert_eq!(sent.1.direction, Direction::Outbound);
        assert_eq!(sent.1.if_index, 42);
    }
    assert_eq!(stats.seen, expected.len() as u64);
    assert_eq!(stats.passed, expected.len() as u64);
    assert_eq!(stats.rewritten, 0);
    assert_eq!(stats.failed_open, 0);
}

/// Backend tükenince (recv → Shutdown) döngü temiz biter: panik yok, sayaçlar
/// tutarlı. Fail-open zincirinin "döngü temiz kapanır" ucu.
#[test]
fn backend_shutdown_ends_loop_cleanly() {
    let mut io = MockPacketIO::new();
    io.push_inbound(vec![1, 2, 3], PacketMeta::outbound(1));
    io.push_inbound(vec![4, 5, 6, 7], PacketMeta::outbound(1));

    let mut engine = Engine::new(io);
    engine.run(); // Shutdown gelince geri döner; sonsuz dönmez.
    let stats = engine.stats();
    assert_eq!(stats.seen, 2);
    assert_eq!(stats.passed, 2);
}

/// Enjeksiyon her pakette hata verse bile motor fail-open davranır: her paket
/// `failed_open` sayılır, döngü ilerler ve backend tükenince temiz biter —
/// hiçbir paket yeniden denenmez, panik olmaz.
#[test]
fn send_failure_fails_open_and_loop_ends() {
    /// recv `remaining` paket servis eder sonra Shutdown; send daima hata verir.
    struct FailingSink {
        remaining: u32,
    }
    impl PacketIO for FailingSink {
        fn recv(&mut self, buf: &mut PacketBuf) -> Result<PacketMeta> {
            if self.remaining == 0 {
                return Err(Error::Shutdown);
            }
            self.remaining -= 1;
            buf.set(&[0xAA, 0xBB, 0xCC]).unwrap();
            Ok(PacketMeta::outbound(9))
        }
        fn send(&mut self, _pkt: &[u8], _meta: &PacketMeta) -> Result<()> {
            // Geçici I/O hatası simülasyonu (ör. WinDivert send başarısız).
            Err(Error::Io(1))
        }
        fn shutdown(&mut self) {
            self.remaining = 0;
        }
    }

    let mut engine = Engine::new(FailingSink { remaining: 50 });
    engine.run();
    let stats = engine.stats();
    assert_eq!(stats.seen, 50);
    assert_eq!(stats.failed_open, 50);
    assert_eq!(stats.passed, 0);
    assert_eq!(stats.rewritten, 0);
}
