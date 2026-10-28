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

/// Aktif strateji: akışın ilk veri paketi split+disorder ile yeniden yazılıyor,
/// enjekte edilen segmentler sıra numarasına göre birleştirilince özgün
/// yük bit-bit geri geliyor (sunucunun gördüğü akış değişmiyor). Sonraki
/// paketler ve TCP olmayan trafik aynen geçiyor (fail-open).
#[test]
fn active_strategy_rewrites_first_segment_and_preserves_stream() {
    use uf_core::action::{DesyncAction, SplitPos};
    use uf_core::{DataStrategy, StrategyId, StrategySpec, TcpPacket};

    // IPv4 TCP paketi kur (20+20 başlık) verilen yük ile.
    fn v4(seq: u32, payload: &[u8]) -> Vec<u8> {
        let total = 40 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&[192, 168, 1, 2]);
        p[16..20].copy_from_slice(&[93, 184, 216, 34]);
        p[20..22].copy_from_slice(&0xC000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[32] = 0x50;
        p[33] = 0x18; // PSH|ACK
        p[34..36].copy_from_slice(&64240u16.to_be_bytes());
        p[40..].copy_from_slice(payload);
        p
    }

    let payload: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let first = v4(1000, payload);
    let second = v4(1000 + payload.len() as u32, b"second-data-passes-through");

    let mut io = MockPacketIO::new();
    io.push_inbound(first.clone(), PacketMeta::outbound(7));
    io.push_inbound(second.clone(), PacketMeta::outbound(7));

    let spec = StrategySpec {
        name: "split+disorder".into(),
        actions: vec![
            DesyncAction::Split {
                at: SplitPos::Offset(5),
            },
            DesyncAction::Disorder,
        ],
    };
    let mut engine = Engine::new(io);
    engine.set_strategy(Some(Box::new(DataStrategy::new(StrategyId(0), &spec))));
    engine.run();
    let io = engine.into_io();

    // İlk paket iki segmente bölündü (ters sırada), ikinci paket aynen geçti.
    assert_eq!(io.sent.len(), 3);

    // Yeniden yazılan segmentleri ayrıştır, SEQ'e göre birleştir.
    let mut rebuilt: Vec<(u32, Vec<u8>)> = Vec::new();
    for (bytes, _meta) in &io.sent[..2] {
        let p = TcpPacket::parse(bytes).unwrap();
        assert_eq!(p.ttl(), 64);
        rebuilt.push((p.seq(), p.payload().to_vec()));
    }
    rebuilt.sort_by_key(|(s, _)| *s);
    let mut stream = Vec::new();
    for (_, data) in &rebuilt {
        stream.extend_from_slice(data);
    }
    assert_eq!(
        stream, payload,
        "birleştirilen akış özgün yükle aynı olmalı"
    );

    // Segmentlerin SEQ'leri doğru.
    assert_eq!(rebuilt[0].0, 1000);
    assert_eq!(rebuilt[1].0, 1005);

    // İkinci (sonraki) paket değişmeden geçti.
    assert_eq!(&io.sent[2].0, &second);
}
