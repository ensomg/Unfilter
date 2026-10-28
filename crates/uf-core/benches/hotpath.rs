//! Hot-path mikro-benchmark'ları (criterion) — docs/perf-budget.md "Mikro-benchmark".
//!
//! Faz 8 kapsamı: bugün var olan sıfır-tahsisli hot-path ilkelleri ölçülür:
//!   - TLS ClientHello parse (SNI/ALPN/ECH)
//!   - HTTP/1.x Host parse
//!   - akış tablosu insert (`get_or_insert`) ve lookup (`get_mut`)
//!   - `classify()` dispatch (sniff → parser)
//!
//! Hedefler (docs/perf-budget.md satır 24): parse < 1 µs, lookup < 100 ns.
//!
//! QUIC Initial şifre çözme (`uf-quic`) ve `Strategy::apply` (desync eylemleri,
//! Faz 2) tam motor gelince eklenecek — aşağıda TODO ile işaretli.
//!
//! CI bunları yalnızca `cargo bench --no-run` ile DERLER (koşmaz); koşum
//! gürültülü olduğundan gerçek sayılar Faz 8'de elde makinede alınır.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{Criterion, criterion_group, criterion_main};
use uf_core::classify::classify;
use uf_core::parse::{http, tls};
use uf_core::{Classification, FlowKey, FlowTable, Protocol};

// --- Fixtures -------------------------------------------------------------

// tls.rs testlerindeki üretici ile aynı düzen: tek TLS kaydı içinde bir
// ClientHello (SNI + ALPN "h2", opsiyonel ECH).
fn client_hello(host: &[u8], with_ech: bool) -> Vec<u8> {
    const EXT_SERVER_NAME: u16 = 0x0000;
    const EXT_ALPN: u16 = 0x0010;
    const EXT_ECH: u16 = 0xfe0d;
    const HS_CLIENT_HELLO: u8 = 0x01;
    const CONTENT_HANDSHAKE: u8 = 0x16;

    let mut sni_list = Vec::new();
    sni_list.push(0u8); // name_type = host_name
    sni_list.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(host);
    let mut sni = Vec::new();
    sni.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    sni.extend_from_slice(&sni_list);

    let alpn_proto: &[u8] = b"h2";
    let mut alpn = Vec::new();
    let inner_len = 1 + alpn_proto.len();
    alpn.extend_from_slice(&(inner_len as u16).to_be_bytes());
    alpn.push(alpn_proto.len() as u8);
    alpn.extend_from_slice(alpn_proto);

    let mut exts = Vec::new();
    let push_ext = |exts: &mut Vec<u8>, t: u16, body: &[u8]| {
        exts.extend_from_slice(&t.to_be_bytes());
        exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
        exts.extend_from_slice(body);
    };
    push_ext(&mut exts, EXT_SERVER_NAME, &sni);
    push_ext(&mut exts, EXT_ALPN, &alpn);
    if with_ech {
        push_ext(&mut exts, EXT_ECH, &[0x00, 0x01, 0x02]);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version TLS1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id len
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
    body.extend_from_slice(&[0x01, 0x00]); // compression_methods
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = Vec::new();
    hs.push(HS_CLIENT_HELLO);
    let l = body.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(CONTENT_HANDSHAKE);
    rec.extend_from_slice(&[0x03, 0x01]); // record version
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn http_request() -> &'static [u8] {
    b"GET /path/to/resource HTTP/1.1\r\n\
      Host: www.blocked.example\r\n\
      User-Agent: unfilter-bench/0.1\r\n\
      Accept: */*\r\n\
      Accept-Encoding: gzip, deflate, br\r\n\
      Connection: keep-alive\r\n\r\n"
}

fn flow_key(dst_port: u16, src_port: u16) -> FlowKey {
    FlowKey {
        protocol: Protocol::Tcp,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        src_port,
        dst_port,
    }
}

// --- Benches --------------------------------------------------------------

fn bench_tls_parse(c: &mut Criterion) {
    let rec = client_hello(b"www.blocked.example", false);
    c.bench_function("tls_client_hello_parse", |b| {
        b.iter(|| {
            let mut out = Classification::default();
            let _ = tls::parse_client_hello(black_box(&rec), &mut out);
            black_box(out.sni)
        })
    });
}

fn bench_http_parse(c: &mut Criterion) {
    let req = http_request();
    c.bench_function("http_host_parse", |b| {
        b.iter(|| {
            let mut out = Classification::default();
            let _ = http::parse_request(black_box(req), &mut out);
            black_box(out.http_host)
        })
    });
}

fn bench_classify(c: &mut Criterion) {
    let tls = client_hello(b"www.blocked.example", false);
    let http = http_request();
    let mut group = c.benchmark_group("classify");
    group.bench_function("tls", |b| {
        b.iter(|| black_box(classify(black_box(&tls), 443).server_name()))
    });
    group.bench_function("http", |b| {
        b.iter(|| black_box(classify(black_box(http), 80).server_name()))
    });
    group.finish();
}

fn bench_flow_table(c: &mut Criterion) {
    let ttl = 30_000_000_000; // 30 s
    let mut group = c.benchmark_group("flow_table");

    // Boş tabloya yeni akış ekleme (insert yolu).
    group.bench_function("insert_fresh", |b| {
        b.iter_batched(
            || FlowTable::new(1024, ttl),
            |mut t| {
                let e = t.get_or_insert(black_box(flow_key(443, 50000)), 1);
                black_box(e.phase)
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Var olan akışı arama (lookup yolu — hedef < 100 ns). 10k akış önceden
    // doldurulup ortadaki bir anahtar sorgulanır.
    let mut populated = FlowTable::new(65_536, ttl);
    for i in 0..10_000u16 {
        populated.get_or_insert(flow_key(443, 20000 + i), i as u64);
    }
    let probe = flow_key(443, 20000 + 5000);
    group.bench_function("lookup_hit", |b| {
        b.iter(|| {
            black_box(
                populated
                    .get_mut(black_box(&probe), 999_999)
                    .map(|e| e.phase),
            )
        })
    });

    group.finish();
}

// TODO(faz-tam-motor): aşağıdaki benchmark'lar ilgili kod yazılınca eklenecek:
//   - QUIC Initial decrypt (uf-quic, ring) — hedef < 1 µs
//   - Strategy::apply / desync eylem üretimi (Faz 2) — DesyncAction → baytlar
//   - uçtan uca capture→inject gecikme histogramı (uf-core LatencyHistogram,
//     docs/perf-budget.md satır 23) mikro değil, Faz 8 elde ölçüm; bkz.
//     scripts/bench/latency.md.

criterion_group!(
    hotpath,
    bench_tls_parse,
    bench_http_parse,
    bench_classify,
    bench_flow_table
);
criterion_main!(hotpath);
