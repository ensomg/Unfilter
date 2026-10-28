# Gecikme ölçümü

Master prompt §2, kısıt #6: eklenen gecikme ort. < 1 ms; bypass uygulanmayan
(passthrough) akışta ~0. İki katman:

## 1. Mikro-benchmark (criterion) — şimdi ölçülebilir

`crates/uf-core/benches/hotpath.rs`, hot-path ilkellerinin tek tek maliyetini
ölçer. Bugün var olan ve sıfır-tahsisli olanlar:

| Benchmark | Ölçülen | Hedef (perf-budget §Mikro-benchmark) |
|---|---|---|
| `tls_client_hello_parse` | TLS ClientHello → SNI/ALPN/ECH | parse < 1 µs |
| `http_host_parse` | HTTP/1.x → Host | parse < 1 µs |
| `classify/tls`, `classify/http` | `classify()` dispatch (sniff → parser) | < 1 µs |
| `flow_table/insert_fresh` | `FlowTable::get_or_insert` (yeni akış) | — |
| `flow_table/lookup_hit` | `FlowTable::get_mut` (10k akış dolu) | lookup < 100 ns |

Koşum (gürültülü olduğu için elde, Faz 8 makinesinde):

```powershell
cargo bench -p uf-core
```

Belirli bir benchmark:

```powershell
cargo bench -p uf-core -- tls_client_hello_parse
```

CI'da **koşulmaz**, yalnızca derlenir — koşum arka plan gürültüsüne duyarlıdır ve
CI makineleri paylaşımlıdır (perf-budget.md satır 24). CI yalnızca şunu yapar:

```powershell
cargo bench --workspace --no-run
```

Bu, benchmark hedeflerinin derlendiğini (API kaymadığını) garanti eder, zaman
harcamadan.

> Not: `criterion` çalışma zamanı desteği (`cargo_bench_support`) workspace'te
> `default-features = false` ile kapalı; benchmark'lar `--no-run` ile derlenmek
> ve elde `cargo bench` ile koşulmak üzere yapılandırılmıştır.

## 2. Uçtan uca histogram (capture → inject) — tam motor bekliyor

Gerçek "eklenen gecikme" (bir paketin yakalanmasından yeniden enjekte
edilmesine kadar geçen süre) motor içindeki `LatencyHistogram` ile ölçülecek:
sabit 32 logaritmik kova (1 µs – ~1 sn), atomik sayaçlar, tahsis yok
(perf-budget.md satır 23). Servis bunu IPC üzerinden p50/p99/max olarak
raporlayacak; UI "ek gecikme" alanı buradan beslenecek.

`PacketMeta.captured_at_nanos` alanı bu ölçüm için **zaten ayrılmış** (io.rs):
backend yakalama anının monotonik zaman damgasını koyar, motor enjeksiyon anında
farkı histograma yazar.

Bu katman şu an **beklemede**:

- `LatencyHistogram` tipi henüz yazılmadı (motor hâlâ passthrough).
- Gerçek capture→inject yolu WinDivert backend'i + yönetici hakları + canlı
  trafik gerektirir (bkz. F1 açık riskleri).

Faz 8'de elde ölçüm prosedürü (motor tamamlanınca):

1. Servisi WinDivert backend'iyle başlat.
2. Bilinen bir engelli siteye `active` trafik üret (iperf3 / replay).
3. Servisin IPC gecikme raporunu oku: p50/p99/max.
4. Passthrough (bypass yok) akışta ek gecikmenin ~0 olduğunu, bypass'lı akışta
   ortalamanın < 1 ms kaldığını doğrula.
5. Çapraz kontrol: `scripts/bench/cpu.ps1 -Mode active` aynı pencerede.

Sonuçlar `docs/phase-reports/F8.md` tablosuna işlenir.
