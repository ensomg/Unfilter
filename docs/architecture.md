# Unfilter — Mimari

Durum: Faz 0 (taslak, gate review ile onaylanır). Kaynak gereksinimler: master prompt §1–§9.

## 1. Katmanlar ve crate grafiği

```
                 ┌──────────┐      ┌────────┐
                 │  uf-ui   │      │uf-tray │        (kullanıcı yetkisi)
                 └────┬─────┘      └───┬────┘
                      │  named pipe    │
                      │  JSON-RPC      │
                      └──────┬─────────┘
                         ┌───┴────┐
                         │ uf-ipc │  (yalnızca protokol tipleri)
                         └───┬────┘
                      ┌──────┴───────┐
                      │  uf-service  │                 (yükseltilmiş)
                      └──┬──┬──┬──┬──┘
        ┌────────────────┘  │  │  └─────────────────┐
   ┌────┴─────┐ ┌──────┐ ┌──┴───┐ ┌────────┐ ┌──────┴─────┐
   │uf-capture│ │uf-dns│ │uf-quic│ │uf-probe│ │uf-fallback │
   └────┬─────┘ └──┬───┘ └──┬───┘ └───┬────┘ └──────┬─────┘
        └──────────┴────────┴─────────┴─────────────┘
                              │
                         ┌────┴────┐
                         │ uf-core │   OS API yok, tokio yok, alloc'suz hot path
                         └─────────┘
```

Kurallar:
- `uf-core` yalnızca `core`/`std` ve `serde` kullanır. OS çağrısı, `windows-sys`, `tokio` yasak. CI bunu `scripts/check-core-deps.ps1` ile zorlar.
- `PacketIO` trait'i `uf-core::io` içinde tanımlıdır; `uf-capture` uygular ve re-export eder (varsayım V1). Böylece core, capture'a bağımlı olmaz ve Linux (nfqueue/eBPF), macOS (pf/NetworkExtension), Android (VpnService) adaptörleri yalnızca yeni bir `PacketIO` impl'i olarak eklenir.
- Servis/tray/UI arası tipler ayrı `uf-ipc` crate'inde (varsayım V3). UI, servis crate'ine hiç bağımlı değildir.
- `installer/` bir crate değildir (varsayım V2).

## 2. Thread modeli (servis içi)

```
WinDivert handle (filtre: giden TCP 80/443, UDP 443, UDP 53, Discord UDP)
     │ recv (bloklayan)
┌────┴─────────┐   rtrb SPSC   ┌───────────────┐   rtrb SPSC   ┌──────────────┐
│ capture thr. │ ─────────────▶│ engine thread │ ─────────────▶│ inject thr.  │
└──────────────┘  PacketBuf id └───────┬───────┘  PacketBuf id └──────────────┘
                                       │ kontrol mesajları (yavaş yol, mpsc)
                         ┌─────────────┴─────────────┐
                         │ tokio runtime (current_th.)│  uf-dns, uf-probe, IPC
                         └───────────────────────────┘
```

- Hot path (capture → engine → inject) senkron, dedicated OS thread'leridir. Async yoktur.
- Thread'ler arası yalnızca `PacketBuf` indeksleri taşınır; veri kopyalanmaz. Buffer'lar başlangıçta ayrılan sabit bir havuzdan gelir (varsayılan 512 × 2 KiB ≈ 1 MiB).
- Faz 1 başlangıç sadeleştirmesi: capture ve inject aynı thread olabilir (WinDivert recv/send aynı handle'da thread-safe). Ölçüm gerekirse ayrılır.
- tokio yalnızca ağ I/O'su olan yavaş yollarda (DoH/DoT, probe, IPC) ve `current_thread` runtime ile kullanılır; idle CPU < %0.3 için timer'lar seyrek tutulur.

## 3. Hot path kuralları

1. Paket başına heap allocation yok. Parser'lar `&[u8]` dilimleri döndürür.
2. Akış tablosu: sabit kapasiteli (65 536), açık adresli hash + intrusive LRU listesi, TTL'li. Tablo doluysa en eski akış atılır; atılan akış "Observe" ile yeniden başlar (en kötü durum: o akışa bypass uygulanmaz, trafik yine geçer).
3. Sınıflandırma yalnızca akışın ilk payload paketlerinde yapılır (ClientHello, HTTP istek satırı, QUIC Initial). Sonraki paketler akış durumu "Pass" ise tablo lookup'tan sonra doğrudan geri enjekte edilir.
4. Engelsiz trafiğe dokunulmaz: karar `Verdict::Pass` ise orijinal bayt dizisi aynen geri gönderilir (F1 bit-bit eşleşme kriteri).
5. Gecikme ölçümü: capture zaman damgası `PacketMeta` içinde taşınır; engine, inject anında sabit kovalı bir histograma yazar (alloc yok).

## 4. Akış durum makinesi

```
Observe ──(ilk payload)──▶ Classify ──(engelli hedef / probe kararı)──▶ Apply ──▶ Verify
   │                          │                                                │
   └──(payload yok, timeout)──┴──(engelsiz)──▶ Pass (terminal)                 │
                                                       ┌───── başarılı ────────┘
                                                       ▼
                                                     Pass   (RST/timeout → yedek strateji, Apply'a dön)
```

`Verify`, sunucu yanıtını (ServerHello / HTTP status / RST anomalisi) gözler ve sonucu `uf-probe`'un pasif izleme kanalına bildirir (§5.6 adım 6).

## 5. Strateji modeli

- Desync eylemleri (`DesyncAction`) veri olarak tanımlanır ve `StrategySpec` içinde sıralı bir liste olarak birleştirilir. Config (JSON/TOML) → `StrategySpec` → derlenmiş `Strategy` impl.
- Yeni teknik = yeni `DesyncAction` varyantı veya yeni `Strategy` impl + şema alanı. Çekirdek motor değişmez.
- `Strategy::apply` çıktısını önceden ayrılmış `Emitter` yuvalarına yazar (en fazla 8 paket/girdi paket; split+fake+disorder kombinasyonları için yeterli).

## 6. Fail-open zinciri

1. Engine bir paketi işleyemezse (parse hatası, buffer yok, beklenmeyen durum) paket **olduğu gibi** geri enjekte edilir.
2. `panic = "abort"`: herhangi bir panik süreci hemen sonlandırır; OS WinDivert handle'ını kapatır, sürücü filtreyi kaldırır, trafik normal yoldan akar. Yakalanmış paketler kaybolabilir (TCP yeniden iletir).
3. Watchdog thread: engine thread'inin heartbeat sayacı 2 sn ilerlemezse handle'ı `WinDivertShutdown` + `WinDivertClose` ile kapatır ve servisi yeniden başlatılmak üzere sonlandırır.
4. Servis recovery politikası: 1., 2., 3. hatada 5 sn sonra yeniden başlat; sayaç 1 günde sıfırlanır.
5. DNS yönlendirmesi paket seviyesinde olduğu için (sistem DNS ayarı değiştirilmez) servis ölünce DNS de kendiliğinden eski haline döner.

## 7. Yetki ayrımı ve IPC

- `uf-service`: Windows servisi. WinDivert sürücüsüne erişim yönetici/SYSTEM ister; servis başlarken ihtiyaç duymadığı ayrıcalıkları (`SeDebugPrivilege` vb.) düşürür. Ayrıntılı inceleme Faz 6 (Opus).
- `uf-tray`, `uf-ui`: kullanıcı yetkisinde çalışır, asla yükseltilmez.
- Kanal: `\\.\pipe\unfilter`, DACL yalnızca SYSTEM + etkileşimli oturum sahibine izin verir; `PIPE_REJECT_REMOTE_CLIENTS`.
- Protokol: satır sonuyla ayrılmış JSON-RPC benzeri mesajlar, `uf-ipc::PROTOCOL_VERSION` ilk el sıkışmada karşılaştırılır.

## 8. Bellek bütçesi dağılımı (hedef, Faz 8'de ölçülür)

| Bileşen | Boşta | Yük altında |
|---|---|---|
| uf-service: buffer havuzu | 1 MiB | 1 MiB |
| uf-service: akış tablosu (64K × ~64 B) | 4 MiB | 4 MiB |
| uf-service: DNS cache (≤ 4096 kayıt) | < 1 MiB | 1 MiB |
| uf-service: tokio + rustls + kod | ~5 MiB | ~12 MiB |
| uf-tray | ≤ 4 MiB (hedef), ≤ 8 MiB (sınır) | aynı |
| **Toplam** | **≤ 25 MiB** | **≤ 60 MiB** |

Akış tablosu tembel değil, başlangıçta ayrılır: boyut sabit ve öngörülebilir olsun diye.

## 9. Platform genişleme noktaları

| Platform | `PacketIO` | Not |
|---|---|---|
| Windows | WinDivert 2.2 | v1 |
| Linux | nfqueue (+ ileride eBPF) | v2 |
| Android | VpnService TUN | v2, userspace TCP gerekir |
| macOS/iOS | NetworkExtension | v3 |

Platform adaptörleri `uf-capture` içinde `cfg(target_os)` ile ayrılır; `uf-core` hiçbir zaman değişmez.
