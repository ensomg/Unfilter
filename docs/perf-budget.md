# Performans bütçesi doğrulama planı

Her kısıt (master prompt §2) için: nasıl ölçülür, hangi araçla, eşik, nerede çalışır. "CI" = her push'ta GitHub Actions; "Faz 8" = gerçek makinede benchmark betiği (`scripts/bench/`), sonuç `docs/phase-reports/F8.md`'ye yazılır.

| # | Kısıt | Eşik | Yöntem | Nerede |
|---|---|---|---|---|
| 1 | Boşta RAM (servis + tray, pencere kapalı) | ≤ 25 MB | Private Working Set, 5 dk boşta, 1 sn aralıkla örnekleme, maksimum raporlanır | Faz 8 |
| 2 | Yük altında RAM (pencere kapalı) | ≤ 60 MB | Aynı sayaç, iperf3 + pcap replay 10 dk | Faz 8 |
| 3 | Pencere açıkken ek RAM, kapanınca iade | ≤ 40 MB ek; kapanınca uf-ui süreci yok | Aç/kapa döngüsü ×20, süreç listesi ve toplam bellek | Faz 6 + 8 |
| 4 | Boşta CPU | < %0.3 | `typeperf "\Process(uf-*)\% Processor Time"`, 5 dk ortalama, çekirdek sayısına normalize | Faz 8 |
| 5 | Aktif trafikte CPU | < %3 tek çekirdek @ 1 Gbit | Sentetik replay (WinDivert loopback) + gerçek iperf3 | Faz 8 |
| 6 | Eklenen gecikme | ort. < 1 ms; bypass'sız akışta ~0 | Motor içi histogram (capture→inject), p50/p99/max; ayrıca criterion mikro-benchmark | CI (micro) + Faz 8 |
| 7 | Dağıtım boyutu | ≤ 8 MB | `scripts/check-size.ps1` (exe'ler + WinDivert + varsayılan config) | CI |
| 8 | Sıfır kullanıcı ayarı | — | Temiz VM'de kur → 10 sn içinde engelli site açılıyor (F5) | Faz 5 + 9 |
| 9 | Telemetri yok | 0 beklenmeyen bağlantı | Probe hedef listesi dışında giden bağlantı yok (ETW / Wireshark filtre) | Faz 8 |
| 10 | Fail-open | İnternet kesilmez | Servis `taskkill /f` ile öldürülür; 1 sn içinde ping/HTTPS sürüyor | Faz 1 + 8 |
| 11 | Temiz kaldırma | iz yok | Kaldırma sonrası servis, sürücü, kayıt defteri, firewall kuralı, dosya tarama betiği | Faz 9 |

## Ölçüm araçları

- **RAM**: `Get-Process -Name uf-service,uf-tray | Select PrivateMemorySize64, WorkingSet64` döngüsü (`scripts/bench/mem.ps1`, Faz 8). Hedef sayaç: Private Working Set (Görev Yöneticisi'nin gösterdiği değer).
- **CPU**: `typeperf` süreç sayaçları; ham değer `/ [Environment]::ProcessorCount`.
- **Gecikme**: `uf-core` içinde `LatencyHistogram` (sabit 32 logaritmik kova, 1 µs – ~1 sn; atomik sayaçlar, alloc yok). Servis IPC üzerinden p50/p99'u raporlar; UI "ek gecikme" alanı buradan beslenir.
- **Mikro-benchmark**: criterion — TLS ClientHello parse, QUIC Initial decrypt, akış tablosu lookup/insert, `Strategy::apply`. Hedef: parse < 1 µs, lookup < 100 ns. CI'da yalnızca derlenir (`--no-run`); koşum gürültülü olduğu için Faz 8'de.
- **Boyut**: CI'da zorunlu; ayrıca her faz raporunda bin başına boyut tablosu.

## Erken uyarı eşikleri

Bir faz sonunda bütçenin %75'i aşılırsa (ör. dağıtım > 6 MB, boşta RAM > 19 MB) gate review bunu "risk" olarak işaretler ve bir sonraki faza geçmeden Opus profilleme görevi açılır.
