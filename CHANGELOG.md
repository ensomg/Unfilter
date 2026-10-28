# Değişiklik Günlüğü

Biçim [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) temellidir;
sürümleme [SemVer](https://semver.org/lang/tr/) izler. Henüz yayımlanmış bir
sürüm yoktur; aşağıdaki girdiler geliştirme fazlarına göre düzenlenmiştir
(bkz. [docs/phase-reports](docs/phase-reports)).

## [Yayımlanmadı]

### Faz 9 — Paketleme, imzalama, dokümantasyon
- Inno Setup kurulum betiği (`installer/unfilter.iss`): üç çalıştırılabiliri,
  WinDivert sürücüsünü ve varsayılan yapılandırmayı kurar; servisi recovery
  politikasıyla kaydeder, tray'i oturum açılışına ekler.
- Temiz kaldırma: kaldırıcı servisi + WinDivert sürücü servisini durdurup siler,
  güvenlik duvarı kuralını, kayıt defteri girdilerini ve tüm dosyaları kaldırır.
- `scripts/verify-clean-uninstall.ps1`: kaldırma sonrası iz taraması (iz varsa
  sıfırdan farklı çıkış).
- `scripts/sign.ps1`: üç exe + kurucu için Authenticode `signtool` sarmalayıcısı
  (parametreli sertifika/zaman damgası, gömülü sır yok).
- Kullanıcı dokümantasyonu: `README.md`, `docs/user-guide.md`, `docs/faq.md`,
  bu değişiklik günlüğü; AV/sürücü yanlış-pozitif notu.
- `config/default.toml`: varsayılan sıfır-yapılandırma profili.

### Faz 3 — DNS çözümleme çekirdeği (`uf-dns`)
- DoH/DoT wire codec (A/AAAA, isim sıkıştırma), build/parse.
- Zehirlenme tespiti (sinkhole / bogon / blok-sayfası / TTL uyuşmazlığı).
- TTL'li pozitif + negatif cache, kapasite/eviction.
- Gömülü güvenilir sağlayıcılar + bootstrap IP; upstream yarış/failover.
- Yanıt id doğrulaması (spoof koruması). 23 birim testi.
- Not: canlı rustls DoH/DoT taşıması `Transport` trait'inin arkasında; servise
  Faz 6'da bağlanacak.

### Faz 1 — Sınıflandırma ve yakalama
- TLS ClientHello parser (SNI/ALPN/ECH), HTTP/1.x istek parser (Host).
- `classify()` dispatch (sniff → parser).
- WinDivert 2.2 elle FFI (dinamik yükleme, ADR 002); `PacketIO` WinDivert
  implementasyonu, fail-open Drop.
- `ShutdownToken` (watchdog için çapraz-thread kapatma).
- `scripts/fetch-windivert.ps1`: WinDivert indirme + SHA-256 sabitleme.
- Not: canlı bit-bit ve fail-open doğrulaması WinDivert ikilisi + yönetici
  gerektirdiği için beklemede.

### Faz 0 — İskelet ve çekirdek
- Cargo workspace, lint/format/CI yapılandırması.
- Mimari doküman, thread modeli, fail-open zinciri, ADR 001–005.
- `PacketIO` trait + veri modelleri (`uf-core`, OS bağımsız).
- IPC protokol tipleri (`uf-ipc`), versiyonlu JSON-RPC, ACL'li named pipe.
- Boyut bütçesi doğrulaması (`scripts/check-size.ps1`, ≤ 8 MB).

[Yayımlanmadı]: https://github.com/ensomg/Unfilter/commits/main
