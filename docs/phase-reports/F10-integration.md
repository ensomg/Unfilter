# Faz 10: Canlı DNS bağlama ve tek çalıştırılabilir (entegrasyon)

| Bileşen | Model | Durum |
| --- | --- | --- |
| uf-dns canlı transport: DoT (RFC 7858, bağlantı yeniden kullanımı) + DoH (RFC 8484, HTTP/1.1 POST) | Opus 4.8 | ✓ |
| Servis DNS konsolidasyonu: `uf_dns::{Dot,Doh}` kullanımı, yinelenen `DotTransport` kaldırıldı | Opus 4.8 | ✓ |
| Tek exe: `unfilter.exe` (--service / --tray / --ui) | Opus 4.8 | ✓ |

## DNS (F3/F6 açık maddelerinin kapatılması)

- Canlı TLS taşıma artık **tek yerde**: `uf-dns/src/transport.rs` içinde `Dot` ve `Doh`.
  rustls + ring (ADR 003), gömülü Mozilla kök seti (`webpki-roots`), sabit bootstrap
  IP'ye doğrudan bağlanır (düz metin bootstrap DNS yok). DoT tek bağlantıyı açık
  tutup yeniden kullanır; bozulan bağlantı sorgu başına bir kez yeniden kurulur.
  DoH her sorguda taze bağlantı (`Connection: close`) açar; önbellek önde olduğu
  için bu per-paket maliyet değildir.
- `uf-service` kendi yinelenen `transport.rs`'ini bıraktı; artık `uf_dns`'i kullanıyor.
  Bu, servisten doğrudan `rustls`/`webpki-roots`/`rustls-pki-types` bağımlılıklarını
  ve `live-tls` feature'ını kaldırdı (sürüm çakışması da temizlendi).
- **DoH artık bağlı** (F6'daki "yalnız DoT" açığı kapandı). `uf-service/src/dns.rs`
  içindeki `DnsService`, config'teki her upstream'i **gömülü `PROVIDERS` ile host
  adından eşleştirir**; pinned IP'ler koddan gelir, config'ten değil — kurcalanmış
  bir config resolver'ı saldırgan adrese yönlendiremez, yalnız hangi bilinen
  sağlayıcıyı ve taşımayı (DoH/DoT) ve sırayı seçer.
- Resolver **artık düşürülmüyor** (eski `let _resolver` ölü kodu gitti). `DnsService`
  servis ömrü boyunca canlı tutulur; başlangıçta gerçek bir sağlık kontrolü
  (`cloudflare.com` çözümlemesi) en az bir güvenilir upstream'in erişilebilir
  olduğunu loglar. Çözümleme politikası tek-thread'li (mock `Transport` `Cell`
  kullanıyor, bu yüzden `Send` değil), bu nedenle sağlık kontrolü kuran thread'de
  çalışır.

## Tek exe

- Üç ikili (uf-service / uf-tray / uf-ui) → tek `unfilter` ikilisi. Mod komut
  satırı bayrağıyla seçilir; her mod ayrı **süreç** olarak çalışır (slint/winit UI
  ana thread ister, tray kendi Win32 mesaj döngüsünü çalıştırır — aynı süreçte bir
  arada olamazlar). Tray, UI'yi `current_exe --ui` ile yeniden çalıştırarak açar.
- `uf-ui` ve `uf-tray` ikili crate'ten **lib** crate'e çevrildi (`pub fn run()`).
  `uf-service` de lib oldu (`uf_service::run`, `entry` modülü). Yeni `unfilter`
  ikili crate'i bu üç lib'i moda göre çağırır.
- İkon kaynakları (`.rc`) tek ikilide birleştirildi (`crates/unfilter/unfilter.rc`,
  id 1 = uygulama, 101–105 = tray durumları). `uf-ui`/`uf-tray`'in çalışma zamanında
  `GetModuleHandleW(null)` ile çözdüğü id'ler bu ikilinin kaynaklarından gelir.
- `#![windows_subsystem = "windows"]` artık yalnız `unfilter` ikilisinde; lib'lerden
  kaldırıldı. Installer ve scriptler tek exe'ye güncellendi (`sc create binPath
  "...\unfilter.exe" --service`, tray autostart `unfilter.exe --tray`).

## Hâlâ açık (çalışma zamanı, test gerektirir)

- **Port-53 yakalama döngüsü:** WinDivert ile giden DNS paketlerini yakalayıp
  `DnsService` üzerinden çözüp yeniden enjekte eden hot-path henüz bağlı değil.
  `DnsService` bu döngüye hazır bir API (`resolve_a`) sağlıyor.
- **SCM dispatcher:** servis hâlâ konsol/pipe olarak çalışıyor; gerçek Windows
  servis sarmalayıcısı (`StartServiceCtrlDispatcher`) eklenmedi.
- **Doğrulama:** değişiklikler `cargo check --workspace --all-targets` ve
  `uf-dns`/`uf-service` birim testleriyle doğrulandı; canlı DPI davranışı
  geliştirici ISP'sinde test edilemediğinden harici bir makinede test edilecek.
