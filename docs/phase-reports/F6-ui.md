# Faz 6 Raporu — masaüstü ön yüz (UI, tray, IPC taşıması)

Çıktı formatı: master prompt §8. Kapsam: Faz 6'nın servis dışındaki kısmı —
`uf-ipc::pipe` (named pipe taşıması, çerçeveleme, el sıkışma, kendiliğinden
yeniden bağlanan istemci), `uf-ui` (slint software renderer, ana ekran +
açılış animasyonu), `uf-tray` (saf Win32), logo ve ikonlar. Servis tarafı
(`PipeServer`'ı kullanan istek işleyici) koordinatörde.

## 1. Tamamlanan iş paketleri ve kullanılan model

| İş paketi | Model | Durum |
|---|---|---|
| `uf-ipc::pipe` çerçeveleme: `FrameReader` / `write_frame`, 64 KiB sınırı, bozuk çerçeve toparlanabilir / taşma ölümcül | Opus | ✓ |
| El sıkışma yardımcıları `client_handshake` / `server_handshake` (Hello + `PROTOCOL_VERSION`, uyuşmazlıkta `VersionMismatch`, Hello'dan önce istek → `BadRequest`) | Opus | ✓ |
| `PipeServer`: ADR 005 DACL (SDDL), mesaj modu, `PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, her zaman bir dinleyen örnek, `ShutdownHandle` ile `accept` iptali | Opus | ✓ |
| `PipeStream`: overlapped I/O (aynı bağlantıda eşzamanlı okuma + yazma), `try_clone`, `Canceller` | Opus | ✓ |
| `PipeClient::connect` (yeniden deneme / zaman aşımı, `SECURITY_IDENTIFICATION`) ve `ServiceLink` (250 ms → 5 s üstel geri çekilme, otomatik `GetStatus`) | Opus | ✓ |
| Logo (`assets/logo/unfilter.svg`), ikon üretici (`assets/icons/gen_icons.py`, yalnızca stdlib), `.ico`'lar exe'lere gömülü (`embed-resource`) | Opus | ✓ |
| `uf-ui`: mockup'a göre ana ekran, Ayarlar / Loglar panelleri, site testi, oyun modu, Onar, toast, çevrimdışı durum | Opus | ✓ |
| `uf-ui` açılış animasyonu (~3 s, yay + smoothstep, tıkla-geç, bitince timer durur) | Opus | ✓ |
| DWM koyu başlık çubuğu + başlık rengi + pencere ikonu | Opus | ✓ |
| `uf-tray`: `Shell_NotifyIconW` (v4), gizli pencere, bağlam menüsü, durum ikonu/ipucu, tek örnek (mutex), `TaskbarCreated` sonrası yeniden ekleme, "Arayüzü aç" | Opus | ✓ |

## 2. Kabul kriteri ölçüm sonuçları

| Kriter | Sonuç |
|---|---|
| `cargo fmt -p uf-ui -p uf-tray -p uf-ipc -- --check` | ✓ |
| `cargo clippy -p uf-ui -p uf-tray -p uf-ipc --all-targets -- -D warnings` | ✓ exit 0 (yalnızca "clippy.toml MSRV 1.85 ≠ uf-ui 1.92" yapılandırma uyarısı) |
| `cargo test -p uf-ipc` | ✓ 25 birim + 2 doc test (gerçek pipe üzerinde 8 test dahil) |
| `cargo test -p uf-ui` | ✓ 25 test (+1 `--ignored` görsel anlık görüntü testi) |
| `cargo test -p uf-tray` | ✓ 6 test |
| `cargo clippy/test --workspace --exclude uf-service` | ✓ (uf-service diğer ajanda yarım düzenlemede, derlenmiyor) |
| 64 KiB üstü çerçeve reddedilir, akış zehirlenir; bozuk JSON/UTF-8 toparlanır | ✓ `oversized_frame_is_rejected_and_poisons`, `malformed_json_is_recoverable` |
| Aynı bağlantıda iki iş parçacığından okuma + yazma (kilitlenme yok) | ✓ `handshake_and_full_duplex_over_real_pipe` |
| `accept` kapanışta açılır, `read` iptal edilir | ✓ `shutdown_unblocks_accept`, `cancel_unblocks_read` |
| Aynı ada ikinci sunucu açılamaz (squatting) | ✓ `second_bind_on_same_name_fails` |
| Servis yokken UI/tray çevrimdışı gösterir, servis gelince bağlanır, kopunca yeniden dener | ✓ `service_link_connects_sends_and_reconnects`; canlı: "SERVİS YOK" ekranı |
| Animasyon matematiği (kritik sönümlü yay, aşmasız; smoothstep/smootherstep; %20 → tam boy; daire → squircle; logo 2.6× → 1×; bitişte başlığa oturur) | ✓ 13 test `splash::tests` |
| Boşta CPU ≈ 0 | ✓ release, servis yokken 10 sn: uf-ui 15.6 ms (tek zamanlayıcı dilimi, 5 sn'lik yeniden deneme), uf-tray 0 ms |
| RAM (Private Bytes) | uf-ui 4.0 MB (WS 20.2 MB), uf-tray 1.6 MB (WS 10.7 MB) — tray hedefi < 4 MB ✓ |
| Tray tek örnek | ✓ ikinci `uf-tray.exe` hemen çıkıyor |
| Pencere 360×620 sabit, koyu başlık, ikon | ✓ canlı ekran görüntüsüyle doğrulandı (büyüt düğmesi pasif) |

### Exe boyutları (release, `lto = "fat"`, `strip`, uf-ui/uf-tray `opt-level = "s"`)

| Dosya | Boyut | Hedef |
|---|---|---|
| `uf-ui.exe` | 8 180 736 B (7.8 MiB) | ADR 004 tahmini ~3–4 MB ✗ |
| `uf-tray.exe` | 392 704 B (384 KiB) | < 300 KB ✗ |

## 3. Açık riskler ve sapmalar

- **uf-ui boyutu bütçeyi aşıyor (en büyük risk).** slint 1.18 winit backend'i
  `i-slint-core/svg` (resvg/usvg/tiny-skia), `image-decoders` (png/jpeg/gif/webp),
  `muda`, `arboard`, `webbrowser` ve parley/ICU metin segmentasyon verisini
  zorunlu açıyor; bunlar slint özellik bayraklarıyla kapatılamıyor. Tek başına
  uf-ui ≈ 7.8 MiB, dağıtım bütçesi (≤ 8 MB toplam) tutmaz. Ayrıca kök profilde
  `opt-level = "s"` yalnızca uf-ui crate'ine uygulanıyor, bağımlılıklar
  `opt-level = 3` ile derleniyor. Öneriler (koordinatör kararı):
  1. Kök `Cargo.toml`'a `[profile.release.package."*"] opt-level = "s"` (ya da
     yalnızca slint/i-slint-*/parley/winit için). Ölçüldü
     (`CARGO_PROFILE_RELEASE_OPT_LEVEL=s`): uf-ui 7 362 560 B (7.0 MiB), yalnızca
     %10 kazanç — tek başına yetmez.
  2. winit yerine kendi `slint::platform::Platform` uygulamamız: Win32 pencere +
     `MinimalSoftwareWindow` + `StretchDIBits`; svg/image/muda/arboard tamamen
     düşer. Tahmini 3–4 MB; ~1 günlük iş (girdi/IME/DPI eşlemesi).
  3. ADR 004'teki yedek: egui + softbuffer.
- **slint sürümü / MSRV sapması.** Software renderer'da `Path` desteği slint
  1.15'te geldi; workspace `rust-version = 1.85` ile MSRV-farkında çözümleyici
  1.13'ü seçiyordu (Path çizilmiyor). uf-ui bu yüzden workspace slint girdisini
  değil doğrudan `slint = "1.18.1"` kullanıyor ve `rust-version = "1.92"`
  bildiriyor (toolchain 1.99). Kökteki `slint = "1.11.0"` girdisi artık
  kullanılmıyor; `clippy.toml` `msrv = 1.85` ile uyuşmazlık uyarısı veriyor.
- **Lisans: cargo-deny kırılacak.** slint `GPL-3.0-only OR
  LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0`;
  `deny.toml` allow listesinde yok. MIT projede uygun yol Royalty-free 2.0
  lisansı — bu lisans masaüstü uygulamada slint atfı (ör. "Made with Slint"
  rozeti / Hakkında metni) ister. `deny.toml`'a ekleme ve atıf metni
  koordinatörde (bu dosyalar kapsamım dışında).
- **uf-tray 384 KiB > 300 KB hedefi.** std + serde_json + uf-ipc pipe kodu +
  6 gömülü ikon (~28 KB). RAM hedefi tutuyor. Küçültme: ikon boyutlarını
  azaltmak, `serde_json` yerine elle yazılmış dar bir ayrıştırıcı (tray yalnızca
  `Status` okuyor) — gerekirse Faz 8.
- **Software renderer kısıtları animasyonu şekillendirdi.** 1.18'de software
  renderer `drop-shadow`, döndürme/ölçek, yuvarlatılmış kırpma ve gradyan kenar
  çizmiyor; gradyanlar yuvarlak köşeyi yok sayıyor. Bu yüzden: gölge radyal
  gradyanla, cam yüzü yarı saydam yuvarlak dikdörtgenlerle, ışık bandı ve kenar
  parlaması Rust'ta üretilen `Path` verisiyle (yuvarlak kareye Sutherland–Hodgman
  ile kırpılmış) çiziliyor; cam arkasındaki büyütülmüş logo, kareye içten teğet
  dikdörtgenle kırpılıyor (köşe yarıçapı × (1 − 1/√2) içeride). Bulanıklık yok;
  "squircle" gerçek süperelips değil, yarıçapı morf edilen yuvarlak kare.
  Tarama halkası döndürme yerine `animation-tick()` ile hesaplanan `ArcTo` yayı;
  yalnızca TARANIYOR durumunda var olduğu için başka durumda kare üretmez.
- **Ayarlar paneli sadeleştirildi.** Mockup'taki "Windows ile başlat",
  "Otomatik güncelle", "Açılınca otomatik bağlan" ve DNS sağlayıcı seçimi için
  IPC'de istek tipi yok; işlevsiz anahtar göstermemek için panelde yalnızca
  Strateji + Yeniden tara, Mod ve Sürüm var. Protokole `Settings` istekleri
  eklenince geri konabilir (`PROTOCOL_VERSION` artışı gerekir).
- **Ek UI durumları.** Mockup'ta olmayan "SERVİS YOK" (çevrimdışı) ve "HATA"
  (`ConnState::Fault`) durumları eklendi; TARANIYOR'da birincil düğme "İPTAL"
  (`Disconnect` gönderir).
- **Güvenlik notları (ADR 005).** DACL: `D:P(A;;GA;;;SY)(A;;0x12019b;;;IU)` —
  etkileşimli kullanıcıya okuma/yazma verilir ama `FILE_CREATE_PIPE_INSTANCE`
  verilmez (sahte örnek açılamaz); ilk örnek `FILE_FLAG_FIRST_PIPE_INSTANCE` ile
  açılır ve sunucu adı hep elinde tutar. İstemci `SECURITY_IDENTIFICATION` ile
  bağlanır (sahte sunucu kimliğe bürünemez). `IU` aynı makinedeki *tüm*
  etkileşimli oturumları kapsar (hızlı kullanıcı değiştirme); yalnızca aktif
  konsol oturumu isteniyorsa servis bağlanan istemcinin oturum kimliğini
  `GetNamedPipeClientSessionId` ile denetlemeli. İstemci, sunucunun SYSTEM
  olduğunu henüz doğrulamıyor (`GetNamedPipeServerProcessId` + token denetimi
  önerilir). `server_handshake` istemci konuşana kadar bekler; servis bunu bir
  zamanlayıcı + `PipeStream::cancel` ile sınırlamalı.
- **"Arayüzü aç"** açık pencereyi winit'in varsayılan sınıf adı (`Window Class`)
  + başlık `Unfilter` ile buluyor; slint/winit sınıf adını değiştirirse ikinci
  pencere açılır (zararsız).
- **Gerçek servisle uçtan uca test yapılmadı** (servis henüz `PipeServer`'ı
  kullanmıyor). Protokol akışı `ServiceLink` ↔ test `PipeServer` testiyle
  doğrulandı.

## 4. Sonraki fazın başlangıç koşulları

- Servis: `PipeServer::bind(PIPE_NAME)` → her `accept` için bir iş parçacığı;
  `try_clone` ile okuma ve olay-itme iş parçacıkları ayrılır; `server_handshake`
  sonrası `ClientMessage` doğrulanıp `ServerMessage` yazılır; durum değişimleri
  ve log satırları `Event` olarak tüm istemcilere itilir; kapanışta
  `ShutdownHandle::shutdown()` + istemci `Canceller`'ları.
- Boyut kararı (yukarıdaki 1/2/3) Faz 8 öncesi verilmeli; `scripts/check-size.ps1`
  şu an uf-ui yüzünden bütçeyi aşar.
- `deny.toml` + slint atıf metni.
- Görsel inceleme: `cargo test -p uf-ui -- --ignored snapshots` splash
  karelerini ve ana ekran durumlarını PNG olarak `%TEMP%\uf-ui-snapshots`'a
  (veya `UF_SNAPSHOT_DIR`) yazar.

**Kaldığım yer:** UI, tray ve pipe taşıması tamam; commit koordinatörde. Açık
karar: uf-ui exe boyutu (slint/winit) ve slint lisansının deny.toml'a eklenmesi.
