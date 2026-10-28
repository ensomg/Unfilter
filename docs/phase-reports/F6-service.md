# Faz 6 Raporu — Servis çekirdeği (kontrol düzlemi)

Kapsam: `uf-service`'in kontrol düzlemi — config, orchestrator, canlı DoT
transport, Windows parmak izi, ve tray/UI'ya named pipe üzerinden hizmet.
Arayüz tarafı (UI/splash/tray/pipe) ayrı raporda: `F6-ui.md`.

## 1. Tamamlanan iş paketleri ve kullanılan model

| İş paketi | Model | Durum |
|---|---|---|
| `config`: default.toml şeması + yükleme sırası, doğrulama, sıfır-config | Opus 4.8 | ✓ |
| `orchestrator`: bağlan/tara/kes, ladder+cache'ten strateji seçimi, skor, failover/rescan | Opus 4.8 | ✓ |
| `transport` (live-tls): rustls + ring ile DoT (RFC 7858), sabit bootstrap IP | Opus 4.8 | ✓ |
| `fingerprint` (Windows): GetAdaptersAddresses + SendARP → ağ geçidi MAC | Opus 4.8 | ✓ |
| `ipc`: pipe sunucu döngüsü, saf Dispatcher, istemcilere olay yayını | Opus 4.8 | ✓ |

## 2. Kabul kriteri ölçüm sonuçları

| Kriter | Sonuç |
|---|---|
| `cargo clippy -p uf-service --all-targets -- -D warnings` (varsayılan + `--no-default-features`) | ✓ exit 0 |
| `cargo test -p uf-service` | ✓ 22 test |
| default.toml ayrıştırılır ve geçerli; eksik alanlar varsayılanla dolar | ✓ |
| Connect → Scanning; ilk başarılı aday → Connected; profil kalıcı | ✓ |
| Ardışık başarısızlık yedeğe geçer; düşük başarı yeniden tarar | ✓ |
| DoT transport RFC-uyumlu kurulur (sabit IP:853, SNI doğrulama) | ✓ (yapı testi; canlı sorgu ağ ister) |
| Dispatcher istekleri doğru eşler, paylaşılan durumu korur | ✓ |

## 3. Açık riskler ve sapmalar

- **SCM dispatcher yok (canlı adım):** `main` başlangıç sonrası pipe sunucusunu
  çalıştırıyor; gerçek Windows servisi olarak koşmak için `StartServiceCtrlDispatcher`
  sarmalayıcısı gerekir. Konsoldan çalıştırıldığında kontrol düzlemi zaten hizmet
  veriyor.
- **Paket motoru Connect'te başlatılmıyor (canlı adım):** WinDivert sürücüsü +
  yönetici gerektirir; orchestrator durumu modelliyor ama gerçek yakalama bu
  oturumda başlatılmıyor. Motor+prober bağlantısı (DataStrategy ← ladder) hazır.
- **DoH (HTTP/2) upstream yok:** `transport` DoT uygular; DoH upstream'leri
  şimdilik atlanır (DoT yeterli). HTTP/2 DoH v1.1.
- **live-tls varsayılan açık:** `ring`/`rustls`/`webpki-roots` getirir. `deny.toml`'a
  lisanslar eklendi (ring için clarify; hash CI'da doğrulanmalı). Kapatmak için
  `--no-default-features` ile kontrol düzlemi TLS'siz derlenir/test edilir.
- **Parmak izi SSID/ASN = None:** yalnız ağ geçidi MAC toplanır (kararlı, ağ
  başına ayırt edici). SSID (`WlanQueryInterface`) v1.1.

## 4. Sonraki fazın başlangıç koşulları

- SCM dispatcher + Connect'te WinDivert motoru başlatma (yönetici + imzalı
  sürücü). Orchestrator'ın `next_candidate`/`record_probe`/`record_flow`
  kancaları canlı tarama yürütücüsüne bağlanır.
- DoH upstream ve SSID parmak izi eklenir.

**Kaldığım yer:** Servis kontrol düzlemi tamam, pipe üzerinden UI/tray'e hizmet
veriyor ve `main`'e push edildi. Açık işler canlı: SCM sarmalayıcı ve paket
motorunun sürücüyle başlatılması.
