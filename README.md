<div align="center">

# 🔓 Unfilter

**Sıfır‑yapılandırma Windows DPI/DNS atlatma aracı.**
Kur, aç, çalışır — tarayıcı eklentisi, proxy, VPN hesabı ya da sistem DNS değişikliği yok.

[![CI](https://github.com/ensomg/Unfilter/actions/workflows/ci.yml/badge.svg)](https://github.com/ensomg/Unfilter/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ensomg/Unfilter?include_prereleases&label=s%C3%BCr%C3%BCm)](https://github.com/ensomg/Unfilter/releases)
[![License: MIT](https://img.shields.io/badge/lisans-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)
![Rust](https://img.shields.io/badge/Rust-2024-dea584?logo=rust&logoColor=white)

</div>

---

Unfilter, derin paket incelemesi (**DPI**) ve **DNS zehirlenmesi** ile engellenen
sitelere erişimi **yerel olarak** geri kazandırır. Trafiğiniz kendi
bilgisayarınızdan dışarı çıkar; aracı bir sunucuya giden tünel **yoktur**.

> **VPN veya proxy değildir.** IP'nizi gizlemez, trafiğinizi başka bir sunucuya
> taşımaz. Yalnızca engellemenin uygulandığı noktadaki kendi paketlerinizi
> yeniden şekillendirir — tıpkı GoodbyeDPI / zapret gibi, ama sıfır ayarla.

## ✨ Nasıl çalışır

| | |
|---|---|
| 🧩 **DPI atlatma** | TLS ClientHello / HTTP isteğini paket seviyesinde (WinDivert) böler, yeniden sıralar, sahte paketle şaşırtır. Sansür kutusu SNI'yı eşleştiremez; siz hedefe doğrudan bağlanırsınız. |
| 🛡️ **DNS düzeltme** | Zehirlenmiş yanıtları tanır ve sorguları güvenilir çözücülere (DoH/DoT) paket seviyesinde yönlendirir. Sistem DNS ayarınız **değişmez**; servis durunca eski haline döner. |
| 🔎 **Otomatik strateji** | Ağınızı parmak izinden tanır, çalışan en ucuz bypass stratejisini kendi bulur, profili saklar — bir sonraki açılışta anında bağlanır. |
| 🧠 **QUIC farkında** | QUIC Initial paketini okuyup hedefi (SNI) tanır. |
| 🪫 **Fail‑open** | Bir sorun olursa trafik **hiç dokunulmadan** akar; servis ölürse internetiniz kesilmez. |
| 🪶 **Hafif** | Boşta ~düşük RAM, GPU'suz yazılım çizici arayüz, açılışta cam/logo animasyonu. |

Ayrıntılı kullanım: [docs/user-guide.md](docs/user-guide.md) · Sık sorulanlar:
[docs/faq.md](docs/faq.md)

## 🚀 Kurulum

> ⚠️ Çalışması için **yönetici** yetkisi ve **WinDivert 2.2 imzalı sürücüsü**
> gerekir. Yayınlanan sürüm henüz **geliştirici ön‑sürümüdür** (aşağıdaki
> duruma bakın).

1. [**Sürümler**](https://github.com/ensomg/Unfilter/releases) sayfasından son
   paketi indirin.
2. İmzalı kurucu (`Unfilter-Setup-<sürüm>.exe`) hazır olduğunda: çalıştırın,
   yönetici onayı verin, ~1 dakikada biter ve tepsi (tray) simgesi gelir.
3. Ön‑sürüm zip'i için: açın, `uf-service.exe`'yi yönetici olarak çalıştırın,
   ardından `uf-ui.exe` ile arayüzü açın.

Kaldırma hiçbir iz bırakmaz — servis, sürücü, dosyalar, kayıt defteri ve
güvenlik duvarı kuralı temizlenir
([doğrulama betiği](scripts/verify-clean-uninstall.ps1)).

## 📊 Durum

Tüm fazların kodu `main` üzerinde, derleniyor ve test ediliyor; proje
**geliştirici ön‑sürümü** aşamasında.

| Alan | Durum |
|---|---|
| Çekirdek tipler, akış tablosu, parser'lar (F0–F1) | ✅ |
| Desync motoru: split / disorder / fake / TLS‑record‑split / case‑mangle (F2) | ✅ |
| DoH/DoT çözücü + DNS zehirlenmesi tespiti (F3) | ✅ |
| QUIC Initial okuma + SNI (F4, RFC 9001 vektörleriyle doğrulandı) | ✅ |
| Strateji prober + profil önbelleği (F5) | ✅ |
| Servis kontrol düzlemi + slint arayüz + tray + IPC (F6) | ✅ |
| Fallback (SOCKS5/HTTP CONNECT), kurucu, benchmark (F7–F9) | ✅ |
| **Canlı:** SCM servis kaydı, Connect'te motoru başlatma, imzalı sürücüyle uçtan uca test | ⏳ |

Yol haritası ve tasarım: [docs/architecture.md](docs/architecture.md) ·
Faz raporları: [docs/phase-reports](docs/phase-reports)

## 🛠️ Kaynaktan derleme

Gereksinimler: Rust (sürümü `rust-toolchain.toml` sabitler), Windows x64,
Windows SDK (imzalama için `signtool`),
[Inno Setup 6](https://jrsoftware.org/isdl.php) (kurucu için `iscc`).

```powershell
# 1) WinDivert ikililerini indir ve hash'leri sabitle (ilk kez -Record)
powershell -File scripts\fetch-windivert.ps1 -Record

# 2) Release derleme (LTO + strip)
cargo build --release --workspace

# 3) Boyut bütçesini doğrula
powershell -File scripts\check-size.ps1

# 4) Kurucuyu derle -> dist\Unfilter-Setup-<sürüm>.exe
iscc installer\unfilter.iss

# 5) (Yayın için) ikilileri ve kurucuyu imzala
powershell -File scripts\sign.ps1 -Thumbprint <SERT_THUMBPRINT>
```

Kurucu ve dosya düzeni: [installer/README.md](installer/README.md)

## 🧪 Geliştirme

```powershell
cargo test --workspace                       # tüm testler
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

- Mimari, thread modeli, fail‑open zinciri: [docs/architecture.md](docs/architecture.md)
- Mimari kararlar (ADR): [docs/decisions](docs/decisions)
- Değişiklik günlüğü: [CHANGELOG.md](CHANGELOG.md)

## 🛡️ Antivirüs / sürücü yanlış pozitifi

Paket yakalamak için imzalı **WinDivert 2.2** çekirdek sürücüsü kullanılır.
Bazı antivirüsler paket enjekte eden her aracı (yasal olanlar dahil) "hacktool"
olarak işaretleyebilir — bu bir **yanlış pozitiftir**. WinDivert açık kaynaklı,
Microsoft imzalı ve geniş kullanımlıdır; ikilileri resmi sürümden alınıp SHA‑256
ile sabitlenir ([assets/windivert](assets/windivert/README.md)). Unfilter'ın üç
çalıştırılabiliri Authenticode ile imzalanır
([scripts/sign.ps1](scripts/sign.ps1)) ve tüm kaynak açıktır.

## 📄 Lisans

Bu depo **MIT** lisanslıdır ([LICENSE](LICENSE)). WinDivert bağımlılığı LGPLv3 /
GPLv2 olarak **dinamik** bağlanır ve ayrı, değiştirilmemiş imzalı ikili olarak
dağıtıldığından uyumludur. Arayüz [Slint](https://slint.dev) ile yapılmıştır —
*Made with Slint*.

<div align="center">
<sub>Trafiğiniz sizde kalır. 🇹🇷</sub>
</div>
