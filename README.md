# Unfilter

**Sıfır-yapılandırma Windows DPI/DNS atlatma aracı.** Kur, aç, çalışır. Tarayıcı
eklentisi, proxy ayarı, VPN hesabı, sistem DNS değişikliği yok. Trafiğiniz
sizin bilgisayarınızdan dışarı çıkar; aracıya giden tünel yoktur.

> Durum: geliştirme aşamasında (Faz 0–3 tamam; motor servisi Faz 6'da bağlanıyor).
> Çalışır bir sürüm için yol haritasına bakın: [docs/architecture.md](docs/architecture.md).

## Nedir, ne değildir

Unfilter, derin paket incelemesi (DPI) ve DNS zehirlenmesiyle engellenen
sitelere erişimi yerel olarak geri kazandırır:

- **DPI atlatma:** TLS ClientHello / HTTP isteklerini paket seviyesinde
  (WinDivert sürücüsüyle) parçalayıp yeniden düzenler; sansür kutusu SNI'yı
  göremez, siz hedefe doğrudan bağlanırsınız.
- **DNS düzeltme:** zehirlenmiş yanıtları tespit eder ve güvenilir çözücülere
  (DoH/DoT) **paket seviyesinde** yönlendirir. Sistem DNS ayarınız değişmez;
  servis durunca DNS kendiliğinden eski haline döner.
- **Değildir:** VPN veya proxy değil. IP'nizi gizlemez, trafiği başka bir
  sunucuya taşımaz. Yalnızca engellemenin uygulandığı noktadaki paketleri
  değiştirir.

Ayrıntılı kullanım: [docs/user-guide.md](docs/user-guide.md) · Sık sorulanlar:
[docs/faq.md](docs/faq.md).

## Kurulum

1. [Sürümler](https://github.com/ensomg/Unfilter/releases) sayfasından
   `Unfilter-Setup-<sürüm>.exe` dosyasını indirin.
2. Çalıştırın (yönetici onayı ister — sürücü ve servis kurulumu için gerekir).
3. Kurulum biter (~1 dakika), arka plan simgesi (tray) görünür. Hepsi bu.

Kaldırma: **Ayarlar → Uygulamalar → Unfilter → Kaldır**. Kaldırma geriye
hiçbir iz bırakmaz — servis, sürücü, dosyalar, kayıt defteri ve güvenlik duvarı
kuralı temizlenir ([doğrulama betiği](scripts/verify-clean-uninstall.ps1)).

## Antivirüs / sürücü yanlış pozitifi

Unfilter, paketleri yakalamak için **WinDivert 2.2** adında imzalı bir çekirdek
sürücüsü kullanır. Bazı antivirüsler, paket enjeksiyonu yapan her aracı (yasal
olanlar dahil) "risk aracı" / "hacktool" olarak işaretleyebilir. Bu bir
**yanlış pozitiftir**:

- WinDivert açık kaynaklı, geniş kullanımlı ve Microsoft imzalı bir sürücüdür;
  ikilileri yukarı-akış resmi sürümünden alınır ve SHA-256 ile sabitlenir
  ([assets/windivert](assets/windivert/README.md)).
- Unfilter'ın üç çalıştırılabiliri (uf-service, uf-tray, uf-ui) Authenticode
  ile imzalanır ([scripts/sign.ps1](scripts/sign.ps1)).
- Tüm kaynak kod açıktır; ikilileri kendiniz derleyip yayımlanan hash'lerle
  karşılaştırabilirsiniz.

Antivirüsünüz uyarı verirse: dosyayı Microsoft'a ve antivirüs sağlayıcınıza
**yanlış pozitif** olarak bildirin ve kurulum dizinini istisnaya ekleyin.
İlk indirmede Windows SmartScreen uyarısı da görülebilir; imza itibarı
indirme hacmiyle birikene kadar normaldir ("Yine de çalıştır").

## Kaynaktan derleme

Gereksinimler: Rust (sürümü `rust-toolchain.toml` sabitler), Windows x64,
Windows SDK (imzalama için `signtool`), [Inno Setup 6](https://jrsoftware.org/isdl.php)
(kurucu için `iscc`).

```powershell
# 1) WinDivert ikililerini indir ve hash'leri sabitle (ilk kez -Record)
powershell -File scripts\fetch-windivert.ps1 -Record

# 2) Release derleme (LTO + strip; <8 MB bütçesi)
cargo build --release --workspace

# 3) Boyut bütçesini doğrula (<= 8 MB)
powershell -File scripts\check-size.ps1

# 4) Kurucuyu derle -> dist\Unfilter-Setup-<sürüm>.exe
iscc installer\unfilter.iss

# 5) (Yayın için) ikilileri ve kurucuyu imzala
powershell -File scripts\sign.ps1 -Thumbprint <SERT_THUMBPRINT>
```

Kurucu ve dosya düzeni: [installer/README.md](installer/README.md).

## Katkı ve mimari

- Mimari, thread modeli, fail-open zinciri: [docs/architecture.md](docs/architecture.md)
- Kararlar (ADR): [docs/decisions](docs/decisions)
- Faz raporları: [docs/phase-reports](docs/phase-reports)
- Değişiklik günlüğü: [CHANGELOG.md](CHANGELOG.md)

## Lisans

Bu depo **MIT** lisanslıdır ([LICENSE](LICENSE)). WinDivert bağımlılığı LGPLv3 /
GPLv2 olarak **dinamik** bağlanır ve ayrı, değiştirilmemiş imzalı ikili olarak
dağıtılır.
