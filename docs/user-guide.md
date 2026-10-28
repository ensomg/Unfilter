# Unfilter — Kullanıcı Kılavuzu

Bu kılavuz günlük kullanım içindir. Teknik mimari için
[architecture.md](architecture.md), sık sorulanlar için [faq.md](faq.md).

## 1. Kurulum ve ilk çalıştırma

1. `Unfilter-Setup-<sürüm>.exe` dosyasını çalıştırın.
2. Yönetici onayı (UAC) verin. Bu, paket yakalama sürücüsünü (WinDivert) ve
   arka plan servisini kurmak için gereklidir; Unfilter yönetici haklarını
   yalnızca servis için kullanır, arayüz ve tray kullanıcı yetkisiyle çalışır.
3. Kurulum yaklaşık bir dakikada biter. Bildirim alanında (saat yanındaki
   simgeler) Unfilter simgesi belirir.

Kurulumdan sonra ek bir ayar yapmanıza gerek yoktur. Servis açılışta otomatik
başlar; tray her oturum açılışında yüklenir.

## 2. Arayüz

Simgeye tıklayınca ana pencere açılır. Durum halkası üç hâli gösterir:

| Durum | Anlamı |
|---|---|
| **HAZIR** | Motor kurulu ama atlatma kapalı. |
| **TARANIYOR** | Engelli hedef için çalışan strateji aranıyor. |
| **BAĞLI** | Çalışan bir strateji etkin; engelleme atlatılıyor. |

Pencerenin altındaki düğmeler:

- **BAĞLAN / BAĞLANTIYI KES:** atlatmayı açar/kapatır.
- **Yeniden Tara:** strateji probunu baştan çalıştırır (bir site yeni
  engellendiyse veya ISP yöntemi değiştiyse).
- **Onar:** sürücü/servis/ağ ayarlarını denetler ve bozuksa düzeltir.
- **Mod:** *Normal* / *Oyun*. Oyun modu Discord ve oyun UDP gecikmesini önceler.
- **Loglar:** bir siteyi test eder; DNS → TCP → TLS → kullanılan yöntem
  adımlarını ve sonucu gösterir.

## 3. Modlar

- **Normal:** dengeli; web gezintisi için uygun.
- **Oyun:** UDP yollarını (Discord sesi, oyun trafiği) düşük gecikmeyle önceler.

Modu arayüzden ya da tray sağ-tık menüsünden değiştirebilirsiniz.

## 4. Bir siteyi test etme

**Loglar** panelinde bir alan adı girin (ör. `example.com`) ve test edin. Çıktı:

- **DNS:** ad çözümlendi mi; zehirlenme algılandı mı.
- **TCP:** bağlantı kuruldu mu.
- **TLS:** doğru SNI ile el sıkışma tamamlandı mı.
- **Engel türü:** DNS / DPI / IP.
- **Yöntem:** siteyi açan strateji (varsa).

IP seviyesinde engelde (DPI stratejisi çözmez) araç bunu bildirir; bu durum
yedek yol (fallback) alanıdır.

## 5. Yapılandırma (isteğe bağlı)

Çoğu kullanıcının dokunmasına gerek yoktur. Varsayılanlar
`Program Files\Unfilter\config\default.toml` içindedir. Kişisel değişiklikler
`%ProgramData%\Unfilter\config.toml` dosyasına yazılır; servis önce bunu,
yoksa varsayılanı yükler. Başlıca seçenekler:

- `general.autostart` — açılışta otomatik bağlan.
- `general.mode` — `normal` / `game`.
- `dns.enabled`, `dns.upstreams` — DNS düzeltme ve güvenilir çözücüler.
- `engine.auto_probe`, `engine.strategy` — otomatik prob ya da sabit strateji.

Değişiklikten sonra arayüzdeki **Onar** veya servis yeniden başlatma değişikliği
uygular.

## 6. Kaldırma

**Ayarlar → Uygulamalar → Unfilter → Kaldır** (veya Başlat menüsündeki
"Unfilter'ı Kaldır"). Kaldırma şunları yapar:

1. Unfilter servisini durdurur ve siler.
2. WinDivert sürücü servisini durdurur ve siler.
3. Güvenlik duvarı kuralını, kayıt defteri girdilerini ve tüm dosyaları
   (`%ProgramData%\Unfilter` dahil) kaldırır.

Geriye hiçbir iz kalmaz. Doğrulamak için (yönetici PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify-clean-uninstall.ps1
```

Betik bir iz bulursa sıfırdan farklı çıkış kodu döndürür ve neyin kaldığını
listeler.

## 7. Sorun giderme

- **Simge yok / açılışta gelmiyor:** Görev Yöneticisi → Başlangıç'ta "Unfilter
  Tray" etkin mi bakın; `Program Files\Unfilter\uf-tray.exe` elle çalıştırın.
- **Durum FAULT:** **Onar**'a basın. Sürücü yüklenemiyorsa Secure Boot/sürücü
  imzası veya antivirüs engeli olabilir (bkz. [faq.md](faq.md)).
- **Site hâlâ açılmıyor:** **Yeniden Tara**; **Loglar**'dan test edin. Engel
  türü IP ise DPI stratejisi yetmez.
- **Antivirüs uyarısı:** yanlış pozitiftir; [README](../README.md#antivirüs--sürücü-yanlış-pozitifi)
  ve [faq.md](faq.md).
