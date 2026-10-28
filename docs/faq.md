# Unfilter — Sık Sorulan Sorular

## Genel

**Unfilter VPN mi?**
Hayır. VPN/proxy trafiğinizi başka bir sunucuya taşır ve IP'nizi gizler.
Unfilter hiçbir tünel kurmaz; trafiğiniz doğrudan hedefe gider. Yalnızca
engellemenin uygulandığı noktadaki paketleri (TLS ClientHello, DNS) yerel
olarak değiştirir. IP adresiniz değişmez.

**Beni anonim yapar mı?**
Hayır. Anonimlik hedefi yoktur; amaç engelli sitelere erişimi geri
kazandırmaktır. Gizliliğinizi önemsiyorsanız anonimlik için ayrıca Tor gibi
araçlar gerekir.

**Hangi işletim sistemleri?**
Şu an yalnızca Windows x64 (WinDivert 2.2 sürücüsüyle). Linux (nfqueue),
Android (VpnService), macOS (NetworkExtension) adaptörleri mimaride
öngörülmüştür ama henüz yoktur (bkz. [architecture.md](architecture.md) §9).

## Kurulum ve sürücü

**Neden yönetici hakkı istiyor?**
Paket yakalama sürücüsünü (WinDivert) ve Windows servisini kurmak için.
Arayüz ve tray asla yükseltilmez; yalnızca servis SYSTEM olarak çalışır.

**Antivirüsüm "hacktool" / "risk aracı" diyor. Virüs mü?**
Hayır, yanlış pozitif. Unfilter ağ paketlerini yakalayıp enjekte eder;
antivirüsler paket-enjeksiyon araçlarını (yasal olanlar dahil) sık sık bu
şekilde işaretler. WinDivert açık kaynaklı ve Microsoft imzalı bir sürücüdür;
ikilileri resmi sürümden SHA-256 ile sabitlenir ve Unfilter çalıştırılabilirleri
Authenticode ile imzalanır. Uyarıyı antivirüs sağlayıcınıza ve Microsoft'a
yanlış pozitif olarak bildirin, kurulum klasörünü istisnaya ekleyin.

**"Windows bu uygulamayı korudu" (SmartScreen) uyarısı.**
İmzalı yeni bir uygulamanın itibarı indirme hacmiyle birikir. "Ek bilgi" →
"Yine de çalıştır". İmzanın geçerliliğini dosyanın özelliklerinden ("Dijital
İmzalar" sekmesi) doğrulayabilirsiniz.

**Secure Boot açıkken sürücü yüklenmiyor.**
WinDivert imzalı olduğundan normalde yüklenir. Yüklenmezse, antivirüs sürücü
engeli veya kurumsal bir sürücü imza politikası olabilir; **Onar** düğmesi
tanı verir.

## Çalışma

**Sistem DNS ayarım değişiyor mu?**
Hayır. DNS yönlendirme paket seviyesindedir (port 53 paketleri motor içinde
güvenilir çözücüye yönlendirilir). Ağ ayarlarınıza dokunulmaz; servis durunca
DNS anında normale döner.

**Servis çökerse internetim kesilir mi?**
Hayır. Fail-open tasarımı (bkz. [architecture.md](architecture.md) §6): motor
bir paketi işleyemezse paket olduğu gibi geçer; süreç ölürse OS sürücü
filtresini kaldırır ve trafik normal yoldan akar. En kötü durumda atlatma
devre dışı kalır, bağlantı kopmaz.

**Bir site hâlâ açılmıyor.**
**Yeniden Tara**'yı deneyin ve **Loglar**'dan test edin. Engel türü **IP** ise
DPI atlatma yetmez (sunucunun IP'si tamamen engellidir); bu yedek yol alanıdır.

**Oyun modu ne yapar?**
UDP yollarını (Discord sesi, oyun trafiği) düşük gecikmeyle önceler.

## Gizlilik ve güvenlik

**Trafiğimi kaydediyor mu / bir yere gönderiyor mu?**
Hayır. Log dosyaya yazım varsayılan kapalıdır; açılırsa loglar yalnızca yerel
`%ProgramData%\Unfilter\logs` altında kalır. Araç hiçbir telemetri göndermez.

**Kaynağına güvenebilir miyim?**
Tüm kod açıktır. İkilileri `rust-toolchain.toml` + `Cargo.lock` ile aynı
toolchain kullanarak kendiniz derleyip (imzadan önceki) yayımlanan SHA-256
değerleriyle karşılaştırabilirsiniz.

## Kaldırma

**Kaldırınca geriye bir şey kalır mı?**
Hayır. Servis, WinDivert sürücü servisi, güvenlik duvarı kuralı, kayıt defteri
girdileri ve tüm dosyalar (ProgramData dahil) silinir. Doğrulamak için
`scripts\verify-clean-uninstall.ps1` (yönetici) — bir iz kalırsa sıfırdan farklı
çıkış kodu döndürür.
