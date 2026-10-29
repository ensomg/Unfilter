# Faz 11: Çalışma zamanı (veri düzlemi) bağlama

| Bileşen | Durum |
| --- | --- |
| Paket motoru çalışma zamanı: WinDivert + `Engine`, strateji yuvası | ✓ |
| Strateji taraması: merdiven + canlı HTTPS probları | ✓ |
| Port-53 yakalama (DoH/DoT'tan cevap enjeksiyonu) | ✓ |
| SCM dispatcher (`StartServiceCtrlDispatcherW`) | ✓ |
| Gerçek "site test" (DNS/TCP/TLS) | ✓ |
| Bench scriptleri tek exe rolleri | ✓ |

## Akış

F10'a kadar "Bağlan" yalnız durum makinesini `Scanning`'e alıyordu; paket motoru
hiç açılmıyor, prober hiçbir adayı denemiyordu. Artık `runtime::Runtime` bir
gözetmen thread'iyle orkestratörün durumunu izler:

- **Scanning:** yakalama başlar (motor öncelik 0, DNS öncelik 1). Her aday motorun
  strateji yuvasına konur, beş hedefe (kategori başına bir) paralel HTTPS probu
  atılır: sistem çözümleyici → TCP 443 → sertifika doğrulamalı TLS (gerçek SNI) →
  `HEAD /` yanıtının ilk baytları. Probların paketleri motordan geçtiği için aktif
  stratejiyi tarayıcı trafiği gibi sınar. Tüm hedeflere ulaşan ilk aday kazanır;
  yoksa en çok hedefe ulaşan (eşitlikte düşük gecikme) kabul edilir; hiçbiri
  ulaşamazsa `Fault`. Skorlar `profiles.json`'a yazılır.
- **Connected:** yakalama aktif stratejiyle çalışır; failover/zorlanmış strateji
  değişiklikleri bir sonraki tikte motora geçer.
- **Ready / Fault:** yakalama durur, handle'lar kapanır, sürücü filtreyi kaldırır.
- Yakalama açılamazsa (yönetici değil / sürücü yok) durum `Fault` olur; `Repair`
  artık taramayı baştan başlatır.

Motor strateji değişikliğini paketler arasında, bir nesil sayacıyla (atomik)
alır; sıcak yolda kilit yok.

## DNS

`dnsproxy` saf bir codec'tir (testli): yakalanan IPv4/IPv6 UDP sorgusunu ayrıştırır,
cevabı uydurur (adres/port takası, `RD` yankısı, `RA`, TTL 60), sağlama
toplamlarını yeniden hesaplanmak üzere sıfır bırakır. Politika: A/AAAA güvenilir
çözümleyiciden; SVCB/HTTPS (64/65) boş NOERROR (zehirli ipuçlarını engeller);
diğer türler ve her hata orijinal sorguyu değiştirmeden geçirir (fail-open).
Çözümleyici politikası tek-thread'li olduğundan DNS thread'i kendi `DnsService`'ini
kurar.

## Servis

`svc::dispatch` SCM'ye kaydolur, Running bildirir; Stop/Shutdown'da Stopped
bildirip süreçten çıkar (çıkış tüm WinDivert handle'larını kapatır → fail-open).
SCM dışında (konsol) `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` ile aynı gövde ön
planda çalışır.

## Tek exe, hız ve arayüz

- Bayraksız çift tıklama: UAC → gömülü WinDivert Program Files'a çıkarılır →
  servis alt süreç olarak (`--service --connect`, kill-on-close job) başlar ve
  hemen bağlanır → pencere + tepsi. Servis günlüğü `%ProgramData%\Unfilter\service.log`.
- Pipe DACL'ına yükseltilmiş Administrators eklendi (servis SYSTEM olmadan da
  örnek açabilsin); accept hatası artık servisi kapatmıyor.
- Hız: DNS sağlık kontrolü açılış yolundan çıkarıldı; tarama probu 2,5 sn
  zaman aşımı ve iki başarısızlıkta erken eleme kullanır; port-53 yakalama 4
  çözümleyici işçisine dağıtılır (kuyruk dolarsa sorgu olduğu gibi geçer).
- Oyun modu kaldırıldı (eski `"game"` değeri Normal olarak okunur).
- Arayüz: durum rengine göre parlayan hale (tararken nefes alır), bağlıyken
  dalga halkaları, onay işaretinin büyüyerek belirmesi, renk geçişleri.
- İlk canlı sonuç (TR ISP): `dns_only` 4/5, `split_sni` 4/5, `split_disorder` 5/5 → bağlandı.

## Açık

- Uçtan uca canlı test (yönetici + WinDivert sürücüsü, TR ISP) yapılmadı.
- Pasif monitör (`record_flow`) henüz motordan beslenmiyor.
- DNS işçilerinin her biri kendi önbelleğini tutar (paylaşılmıyor).
