# İmzalı sürüm yayınlama (otomatik güncelleme)

Unfilter, GitHub Releases'taki en son sürümü (`releases/latest`) denetler ve
yalnızca **imzalı** sürümleri kurar. Bir sürümde iki dosya bulunmalıdır:

| Asset | İçerik |
|---|---|
| `unfilter.exe` | Release derlemesi |
| `unfilter.exe.sig` | Sürüm numarası ve exe'nin SHA-256 özetini kapsayan, hex biçiminde Ed25519 imzası |

`.sig` dosyası olmayan ya da imzası geçersiz olan sürümler reddedilir. İmza sürüm
numarasını da kapsadığı için eski bir imzalı exe, yeni bir etiket altında yeniden
yayınlanamaz (sürüm düşürme koruması).

## Anahtar

İmzalama anahtarı repoda **bulunmaz**: `%USERPROFILE%\.unfilter\update-signing.key`.
Açık anahtar `crates/uf-update/src/lib.rs` içindeki `PUBLIC_KEY` sabitindedir.
Anahtar kaybolursa yeni bir anahtar üretilmeli, `PUBLIC_KEY` güncellenmelidir ve
eski sürümleri kullananlar bir kez elle güncelleme yapmak zorunda kalır. Anahtarı
yedekleyin ve kimseyle paylaşmayın.

```powershell
# yalnızca bir kez (anahtar dosyası varsa üzerine yazmaz)
cargo run -p uf-update --bin uf-release -- keygen $HOME\.unfilter\update-signing.key
```

## Sürüm adımları

1. `Cargo.toml` içindeki `[workspace.package] version` değerini artır (ör. `1.1.0`).
2. `cargo build --release -p unfilter`
3. İmzala:
   ```powershell
   cargo run -p uf-update --bin uf-release -- sign $HOME\.unfilter\update-signing.key 1.1.0 target\release\unfilter.exe
   ```
4. `v1.1.0` etiketiyle bir GitHub Release oluştur; `unfilter.exe` ve
   `unfilter.exe.sig` dosyalarını ekle. Etiket, imzadaki sürümle aynı olmalıdır.
   Ön sürüm (pre-release) olarak işaretlenen sürümler kurulmaz.

## İstemci davranışı

- **Çift tıklamayla açılan uygulama (yönetici):** açılıştan 30 sn sonra, sonra 12
  saatte bir arka planda denetler ve kurar. Yeni sürüm bir sonraki açılışta devreye girer.
- **Pencere:** açılışta denetler. Yeni sürüm varsa bildirim gösterir; Ayarlar →
  Güncellemeler → *Güncelle* `unfilter.exe --update` komutunu UAC ile çalıştırır.
- Kurulum, çalışan exe'yi `unfilter.exe.old` adıyla kenara alıp yenisini aynı yere
  koyar. `.old` dosyası, onu kullanan süreç kalmadığında silinir.
- `--update` çıkış kodları: `0` kuruldu, `1` hata, `2` güncel, `3` yeniden başlatma bekliyor.
