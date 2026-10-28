# ADR 003 — TLS yığını: rustls + ring

**Durum:** Kabul (Faz 0)

**Karar:** DoH/DoT istemcisi ve probe için `rustls` `ring` kripto sağlayıcısıyla kullanılır (`default-features = false, features = ["ring", "std", "tls12"]`). HTTP/2 için `h2` doğrudan (hyper'sız) değerlendirilir; Faz 3'te boyut ölçülüp karar kesinleşir. QUIC Initial şifre çözme için yine `ring` (AES-128-GCM, HKDF, AES-ECB header protection) kullanılır — ek kripto crate'i yok.

**Gerekçe:**
- rustls'in varsayılanı `aws-lc-rs`, Windows'ta CMake + NASM ister ve ikili boyutu belirgin şekilde büyütür (8 MB bütçesi, §2).
- Schannel (native-tls) SNI'sız / parçalı ClientHello gibi düşük seviye kontrolleri vermez; DoH sağlayıcısına "SNI'sız veya fragmentli bağlantı denemesi" (§5.2) için kendi ClientHello'muzu kontrol etmemiz gerekiyor.
- Kök sertifikalar: `webpki-roots` gömülü yerine Windows sertifika deposu (`rustls-platform-verifier`) değerlendirilecek; boyut açısından daha küçük.
