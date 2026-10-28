# ADR 002 — WinDivert için kendi ince FFI katmanımız

**Durum:** Kabul (Faz 0)

**Karar:** `windivert` / `windivert-sys` crate'leri yerine `uf-capture` içinde ~10 fonksiyonluk elle yazılmış bir FFI (`WinDivertOpen`, `Recv(Ex)`, `Send(Ex)`, `Shutdown`, `Close`, `HelperCalcChecksums`, `SetParam`) kullanılır. DLL `LoadLibraryExW` + `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` ile yüklenir (DLL hijack önlemi).

**Gerekçe:**
- Tüm `unsafe` tek bir küçük modülde, her blok `// SAFETY:` ile belgelenmiş olur (§5.9).
- Üçüncü parti crate'ler build.rs ile kaynak derleme veya vendored binary getirir; boyut ve tedarik zinciri kontrolü zorlaşır.
- WinDivert 2.2 ABI'si yıllardır sabit.

**Sürüm:** WinDivert 2.2.2 (imzalı sürücü, LGPLv3 / GPLv2). Dinamik bağlanır; Unfilter GPL-3.0-or-later lisanslıdır, uyumlu. İkili dosyalar Faz 1'de resmi sürümden alınır ve SHA-256 ile `assets/windivert/SHA256SUMS` içinde sabitlenir.
