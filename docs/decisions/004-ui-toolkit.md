# ADR 004 — UI: slint (software renderer), tray: saf Win32

**Durum:** Kabul (Faz 0), Faz 6'da boyut ölçümüyle doğrulanır

**Karar:**
- `uf-ui`: `slint`, `renderer-software` + `backend-winit`; femtovg/skia ve OpenGL kapalı. Pencere 360×620 sabit, DWM koyu başlık çubuğu `DwmSetWindowAttribute(DWMWA_USE_IMMERSIVE_DARK_MODE)`.
- `uf-tray`: slint kullanmaz. `windows-sys` ile `Shell_NotifyIconW` + gizli mesaj penceresi. Hedef < 4 MB RAM, < 300 KB exe.

**Gerekçe:**
- Tray her zaman açık; GUI toolkit yüklemek boşta RAM bütçesini (§2: tray ≤ 8 MB) boşa harcar.
- slint software renderer GPU sürücüsü yüklemez (ek 20–40 MB RAM önlenir) ve açılış < 300 ms hedefine uygundur.
- egui yedek seçenek: slint boyut ölçümü (Faz 6) bütçeyi aşarsa egui + glow yerine egui + softbuffer denenir.

**Risk:** slint + winit statik bağlandığında ~3–4 MB exe. Dağıtım bütçesinin en büyük kalemi; Faz 0 baseline'ı ve Faz 6 ölçümü raporlanır.
