# Installer

Faz 9 kurulum betikleri. Crate değil (ADR / F0 varsayım V2).

## Inno Setup (tercih edilen) — `unfilter.iss`

Boyut için Inno Setup tercih edildi: tek, küçük bir `.exe` kurucu üretir ve
servis/recovery betiklemesi WiX/MSI'ye göre daha basittir.

Derleme (Inno Setup 6 gerekir, `iscc` PATH'te):

```powershell
# Önkoşullar: release ikilileri ve WinDivert dosyaları yerinde olmalı
cargo build --release -p unfilter
powershell -File scripts\fetch-windivert.ps1        # assets\windivert\ doldurulur

iscc installer\unfilter.iss                         # -> dist\Unfilter-Setup-<sürüm>.exe
powershell -File scripts\sign.ps1 -Thumbprint <...> # (yayın için) imzala
```

### Kurulan dosya düzeni

```
%ProgramFiles%\Unfilter\
  unfilter.exe            # tek ikili: --service (yükseltilmiş servis), --tray, --ui
  WinDivert.dll           # exe'nin YANINDA (LOAD_LIBRARY_SEARCH_APPLICATION_DIR, ADR 002)
  WinDivert64.sys
  config\default.toml     # varsayılan sıfır-yapılandırma profili
  LICENSE, README.md
%ProgramData%\Unfilter\   # çalışma-zamanı veri/log, kullanıcı config.toml
```

### Kurulumun yaptıkları

| Adım | Nasıl |
|---|---|
| Servis kaydı | `sc create Unfilter binPath= "\"...\unfilter.exe\" --service" start= auto` |
| Recovery politikası (§6.4) | `sc failure Unfilter reset= 86400 actions= restart/5000/restart/5000/restart/5000` |
| Güvenlik duvarı (giden DoH/DoT) | `netsh advfirewall firewall add rule name="Unfilter" dir=out ...` |
| Tray oturum açılışında | HKLM `...\Run` değeri `Unfilter Tray` = `"...\unfilter.exe" --tray` (uninsdeletevalue) |

### Kaldırmanın yaptıkları (temiz kaldırma, §2)

| Adım | Nasıl |
|---|---|
| Servisi durdur + sil | `sc stop Unfilter` / `sc delete Unfilter` |
| WinDivert sürücü servisini durdur + sil | `sc stop WinDivert` / `sc delete WinDivert` |
| Güvenlik duvarı kuralını sil | `netsh advfirewall firewall delete rule name="Unfilter"` |
| Kayıt defteri + dosyalar + ProgramData | Inno `[Registry]`/`[UninstallDelete]` |

Doğrulama: `scripts\verify-clean-uninstall.ps1` (kaldırma sonrası, yönetici).

> Not: WinDivert sürücü servisi, `unfilter.exe --service` ilk `WinDivertOpen` çağrısında
> çalışma zamanında oluşur (`WinDivert` adıyla); bu yüzden kaldırıcı onu ayrıca
> durdurup siler.

## WiX / MSI (alternatif)

Kurumsal GPO/SCCM dağıtımı MSI isterse WiX Toolset ile `.msi` üretilebilir.
Aynı dosya düzeni ve aynı servis adı (`Unfilter`) kullanılır:

- Servis: WiX `ServiceInstall` + `ServiceControl` öğeleri (recovery için
  `util:ServiceConfig` ya da bir `sc failure` CustomAction — bu betikteki
  parametrelerin aynısı).
- Güvenlik duvarı: `firewall:FirewallException` (WixFirewallExtension).
- Tray oturum açılışı: `Registry` Run değeri.
- Temiz kaldırma: `ServiceControl Remove="uninstall"`, `RemoveFile`/
  `RemoveFolderEx`, ve WinDivert sürücüsü için bu betikteki `sc delete WinDivert`
  mantığını taşıyan bir CustomAction.

MSI tipik olarak Inno `.exe`'den daha büyüktür; 8 MB bütçesi (§2) için Inno
birincil hedeftir, MSI yalnızca kurumsal gereksinimde.
