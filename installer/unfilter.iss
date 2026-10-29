; Unfilter — Inno Setup kurulum betiği (Faz 9, §5.9).
;
; Inno Setup tercih edildi: üretilen kurucu tek, küçük bir .exe'dir (LZMA2 ile
; ~1–2 MB ek yük), WiX/MSI'ye göre daha az boyut ve daha basit servis/recovery
; betikleme sağlar. MSI gerekirse (ör. kurumsal GPO dağıtımı) WiX alternatifi
; installer/README.md içinde anlatılır; aynı dosya düzenini ve aynı servis adını
; kullanır, bu betiğin [Run]/[UninstallRun] mantığı WiX CustomAction'lara birebir
; taşınabilir.
;
; Derleme:
;   iscc installer\unfilter.iss        (ISCC.exe = Inno Setup 6 derleyicisi)
; Önkoşul: cargo build --release ve scripts\fetch-windivert.ps1 çalışmış olmalı
; (release ikilileri ve WinDivert dosyaları yerinde olmalı).
;
; TEMİZ KALDIRMA (§2): kaldırma işlemi Unfilter servisini ve WinDivert sürücü
; servisini durdurup siler, güvenlik duvarı kuralını, kayıt defteri anahtarlarını
; ve tüm dosyaları (ProgramData dahil) kaldırır — geriye hiçbir iz bırakmaz.
; scripts\verify-clean-uninstall.ps1 bunu doğrular.

#define AppName "Unfilter"
#define AppVersion "1.0.0"
#define AppPublisher "Unfilter"
#define AppURL "https://github.com/ensomg/Unfilter"
#define ServiceName "Unfilter"
#define ServiceDisplay "Unfilter"
#define ServiceDesc "Unfilter DPI/DNS atlatma motoru (sıfır-yapılandırma)."
#define DriverService "WinDivert"
#define FirewallRule "Unfilter"
#define TrayRunValue "Unfilter Tray"

; Release ikililerinin ve varlıkların bulunduğu kökler (installer\ klasörüne göre).
#define BinDir "..\target\release"
#define AssetDir "..\assets\windivert"
#define ConfigDir "..\config"

[Setup]
; Kalıcı, sabit AppId — sürümler arası yükseltme ve temiz kaldırma için.
AppId={{B7E4F2A1-9C3D-4E5F-A6B8-1D2C3E4F5A6B}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
; Yalnızca x64; WinDivert64.sys ve motor x64'tür.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Servis + sürücü kurulumu yönetici ister.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
OutputDir=..\dist
OutputBaseFilename=Unfilter-Setup-{#AppVersion}
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\unfilter.exe
; Kaldırmada ProgramData izlerini de sil.
LicenseFile=..\LICENSE
; SmartScreen itibarı için kurucu imzalanmalı (bkz. scripts\sign.ps1, §5.9).
; SignTool=... (imzalama derleme sonrası scripts\sign.ps1 ile yapılır)

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "startmenuicon"; Description: "Başlat menüsü kısayolu"; GroupDescription: "Kısayollar:"
Name: "trayatlogin"; Description: "Oturum açılışında arka plan simgesini (tray) başlat"; GroupDescription: "Başlangıç:"

[Files]
; Tek çalıştırılabilir (--service / --tray / --ui bayraklarıyla modlar).
Source: "{#BinDir}\unfilter.exe"; DestDir: "{app}"; Flags: ignoreversion
; WinDivert: exe'nin YANINA kopyalanır ki yükleyici
; LOAD_LIBRARY_SEARCH_APPLICATION_DIR ile bulsun (ADR 002).
Source: "{#AssetDir}\WinDivert.dll";   DestDir: "{app}"; Flags: ignoreversion
Source: "{#AssetDir}\WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion
; Varsayılan yapılandırma ve lisans.
Source: "{#ConfigDir}\default.toml"; DestDir: "{app}\config"; Flags: ignoreversion
Source: "..\LICENSE";                DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";              DestDir: "{app}"; Flags: ignoreversion isreadme

[Dirs]
; Çalışma-zamanı veri/log dizini; kaldırmada [UninstallDelete] siler.
Name: "{commonappdata}\{#AppName}"

[Icons]
Name: "{group}\Unfilter";             Filename: "{app}\unfilter.exe"; Parameters: "--ui"; Tasks: startmenuicon
Name: "{group}\Unfilter'ı Kaldır";    Filename: "{uninstallexe}"

[Registry]
; Tray'i oturum açılışında başlat (per-machine Run anahtarı; kaldırmada silinir).
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "{#TrayRunValue}"; ValueData: """{app}\unfilter.exe"" --tray"; \
    Flags: uninsdeletevalue; Tasks: trayatlogin

[Run]
; 1) Servisi oluştur (otomatik başlangıç, LocalSystem — WinDivert sürücüsü SYSTEM ister).
Filename: "{sys}\sc.exe"; \
    Parameters: "create {#ServiceName} binPath= ""\""{app}\unfilter.exe\"" --service"" start= auto DisplayName= ""{#ServiceDisplay}"""; \
    Flags: runhidden; StatusMsg: "Servis kaydediliyor..."
; 2) Açıklama.
Filename: "{sys}\sc.exe"; \
    Parameters: "description {#ServiceName} ""{#ServiceDesc}"""; \
    Flags: runhidden
; 3) Recovery politikası (§6.4): 1./2./3. hatada 5 sn sonra yeniden başlat, sayaç 1 günde sıfırlanır.
Filename: "{sys}\sc.exe"; \
    Parameters: "failure {#ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000"; \
    Flags: runhidden
; 4) Güvenlik duvarı: servisin giden DoH/DoT bağlantılarına izin (kısıtlı profillerde gerekebilir).
Filename: "{sys}\netsh.exe"; \
    Parameters: "advfirewall firewall add rule name=""{#FirewallRule}"" dir=out action=allow program=""{app}\unfilter.exe"" enable=yes profile=any"; \
    Flags: runhidden; StatusMsg: "Güvenlik duvarı kuralı ekleniyor..."
; 5) Servisi başlat (hata ölümcül değildir; yönetici sonra başlatabilir).
Filename: "{sys}\sc.exe"; \
    Parameters: "start {#ServiceName}"; \
    Flags: runhidden; StatusMsg: "Servis başlatılıyor..."
; 6) Tray'i hemen başlat (kullanıcı yetkisinde, yükseltilmeden).
Filename: "{app}\unfilter.exe"; Parameters: "--tray"; \
    Description: "Unfilter'ı şimdi başlat"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; Sıra: servisleri ÖNCE durdur/sil (dosyalar silinmeden önce çalışır), sonra duvar kuralı.
; WinDivert sürücü servisi, unfilter.exe --service ilk kez WinDivertOpen çağırınca OLUŞUR;
; bu yüzden kaldırmada ayrıca durdurup siliyoruz (varsa).
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}";    Flags: runhidden; RunOnceId: "StopSvc"
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}";  Flags: runhidden; RunOnceId: "DelSvc"
Filename: "{sys}\sc.exe"; Parameters: "stop {#DriverService}";  Flags: runhidden; RunOnceId: "StopDrv"
Filename: "{sys}\sc.exe"; Parameters: "delete {#DriverService}"; Flags: runhidden; RunOnceId: "DelDrv"
Filename: "{sys}\netsh.exe"; \
    Parameters: "advfirewall firewall delete rule name=""{#FirewallRule}"""; \
    Flags: runhidden; RunOnceId: "DelFw"

[UninstallDelete]
; Çalışma-zamanı veri, log ve kullanıcı yapılandırması — geriye iz bırakma.
Type: filesandordirs; Name: "{commonappdata}\{#AppName}"
Type: dirifempty;     Name: "{app}\config"
Type: dirifempty;     Name: "{app}"

[Code]
// Kaldırma başında servisin durması için kısa bekleme (sc stop asenkron).
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    Sleep(1500);
end;
