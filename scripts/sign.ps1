# Authenticode-sign the Unfilter executables and the installer (master prompt 5.9).
#
# No secret is hard-coded. The signing cert is supplied either as a store
# thumbprint (-Thumbprint, recommended for CI with an HSM/token) or as a .pfx
# file (-PfxPath); the .pfx password is read from the UF_PFX_PASSWORD environment
# variable or prompted securely -- never passed on the command line and never
# written to disk or logs.
#
# Usage:
#   # Sign with a cert already in the certificate store (by SHA-1 thumbprint):
#   powershell -File scripts\sign.ps1 -Thumbprint ABCD...1234
#
#   # Sign with a .pfx file (password from env or secure prompt):
#   $env:UF_PFX_PASSWORD = '...'   # optional; prompted if unset
#   powershell -File scripts\sign.ps1 -PfxPath C:\keys\unfilter.pfx
#
#   # Override what gets signed / the timestamp authority:
#   powershell -File scripts\sign.ps1 -Thumbprint ... -TimestampUrl http://timestamp.digicert.com
#
# PowerShell 5.1 compatible.

[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
param(
    [Parameter(ParameterSetName = 'Thumbprint', Mandatory = $true)]
    [string]$Thumbprint,

    [Parameter(ParameterSetName = 'Pfx', Mandatory = $true)]
    [string]$PfxPath,

    # RFC 3161 timestamp authority (keeps signatures valid after the cert expires).
    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    # Files to sign. Default: the three exes + the built installer.
    [string[]]$Files,

    [string]$ReleaseDir = 'target/release',
    [string]$DistDir = 'dist'
)

$ErrorActionPreference = 'Stop'

# --- Locate signtool.exe ------------------------------------------------------
function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # Fall back to the newest Windows SDK x64 signtool.
    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin"
    )
    foreach ($root in $roots) {
        if (Test-Path -LiteralPath $root) {
            $found = Get-ChildItem -LiteralPath $root -Recurse -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\x64\\' } |
                Sort-Object FullName -Descending |
                Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    throw "signtool.exe bulunamadi. Windows SDK kurun veya PATH'e ekleyin."
}

$signtool = Find-SignTool
Write-Host "signtool: $signtool"

# --- Resolve the file list ----------------------------------------------------
if (-not $Files -or $Files.Count -eq 0) {
    $Files = @(
        (Join-Path $ReleaseDir 'unfilter.exe')
    )
    # Installer (name set in installer\unfilter.iss: OutputBaseFilename).
    if (Test-Path -LiteralPath $DistDir) {
        $setup = Get-ChildItem -LiteralPath $DistDir -Filter 'Unfilter-Setup-*.exe' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($setup) { $Files += $setup.FullName }
    }
}

$missing = $Files | Where-Object { -not (Test-Path -LiteralPath $_) }
if ($missing) {
    throw ("Imzalanacak dosya(lar) yok: {0}. Once 'cargo build --release' ve 'iscc installer\unfilter.iss' calistirin." -f ($missing -join ', '))
}

# --- Build the common signtool arguments --------------------------------------
# /fd sha256  : file digest algorithm
# /tr + /td   : RFC 3161 timestamp (sha256)  -- NOT the legacy /t
$common = @('sign', '/fd', 'sha256', '/tr', $TimestampUrl, '/td', 'sha256', '/v')

if ($PSCmdlet.ParameterSetName -eq 'Thumbprint') {
    # Match the leaf cert in the store by thumbprint; /a as a safety fallback.
    $certArgs = @('/sha1', $Thumbprint)
} else {
    if (-not (Test-Path -LiteralPath $PfxPath)) { throw "PFX yok: $PfxPath" }
    # Password: env var first, else secure prompt. Converted to plain text only
    # in-process, for the single signtool invocation.
    if ($env:UF_PFX_PASSWORD) {
        $pfxPass = $env:UF_PFX_PASSWORD
    } else {
        $secure = Read-Host -AsSecureString "PFX parolasi"
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            $pfxPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    $certArgs = @('/f', $PfxPath, '/p', $pfxPass)
}

# --- Sign each file -----------------------------------------------------------
$failed = $false
foreach ($f in $Files) {
    Write-Host ""
    Write-Host ("Imzalaniyor: {0}" -f $f) -ForegroundColor Cyan
    & $signtool @common @certArgs $f
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("  BASARISIZ (exit {0}): {1}" -f $LASTEXITCODE, $f) -ForegroundColor Red
        $failed = $true
        continue
    }
    # Verify the signature chains and the timestamp is present.
    & $signtool verify /pa /v $f
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("  DOGRULAMA BASARISIZ: {0}" -f $f) -ForegroundColor Red
        $failed = $true
    }
}

# Scrub the password reference.
$pfxPass = $null

if ($failed) {
    Write-Host ""
    Write-Host "Bir veya daha fazla dosya imzalanamadi/dogrulanamadi." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Tum dosyalar imzalandi ve dogrulandi." -ForegroundColor Green
exit 0

# ----------------------------------------------------------------------------
# NOTLAR (master prompt 5.9)
#
# Yeniden-uretilebilir derleme (reproducible build):
#   - Cargo.toml [profile.release]: lto=fat, codegen-units=1, strip=true,
#     panic=abort -> deterministik, kucuk, sembolsuz ikililer.
#   - rust-toolchain.toml toolchain surumunu sabitler; Cargo.lock bagimliliklari
#     sabitler. Ayni toolchain + ayni lock = ayni baytlar.
#   - WinDivert ikilileri scripts\fetch-windivert.ps1 ile SHA-256 sabitlenir
#     (assets\windivert\SHA256SUMS); imzali surucu dogrudan yukari-akistan gelir.
#   - Imzalama baytlari degistirir; bu yuzden SHA-256 "beklenen" degerler
#     imzadan ONCEKI ikililer icin yayimlanir. Kullanicilar kaynaktan ayni
#     ikiliyi uretip imzasiz hash'i karsilastirabilir (ters-muhendislik gerekmez).
#
# SmartScreen itibari:
#   - Yeni imza sertifikasi ("standart" OV) ilk gunlerde SmartScreen uyarisi
#     verebilir; itibar indirme hacmiyle birikir. EV sertifika uyariyi aninda
#     kaldirir ama donanim token'i/HSM gerektirir ve pahalidir.
#   - Her surumde AYNI sertifikayla imzalamak itibari biriktirir; sertifikayi
#     surumler arasi degistirmek itibari sifirlar.
#   - Microsoft'a yanlis-pozitif bildirimi (AV bolumu, README) itibari hizlandirir.
