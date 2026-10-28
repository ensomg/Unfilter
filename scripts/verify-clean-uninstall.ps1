# Verify that uninstalling Unfilter left no trace (master prompt "temiz kaldirma").
#
# Run as administrator AFTER uninstalling. Scans for every artifact the installer
# can create -- the Unfilter service, the WinDivert driver service, installed
# files, the ProgramData data dir, registry keys (uninstall entry + Run value)
# and the firewall rule -- and exits non-zero if ANYTHING remains.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\verify-clean-uninstall.ps1
#
# PowerShell 5.1 compatible (no ternary / null-coalescing).

[CmdletBinding()]
param(
    [string]$AppName = 'Unfilter',
    [string]$ServiceName = 'Unfilter',
    [string]$DriverService = 'WinDivert',
    [string]$FirewallRule = 'Unfilter',
    [string]$TrayRunValue = 'Unfilter Tray'
)

$ErrorActionPreference = 'Stop'

# Each found trace is appended here; a non-empty list means "not clean".
$traces = New-Object System.Collections.Generic.List[string]

function Add-Trace([string]$msg) {
    $traces.Add($msg)
    Write-Host ("  [KALDI] {0}" -f $msg) -ForegroundColor Red
}

function Test-ServiceGone([string]$name) {
    # sc.exe query is the authority; Get-Service can lag. 1060 == does not exist.
    $null = & "$env:SystemRoot\System32\sc.exe" query $name 2>$null
    if ($LASTEXITCODE -ne 1060) {
        Add-Trace ("servis hala kayitli: {0} (sc query exit {1})" -f $name, $LASTEXITCODE)
    }
}

Write-Host "Unfilter temiz-kaldirma dogrulamasi..." -ForegroundColor Cyan

# 1) Unfilter servisi.
Test-ServiceGone $ServiceName

# 2) WinDivert surucu servisi.
Test-ServiceGone $DriverService

# 3) Surucu dosyasi hala yuklu mu (nadiren sc delete sonrasi .sys kalir).
$sysFile = Join-Path $env:SystemRoot 'System32\drivers\WinDivert64.sys'
if (Test-Path -LiteralPath $sysFile) {
    Add-Trace ("surucu dosyasi: {0}" -f $sysFile)
}

# 4) Kurulum dizini (Program Files\Unfilter).
$installDirs = @(
    (Join-Path $env:ProgramFiles $AppName)
)
if (${env:ProgramFiles(x86)}) {
    $installDirs += (Join-Path ${env:ProgramFiles(x86)} $AppName)
}
foreach ($d in $installDirs) {
    if (Test-Path -LiteralPath $d) {
        Add-Trace ("kurulum dizini: {0}" -f $d)
    }
}

# 5) ProgramData veri/log dizini.
$dataDir = Join-Path $env:ProgramData $AppName
if (Test-Path -LiteralPath $dataDir) {
    Add-Trace ("veri dizini: {0}" -f $dataDir)
}

# 6) Kayit defteri: kaldirma anahtari (AppId_is1) ve varyantlari.
$uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach ($root in $uninstallRoots) {
    if (Test-Path -LiteralPath $root) {
        $keys = Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue
        foreach ($k in $keys) {
            $dn = (Get-ItemProperty -LiteralPath $k.PSPath -Name 'DisplayName' -ErrorAction SilentlyContinue).DisplayName
            if ($dn -and $dn -like "*$AppName*") {
                Add-Trace ("kaldirma kayit anahtari: {0} ({1})" -f $k.PSChildName, $dn)
            }
        }
    }
}

# 7) Kayit defteri: tray Run degeri (HKLM ve HKCU).
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($rk in $runKeys) {
    if (Test-Path -LiteralPath $rk) {
        $prop = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
        if ($prop -and ($prop.PSObject.Properties.Name -contains $TrayRunValue)) {
            Add-Trace ("Run degeri: {0}\{1}" -f $rk, $TrayRunValue)
        }
    }
}

# 8) Guvenlik duvari kurali.
$fw = & "$env:SystemRoot\System32\netsh.exe" advfirewall firewall show rule name="$FirewallRule" 2>$null
if ($LASTEXITCODE -eq 0) {
    Add-Trace ("guvenlik duvari kurali: {0}" -f $FirewallRule)
}

Write-Host ""
if ($traces.Count -eq 0) {
    Write-Host "TEMIZ: Unfilter'dan geriye hicbir iz kalmadi." -ForegroundColor Green
    exit 0
}

Write-Host ("KIRLI: {0} iz bulundu (yukarida)." -f $traces.Count) -ForegroundColor Red
exit 1
