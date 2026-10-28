# Fetch the signed WinDivert 2.2 binaries and verify them against SHA256SUMS.
#
# Usage:
#   scripts/fetch-windivert.ps1            # download, verify (or record) hashes
#   scripts/fetch-windivert.ps1 -Record   # (re)write SHA256SUMS from downloads
#
# No hash is hard-coded here: on first run with -Record the script writes the
# SHA-256 of what it downloaded into assets/windivert/SHA256SUMS. Commit that
# file; afterwards the script fails if the bytes ever differ.

param(
    [string]$Version = "2.2.2",
    [switch]$Record
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root 'assets/windivert'
$sumsFile = Join-Path $dest 'SHA256SUMS'
$tmp = Join-Path $env:TEMP "windivert-$Version.zip"

$url = "https://github.com/basil00/WinDivert/releases/download/v$Version/WinDivert-$Version-A.zip"
$wanted = @('WinDivert.dll', 'WinDivert64.sys')

Write-Host "Downloading WinDivert $Version ..."
Invoke-WebRequest -Uri $url -OutFile $tmp

$extract = Join-Path $env:TEMP "windivert-$Version"
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
Expand-Archive -Path $tmp -DestinationPath $extract

New-Item -ItemType Directory -Force -Path $dest | Out-Null
$lines = @()
foreach ($name in $wanted) {
    $src = Get-ChildItem -Path $extract -Recurse -Filter $name |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Select-Object -First 1
    if (-not $src) { throw "could not find $name (x64) in the archive" }
    Copy-Item $src.FullName (Join-Path $dest $name) -Force
    $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $dest $name)).Hash.ToLower()
    $lines += "$hash  $name"
    Write-Host "  $name  $hash"
}

if ($Record -or -not (Test-Path $sumsFile)) {
    Set-Content -Path $sumsFile -Value $lines -Encoding ascii
    Write-Host "Recorded hashes to SHA256SUMS."
} else {
    $expected = Get-Content $sumsFile
    if (Compare-Object $expected $lines) {
        throw "SHA256 mismatch against committed SHA256SUMS -- refusing."
    }
    Write-Host "Verified against SHA256SUMS."
}
