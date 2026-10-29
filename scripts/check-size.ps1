param(
    [string]$Target = "target/release",
    [long]$BudgetBytes = 8MB
)

$ErrorActionPreference = 'Stop'

$files = @()

foreach ($exe in @('unfilter.exe')) {
    $path = Join-Path $Target $exe
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $files += Get-Item -LiteralPath $path
    } else {
        Write-Warning "Missing executable: $path"
    }
}

$assetDir = 'assets/windivert'
if (Test-Path -LiteralPath $assetDir -PathType Container) {
    $files += Get-ChildItem -LiteralPath $assetDir -Recurse -File
}

$configFile = 'config/default.toml'
if (Test-Path -LiteralPath $configFile -PathType Leaf) {
    $files += Get-Item -LiteralPath $configFile
}

if ($files.Count -gt 0) {
    $rows = foreach ($f in $files) {
        [pscustomobject]@{
            Name = $f.Name
            KB   = [math]::Round($f.Length / 1KB, 1)
        }
    }
    $rows | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Warning "No artifacts found."
}

[long]$total = 0
foreach ($f in $files) {
    $total += $f.Length
}

Write-Host ("Total:  {0:N2} MB" -f ($total / 1MB))
Write-Host ("Budget: {0:N2} MB" -f ($BudgetBytes / 1MB))

if ($total -gt $BudgetBytes) {
    Write-Host "FAIL: total size exceeds budget." -ForegroundColor Red
    exit 1
}

Write-Host "OK: total size within budget." -ForegroundColor Green
exit 0
