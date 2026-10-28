$ErrorActionPreference = 'Stop'

$tree = & cargo tree -p uf-core -e normal --prefix none
if ($LASTEXITCODE -ne 0) {
    Write-Host "cargo tree failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}

$offenders = @($tree | Where-Object { $_ -match '^(windows|winapi|tokio)' })

if ($offenders.Count -gt 0) {
    Write-Host "uf-core has OS-specific or runtime dependencies:" -ForegroundColor Red
    foreach ($line in $offenders) {
        Write-Host "  $line"
    }
    exit 1
}

Write-Host "uf-core is OS-independent"
exit 0
