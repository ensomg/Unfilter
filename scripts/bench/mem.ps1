<#
.SYNOPSIS
    Memory (RAM) budget measurement -- master prompt section 2, constraints
    #1/#2 (docs/perf-budget.md).

.DESCRIPTION
    Samples the Private Working Set of the uf-service and uf-tray processes over
    a time window, reports the maximum, and compares it to the budget.

    Target counter: `\Process(<name>)\Working Set - Private` -- the same value
    Task Manager shows as "Memory (private working set)". For cross-checking,
    Get-Process WorkingSet64 (working set) and PrivateMemorySize64 (private
    bytes / commit) are available but the Private Working Set is authoritative.

    Thresholds (section 2):
      - idle : window closed, idle          -> total <= 25 MB
      - load : window closed, under traffic -> total <= 60 MB

    For the load scenario, generate traffic in a separate window first
    (iperf3 + pcap replay, docs/perf-budget.md line 8); this script only
    measures.

.PARAMETER Mode
    'idle' (default, 25 MB) or 'load' (60 MB). Selects threshold and the
    default sampling duration.

.PARAMETER Processes
    Process names (without extension) to measure. Default: uf-service, uf-tray.
    Note: uf-ui (the window) is intentionally excluded -- the idle/load budget
    is for the window closed.

.PARAMETER DurationSeconds
    Sampling window. Default: idle=300 (5 min), load=600 (10 min).

.PARAMETER IntervalSeconds
    Seconds between samples. Default 1.

.EXAMPLE
    pwsh scripts/bench/mem.ps1 -Mode idle
    pwsh scripts/bench/mem.ps1 -Mode load -DurationSeconds 600

.NOTES
    Exit code: 0 within budget, 1 over budget, 2 process not found
    (binary not installed / not running -> "pending full engine").
#>
[CmdletBinding()]
param(
    [ValidateSet('idle', 'load')]
    [string]$Mode = 'idle',
    [string[]]$Processes = @('uf-service', 'uf-tray'),
    [int]$DurationSeconds = 0,
    [double]$IntervalSeconds = 1
)

$ErrorActionPreference = 'Stop'

if ($Mode -eq 'idle') {
    $budgetBytes = 25MB
    if ($DurationSeconds -le 0) { $DurationSeconds = 300 }
} else {
    $budgetBytes = 60MB
    if ($DurationSeconds -le 0) { $DurationSeconds = 600 }
}

# Private Working Set performance counter. The counter name may be localized;
# if the English path fails we fall back to Get-Process WorkingSet64.
function Get-PrivateWorkingSet {
    param([string]$Name)
    $path = "\Process($Name)\Working Set - Private"
    try {
        $sample = Get-Counter -Counter $path -ErrorAction Stop
        # There may be several instances with the same name; sum them all.
        return ($sample.CounterSamples | Measure-Object -Property CookedValue -Sum).Sum
    } catch {
        # Counter path did not resolve (process gone or localized name):
        # fall back to Get-Process. WorkingSet64 is slightly larger than the
        # private working set (it includes shared pages) -- safe as an upper
        # bound.
        $procs = Get-Process -Name $Name -ErrorAction SilentlyContinue
        if (-not $procs) { return $null }
        return ($procs | Measure-Object -Property WorkingSet64 -Sum).Sum
    }
}

Write-Host ("Mem budget: mode={0}, budget={1:N0} MB, duration={2}s, interval={3}s" -f `
    $Mode, ($budgetBytes / 1MB), $DurationSeconds, $IntervalSeconds)
Write-Host ("Processes: {0}" -f ($Processes -join ', '))

# Verify the processes exist first.
$running = @{}
foreach ($p in $Processes) {
    $found = Get-Process -Name $p -ErrorAction SilentlyContinue
    $running[$p] = [bool]$found
}
$missing = $Processes | Where-Object { -not $running[$_] }
if ($missing.Count -eq $Processes.Count) {
    Write-Warning ("No process running ({0}). Cannot measure before the binary is installed and the service is started." -f ($missing -join ', '))
    Write-Host "RESULT: pending (full engine / install)."
    exit 2
}
if ($missing.Count -gt 0) {
    Write-Warning ("Missing process(es): {0} -- continuing with what is running." -f ($missing -join ', '))
}

$deadline = (Get-Date).AddSeconds($DurationSeconds)
$maxTotal = 0.0
$perProcMax = @{}
foreach ($p in $Processes) { $perProcMax[$p] = 0.0 }
$samples = 0

while ((Get-Date) -lt $deadline) {
    $total = 0.0
    foreach ($p in $Processes) {
        $v = Get-PrivateWorkingSet -Name $p
        if ($null -ne $v) {
            $total += $v
            if ($v -gt $perProcMax[$p]) { $perProcMax[$p] = $v }
        }
    }
    if ($total -gt $maxTotal) { $maxTotal = $total }
    $samples++
    Start-Sleep -Seconds $IntervalSeconds
}

Write-Host ""
Write-Host ("Samples: {0}" -f $samples)
foreach ($p in $Processes) {
    Write-Host ("  {0,-12} peak private working set: {1,8:N2} MB" -f $p, ($perProcMax[$p] / 1MB))
}
Write-Host ("Total peak: {0:N2} MB" -f ($maxTotal / 1MB))
Write-Host ("Budget:     {0:N2} MB" -f ($budgetBytes / 1MB))

if ($maxTotal -gt $budgetBytes) {
    Write-Host "FAIL: memory exceeds budget." -ForegroundColor Red
    exit 1
}
Write-Host "OK: memory within budget." -ForegroundColor Green
exit 0
