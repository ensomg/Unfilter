<#
.SYNOPSIS
    CPU budget measurement -- master prompt section 2, constraints #4/#5
    (docs/perf-budget.md).

.DESCRIPTION
    Samples the `% Processor Time` counter of uf-service and uf-tray with
    `typeperf`, averages it, and normalizes by the core count.

    `\Process(<name>)\% Processor Time` is the sum across all cores and tops out
    at 100 * N (N = logical cores). The section 2 threshold is expressed as a
    single-core percentage, so we divide the raw sum by
    [Environment]::ProcessorCount.

    Thresholds (section 2):
      - idle   : idle                  -> < 0.3% (single core)
      - active : 1 Gbit active traffic -> < 3%   (single core)

    In 'active' mode, generate 1 Gbit replay/iperf3 in a separate window first
    (docs/perf-budget.md line 11); this script only measures.

.PARAMETER Mode
    'idle' (default, 0.3%) or 'active' (3%).

.PARAMETER Processes
    Process names (without extension) to measure. Default: uf-service, uf-tray.

.PARAMETER DurationSeconds
    Total sampling duration. Default: idle=300, active=120.

.PARAMETER IntervalSeconds
    typeperf sampling interval in seconds. Default 1.

.EXAMPLE
    pwsh scripts/bench/cpu.ps1 -Mode idle
    pwsh scripts/bench/cpu.ps1 -Mode active -DurationSeconds 120

.NOTES
    Exit code: 0 within budget, 1 over budget, 2 process not found
    (pending full engine).
#>
[CmdletBinding()]
param(
    [ValidateSet('idle', 'active')]
    [string]$Mode = 'idle',
    [string[]]$Processes = @('uf-service', 'uf-tray'),
    [int]$DurationSeconds = 0,
    [int]$IntervalSeconds = 1
)

$ErrorActionPreference = 'Stop'

if ($Mode -eq 'idle') {
    $budgetPercent = 0.3
    if ($DurationSeconds -le 0) { $DurationSeconds = 300 }
} else {
    $budgetPercent = 3.0
    if ($DurationSeconds -le 0) { $DurationSeconds = 120 }
}

$cores = [Environment]::ProcessorCount
$sampleCount = [math]::Max(1, [int]($DurationSeconds / $IntervalSeconds))

Write-Host ("CPU budget: mode={0}, threshold={1}%, duration={2}s, interval={3}s, cores={4}" -f `
    $Mode, $budgetPercent, $DurationSeconds, $IntervalSeconds, $cores)
Write-Host ("Processes: {0}" -f ($Processes -join ', '))

# Process check -- nothing to measure if none are running.
$anyRunning = $false
foreach ($p in $Processes) {
    if (Get-Process -Name $p -ErrorAction SilentlyContinue) { $anyRunning = $true }
}
if (-not $anyRunning) {
    Write-Warning ("No process running ({0}). Cannot measure CPU before the service is started." -f ($Processes -join ', '))
    Write-Host "RESULT: pending (full engine / install)."
    exit 2
}

# typeperf counter paths. '% Processor Time' is localized on non-English
# Windows (e.g. Turkish), where typeperf/Get-Counter by English name fail; the
# robust fallback below reads CPU time from Get-Process instead, which needs no
# counter names.
$counters = $Processes | ForEach-Object { "\Process($_)\% Processor Time" }

function Measure-WithTypeperf {
    param([string[]]$Counters, [int]$Samples, [int]$Interval)
    $tpArgs = @()
    foreach ($c in $Counters) { $tpArgs += "`"$c`"" }
    $tpArgs += @('-si', $Interval, '-sc', $Samples)
    # typeperf writes CSV: first line is the header, following lines are
    # samples. The first column is a timestamp. A missing process reads as ""
    # or 0.
    $raw = & typeperf @tpArgs 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
    $lines = $raw | Where-Object { $_ -match '^"' }
    if ($lines.Count -lt 2) { return $null }
    $rowTotals = @()
    foreach ($line in ($lines | Select-Object -Skip 1)) {
        $cells = $line -split '","' | ForEach-Object { $_.Trim('"') }
        # cells[0] = timestamp; the rest are counter values.
        $sum = 0.0
        for ($i = 1; $i -lt $cells.Count; $i++) {
            $val = 0.0
            if ([double]::TryParse($cells[$i], [ref]$val)) { $sum += $val }
        }
        $rowTotals += $sum
    }
    if ($rowTotals.Count -eq 0) { return $null }
    return ($rowTotals | Measure-Object -Average -Maximum)
}

# Locale-independent fallback: sample the summed CPU time (TotalProcessorTime,
# in seconds) of the matching processes and divide the delta by the elapsed
# wall-clock time. That ratio * 100 equals the `% Processor Time` counter --
# core-equivalent percent, 0..100*N -- with no counter-name lookup.
function Measure-WithProcessCpu {
    param([string[]]$Names, [int]$Samples, [int]$Interval)
    function Get-CpuSeconds {
        param([string[]]$Names)
        $sum = 0.0
        foreach ($n in $Names) {
            $procs = Get-Process -Name $n -ErrorAction SilentlyContinue
            if ($procs) {
                $sum += ($procs | Measure-Object -Property CPU -Sum).Sum
            }
        }
        return $sum
    }
    $prevCpu = Get-CpuSeconds -Names $Names
    $prevTime = Get-Date
    $rowTotals = @()
    for ($s = 0; $s -lt $Samples; $s++) {
        Start-Sleep -Seconds $Interval
        $nowCpu = Get-CpuSeconds -Names $Names
        $nowTime = Get-Date
        $wall = ($nowTime - $prevTime).TotalSeconds
        if ($wall -gt 0) {
            $rowTotals += (($nowCpu - $prevCpu) / $wall) * 100.0
        }
        $prevCpu = $nowCpu
        $prevTime = $nowTime
    }
    if ($rowTotals.Count -eq 0) { return $null }
    return ($rowTotals | Measure-Object -Average -Maximum)
}

$stats = Measure-WithTypeperf -Counters $counters -Samples $sampleCount -Interval $IntervalSeconds
if ($null -eq $stats) {
    Write-Warning "typeperf unavailable (localized counters?) -- using Get-Process CPU time."
    $stats = Measure-WithProcessCpu -Names $Processes -Samples $sampleCount -Interval $IntervalSeconds
}
if ($null -eq $stats) {
    Write-Warning "Could not read CPU counters."
    Write-Host "RESULT: pending (full engine / install)."
    exit 2
}

# Raw value is core-equivalent percent (0..100*N). Normalize by core count as
# docs/perf-budget.md specifies (raw / ProcessorCount).
$avgNorm = $stats.Average / $cores
$maxNorm = $stats.Maximum / $cores

Write-Host ""
Write-Host ("Raw core-equivalent: avg {0:N3}%  peak {1:N3}%  (0..{2}%)" -f $stats.Average, $stats.Maximum, (100 * $cores))
Write-Host ("Normalized (raw/{0}): avg {1:N3}%  peak {2:N3}%" -f $cores, $avgNorm, $maxNorm)
Write-Host ("Threshold (normalized avg): {0:N3}%" -f $budgetPercent)

if ($avgNorm -gt $budgetPercent) {
    Write-Host "FAIL: average CPU exceeds threshold." -ForegroundColor Red
    exit 1
}
Write-Host "OK: CPU within budget." -ForegroundColor Green
exit 0
