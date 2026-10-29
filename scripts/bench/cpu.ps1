<#
.SYNOPSIS
    CPU budget measurement -- master prompt section 2, constraints #4/#5
    (docs/perf-budget.md).

.DESCRIPTION
    Samples the CPU time of the unfilter.exe service and tray processes (told
    apart by command line, see roles.ps1), averages it, and normalizes by the
    core count.

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
    Roles of unfilter.exe to measure. Default: service, tray.

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
    [ValidateSet('service', 'tray', 'ui')]
    [string[]]$Processes = @('service', 'tray'),
    [int]$DurationSeconds = 0,
    [int]$IntervalSeconds = 1
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'roles.ps1')

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
    if (@(Get-UnfilterPids -Role $p).Count -gt 0) { $anyRunning = $true }
}
if (-not $anyRunning) {
    Write-Warning ("No process running ({0}). Cannot measure CPU before the service is started." -f ($Processes -join ', '))
    Write-Host "RESULT: pending (full engine / install)."
    exit 2
}

# Locale-independent: sample the summed CPU time (TotalProcessorTime,
# in seconds) of the matching processes and divide the delta by the elapsed
# wall-clock time. That ratio * 100 equals the `% Processor Time` counter --
# core-equivalent percent, 0..100*N -- with no counter-name lookup.
function Measure-WithProcessCpu {
    param([string[]]$Names, [int]$Samples, [int]$Interval)
    function Get-CpuSeconds {
        param([string[]]$Names)
        $sum = 0.0
        foreach ($n in $Names) {
            $ids = @(Get-UnfilterPids -Role $n)
            if ($ids.Count -eq 0) { continue }
            $procs = Get-Process -Id $ids -ErrorAction SilentlyContinue
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

# Per-name counters (typeperf) cannot tell the roles apart -- every mode is
# unfilter.exe -- so sample CPU time per PID.
$stats = Measure-WithProcessCpu -Names $Processes -Samples $sampleCount -Interval $IntervalSeconds
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
