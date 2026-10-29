# Shared by mem.ps1 / cpu.ps1. Since F10 every mode runs from one binary
# (unfilter.exe), so the process name no longer tells the service from the
# tray; the command line does (`--service`, `--tray`, `--ui`; no flag = tray).

# PIDs of the unfilter.exe processes running in the given role.
function Get-UnfilterPids {
    param([ValidateSet('service', 'tray', 'ui')][string]$Role)
    $procs = Get-CimInstance Win32_Process -Filter "Name = 'unfilter.exe'" -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $cmd = [string]$p.CommandLine
        $procRole = if ($cmd -match '--service') { 'service' }
                elseif ($cmd -match '--ui') { 'ui' }
                else { 'tray' }
        if ($procRole -eq $Role) { [int]$p.ProcessId }
    }
}
