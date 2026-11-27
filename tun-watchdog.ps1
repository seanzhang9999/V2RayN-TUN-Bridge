[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$StateFilePath,
    [int]$StartupGuardSeconds = 45,
    # 0 (default) means no lifetime cap. A positive value is a renewal window, not a
    # death sentence: on expiry the guard exits and the supervisor starts a new one,
    # while the core keeps running.
    [int]$TimeoutSeconds = 0,
    [Parameter(Mandatory)] [string]$HeartbeatFilePath,
    [int]$HeartbeatStaleSeconds = 20,
    [int]$HeartbeatConfirmSeconds = 30,
    [Parameter(Mandatory)] [string]$CancelFilePath,
    [string]$ReportFileName = 'mihomo-runtime-watchdog-report.json'
)

$ErrorActionPreference = 'SilentlyContinue'
$runtimeRoot = Join-Path $env:LOCALAPPDATA 'v2rayn-tun-controller'
$knownStatePath = Join-Path $runtimeRoot 'mihomo-runtime-state.json'
$knownCorePath = Join-Path $runtimeRoot 'mihomo-controller.exe'
$reportPath = Join-Path $runtimeRoot $ReportFileName
$startedAt = [DateTimeOffset]::UtcNow

function Read-VerifiedState {
    if (-not ([IO.Path]::GetFullPath($StateFilePath)).Equals([IO.Path]::GetFullPath($knownStatePath), [StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
    if (-not (Test-Path -LiteralPath $StateFilePath)) { return $null }
    try {
        $state = Get-Content -Raw -LiteralPath $StateFilePath | ConvertFrom-Json
        if (([string]$state.executablePath).Equals($knownCorePath, [StringComparison]::OrdinalIgnoreCase) -and
            ([string]$state.adapterName) -eq 'mihomo_tun_controller' -and
            ([int]$state.expectedPort) -in @(1081, 1082)) {
            return $state
        }
    } catch {}
    return $null
}

function Test-ExactProcess([object]$State) {
    if (-not $State) { return $false }
    $process = Get-Process -Id ([int]$State.pid) -ErrorAction SilentlyContinue
    if (-not $process -or -not $process.Path) { return $false }
    $sameStart = $process.StartTime.ToUniversalTime().Ticks -eq [long]$State.startTimeUtcTicks
    $samePath = $process.Path.Equals($knownCorePath, [StringComparison]::OrdinalIgnoreCase)
    return $sameStart -and $samePath
}

$state = $null
$startupDeadline = [DateTimeOffset]::UtcNow.AddSeconds($StartupGuardSeconds)
do {
    if (Test-Path -LiteralPath $CancelFilePath) { break }
    $state = Read-VerifiedState
    if ($state) { break }
    Start-Sleep -Milliseconds 200
} while ([DateTimeOffset]::UtcNow -lt $startupDeadline)

$cancelled = Test-Path -LiteralPath $CancelFilePath
$heartbeatExpired = $false
$lifetimeExpired = $false
$staleObservedAt = $null
$deadline = if ($TimeoutSeconds -gt 0) { [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds) } else { $null }
while ($state -and -not $cancelled -and (Test-ExactProcess -State $state)) {
    if (Test-Path -LiteralPath $CancelFilePath) {
        $cancelled = $true
        break
    }
    $heartbeat = Get-Item -LiteralPath $HeartbeatFilePath -ErrorAction SilentlyContinue
    $now = [DateTimeOffset]::UtcNow
    $heartbeatFresh = $heartbeat -and (($now - $heartbeat.LastWriteTimeUtc).TotalSeconds -le $HeartbeatStaleSeconds)
    if ($heartbeatFresh) {
        $staleObservedAt = $null
    } elseif (-not $staleObservedAt) {
        # A laptop sleep/resume pauses both the supervisor and its heartbeat.
        # Give the supervisor a full confirmation window to recover after wake.
        $staleObservedAt = $now
    } elseif (($now - $staleObservedAt).TotalSeconds -ge $HeartbeatConfirmSeconds) {
        $heartbeatExpired = $true
        break
    }
    if ($deadline -and $now -ge $deadline) {
        $lifetimeExpired = $true
        break
    }
    Start-Sleep -Milliseconds 300
}

$coreRunning = [bool](Test-ExactProcess -State $state)
$forcedStop = $false
if (-not $cancelled -and -not $lifetimeExpired -and $coreRunning) {
    # Stop only an orphaned core: one whose supervisor stopped proving it is alive.
    Stop-Process -Id ([int]$state.pid) -Force -ErrorAction SilentlyContinue
    $forcedStop = $true
    $coreRunning = $false
}
if ($forcedStop -or ($state -and -not $coreRunning)) {
    # Only withdraw the credentials once the core they describe is gone. A renewal
    # leaves a running core behind, and a guard that never attached knows nothing.
    Remove-Item -LiteralPath (Join-Path $runtimeRoot 'mihomo-controller-access.json') -Force -ErrorAction SilentlyContinue
}

$report = [ordered]@{
    startedAt = $startedAt.ToString('o')
    finishedAt = [DateTimeOffset]::UtcNow.ToString('o')
    corePid = if ($state) { [int]$state.pid } else { $null }
    cancelled = $cancelled
    heartbeatExpired = $heartbeatExpired
    lifetimeExpired = $lifetimeExpired
    staleConfirmationSeconds = $HeartbeatConfirmSeconds
    forcedStop = $forcedStop
    coreStillRunning = $coreRunning
    reason = if ($heartbeatExpired) { 'heartbeat-timeout' } elseif ($lifetimeExpired) { 'lifetime-expired' } elseif ($forcedStop) { 'forced-stop' } elseif ($cancelled) { 'cancelled' } else { 'core-exited' }
}
if ($lifetimeExpired -and $coreRunning) {
    # Renewal, not termination: leave no verdict behind for a core that is still up,
    # otherwise a later exit would inherit this stale report.
    Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
} else {
    $report | ConvertTo-Json | Set-Content -LiteralPath $reportPath -Encoding utf8
}
exit 0
