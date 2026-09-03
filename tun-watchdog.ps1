[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$StateFilePath,
    [int]$StartupGuardSeconds = 45,
    [int]$TimeoutSeconds = 86400,
    [Parameter(Mandatory)] [string]$HeartbeatFilePath,
    [int]$HeartbeatStaleSeconds = 20,
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
$deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
while ($state -and -not $cancelled -and (Test-ExactProcess -State $state)) {
    if (Test-Path -LiteralPath $CancelFilePath) {
        $cancelled = $true
        break
    }
    $heartbeat = Get-Item -LiteralPath $HeartbeatFilePath -ErrorAction SilentlyContinue
    if ($heartbeat -and (([DateTimeOffset]::UtcNow - $heartbeat.LastWriteTimeUtc).TotalSeconds -gt $HeartbeatStaleSeconds)) {
        $heartbeatExpired = $true
        break
    }
    if ([DateTimeOffset]::UtcNow -ge $deadline) { break }
    Start-Sleep -Milliseconds 300
}

$forcedStop = $false
if (-not $cancelled -and (Test-ExactProcess -State $state)) {
    Stop-Process -Id ([int]$state.pid) -Force -ErrorAction SilentlyContinue
    $forcedStop = $true
}
Remove-Item -LiteralPath (Join-Path $runtimeRoot 'mihomo-controller-access.json') -Force -ErrorAction SilentlyContinue

[ordered]@{
    startedAt = $startedAt.ToString('o')
    finishedAt = [DateTimeOffset]::UtcNow.ToString('o')
    cancelled = $cancelled
    heartbeatExpired = $heartbeatExpired
    forcedStop = $forcedStop
} | ConvertTo-Json | Set-Content -LiteralPath $reportPath -Encoding utf8
exit 0
