[CmdletBinding()]
param([switch]$Elevated)

$ErrorActionPreference = 'SilentlyContinue'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
        '-File', ('"{0}"' -f $PSCommandPath), '-Elevated'
    )
    $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
    exit $process.ExitCode
}

$runtimeRoot = Join-Path $env:LOCALAPPDATA 'v2rayn-tun-controller'
$statePath = Join-Path $runtimeRoot 'mihomo-runtime-state.json'
$knownCorePath = Join-Path $runtimeRoot 'mihomo-controller.exe'
$safetyRefused = $false

if (Test-Path -LiteralPath $statePath) {
    try {
        $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
        $process = Get-Process -Id ([int]$state.pid) -ErrorAction SilentlyContinue
        if ($process) {
            $sameStart = $process.StartTime.ToUniversalTime().Ticks -eq [long]$state.startTimeUtcTicks
            $samePath = $process.Path -and
                $process.Path.Equals($knownCorePath, [StringComparison]::OrdinalIgnoreCase) -and
                ([string]$state.executablePath).Equals($knownCorePath, [StringComparison]::OrdinalIgnoreCase)
            $ownsExpectedPort = [bool](
                Get-NetTCPConnection -State Listen -LocalPort ([int]$state.expectedPort) -ErrorAction SilentlyContinue |
                    Where-Object OwningProcess -eq $process.Id
            )
            if ($sameStart -and $samePath -and $ownsExpectedPort) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            } else {
                $safetyRefused = $true
            }
        }
    } catch {
        $safetyRefused = $true
    }
}

$deadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
do {
    $adapterUp = [bool](Get-NetAdapter -Name 'mihomo_tun_controller' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')
    if (-not $adapterUp) { break }
    Start-Sleep -Milliseconds 300
} while ([DateTimeOffset]::UtcNow -lt $deadline)

if (-not $adapterUp) {
    Remove-Item -LiteralPath (Join-Path $runtimeRoot 'mihomo-controller-access.json') -Force -ErrorAction SilentlyContinue
}

if ($safetyRefused) { exit 4 }
if ($adapterUp) { exit 3 }
exit 0
