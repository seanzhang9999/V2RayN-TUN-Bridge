[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Start', 'Stop', 'Restart', 'Status')]
    [string]$Action,
    [ValidatePattern('^[A-Za-z0-9._-]{1,128}$')]
    [string]$ProfileId,
    [string]$AppRoot = '',
    [string]$AppExecutable = '',
    [switch]$ManualV2rayN,
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RuntimeRoot = Join-Path $env:LOCALAPPDATA 'v2rayn-tun-controller'
$StatusPath = Join-Path $RuntimeRoot 'mihomo-runtime-report.json'
$StopRequestPath = Join-Path $RuntimeRoot 'mihomo-runtime-stop.txt'
$SupervisorStdout = Join-Path $RuntimeRoot 'mihomo-supervisor-stdout.log'
$SupervisorStderr = Join-Path $RuntimeRoot 'mihomo-supervisor-stderr.log'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($Action -ne 'Status' -and -not (Test-IsAdministrator)) {
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-WindowStyle',
        'Hidden',
        '-File',
        ('"{0}"' -f $PSCommandPath),
        '-Action',
        $Action,
        '-Elevated'
    )
    if ($ManualV2rayN) { $arguments += '-ManualV2rayN' }
    if ($ProfileId) { $arguments += @('-ProfileId', $ProfileId) }
    if ($AppRoot) { $arguments += @('-AppRoot', ('"{0}"' -f $AppRoot)) }
    if ($AppExecutable) { $arguments += @('-AppExecutable', ('"{0}"' -f $AppExecutable)) }
    try {
        $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -WindowStyle Hidden -PassThru
    } catch {
        exit 5
    }
    $process.WaitForExit()
    $process.Refresh()
    exit $process.ExitCode
}

function Protect-RuntimeRoot {
    New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $RuntimeRoot /inheritance:r /grant:r "${currentUser}:(OI)(CI)F" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'runtime-acl-failed' }
}

function Move-PreviousDiagnostic([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $directory = Split-Path -Parent $Path
    $name = [IO.Path]::GetFileNameWithoutExtension($Path)
    $extension = [IO.Path]::GetExtension($Path)
    $previous = Join-Path $directory ("{0}.previous{1}" -f $name, $extension)
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        try {
            Remove-Item -LiteralPath $previous -Force -ErrorAction SilentlyContinue
            Move-Item -LiteralPath $Path -Destination $previous -Force -ErrorAction Stop
            return
        } catch {
            Start-Sleep -Milliseconds (50 * ($attempt + 1))
        }
    }
}

function Read-SafeStatus {
    if (-not (Test-Path -LiteralPath $StatusPath)) { return $null }
    try {
        return Get-Content -Raw -LiteralPath $StatusPath | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Test-SupervisorRunning([object]$Status) {
    if (-not $Status -or -not $Status.supervisorPid) { return $false }
    return [bool](Get-Process -Id ([int]$Status.supervisorPid) -ErrorAction SilentlyContinue)
}

if ($Action -eq 'Status') {
    $status = Read-SafeStatus
    if ($status) {
        $status | ConvertTo-Json -Depth 10
        if ($status.state -eq 'running' -and (Test-SupervisorRunning -Status $status)) { exit 0 }
    } else {
        [ordered]@{ mode = 'mihomo-daily-tun'; state = 'not-started' } | ConvertTo-Json
    }
    exit 1
}

Protect-RuntimeRoot

if ($Action -eq 'Restart') {
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $PSCommandPath -Action Stop -AppRoot $AppRoot -Elevated
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $restartArguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-WindowStyle', 'Hidden', '-File', ('"{0}"' -f $PSCommandPath),
        '-Action', 'Start', '-AppRoot', ('"{0}"' -f $AppRoot), '-Elevated'
    )
    if ($ManualV2rayN) { $restartArguments += '-ManualV2rayN' }
    if ($ProfileId) { $restartArguments += @('-ProfileId', ('"{0}"' -f $ProfileId)) }
    if ($AppExecutable) { $restartArguments += @('-AppExecutable', ('"{0}"' -f $AppExecutable)) }
    $restart = Start-Process -FilePath 'powershell.exe' -ArgumentList $restartArguments -WindowStyle Hidden -Wait -PassThru
    exit $restart.ExitCode
}

if ($Action -eq 'Start') {
    $AppRoot = (Resolve-Path -LiteralPath $AppRoot -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath (Join-Path $AppRoot 'v2rayN.exe') -PathType Leaf)) {
        throw 'invalid-v2rayn-root'
    }
    $existing = Read-SafeStatus
    if ($existing -and $existing.state -eq 'running' -and (Test-SupervisorRunning -Status $existing)) {
        exit 0
    }
    Move-PreviousDiagnostic -Path $StatusPath
    Move-PreviousDiagnostic -Path $SupervisorStdout
    Move-PreviousDiagnostic -Path $SupervisorStderr
    Remove-Item -LiteralPath $StopRequestPath -Force -ErrorAction SilentlyContinue
    Write-Host '[1/3] Reading the selected v2rayN node and physical network...'
    $arguments = @(
        '--runtime-root', ('"{0}"' -f $RuntimeRoot),
        '--app-root', ('"{0}"' -f $AppRoot),
        '--script-root', ('"{0}"' -f $ScriptRoot)
    )
    if ($ManualV2rayN) { $arguments += '--manual-v2rayn' }
    if ($ProfileId) { $arguments += @('--profile-id', ('"{0}"' -f $ProfileId)) }
    if ($AppExecutable) {
        $arguments = @('--supervisor') + $arguments
        $supervisorPath = (Resolve-Path -LiteralPath $AppExecutable -ErrorAction Stop).Path
    } else {
        $env:PYTHONPATH = Join-Path $ScriptRoot 'src'
        $supervisorPath = (Get-Command python -ErrorAction Stop).Source
        $arguments = @('-m', 'tun_controller.mihomo_supervisor') + $arguments
    }
    $supervisor = Start-Process -FilePath $supervisorPath -ArgumentList $arguments -WorkingDirectory $ScriptRoot -WindowStyle Hidden -RedirectStandardOutput $SupervisorStdout -RedirectStandardError $SupervisorStderr -PassThru
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(100)
    $lastCheckpoint = ''
    do {
        $status = Read-SafeStatus
        if ($status -and $status.supervisorPid -eq $supervisor.Id) {
            if ($status.checkpoint -and $status.checkpoint -ne $lastCheckpoint) {
                $lastCheckpoint = [string]$status.checkpoint
                Write-Host (('[2/3] {0}...' -f $lastCheckpoint))
            }
            if ($status.state -eq 'running') {
                Write-Host '[3/3] Mihomo TUN is running. Website checks are informational only.'
                exit 0
            }
            if ($status.state -eq 'failed') {
                Write-Host (('Start failed safely at: {0}' -f $status.errorCheckpoint))
                exit 2
            }
        }
        if (-not (Get-Process -Id $supervisor.Id -ErrorAction SilentlyContinue)) { exit 2 }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    exit 3
}

$status = Read-SafeStatus
if (-not $status -or -not (Test-SupervisorRunning -Status $status)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ScriptRoot 'cleanup-tun.ps1') -Elevated
    exit $LASTEXITCODE
}

'stop' | Set-Content -LiteralPath $StopRequestPath -Encoding ascii
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(100)
do {
    $status = Read-SafeStatus
    if ($status -and $status.state -eq 'stopped') { exit 0 }
    if ($status -and $status.state -eq 'failed') { exit 2 }
    if (-not (Test-SupervisorRunning -Status $status)) { break }
    Start-Sleep -Milliseconds 500
} while ([DateTimeOffset]::UtcNow -lt $deadline)

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ScriptRoot 'cleanup-tun.ps1') -Elevated
exit $LASTEXITCODE
