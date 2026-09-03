[CmdletBinding()]
param([string]$Destination = '')

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$Destination = if ($Destination) { $Destination } else { Join-Path $projectRoot 'runtime' }
$destinationPath = [IO.Path]::GetFullPath($Destination)
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot 'runtime'))
if (-not $destinationPath.Equals($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'runtime-destination-refused'
}
New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
$downloadRoot = Join-Path ([IO.Path]::GetTempPath()) ('v2rayn-tun-bridge-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null

function Receive-VerifiedFile([string]$Url, [string]$Name, [string]$Sha256) {
    $temporary = Join-Path $downloadRoot $Name
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $temporary
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $temporary).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) { throw "hash-mismatch:$Name" }
    return $temporary
}

try {
    $archive = Receive-VerifiedFile `
        'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/mihomo-windows-amd64-compatible-v1.19.29.zip' `
        'mihomo.zip' `
        '322aaa5957ba9e72afdda9b71cc4329f691d2d45ec39e70bbca3f7bf5aa93d52'
    $expanded = Join-Path $downloadRoot 'core'
    Expand-Archive -LiteralPath $archive -DestinationPath $expanded
    $core = Get-ChildItem -LiteralPath $expanded -Filter '*.exe' -File | Select-Object -First 1
    if (-not $core) { throw 'core-not-found-in-archive' }
    Copy-Item -LiteralPath $core.FullName -Destination (Join-Path $destinationPath 'mihomo.exe') -Force

    $assets = @(
        @('geosite.dat', 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat', '556c880698ccc141a73f74fc4aac1484e459f90e2321561b59d84dcb32df87cd'),
        @('geoip.dat', 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat', '0d5d2ba0c5a5c58027fd1347a6afd57c9470799b6bb3cbc274fd4657ed8de382'),
        @('Country.mmdb', 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb', 'fe721d5e47d320b2a23db4eafddb796a22026ef01899bbe7007fc0274016e5f4')
    )
    foreach ($asset in $assets) {
        $downloaded = Receive-VerifiedFile $asset[1] $asset[0] $asset[2]
        Copy-Item -LiteralPath $downloaded -Destination (Join-Path $destinationPath $asset[0]) -Force
    }

    $license = Receive-VerifiedFile `
        'https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/LICENSE' `
        'MIHOMO_LICENSE.txt' `
        '3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986'
    Copy-Item -LiteralPath $license -Destination (Join-Path $destinationPath 'MIHOMO_LICENSE.txt') -Force
} finally {
    if ([IO.Path]::GetFullPath($downloadRoot).StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $downloadRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Output "Runtime assets prepared in $destinationPath"
