"""Resolve the selected proxy endpoint without trusting Mihomo fake-IP DNS."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path

from tun_controller.dns_resolver import resolve_server_ipv4
from tun_controller.network_monitor import NetworkDetectionError


CREATE_NO_WINDOW = 0x08000000
FAKE_IP_NETWORK = ipaddress.IPv4Network("198.18.0.0/15")


def resolve_proxy_server_ipv4(
    host: str,
    remote_port: int,
    app_root: Path,
    *,
    active_reader: Callable[[Path, int], Iterable[str]] | None = None,
    dns_resolver: Callable[[str], Iterable[str]] = resolve_server_ipv4,
) -> tuple[str, ...]:
    """Prefer the live v2rayN/Xray peer, then use DNS with fake-IP rejection."""
    reader = active_reader or read_v2rayn_active_proxy_ipv4
    active = _usable_ipv4(reader(app_root, remote_port))
    if active:
        return active

    resolved = _usable_ipv4(dns_resolver(host))
    if resolved:
        return resolved
    raise NetworkDetectionError(
        "节点地址只解析到 fake-IP，已拒绝启动以避免代理出口回环"
    )


def read_v2rayn_active_proxy_ipv4(app_root: Path, remote_port: int) -> tuple[str, ...]:
    """Read public TCP peers owned by the verified v2rayN core process."""
    addresses = _query_v2rayn_connections(app_root, remote_port)
    if addresses:
        return addresses

    # Create one short proxy request so a lazy gRPC/TCP connection becomes visible.
    subprocess.run(
        [
            "curl.exe",
            "--ipv4",
            "--silent",
            "--output",
            "NUL",
            "--proxy",
            "socks5h://127.0.0.1:1081",
            "--connect-timeout",
            "3",
            "--max-time",
            "8",
            "https://www.google.com/generate_204",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )
    return _query_v2rayn_connections(app_root, remote_port)


def _query_v2rayn_connections(app_root: Path, remote_port: int) -> tuple[str, ...]:
    environment = os.environ.copy()
    environment["TUN_V2RAYN_ROOT"] = str(app_root.resolve())
    environment["TUN_REMOTE_PORT"] = str(remote_port)
    script = r"""
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($env:TUN_V2RAYN_ROOT).TrimEnd('\') + '\'
$owners = @(Get-NetTCPConnection -State Listen -LocalPort 1081 -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique)
$values = foreach ($ownerId in $owners) {
    $process = Get-Process -Id $ownerId -ErrorAction SilentlyContinue
    if (-not $process -or -not $process.Path) { continue }
    $fullPath = [IO.Path]::GetFullPath($process.Path)
    if (-not $fullPath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { continue }
    if ($process.Name -notin @('xray', 'sing-box')) { continue }
    Get-NetTCPConnection -State Established -OwningProcess $ownerId -ErrorAction SilentlyContinue |
        Where-Object { $_.RemotePort -eq [int]$env:TUN_REMOTE_PORT } |
        Select-Object -ExpandProperty RemoteAddress
}
@($values | Sort-Object -Unique) | ConvertTo-Json -Compress
"""
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=12,
        check=False,
        env=environment,
        creationflags=CREATE_NO_WINDOW,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return ()
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()


def _usable_ipv4(values: Iterable[str]) -> tuple[str, ...]:
    addresses: set[ipaddress.IPv4Address] = set()
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if not isinstance(address, ipaddress.IPv4Address):
            continue
        if address in FAKE_IP_NETWORK or address.is_loopback or address.is_unspecified:
            continue
        addresses.add(address)
    return tuple(str(address) for address in sorted(addresses, key=int))
