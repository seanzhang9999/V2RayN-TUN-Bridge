"""Debounced physical-network monitoring for guarded independent-Xray restarts."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from tun_controller.dns_resolver import resolve_server_ipv4


class NetworkDetectionError(RuntimeError):
    """A credential-free physical network detection error."""


@dataclass(frozen=True, repr=False)
class NetworkSignature:
    interface_index: int
    interface_name: str
    local_ipv4: str
    gateway: str
    route_metric: int
    proxy_ipv4: tuple[str, ...] = field(repr=False)

    def __repr__(self) -> str:
        return (
            "NetworkSignature("
            f"interface_index={self.interface_index}, "
            f"interface_name={self.interface_name!r}, "
            f"local_ipv4={self.local_ipv4!r}, gateway={self.gateway!r}, "
            f"route_metric={self.route_metric}, proxy_ipv4='<redacted>')"
        )


class MonitorEvent(str, Enum):
    UNCHANGED = "unchanged"
    PENDING = "pending"
    NETWORK_UNAVAILABLE = "network_unavailable"
    RESTARTED = "restarted"
    RESTART_FAILED = "restart_failed"
    RATE_LIMITED = "rate_limited"
    BASELINE_SET = "baseline_set"


@dataclass(frozen=True)
class MonitorResult:
    event: MonitorEvent
    message: str


class NetworkMonitor:
    def __init__(
        self,
        initial_signature: NetworkSignature | None,
        prepare_and_validate: Callable[[NetworkSignature], Any],
        guarded_restart: Callable[[Any], None],
        *,
        stable_samples: int = 2,
        poll_interval_seconds: float = 3,
        retry_cooldown_seconds: float = 30,
    ) -> None:
        if stable_samples < 2:
            raise ValueError("stable_samples must be at least two")
        self.current_signature = initial_signature
        self.poll_interval_seconds = poll_interval_seconds
        self._prepare_and_validate = prepare_and_validate
        self._guarded_restart = guarded_restart
        self._stable_samples = stable_samples
        self._retry_cooldown_seconds = retry_cooldown_seconds
        self._pending: NetworkSignature | None = None
        self._pending_count = 0
        self._retry_not_before = 0.0
        self._lock = threading.RLock()

    def observe(
        self, signature: NetworkSignature | None, *, now: float | None = None
    ) -> MonitorResult:
        timestamp = time.monotonic() if now is None else now
        with self._lock:
            if signature is None:
                self._clear_pending()
                return MonitorResult(
                    MonitorEvent.NETWORK_UNAVAILABLE,
                    "暂时没有可用的物理默认网络，保持当前运行状态",
                )

            if signature == self.current_signature:
                self._clear_pending()
                return MonitorResult(MonitorEvent.UNCHANGED, "网络未变化")

            if timestamp < self._retry_not_before:
                self._clear_pending()
                return MonitorResult(
                    MonitorEvent.RATE_LIMITED,
                    "上次网络重启失败，正在等待安全重试窗口",
                )

            if signature == self._pending:
                self._pending_count += 1
            else:
                self._pending = signature
                self._pending_count = 1

            if self._pending_count < self._stable_samples:
                return MonitorResult(
                    MonitorEvent.PENDING,
                    "检测到网络变化，等待下一次确认",
                )

            self._clear_pending()
            if self.current_signature is None:
                self.current_signature = signature
                return MonitorResult(MonitorEvent.BASELINE_SET, "已记录当前物理网络")

            try:
                prepared = self._prepare_and_validate(signature)
                self._guarded_restart(prepared)
            except Exception:
                self._retry_not_before = timestamp + self._retry_cooldown_seconds
                return MonitorResult(
                    MonitorEvent.RESTART_FAILED,
                    "网络变化重启失败，继续保留最后有效配置",
                )

            self.current_signature = signature
            self._retry_not_before = 0.0
            return MonitorResult(MonitorEvent.RESTARTED, "已适配新的物理网络")

    def run(
        self,
        signature_provider: Callable[[], NetworkSignature | None],
        stop_event: threading.Event,
        *,
        heartbeat: Callable[[], None] | None = None,
        on_result: Callable[[MonitorResult], None] | None = None,
    ) -> None:
        """Poll until stopped; a heartbeat keeps the external watchdog armed."""
        while not stop_event.is_set():
            try:
                result = self.observe(signature_provider())
            except Exception:
                result = MonitorResult(
                    MonitorEvent.NETWORK_UNAVAILABLE,
                    "暂时无法读取物理网络，保持当前运行状态",
                )
            if on_result is not None:
                on_result(result)
            if heartbeat is not None:
                heartbeat()
            stop_event.wait(self.poll_interval_seconds)

    def _clear_pending(self) -> None:
        self._pending = None
        self._pending_count = 0


def detect_network_signature(
    proxy_host: str,
    *,
    route_reader: Callable[[], dict[str, Any] | None] | None = None,
    resolver: Callable[[str], Iterable[str]] = resolve_server_ipv4,
) -> NetworkSignature | None:
    reader = route_reader or read_windows_physical_default_route
    route = reader()
    if not route:
        return None
    try:
        addresses = sorted(
            {
                str(ipaddress.ip_address(value))
                for value in resolver(proxy_host)
                if ipaddress.ip_address(value).version == 4
            },
            key=lambda value: int(ipaddress.ip_address(value)),
        )
        if not addresses:
            raise ValueError("no IPv4")
        return NetworkSignature(
            interface_index=int(route["interfaceIndex"]),
            interface_name=str(route["interfaceName"]),
            local_ipv4=str(ipaddress.ip_address(route["localIPv4"])),
            gateway=str(ipaddress.ip_address(route["gateway"])),
            route_metric=int(route["routeMetric"]),
            proxy_ipv4=tuple(addresses),
        )
    except (KeyError, TypeError, ValueError):
        raise NetworkDetectionError("物理默认网络信息不完整") from None


def read_windows_physical_default_route() -> dict[str, Any] | None:
    """Read the best non-TUN IPv4 default route without changing system state."""
    script = r"""
$ErrorActionPreference = 'Stop'
$rows = foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore)) {
    if ($route.InterfaceAlias -like 'xray_tun*' -or
        $route.InterfaceAlias -like 'singbox_tun*' -or
        $route.InterfaceAlias -like 'mihomo_tun*') { continue }
    if ($route.NextHop -eq '0.0.0.0') { continue }
    $interface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    $address = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -AddressState Preferred -ErrorAction SilentlyContinue |
        Where-Object { -not $_.SkipAsSource -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1
    if (-not $interface -or -not $address) { continue }
    [pscustomobject]@{
        interfaceIndex = [int]$route.InterfaceIndex
        interfaceName = [string]$route.InterfaceAlias
        localIPv4 = [string]$address.IPAddress
        gateway = [string]$route.NextHop
        routeMetric = [int]($route.RouteMetric + $interface.InterfaceMetric)
    }
}
$rows | Sort-Object routeMetric,interfaceIndex | Select-Object -First 1 | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    windows_root = PathLikeWindowsRoot(environment)
    module_paths = [
        os.path.join(
            windows_root,
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "Modules",
        ),
        os.path.join(
            environment.get("ProgramFiles", r"C:\Program Files"),
            "WindowsPowerShell",
            "Modules",
        ),
    ]
    environment["PSModulePath"] = os.pathsep.join(module_paths)
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=12,
        check=False,
        env=environment,
    )
    if completed.returncode != 0:
        raise NetworkDetectionError("无法读取物理默认路由")
    if not completed.stdout.strip():
        return None
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise NetworkDetectionError("无法解析物理默认路由") from None
    return value if isinstance(value, dict) else None


def PathLikeWindowsRoot(environment: dict[str, str]) -> str:
    """Kept separate for deterministic tests and unusual Windows installations."""
    return environment.get("SystemRoot") or environment.get("WINDIR") or r"C:\Windows"
