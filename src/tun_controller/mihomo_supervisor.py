"""Persistent, guarded Mihomo TUN runtime driven by v2rayN data."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes
import json
import os
import secrets
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tun_controller.mihomo_prepare import prepare_mihomo_configs
from tun_controller.network_monitor import NetworkSignature, detect_network_signature
from tun_controller.proxy_endpoint import resolve_proxy_server_ipv4
from tun_controller.v2rayn_source import DEFAULT_APP_ROOT, load_v2rayn_config


CREATE_NO_WINDOW = 0x08000000
WINDOWS_EPOCH_TICKS = 504_911_232_000_000_000
TUN_NAME = "mihomo_tun_controller"
CONTROLLER_PORT = 19092
WATCHDOG_REPORT_NAME = "mihomo-runtime-watchdog-report.json"


class SupervisorError(RuntimeError):
    """A redaction-safe runtime error."""


def normalize_windows_exit_code(return_code: int) -> int:
    """Render unsigned Win32 process status values as their signed equivalent."""
    if return_code >= 1 << 31:
        return return_code - (1 << 32)
    return return_code


def classify_core_exit(
    return_code: int, watchdog_report: dict[str, Any] | None
) -> str:
    """Turn a process exit and watchdog evidence into a stable reason."""
    if watchdog_report:
        if watchdog_report.get("heartbeatExpired") and watchdog_report.get("forcedStop"):
            return "watchdog-heartbeat-timeout"
        if watchdog_report.get("forcedStop"):
            return "watchdog-forced-stop"
    if return_code == 0:
        return "core-clean-exit"
    return "core-error-exit"


def describe_core_exit(return_code: int, reason: str) -> str:
    """Return a concise, user-facing explanation for a core termination."""
    if reason == "watchdog-heartbeat-timeout":
        return (
            "看门狗检测到控制程序心跳持续中断，已安全停止 Mihomo 核心"
            "（可能发生于系统睡眠或唤醒后恢复较慢；退出代码 "
            f"{return_code}）"
        )
    if reason == "watchdog-forced-stop":
        return f"看门狗已停止 Mihomo 核心（退出代码 {return_code}）"
    if reason == "core-clean-exit":
        return "Mihomo 核心意外提前退出（退出代码 0）"
    return f"Mihomo 核心异常退出（退出代码 {return_code}）"



@dataclass(frozen=True)
class SourceSnapshot:
    network: NetworkSignature
    profile_id: str
    route_id: str
    gui_modified_ns: int
    database_modified_ns: int


class MihomoSupervisor:
    def __init__(
        self,
        runtime_root: Path,
        app_root: Path,
        script_root: Path,
        *,
        manage_v2rayn: bool = True,
        profile_id: str | None = None,
    ) -> None:
        self.runtime_root = runtime_root
        self.app_root = app_root
        self.script_root = script_root
        self.manage_v2rayn = manage_v2rayn
        self.profile_id = profile_id
        # Automatic handoff replaces v2rayN on its familiar local endpoint.
        # Manual coexistence must retain 1082 because v2rayN owns 1081.
        self.mixed_port = 1081 if manage_v2rayn else 1082
        self.core_path = runtime_root / "mihomo-controller.exe"
        self.config_path = runtime_root / "mihomo-full-config.json"
        self.prepare_report = runtime_root / "mihomo-offline-report.json"
        self.status_path = runtime_root / "mihomo-runtime-report.json"
        self.state_path = runtime_root / "mihomo-runtime-state.json"
        self.heartbeat_path = runtime_root / "mihomo-runtime-heartbeat.txt"
        self.cancel_path = runtime_root / "mihomo-runtime-watchdog-cancel.txt"
        self.stop_request = runtime_root / "mihomo-runtime-stop.txt"
        self.stdout_path = runtime_root / "mihomo-runtime-stdout.log"
        self.stderr_path = runtime_root / "mihomo-runtime-stderr.log"
        self.watchdog_report_path = runtime_root / WATCHDOG_REPORT_NAME
        self.controller_access_path = runtime_root / "mihomo-controller-access.json"
        self.controller_secret = secrets.token_urlsafe(32)
        self.core: subprocess.Popen[bytes] | None = None
        self.watchdog: subprocess.Popen[bytes] | None = None
        self._stdout: Any = None
        self._stderr: Any = None
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self.last_core_exit_code: int | None = None
        self.last_core_exit_reason: str | None = None
        self.checkpoint = "created"
        self.health_checks: dict[str, dict[str, Any]] = {}
        self.profile_summary: dict[str, Any] = {}

    def run(self) -> int:
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.stop_request.unlink(missing_ok=True)
        self._write_status("starting", "offline-prepare")
        try:
            self.checkpoint = "initial-snapshot"
            snapshot = self._snapshot()
            self.checkpoint = "offline-prepare"
            self._prepare(snapshot.network)
            if self.manage_v2rayn:
                self.checkpoint = "stop-v2rayn"
                self._stop_v2rayn()
            self.checkpoint = "start-core"
            self._start_core()
            self._write_controller_access()
            if self.manage_v2rayn:
                snapshot = self._snapshot(snapshot.network.proxy_ipv4)
            # Core readiness (process + TUN adapter + local port) is the startup
            # contract. Public websites are diagnostics only and can be blocked,
            # rate-limited, or temporarily unavailable without invalidating TUN.
            self._write_status("running", "connectivity-tests", network=snapshot.network)
            self._run_connectivity_checks("running")
            self.checkpoint = "monitoring"
            self._write_status("running", "monitoring", network=snapshot.network)
            return self._monitor(snapshot)
        except Exception as exc:
            # Port 1081 belongs to exactly one process at a time. Always finish
            # Mihomo cleanup before returning control to the user. v2rayN is
            # deliberately never launched automatically.
            try:
                if self.core is not None:
                    self._stop_core()
            except Exception:
                pass
            self._write_status(
                "failed",
                "manual-v2rayn-required",
                error_type=type(exc).__name__,
                error_checkpoint=self.checkpoint,
                error_message=str(exc),
            )
            self._delete_sensitive_files()
            return 2

    def _monitor(self, current: SourceSnapshot) -> int:
        pending: SourceSnapshot | None = None
        pending_count = 0
        while not self.stop_request.exists():
            self._touch_heartbeat()
            if self.core is None:
                raise SupervisorError("Mihomo process handle is missing")
            return_code = self.core.poll()
            if return_code is not None:
                self._stop_heartbeat_worker()
                watchdog_report = _read_json(self.watchdog_report_path)
                if watchdog_report and int(watchdog_report.get("corePid") or 0) != self.core.pid:
                    watchdog_report = None
                return_code = normalize_windows_exit_code(return_code)
                self.last_core_exit_code = return_code
                self.last_core_exit_reason = classify_core_exit(
                    return_code, watchdog_report
                )
                raise SupervisorError(describe_core_exit(return_code, self.last_core_exit_reason))
            if not self.manage_v2rayn:
                time.sleep(3)
                continue
            try:
                observed = self._snapshot(current.network.proxy_ipv4)
            except Exception:
                observed = None
            if observed is None or observed == current:
                pending = None
                pending_count = 0
            elif observed == pending:
                pending_count += 1
            else:
                pending = observed
                pending_count = 1
            if observed is not None and pending_count >= 2:
                self._write_status("restarting", "network-or-config-change")
                current = self._restart_guarded()
                pending = None
                pending_count = 0
                self._write_status("running", "monitoring", network=current.network)
            time.sleep(3)

        if self.manage_v2rayn:
            self._write_status("stopping", "stop-mihomo")
        else:
            self._write_status("stopping", "manual-v2rayn-unchanged")
        self.checkpoint = "stop-mihomo"
        self._stop_core()
        self.checkpoint = "stop-complete"
        self._write_status("stopped", "manual-v2rayn-required")
        self._delete_sensitive_files()
        return 0

    def _restart_guarded(self) -> SourceSnapshot:
        self._stop_core()
        snapshot = self._snapshot()
        self._prepare(snapshot.network)
        self._stop_v2rayn()
        self._start_core()
        self._write_controller_access()
        snapshot = self._snapshot(snapshot.network.proxy_ipv4)
        self._write_status("running", "connectivity-tests", network=snapshot.network)
        self._run_connectivity_checks("running")
        self.checkpoint = "monitoring"
        return snapshot

    def _snapshot(
        self, pinned_proxy_ipv4: tuple[str, ...] | None = None
    ) -> SourceSnapshot:
        imported = load_v2rayn_config(self.app_root, profile_id=self.profile_id)
        if pinned_proxy_ipv4 is None:
            resolver = lambda host: resolve_proxy_server_ipv4(
                host, imported.profile.port, self.app_root
            )
        else:
            resolver = lambda _host: pinned_proxy_ipv4
        network = detect_network_signature(imported.profile.address, resolver=resolver)
        if network is None:
            raise SupervisorError("No physical IPv4 default route")
        return SourceSnapshot(
            network=network,
            profile_id=imported.profile.index_id,
            route_id=imported.route_id,
            gui_modified_ns=imported.gui_modified_ns,
            database_modified_ns=imported.database_modified_ns,
        )

    def _prepare(self, network: NetworkSignature) -> None:
        report = prepare_mihomo_configs(
            self.runtime_root,
            self.app_root,
            network_signature=network,
            profile_id=self.profile_id,
            mixed_port=self.mixed_port,
            controller_port=CONTROLLER_PORT,
            controller_secret=self.controller_secret,
        )
        summary = report.get("modes", {}).get("full-ipv4-tun", {})
        if isinstance(summary, dict):
            self.profile_summary = {
                "remarks": str(summary.get("profile_remarks") or "未命名节点"),
                "protocol": str(summary.get("protocol") or "unknown"),
                "transport": str(summary.get("transport") or ""),
                "routeName": str(summary.get("route_name") or ""),
            }
        _write_atomic_json(self.prepare_report, report)

    def _write_controller_access(self) -> None:
        """Publish local read credentials only inside the protected runtime root."""
        _write_atomic_json(
            self.controller_access_path,
            {
                "schemaVersion": 1,
                "port": CONTROLLER_PORT,
                "secret": self.controller_secret,
                "corePid": self.core.pid if self.core else None,
            },
        )

    def _start_core(self) -> None:
        for path in (
            self.state_path,
            self.heartbeat_path,
            self.cancel_path,
            self.watchdog_report_path,
        ):
            path.unlink(missing_ok=True)
        _rotate_log(self.stdout_path)
        _rotate_log(self.stderr_path)
        self.last_core_exit_code = None
        self.last_core_exit_reason = None
        self._touch_heartbeat()
        self.watchdog = subprocess.Popen(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.script_root / "tun-watchdog.ps1"),
                "-StateFilePath",
                str(self.state_path),
                "-StartupGuardSeconds",
                "45",
                "-TimeoutSeconds",
                "86400",
                "-HeartbeatFilePath",
                str(self.heartbeat_path),
                "-HeartbeatStaleSeconds",
                "20",
                "-HeartbeatConfirmSeconds",
                "30",
                "-CancelFilePath",
                str(self.cancel_path),
                "-ReportFileName",
                WATCHDOG_REPORT_NAME,
            ],
            creationflags=CREATE_NO_WINDOW,
        )
        self._stdout = self.stdout_path.open("wb")
        self._stderr = self.stderr_path.open("wb")
        self.core = subprocess.Popen(
            [
                str(self.core_path),
                "-d",
                str(self.runtime_root),
                "-f",
                str(self.config_path),
            ],
            cwd=self.runtime_root,
            stdout=self._stdout,
            stderr=self._stderr,
            creationflags=CREATE_NO_WINDOW,
        )
        _write_atomic_json(
            self.state_path,
            {
                "pid": self.core.pid,
                "startTimeUtcTicks": _process_start_ticks(self.core),
                "executablePath": str(self.core_path),
                "adapterName": TUN_NAME,
                "expectedAdapterMode": "Required",
                "expectedPort": self.mixed_port,
            },
        )
        self._start_heartbeat_worker()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            self._touch_heartbeat()
            if self.core.poll() is not None:
                break
            if _powershell_bool(
                "$a=Get-NetAdapter -Name 'mihomo_tun_controller' -ErrorAction SilentlyContinue; "
                f"$p=Get-NetTCPConnection -State Listen -LocalPort {self.mixed_port} -ErrorAction SilentlyContinue; "
                "[bool]($a -and $a.Status -eq 'Up' -and $p)"
            ):
                return
            time.sleep(0.3)
        raise SupervisorError("Mihomo TUN did not become ready")

    def _stop_core(self) -> None:
        try:
            self.cancel_path.write_text("cancel", encoding="ascii")
        except OSError:
            pass
        self._stop_heartbeat_worker()
        if self.core is not None and self.core.poll() is None:
            try:
                self.core.terminate()
                self.core.wait(timeout=12)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self.core.kill()
                    self.core.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        if self.watchdog is not None:
            try:
                self.watchdog.wait(timeout=12)
            except subprocess.TimeoutExpired:
                pass
        for stream in (self._stdout, self._stderr):
            if stream is not None:
                stream.close()
        self.core = None
        self.watchdog = None
        self._stdout = None
        self._stderr = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            adapter_up = _powershell_bool(
                "[bool](Get-NetAdapter -Name 'mihomo_tun_controller' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')"
            )
            port_busy = _powershell_bool(
                f"[bool](Get-NetTCPConnection -State Listen -LocalPort {self.mixed_port} -ErrorAction SilentlyContinue)"
            )
            if not adapter_up and not port_busy:
                break
            time.sleep(0.3)
        if _powershell_bool(
            "[bool](Get-NetAdapter -Name 'mihomo_tun_controller' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')"
        ) or _powershell_bool(
            f"[bool](Get-NetTCPConnection -State Listen -LocalPort {self.mixed_port} -ErrorAction SilentlyContinue)"
        ):
            raise SupervisorError("Mihomo cleanup did not complete")

    def _run_connectivity_checks(self, state: str) -> None:
        """Record endpoint diagnostics without deciding whether TUN is healthy."""
        self.health_checks = {}
        checks = (
            (
                "google",
                "https://www.google.com/generate_204",
                0,
                lambda status: status == "204",
            ),
            (
                "chatgpt",
                "https://chatgpt.com/",
                0,
                _web_endpoint_reachable,
            ),
            (
                "mihomo-google",
                "https://www.google.com/generate_204",
                self.mixed_port,
                lambda status: status == "204",
            ),
            (
                "mihomo-chatgpt",
                "https://chatgpt.com/",
                self.mixed_port,
                _web_endpoint_reachable,
            ),
            (
                "direct-baidu",
                "https://www.baidu.com/",
                self.mixed_port,
                lambda status: status == "200",
            ),
        )
        for name, url, proxy_port, accepted in checks:
            self.checkpoint = f"health-{name}"
            self.health_checks[name] = {"state": "testing", "httpStatus": ""}
            self._write_status(state, self.checkpoint)
            self._touch_heartbeat()
            status = _curl_status(url, proxy_port=proxy_port)
            passed = bool(accepted(status))
            self.health_checks[name] = {
                "state": "passed" if passed else "failed",
                "httpStatus": status,
            }
            self._write_status(state, self.checkpoint)
        self._touch_heartbeat()

    def _stop_v2rayn(self) -> None:
        environment = os.environ.copy()
        environment["V2RAYN_EXPECTED"] = str(self.app_root / "v2rayN.exe")
        environment["XRAY_EXPECTED"] = str(self.app_root / "bin" / "Xray" / "xray.exe")
        script = r"""
$gui = Get-Process -Name v2rayN -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.Equals($env:V2RAYN_EXPECTED,[StringComparison]::OrdinalIgnoreCase) }
foreach ($process in @($gui)) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
$owner = @(Get-NetTCPConnection -State Listen -LocalPort 1081 -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess
if ($owner) {
    $core = Get-Process -Id $owner -ErrorAction SilentlyContinue
    if ($core -and $core.Path -and $core.Path.Equals($env:XRAY_EXPECTED,[StringComparison]::OrdinalIgnoreCase)) {
        Stop-Process -Id $core.Id -Force -ErrorAction SilentlyContinue
    }
}
"""
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            env=environment,
            capture_output=True,
            timeout=15,
            check=False,
            creationflags=CREATE_NO_WINDOW,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if _powershell_bool(
                "[bool](-not (Get-NetTCPConnection -State Listen -LocalPort 1081 -ErrorAction SilentlyContinue))"
            ):
                return
            time.sleep(0.25)
        raise SupervisorError("v2rayN local port 1081 was not released")

    def _touch_heartbeat(self) -> None:
        self.heartbeat_path.write_text(str(time.time_ns()), encoding="ascii")

    def _start_heartbeat_worker(self) -> None:
        self._stop_heartbeat_worker()
        self._heartbeat_stop.clear()

        def heartbeat_loop() -> None:
            while not self._heartbeat_stop.wait(3):
                try:
                    self._touch_heartbeat()
                except OSError:
                    # The watchdog still handles a supervisor that genuinely
                    # disappears; a transient write failure should not crash it.
                    pass

        self._heartbeat_thread = threading.Thread(
            target=heartbeat_loop,
            name="mihomo-heartbeat",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat_worker(self) -> None:
        self._heartbeat_stop.set()
        thread = self._heartbeat_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)
        self._heartbeat_thread = None

    def _write_status(
        self,
        state: str,
        checkpoint: str,
        *,
        network: NetworkSignature | None = None,
        error_type: str | None = None,
        error_checkpoint: str | None = None,
        error_message: str | None = None,
        error_check: str | None = None,
    ) -> None:
        value: dict[str, Any] = {
            "schemaVersion": 1,
            "mode": "mihomo-daily-tun",
            "state": state,
            "checkpoint": checkpoint,
            "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "supervisorPid": os.getpid(),
            "corePid": self.core.pid if self.core and self.core.poll() is None else None,
            "v2rayNManagement": "stop-only" if self.manage_v2rayn else "unchanged",
            "localProxyPort": self.mixed_port,
            "healthChecks": self.health_checks,
            "selectedProfile": self.profile_summary,
        }
        if network is not None:
            value["physicalInterface"] = network.interface_name
        if error_type is not None:
            value["errorType"] = error_type
        if error_checkpoint is not None:
            value["errorCheckpoint"] = error_checkpoint
        if error_message is not None:
            value["errorMessage"] = error_message
        if error_check is not None:
            value["errorCheck"] = error_check
        if self.last_core_exit_code is not None:
            value["coreExitCode"] = self.last_core_exit_code
        if self.last_core_exit_reason is not None:
            value["coreExitReason"] = self.last_core_exit_reason
        _write_atomic_json(self.status_path, value)

    def _delete_sensitive_files(self) -> None:
        for path in (
            self.config_path,
            self.runtime_root / "mihomo-mixed-config.json",
            self.runtime_root / "mihomo-single-config.json",
            self.state_path,
            self.heartbeat_path,
            self.cancel_path,
            self.stop_request,
            self.controller_access_path,
        ):
            path.unlink(missing_ok=True)


def _curl_status(url: str, *, proxy_port: int = 0, timeout: int = 12) -> str:
    arguments = [
        "curl.exe",
        "--ipv4",
        "--silent",
        "--output",
        "NUL",
        "--write-out",
        "%{http_code}",
        "--connect-timeout",
        "5",
        "--max-time",
        str(timeout),
    ]
    if proxy_port:
        arguments += ["--proxy", f"socks5h://127.0.0.1:{proxy_port}"]
    else:
        arguments += ["--noproxy", "*"]
    arguments.append(url)
    completed = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        timeout=timeout + 3,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "000"


def _web_endpoint_reachable(status: str) -> bool:
    """Treat an HTTP response as connectivity, including access-policy responses."""
    try:
        code = int(status)
    except ValueError:
        return False
    return 200 <= code < 500


def _powershell_bool(script: str) -> bool:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$value = & {{ {script} }}; if ([bool]$value) {{ 'true' }} else {{ 'false' }}",
        ],
        capture_output=True,
        text=True,
        timeout=12,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )
    return completed.returncode == 0 and completed.stdout.strip().lower() == "true"


def _process_start_ticks(process: subprocess.Popen[bytes]) -> int:
    creation = ctypes.wintypes.FILETIME()
    exit_time = ctypes.wintypes.FILETIME()
    kernel = ctypes.wintypes.FILETIME()
    user = ctypes.wintypes.FILETIME()
    if not ctypes.windll.kernel32.GetProcessTimes(
        int(process._handle),
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise SupervisorError("Unable to read Mihomo process identity")
    filetime = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    return filetime + WINDOWS_EPOCH_TICKS


def _write_atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    payload = json.dumps(value, ensure_ascii=False, indent=2)
    # On Windows, a file that is being actively read by GUI/Tk polling can hold
    # a lock that prevents atomic replace. Keep the core alive and retry with
    # short backoff, then fall back to a best-effort direct write.
    max_retries = 6
    delay_sec = 0.12
    for attempt in range(max_retries):
        try:
            temporary.write_text(payload, encoding="utf-8")
            try:
                os.replace(temporary, path)
                return
            except PermissionError:
                pass
        except PermissionError:
            pass
        finally:
            if temporary.exists():
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
        if attempt < max_retries - 1:
            time.sleep(delay_sec * (attempt + 1))

    # Final best-effort write path if atomic replace is continuously blocked by
    # readers. We prefer progress over strict atomicity for this local status file.
    try:
        path.write_text(payload, encoding="utf-8")
    except OSError:
        return


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _rotate_log(path: Path) -> None:
    if not path.exists():
        return
    previous = path.with_name(f"{path.stem}.previous{path.suffix}")
    try:
        previous.unlink(missing_ok=True)
        path.replace(previous)
    except OSError:
        # Starting the core is more important than retaining an old diagnostic.
        path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--app-root", type=Path, default=DEFAULT_APP_ROOT)
    parser.add_argument("--script-root", required=True, type=Path)
    parser.add_argument("--manual-v2rayn", action="store_true")
    parser.add_argument("--profile-id")
    args = parser.parse_args()
    return MihomoSupervisor(
        args.runtime_root,
        args.app_root,
        args.script_root,
        manage_v2rayn=not args.manual_v2rayn,
        profile_id=args.profile_id,
    ).run()


if __name__ == "__main__":
    raise SystemExit(main())
