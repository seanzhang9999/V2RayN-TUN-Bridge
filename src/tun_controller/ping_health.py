"""Bounded ICMP checks: any reachable target vetoes automatic recovery."""
import json
import subprocess
import time

PING_TARGETS = ("223.5.5.5", "1.1.1.1")
CHECK_INTERVAL = 10
RESTART_COOLDOWN = 300


def ping_connected() -> bool | None:
    # Ping.Status avoids localized ping.exe output and unreachable replies whose
    # process exit code can misleadingly be zero. Errors are unknown, not outage.
    script = r'''
$success = $false
$unknown = $false
foreach ($target in @('223.5.5.5', '1.1.1.1')) {
    $probe = New-Object System.Net.NetworkInformation.Ping
    try {
        if ($probe.Send($target, 1500).Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $success = $true
            break
        }
    } catch { $unknown = $true }
    finally { $probe.Dispose() }
}
if ($success) { 'true' } elseif ($unknown) { 'null' } else { 'false' }
'''
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=8, check=False,
            creationflags=0x08000000,
        )
        if result.returncode != 0:
            return None
        value = json.loads(result.stdout.strip())
        return value if isinstance(value, bool) else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


class PingOutage:
    def __init__(self):
        self.first_failure = None
        self.failures = 0
        self.episode = 0
        self.next_restart = 0.0

    def observe(self, connected: bool | None, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if connected is not False:
            if self.failures:
                self.episode += 1
            self.first_failure = None
            self.failures = 0
            return False
        if self.first_failure is None:
            self.first_failure = now
        self.failures += 1
        return self.failures >= 3 and now - self.first_failure >= 30 and now >= self.next_restart

    def attempted(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self.next_restart = now + RESTART_COOLDOWN
        self.first_failure = None
        self.failures = 0
