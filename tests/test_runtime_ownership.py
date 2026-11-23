import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from tun_controller.runtime_lease import RuntimeLease
from tun_gui.app import StatusFileWatcher, TunGuiApp


class OwnershipTests(unittest.TestCase):
    def test_second_process_cannot_own_runtime_and_lock_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            code = ('from pathlib import Path; from tun_controller.runtime_lease import RuntimeLease; '
                    'import sys\nwith RuntimeLease(Path(sys.argv[1])) as acquired: print(acquired)')
            env = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
            def probe():
                return subprocess.check_output([sys.executable, '-c', code, directory], env=env, text=True).strip()
            with RuntimeLease(Path(directory)) as acquired:
                self.assertTrue(acquired)
                self.assertEqual(probe(), 'False')
            self.assertEqual(probe(), 'True')

    def test_status_refresh_recovers_after_render_exception(self):
        app = object.__new__(TunGuiApp)
        app.root = Mock()
        app.message_var = Mock()
        app._render_status = Mock(side_effect=[ValueError('bad status'), None])
        app._poll_status()
        app.root.after.assert_called_once_with(750, app._poll_status)
        app._poll_status()
        self.assertEqual(app.root.after.call_count, 2)

    def test_cache_eventually_recovers_even_when_file_signature_is_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            path.write_text('{"state":"failed "}', encoding='utf-8')
            watcher = StatusFileWatcher(path)
            with patch('tun_gui.app.time.monotonic', return_value=10):
                watcher.poll()
            original = path.stat()
            path.write_text('{"state":"running"}', encoding='utf-8')
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
            with patch('tun_gui.app.time.monotonic', return_value=16):
                changed, value = watcher.poll()
            self.assertTrue(changed)
            self.assertEqual(value['state'], 'running')

    def test_supervisor_detection_uses_command_identity_not_status_or_gui(self):
        script = (ROOT / 'mihomo-tun.ps1').read_text(encoding='utf-8-sig')
        function = script[script.index('function Get-RuntimeSupervisors'):script.index('function Test-SupervisorRunning')]
        harness = r'''
$RuntimeRoot = 'C:\runtime'
function Get-CimInstance {
    [pscustomobject]@{ProcessId=1;Name='V2RayN-TUN-Bridge.exe';CommandLine='"C:\app.exe" --supervisor --runtime-root "C:\runtime"'}
    [pscustomobject]@{ProcessId=2;Name='V2RayN-TUN-Bridge.exe';CommandLine='"C:\app.exe"'}
    [pscustomobject]@{ProcessId=3;Name='V2RayN-TUN-Bridge.exe';CommandLine='"C:\app.exe" --supervisor --runtime-root "C:\other"'}
    [pscustomobject]@{ProcessId=4;Name='python.exe';CommandLine='python -m tun_controller.mihomo_supervisor --runtime-root C:\runtime'}
}
'''
        result = subprocess.check_output(['powershell.exe', '-NoProfile', '-Command', harness + function + '\n@(Get-RuntimeSupervisors | Select-Object -ExpandProperty ProcessId) | ConvertTo-Json -Compress'], text=True)
        self.assertEqual(json.loads(result), [1, 4])

    def test_stop_waits_for_actual_process_exit_even_with_stale_stopped_report(self):
        script = (ROOT / 'mihomo-tun.ps1').read_text(encoding='utf-8-sig')
        stop = script[script.rindex('$owners = @(Get-RuntimeSupervisors)'):]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stop-test.ps1'
            harness = r'''
$StopRequestPath = Join-Path $PSScriptRoot 'stop.txt'
$ScriptRoot = $PSScriptRoot
$script:checks = 0
function Get-RuntimeSupervisors { [pscustomobject]@{ProcessId=123} }
function Read-SafeStatus { [pscustomobject]@{state='stopped';supervisorPid=999} }
function Get-Process { $script:checks++; if ($script:checks -eq 1) { [pscustomobject]@{Id=123} } }
function Start-Sleep { }
function powershell.exe { Write-Output "cleanup-after-$script:checks-checks"; $global:LASTEXITCODE=0 }
'''
            path.write_text(harness + stop, encoding='utf-8-sig')
            output = subprocess.check_output(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(path)], text=True)
            self.assertIn('cleanup-after-3-checks', output)


if __name__ == '__main__':
    unittest.main()
