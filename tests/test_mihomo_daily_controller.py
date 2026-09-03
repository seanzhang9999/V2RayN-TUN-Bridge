import inspect
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tun_controller.mihomo_supervisor import MihomoSupervisor, SourceSnapshot
from tun_controller.network_monitor import NetworkSignature


class MihomoDailyControllerTests(unittest.TestCase):
    def test_automatic_mode_uses_1081_and_compatibility_mode_uses_1082(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            automatic = MihomoSupervisor(root, root, PROJECT_ROOT)
            compatibility = MihomoSupervisor(
                root, root, PROJECT_ROOT, manage_v2rayn=False
            )
        self.assertEqual(automatic.mixed_port, 1081)
        self.assertEqual(compatibility.mixed_port, 1082)

    def test_automatic_handoff_releases_1081_before_start_and_never_autostarts_v2rayn(self):
        start_source = inspect.getsource(MihomoSupervisor.run)
        self.assertLess(
            start_source.index("self._prepare"),
            start_source.index("self._stop_v2rayn"),
        )
        self.assertLess(
            start_source.index("self._stop_v2rayn"),
            start_source.index("self._start_core"),
        )

        supervisor_source = inspect.getsource(MihomoSupervisor)
        self.assertNotIn("_restore_v2rayn", supervisor_source)
        self.assertNotIn("v2rayN.exe\"], cwd=", supervisor_source)

    def test_source_snapshot_changes_for_wifi_or_v2rayn_data(self):
        network = NetworkSignature(8, "WLAN", "192.168.1.2", "192.168.1.1", 25, ("203.0.113.8",))
        first = SourceSnapshot(network, "profile-a", "route-a", 1, 2)
        self.assertNotEqual(
            first,
            SourceSnapshot(
                NetworkSignature(9, "Wi-Fi", "10.0.0.2", "10.0.0.1", 30, ("203.0.113.8",)),
                "profile-a",
                "route-a",
                1,
                2,
            ),
        )
        self.assertNotEqual(first, SourceSnapshot(network, "profile-b", "route-a", 1, 3))

    def test_launcher_has_guarded_handoff_and_cleanup(self):
        text = (PROJECT_ROOT / "mihomo-tun.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("tun_controller.mihomo_supervisor", text)
        self.assertIn("cleanup-tun.ps1", text)
        self.assertIn("mihomo-runtime-stop.txt", text)
        self.assertIn("ManualV2rayN", text)
        self.assertIn("Test-SupervisorRunning", text)
        self.assertNotIn("Stop-Process -Name", text)

    def test_supervisor_arms_watchdog_and_runs_informational_checks_after_start(self):
        text = (PROJECT_ROOT / "src/tun_controller/mihomo_supervisor.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("tun-watchdog.ps1", text)
        self.assertIn("mihomo-runtime-state.json", text)
        self.assertIn("_run_connectivity_checks", text)
        self.assertIn("manual-v2rayn", text)
        self.assertIn("resolve_proxy_server_ipv4", text)
        self.assertIn("mihomo-controller-access.json", text)
        self.assertIn("if not self.manage_v2rayn", text)
        running = text.index('self._write_status("running", "connectivity-tests"')
        checks = text.index('self._run_connectivity_checks("running")', running)
        self.assertLess(running, checks)

    def test_all_connectivity_failures_are_recorded_without_failing_tun(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            supervisor = MihomoSupervisor(
                Path(temp_dir), Path(temp_dir), PROJECT_ROOT, manage_v2rayn=False
            )
            written = []
            supervisor._write_status = lambda state, checkpoint, **_kwargs: written.append(
                (state, checkpoint)
            )
            supervisor._touch_heartbeat = lambda: None

            with mock.patch(
                "tun_controller.mihomo_supervisor._curl_status", return_value="000"
            ) as curl_status:
                result = supervisor._run_connectivity_checks("running")

            self.assertIsNone(result)
            self.assertEqual(curl_status.call_count, 5)
            self.assertEqual(len(supervisor.health_checks), 5)
            self.assertTrue(
                all(item["state"] == "failed" for item in supervisor.health_checks.values())
            )
            self.assertTrue(all(state == "running" for state, _ in written))

if __name__ == "__main__":
    unittest.main()
