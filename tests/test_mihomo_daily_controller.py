import inspect
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tun_controller.mihomo_supervisor import (
    MihomoSupervisor,
    SourceSnapshot,
    SupervisorError,
    append_failure_history,
    await_watchdog_report,
    classify_core_exit,
    describe_core_exit,
    load_failure_history,
    normalize_windows_exit_code,
)
from tun_controller.network_monitor import NetworkSignature


class MihomoDailyControllerTests(unittest.TestCase):
    def test_guarded_readiness_waits_for_current_committed_luid(self):
        module = "tun_controller.mihomo_supervisor"
        supervisor = MihomoSupervisor(PROJECT_ROOT, PROJECT_ROOT, PROJECT_ROOT)
        supervisor.core = mock.Mock()
        supervisor.core.poll.return_value = None
        def get_luid(_alias, output):
            output._obj.value = 42
            return 0
        records = [
            {"on": True, "at": 10, "tunLuid": 41},
            {"on": True, "at": 9, "tunLuid": 42},
            {"on": False, "at": 10, "tunLuid": 42},
            {"on": True, "at": 10, "tunLuid": 42},
        ]
        with mock.patch(module + "._read_json", side_effect=records), \
             mock.patch(module + ".ctypes.windll", create=True) as win, \
             mock.patch(module + ".time.time", return_value=10), \
             mock.patch(module + ".time.sleep"), mock.patch.object(supervisor, "_touch_heartbeat") as tick:
            win.iphlpapi.ConvertInterfaceAliasToLuid.side_effect = get_luid
            supervisor._wait_guard_tun()
        self.assertEqual(tick.call_count, 3)

    def test_default_and_compatibility_modes_preserve_port_1081(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            automatic = MihomoSupervisor(root, root, PROJECT_ROOT)
            compatibility = MihomoSupervisor(
                root, root, PROJECT_ROOT, manage_v2rayn=False
            )
        self.assertFalse(automatic.manage_v2rayn)
        self.assertEqual(automatic.mixed_port, 1082)
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
        self.assertIn(
            "-Verb RunAs -ArgumentList $arguments -WindowStyle Hidden -PassThru",
            text,
        )
        self.assertIn("Move-PreviousDiagnostic -Path $StatusPath", text)
        self.assertIn("Move-PreviousDiagnostic -Path $SupervisorStdout", text)
        self.assertIn("Move-PreviousDiagnostic -Path $SupervisorStderr", text)
        self.assertIn("$attempt -lt 5", text)

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

    def test_core_exit_classification_uses_watchdog_evidence(self):
        self.assertEqual(
            classify_core_exit(-1, {"heartbeatExpired": True, "forcedStop": True}),
            "watchdog-heartbeat-timeout",
        )
        self.assertEqual(
            classify_core_exit(0, {"cancelled": False, "forcedStop": False}),
            "core-clean-exit",
        )
        self.assertEqual(classify_core_exit(2, None), "core-error-exit")

    def test_watchdog_report_must_match_the_exited_core(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "watchdog.json"
            report_path.write_text('{"corePid":321,"forcedStop":true}', encoding="utf-8")
            self.assertEqual(
                await_watchdog_report(report_path, 321, timeout=0),
                {"corePid": 321, "forcedStop": True},
            )
            self.assertIsNone(await_watchdog_report(report_path, 999, timeout=0))

    def test_windows_unsigned_exit_code_is_normalized(self):
        self.assertEqual(normalize_windows_exit_code(4294967295), -1)
        self.assertEqual(normalize_windows_exit_code(2), 2)
        self.assertEqual(normalize_windows_exit_code(-1), -1)

    def test_watchdog_timeout_has_actionable_message(self):
        message = describe_core_exit(-1, "watchdog-heartbeat-timeout")
        self.assertIn("心跳持续中断", message)
        self.assertIn("睡眠或唤醒", message)

    def test_forced_stop_message_names_the_reason_and_the_way_out(self):
        message = describe_core_exit(-1, "watchdog-forced-stop")
        self.assertIn("watchdog-forced-stop", message)
        self.assertIn("Restart", message)

    def test_watchdog_starts_without_a_lifetime_cap(self):
        # A cap used to end a healthy core after 24 h with nothing to restart it.
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            supervisor = MihomoSupervisor(root, root, PROJECT_ROOT)
            args = supervisor._watchdog_args()

        value = args[args.index("-TimeoutSeconds") + 1]
        self.assertEqual(value, "0")
        self.assertNotIn("86400", args)

    def test_watchdog_reports_a_renewal_instead_of_killing_a_live_core(self):
        text = (PROJECT_ROOT / "tun-watchdog.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("[int]$TimeoutSeconds = 0", text)
        self.assertIn("$lifetimeExpired", text)
        self.assertIn("lifetime-expired", text)
        self.assertIn("coreStillRunning", text)
        # Expiry must not fall into the stop branch.
        self.assertIn("-not $lifetimeExpired -and $coreRunning", text)

    def test_supervisor_renews_a_watchdog_that_exits_early(self):
        text = (
            PROJECT_ROOT / "src/tun_controller/mihomo_supervisor.py"
        ).read_text(encoding="utf-8")
        self.assertIn("_renew_watchdog", text)
        self.assertIn("self.watchdog.poll() is not None", text)

    def test_watchdog_requires_continuous_stale_confirmation(self):
        text = (PROJECT_ROOT / "tun-watchdog.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("HeartbeatConfirmSeconds", text)
        self.assertIn("$staleObservedAt", text)
        self.assertIn("$heartbeatFresh", text)
        self.assertIn("staleConfirmationSeconds", text)

    def test_failure_history_is_bounded_and_recovers_from_corruption(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            history_path = Path(temp_dir) / "failure-history.json"
            history_path.write_text("not-json", encoding="utf-8")
            for sequence in range(25):
                append_failure_history(history_path, {"sequence": sequence})

            history = load_failure_history(history_path)

        self.assertEqual(len(history), 20)
        self.assertEqual(history[0]["sequence"], 5)
        self.assertEqual(history[-1]["sequence"], 24)

    def test_supervisor_persists_a_safe_failure_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            supervisor = MihomoSupervisor(root, root, PROJECT_ROOT)
            supervisor._snapshot = mock.Mock(
                side_effect=SupervisorError("synthetic safe failure")
            )

            result = supervisor.run()
            history = load_failure_history(root / "mihomo-failure-history.json")

        self.assertEqual(result, 2)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["errorCheckpoint"], "initial-snapshot")
        self.assertEqual(history[0]["errorMessage"], "synthetic safe failure")
        serialized = str(history[0]).casefold()
        self.assertNotIn("password", serialized)
        self.assertNotIn("secret", serialized)

    def test_supervisor_uses_independent_heartbeat_worker(self):
        text = (PROJECT_ROOT / "src/tun_controller/mihomo_supervisor.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("_start_heartbeat_worker", text)
        self.assertIn("_stop_heartbeat_worker", text)

if __name__ == "__main__":
    unittest.main()
