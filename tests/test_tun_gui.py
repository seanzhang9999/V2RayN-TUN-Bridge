import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tun_gui.app import (
    APP_TITLE,
    CONTROL_SCRIPT,
    StatusFileWatcher,
    build_control_command,
    format_persisted_failure,
    status_is_live,
)
from tun_bridge import __version__


class TunGuiCommandTests(unittest.TestCase):
    def test_version_is_visible_in_application_title(self):
        self.assertEqual(__version__, "0.2.2")
        self.assertIn("v0.2.2", APP_TITLE)

    def test_persisted_failure_is_clearly_historical(self):
        message = format_persisted_failure(
            {
                "failedAt": "2026-09-12T01:15:00Z",
                "errorCheckpoint": "monitoring",
                "errorMessage": "核心异常退出",
                "coreExitCode": -1,
            }
        )
        self.assertIn("历史失败", message)
        self.assertIn("monitoring", message)
        self.assertIn("-1", message)

    def test_start_uses_the_shared_powershell_control_script(self):
        app_root = Path(r"C:\fixture\v2rayN")

        command = build_control_command(
            "Start",
            app_root,
            profile_id="profile-123",
            manual_v2rayn=True,
            elevated=True,
            app_executable=Path(r"C:\Program Files\V2RayN TUN Bridge\V2RayN-TUN-Bridge.exe"),
        )

        self.assertEqual(command[0], "powershell.exe")
        self.assertEqual(command[command.index("-File") + 1], str(CONTROL_SCRIPT))
        self.assertEqual(command[command.index("-Action") + 1], "Start")
        self.assertEqual(command[command.index("-AppRoot") + 1], str(app_root))
        self.assertEqual(command[command.index("-ProfileId") + 1], "profile-123")
        self.assertIn("-ManualV2rayN", command)
        self.assertIn("-Elevated", command)
        self.assertEqual(
            command[command.index("-AppExecutable") + 1],
            r"C:\Program Files\V2RayN TUN Bridge\V2RayN-TUN-Bridge.exe",
        )

    def test_stop_does_not_include_start_only_options(self):
        command = build_control_command(
            "Stop", Path(r"C:\fixture\v2rayN"), profile_id="ignored", manual_v2rayn=True
        )

        self.assertNotIn("-ProfileId", command)
        self.assertNotIn("-ManualV2rayN", command)

    def test_status_watcher_emits_only_when_file_changes(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            status_path = Path(directory) / "status.json"
            status_path.write_text(json.dumps({"state": "failed"}), encoding="utf-8")
            watcher = StatusFileWatcher(status_path)

            changed, value = watcher.poll()
            self.assertTrue(changed)
            self.assertEqual(value, {"state": "failed"})

            changed, value = watcher.poll()
            self.assertFalse(changed)
            self.assertEqual(value, {"state": "failed"})

            status_path.write_text(
                json.dumps({"state": "running", "checkpoint": "monitoring"}),
                encoding="utf-8",
            )
            changed, value = watcher.poll()
            self.assertTrue(changed)
            self.assertEqual(value["state"], "running")

    def test_status_watcher_reports_file_removal_once(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            status_path = Path(directory) / "status.json"
            status_path.write_text('{"state":"running"}', encoding="utf-8")
            watcher = StatusFileWatcher(status_path)
            watcher.poll()
            status_path.unlink()

            changed, value = watcher.poll()
            self.assertTrue(changed)
            self.assertIsNone(value)
            changed, value = watcher.poll()
            self.assertFalse(changed)
            self.assertIsNone(value)

    def test_active_status_requires_a_live_supervisor_but_failure_is_historical(self):
        running = {"state": "running", "supervisorPid": 123}
        failed = {"state": "failed", "supervisorPid": 123}

        self.assertFalse(status_is_live(running, process_exists=lambda _pid: False))
        self.assertTrue(status_is_live(running, process_exists=lambda _pid: True))
        self.assertTrue(status_is_live(failed, process_exists=lambda _pid: False))


if __name__ == "__main__":
    unittest.main()
