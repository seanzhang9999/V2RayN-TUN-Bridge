import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tun_gui.app import CONTROL_SCRIPT, build_control_command


class TunGuiCommandTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
