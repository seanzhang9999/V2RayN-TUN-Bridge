import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tun_controller.mihomo_prepare import _validate, _version


class MihomoPrepareProcessTests(unittest.TestCase):
    def test_core_validation_and_version_checks_are_windowless(self):
        completed = mock.Mock(returncode=0, stdout="Mihomo fixture\n")
        with mock.patch(
            "tun_controller.mihomo_prepare.subprocess.run", return_value=completed
        ) as run:
            _validate(Path("mihomo.exe"), Path("data"), Path("config.json"))
            self.assertEqual(_version(Path("mihomo.exe")), "Mihomo fixture")

        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertEqual(
                call.kwargs["creationflags"],
                getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )


if __name__ == "__main__":
    unittest.main()
