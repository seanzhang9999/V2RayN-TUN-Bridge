import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PublicScriptTests(unittest.TestCase):
    def test_scripts_have_no_machine_specific_v2rayn_path(self):
        for name in ("mihomo-tun.ps1", "cleanup-tun.ps1", "tun-watchdog.ps1"):
            text = (PROJECT_ROOT / name).read_text(encoding="utf-8-sig")
            self.assertNotIn("D:\\run", text)

    def test_watchdog_only_accepts_private_runtime_identity(self):
        text = (PROJECT_ROOT / "tun-watchdog.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("mihomo-runtime-state.json", text)
        self.assertIn("mihomo-controller.exe", text)
        self.assertIn("startTimeUtcTicks", text)
        self.assertIn("@(1081, 1082)", text)
        self.assertNotIn("Start-Process -FilePath $V2rayN", text)

    def test_packaged_launcher_uses_its_own_executable_for_supervisor(self):
        text = (PROJECT_ROOT / "mihomo-tun.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("AppExecutable", text)
        self.assertIn("--supervisor", text)

    def test_stop_does_not_require_a_v2rayn_installation_path(self):
        text = (PROJECT_ROOT / "mihomo-tun.ps1").read_text(encoding="utf-8-sig")
        start_block = text.index("if ($Action -eq 'Start')")
        validation = text.index("invalid-v2rayn-root")
        self.assertGreater(validation, start_block)


if __name__ == "__main__":
    unittest.main()
