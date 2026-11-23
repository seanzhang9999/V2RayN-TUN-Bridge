import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from concurrent.futures import Future

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from tun_controller.ping_health import PingOutage, ping_connected
from tun_controller.mihomo_supervisor import MihomoSupervisor, SourceSnapshot
from tun_controller.network_monitor import NetworkSignature
from tun_controller.restart_consent import RestartConsent


class PingTests(unittest.TestCase):
    def test_sustained_failure_recovery_unknown_and_cooldown(self):
        outage = PingOutage()
        for now in (0, 10, 20):
            self.assertFalse(outage.observe(False, now))
        self.assertTrue(outage.observe(False, 30))
        self.assertFalse(outage.observe(True, 31))
        self.assertFalse(outage.observe(False, 32))
        self.assertFalse(outage.observe(None, 60))
        self.assertFalse(outage.observe(False, 61))
        outage.attempted(62)
        for now in (70, 100, 200, 361):
            self.assertFalse(outage.observe(False, now))
        self.assertTrue(outage.observe(False, 362))

    def test_probe_success_failure_and_errors_are_distinct(self):
        for output, expected in [('true', True), ('false', False), ('null', None), ('invalid', None)]:
            with patch('tun_controller.ping_health.subprocess.run', return_value=Mock(returncode=0, stdout=output)):
                self.assertIs(ping_connected(), expected)

    def run_monitor(self, samples, locked=False):
        with tempfile.TemporaryDirectory() as directory:
            supervisor = MihomoSupervisor(Path(directory), ROOT, ROOT, manage_v2rayn=True)
            snapshot = SourceSnapshot(NetworkSignature(8, 'WLAN', '192.168.1.2', '192.168.1.1', 25, ('203.0.113.8',)), 'a', 'a', 1, 1)
            supervisor.core = Mock()
            supervisor.core.poll.return_value = None
            supervisor._snapshot = Mock(return_value=snapshot)
            supervisor._touch_heartbeat = Mock()
            supervisor._write_status = Mock()
            supervisor._stop_core = Mock()
            supervisor._delete_sensitive_files = Mock()
            supervisor._restart_guarded = Mock(return_value=snapshot)
            prompt = Mock(return_value=Future())
            supervisor.restart_consent = RestartConsent(locked=lambda: locked, prompt=prompt)
            now = [0]
            values = iter(samples)
            calls = [0]
            def probe():
                value = next(values)
                calls[0] += 1
                if calls[0] == len(samples):
                    supervisor.stop_request.touch()
                return value
            def sleep(_seconds):
                now[0] += 10
            with patch('tun_controller.mihomo_supervisor.time.monotonic', side_effect=lambda: now[0]), patch('tun_controller.mihomo_supervisor.time.sleep', side_effect=sleep), patch('tun_controller.mihomo_supervisor.ping_connected', side_effect=probe):
                supervisor._monitor(snapshot)
            return supervisor, prompt

    def test_healthy_ping_never_reads_changed_config_or_prompts_even_locked(self):
        for locked in (False, True):
            supervisor, prompt = self.run_monitor([True] * 8, locked)
            supervisor._snapshot.assert_not_called()
            prompt.assert_not_called()
            supervisor._restart_guarded.assert_not_called()

    def test_transient_failure_does_not_prompt(self):
        supervisor, prompt = self.run_monitor([False, False, True, False, None, True])
        prompt.assert_not_called()
        supervisor._restart_guarded.assert_not_called()

    def test_unlocked_sustained_failure_waits_while_heartbeat_continues(self):
        supervisor, prompt = self.run_monitor([False] * 7)
        prompt.assert_called_once()
        supervisor._restart_guarded.assert_not_called()
        self.assertGreaterEqual(supervisor._touch_heartbeat.call_count, 7)

    def test_locked_sustained_failure_reaches_guard(self):
        supervisor, prompt = self.run_monitor([False] * 5, True)
        prompt.assert_not_called()
        supervisor._restart_guarded.assert_called_once()

    def test_recovery_invalidates_pending_yes(self):
        supervisor, prompt = self.run_monitor([False] * 4 + [True, True])
        self.assertIsNone(supervisor.restart_consent.pending[0])
        prompt.return_value.set_result(True)
        self.assertFalse(supervisor.restart_consent.allow(None, None, ''))

    def test_final_ping_veto_ignores_timestamp_differences(self):
        with tempfile.TemporaryDirectory() as directory:
            supervisor = MihomoSupervisor(Path(directory), ROOT, ROOT, manage_v2rayn=True)
            network = NetworkSignature(8, 'WLAN', '192.168.1.2', '192.168.1.1', 25, ('203.0.113.8',))
            approved = SourceSnapshot(network, 'a', 'a', 1, 1)
            supervisor._snapshot = Mock(return_value=SourceSnapshot(network, 'a', 'a', 999, 999))
            supervisor._stop_core = Mock()
            for value in (True, None):
                with patch('tun_controller.mihomo_supervisor.ping_connected', return_value=value) as probe:
                    self.assertEqual(supervisor._restart_guarded(approved, approved), approved)
                    probe.assert_called_once()
                supervisor._stop_core.assert_not_called()


if __name__ == '__main__':
    unittest.main()
