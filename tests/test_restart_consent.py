import sys
import tempfile
import unittest
from concurrent.futures import Future
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from tun_controller.restart_consent import RestartConsent, confirm_restart
from tun_controller.mihomo_supervisor import MihomoSupervisor, SourceSnapshot
from tun_controller.network_monitor import NetworkSignature


class RestartConsentTests(unittest.TestCase):
    def gate(self, locked=False):
        future = Future()
        prompt = Mock(return_value=future)
        gate = RestartConsent(locked=lambda: locked, prompt=prompt)
        return gate, future, prompt

    def test_unlocked_waits_then_accepts_exact_snapshot_once(self):
        gate, future, prompt = self.gate()
        for _ in range(3):
            self.assertFalse(gate.allow("snapshot", "reason", "changed"))
        prompt.assert_called_once()
        future.set_result(True)
        self.assertTrue(gate.allow("snapshot", "reason", "changed"))
        self.assertFalse(gate.allow("snapshot", "reason", "changed"))

    def test_denial_close_and_unknown_lock_never_restart_or_repeat(self):
        for locked in (False, None):
            gate, future, prompt = self.gate(locked)
            self.assertFalse(gate.allow("snapshot", "reason", "changed"))
            future.set_result(False)
            for candidate in ("snapshot", "timestamp-only-change", "another-write"):
                self.assertFalse(gate.allow(candidate, "reason", "changed"))
            prompt.assert_called_once()

    def test_changed_or_unavailable_snapshot_invalidates_old_yes(self):
        for interim in (None, "other"):
            gate, future, _ = self.gate()
            gate.allow("first", "reason", "changed")
            gate.allow(interim, "reason", "changed")
            future.set_result(True)
            self.assertFalse(gate.allow("first", "reason", "changed"))

    def test_lock_while_dialog_pending_allows_recovery_and_invalidates_old_yes(self):
        gate, future, prompt = self.gate()
        gate.allow("first", "reason", "changed")
        gate.locked = lambda: True
        self.assertTrue(gate.allow("first", "reason", "changed"))
        gate.locked = lambda: False
        future.set_result(True)
        self.assertFalse(gate.allow("first", "reason", "changed"))
        prompt.assert_called_once()

    def test_already_locked_does_not_prompt(self):
        gate, _, prompt = self.gate(True)
        self.assertTrue(gate.allow("snapshot", "reason", "changed"))
        prompt.assert_not_called()

    def test_manual_confirmation_fails_closed(self):
        for lock in (False, None):
            with patch('tun_controller.restart_consent.session_locked', return_value=lock), patch('tun_controller.restart_consent.ask_restart', return_value=False) as ask:
                self.assertFalse(confirm_restart("manual"))
                ask.assert_called_once()
        with patch('tun_controller.restart_consent.session_locked', return_value=True), patch('tun_controller.restart_consent.ask_restart') as ask:
            self.assertTrue(confirm_restart("manual"))
            ask.assert_not_called()

    def test_restart_revalidation_never_stops_core_on_failure_or_unlock(self):
        network = NetworkSignature(8, 'WLAN', '192.168.1.2', '192.168.1.1', 25, ('203.0.113.8',))
        baseline = SourceSnapshot(network, 'baseline', 'a', 1, 1)
        approved = SourceSnapshot(network, 'a', 'a', 2, 2)
        with tempfile.TemporaryDirectory() as directory:
            supervisor = MihomoSupervisor(Path(directory), ROOT, ROOT)
            supervisor._stop_core = Mock()
            for snapshot in (Mock(side_effect=RuntimeError('unavailable')), Mock(return_value=baseline)):
                supervisor._snapshot = snapshot
                self.assertEqual(supervisor._restart_guarded(approved, baseline), baseline)
                supervisor._stop_core.assert_not_called()
            supervisor._snapshot = Mock(return_value=approved)
            supervisor.restart_consent.state = 'locked-auto-restart'
            with patch('tun_controller.mihomo_supervisor.session_locked', return_value=False):
                self.assertEqual(supervisor._restart_guarded(approved, baseline), baseline)
            supervisor._stop_core.assert_not_called()



if __name__ == '__main__':
    unittest.main()
