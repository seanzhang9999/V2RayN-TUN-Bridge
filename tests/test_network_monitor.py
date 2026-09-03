import sys
import subprocess
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tun_controller.network_monitor import (
    MonitorEvent,
    NetworkMonitor,
    NetworkSignature,
    detect_network_signature,
    read_windows_physical_default_route,
)


WIFI_A = NetworkSignature(8, "Wi-Fi", "192.168.1.20", "192.168.1.1", 35, ("203.0.113.52",))
WIFI_B = NetworkSignature(8, "Wi-Fi", "192.168.50.20", "192.168.50.1", 35, ("203.0.113.52",))
ETHERNET = NetworkSignature(12, "Ethernet", "10.0.0.20", "10.0.0.1", 20, ("203.0.113.52",))


class TransitionRecorder:
    def __init__(self):
        self.events = []
        self.fail_restart = False

    def prepare_and_validate(self, signature):
        self.events.append(("prepare", signature))
        return {"prepared_for": signature}

    def guarded_restart(self, prepared):
        self.events.append(("restart", prepared["prepared_for"]))
        if self.fail_restart:
            raise RuntimeError("synthetic restart failure")


class NetworkMonitorTests(unittest.TestCase):
    def monitor(self, recorder=None):
        recorder = recorder or TransitionRecorder()
        return (
            NetworkMonitor(
                WIFI_A,
                recorder.prepare_and_validate,
                recorder.guarded_restart,
                stable_samples=2,
                retry_cooldown_seconds=30,
            ),
            recorder,
        )

    def test_unchanged_polling_does_nothing(self):
        monitor, recorder = self.monitor()

        first = monitor.observe(WIFI_A, now=0)
        second = monitor.observe(WIFI_A, now=3)

        self.assertEqual(first.event, MonitorEvent.UNCHANGED)
        self.assertEqual(second.event, MonitorEvent.UNCHANGED)
        self.assertEqual(recorder.events, [])
        self.assertEqual(monitor.poll_interval_seconds, 3)

    def test_transient_flap_is_debounced(self):
        monitor, recorder = self.monitor()

        pending = monitor.observe(WIFI_B, now=0)
        recovered = monitor.observe(WIFI_A, now=3)

        self.assertEqual(pending.event, MonitorEvent.PENDING)
        self.assertEqual(recovered.event, MonitorEvent.UNCHANGED)
        self.assertEqual(recorder.events, [])

    def test_stable_change_prepares_before_one_guarded_restart(self):
        monitor, recorder = self.monitor()

        first = monitor.observe(WIFI_B, now=0)
        second = monitor.observe(WIFI_B, now=3)

        self.assertEqual(first.event, MonitorEvent.PENDING)
        self.assertEqual(second.event, MonitorEvent.RESTARTED)
        self.assertEqual(
            recorder.events,
            [("prepare", WIFI_B), ("restart", WIFI_B)],
        )
        self.assertEqual(monitor.current_signature, WIFI_B)

    def test_wifi_to_wifi_and_wifi_to_ethernet_are_changes(self):
        for changed in (WIFI_B, ETHERNET):
            with self.subTest(interface=changed.interface_name):
                monitor, recorder = self.monitor()
                monitor.observe(changed, now=0)
                result = monitor.observe(changed, now=3)
                self.assertEqual(result.event, MonitorEvent.RESTARTED)
                self.assertEqual(recorder.events[-1], ("restart", changed))

    def test_no_default_route_waits_without_stopping_current_runtime(self):
        monitor, recorder = self.monitor()

        first = monitor.observe(None, now=0)
        second = monitor.observe(None, now=3)
        restored = monitor.observe(ETHERNET, now=6)
        restarted = monitor.observe(ETHERNET, now=9)

        self.assertEqual(first.event, MonitorEvent.NETWORK_UNAVAILABLE)
        self.assertEqual(second.event, MonitorEvent.NETWORK_UNAVAILABLE)
        self.assertEqual(restored.event, MonitorEvent.PENDING)
        self.assertEqual(restarted.event, MonitorEvent.RESTARTED)
        self.assertEqual(recorder.events, [("prepare", ETHERNET), ("restart", ETHERNET)])

    def test_failed_restart_is_rate_limited_and_keeps_last_good_signature(self):
        recorder = TransitionRecorder()
        recorder.fail_restart = True
        monitor, _ = self.monitor(recorder)

        monitor.observe(WIFI_B, now=0)
        failed = monitor.observe(WIFI_B, now=3)
        limited = monitor.observe(WIFI_B, now=6)

        self.assertEqual(failed.event, MonitorEvent.RESTART_FAILED)
        self.assertEqual(limited.event, MonitorEvent.RATE_LIMITED)
        self.assertEqual(monitor.current_signature, WIFI_A)
        self.assertNotIn("synthetic restart failure", limited.message)

        recorder.fail_restart = False
        pending = monitor.observe(WIFI_B, now=34)
        restarted = monitor.observe(WIFI_B, now=37)
        self.assertEqual(pending.event, MonitorEvent.PENDING)
        self.assertEqual(restarted.event, MonitorEvent.RESTARTED)
        self.assertEqual(monitor.current_signature, WIFI_B)

    def test_detect_signature_includes_interface_route_and_resolved_proxy_ips(self):
        route = {
            "interfaceIndex": 8,
            "interfaceName": "Wi-Fi",
            "localIPv4": "192.168.1.20",
            "gateway": "192.168.1.1",
            "routeMetric": 35,
        }

        signature = detect_network_signature(
            "server.example",
            route_reader=lambda: route,
            resolver=lambda _host: ("203.0.113.53", "203.0.113.52"),
        )

        self.assertEqual(signature.interface_index, 8)
        self.assertEqual(signature.interface_name, "Wi-Fi")
        self.assertEqual(signature.local_ipv4, "192.168.1.20")
        self.assertEqual(signature.gateway, "192.168.1.1")
        self.assertEqual(signature.route_metric, 35)
        self.assertEqual(signature.proxy_ipv4, ("203.0.113.52", "203.0.113.53"))

    def test_detect_returns_none_when_no_physical_default_route(self):
        called = []
        signature = detect_network_signature(
            "server.example",
            route_reader=lambda: None,
            resolver=lambda host: called.append(host),
        )

        self.assertIsNone(signature)
        self.assertEqual(called, [])

    def test_repeated_route_probe_never_opens_a_console_window(self):
        completed = mock.Mock(returncode=0, stdout="")
        with mock.patch(
            "tun_controller.network_monitor.subprocess.run", return_value=completed
        ) as run:
            self.assertIsNone(read_windows_physical_default_route())

        self.assertEqual(
            run.call_args.kwargs["creationflags"],
            getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


if __name__ == "__main__":
    unittest.main()
