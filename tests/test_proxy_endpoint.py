import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tun_controller.network_monitor import NetworkDetectionError
from tun_controller.proxy_endpoint import resolve_proxy_server_ipv4


class ProxyEndpointTests(unittest.TestCase):
    def test_live_verified_core_endpoint_has_priority_over_dns(self):
        dns_calls = []
        result = resolve_proxy_server_ipv4(
            "node.example",
            443,
            Path(r"D:\v2rayN"),
            active_reader=lambda _root, _port: ("8.8.8.8",),
            dns_resolver=lambda host: dns_calls.append(host),
        )
        self.assertEqual(result, ("8.8.8.8",))
        self.assertEqual(dns_calls, [])

    def test_fake_live_endpoint_is_discarded_before_dns_fallback(self):
        result = resolve_proxy_server_ipv4(
            "node.example",
            443,
            Path(r"D:\v2rayN"),
            active_reader=lambda _root, _port: ("198.18.0.20",),
            dns_resolver=lambda _host: ("1.1.1.1",),
        )
        self.assertEqual(result, ("1.1.1.1",))

    def test_fake_only_resolution_fails_closed(self):
        with self.assertRaises(NetworkDetectionError) as raised:
            resolve_proxy_server_ipv4(
                "node.example",
                443,
                Path(r"D:\v2rayN"),
                active_reader=lambda _root, _port: (),
                dns_resolver=lambda _host: ("198.18.0.20", "198.19.255.1"),
            )
        self.assertIn("fake-IP", str(raised.exception))
        self.assertNotIn("198.18.0.20", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
