import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tun_gui.monitor import (
    ConnectionAccumulator,
    fetch_connections,
    format_rate,
    format_transfer,
)


def connection(
    connection_id: str,
    *,
    host: str,
    chain: str,
    upload: int,
    download: int,
    process: str = "browser.exe",
    inbound_type: str = "TUN",
) -> dict:
    return {
        "id": connection_id,
        "metadata": {
            "host": host,
            "destinationIP": "203.0.113.1",
            "destinationPort": "443",
            "process": process,
            "type": inbound_type,
        },
        "upload": upload,
        "download": download,
        "start": "2026-09-03T12:34:56+08:00",
        "chains": [chain],
    }


class ConnectionAccumulatorTests(unittest.TestCase):
    def test_calculates_proxy_and_direct_rates_from_connection_deltas(self):
        monitor = ConnectionAccumulator()
        first = {
            "connections": [
                connection("p", host="google.com", chain="proxy-node", upload=100, download=200),
                connection("d", host="baidu.com", chain="DIRECT-BOUND", upload=50, download=80),
            ]
        }
        monitor.update(first, sampled_at=10.0)

        second = {
            "connections": [
                connection("p", host="google.com", chain="proxy-node", upload=300, download=600),
                connection("d", host="baidu.com", chain="DIRECT-BOUND", upload=150, download=280),
            ]
        }
        result = monitor.update(second, sampled_at=12.0)

        self.assertEqual(result["rates"]["proxy"], {"up": 100.0, "down": 200.0})
        self.assertEqual(result["rates"]["direct"], {"up": 50.0, "down": 100.0})

    def test_keeps_recently_closed_connections_and_limits_view_to_five(self):
        monitor = ConnectionAccumulator()
        for index in range(6):
            monitor.update(
                {
                    "connections": [
                        connection(
                            str(index),
                            host=f"site-{index}.example",
                            chain="proxy-node",
                            upload=index,
                            download=index,
                        )
                    ]
                },
                sampled_at=float(index + 1),
            )

        result = monitor.update({"connections": []}, sampled_at=8.0)

        self.assertEqual(len(result["connections"]), 5)
        self.assertEqual(result["connections"][0]["target"], "site-5.example:443")
        self.assertTrue(all(not item["active"] for item in result["connections"]))

    def test_human_readable_units(self):
        self.assertEqual(format_rate(2048), "2.0 KB/s")
        self.assertEqual(format_transfer(1024, 2 * 1024 * 1024), "↑ 1.0 KB  ↓ 2.0 MB")

    def test_groups_active_connections_by_application_and_identifies_tun(self):
        monitor = ConnectionAccumulator()
        monitor.update(
            {
                "connections": [
                    connection(
                        "one", host="one.example", chain="proxy-node", upload=10, download=20
                    ),
                    connection(
                        "two", host="two.example", chain="DIRECT-BOUND", upload=30, download=40
                    ),
                ]
            },
            sampled_at=1.0,
        )
        result = monitor.update(
            {
                "connections": [
                    connection(
                        "one", host="one.example", chain="proxy-node", upload=110, download=220
                    ),
                    connection(
                        "two", host="two.example", chain="DIRECT-BOUND", upload=130, download=240
                    ),
                ]
            },
            sampled_at=3.0,
        )

        self.assertEqual(len(result["applications"]), 1)
        application = result["applications"][0]
        self.assertEqual(application["process"], "browser.exe")
        self.assertEqual(application["source"], "tun")
        self.assertEqual(application["route"], "mixed")
        self.assertEqual(application["connections"], 2)
        self.assertEqual(application["up"], 100.0)
        self.assertEqual(application["down"], 200.0)
        self.assertEqual(result["connections"][0]["source"], "tun")

    def test_controller_reader_is_loopback_only_and_uses_bearer_secret(self):
        response = mock.MagicMock()
        response.__enter__.return_value.readline.return_value = b'{"connections":[]}\n'
        response.__exit__.return_value = False
        with tempfile.TemporaryDirectory() as directory:
            access_path = Path(directory) / "access.json"
            access_path.write_text(
                json.dumps({"port": 19092, "secret": "temporary-secret"}),
                encoding="utf-8",
            )
            with mock.patch("tun_gui.monitor.urllib.request.urlopen", return_value=response) as opened:
                result = fetch_connections(access_path)

        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:19092/connections?interval=1000")
        self.assertEqual(request.get_header("Authorization"), "Bearer temporary-secret")
        self.assertEqual(result, {"connections": []})


if __name__ == "__main__":
    unittest.main()
