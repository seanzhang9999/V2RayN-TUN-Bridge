import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from tun_controller.models import RoutingRule
from tun_controller.v2rayn_route_writer import update_active_v2rayn_route


class V2rayNRouteWriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        config = self.root / "guiConfigs"
        config.mkdir()
        (config / "guiNConfig.json").write_text("{}", encoding="utf-8")
        connection = sqlite3.connect(config / "guiNDB.db")
        connection.execute(
            "CREATE TABLE RoutingItem (id TEXT, remarks TEXT, ruleSet TEXT, ruleNum INTEGER, sort INTEGER, IsActive INTEGER)"
        )
        original = [{"Id": "original", "OutboundTag": "direct", "Domain": ["geosite:cn"], "Enabled": True}]
        connection.execute(
            "INSERT INTO RoutingItem VALUES (?,?,?,?,?,?)",
            ("route-v4", "V4 whitelist", json.dumps(original), 1, 1, 1),
        )
        connection.commit()
        connection.close()

    def tearDown(self):
        self.temp.cleanup()

    def test_updates_active_route_and_creates_restorable_backup(self):
        rules = (
            RoutingRule("p", "proxy", "proxy", domains=("domain:google.com",)),
            RoutingRule("d", "direct", "direct", domains=("domain:zhihu.com",)),
        )
        report = update_active_v2rayn_route(
            self.root, rules, backup_root=self.root / "backups"
        )
        self.assertEqual(report["route_name"], "V4 whitelist")
        self.assertTrue(Path(report["backup_path"]).is_file())

        connection = sqlite3.connect(self.root / "guiConfigs" / "guiNDB.db")
        raw, count = connection.execute(
            "SELECT ruleSet, ruleNum FROM RoutingItem WHERE id='route-v4'"
        ).fetchone()
        connection.close()
        updated = json.loads(raw)
        self.assertEqual(count, 3)
        self.assertEqual(updated[0]["Id"], "tun-bridge-import-proxy")
        self.assertEqual(updated[1]["Id"], "tun-bridge-import-direct")
        self.assertEqual(updated[0]["Domain"], ["google.com"])
        self.assertEqual(updated[1]["Domain"], ["zhihu.com"])
        self.assertEqual(updated[2]["Id"], "original")

    def test_replaces_previous_bridge_groups_without_duplicates(self):
        first = (RoutingRule("p", "proxy", "proxy", domains=("domain:first.test",)),)
        second = (RoutingRule("p", "proxy", "proxy", domains=("domain:second.test",)),)
        update_active_v2rayn_route(self.root, first, backup_root=self.root / "backups")
        update_active_v2rayn_route(self.root, second, backup_root=self.root / "backups")
        connection = sqlite3.connect(self.root / "guiConfigs" / "guiNDB.db")
        items = json.loads(connection.execute("SELECT ruleSet FROM RoutingItem").fetchone()[0])
        connection.close()
        bridge = [item for item in items if str(item.get("Id", "")).startswith("tun-bridge-")]
        self.assertEqual(len(bridge), 1)
        self.assertEqual(bridge[0]["Domain"], ["second.test"])


if __name__ == "__main__":
    unittest.main()
