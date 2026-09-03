import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tun_controller.v2rayn_source import (  # noqa: E402
    _connect_read_only,
    list_v2rayn_profiles,
    load_v2rayn_config,
)


PROFILE_COLUMNS = {
    "indexId": "varchar",
    "configType": "INTEGER",
    "configVersion": "INTEGER",
    "address": "varchar",
    "port": "INTEGER",
    "id": "varchar",
    "security": "varchar",
    "network": "varchar",
    "remarks": "varchar",
    "streamSecurity": "varchar",
    "allowInsecure": "varchar",
    "flow": "varchar",
    "sni": "varchar",
    "alpn": "varchar",
    "fingerprint": "varchar",
    "publicKey": "varchar",
    "shortId": "varchar",
    "spiderX": "varchar",
    "Password": "varchar",
    "Username": "varchar",
    "Mldsa65Verify": "varchar",
    "Cert": "varchar",
    "CertSha": "varchar",
    "EchConfigList": "varchar",
    "VerifyPeerCertByName": "varchar",
    "ProtoExtra": "varchar",
    "TransportExtra": "varchar",
    "Ports": "varchar",
}


class V2rayNSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.app_root = Path(self.temp.name)
        (self.app_root / "guiConfigs").mkdir()
        self.db_path = self.app_root / "guiConfigs" / "guiNDB.db"
        self._create_database()
        self._write_gui_config()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _create_database(self) -> None:
        connection = sqlite3.connect(self.db_path)
        columns = ",".join(f'"{name}" {kind}' for name, kind in PROFILE_COLUMNS.items())
        connection.execute(f"CREATE TABLE ProfileItem ({columns})")
        connection.execute(
            "CREATE TABLE RoutingItem (id varchar, remarks varchar, ruleSet varchar, "
            "domainStrategy varchar, IsActive INTEGER, sort INTEGER)"
        )
        profile = {name: None for name in PROFILE_COLUMNS}
        profile.update(
            {
                "indexId": "selected-profile",
                "configType": 7,
                "configVersion": 4,
                "address": "vpn.secret.example",
                "port": 55807,
                "network": "",
                "remarks": "Current HY2",
                "streamSecurity": "tls",
                "allowInsecure": "false",
                "sni": "edge.example",
                "alpn": "h3",
                "fingerprint": "chrome",
                "Password": "super-secret-password",
                "ProtoExtra": json.dumps(
                    {"UpMbps": 50, "DownMbps": 100, "HopInterval": "30"}
                ),
                "TransportExtra": "{}",
            }
        )
        names = list(profile)
        placeholders = ",".join("?" for _ in names)
        connection.execute(
            f"INSERT INTO ProfileItem ({','.join(names)}) VALUES ({placeholders})",
            [profile[name] for name in names],
        )
        rules = [
            {
                "Id": "1",
                "Enabled": True,
                "Domain": ["domain:example.cn"],
                "OutboundTag": "direct",
                "Remarks": "direct domain",
            },
            {
                "Id": "2",
                "Enabled": False,
                "Port": "443",
                "Network": "udp",
                "OutboundTag": "block",
            },
            {
                "Id": "3",
                "Enabled": True,
                "Ip": ["geoip:private"],
                "OutboundTag": "direct",
            },
            {
                "Id": "4",
                "Enabled": True,
                "Domain": ["geosite:openai"],
                "OutboundTag": "proxy",
            },
        ]
        connection.execute(
            "INSERT INTO RoutingItem VALUES (?,?,?,?,?,?)",
            ("active-route", "My Whitelist", json.dumps(rules), "AsIs", 1, 1),
        )
        connection.commit()
        connection.close()

    def _write_gui_config(self) -> None:
        value = {
            "IndexId": "selected-profile",
            "RoutingBasicItem": {"RoutingIndexId": None, "DomainStrategy": "AsIs"},
            "TunModeItem": {"RouteExcludeAddress": ["203.0.113.7/32"]},
            "CoreBasicItem": {"DefFingerprint": "chrome"},
        }
        (self.app_root / "guiConfigs" / "guiNConfig.json").write_text(
            json.dumps(value), encoding="utf-8"
        )

    def test_loads_selected_profile_and_active_enabled_rules(self) -> None:
        imported = load_v2rayn_config(self.app_root)

        self.assertEqual(imported.profile.config_type, 7)
        self.assertEqual(imported.profile.remarks, "Current HY2")
        self.assertEqual(imported.profile.password, "super-secret-password")
        self.assertEqual(imported.profile.protocol_extra["UpMbps"], 50)
        self.assertEqual(imported.route_name, "My Whitelist")
        self.assertEqual(imported.route_domain_strategy, "AsIs")
        self.assertEqual(len(imported.rules), 3)
        self.assertEqual([rule.outbound_tag for rule in imported.rules], ["direct", "direct", "proxy"])
        self.assertEqual(imported.route_exclusions, ("203.0.113.7/32",))

    def test_repr_never_contains_credentials_or_server_address(self) -> None:
        imported = load_v2rayn_config(self.app_root)
        rendered = repr(imported)

        self.assertNotIn("super-secret-password", rendered)
        self.assertNotIn("vpn.secret.example", rendered)
        self.assertIn("Current HY2", rendered)
        self.assertIn("My Whitelist", rendered)

    def test_lists_safe_profiles_and_can_load_an_explicit_choice(self) -> None:
        connection = sqlite3.connect(self.db_path)
        profile = {name: None for name in PROFILE_COLUMNS}
        profile.update(
            {
                "indexId": "grpc-choice",
                "configType": 5,
                "configVersion": 2,
                "address": "second.secret.example",
                "port": 443,
                "network": "grpc",
                "remarks": "Selectable gRPC",
                "streamSecurity": "tls",
                "Password": "another-secret",
                "ProtoExtra": "{}",
                "TransportExtra": "{}",
            }
        )
        names = list(profile)
        connection.execute(
            f"INSERT INTO ProfileItem ({','.join(names)}) VALUES ({','.join('?' for _ in names)})",
            [profile[name] for name in names],
        )
        connection.commit()
        connection.close()

        choices = list_v2rayn_profiles(self.app_root)
        self.assertEqual(len(choices), 2)
        self.assertTrue(all(choice.supported for choice in choices))
        self.assertTrue(next(item for item in choices if item.profile_id == "selected-profile").is_selected)
        rendered = repr(choices)
        self.assertNotIn("second.secret.example", rendered)
        self.assertNotIn("another-secret", rendered)

        imported = load_v2rayn_config(self.app_root, profile_id="grpc-choice")
        self.assertEqual(imported.profile.remarks, "Selectable gRPC")

    def test_retries_transient_database_lock(self) -> None:
        attempts = []

        def connector(*args, **kwargs):
            attempts.append(1)
            if len(attempts) < 3:
                raise sqlite3.OperationalError("database is locked")
            return sqlite3.connect(":memory:")

        connection = _connect_read_only(
            self.db_path,
            attempts=3,
            retry_delay=0,
            connector=connector,
        )
        connection.close()
        self.assertEqual(len(attempts), 3)

    def test_does_not_retry_non_lock_database_errors(self) -> None:
        def connector(*args, **kwargs):
            raise sqlite3.OperationalError("malformed database schema")

        with self.assertRaisesRegex(sqlite3.OperationalError, "malformed"):
            _connect_read_only(
                self.db_path,
                attempts=3,
                retry_delay=0,
                connector=connector,
            )


if __name__ == "__main__":
    unittest.main()
