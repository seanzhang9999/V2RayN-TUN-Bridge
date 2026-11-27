"""Direct rules must survive a mixed `domain` + `ip` condition."""
import ipaddress
import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from xray_direct import direct_items, direct_networks, literal_targets


def _varint(value):
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        out.append(bits | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _bytes_field(number, payload):
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def _int_field(number, value):
    return _varint(number << 3) + _varint(value)


def geoip_dat(countries):
    """Encode the GeoIPList subset that `_cn_networks` understands."""
    entries = b""
    for country, networks in countries:
        body = _bytes_field(1, country.encode())
        for network in networks:
            body += _bytes_field(
                2,
                _bytes_field(1, network.network_address.packed)
                + _int_field(2, network.prefixlen),
            )
        entries += _bytes_field(1, body)
    return entries


class DirectRuleTest(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        (self.root / "binConfigs").mkdir()
        (self.root / "bin").mkdir()
        self.config = self.root / "binConfigs/config.json"

    def tearDown(self):
        self._temp.cleanup()

    def _write(self, rules, outbounds=None):
        outbounds = outbounds or [
            {"tag": "proxy", "protocol": "vless"},
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ]
        self.config.write_text(
            json.dumps({"outbounds": outbounds, "routing": {"rules": rules}}),
            encoding="utf-8",
        )

    def test_mixed_domain_and_ip_rule_keeps_its_prefixes(self):
        # This is what v2rayN actually ships. Dropping the whole rule emptied the
        # WFP permit list, so every direct connection was blocked.
        self._write(
            [
                {
                    "type": "field",
                    "domain": ["geosite:cn"],
                    "ip": ["10.0.0.0/8", "192.168.0.0/16"],
                    "outboundTag": "direct",
                }
            ]
        )
        self.assertEqual(
            direct_networks(self.config),
            {
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("192.168.0.0/16"),
            },
        )

    def test_domain_only_rule_contributes_nothing(self):
        self._write(
            [{"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct"}]
        )
        self.assertEqual(direct_networks(self.config), set())

    def test_rule_without_an_explicit_type_is_a_field_rule(self):
        # Xray defaults `type` to "field"; the old check demanded the key.
        self._write([{"ip": ["172.16.0.0/12"], "outboundTag": "direct"}])
        self.assertEqual(
            direct_networks(self.config),
            {ipaddress.ip_network("172.16.0.0/12")},
        )

    def test_conditional_rule_is_not_widened_into_a_blanket_permit(self):
        self._write(
            [
                {
                    "ip": ["10.0.0.0/8"],
                    "inboundTag": ["lan"],
                    "outboundTag": "direct",
                },
                {"ip": ["10.0.0.0/8"], "source": ["10.0.0.0/8"], "outboundTag": "direct"},
            ]
        )
        self.assertEqual(direct_networks(self.config), set())

    def test_non_field_and_non_direct_rules_are_ignored(self):
        self._write(
            [
                {"type": "field", "ip": ["10.1.0.0/16"], "outboundTag": "proxy"},
                {"ip": ["10.2.0.0/16"], "outboundTag": "block"},
            ]
        )
        self.assertEqual(direct_networks(self.config), set())

    def test_default_route_and_unsupported_entries_are_ignored(self):
        self._write(
            [
                {
                    "ip": ["0.0.0.0/0", "geoip:private", "10.3.0.0/16"],
                    "outboundTag": "direct",
                }
            ]
        )
        self.assertEqual(
            direct_networks(self.config),
            {ipaddress.ip_network("10.3.0.0/16")},
        )

    def test_geoip_cn_expands_from_the_shipped_database(self):
        networks = [
            ipaddress.ip_network("223.5.5.0/24"),
            ipaddress.ip_network("223.5.5.128/25"),
        ]
        (self.root / "bin/geoip.dat").write_bytes(geoip_dat([("CN", networks)]))
        self._write(
            [
                {
                    "type": "field",
                    "domain": ["geosite:cn"],
                    "ip": ["geoip:cn"],
                    "outboundTag": "direct",
                }
            ]
        )
        self.assertEqual(
            direct_networks(self.config),
            {ipaddress.ip_network("223.5.5.0/24")},
        )

    def test_inverted_cn_record_is_rejected(self):
        body = _bytes_field(1, b"CN") + _int_field(3, 1)
        (self.root / "bin/geoip.dat").write_bytes(_bytes_field(1, body))
        self._write([{"ip": ["geoip:cn"], "outboundTag": "direct"}])
        with self.assertRaises(ValueError):
            direct_networks(self.config)

    def test_literal_targets_matches_the_permit_set(self):
        rule = {"domain": ["example.com"], "ip": ["1.2.3.4"], "outboundTag": "direct"}
        self.assertEqual(direct_items(rule), ("1.2.3.4",))
        self.assertEqual(literal_targets(rule), {ipaddress.ip_address("1.2.3.4")})
        self.assertEqual(literal_targets({"ip": ["1.2.3.4"], "user": ["x"]}), set())


if __name__ == "__main__":
    unittest.main()
