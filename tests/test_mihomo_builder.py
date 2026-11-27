import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from tun_controller.mihomo_builder import (
    MihomoBuildError,
    build_mihomo_config,
    build_mihomo_safe_summary,
)
from tun_controller.models import ImportedConfig, RoutingRule, SelectedProfile
from tun_controller.network_monitor import NetworkSignature


MIHOMO = PROJECT_ROOT / "runtime" / "mihomo.exe"
GEO_ROOT = PROJECT_ROOT / "runtime"


def imported_config() -> ImportedConfig:
    return ImportedConfig(
        profile=SelectedProfile(
            index_id="fixture",
            config_type=5,
            config_version=2,
            remarks="fixture vless",
            address="secret-server.example",
            port=443,
            password="11111111-1111-1111-1111-111111111111",
            network="grpc",
            stream_security="tls",
            sni="cdn.example.com",
            alpn=("h2",),
            fingerprint="chrome",
            transport_extra={"GrpcServiceName": "fixture-service"},
        ),
        route_id="route",
        route_name="fixture route",
        route_domain_strategy="AsIs",
        rules=(
            RoutingRule("1", "cn", "direct", domains=("geosite:cn",)),
            RoutingRule("2", "private", "direct", ips=("geoip:private",)),
            RoutingRule("3", "literal", "direct", domains=("domain:example.cn",)),
            RoutingRule("4", "blocked", "block", domains=("full:blocked.example",)),
        ),
        route_exclusions=("198.51.100.7/32",),
        default_fingerprint="chrome",
        gui_modified_ns=1,
        database_modified_ns=2,
    )


SIGNATURE = NetworkSignature(
    8, "Wi-Fi", "192.168.1.20", "192.168.1.1", 35, ("203.0.113.52",)
)


class MihomoBuilderTests(unittest.TestCase):
    def test_guarded_tun_preserves_ssh_route_to_node_and_matches_only_xray(self):
        from types import SimpleNamespace
        relay = SimpleNamespace(exe=Path("C:/v2rayN/bin/Xray/xray.exe"), port=18000,
                                identity="00000000-0000-4000-8000-000000000001",
                                hosts={"secret-server.example": ["203.0.113.52"]})
        cfg = build_mihomo_config(imported_config(), SIGNATURE, mode="full-ipv4-tun",
                                  use_local_upstream=True, physical_egress=relay)
        self.assertEqual(cfg["tun"]["route-exclude-address"], ["127.0.0.0/8"])
        self.assertEqual(cfg["rules"], [f"PROCESS-PATH,{relay.exe},XRAY-PHYSICAL", "MATCH,PROXY"])
        self.assertEqual(cfg["proxies"][0]["port"], 1081)
        self.assertEqual(cfg["proxies"][1]["uuid"], relay.identity)
        self.assertEqual(cfg["hosts"], relay.hosts)
        self.assertIn("secret-server.example", cfg["dns"]["fake-ip-filter"])
        self.assertEqual(cfg["dns"]["nameserver"], ["https://1.1.1.1/dns-query#PROXY"])
        relay.hosts = {"other.example": ["203.0.113.52"]}
        with self.assertRaises(MihomoBuildError):
            build_mihomo_config(imported_config(), SIGNATURE, mode="full-ipv4-tun",
                                use_local_upstream=True, physical_egress=relay)

    def test_only_exact_dns_names_are_pinned(self):
        from tun_controller.physical_egress import endpoint_hosts
        addresses = ("203.0.113.52", "203.0.113.53")
        self.assertEqual(endpoint_hosts("NODE.example.", addresses),
                         {"node.example": list(addresses)})
        self.assertEqual(endpoint_hosts("203.0.113.52", addresses), {})
        for invalid in ("*.example", "+.example", "bad,example", ""):
            with self.assertRaises(ValueError):
                endpoint_hosts(invalid, addresses)

    def test_local_socks_upstream_accepts_node_protocol_unknown_to_bridge(self):
        from dataclasses import replace

        imported = imported_config()
        imported = replace(imported, profile=replace(imported.profile, config_type=999))
        config = build_mihomo_config(
            imported, SIGNATURE, mode="mixed-only", use_local_upstream=True
        )
        self.assertEqual(config["proxies"][0]["type"], "socks5")
        self.assertEqual(config["proxies"][0]["port"], 1081)

    def test_local_upstream_keeps_base_proxy_and_drops_imported_direct_rules(self):
        config = build_mihomo_config(
            imported_config(), SIGNATURE, mode="full-ipv4-tun", use_local_upstream=True
        )
        self.assertEqual(config["mixed-port"], 1082)
        self.assertEqual(config["proxies"], [{
            "name": "proxy-node", "type": "socks5", "server": "127.0.0.1",
            "port": 1081, "udp": True,
        }])
        self.assertEqual(config["rules"], ["MATCH,PROXY"])
        self.assertTrue(config["tun"]["strict-route"])
        self.assertNotIn("198.51.100.7/32", config["tun"]["route-exclude-address"])

    def build(self, mode="full-ipv4-tun"):
        return build_mihomo_config(imported_config(), SIGNATURE, mode=mode)

    def test_mixed_only_uses_1082_without_tun(self):
        config = self.build("mixed-only")
        self.assertEqual(config["mixed-port"], 1082)
        self.assertFalse(config["tun"]["enable"])

    def test_mixed_port_can_be_assigned_to_v2rayn_endpoint(self):
        config = build_mihomo_config(
            imported_config(), SIGNATURE, mode="full-ipv4-tun", mixed_port=1081
        )
        self.assertEqual(config["mixed-port"], 1081)

        with self.assertRaises(MihomoBuildError):
            build_mihomo_config(
                imported_config(), SIGNATURE, mode="full-ipv4-tun", mixed_port=0
            )

    def test_single_and_full_tun_are_ipv4_only_and_exclude_backend(self):
        single = self.build("single-address-tun")
        full = self.build("full-ipv4-tun")
        self.assertEqual(single["tun"]["route-address"], ["1.0.0.1/32"])
        self.assertNotIn("route-address", full["tun"])
        self.assertEqual(full["tun"]["stack"], "gvisor")
        self.assertEqual(full["tun"]["device"], "mihomo_tun_controller")
        self.assertIn("203.0.113.52/32", full["tun"]["route-exclude-address"])
        self.assertFalse(full["ipv6"])

    def test_builds_pinned_vless_grpc_and_bound_direct(self):
        config = self.build()
        proxy = next(item for item in config["proxies"] if item["name"] == "proxy-node")
        direct = next(item for item in config["proxies"] if item["name"] == "DIRECT-BOUND")
        self.assertEqual(proxy["type"], "vless")
        self.assertEqual(proxy["server"], "203.0.113.52")
        self.assertEqual(proxy["interface-name"], "Wi-Fi")
        self.assertEqual(proxy["grpc-opts"]["grpc-service-name"], "fixture-service")
        self.assertEqual(proxy["servername"], "cdn.example.com")
        self.assertEqual(direct, {
            "name": "DIRECT-BOUND",
            "type": "direct",
            "udp": True,
            "ip-version": "ipv4",
            "interface-name": "Wi-Fi",
        })

    def test_builds_native_hysteria2_with_v2rayn_bandwidth_and_obfs(self):
        imported = imported_config()
        profile = replace(
            imported.profile,
            config_type=7,
            network="",
            sni="hy.example.com",
            alpn=("h3",),
            protocol_extra={
                "Ports": "443:445",
                "SalamanderPass": "obfs-secret",
            },
        )
        imported = replace(
            imported,
            profile=profile,
            hysteria_up_mbps=30,
            hysteria_down_mbps=200,
            hysteria_hop_interval=25,
        )
        config = build_mihomo_config(imported, SIGNATURE, mode="mixed-only")
        proxy = next(item for item in config["proxies"] if item["name"] == "proxy-node")
        self.assertEqual(proxy["type"], "hysteria2")
        self.assertEqual(proxy["server"], "203.0.113.52")
        self.assertEqual(proxy["password"], profile.password)
        self.assertEqual(proxy["ports"], "443-445")
        self.assertEqual(proxy["hop-interval"], 25)
        self.assertEqual(proxy["up"], "30 Mbps")
        self.assertEqual(proxy["down"], "200 Mbps")
        self.assertEqual(proxy["obfs"], "salamander")
        self.assertEqual(proxy["obfs-password"], "obfs-secret")
        self.assertEqual(proxy["interface-name"], "Wi-Fi")
        self.assertEqual(proxy["sni"], "hy.example.com")

    def test_full_tun_uses_explicit_physical_interface(self):
        config = self.build()
        self.assertEqual(config["interface-name"], "Wi-Fi")
        self.assertEqual(config["find-process-mode"], "strict")
        self.assertFalse(config["tun"]["auto-detect-interface"])

    def test_controller_is_loopback_only_and_requires_a_secret(self):
        config = build_mihomo_config(
            imported_config(),
            SIGNATURE,
            mode="full-ipv4-tun",
            controller_port=19092,
            controller_secret="fixture-controller-secret",
        )
        self.assertEqual(config["external-controller"], "127.0.0.1:19092")
        self.assertEqual(config["secret"], "fixture-controller-secret")
        self.assertNotIn(
            "fixture-controller-secret",
            repr(build_mihomo_safe_summary(imported_config(), config)),
        )
        with self.assertRaises(MihomoBuildError):
            build_mihomo_config(
                imported_config(), SIGNATURE, mode="full-ipv4-tun", controller_port=19092
            )

    def test_empty_xray_grpc_service_uses_literal_xray_path(self):
        imported = imported_config()
        profile = replace(imported.profile, transport_extra={"GrpcServiceName": ""})
        imported = replace(imported, profile=profile)
        config = build_mihomo_config(imported, SIGNATURE, mode="mixed-only")
        proxy = next(item for item in config["proxies"] if item["name"] == "proxy-node")
        self.assertEqual(proxy["grpc-opts"]["grpc-service-name"], "//Tun")

    def test_translates_ordered_route_actions(self):
        rules = self.build()["rules"]
        self.assertIn("GEOSITE,cn,DIRECT-BOUND", rules)
        self.assertIn("DOMAIN-SUFFIX,example.cn,DIRECT-BOUND", rules)
        self.assertIn("DOMAIN,blocked.example,REJECT", rules)
        self.assertTrue(any(rule.startswith("IP-CIDR,10.0.0.0/8,DIRECT-BOUND") for rule in rules))
        self.assertEqual(rules[-1], "MATCH,PROXY")

    def test_plain_and_wildcard_domains_use_suffix_matching(self):
        imported = replace(
            imported_config(),
            rules=(
                RoutingRule("plain", "plain", "direct", domains=("linkedin.com",)),
                RoutingRule("wildcard", "wildcard", "proxy", domains=("*.google.com",)),
            ),
        )
        rules = build_mihomo_config(
            imported, SIGNATURE, mode="full-ipv4-tun", mixed_port=1081
        )["rules"]
        self.assertIn("DOMAIN-SUFFIX,linkedin.com,DIRECT-BOUND", rules)
        self.assertIn("DOMAIN-SUFFIX,google.com,PROXY", rules)

    def test_dns_is_internal_fake_ip_ipv4(self):
        dns = self.build()["dns"]
        self.assertTrue(dns["enable"])
        self.assertFalse(dns["ipv6"])
        self.assertEqual(dns["enhanced-mode"], "fake-ip")
        self.assertEqual(dns["nameserver"], ["https://1.1.1.1/dns-query#PROXY"])
        self.assertEqual(dns["proxy-server-nameserver"], ["system"])
        self.assertEqual(dns["direct-nameserver"], ["system"])
        self.assertFalse(dns["direct-nameserver-follow-policy"])
        self.assertIn("any:53", self.build()["tun"]["dns-hijack"])

    def test_sniffer_recovers_domains_from_ip_only_tun_connections(self):
        sniffer = self.build()["sniffer"]
        self.assertTrue(sniffer["enable"])
        self.assertTrue(sniffer["force-dns-mapping"])
        self.assertTrue(sniffer["parse-pure-ip"])
        self.assertTrue(sniffer["override-destination"])
        self.assertEqual(sniffer["sniff"]["HTTP"]["ports"], [80, "8080-8880"])
        self.assertEqual(sniffer["sniff"]["TLS"]["ports"], [443, 8443])
        self.assertEqual(sniffer["sniff"]["QUIC"]["ports"], [443, 8443])

    def test_safe_summary_reports_sniffer_state(self):
        summary = build_mihomo_safe_summary(imported_config(), self.build())
        self.assertTrue(summary["sniffer_enabled"])

    def test_invalid_mode_and_unsupported_protocol_fail_safely(self):
        with self.assertRaises(MihomoBuildError):
            build_mihomo_config(imported_config(), SIGNATURE, mode="bad")

    def test_fake_ip_can_never_be_pinned_as_the_proxy_endpoint(self):
        fake_signature = replace(SIGNATURE, proxy_ipv4=("198.18.0.20",))
        with self.assertRaises(MihomoBuildError):
            build_mihomo_config(imported_config(), fake_signature, mode="mixed-only")

    def test_summary_hides_endpoint_and_auth(self):
        summary = repr(build_mihomo_safe_summary(imported_config(), self.build()))
        self.assertNotIn("secret-server.example", summary)
        self.assertNotIn("11111111-1111-1111-1111-111111111111", summary)
        self.assertNotIn("203.0.113.52", summary)

    @unittest.skipUnless(MIHOMO.exists(), "Mihomo is not installed")
    def test_mihomo_accepts_synthetic_config_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(self.build()), encoding="utf-8")
            completed = subprocess.run(
                [str(MIHOMO), "-t", "-d", str(GEO_ROOT), "-f", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)


if __name__ == "__main__":
    unittest.main()
