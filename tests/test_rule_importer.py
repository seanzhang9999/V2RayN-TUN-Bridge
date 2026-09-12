import unittest

from tun_controller.models import RoutingRule
from tun_controller.rule_importer import (
    format_managed_rule_lines,
    format_for_v2rayn_rules,
    merge_routing_rules,
    parse_managed_rule_lines,
    parse_switchyomega_rules,
)


class RuleImporterTests(unittest.TestCase):
    def test_parses_proxy_direct_and_ip_entries(self):
        result = parse_switchyomega_rules("[SwitchyOmega Conditions]\n*.google.com\n!*.zhihu.com\n118.89.204.198")
        self.assertEqual(len(result.rules), 3)
        self.assertEqual(result.rules[0].outbound_tag, "proxy")
        self.assertEqual(result.rules[1].outbound_tag, "direct")
        self.assertEqual(result.rules[2].ips, ("118.89.204.198",))

    def test_formats_proxy_before_direct(self):
        rules = (
            RoutingRule("1", "direct", "direct", domains=("domain:zhihu.com",)),
            RoutingRule("2", "proxy", "proxy", domains=("domain:google.com",)),
        )
        self.assertEqual(format_for_v2rayn_rules(rules), (
            "DOMAIN-SUFFIX,google.com,PROXY",
            "DOMAIN-SUFFIX,zhihu.com,DIRECT",
        ))

    def test_accepts_prefixed_entries_and_urls(self):
        result = parse_switchyomega_rules("domain:example.com\nfull:exact.example.com\nip:10.0.0.1\nhttps://openai.com")
        self.assertEqual(len(result.rules), 4)
        self.assertEqual(result.skipped, ())

    def test_accepts_v2rayn_style_trailing_commas(self):
        result = parse_switchyomega_rules(
            "domain:openagi.duckdns.org,\ndomain:qq.com,\nfull:internal.example.com"
        )
        self.assertEqual(
            [rule.domains[0] for rule in result.rules],
            [
                "domain:openagi.duckdns.org",
                "domain:qq.com",
                "full:internal.example.com",
            ],
        )
        self.assertEqual(result.skipped, ())

    def test_rejects_embedded_commas_in_domain(self):
        result = parse_switchyomega_rules("domain:qq.com,domain:baidu.com")
        self.assertEqual(result.rules, ())
        self.assertEqual(len(result.skipped), 1)

    def test_managed_lists_merge_existing_and_new_without_duplicates(self):
        existing = parse_managed_rule_lines("google.com\nprocess:msedge.exe", "proxy")
        imported = parse_switchyomega_rules("*.google.com\n!*.zhihu.com").rules
        merged = merge_routing_rules(existing, imported)
        self.assertEqual(len(merged), 3)
        self.assertEqual(merged[1].processes, ("msedge.exe",))
        self.assertIn("process:msedge.exe", format_managed_rule_lines(merged))


if __name__ == "__main__":
    unittest.main()
