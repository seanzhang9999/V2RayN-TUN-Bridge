"""Convert SwitchyOmega condition lists into pasteable v2rayN rules."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, replace
from typing import Iterable

from tun_controller.models import RoutingRule


@dataclass(frozen=True)
class ImportResult:
    rules: tuple[RoutingRule, ...]
    skipped: tuple[str, ...]


def parse_switchyomega_rules(raw: str) -> ImportResult:
    rules: list[RoutingRule] = []
    skipped: list[str] = []
    for index, raw_line in enumerate(raw.splitlines(), start=1):
        # v2rayN displays list values with trailing commas in several editors,
        # so accept copied lines in both `domain:x` and `domain:x,` form.
        line = raw_line.strip().rstrip(",").strip()
        if not line or line.startswith(";") or (line.startswith("[") and line.endswith("]")):
            continue
        negative = line.startswith("!")
        if negative:
            line = line[1:].strip()
        if line.startswith(("http://", "https://")):
            line = re.sub(r"^https?://", "", line, flags=re.IGNORECASE)
        line = line.strip("[]()")
        converted = _normalize_entry(line) if line else None
        if converted is None:
            skipped.append(f"line {index}: {raw_line.strip()}")
            continue
        item_type, value = converted
        common = {
            "rule_id": f"switchyomega-{item_type}-{index}",
            "remarks": line,
            "outbound_tag": "direct" if negative else "proxy",
        }
        if item_type == "domain":
            rules.append(RoutingRule(**common, domains=(f"domain:{value.replace('*', '').lstrip('.')}",)))
        elif item_type == "full":
            rules.append(RoutingRule(**common, domains=(f"full:{value}",)))
        elif item_type == "ip":
            rules.append(RoutingRule(**common, ips=(value,)))
        elif item_type == "process":
            rules.append(RoutingRule(**common, processes=(value,)))
    return ImportResult(tuple(rules), tuple(skipped))


def _normalize_entry(line: str) -> tuple[str, str] | None:
    if "," in line:
        return None
    if line.startswith(("domain:", "full:", "ip:", "process:")):
        prefix, value = line.split(":", 1)
        return (prefix, value.strip()) if value.strip() else None
    try:
        ipaddress.ip_network(line, strict=False)
        return "ip", line
    except ValueError:
        pass
    if "*" in line or line.lower().endswith(".local"):
        return "domain", line
    if "\\" in line:
        return "process", line
    return "full", line


def format_for_v2rayn_rules(rules: Iterable[RoutingRule]) -> tuple[str, ...]:
    """Return PROXY rules first and DIRECT rules second."""
    proxy_lines: list[str] = []
    direct_lines: list[str] = []
    for rule in rules:
        target = "DIRECT" if str(rule.outbound_tag).lower() == "direct" else "PROXY"
        output = direct_lines if target == "DIRECT" else proxy_lines
        for domain in rule.domains:
            prefix, _, value = domain.partition(":")
            kind = {"full": "DOMAIN", "domain": "DOMAIN-SUFFIX", "keyword": "DOMAIN-KEYWORD", "regexp": "DOMAIN-REGEX"}.get(prefix.lower())
            if kind and value:
                output.append(f"{kind},{value},{target}")
        output.extend(f"IP-CIDR,{value},no-resolve,{target}" for value in rule.ips if value)
        output.extend(f"PROCESS-NAME,{value},{target}" for value in rule.processes if value)
    return tuple(proxy_lines + direct_lines)


def parse_managed_rule_lines(raw: str, outbound: str) -> tuple[RoutingRule, ...]:
    """Parse an editable managed list while forcing its selected route."""
    result = parse_switchyomega_rules(raw)
    return tuple(replace(rule, outbound_tag=outbound) for rule in result.rules)


def merge_routing_rules(*groups: Iterable[RoutingRule]) -> tuple[RoutingRule, ...]:
    """Merge rule inputs without repeating the same match and outbound."""
    result: list[RoutingRule] = []
    seen: set[tuple[object, ...]] = set()
    for group in groups:
        for rule in group:
            key = (
                rule.outbound_tag.lower(),
                tuple(_canonical_domain(value) for value in rule.domains),
                rule.ips,
                rule.processes,
                rule.port,
                rule.network,
            )
            if key not in seen:
                seen.add(key)
                result.append(rule)
    return tuple(result)


def _canonical_domain(value: str) -> str:
    text = value.strip().rstrip(",").strip()
    if text.lower().startswith(("domain:", "full:")):
        text = text.split(":", 1)[1]
    return text.lstrip("*+").lstrip(".").casefold()


def format_managed_rule_lines(rules: Iterable[RoutingRule]) -> str:
    """Render managed values in the same plain style shown by v2rayN."""
    values: list[str] = []
    for rule in rules:
        for domain in rule.domains:
            lowered = domain.lower()
            if lowered.startswith(("domain:", "full:")):
                domain = domain.split(":", 1)[1]
            values.append(domain)
        values.extend(rule.ips)
        values.extend(f"process:{process}" for process in rule.processes)
    return "\n".join(dict.fromkeys(value for value in values if value))
