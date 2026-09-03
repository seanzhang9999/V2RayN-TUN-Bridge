"""Immutable, redaction-safe models imported from v2rayN."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, repr=False)
class SelectedProfile:
    index_id: str
    config_type: int
    config_version: int
    remarks: str
    address: str = field(repr=False)
    port: int = 0
    password: str = field(default="", repr=False)
    username: str = field(default="", repr=False)
    network: str = ""
    stream_security: str = ""
    allow_insecure: bool = False
    sni: str = ""
    alpn: tuple[str, ...] = ()
    fingerprint: str = ""
    public_key: str = field(default="", repr=False)
    short_id: str = field(default="", repr=False)
    spider_x: str = ""
    mldsa65_verify: str = field(default="", repr=False)
    cert: str = field(default="", repr=False)
    cert_sha: str = field(default="", repr=False)
    ech_config_list: str = field(default="", repr=False)
    verify_peer_cert_by_name: str = ""
    protocol_extra: dict[str, Any] = field(default_factory=dict, repr=False)
    transport_extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def __repr__(self) -> str:
        return (
            "SelectedProfile("
            f"config_type={self.config_type}, remarks={self.remarks!r}, "
            "address='<redacted>', "
            f"port={self.port}, password='<redacted>')"
        )


@dataclass(frozen=True)
class ProfileSummary:
    """Credential-free profile metadata safe to show in a GUI."""

    profile_id: str
    remarks: str
    protocol: str
    transport: str
    security: str
    is_selected: bool
    supported: bool
    support_detail: str = ""


@dataclass(frozen=True)
class RoutingRule:
    rule_id: str
    remarks: str
    outbound_tag: str
    rule_type: Any = None
    domains: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    port: str = ""
    network: str = ""
    protocols: tuple[str, ...] = ()
    processes: tuple[str, ...] = ()
    inbound_tags: tuple[str, ...] = ()


@dataclass(frozen=True, repr=False)
class ImportedConfig:
    profile: SelectedProfile
    route_id: str
    route_name: str
    route_domain_strategy: str
    rules: tuple[RoutingRule, ...]
    route_exclusions: tuple[str, ...]
    default_fingerprint: str
    gui_modified_ns: int
    database_modified_ns: int
    hysteria_up_mbps: int = 0
    hysteria_down_mbps: int = 0
    hysteria_hop_interval: int = 30

    def __repr__(self) -> str:
        return (
            "ImportedConfig("
            f"profile={self.profile!r}, route_name={self.route_name!r}, "
            f"enabled_rule_count={len(self.rules)}, "
            f"route_exclusions={self.route_exclusions!r})"
        )
