"""Translate v2rayN's selected profile and route into a Mihomo configuration."""

from __future__ import annotations

import ipaddress
from typing import Any

from tun_controller.models import ImportedConfig, RoutingRule, SelectedProfile
from tun_controller.network_monitor import NetworkSignature


class MihomoBuildError(ValueError):
    """A redaction-safe Mihomo translation error."""


_VALID_MODES = {"mixed-only", "single-address-tun", "full-ipv4-tun"}
_FAKE_IP_NETWORK = ipaddress.IPv4Network("198.18.0.0/15")
_PRIVATE_IPV4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)


def build_mihomo_config(
    imported: ImportedConfig,
    signature: NetworkSignature,
    *,
    mode: str,
    mixed_port: int = 1082,
    controller_port: int | None = None,
    controller_secret: str = "",
) -> dict[str, Any]:
    if mode not in _VALID_MODES:
        raise MihomoBuildError(f"Unsupported Mihomo test mode: {mode}")
    if not 1 <= mixed_port <= 65535:
        raise MihomoBuildError("Invalid mixed proxy port")
    if not signature.proxy_ipv4:
        raise MihomoBuildError("The selected proxy server has no pinned IPv4 address")
    proxy_ip = signature.proxy_ipv4[0]
    try:
        proxy_address = ipaddress.IPv4Address(proxy_ip)
    except ipaddress.AddressValueError as exc:
        raise MihomoBuildError("The pinned proxy address is not IPv4") from exc
    if proxy_address in _FAKE_IP_NETWORK:
        raise MihomoBuildError(
            "The pinned proxy address is a fake-IP and cannot be used as an endpoint"
        )

    tun: dict[str, Any] = {
        "enable": mode != "mixed-only",
        "device": "mihomo_tun_controller",
        "stack": "gvisor",
        "dns-hijack": ["any:53", "tcp://any:53"],
        "auto-route": True,
        "auto-detect-interface": False,
        "strict-route": False,
        "mtu": 1400,
        "route-exclude-address": _deduplicate(
            [*imported.route_exclusions, f"{proxy_ip}/32"]
        ),
    }
    if mode == "single-address-tun":
        tun["route-address"] = ["1.0.0.1/32"]

    rules: list[str] = []
    for source_rule in imported.rules:
        rules.extend(_translate_rule(source_rule))
    rules.append("MATCH,PROXY")

    config: dict[str, Any] = {
        "mixed-port": mixed_port,
        "bind-address": "127.0.0.1",
        "interface-name": signature.interface_name,
        "allow-lan": False,
        "mode": "rule",
        "find-process-mode": "strict",
        "log-level": "warning",
        "ipv6": False,
        "geodata-mode": True,
        "geodata-loader": "standard",
        "geo-auto-update": False,
        "unified-delay": True,
        "tcp-concurrent": True,
        "sniffer": {
            "enable": True,
            "force-dns-mapping": True,
            "parse-pure-ip": True,
            "override-destination": True,
            "sniff": {
                "HTTP": {
                    "ports": [80, "8080-8880"],
                    "override-destination": True,
                },
                "TLS": {"ports": [443, 8443]},
                "QUIC": {"ports": [443, 8443]},
            },
        },
        "dns": {
            "enable": True,
            "ipv6": False,
            "listen": "0.0.0.0:1053",
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter-mode": "blacklist",
            "fake-ip-filter": ["+.lan", "+.local", "localhost.ptlogin2.qq.com"],
            "respect-rules": True,
            "nameserver": ["https://1.1.1.1/dns-query#PROXY"],
            "proxy-server-nameserver": ["system"],
        },
        "tun": tun,
        "proxies": [
            _build_proxy(imported.profile, imported, proxy_ip, signature.interface_name),
            {
                "name": "DIRECT-BOUND",
                "type": "direct",
                "udp": True,
                "ip-version": "ipv4",
                "interface-name": signature.interface_name,
            },
        ],
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["proxy-node"]}
        ],
        "rules": rules,
    }
    if controller_port is not None:
        if not 1 <= controller_port <= 65535:
            raise MihomoBuildError("Invalid local controller port")
        if not controller_secret:
            raise MihomoBuildError("Local controller secret is required")
        config["external-controller"] = f"127.0.0.1:{controller_port}"
        config["secret"] = controller_secret
    return config


def build_mihomo_safe_summary(
    imported: ImportedConfig, config: dict[str, Any]
) -> dict[str, Any]:
    return {
        "profile_remarks": imported.profile.remarks,
        "protocol": {5: "vless", 7: "hysteria2"}.get(
            imported.profile.config_type, "unsupported"
        ),
        "transport": imported.profile.network.lower().strip(),
        "security": imported.profile.stream_security.lower().strip(),
        "sni_configured": bool(imported.profile.sni.strip()),
        "alpn": list(imported.profile.alpn),
        "fingerprint_configured": bool(imported.profile.fingerprint.strip()),
        "skip_certificate_verify": imported.profile.allow_insecure,
        "grpc_service_configured": bool(
            str(imported.profile.transport_extra.get("GrpcServiceName") or "").strip()
        ),
        "route_name": imported.route_name,
        "source_rule_count": len(imported.rules),
        "generated_rule_count": len(config.get("rules", [])),
        "mixed_port": config.get("mixed-port"),
        "tun_enabled": bool(config.get("tun", {}).get("enable")),
        "tun_stack": config.get("tun", {}).get("stack"),
        "dns_mode": config.get("dns", {}).get("enhanced-mode"),
        "sniffer_enabled": bool(config.get("sniffer", {}).get("enable")),
    }


def _build_proxy(
    profile: SelectedProfile,
    imported: ImportedConfig,
    proxy_ip: str,
    interface_name: str,
) -> dict[str, Any]:
    if profile.config_type == 7:
        return _build_hysteria2_proxy(
            profile, imported, proxy_ip, interface_name
        )
    if profile.config_type != 5:
        raise MihomoBuildError("Selected v2rayN protocol is not supported yet")
    proxy: dict[str, Any] = {
        "name": "proxy-node",
        "type": "vless",
        "server": proxy_ip,
        "port": profile.port,
        "uuid": profile.password,
        "udp": True,
        "ip-version": "ipv4",
        "interface-name": interface_name,
        "network": profile.network.lower().strip() or "tcp",
    }
    flow = str(profile.protocol_extra.get("Flow") or "").strip()
    if flow:
        proxy["flow"] = flow

    security = profile.stream_security.lower().strip()
    if security in {"tls", "reality"}:
        proxy["tls"] = True
        proxy["servername"] = profile.sni.strip() or profile.address.strip()
        proxy["skip-cert-verify"] = profile.allow_insecure
        if profile.alpn:
            proxy["alpn"] = list(profile.alpn)
        fingerprint = profile.fingerprint.strip() or imported.default_fingerprint.strip()
        if fingerprint:
            proxy["client-fingerprint"] = fingerprint
        if security == "reality":
            proxy["reality-opts"] = {
                "public-key": profile.public_key,
                "short-id": profile.short_id,
            }

    network = proxy["network"]
    extra = profile.transport_extra
    if network == "grpc":
        service_name = str(extra.get("GrpcServiceName") or "").strip()
        # Xray maps an empty gRPC service name to the literal path //Tun.
        # Mihomo otherwise substitutes GunService, so use its custom-path form.
        if not service_name:
            service_name = "//Tun"
        proxy["grpc-opts"] = {
            "grpc-service-name": service_name
        }
    elif network == "ws":
        ws_opts: dict[str, Any] = {"path": str(extra.get("Path") or "/")}
        host = str(extra.get("Host") or "").strip()
        if host:
            ws_opts["headers"] = {"Host": host}
        proxy["ws-opts"] = ws_opts
    elif network not in {"tcp", "raw"}:
        raise MihomoBuildError(f"Unsupported VLESS transport: {network}")
    if network == "raw":
        proxy["network"] = "tcp"
    return proxy


def _build_hysteria2_proxy(
    profile: SelectedProfile,
    imported: ImportedConfig,
    proxy_ip: str,
    interface_name: str,
) -> dict[str, Any]:
    """Translate v2rayN Hysteria2 fields to Mihomo's native schema."""
    extra = profile.protocol_extra
    proxy: dict[str, Any] = {
        "name": "proxy-node",
        "type": "hysteria2",
        "server": proxy_ip,
        "port": profile.port,
        "password": profile.password,
        "udp": True,
        "ip-version": "ipv4",
        "interface-name": interface_name,
        "sni": profile.sni.strip() or profile.address.strip(),
        "skip-cert-verify": profile.allow_insecure,
    }
    if profile.alpn:
        proxy["alpn"] = list(profile.alpn)
    if profile.verify_peer_cert_by_name:
        proxy["name-cert-verify"] = profile.verify_peer_cert_by_name

    ports = str(extra.get("Ports") or "").strip()
    if ports:
        proxy["ports"] = ports.replace(":", "-")
        proxy["hop-interval"] = max(imported.hysteria_hop_interval, 1)
    if imported.hysteria_up_mbps > 0:
        proxy["up"] = f"{imported.hysteria_up_mbps} Mbps"
    if imported.hysteria_down_mbps > 0:
        proxy["down"] = f"{imported.hysteria_down_mbps} Mbps"

    obfs_password = str(extra.get("SalamanderPass") or "").strip()
    if obfs_password:
        proxy["obfs"] = "salamander"
        proxy["obfs-password"] = obfs_password
    return proxy


def _translate_rule(rule: RoutingRule) -> list[str]:
    target = _target(rule.outbound_tag)
    result: list[str] = []
    for raw in rule.domains:
        value = raw.strip()
        lowered = value.lower()
        if lowered.startswith("geosite:"):
            result.append(f"GEOSITE,{value.split(':', 1)[1]},{target}")
        elif lowered.startswith("full:"):
            result.append(f"DOMAIN,{value.split(':', 1)[1]},{target}")
        elif lowered.startswith("domain:"):
            result.append(f"DOMAIN-SUFFIX,{value.split(':', 1)[1]},{target}")
        elif lowered.startswith("keyword:"):
            result.append(f"DOMAIN-KEYWORD,{value.split(':', 1)[1]},{target}")
        elif lowered.startswith("regexp:"):
            result.append(f"DOMAIN-REGEX,{value.split(':', 1)[1]},{target}")
        elif value:
            normalized = value.lstrip("*+").lstrip(".")
            if "." in normalized and not any(character.isspace() for character in normalized):
                result.append(f"DOMAIN-SUFFIX,{normalized},{target}")
            else:
                result.append(f"DOMAIN-KEYWORD,{value},{target}")

    for raw in rule.ips:
        value = raw.strip()
        lowered = value.lower()
        if lowered == "geoip:private":
            result.extend(
                f"IP-CIDR,{cidr},{target},no-resolve" for cidr in _PRIVATE_IPV4
            )
        elif lowered.startswith("geoip:"):
            result.append(f"GEOIP,{value.split(':', 1)[1]},{target},no-resolve")
        elif value:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise MihomoBuildError("Invalid IP route entry") from exc
            if network.version == 4:
                result.append(f"IP-CIDR,{network},{target},no-resolve")

    for port in _split_values(rule.port):
        result.append(f"DST-PORT,{port},{target}")
    for process in rule.processes:
        if process.strip():
            result.append(f"PROCESS-NAME,{process.strip()},{target}")
    for network in _split_values(rule.network):
        value = network.upper()
        if value in {"TCP", "UDP"}:
            result.append(f"NETWORK,{value},{target}")
    return result


def _target(outbound_tag: str) -> str:
    value = outbound_tag.lower().strip()
    if value == "direct":
        return "DIRECT-BOUND"
    if value in {"block", "blocked", "reject"}:
        return "REJECT"
    return "PROXY"


def _split_values(raw: str) -> list[str]:
    return [item.strip() for item in raw.replace(";", ",").split(",") if item.strip()]


def _deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
