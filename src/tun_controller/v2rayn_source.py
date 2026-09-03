"""Read the selected profile and active route directly from v2rayN storage."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tun_controller.models import (
    ImportedConfig,
    ProfileSummary,
    RoutingRule,
    SelectedProfile,
)


def find_default_app_root() -> Path | None:
    """Return a likely v2rayN directory without scanning unrelated user files."""
    candidates: list[Path] = []
    configured = os.environ.get("V2RAYN_HOME", "").strip()
    if configured:
        candidates.append(Path(configured))
    for variable, suffix in (
        ("LOCALAPPDATA", ("Programs", "v2rayN")),
        ("ProgramFiles", ("v2rayN",)),
        ("ProgramFiles(x86)", ("v2rayN",)),
    ):
        root = os.environ.get(variable, "").strip()
        if root:
            candidates.append(Path(root).joinpath(*suffix))
    candidates.append(Path.home() / "v2rayN")
    return next((path for path in candidates if (path / "v2rayN.exe").is_file()), None)


DEFAULT_APP_ROOT = find_default_app_root() or Path(r"C:\Program Files\v2rayN")


def _connect_read_only(
    database_path: Path,
    *,
    attempts: int = 5,
    retry_delay: float = 0.15,
    connector: Callable[..., sqlite3.Connection] | None = None,
) -> sqlite3.Connection:
    connect = connector or sqlite3.connect
    uri = f"file:{database_path.resolve().as_posix()}?mode=ro"
    for attempt in range(1, attempts + 1):
        try:
            return connect(uri, uri=True, timeout=0.1)
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == attempts:
                raise
            time.sleep(retry_delay)
    raise AssertionError("unreachable")


def load_v2rayn_config(
    app_root: Path = DEFAULT_APP_ROOT, *, profile_id: str | None = None
) -> ImportedConfig:
    gui_path = app_root / "guiConfigs" / "guiNConfig.json"
    database_path = app_root / "guiConfigs" / "guiNDB.db"
    with gui_path.open("r", encoding="utf-8-sig") as stream:
        gui = json.load(stream)

    selected_id = str(profile_id or gui.get("IndexId") or "").strip()
    if not selected_id:
        raise ValueError("v2rayN does not have a selected profile")

    connection = _connect_read_only(database_path)
    connection.row_factory = sqlite3.Row
    try:
        profile_row = connection.execute(
            "SELECT * FROM ProfileItem WHERE indexId = ? LIMIT 1", (selected_id,)
        ).fetchone()
        if profile_row is None:
            raise ValueError("The selected v2rayN profile no longer exists")
        route_row = _select_route(connection, gui)
    finally:
        connection.close()

    profile = _profile_from_row(profile_row)
    route_rules = _rules_from_json(_row_value(route_row, "ruleSet", "[]"))
    tun = gui.get("TunModeItem") or {}
    exclusions = tuple(
        str(value).strip()
        for value in (tun.get("RouteExcludeAddress") or [])
        if str(value).strip()
    )
    core = gui.get("CoreBasicItem") or {}
    hysteria = gui.get("HysteriaItem") or {}
    return ImportedConfig(
        profile=profile,
        route_id=str(_row_value(route_row, "id", "")),
        route_name=str(_row_value(route_row, "remarks", "Unnamed route")),
        route_domain_strategy=str(
            _row_value(route_row, "domainStrategy", "")
            or (gui.get("RoutingBasicItem") or {}).get("DomainStrategy")
            or "AsIs"
        ),
        rules=route_rules,
        route_exclusions=exclusions,
        default_fingerprint=str(core.get("DefFingerprint") or "chrome"),
        gui_modified_ns=gui_path.stat().st_mtime_ns,
        database_modified_ns=database_path.stat().st_mtime_ns,
        hysteria_up_mbps=int(hysteria.get("UpMbps") or 0),
        hysteria_down_mbps=int(hysteria.get("DownMbps") or 0),
        hysteria_hop_interval=int(hysteria.get("HopInterval") or 30),
    )


def list_v2rayn_profiles(
    app_root: Path = DEFAULT_APP_ROOT,
) -> tuple[ProfileSummary, ...]:
    """List profiles without returning endpoints, credentials, or raw extras."""
    gui_path = app_root / "guiConfigs" / "guiNConfig.json"
    database_path = app_root / "guiConfigs" / "guiNDB.db"
    with gui_path.open("r", encoding="utf-8-sig") as stream:
        gui = json.load(stream)
    selected_id = str(gui.get("IndexId") or "").strip()

    connection = _connect_read_only(database_path)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("SELECT * FROM ProfileItem").fetchall()
    finally:
        connection.close()

    summaries: list[ProfileSummary] = []
    for row in rows:
        profile = _profile_from_row(row)
        supported, detail = _mihomo_support(profile)
        summaries.append(
            ProfileSummary(
                profile_id=profile.index_id,
                remarks=profile.remarks or "未命名节点",
                protocol=_protocol_name(profile.config_type),
                transport=(profile.network or "QUIC").upper(),
                security=(profile.stream_security or "none").upper(),
                is_selected=profile.index_id == selected_id,
                supported=supported,
                support_detail=detail,
            )
        )
    return tuple(
        sorted(
            summaries,
            key=lambda item: (
                not item.supported,
                not item.is_selected,
                item.protocol.lower(),
                item.remarks.lower(),
            ),
        )
    )


def _protocol_name(config_type: int) -> str:
    return {5: "VLESS", 7: "Hysteria2"}.get(config_type, f"类型 {config_type}")


def _mihomo_support(profile: SelectedProfile) -> tuple[bool, str]:
    if profile.config_type == 7:
        return True, "Mihomo Hysteria2"
    if profile.config_type == 5:
        network = (profile.network or "tcp").lower().strip()
        if network in {"tcp", "raw", "grpc", "ws"}:
            return True, f"Mihomo VLESS/{network}"
        return False, f"暂不支持 VLESS/{network or 'unknown'}"
    return False, f"暂不支持 {_protocol_name(profile.config_type)}"


def _select_route(connection: sqlite3.Connection, gui: dict[str, Any]) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM RoutingItem WHERE IsActive = 1 ORDER BY sort LIMIT 1"
    ).fetchone()
    if row is not None:
        return row
    route_id = str((gui.get("RoutingBasicItem") or {}).get("RoutingIndexId") or "").strip()
    if route_id:
        row = connection.execute(
            "SELECT * FROM RoutingItem WHERE id = ? LIMIT 1", (route_id,)
        ).fetchone()
    if row is None:
        raise ValueError("v2rayN does not have an active routing profile")
    return row


def _profile_from_row(row: sqlite3.Row) -> SelectedProfile:
    protocol_extra = _json_object(_row_value(row, "ProtoExtra", ""))
    transport_extra = _json_object(_row_value(row, "TransportExtra", ""))
    if not protocol_extra.get("Flow"):
        legacy_flow = str(_row_value(row, "flow", "") or "")
        if legacy_flow:
            protocol_extra["Flow"] = legacy_flow
    if not protocol_extra.get("Ports"):
        legacy_ports = str(_row_value(row, "Ports", "") or "")
        if legacy_ports:
            protocol_extra["Ports"] = legacy_ports

    password = str(_row_value(row, "Password", "") or _row_value(row, "id", "") or "")
    return SelectedProfile(
        index_id=str(_row_value(row, "indexId", "")),
        config_type=int(_row_value(row, "configType", 0) or 0),
        config_version=int(_row_value(row, "configVersion", 0) or 0),
        remarks=str(_row_value(row, "remarks", "") or ""),
        address=str(_row_value(row, "address", "") or ""),
        port=int(_row_value(row, "port", 0) or 0),
        password=password,
        username=str(_row_value(row, "Username", "") or ""),
        network=str(_row_value(row, "network", "") or ""),
        stream_security=str(_row_value(row, "streamSecurity", "") or ""),
        allow_insecure=str(_row_value(row, "allowInsecure", "")).lower() == "true",
        sni=str(_row_value(row, "sni", "") or ""),
        alpn=_string_tuple(_row_value(row, "alpn", "")),
        fingerprint=str(_row_value(row, "fingerprint", "") or ""),
        public_key=str(_row_value(row, "publicKey", "") or ""),
        short_id=str(_row_value(row, "shortId", "") or ""),
        spider_x=str(_row_value(row, "spiderX", "") or ""),
        mldsa65_verify=str(_row_value(row, "Mldsa65Verify", "") or ""),
        cert=str(_row_value(row, "Cert", "") or ""),
        cert_sha=str(_row_value(row, "CertSha", "") or ""),
        ech_config_list=str(_row_value(row, "EchConfigList", "") or ""),
        verify_peer_cert_by_name=str(
            _row_value(row, "VerifyPeerCertByName", "") or ""
        ),
        protocol_extra=protocol_extra,
        transport_extra=transport_extra,
    )


def _rules_from_json(raw: Any) -> tuple[RoutingRule, ...]:
    parsed = json.loads(raw or "[]") if isinstance(raw, str) else raw
    if isinstance(parsed, dict):
        parsed = parsed.get("rules") or parsed.get("Rules") or []
    result: list[RoutingRule] = []
    for item in parsed or []:
        if not isinstance(item, dict) or not item.get("Enabled", True):
            continue
        result.append(
            RoutingRule(
                rule_id=str(item.get("Id") or ""),
                remarks=str(item.get("Remarks") or ""),
                outbound_tag=str(item.get("OutboundTag") or "proxy"),
                rule_type=item.get("RuleType"),
                domains=_value_tuple(item.get("Domain")),
                ips=_value_tuple(item.get("Ip") or item.get("IP")),
                port=str(item.get("Port") or ""),
                network=str(item.get("Network") or ""),
                protocols=_value_tuple(item.get("Protocol")),
                processes=_value_tuple(item.get("Process")),
                inbound_tags=_value_tuple(item.get("InboundTag")),
            )
        )
    return tuple(result)


def _row_value(row: sqlite3.Row, name: str, default: Any = None) -> Any:
    names = {key.lower(): key for key in row.keys()}
    actual = names.get(name.lower())
    return row[actual] if actual is not None else default


def _json_object(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        return {}
    return dict(value) if isinstance(value, dict) else {}


def _value_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list):
        return tuple(str(item) for item in value if str(item))
    return (str(value),) if str(value) else ()


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in str(value).replace(";", ",").split(",") if item.strip())
