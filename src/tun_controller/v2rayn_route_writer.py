"""Safely update the active v2rayN routing table from Bridge."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Iterable

from tun_controller.models import RoutingRule

BRIDGE_RULE_IDS = {"tun-bridge-import-proxy", "tun-bridge-import-direct"}


def load_managed_v2rayn_rules(app_root: Path) -> dict[str, tuple[RoutingRule, ...]]:
    """Read only the Proxy/Direct groups previously managed by Bridge."""
    database_path = app_root / "guiConfigs" / "guiNDB.db"
    gui_path = app_root / "guiConfigs" / "guiNConfig.json"
    gui = json.loads(gui_path.read_text(encoding="utf-8-sig"))
    connection = sqlite3.connect(
        f"file:{database_path.resolve().as_posix()}?mode=ro", uri=True, timeout=1.0
    )
    connection.row_factory = sqlite3.Row
    try:
        row = _select_active_route(connection, gui)
        _, items = _decode_rule_set(str(row["ruleSet"] or "[]"))
    finally:
        connection.close()
    result: dict[str, list[RoutingRule]] = {"proxy": [], "direct": []}
    for item in items:
        rule_id = str(item.get("Id") or "")
        if rule_id not in BRIDGE_RULE_IDS:
            continue
        outbound = "direct" if str(item.get("OutboundTag")).lower() == "direct" else "proxy"
        result[outbound].append(
            RoutingRule(
                rule_id=rule_id,
                remarks=str(item.get("Remarks") or ""),
                outbound_tag=outbound,
                domains=_tuple_values(item.get("Domain")),
                ips=_tuple_values(item.get("Ip") or item.get("IP")),
                processes=_tuple_values(item.get("Process")),
            )
        )
    return {key: tuple(value) for key, value in result.items()}


def update_active_v2rayn_route(
    app_root: Path,
    rules: Iterable[RoutingRule],
    *,
    backup_root: Path,
) -> dict[str, object]:
    """Replace Bridge-managed rules in v2rayN's active route transactionally."""
    database_path = app_root / "guiConfigs" / "guiNDB.db"
    gui_path = app_root / "guiConfigs" / "guiNConfig.json"
    if not database_path.is_file() or not gui_path.is_file():
        raise FileNotFoundError("v2rayN routing database was not found")

    normalized_rules = tuple(rules)
    gui = json.loads(gui_path.read_text(encoding="utf-8-sig"))
    backup_root.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = _select_active_route(connection, gui)
        original_raw = str(row["ruleSet"] or "[]")
        backup_path = backup_root / f"active-route-before-{time.time_ns()}.json"
        _write_route_backup(backup_path, row, original_raw)
        container, items = _decode_rule_set(original_raw)
        retained = [item for item in items if str(item.get("Id") or "") not in BRIDGE_RULE_IDS]
        managed = _build_managed_rules(normalized_rules)
        updated_items = [*managed, *retained]
        updated_raw = _encode_rule_set(container, updated_items)
        cursor = connection.execute(
            "UPDATE RoutingItem SET ruleSet = ?, ruleNum = ? WHERE id = ? AND ruleSet = ?",
            (updated_raw, len(updated_items), str(row["id"]), original_raw),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("v2rayN route changed during update; no data was overwritten")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    _trim_backups(backup_root, keep=10)
    return {
        "route_id": str(row["id"]),
        "route_name": str(row["remarks"] or "Unnamed route"),
        "imported_rule_count": len(normalized_rules),
        "managed_group_count": len(managed),
        "backup_path": str(backup_path),
    }


def _select_active_route(connection: sqlite3.Connection, gui: dict[str, object]) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM RoutingItem WHERE IsActive = 1 ORDER BY sort LIMIT 1"
    ).fetchone()
    if row is not None:
        return row
    basic = gui.get("RoutingBasicItem")
    route_id = str(basic.get("RoutingIndexId") or "") if isinstance(basic, dict) else ""
    row = connection.execute(
        "SELECT * FROM RoutingItem WHERE id = ? LIMIT 1", (route_id,)
    ).fetchone()
    if row is None:
        raise ValueError("v2rayN does not have an active routing profile")
    return row


def _decode_rule_set(raw: str) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    value = json.loads(raw or "[]")
    if isinstance(value, list):
        return None, [dict(item) for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        key = "rules" if "rules" in value else "Rules"
        items = value.get(key, [])
        if not isinstance(items, list):
            raise ValueError("Active v2rayN route has an invalid rule list")
        return dict(value), [dict(item) for item in items if isinstance(item, dict)]
    raise ValueError("Active v2rayN route has an invalid rule set")


def _encode_rule_set(
    container: dict[str, object] | None, items: list[dict[str, object]]
) -> str:
    if container is None:
        value: object = items
    else:
        key = "rules" if "rules" in container else "Rules"
        container[key] = items
        value = container
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _build_managed_rules(rules: tuple[RoutingRule, ...]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for outbound, rule_id, label in (
        ("proxy", "tun-bridge-import-proxy", "[TUN Bridge] 导入代理规则"),
        ("direct", "tun-bridge-import-direct", "[TUN Bridge] 导入直连规则"),
    ):
        selected = [rule for rule in rules if rule.outbound_tag.lower() == outbound]
        domains = [
            _v2rayn_display_domain(value)
            for rule in selected
            for value in rule.domains
            if _v2rayn_display_domain(value)
        ]
        ips = [value for rule in selected for value in rule.ips]
        processes = [value for rule in selected for value in rule.processes]
        if not domains and not ips and not processes:
            continue
        item: dict[str, object] = {
            "Id": rule_id,
            "OutboundTag": outbound,
            "Enabled": True,
            "Remarks": label,
        }
        if domains:
            item["Domain"] = list(dict.fromkeys(domains))
        if ips:
            item["Ip"] = list(dict.fromkeys(ips))
        if processes:
            item["Process"] = list(dict.fromkeys(processes))
        result.append(item)
    return result


def _v2rayn_display_domain(value: str) -> str:
    """Store ordinary imported hosts the same way v2rayN's editor displays them."""
    text = value.strip().rstrip(",").strip()
    lowered = text.lower()
    if lowered.startswith(("domain:", "full:")):
        return text.split(":", 1)[1].strip()
    return text


def _tuple_values(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(item) for item in value if str(item))
    return (str(value),) if value else ()


def _write_route_backup(path: Path, row: sqlite3.Row, rule_set: str) -> None:
    path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "routeId": str(row["id"]),
                "routeName": str(row["remarks"] or ""),
                "ruleNum": int(row["ruleNum"] or 0),
                "ruleSet": json.loads(rule_set or "[]"),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def _trim_backups(root: Path, *, keep: int) -> None:
    backups = sorted(root.glob("active-route-before-*.json"), key=lambda item: item.stat().st_mtime_ns)
    for path in backups[:-keep]:
        path.unlink(missing_ok=True)
