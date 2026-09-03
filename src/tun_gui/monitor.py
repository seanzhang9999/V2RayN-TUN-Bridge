"""Read-only Mihomo connection monitoring for the desktop GUI."""

from __future__ import annotations

import json
import time
import urllib.request
from collections import OrderedDict
from pathlib import Path
from typing import Any


MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DIRECT_CHAIN = "DIRECT-BOUND"


def fetch_connections(access_path: Path, *, timeout: float = 3.0) -> dict[str, Any]:
    """Read one streamed `/connections` snapshot from the loopback controller."""
    access = json.loads(access_path.read_text(encoding="utf-8"))
    port = int(access.get("port", 0))
    secret = str(access.get("secret", ""))
    if not 1 <= port <= 65535 or not secret:
        raise ValueError("invalid local controller access data")

    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/connections?interval=1000",
        headers={"Authorization": f"Bearer {secret}"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        line = response.readline(MAX_RESPONSE_BYTES + 1)
    if len(line) > MAX_RESPONSE_BYTES:
        raise ValueError("controller response is too large")
    value = json.loads(line.decode("utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("connections"), list):
        raise ValueError("invalid controller response")
    return value


class ConnectionAccumulator:
    """Calculate route-specific rates and retain a small in-memory recent list."""

    def __init__(self, *, history_limit: int = 100) -> None:
        self.history_limit = history_limit
        self._previous: dict[str, tuple[int, int]] = {}
        self._recent: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        self._last_sample_at: float | None = None
        self._sequence = 0

    def reset_rates(self) -> None:
        self._previous.clear()
        self._last_sample_at = None

    def update(
        self, payload: dict[str, Any], *, sampled_at: float | None = None
    ) -> dict[str, Any]:
        now = time.monotonic() if sampled_at is None else sampled_at
        elapsed = max(now - self._last_sample_at, 0.001) if self._last_sample_at is not None else 0.0
        totals = {
            "proxy": {"up": 0.0, "down": 0.0},
            "direct": {"up": 0.0, "down": 0.0},
        }
        applications: dict[str, dict[str, Any]] = {}
        current: dict[str, tuple[int, int]] = {}
        active_ids: set[str] = set()

        connections = payload.get("connections", [])
        if not isinstance(connections, list):
            connections = []
        for raw in connections:
            if not isinstance(raw, dict):
                continue
            connection_id = str(raw.get("id") or "")
            if not connection_id:
                continue
            active_ids.add(connection_id)
            upload = _non_negative_int(raw.get("upload"))
            download = _non_negative_int(raw.get("download"))
            current[connection_id] = (upload, download)
            route = _connection_route(raw)
            previous = self._previous.get(connection_id)
            up_rate = 0.0
            down_rate = 0.0
            if elapsed and previous is not None:
                up_rate = max(upload - previous[0], 0) / elapsed
                down_rate = max(download - previous[1], 0) / elapsed
            elif elapsed:
                up_rate = upload / elapsed
                down_rate = download / elapsed
            totals[route]["up"] += up_rate
            totals[route]["down"] += down_rate

            item = _connection_view(raw, route=route)
            app_key = str(item["process"]).casefold()
            application = applications.setdefault(
                app_key,
                {
                    "process": item["process"],
                    "sources": set(),
                    "routes": set(),
                    "connections": 0,
                    "up": 0.0,
                    "down": 0.0,
                },
            )
            application["sources"].add(item["source"])
            application["routes"].add(route)
            application["connections"] += 1
            application["up"] += up_rate
            application["down"] += down_rate
            existing = self._recent.get(connection_id)
            if existing is not None:
                item["sequence"] = existing["sequence"]
            else:
                self._sequence += 1
                item["sequence"] = self._sequence
            item["active"] = True
            self._recent[connection_id] = item

        for connection_id, item in self._recent.items():
            if connection_id not in active_ids:
                item["active"] = False

        while len(self._recent) > self.history_limit:
            self._recent.popitem(last=False)
        self._previous = current
        self._last_sample_at = now
        recent = sorted(
            self._recent.values(), key=lambda item: float(item["sequence"]), reverse=True
        )[:5]
        application_rows = [
            {
                "process": item["process"],
                "source": _collapse_values(item["sources"]),
                "route": _collapse_values(item["routes"]),
                "connections": item["connections"],
                "up": item["up"],
                "down": item["down"],
            }
            for item in applications.values()
        ]
        application_rows.sort(
            key=lambda item: (
                -(float(item["up"]) + float(item["down"])),
                str(item["process"]).casefold(),
            )
        )
        return {
            "rates": totals,
            "applications": application_rows,
            "connections": [dict(item) for item in recent],
        }


def _connection_route(connection: dict[str, Any]) -> str:
    chains = connection.get("chains", [])
    if isinstance(chains, list) and any(
        str(item).upper() == DIRECT_CHAIN for item in chains
    ):
        return "direct"
    return "proxy"


def _connection_view(connection: dict[str, Any], *, route: str) -> dict[str, Any]:
    metadata = connection.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    host = str(metadata.get("host") or metadata.get("destinationIP") or "未知目标")
    port = str(metadata.get("destinationPort") or "")
    target = f"{host}:{port}" if port else host
    process = str(metadata.get("process") or metadata.get("processPath") or "—")
    if "\\" in process or "/" in process:
        process = Path(process).name
    start = str(connection.get("start") or "")
    return {
        "started": _short_time(start),
        "target": target[:80],
        "route": route,
        "process": process[:40],
        "source": _connection_source(metadata),
        "upload": _non_negative_int(connection.get("upload")),
        "download": _non_negative_int(connection.get("download")),
    }


def _connection_source(metadata: dict[str, Any]) -> str:
    inbound = " ".join(
        str(metadata.get(key) or "")
        for key in ("type", "inboundName", "inbound")
    ).casefold()
    if "tun" in inbound:
        return "tun"
    if "mixed" in inbound or "socks" in inbound or "http" in inbound:
        return "mixed"
    return "unknown"


def _collapse_values(values: set[str]) -> str:
    if not values:
        return "unknown"
    if len(values) == 1:
        return next(iter(values))
    return "mixed"


def _short_time(value: str) -> str:
    if "T" in value:
        clock = value.split("T", 1)[1]
        return clock[:8]
    return value[:8] or time.strftime("%H:%M:%S")


def _non_negative_int(value: Any) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def format_rate(value: float) -> str:
    return f"{_format_size(value)}/s"


def format_transfer(upload: int, download: int) -> str:
    return f"↑ {_format_size(upload)}  ↓ {_format_size(download)}"


def _format_size(value: float | int) -> str:
    amount = max(float(value), 0.0)
    units = ("B", "KB", "MB", "GB")
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{amount:.0f} {unit}"
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return "0 B"
