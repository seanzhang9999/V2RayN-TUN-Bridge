"""Small IPv4 resolver shared by network and proxy endpoint detection."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import Any


class ResolveError(ValueError):
    """A redaction-safe name resolution error."""


def resolve_server_ipv4(
    host: str,
    *,
    resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
) -> tuple[str, ...]:
    try:
        answers = resolver(host, None, socket.AF_UNSPEC, 0, 0)
    except OSError:
        raise ResolveError("无法解析当前代理服务器的 IPv4 地址") from None

    result: list[str] = []
    for answer in answers:
        try:
            value = str(answer[4][0])
            address = ipaddress.ip_address(value)
        except (IndexError, TypeError, ValueError):
            continue
        if address.version == 4 and value not in result:
            result.append(value)
    if not result:
        raise ResolveError("当前代理服务器没有可用的 IPv4 地址")
    return tuple(result)
