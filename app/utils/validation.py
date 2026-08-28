"""Strict validation for values that become firewalld command arguments."""

import ipaddress
import re
from collections.abc import Collection

from app.utils.errors import InvalidFirewallArgumentError


_PORT_PATTERN = re.compile(r"([0-9]+)(?:-([0-9]+))?\Z", re.ASCII)
_PROTOCOLS = frozenset({"tcp", "udp"})
_RICH_ACTIONS = frozenset({"accept", "reject", "drop"})


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or any(char.isspace() for char in value):
        raise InvalidFirewallArgumentError(field, "must be a non-empty token without whitespace")
    return value


def validate_port(value: str) -> str:
    value = _text(value, "port")
    match = _PORT_PATTERN.fullmatch(value)
    if match is None:
        raise InvalidFirewallArgumentError("port", "must be a number or ascending range")
    first = int(match.group(1))
    last = int(match.group(2) or match.group(1))
    if not (1 <= first <= 65535 and 1 <= last <= 65535 and first <= last):
        raise InvalidFirewallArgumentError("port", "must be between 1 and 65535 with an ascending range")
    return value


def validate_protocol(value: str) -> str:
    value = _text(value, "protocol")
    normalized = value.lower()
    if normalized not in _PROTOCOLS:
        raise InvalidFirewallArgumentError("protocol", "must be tcp or udp")
    return normalized


def validate_inventory_value(kind: str, value: str, allowed: Collection[str]) -> str:
    value = _text(value, kind)
    if value not in allowed:
        raise InvalidFirewallArgumentError(kind, "must match an item in the remote inventory")
    return value


def validate_ip_network(value: str) -> str:
    value = _text(value, "network")
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise InvalidFirewallArgumentError("network", "must be a valid IPv4 or IPv6 network") from None


def validate_rich_action(value: str) -> str:
    value = _text(value, "action")
    normalized = value.lower()
    if normalized not in _RICH_ACTIONS:
        raise InvalidFirewallArgumentError("action", "must be accept, reject, or drop")
    return normalized
