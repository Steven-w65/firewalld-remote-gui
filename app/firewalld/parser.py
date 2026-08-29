"""Pure, bounded parsers for firewalld and operating-system command output."""

from __future__ import annotations

import re

from app.models.firewall import FirewallPort, RichRule, ZoneState
from app.utils.errors import FirewallParseError, InvalidFirewallArgumentError
from app.utils.validation import validate_ip_network, validate_port, validate_protocol, validate_rich_action


_ZONE_LIST_FIELDS = frozenset({"interfaces", "sources", "services", "ports", "protocols"})
_ZONE_BOOLEAN_FIELDS = frozenset({"forward", "masquerade"})
_ZONE_OTHER_FIELDS = frozenset({"target", "icmp-block-inversion", "forward-ports", "source-ports", "icmp-blocks"})
_ZONE_REQUIRED_FIELDS = _ZONE_LIST_FIELDS | _ZONE_BOOLEAN_FIELDS | frozenset({"rich rules"})
_RICH_PATTERN = re.compile(r"^rule(?:\s|$)")
_RICH_CLAUSES = {
    "family": re.compile(r'(?:^|\s)family="([^"]*)"(?:\s|$)'),
    "source": re.compile(r'(?:^|\s)source\s+address="([^"]*)"(?:\s|$)'),
    "destination": re.compile(r'(?:^|\s)destination\s+address="([^"]*)"(?:\s|$)'),
    "service": re.compile(r'(?:^|\s)service\s+name="([^"]*)"(?:\s|$)'),
    "port": re.compile(r'(?:^|\s)port\s+port="([^"]*)"(?:\s|$)'),
    "protocol": re.compile(r'(?:^|\s)protocol(?:\s+value)?="([^"]*)"(?:\s|$)'),
}
_RICH_ACTION = re.compile(r"(?:^|\s)(accept|reject|drop)(?:\s|$)", re.IGNORECASE)


def _fail(operation: str, reason: str) -> None:
    raise FirewallParseError(operation, reason)


def _validated(operation: str, validator, value: str, reason: str) -> str:
    try:
        return validator(value)
    except InvalidFirewallArgumentError:
        _fail(operation, reason)
    raise AssertionError("unreachable")


def parse_words(output: str) -> tuple[str, ...]:
    """Return nonempty whitespace-delimited firewalld words in input order."""
    if not isinstance(output, str):
        _fail("word list", "output was not text")
    return tuple(output.split())


def parse_active_zones(output: str) -> dict[str, tuple[str, ...]]:
    """Parse ``--get-active-zones`` output, retaining interface assignments only."""
    if not isinstance(output, str):
        _fail("active zones", "output was not text")
    zones: dict[str, tuple[str, ...]] = {}
    active_zone: str | None = None
    for line in output.splitlines():
        if not line.strip():
            continue
        if line[0].isspace():
            if active_zone is None or ":" not in line:
                _fail("active zones", "malformed zone block")
            field, value = line.strip().split(":", 1)
            if field not in {"interfaces", "sources"}:
                _fail("active zones", "unknown zone block field")
            if field == "interfaces":
                zones[active_zone] = parse_words(value)
            continue
        if ":" in line or line.strip() != line or line in zones:
            _fail("active zones", "invalid zone name")
        active_zone = line
        zones[active_zone] = ()
    return zones


def _parse_bool(value: str, operation: str, field: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "yes":
        return True
    if normalized == "no":
        return False
    _fail(operation, f"invalid {field} value")


def _parse_ports(value: str, name: str, permanent: bool) -> tuple[FirewallPort, ...]:
    ports: list[FirewallPort] = []
    for item in parse_words(value):
        if item.count("/") != 1:
            _fail("zone state", "invalid port entry")
        port, protocol = item.split("/", 1)
        ports.append(
            FirewallPort(
                _validated("zone state", validate_port, port, "invalid port value"),
                _validated("zone state", validate_protocol, protocol, "invalid protocol value"),
                name,
                not permanent,
                permanent,
            )
        )
    return tuple(ports)


def parse_zone_state(name: str, output: str, permanent: bool) -> ZoneState:
    """Parse ``--list-all`` into a target-specific immutable zone state."""
    if not isinstance(output, str) or not isinstance(name, str) or not name:
        _fail("zone state", "output or zone name was invalid")
    lines = output.splitlines()
    header_index = next((index for index, line in enumerate(lines) if line.strip()), None)
    if header_index is None:
        _fail("zone state", "missing zone header")
    header = lines[header_index].strip()
    header_name = header.removesuffix(" (active)")
    if not header_name or header_name != name:
        _fail("zone state", "zone header did not match")

    fields: dict[str, str] = {}
    rich_rule_lines: list[str] = []
    in_rich_rules = False
    for line in lines[header_index + 1 :]:
        if not line.strip():
            continue
        stripped = line.lstrip()
        if in_rich_rules and _RICH_PATTERN.match(stripped):
            rich_rule_lines.append(line)
            continue
        if ":" not in stripped:
            _fail("zone state", "malformed zone field")
        field, value = stripped.split(":", 1)
        if field not in _ZONE_LIST_FIELDS | _ZONE_BOOLEAN_FIELDS | _ZONE_OTHER_FIELDS | {"rich rules"}:
            _fail("zone state", "unknown zone field")
        if field in fields:
            _fail("zone state", "duplicate zone field")
        fields[field] = value
        in_rich_rules = field == "rich rules"
    if not _ZONE_REQUIRED_FIELDS.issubset(fields):
        _fail("zone state", "required zone fields were missing")

    sources = tuple(
        _validated("zone state", validate_ip_network, source, "invalid source network")
        for source in parse_words(fields["sources"])
    )
    services = parse_words(fields["services"])
    for protocol in parse_words(fields["protocols"]):
        _validated("zone state", validate_protocol, protocol, "invalid protocol value")
    return ZoneState(
        name=name,
        interfaces=parse_words(fields["interfaces"]),
        sources=sources,
        services=services,
        ports=_parse_ports(fields["ports"], name, permanent),
        rich_rules=parse_rich_rules("\n".join(rich_rule_lines)),
        masquerade=_parse_bool(fields["masquerade"], "zone state", "masquerade"),
        forwarding=_parse_bool(fields["forward"], "zone state", "forward"),
        permanent=permanent,
    )


def _single_rich_value(rule: str, field: str) -> str | None:
    matches = _RICH_CLAUSES[field].findall(rule)
    if len(matches) > 1:
        _fail("rich rules", "duplicate structured clause")
    return matches[0] if matches else None


def parse_rich_rules(output: str) -> tuple[RichRule, ...]:
    """Preserve raw rich-rule display lines while extracting recognized safe clauses."""
    if not isinstance(output, str):
        _fail("rich rules", "output was not text")
    rules: list[RichRule] = []
    for rule in output.splitlines():
        if not rule.strip():
            continue
        if not _RICH_PATTERN.match(rule.strip()):
            _fail("rich rules", "malformed rich rule")
        family = _single_rich_value(rule, "family")
        if family is not None and family.lower() not in {"ipv4", "ipv6"}:
            _fail("rich rules", "invalid address family")
        source = _single_rich_value(rule, "source")
        if source is not None:
            source = _validated("rich rules", validate_ip_network, source, "invalid source network")
        destination = _single_rich_value(rule, "destination")
        if destination is not None:
            destination = _validated("rich rules", validate_ip_network, destination, "invalid destination network")
        service = _single_rich_value(rule, "service")
        port = _single_rich_value(rule, "port")
        if port is not None:
            port = _validated("rich rules", validate_port, port, "invalid port value")
        protocol = _single_rich_value(rule, "protocol")
        if protocol is not None:
            protocol = _validated("rich rules", validate_protocol, protocol, "invalid protocol value")
        actions = _RICH_ACTION.findall(rule)
        if len(actions) > 1:
            _fail("rich rules", "duplicate action")
        action = _validated("rich rules", validate_rich_action, actions[0], "invalid action") if actions else None
        rules.append(
            RichRule(
                rule=rule,
                family=family,
                source=source,
                destination=destination,
                service=service,
                port=port,
                protocol=protocol,
                action=action,
            )
        )
    return tuple(rules)


def _decode_os_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    decoded: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\" or index + 1 == len(value):
            decoded.append(value[index])
            index += 1
            continue
        if value[index + 1] == "x" and index + 3 < len(value):
            hex_value = value[index + 2 : index + 4]
            if all(character in "0123456789abcdefABCDEF" for character in hex_value):
                decoded.append(chr(int(hex_value, 16)))
                index += 4
                continue
        decoded.append(value[index + 1])
        index += 2
    return "".join(decoded)


def parse_os_release(output: str) -> str:
    """Return PRETTY_NAME, or NAME when PRETTY_NAME is absent, from os-release text."""
    if not isinstance(output, str):
        _fail("os release", "output was not text")
    values: dict[str, str] = {}
    for line in output.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"PRETTY_NAME", "NAME"}:
            values[key] = _decode_os_value(value)
    result = values.get("PRETTY_NAME") or values.get("NAME")
    if not result:
        _fail("os release", "distribution identity was missing")
    return result
