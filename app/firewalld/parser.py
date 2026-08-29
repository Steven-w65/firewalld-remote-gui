"""Pure, bounded parsers for firewalld and operating-system command output."""

from __future__ import annotations

import re

from app.models.firewall import FirewallPort, RichRule, ZoneState
from app.utils.errors import FirewallParseError, InvalidFirewallArgumentError
from app.utils.validation import (
    validate_inventory_token,
    validate_ip_network,
    validate_port,
    validate_rich_action,
)


_ZONE_LIST_FIELDS = frozenset({"interfaces", "sources", "services", "ports", "protocols"})
_ZONE_BOOLEAN_FIELDS = frozenset({"forward", "masquerade"})
_ZONE_OTHER_FIELDS = frozenset(
    {
        "target",
        "icmp-block-inversion",
        "ingress-priority",
        "egress-priority",
        "forward-ports",
        "source-ports",
        "icmp-blocks",
    }
)
_ZONE_MULTILINE_FIELDS = frozenset({"forward-ports", "source-ports", "icmp-blocks"})
_ZONE_REQUIRED_FIELDS = _ZONE_LIST_FIELDS | _ZONE_BOOLEAN_FIELDS | frozenset({"rich rules"})
_PORT_PROTOCOLS = frozenset({"tcp", "udp", "sctp", "dccp"})
_READ_PROTOCOL_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.+-]{0,63}\Z", re.ASCII)
_MAC_ADDRESS = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z", re.ASCII)
_IPSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_RICH_RULE = re.compile(
    r'^rule'
    r'(?: family="(?P<family>[^"]*)")?'
    r'(?: source address="(?P<source>[^"]*)")?'
    r'(?: destination address="(?P<destination>[^"]*)")?'
    r'(?: service name="(?P<service>[^"]*)"'
    r'| port port="(?P<port>[^"]*)" protocol="(?P<port_protocol>[^"]*)"'
    r'| protocol value="(?P<protocol>[^"]*)")'
    r' (?P<action>accept|reject|drop)$',
    re.IGNORECASE | re.ASCII,
)


def _fail(operation: str, reason: str) -> None:
    raise FirewallParseError(operation, reason)


def _validated(operation: str, validator, value: str, reason: str) -> str:
    try:
        return validator(value)
    except InvalidFirewallArgumentError:
        _fail(operation, reason)
    raise AssertionError("unreachable")


def _read_token(value: str, operation: str, reason: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or any(character.isspace() for character in value):
        _fail(operation, reason)
    return value


def _parse_port_protocol(value: str, operation: str) -> str:
    normalized = _read_token(value, operation, "invalid port protocol").lower()
    if normalized not in _PORT_PROTOCOLS:
        _fail(operation, "invalid port protocol")
    return normalized


def _parse_read_protocol(value: str, operation: str) -> str:
    value = _read_token(value, operation, "invalid protocol value")
    if value.isascii() and value.isdecimal():
        if 0 <= int(value) <= 255:
            return value
    elif _READ_PROTOCOL_NAME.fullmatch(value) is not None:
        return value.lower()
    _fail(operation, "invalid protocol value")


def _parse_zone_source(value: str) -> str:
    value = _read_token(value, "zone state", "invalid source value")
    if _MAC_ADDRESS.fullmatch(value) is not None:
        return value.lower()
    if value.startswith("ipset:") and _IPSET_NAME.fullmatch(value.removeprefix("ipset:")) is not None:
        return value
    try:
        return validate_ip_network(value)
    except InvalidFirewallArgumentError:
        _fail("zone state", "invalid source value")
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
                _parse_port_protocol(protocol, "zone state"),
                name,
                not permanent,
                permanent,
            )
        )
    return tuple(ports)


def _matches_zone_header(name: str, header: str) -> bool:
    if header == name:
        return True
    prefix = f"{name} ("
    if not header.startswith(prefix) or not header.endswith(")"):
        return False
    annotations = tuple(part.strip() for part in header[len(prefix) : -1].split(","))
    return bool(annotations) and len(annotations) <= 2 and len(set(annotations)) == len(annotations) and set(annotations) <= {
        "active",
        "default",
    }


def parse_zone_state(name: str, output: str, permanent: bool) -> ZoneState:
    """Parse ``--list-all`` into a target-specific immutable zone state."""
    if not isinstance(output, str) or not isinstance(name, str) or not name:
        _fail("zone state", "output or zone name was invalid")
    lines = output.splitlines()
    header_index = next((index for index, line in enumerate(lines) if line.strip()), None)
    if header_index is None:
        _fail("zone state", "missing zone header")
    if not _matches_zone_header(name, lines[header_index].strip()):
        _fail("zone state", "zone header did not match")

    fields: dict[str, str] = {}
    rich_rule_lines: list[str] = []
    top_level_indent: int | None = None
    current_field: str | None = None
    known_fields = _ZONE_LIST_FIELDS | _ZONE_BOOLEAN_FIELDS | _ZONE_OTHER_FIELDS | {"rich rules"}
    for line in lines[header_index + 1 :]:
        if not line.strip():
            continue
        indentation = len(line) - len(line.lstrip())
        if indentation == 0:
            _fail("zone state", "malformed zone field")
        if top_level_indent is None:
            top_level_indent = indentation
        if indentation > top_level_indent:
            if current_field == "rich rules":
                rich_rule_lines.append(line)
                continue
            if current_field in _ZONE_MULTILINE_FIELDS:
                continue
            _fail("zone state", "unexpected zone field continuation")
        if indentation != top_level_indent:
            _fail("zone state", "malformed zone field")
        stripped = line.lstrip()
        if ":" not in stripped:
            _fail("zone state", "malformed zone field")
        field, value = stripped.split(":", 1)
        if field not in known_fields:
            _fail("zone state", "unknown zone field")
        if field in fields:
            _fail("zone state", "duplicate zone field")
        fields[field] = value
        current_field = field
    if not _ZONE_REQUIRED_FIELDS.issubset(fields):
        _fail("zone state", "required zone fields were missing")

    return ZoneState(
        name=name,
        interfaces=parse_words(fields["interfaces"]),
        sources=tuple(_parse_zone_source(source) for source in parse_words(fields["sources"])),
        services=parse_words(fields["services"]),
        ports=_parse_ports(fields["ports"], name, permanent),
        rich_rules=parse_rich_rules("\n".join(rich_rule_lines)),
        masquerade=_parse_bool(fields["masquerade"], "zone state", "masquerade"),
        forwarding=_parse_bool(fields["forward"], "zone state", "forward"),
        permanent=permanent,
        protocols=tuple(_parse_read_protocol(protocol, "zone state") for protocol in parse_words(fields["protocols"])),
    )


def _raw_rich_rule(rule: str) -> RichRule:
    return RichRule(rule=rule)


def parse_rich_rules(output: str) -> tuple[RichRule, ...]:
    """Preserve rich-rule display lines and structure only the complete safe subset."""
    if not isinstance(output, str):
        _fail("rich rules", "output was not text")
    rules: list[RichRule] = []
    for raw_rule in output.splitlines():
        if not raw_rule.strip():
            continue
        match = _RICH_RULE.fullmatch(raw_rule.strip())
        if match is None:
            rules.append(_raw_rich_rule(raw_rule))
            continue
        values = match.groupdict()
        family = values["family"]
        if family is not None and family.lower() not in {"ipv4", "ipv6"}:
            _fail("rich rules", "invalid address family")
        source = values["source"]
        destination = values["destination"]
        if (source is not None or destination is not None) and family is None:
            rules.append(_raw_rich_rule(raw_rule))
            continue
        if source is not None:
            source = _validated("rich rules", validate_ip_network, source, "invalid source network")
        if destination is not None:
            destination = _validated("rich rules", validate_ip_network, destination, "invalid destination network")
        service = values["service"]
        if service is not None:
            service = _validated("rich rules", lambda value: validate_inventory_token("service", value), service, "invalid service value")
        port = values["port"]
        if port is not None:
            port = _validated("rich rules", validate_port, port, "invalid port value")
            protocol = _parse_port_protocol(values["port_protocol"], "rich rules")
        else:
            protocol = _parse_read_protocol(values["protocol"], "rich rules") if values["protocol"] is not None else None
        action = _validated("rich rules", validate_rich_action, values["action"], "invalid action")
        rules.append(
            RichRule(
                rule=raw_rule,
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
    if not value:
        return ""
    if value[0] == "'":
        if len(value) < 2 or not value.endswith("'") or "'" in value[1:-1]:
            _fail("os release", "malformed os release value")
        return value[1:-1]
    if value[0] == '"':
        decoded: list[str] = []
        index = 1
        while index < len(value):
            character = value[index]
            if character == '"':
                if index != len(value) - 1:
                    _fail("os release", "malformed os release value")
                return "".join(decoded)
            if character != "\\":
                decoded.append(character)
                index += 1
                continue
            if index + 1 == len(value):
                _fail("os release", "malformed os release value")
            escaped = value[index + 1]
            if escaped in {'"', "\\", "$", "`"}:
                decoded.append(escaped)
            else:
                decoded.extend(("\\", escaped))
            index += 2
        _fail("os release", "malformed os release value")
    decoded: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character.isspace() or character in {'"', "'"}:
            _fail("os release", "malformed os release value")
        if character == "\\":
            if index + 1 == len(value):
                _fail("os release", "malformed os release value")
            decoded.append(value[index + 1])
            index += 2
            continue
        decoded.append(character)
        index += 1
    return "".join(decoded)


def parse_os_release(output: str) -> str:
    """Return PRETTY_NAME, or NAME when PRETTY_NAME is absent, without executing text."""
    if not isinstance(output, str):
        _fail("os release", "output was not text")
    values: dict[str, str] = {}
    for line in output.splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"PRETTY_NAME", "NAME"}:
            values[key] = _decode_os_value(value)
    result = values.get("PRETTY_NAME") or values.get("NAME")
    if not result:
        _fail("os release", "distribution identity was missing")
    return result
