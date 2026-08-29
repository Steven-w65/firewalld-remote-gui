from pathlib import Path

import pytest

from app.firewalld.parser import (
    parse_active_zones,
    parse_os_release,
    parse_rich_rules,
    parse_words,
    parse_zone_state,
)
from app.utils.errors import FirewallParseError


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_words_normalizes_whitespace_and_omits_empty_fields():
    assert parse_words("  public\tinternal\n\n trusted  \n") == ("public", "internal", "trusted")


def test_parse_active_zones_keeps_interfaces_but_not_source_blocks():
    output = (FIXTURES / "active_zones.txt").read_text(encoding="utf-8")

    assert parse_active_zones(output) == {"public": ("eth0", "eth1"), "internal": (), "trusted": ()}


def test_parse_active_zones_allows_no_active_zone_blocks():
    assert parse_active_zones("\n  \n") == {}


def test_parse_active_zones_rejects_an_orphaned_attribute():
    with pytest.raises(FirewallParseError) as error:
        parse_active_zones("  interfaces: eth0\n")

    assert error.value.operation == "active zones"
    assert "eth0" not in str(error.value)


def test_parse_zone_details_preserves_ranges_and_builds_typed_state():
    output = (FIXTURES / "zone_public.txt").read_text(encoding="utf-8")

    zone = parse_zone_state("public", output, permanent=False)

    assert zone.name == "public"
    assert zone.interfaces == ("eth0", "eth1")
    assert zone.sources == ("192.0.2.0/24", "2001:db8::/64")
    assert zone.services == ("http", "https", "ssh")
    assert {(port.port, port.protocol, port.zone, port.runtime, port.permanent) for port in zone.ports} == {
        ("8000-8100", "tcp", "public", True, False),
        ("53", "udp", "public", True, False),
    }
    assert zone.masquerade is False
    assert zone.forwarding is True
    assert zone.permanent is False


def test_parse_zone_state_marks_permanent_ports_and_keeps_multiple_rich_rules():
    output = (FIXTURES / "zone_public.txt").read_text(encoding="utf-8")

    zone = parse_zone_state("public", output, permanent=True)

    assert all(not port.runtime and port.permanent for port in zone.ports)
    assert zone.permanent is True
    assert len(zone.rich_rules) == 2
    assert zone.rich_rules[0].rule == '    rule family="ipv4" source address="192.0.2.0/24" port port="8443" protocol="tcp" accept'


@pytest.mark.parametrize(
    ("output", "operation"),
    [
        ("public (active)\n  interfaces eth0\n", "zone state"),
        ("public (active)\n  interfaces: eth0\n  ports: 99999/tcp\n", "zone state"),
        ("public (active)\n  interfaces: eth0\n  ports: 22/sctp\n", "zone state"),
        ("public (active)\n  interfaces: eth0\n  sources: not-a-network\n", "zone state"),
        ("public (active)\n  interfaces: eth0\n  forward: maybe\n", "zone state"),
        ("target: default\n  interfaces: eth0\n", "zone state"),
    ],
)
def test_parse_zone_state_rejects_malformed_or_missing_required_fields_without_echoing_output(output, operation):
    with pytest.raises(FirewallParseError) as error:
        parse_zone_state("public", output, permanent=False)

    assert error.value.operation == operation
    assert "eth0" not in str(error.value)


def test_parse_zone_state_splits_only_on_the_first_colon_in_a_field_value():
    output = "public\n  interfaces: br-0.1:2\n  sources:\n  services:\n  ports:\n  protocols:\n  forward: no\n  masquerade: yes\n  rich rules:\n"

    zone = parse_zone_state("public", output, permanent=False)

    assert zone.interfaces == ("br-0.1:2",)
    assert zone.masquerade is True


def test_parse_rich_rules_extracts_only_recognized_structured_clauses_and_preserves_unknown_syntax():
    raw = (
        'rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="TCP" log prefix="audit" level="info" accept\n'
        'rule family="ipv6" destination address="2001:db8::/64" service name="ssh" reject\n'
    )

    rules = parse_rich_rules(raw)

    assert rules[0].rule == 'rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="TCP" log prefix="audit" level="info" accept'
    assert (rules[0].family, rules[0].source, rules[0].destination, rules[0].service) == (
        "ipv4", "192.0.2.0/24", None, None,
    )
    assert (rules[0].port, rules[0].protocol, rules[0].action) == ("22", "tcp", "accept")
    assert (rules[1].family, rules[1].destination, rules[1].service, rules[1].action) == (
        "ipv6", "2001:db8::/64", "ssh", "reject",
    )


def test_parse_rich_rules_extracts_a_standalone_protocol_value_clause():
    (rule,) = parse_rich_rules('rule family="ipv4" protocol value="tcp" accept\n')

    assert rule.family == "ipv4"
    assert rule.port is None
    assert rule.protocol == "tcp"
    assert rule.action == "accept"


@pytest.mark.parametrize(
    "output",
    [
        'rule family="ipv4" port port="not-a-port" protocol="tcp" accept\n',
        'rule family="ipv4" port port="22" protocol="sctp" accept\n',
        'rule family="ipv4" source address="not-a-network" service name="ssh" accept\n',
        'rule family="other" service name="ssh" accept\n',
    ],
)
def test_parse_rich_rules_rejects_invalid_recognized_clause_values(output):
    with pytest.raises(FirewallParseError) as error:
        parse_rich_rules(output)

    assert error.value.operation == "rich rules"


def test_parse_os_release_decodes_quoted_and_escaped_pretty_name():
    output = 'NAME="Fedora Linux"\nPRETTY_NAME="Fedora \\"Forty Two\\" \\x28Server\\x29"\nID=fedora\n'

    assert parse_os_release(output) == 'Fedora "Forty Two" (Server)'


def test_parse_os_release_falls_back_to_unquoted_name_and_rejects_missing_identity():
    assert parse_os_release("NAME=Ubuntu Server\nID=ubuntu\n") == "Ubuntu Server"

    with pytest.raises(FirewallParseError) as error:
        parse_os_release("ID=fedora\n")

    assert error.value.operation == "os release"
