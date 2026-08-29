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


def _public_zone_output() -> str:
    return (FIXTURES / "zone_public.txt").read_text(encoding="utf-8")


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
    output = _public_zone_output()

    zone = parse_zone_state("public", output, permanent=False)

    assert zone.name == "public"
    assert zone.interfaces == ("eth0", "eth1")
    assert zone.sources == (
        "192.0.2.0/24",
        "2001:db8::/64",
        "00:11:22:33:44:55",
        "ipset:trusted_clients",
    )
    assert zone.services == ("http", "https", "ssh")
    assert {(port.port, port.protocol, port.zone, port.runtime, port.permanent) for port in zone.ports} == {
        ("8000-8100", "tcp", "public", True, False),
        ("53", "udp", "public", True, False),
        ("5000", "sctp", "public", True, False),
        ("5001", "dccp", "public", True, False),
    }
    assert zone.protocols == ("tcp", "udp", "icmp", "17")
    assert zone.masquerade is False
    assert zone.forwarding is True
    assert zone.permanent is False


def test_parse_zone_state_marks_permanent_ports_and_keeps_multiple_rich_rules():
    output = _public_zone_output()

    zone = parse_zone_state("public", output, permanent=True)

    assert all(not port.runtime and port.permanent for port in zone.ports)
    assert zone.permanent is True
    assert len(zone.rich_rules) == 2
    assert zone.rich_rules[0].rule == '    rule family="ipv4" source address="192.0.2.0/24" port port="8443" protocol="tcp" accept'


@pytest.mark.parametrize("annotation", ("active", "default", "default, active", "active, default"))
def test_parse_zone_state_accepts_matching_modern_zone_annotations(annotation):
    output = _public_zone_output().replace("public (default, active)", f"public ({annotation})", 1)

    assert parse_zone_state("public", output, permanent=False).name == "public"


def test_parse_zone_state_rejects_a_different_modern_annotated_zone_name():
    output = _public_zone_output().replace("public (default, active)", "internal (default, active)", 1)

    with pytest.raises(FirewallParseError) as error:
        parse_zone_state("public", output, permanent=False)

    assert error.value.reason == "zone header did not match"


def test_parse_zone_state_skips_unmodeled_multiline_sections_and_resumes_top_level_fields():
    zone = parse_zone_state("public", _public_zone_output(), permanent=False)

    assert zone.forwarding is True
    assert zone.masquerade is False
    assert len(zone.rich_rules) == 2


@pytest.mark.parametrize(
    ("old", "new", "reason"),
    [
        ("ports: 8000-8100/tcp 53/udp 5000/sctp 5001/dccp", "ports: 99999/tcp", "invalid port value"),
        ("ports: 8000-8100/tcp 53/udp 5000/sctp 5001/dccp", "ports: 22/gre", "invalid port protocol"),
        ("sources: 192.0.2.0/24 2001:db8::/64 00:11:22:33:44:55 ipset:trusted_clients", "sources: not-a-source", "invalid source value"),
        ("forward: yes", "forward: maybe", "invalid forward value"),
    ],
)
def test_parse_zone_state_rejects_invalid_complete_fixture_values_with_a_safe_reason(old, new, reason):
    output = _public_zone_output().replace(old, new, 1)

    with pytest.raises(FirewallParseError) as error:
        parse_zone_state("public", output, permanent=False)

    assert error.value.operation == "zone state"
    assert error.value.reason == reason
    assert "not-a-source" not in str(error.value)


def test_parse_zone_state_splits_only_on_the_first_colon_in_a_field_value():
    output = "public\n  interfaces: br-0.1:2\n  sources:\n  services:\n  ports:\n  protocols:\n  forward: no\n  masquerade: yes\n  rich rules:\n"

    zone = parse_zone_state("public", output, permanent=False)

    assert zone.interfaces == ("br-0.1:2",)
    assert zone.masquerade is True


def test_parse_rich_rules_extracts_the_complete_supported_subset():
    raw = (
        'rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="SCTP" accept\n'
        'rule family="ipv6" destination address="2001:db8::/64" service name="ssh" reject\n'
    )

    rules = parse_rich_rules(raw)

    assert rules[0].rule == 'rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="SCTP" accept'
    assert (rules[0].family, rules[0].source, rules[0].destination, rules[0].service) == (
        "ipv4", "192.0.2.0/24", None, None,
    )
    assert (rules[0].port, rules[0].protocol, rules[0].action) == ("22", "sctp", "accept")
    assert (rules[1].family, rules[1].destination, rules[1].service, rules[1].action) == (
        "ipv6", "2001:db8::/64", "ssh", "reject",
    )


@pytest.mark.parametrize(
    "raw",
    [
        'rule family="ipv4" source address="not-a-network" service name="ssh" log prefix="audit" accept',
        'rule priority="1" family="ipv4" source address="192.0.2.0/24" service name="ssh" accept',
        'rule family="ipv4" source-port port="22" protocol="tcp" accept',
        'rule family="ipv4" forward-port port="22" protocol="tcp" to-port="2222" accept',
    ],
)
def test_parse_rich_rules_keeps_every_structured_field_empty_for_unsupported_syntax(raw):
    (rule,) = parse_rich_rules(raw + "\n")

    assert rule.rule == raw
    assert (rule.family, rule.source, rule.destination, rule.service, rule.port, rule.protocol, rule.action) == (
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )


def test_parse_rich_rules_extracts_a_standalone_protocol_value_clause():
    (rule,) = parse_rich_rules('rule family="ipv4" protocol value="icmp" accept\n')

    assert rule.family == "ipv4"
    assert rule.port is None
    assert rule.protocol == "icmp"
    assert rule.action == "accept"


@pytest.mark.parametrize(
    "output",
    [
        'rule family="ipv4" port port="not-a-port" protocol="tcp" accept\n',
        'rule family="ipv4" port port="22" protocol="gre" accept\n',
        'rule family="ipv4" source address="not-a-network" service name="ssh" accept\n',
        'rule family="other" service name="ssh" accept\n',
    ],
)
def test_parse_rich_rules_rejects_invalid_recognized_clause_values(output):
    with pytest.raises(FirewallParseError) as error:
        parse_rich_rules(output)

    assert error.value.operation == "rich rules"


def test_parse_os_release_decodes_shell_quotes_without_expanding_or_inventing_escapes():
    output = (
        "NAME='Fallback Linux'\n"
        'PRETTY_NAME="Fedora \\"Forty Two\\" \\x28Server\\x29 $HOME \\q"\n'
        "PRETTY_NAME='Fedora Final'\n"
    )

    assert parse_os_release(output) == "Fedora Final"


def test_parse_os_release_keeps_double_quoted_non_shell_backslashes_literal():
    assert parse_os_release('PRETTY_NAME="Fedora \\x28Server\\x29 $HOME \\q"\n') == r"Fedora \x28Server\x29 $HOME \q"


def test_parse_os_release_falls_back_to_a_single_token_unquoted_name_and_rejects_malformed_values():
    assert parse_os_release("NAME=Ubuntu\nID=ubuntu\n") == "Ubuntu"

    with pytest.raises(FirewallParseError) as error:
        parse_os_release("NAME=Ubuntu Server\n")

    assert error.value.operation == "os release"
    assert error.value.reason == "malformed os release value"
