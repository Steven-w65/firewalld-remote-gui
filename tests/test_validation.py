import pytest

from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import (
    validate_inventory_value,
    validate_ip_network,
    validate_port,
    validate_protocol,
    validate_rich_action,
)


@pytest.mark.parametrize("value", ["1", "22", "443", "65535", "1-1", "8000-8100"])
def test_accepts_valid_ports(value):
    assert validate_port(value) == value


@pytest.mark.parametrize(
    "value",
    ["0", "65536", "-1", "abc", "9000-8000", "22; rm -rf /", " 22", "22 ", ""],
)
def test_rejects_invalid_ports(value):
    with pytest.raises(InvalidFirewallArgumentError):
        validate_port(value)


@pytest.mark.parametrize("value, expected", [("TCP", "tcp"), ("udp", "udp")])
def test_protocol_is_normalized_after_validation(value, expected):
    assert validate_protocol(value) == expected


@pytest.mark.parametrize("value", ["sctp", "tcp;id", " TCP", "UDP ", ""])
def test_rejects_unsupported_or_injected_protocols(value):
    with pytest.raises(InvalidFirewallArgumentError):
        validate_protocol(value)


@pytest.mark.parametrize("value", ["accept", "REJECT", "Drop"])
def test_rich_action_is_normalized_after_validation(value):
    assert validate_rich_action(value) == value.lower()


@pytest.mark.parametrize("value", ["log", "accept;id", " accept", "drop ", ""])
def test_rejects_unsupported_or_injected_rich_actions(value):
    with pytest.raises(InvalidFirewallArgumentError):
        validate_rich_action(value)


def test_inventory_value_must_come_from_remote_inventory():
    assert validate_inventory_value("zone", "public", {"public", "internal"}) == "public"
    with pytest.raises(InvalidFirewallArgumentError, match="zone"):
        validate_inventory_value("zone", "public;id", {"public", "internal"})
    with pytest.raises(InvalidFirewallArgumentError):
        validate_inventory_value("zone", " public", {"public"})


@pytest.mark.parametrize(
    "value, expected",
    [("192.0.2.4/24", "192.0.2.0/24"), ("2001:db8::1/64", "2001:db8::/64")],
)
def test_ip_networks_are_normalized(value, expected):
    assert validate_ip_network(value) == expected


@pytest.mark.parametrize("value", ["", "not-an-ip", "192.0.2.1/", " 192.0.2.0/24", "192.0.2.0/24 ", "192.0.2.0/24;id"])
def test_rejects_malformed_whitespace_and_injection_shaped_networks(value):
    with pytest.raises(InvalidFirewallArgumentError):
        validate_ip_network(value)
