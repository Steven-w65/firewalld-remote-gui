import pytest

from app.firewalld.command_builder import FirewalldCommandBuilder as Builder
from app.firewalld.renderer import render_command
from app.utils.errors import InvalidFirewallArgumentError


@pytest.mark.parametrize(
    ("method", "arguments", "expected"),
    [
        ("get_state", (), ("firewall-cmd", "--state")),
        ("get_version", (), ("firewall-cmd", "--version")),
        ("list_zones", (False,), ("firewall-cmd", "--get-zones")),
        ("list_zones", (True,), ("firewall-cmd", "--permanent", "--get-zones")),
        ("list_active_zones", (), ("firewall-cmd", "--get-active-zones")),
        ("get_default_zone", (), ("firewall-cmd", "--get-default-zone")),
        ("set_default_zone", ("public",), ("firewall-cmd", "--set-default-zone=public")),
        ("get_zone_details", ("public", False), ("firewall-cmd", "--zone=public", "--list-all")),
        ("get_zone_details", ("public", True), ("firewall-cmd", "--permanent", "--zone=public", "--list-all")),
        ("list_ports", ("public", False), ("firewall-cmd", "--zone=public", "--list-ports")),
        ("list_ports", ("public", True), ("firewall-cmd", "--permanent", "--zone=public", "--list-ports")),
        ("list_available_services", (), ("firewall-cmd", "--get-services")),
        ("list_services", ("public", False), ("firewall-cmd", "--zone=public", "--list-services")),
        ("list_services", ("public", True), ("firewall-cmd", "--permanent", "--zone=public", "--list-services")),
        ("list_interfaces", ("public", False), ("firewall-cmd", "--zone=public", "--list-interfaces")),
        ("list_interfaces", ("public", True), ("firewall-cmd", "--permanent", "--zone=public", "--list-interfaces")),
        ("list_rich_rules", ("public", False), ("firewall-cmd", "--zone=public", "--list-rich-rules")),
        ("list_rich_rules", ("public", True), ("firewall-cmd", "--permanent", "--zone=public", "--list-rich-rules")),
        ("reload", (), ("firewall-cmd", "--reload")),
    ],
)
def test_read_and_fixed_operations_have_exact_allowlisted_arguments(method, arguments, expected):
    assert getattr(Builder, method)(*arguments).argv == expected


def test_default_zone_operations_are_global_and_do_not_accept_a_target():
    get_default = Builder.get_default_zone()
    set_default = Builder.set_default_zone("public")

    assert get_default.operation == "get_default_zone"
    assert set_default.operation == "set_default_zone"
    with pytest.raises(TypeError):
        Builder.get_default_zone(permanent=True)
    with pytest.raises(TypeError):
        Builder.set_default_zone("public", permanent=True)


@pytest.mark.parametrize(
    ("method", "arguments", "expected"),
    [
        ("add_port", ("public", "8080", "tcp", False), ("firewall-cmd", "--zone=public", "--add-port=8080/tcp")),
        ("add_port", ("public", "8080", "tcp", True), ("firewall-cmd", "--permanent", "--zone=public", "--add-port=8080/tcp")),
        ("remove_port", ("public", "8000-8100", "UDP", False), ("firewall-cmd", "--zone=public", "--remove-port=8000-8100/udp")),
        ("remove_port", ("public", "8000-8100", "UDP", True), ("firewall-cmd", "--permanent", "--zone=public", "--remove-port=8000-8100/udp")),
        ("add_service", ("public", "ssh", False), ("firewall-cmd", "--zone=public", "--add-service=ssh")),
        ("add_service", ("public", "ssh", True), ("firewall-cmd", "--permanent", "--zone=public", "--add-service=ssh")),
        ("remove_service", ("public", "ssh", False), ("firewall-cmd", "--zone=public", "--remove-service=ssh")),
        ("remove_service", ("public", "ssh", True), ("firewall-cmd", "--permanent", "--zone=public", "--remove-service=ssh")),
        ("change_interface_zone", ("eth0", "internal", False), ("firewall-cmd", "--zone=internal", "--change-interface=eth0")),
        ("change_interface_zone", ("eth0", "internal", True), ("firewall-cmd", "--permanent", "--zone=internal", "--change-interface=eth0")),
    ],
)
def test_mutating_operations_have_exact_runtime_and_permanent_arguments(method, arguments, expected):
    assert getattr(Builder, method)(*arguments).argv == expected


def test_interface_builder_accepts_valid_punctuation_and_renderer_quotes_it():
    spec = Builder.change_interface_zone("br+0#x=lab@z", "public")

    assert spec.argv == ("firewall-cmd", "--zone=public", "--change-interface=br+0#x=lab@z")
    assert render_command(spec) == "firewall-cmd --zone=public '--change-interface=br+0#x=lab@z'"


def test_structured_rich_service_rule_has_deterministic_clauses():
    spec = Builder.add_rich_rule(
        zone="public", source="192.0.2.4/24", destination="198.51.100.5/24",
        service="ssh", port=None, protocol=None, action="ACCEPT", permanent=False,
    )
    assert spec.argv == (
        "firewall-cmd", "--zone=public",
        '--add-rich-rule=rule family="ipv4" source address="192.0.2.0/24" destination address="198.51.100.0/24" service name="ssh" accept',
    )


def test_structured_rich_port_rule_chooses_ipv6_and_is_removable():
    spec = Builder.remove_rich_rule(
        zone="public", source="2001:db8::1/64", destination=None,
        service=None, port="8443", protocol="tcp", action="drop", permanent=True,
    )
    assert spec.argv == (
        "firewall-cmd", "--permanent", "--zone=public",
        '--remove-rich-rule=rule family="ipv6" source address="2001:db8::/64" port port="8443" protocol="tcp" drop',
    )


@pytest.mark.parametrize(
    ("method", "arguments", "expected"),
    [
        (
            "add_rich_rule",
            ("public", None, None, "ssh", None, None, "accept", False),
            (
                "firewall-cmd",
                "--zone=public",
                '--add-rich-rule=rule service name="ssh" accept',
            ),
        ),
        (
            "add_rich_rule",
            ("public", None, None, "ssh", None, None, "accept", True),
            (
                "firewall-cmd",
                "--permanent",
                "--zone=public",
                '--add-rich-rule=rule service name="ssh" accept',
            ),
        ),
        (
            "remove_rich_rule",
            ("public", None, None, "ssh", None, None, "drop", False),
            (
                "firewall-cmd",
                "--zone=public",
                '--remove-rich-rule=rule service name="ssh" drop',
            ),
        ),
        (
            "remove_rich_rule",
            ("public", None, None, "ssh", None, None, "drop", True),
            (
                "firewall-cmd",
                "--permanent",
                "--zone=public",
                '--remove-rich-rule=rule service name="ssh" drop',
            ),
        ),
        (
            "add_rich_rule",
            ("public", None, None, None, "8443", "TCP", "accept", False),
            (
                "firewall-cmd",
                "--zone=public",
                '--add-rich-rule=rule port port="8443" protocol="tcp" accept',
            ),
        ),
        (
            "add_rich_rule",
            ("public", None, None, None, "8443", "TCP", "accept", True),
            (
                "firewall-cmd",
                "--permanent",
                "--zone=public",
                '--add-rich-rule=rule port port="8443" protocol="tcp" accept',
            ),
        ),
        (
            "remove_rich_rule",
            ("public", None, None, None, "53", "udp", "reject", False),
            (
                "firewall-cmd",
                "--zone=public",
                '--remove-rich-rule=rule port port="53" protocol="udp" reject',
            ),
        ),
        (
            "remove_rich_rule",
            ("public", None, None, None, "53", "udp", "reject", True),
            (
                "firewall-cmd",
                "--permanent",
                "--zone=public",
                '--remove-rich-rule=rule port port="53" protocol="udp" reject',
            ),
        ),
    ],
)
def test_addressless_structured_rich_rules_have_exact_runtime_and_permanent_arguments(
    method, arguments, expected
):
    """Catches requiring an address or emitting a meaningless family clause."""
    assert getattr(Builder, method)(*arguments).argv == expected


@pytest.mark.parametrize(
    "call",
    [
        lambda: Builder.add_port("public; id", "22", "tcp", False),
        lambda: Builder.add_service("public", "ssh; id", False),
        lambda: Builder.change_interface_zone("eth0; id", "public", False),
        lambda: Builder.change_interface_zone("eth0/1", "public", False),
        lambda: Builder.change_interface_zone("abcdefghijklmnopq", "public", False),
        lambda: Builder.set_default_zone("trusted;id"),
        lambda: Builder.add_rich_rule("public", "192.0.2.0/24;id", None, "ssh", None, None, "accept", False),
        lambda: Builder.add_rich_rule("public", None, None, "ssh;id", None, None, "accept", False),
    ],
)
def test_builders_reject_injection_shaped_components_before_argv_construction(call):
    with pytest.raises(InvalidFirewallArgumentError):
        call()


@pytest.mark.parametrize(
    "service, port, protocol, source, destination",
    [
        (None, None, None, "192.0.2.0/24", None),
        ("ssh", "22", "tcp", "192.0.2.0/24", None),
        ("ssh", None, "tcp", "192.0.2.0/24", None),
        (None, "22", None, "192.0.2.0/24", None),
        ("ssh", None, None, "192.0.2.0/24", "2001:db8::/64"),
    ],
)
def test_rich_rules_reject_ambiguous_or_unsafe_structures(service, port, protocol, source, destination):
    with pytest.raises(InvalidFirewallArgumentError):
        Builder.add_rich_rule("public", source, destination, service, port, protocol, "accept", False)
