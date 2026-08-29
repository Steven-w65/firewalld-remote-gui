from dataclasses import FrozenInstanceError

import pytest

from app.models.command import CommandResult, CommandSpec, CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, TargetStatus
from app.models.firewall import FirewallPort, FirewallSnapshot, RichRule, ZoneState


def test_composite_result_reports_complete_success():
    command = CommandResult(True, 0, "success", "", "web01", "add_port", 0.2)
    runtime = TargetResult(ApplyTarget.RUNTIME, TargetStatus.SUCCEEDED, TargetStatus.SUCCEEDED, command, "")
    permanent = TargetResult(ApplyTarget.PERMANENT, TargetStatus.SUCCEEDED, TargetStatus.SUCCEEDED, command, "")

    result = CompositeOperationResult("add_port", runtime=runtime, permanent=permanent)

    assert result.is_success
    assert not result.is_partial


def test_composite_result_reports_complete_failure():
    runtime = TargetResult(ApplyTarget.RUNTIME, TargetStatus.FAILED, TargetStatus.NOT_RUN, None, "denied")
    permanent = TargetResult(ApplyTarget.PERMANENT, TargetStatus.FAILED, TargetStatus.NOT_RUN, None, "denied")

    result = CompositeOperationResult("add_port", runtime=runtime, permanent=permanent)

    assert not result.is_success
    assert not result.is_partial


def test_composite_result_reports_partial_success():
    ok = CommandResult(True, 0, "success", "", "web01", "add_port", 0.2)
    runtime = TargetResult(ApplyTarget.RUNTIME, TargetStatus.SUCCEEDED, TargetStatus.SUCCEEDED, ok, "")
    permanent = TargetResult(ApplyTarget.PERMANENT, TargetStatus.FAILED, TargetStatus.NOT_RUN, None, "denied")

    result = CompositeOperationResult("add_port", runtime=runtime, permanent=permanent)

    assert result.is_partial
    assert not result.is_success


def test_firewall_port_normalizes_protocol():
    assert FirewallPort("8080", "TCP", "public", True, False).protocol == "tcp"


def test_snapshot_looks_up_zones_and_ports_in_requested_target_only():
    runtime = ZoneState("public", ports=(FirewallPort("8080", "tcp", "public", True, False),))
    permanent = ZoneState("public", ports=(FirewallPort("8443", "tcp", "public", False, True),))
    snapshot = FirewallSnapshot("web01", "Fedora", True, "2.1.0", "public", (runtime,), (permanent,), ("ssh",))

    assert snapshot.zone("public", permanent=False) is runtime
    assert snapshot.zone("public", permanent=True) is permanent
    assert snapshot.zone("missing", permanent=False) is None
    assert snapshot.has_port("public", "8080", "TCP", permanent=False)
    assert not snapshot.has_port("public", "8080", "tcp", permanent=True)
    assert snapshot.has_port("public", "8443", "tcp", permanent=True)


def test_rich_rule_preserves_an_unstructured_remote_value():
    remote_rule = 'rule family="ipv4" source address="192.0.2.0/24" log prefix="audit" level="info" accept'

    rule = RichRule(remote_rule)

    assert rule.rule == remote_rule
    assert rule.source is None
    assert rule.port is None
    assert rule.service is None
    assert rule.action is None


def test_rich_rule_keeps_the_existing_optional_positional_field_order():
    rule = RichRule('rule service name="ssh" accept', "192.0.2.0/24")

    assert rule.source == "192.0.2.0/24"
    assert rule.family is None


def test_models_are_frozen_value_objects():
    spec = CommandSpec("list_zones", ("firewall-cmd", "--get-zones"))

    with pytest.raises(FrozenInstanceError):
        spec.operation = "other"


def test_command_spec_copies_mutable_argv():
    argv = ["firewall-cmd", "--get-zones"]

    spec = CommandSpec("list_zones", argv)
    argv.append("--permanent")

    assert spec.argv == ("firewall-cmd", "--get-zones")
    assert isinstance(spec.argv, tuple)


def test_zone_state_copies_mutable_collections():
    interfaces = ["eth0"]
    sources = ["192.0.2.0/24"]
    services = ["ssh"]
    ports = [FirewallPort("22", "tcp", "public", True, False)]
    rich_rules = [RichRule('rule service name="ssh" accept')]

    zone = ZoneState("public", interfaces, sources, services, ports, rich_rules)
    interfaces.append("eth1")
    sources.append("198.51.100.0/24")
    services.append("http")
    ports.append(FirewallPort("80", "tcp", "public", True, False))
    rich_rules.append(RichRule('rule service name="http" accept'))

    assert zone.interfaces == ("eth0",)
    assert zone.sources == ("192.0.2.0/24",)
    assert zone.services == ("ssh",)
    assert zone.ports == (FirewallPort("22", "tcp", "public", True, False),)
    assert zone.rich_rules == (RichRule('rule service name="ssh" accept'),)
    assert all(isinstance(value, tuple) for value in (zone.interfaces, zone.sources, zone.services, zone.ports, zone.rich_rules))


def test_zone_state_defaults_to_runtime_state():
    assert ZoneState("public").permanent is False


def test_zone_state_accepts_an_explicit_frozen_permanent_state():
    zone = ZoneState("public", permanent=True)

    assert zone.permanent is True
    with pytest.raises(FrozenInstanceError):
        zone.permanent = False


def test_zone_state_copies_read_side_protocols_into_an_immutable_tuple():
    protocols = ["icmp", "17"]

    zone = ZoneState("public", protocols=protocols)
    protocols.append("gre")

    assert zone.protocols == ("icmp", "17")


def test_snapshot_copies_mutable_collections():
    runtime_zones = [ZoneState("public")]
    permanent_zones = [ZoneState("internal")]
    services = ["ssh"]

    snapshot = FirewallSnapshot("web01", "Fedora", True, "2.1.0", "public", runtime_zones, permanent_zones, services)
    runtime_zones.append(ZoneState("trusted"))
    permanent_zones.append(ZoneState("dmz"))
    services.append("http")

    assert snapshot.runtime_zones == (ZoneState("public"),)
    assert snapshot.permanent_zones == (ZoneState("internal"),)
    assert snapshot.available_services == ("ssh",)
    assert all(isinstance(value, tuple) for value in (snapshot.runtime_zones, snapshot.permanent_zones, snapshot.available_services))
