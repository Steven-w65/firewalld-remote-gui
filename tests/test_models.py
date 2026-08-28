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


def test_models_are_frozen_value_objects():
    spec = CommandSpec("list_zones", ("firewall-cmd", "--get-zones"))

    with pytest.raises(FrozenInstanceError):
        spec.operation = "other"
