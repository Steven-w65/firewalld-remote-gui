from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from app.firewalld.lockout import (
    LockoutRisk,
    MoveInterfaceChange,
    RemovePortChange,
    RemoveRichRuleChange,
    RemoveServiceChange,
    RiskLevel,
    assess_lockout_risk,
)
from app.models.firewall import FirewallPort, FirewallSnapshot, RichRule, ZoneState
from app.utils.errors import InvalidFirewallArgumentError


def _snapshot(
    *,
    stale: bool = False,
    runtime_zones: tuple[ZoneState, ...] | None = None,
) -> FirewallSnapshot:
    public = ZoneState(
        name="public",
        interfaces=("eth0",),
        services=("ssh",),
        ports=(FirewallPort("22", "tcp", "public", True, False),),
    )
    internal = ZoneState(name="internal", interfaces=("eth1",))
    return FirewallSnapshot(
        hostname="host.example",
        distribution="Example Linux",
        firewalld_running=True,
        firewalld_version="2.3.1",
        default_zone="public",
        runtime_zones=(public, internal) if runtime_zones is None else runtime_zones,
        permanent_zones=(ZoneState(name="public", permanent=True),),
        available_services=("http", "ssh"),
        stale=stale,
    )


def test_removing_management_port_is_high_risk() -> None:
    risk = assess_lockout_risk(
        RemovePortChange("public", "2222", "tcp"), _snapshot(), ssh_port=2222
    )

    assert risk.is_high
    assert "TCP port 2222" in risk.reasons[0]
    assert "detection is incomplete" in risk.reasons[-1].lower()


@pytest.mark.parametrize("port", ["22", "1-22", "22-65535", "1-65535"])
def test_management_port_range_endpoints_are_inclusive(port: str) -> None:
    risk = assess_lockout_risk(
        RemovePortChange("public", port, "TCP"), _snapshot(), ssh_port=22
    )

    assert risk.is_high


@pytest.mark.parametrize("port", ["", "0", "65536", "23-22", "1-65536", "22--23", "ssh"])
def test_remove_port_change_rejects_malformed_or_reversed_ranges(port: str) -> None:
    with pytest.raises(InvalidFirewallArgumentError, match="Invalid port"):
        RemovePortChange("public", port, "tcp")


@pytest.mark.parametrize("ssh_port", [0, 65536, True, "22", None])
def test_assessment_rejects_invalid_management_ports(ssh_port: object) -> None:
    with pytest.raises(InvalidFirewallArgumentError, match="management port"):
        assess_lockout_risk(
            RemovePortChange("public", "22", "tcp"),
            _snapshot(),
            ssh_port=ssh_port,  # type: ignore[arg-type]
        )


def test_unrelated_or_udp_port_has_no_known_risk_without_claiming_safety() -> None:
    unrelated = assess_lockout_risk(
        RemovePortChange("public", "23-30", "tcp"), _snapshot(), ssh_port=22
    )
    udp = assess_lockout_risk(
        RemovePortChange("public", "22", "udp"), _snapshot(), ssh_port=22
    )

    assert not unrelated.has_risk
    assert not udp.has_risk
    assert unrelated.reasons == udp.reasons
    assert "does not guarantee" in unrelated.reasons[0].lower()
    assert "safe" in unrelated.reasons[0].lower()


def test_removing_ssh_service_is_high_risk_but_other_services_are_not_known_risks() -> None:
    ssh = assess_lockout_risk(
        RemoveServiceChange("public", "ssh"), _snapshot(), ssh_port=22
    )
    http = assess_lockout_risk(
        RemoveServiceChange("public", "http"), _snapshot(), ssh_port=22
    )

    assert ssh.is_high
    assert "ssh service" in ssh.reasons[0].lower()
    assert not http.has_risk


def test_moving_an_active_interface_is_high_risk() -> None:
    risk = assess_lockout_risk(
        MoveInterfaceChange("eth0", "public", "internal"), _snapshot(), ssh_port=22
    )

    assert risk.is_high
    assert "active interface 'eth0'" in risk.reasons[0]
    assert "management route" in risk.reasons[0]


def test_moving_an_inactive_interface_is_only_no_known_risk() -> None:
    risk = assess_lockout_risk(
        MoveInterfaceChange("eth9", "public", "internal"), _snapshot(), ssh_port=22
    )

    assert not risk.has_risk
    assert "does not guarantee" in risk.reasons[0].lower()


def test_conflicting_active_interface_assignment_is_an_incomplete_high_risk_state() -> None:
    risk = assess_lockout_risk(
        MoveInterfaceChange("eth1", "public", "internal"), _snapshot(), ssh_port=22
    )

    assert risk.is_high
    assert "different active zone" in risk.reasons[0].lower()


@pytest.mark.parametrize(
    "rule",
    [
        RichRule(
            'rule family="ipv4" service name="ssh" accept',
            family="ipv4",
            service="ssh",
            action="accept",
        ),
        RichRule(
            'rule family="ipv4" port port="22" protocol="tcp" accept',
            family="ipv4",
            port="22",
            protocol="tcp",
            action="accept",
        ),
        RichRule(
            'rule family="ipv4" port port="1-22" protocol="tcp" accept',
            family="ipv4",
            port="1-22",
            protocol="tcp",
            action="accept",
        ),
    ],
)
def test_removing_structured_accept_rule_for_ssh_is_high_risk(rule: RichRule) -> None:
    risk = assess_lockout_risk(
        RemoveRichRuleChange("public", rule), _snapshot(), ssh_port=22
    )

    assert risk.is_high
    assert "structured rich rule" in risk.reasons[0].lower()


def test_remove_rich_rule_change_accepts_the_public_rule_keyword() -> None:
    rule = RichRule(
        'rule family="ipv4" service name="ssh" accept',
        family="ipv4",
        service="ssh",
        action="accept",
    )

    change = RemoveRichRuleChange(zone="public", rule=rule)

    assert change.rule is rule


@pytest.mark.parametrize(
    "rule",
    [
        RichRule(
            'rule family="ipv4" port port="22" protocol="udp" accept',
            family="ipv4",
            port="22",
            protocol="udp",
            action="accept",
        ),
        RichRule(
            'rule family="ipv4" service name="ssh" drop',
            family="ipv4",
            service="ssh",
            action="drop",
        ),
    ],
)
def test_nonpermitting_structured_rules_have_no_known_risk(rule: RichRule) -> None:
    risk = assess_lockout_risk(
        RemoveRichRuleChange("public", rule), _snapshot(), ssh_port=22
    )

    assert not risk.has_risk


@pytest.mark.parametrize("port", ["0", "65536", "23-22", "22--23"])
def test_assessment_rejects_malformed_structured_rich_rule_ports(port: str) -> None:
    rule = RichRule(
        "display-only",
        port=port,
        protocol="tcp",
        action="accept",
    )

    with pytest.raises(InvalidFirewallArgumentError, match="Invalid port"):
        assess_lockout_risk(
            RemoveRichRuleChange("public", rule), _snapshot(), ssh_port=22
        )


def test_raw_rich_rule_text_is_display_only_and_never_drives_risk() -> None:
    dangerous_looking_raw = RichRule(
        'rule family="ipv4" service name="ssh" port port="22" protocol="tcp" accept'
    )
    harmless_looking_raw = RichRule("rule accept")

    first = assess_lockout_risk(
        RemoveRichRuleChange("public", dangerous_looking_raw), _snapshot(), 22
    )
    second = assess_lockout_risk(
        RemoveRichRuleChange("public", harmless_looking_raw), _snapshot(), 22
    )

    assert first == second
    assert not first.has_risk
    assert "structured" in first.reasons[0].lower()
    assert "incomplete" in first.reasons[0].lower()


def test_structured_service_and_port_matches_produce_independent_deduplicated_reasons() -> None:
    rule = RichRule(
        "display-only",
        service="ssh",
        port="22",
        protocol="tcp",
        action="accept",
    )

    risk = assess_lockout_risk(
        RemoveRichRuleChange("public", rule), _snapshot(stale=True), ssh_port=22
    )

    assert risk.is_high
    assert sum("structured rich rule" in reason.lower() for reason in risk.reasons) == 2
    assert sum("snapshot is stale" in reason.lower() for reason in risk.reasons) == 1
    assert len(risk.reasons) == len(dict.fromkeys(risk.reasons))


def test_stale_snapshot_and_missing_zone_are_high_risk_incomplete_states() -> None:
    stale = assess_lockout_risk(
        RemovePortChange("public", "53", "udp"), _snapshot(stale=True), ssh_port=22
    )
    missing = assess_lockout_risk(
        RemoveServiceChange("dmz", "http"), _snapshot(), ssh_port=22
    )

    assert stale.is_high
    assert "snapshot is stale" in stale.reasons[0].lower()
    assert missing.is_high
    assert "zone 'dmz'" in missing.reasons[0].lower()
    assert "incomplete" in missing.reasons[0].lower()


def test_assessment_is_pure_and_does_not_mutate_change_or_snapshot() -> None:
    snapshot = _snapshot()
    change = RemovePortChange("public", "22", "tcp")

    before_snapshot = snapshot
    before_change = change
    first = assess_lockout_risk(change, snapshot, ssh_port=22)
    second = assess_lockout_risk(change, snapshot, ssh_port=22)

    assert first == second
    assert snapshot == before_snapshot
    assert change == before_change
    with pytest.raises(FrozenInstanceError):
        change.port = "23"  # type: ignore[misc]


def test_lockout_risk_normalizes_reasons_to_an_immutable_unique_tuple() -> None:
    risk = LockoutRisk(RiskLevel.HIGH, ["first", "first", "second"])  # type: ignore[arg-type]

    assert risk.reasons == ("first", "second")
    with pytest.raises(FrozenInstanceError):
        risk.level = RiskLevel.NONE  # type: ignore[misc]
