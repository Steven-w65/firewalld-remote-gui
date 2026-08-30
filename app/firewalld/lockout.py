"""Pure, conservative warnings for firewall changes that may interrupt SSH."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TypeAlias

from app.models.firewall import FirewallSnapshot, RichRule
from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import (
    validate_inventory_token,
    validate_port,
    validate_protocol,
)


_INCOMPLETE_DETECTION = (
    "SSH lockout detection is incomplete and does not guarantee that this change "
    "is safe."
)


class RiskLevel(str, Enum):
    """Severity of a recognized SSH lockout risk."""

    NONE = "none"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class LockoutRisk:
    """Immutable result containing recognized risks and conservative context."""

    level: RiskLevel
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.level, RiskLevel):
            raise TypeError("level must be a RiskLevel")
        if isinstance(self.reasons, str):
            raise TypeError("reasons must be an iterable of strings")
        reasons = tuple(dict.fromkeys(self.reasons))
        if any(not isinstance(reason, str) or not reason for reason in reasons):
            raise TypeError("reasons must contain nonempty strings")
        object.__setattr__(self, "reasons", reasons)

    @property
    def has_risk(self) -> bool:
        return self.level is not RiskLevel.NONE

    @property
    def is_high(self) -> bool:
        return self.level is RiskLevel.HIGH


@dataclass(frozen=True, slots=True)
class RemovePortChange:
    zone: str
    port: str
    protocol: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "zone", validate_inventory_token("zone", self.zone))
        object.__setattr__(self, "port", validate_port(self.port))
        object.__setattr__(self, "protocol", validate_protocol(self.protocol))


@dataclass(frozen=True, slots=True)
class RemoveServiceChange:
    zone: str
    service: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "zone", validate_inventory_token("zone", self.zone))
        object.__setattr__(
            self, "service", validate_inventory_token("service", self.service)
        )


@dataclass(frozen=True, slots=True)
class MoveInterfaceChange:
    interface: str
    current_zone: str
    new_zone: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "interface",
            validate_inventory_token("interface", self.interface),
        )
        object.__setattr__(
            self,
            "current_zone",
            validate_inventory_token("zone", self.current_zone),
        )
        object.__setattr__(
            self, "new_zone", validate_inventory_token("zone", self.new_zone)
        )


@dataclass(frozen=True, slots=True)
class RemoveRichRuleChange:
    zone: str
    rule: RichRule

    def __post_init__(self) -> None:
        object.__setattr__(self, "zone", validate_inventory_token("zone", self.zone))
        if not isinstance(self.rule, RichRule):
            raise TypeError("rule must be a RichRule")


FirewallChange: TypeAlias = (
    RemovePortChange | RemoveServiceChange | MoveInterfaceChange | RemoveRichRuleChange
)


def _management_port(ssh_port: int) -> int:
    if isinstance(ssh_port, bool) or not isinstance(ssh_port, int):
        raise InvalidFirewallArgumentError(
            "management port", "must be an integer between 1 and 65535"
        )
    if not 1 <= ssh_port <= 65535:
        raise InvalidFirewallArgumentError(
            "management port", "must be between 1 and 65535"
        )
    return ssh_port


def _port_contains(port: str, ssh_port: int) -> bool:
    validated = validate_port(port)
    first, separator, last = validated.partition("-")
    lower = int(first)
    upper = int(last) if separator else lower
    return lower <= ssh_port <= upper


def _known_zones(snapshot: FirewallSnapshot) -> frozenset[str]:
    return frozenset(
        zone.name for zone in snapshot.runtime_zones + snapshot.permanent_zones
    )


def _inventory_reasons(
    change: FirewallChange, snapshot: FirewallSnapshot
) -> list[str]:
    reasons: list[str] = []
    if snapshot.stale:
        reasons.append(
            "The firewall snapshot is stale, so SSH lockout detection is incomplete."
        )
    if not snapshot.firewalld_running:
        reasons.append(
            "Firewalld is not reported as running, so active SSH access cannot be "
            "assessed reliably."
        )

    zones = _known_zones(snapshot)
    required_zones = (
        (change.current_zone, change.new_zone)
        if isinstance(change, MoveInterfaceChange)
        else (change.zone,)
    )
    for zone in required_zones:
        if zone not in zones:
            reasons.append(
                f"Zone '{zone}' is absent from the snapshot, so SSH lockout "
                "detection is incomplete."
            )
    return reasons


def _port_reasons(change: RemovePortChange, ssh_port: int) -> list[str]:
    if change.protocol != "tcp" or not _port_contains(change.port, ssh_port):
        return []
    if "-" in change.port:
        return [
            f"Removing TCP port range {change.port} from zone '{change.zone}' "
            f"includes management port {ssh_port} and may interrupt SSH access."
        ]
    return [
        f"Removing TCP port {change.port} from zone '{change.zone}' may interrupt "
        f"SSH access on management port {ssh_port}."
    ]


def _service_reasons(change: RemoveServiceChange, ssh_port: int) -> list[str]:
    if change.service.lower() != "ssh":
        return []
    return [
        f"Removing the ssh service from zone '{change.zone}' may interrupt SSH "
        f"access on management port {ssh_port}."
    ]


def _interface_reasons(
    change: MoveInterfaceChange, snapshot: FirewallSnapshot
) -> list[str]:
    active_zones = tuple(
        zone.name
        for zone in snapshot.runtime_zones
        if change.interface in zone.interfaces
    )
    if change.current_zone in active_zones:
        return [
            f"Moving active interface '{change.interface}' from zone "
            f"'{change.current_zone}' to '{change.new_zone}' may change the "
            "management route and interrupt SSH access."
        ]
    if active_zones:
        return [
            f"Interface '{change.interface}' appears in a different active zone "
            "than the requested source, so SSH lockout detection is incomplete."
        ]
    return []


def _rich_rule_reasons(
    change: RemoveRichRuleChange, ssh_port: int
) -> tuple[list[str], bool]:
    rule = change.rule
    if rule.port is not None:
        validate_port(rule.port)

    structured = rule.action is not None and (
        rule.service is not None
        or (rule.port is not None and rule.protocol is not None)
    )
    if not structured:
        return (
            [
                "The selected rich rule has no complete structured safe-subset fields; "
                "its display text is not analyzed, so SSH lockout detection is incomplete."
            ],
            False,
        )
    if rule.action.lower() != "accept":
        return [], False

    reasons: list[str] = []
    if rule.service is not None and rule.service.lower() == "ssh":
        reasons.append(
            f"Removing a structured rich rule that accepts the ssh service in zone "
            f"'{change.zone}' may interrupt SSH access on management port {ssh_port}."
        )
    if (
        rule.port is not None
        and rule.protocol is not None
        and rule.protocol.lower() == "tcp"
        and _port_contains(rule.port, ssh_port)
    ):
        reasons.append(
            f"Removing a structured rich rule that accepts TCP port {rule.port} in "
            f"zone '{change.zone}' may interrupt SSH access on management port "
            f"{ssh_port}."
        )
    return reasons, bool(reasons)


def assess_lockout_risk(
    change: FirewallChange,
    snapshot: FirewallSnapshot,
    ssh_port: int,
) -> LockoutRisk:
    """Return recognized risks without ever claiming that a change is safe."""
    management_port = _management_port(ssh_port)
    if not isinstance(snapshot, FirewallSnapshot):
        raise TypeError("snapshot must be a FirewallSnapshot")
    if not isinstance(
        change,
        (
            RemovePortChange,
            RemoveServiceChange,
            MoveInterfaceChange,
            RemoveRichRuleChange,
        ),
    ):
        raise InvalidFirewallArgumentError(
            "change", "must be a supported typed firewall change"
        )

    reasons = _inventory_reasons(change, snapshot)
    detected = bool(reasons)
    if isinstance(change, RemovePortChange):
        change_reasons = _port_reasons(change, management_port)
        reasons.extend(change_reasons)
        detected = detected or bool(change_reasons)
    elif isinstance(change, RemoveServiceChange):
        change_reasons = _service_reasons(change, management_port)
        reasons.extend(change_reasons)
        detected = detected or bool(change_reasons)
    elif isinstance(change, MoveInterfaceChange):
        change_reasons = _interface_reasons(change, snapshot)
        reasons.extend(change_reasons)
        detected = detected or bool(change_reasons)
    else:
        change_reasons, rich_rule_detected = _rich_rule_reasons(
            change, management_port
        )
        reasons.extend(change_reasons)
        detected = detected or rich_rule_detected

    reasons.append(_INCOMPLETE_DETECTION)
    return LockoutRisk(
        RiskLevel.HIGH if detected else RiskLevel.NONE,
        reasons,
    )


__all__ = [
    "FirewallChange",
    "LockoutRisk",
    "MoveInterfaceChange",
    "RemovePortChange",
    "RemoveRichRuleChange",
    "RemoveServiceChange",
    "RiskLevel",
    "assess_lockout_risk",
]
