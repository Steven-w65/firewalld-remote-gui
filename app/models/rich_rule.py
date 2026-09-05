"""Immutable structured-rich-rule presentation and intention values."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress

from app.models.enums import ApplyTarget
from app.models.firewall import RichRule
from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import (
    validate_inventory_token,
    validate_ip_network,
    validate_port,
    validate_protocol,
    validate_rich_action,
)


def _optional_network(value: str | None) -> str | None:
    return None if value is None else validate_ip_network(value)


def _family(source: str | None, destination: str | None) -> str | None:
    versions = {
        ipaddress.ip_network(value).version
        for value in (source, destination)
        if value is not None
    }
    if len(versions) > 1:
        raise InvalidFirewallArgumentError(
            "rich rule", "source and destination must use the same address family"
        )
    if not versions:
        return None
    return "ipv6" if versions.pop() == 6 else "ipv4"


def validate_structured_rule(rule: RichRule) -> tuple[object, ...] | None:
    """Return canonical identity, or ``None`` for a display-only raw rule."""
    if not isinstance(rule, RichRule):
        raise TypeError("rule must be a RichRule")
    fields = (
        rule.source,
        rule.destination,
        rule.service,
        rule.port,
        rule.protocol,
        rule.action,
        rule.family,
    )
    if all(value is None for value in fields):
        return None
    if rule.action is None or (rule.service is None) == (rule.port is None):
        return None
    source = _optional_network(rule.source)
    destination = _optional_network(rule.destination)
    family = _family(source, destination)
    if rule.family != family:
        return None
    action = validate_rich_action(rule.action)
    if rule.service is not None:
        if rule.protocol is not None:
            return None
        service = validate_inventory_token("service", rule.service)
        port = protocol = None
    else:
        if rule.protocol is None:
            return None
        service = None
        port = validate_port(rule.port)
        protocol = validate_protocol(rule.protocol)
    return (
        family,
        source,
        destination,
        service,
        port,
        protocol,
        action,
    )


def structured_rule_summary(rule: RichRule) -> str:
    identity = validate_structured_rule(rule)
    if identity is None:
        return rule.rule.strip() or "Unsupported rich rule"
    family, source, destination, service, port, protocol, action = identity
    del family
    resource = service if service is not None else f"{port}/{protocol}"
    qualifiers = []
    if source is not None:
        qualifiers.append(f"from {source}")
    if destination is not None:
        qualifiers.append(f"to {destination}")
    suffix = f" {' '.join(qualifiers)}" if qualifiers else ""
    return f"{str(action).title()} {resource}{suffix}"


@dataclass(frozen=True, slots=True)
class RichRuleRow:
    zone: str
    summary: str
    runtime: bool
    permanent: bool
    rule: RichRule

    def __post_init__(self) -> None:
        object.__setattr__(self, "zone", validate_inventory_token("zone", self.zone))
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise TypeError("summary must be a nonempty string")
        if type(self.runtime) is not bool or type(self.permanent) is not bool:
            raise TypeError("runtime and permanent must be booleans")
        if not self.runtime and not self.permanent:
            raise ValueError("a rich-rule row must exist in runtime or permanent")
        validate_structured_rule(self.rule)

    @property
    def supported(self) -> bool:
        return validate_structured_rule(self.rule) is not None


@dataclass(frozen=True, slots=True)
class RichRuleRequest:
    zone: str
    source: str | None
    destination: str | None
    service: str | None
    port: str | None
    protocol: str | None
    action: str
    target: ApplyTarget

    def __post_init__(self) -> None:
        object.__setattr__(self, "zone", validate_inventory_token("zone", self.zone))
        source = _optional_network(self.source)
        destination = _optional_network(self.destination)
        _family(source, destination)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "destination", destination)
        if (self.service is None) == (self.port is None):
            raise InvalidFirewallArgumentError(
                "rich rule", "requires exactly one of service or port"
            )
        if self.service is not None:
            if self.protocol is not None:
                raise InvalidFirewallArgumentError(
                    "rich rule", "does not allow protocol with a service"
                )
            object.__setattr__(
                self, "service", validate_inventory_token("service", self.service)
            )
        else:
            if self.protocol is None:
                raise InvalidFirewallArgumentError(
                    "rich rule", "requires protocol with a port"
                )
            object.__setattr__(self, "port", validate_port(self.port))
            object.__setattr__(self, "protocol", validate_protocol(self.protocol))
        object.__setattr__(self, "action", validate_rich_action(self.action))
        if not isinstance(self.target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")

    def structured_rule(self) -> RichRule:
        clauses = ["rule"]
        family = _family(self.source, self.destination)
        if family is not None:
            clauses.append(f'family="{family}"')
        if self.source is not None:
            clauses.append(f'source address="{self.source}"')
        if self.destination is not None:
            clauses.append(f'destination address="{self.destination}"')
        if self.service is not None:
            clauses.append(f'service name="{self.service}"')
        else:
            clauses.append(
                f'port port="{self.port}" protocol="{self.protocol}"'
            )
        clauses.append(self.action)
        return RichRule(
            " ".join(clauses),
            source=self.source,
            destination=self.destination,
            service=self.service,
            port=self.port,
            protocol=self.protocol,
            action=self.action,
            family=family,
        )


__all__ = [
    "RichRuleRequest",
    "RichRuleRow",
    "structured_rule_summary",
    "validate_structured_rule",
]
