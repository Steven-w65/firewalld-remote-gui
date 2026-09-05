"""Immutable validated values for firewall service presentation and intentions."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import ApplyTarget
from app.utils.validation import validate_inventory_token


@dataclass(frozen=True, slots=True)
class ServiceRow:
    """One exact service merged across runtime and permanent inventories."""

    name: str
    zone: str
    runtime: bool
    permanent: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "name", validate_inventory_token("service", self.name)
        )
        object.__setattr__(
            self, "zone", validate_inventory_token("zone", self.zone)
        )
        if type(self.runtime) is not bool or type(self.permanent) is not bool:
            raise TypeError("runtime and permanent must be booleans")
        if not self.runtime and not self.permanent:
            raise ValueError("a service row must exist in runtime or permanent")


@dataclass(frozen=True, slots=True)
class AddServiceRequest:
    """A validated add-service intention independent of GUI widgets."""

    zone: str
    service: str
    target: ApplyTarget

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "zone", validate_inventory_token("zone", self.zone)
        )
        object.__setattr__(
            self, "service", validate_inventory_token("service", self.service)
        )
        if not isinstance(self.target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")


__all__ = ["AddServiceRequest", "ServiceRow"]
