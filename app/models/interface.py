"""Immutable validated values for interface-zone presentation and intentions."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import ApplyTarget
from app.utils.validation import validate_inventory_token


@dataclass(frozen=True, slots=True)
class InterfaceRow:
    """One discovered interface merged across runtime and permanent snapshots."""

    name: str
    runtime_zone: str | None
    permanent_zone: str | None
    active: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "name", validate_inventory_token("interface", self.name)
        )
        for field_name in ("runtime_zone", "permanent_zone"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(
                    self, field_name, validate_inventory_token("zone", value)
                )
        if type(self.active) is not bool:
            raise TypeError("active must be a boolean")
        if self.runtime_zone is None and self.permanent_zone is None:
            raise ValueError("an interface row must have a snapshot assignment")


@dataclass(frozen=True, slots=True)
class ChangeInterfaceRequest:
    """One exact interface-zone change selected from snapshot inventory."""

    interface: str
    current_zone: str | None
    new_zone: str
    target: ApplyTarget

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "interface",
            validate_inventory_token("interface", self.interface),
        )
        if self.current_zone is not None:
            object.__setattr__(
                self,
                "current_zone",
                validate_inventory_token("zone", self.current_zone),
            )
        object.__setattr__(
            self, "new_zone", validate_inventory_token("zone", self.new_zone)
        )
        if not isinstance(self.target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        if self.current_zone == self.new_zone:
            raise ValueError("new_zone must differ from current_zone")


__all__ = ["ChangeInterfaceRequest", "InterfaceRow"]
