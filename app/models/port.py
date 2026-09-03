"""Immutable validated values for port presentation and intentions."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import ApplyTarget
from app.utils.validation import (
    validate_inventory_token,
    validate_port,
    validate_protocol,
)


@dataclass(frozen=True, slots=True)
class PortRow:
    """One merged runtime/permanent port row safe for GUI consumption."""

    port: str
    protocol: str
    zone: str
    runtime: bool
    permanent: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "port", validate_port(self.port))
        object.__setattr__(self, "protocol", validate_protocol(self.protocol))
        object.__setattr__(self, "zone", validate_inventory_token("zone", self.zone))
        if type(self.runtime) is not bool or type(self.permanent) is not bool:
            raise TypeError("runtime and permanent must be booleans")
        if not self.runtime and not self.permanent:
            raise ValueError("a port row must exist in runtime or permanent")


@dataclass(frozen=True, slots=True)
class AddPortRequest:
    """A validated add-port intention independent of GUI widgets."""

    zone: str
    port: str
    protocol: str
    target: ApplyTarget

    def __post_init__(self) -> None:
        object.__setattr__(self, "zone", validate_inventory_token("zone", self.zone))
        object.__setattr__(self, "port", validate_port(self.port))
        object.__setattr__(self, "protocol", validate_protocol(self.protocol))
        if not isinstance(self.target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")


__all__ = ["AddPortRequest", "PortRow"]
