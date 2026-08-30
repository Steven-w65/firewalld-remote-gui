"""Immutable, GUI-independent previews for confirmed firewall changes."""

from __future__ import annotations

from dataclasses import dataclass

from app.firewalld.lockout import LockoutRisk
from app.models.enums import ApplyTarget


@dataclass(frozen=True, slots=True)
class ChangePreview:
    """Exact user-facing description of one validated firewall intention."""

    server_name: str
    host: str
    operation: str
    zone: str
    resource: str
    target: ApplyTarget
    risk: LockoutRisk

    def __post_init__(self) -> None:
        for field_name in ("server_name", "host", "operation", "zone", "resource"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise TypeError(f"{field_name} must be a nonempty string")
        if not isinstance(self.target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        if not isinstance(self.risk, LockoutRisk):
            raise TypeError("risk must be a LockoutRisk")


__all__ = ["ChangePreview"]
