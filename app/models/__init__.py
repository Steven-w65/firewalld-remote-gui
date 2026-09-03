"""Immutable value objects shared by the configuration, backend, and UI layers."""

from .command import CommandResult, CommandSpec, CompositeOperationResult, TargetResult
from .enums import ApplyTarget, ConnectionStatus, TargetStatus
from .firewall import FirewallPort, FirewallSnapshot, InterfaceAssignment, RichRule, ZoneState
from .port import AddPortRequest, PortRow

__all__ = [
    "ApplyTarget",
    "AddPortRequest",
    "CommandResult",
    "CommandSpec",
    "CompositeOperationResult",
    "ConnectionStatus",
    "FirewallPort",
    "FirewallSnapshot",
    "InterfaceAssignment",
    "PortRow",
    "RichRule",
    "TargetResult",
    "TargetStatus",
    "ZoneState",
]
