"""Immutable value objects shared by the configuration, backend, and UI layers."""

from .command import CommandResult, CommandSpec, CompositeOperationResult, TargetResult
from .enums import ApplyTarget, ConnectionStatus, TargetStatus
from .firewall import FirewallPort, FirewallSnapshot, InterfaceAssignment, RichRule, ZoneState

__all__ = [
    "ApplyTarget",
    "CommandResult",
    "CommandSpec",
    "CompositeOperationResult",
    "ConnectionStatus",
    "FirewallPort",
    "FirewallSnapshot",
    "InterfaceAssignment",
    "RichRule",
    "TargetResult",
    "TargetStatus",
    "ZoneState",
]
