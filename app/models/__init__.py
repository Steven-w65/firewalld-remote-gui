"""Immutable value objects shared by the configuration, backend, and UI layers."""

from .command import CommandResult, CommandSpec, CompositeOperationResult, TargetResult
from .enums import ApplyTarget, ConnectionStatus, TargetStatus
from .firewall import FirewallPort, FirewallSnapshot, InterfaceAssignment, RichRule, ZoneState
from .interface import ChangeInterfaceRequest, InterfaceRow
from .port import AddPortRequest, PortRow
from .service import AddServiceRequest, ServiceRow

__all__ = [
    "ApplyTarget",
    "AddPortRequest",
    "AddServiceRequest",
    "CommandResult",
    "CommandSpec",
    "CompositeOperationResult",
    "ConnectionStatus",
    "ChangeInterfaceRequest",
    "FirewallPort",
    "FirewallSnapshot",
    "InterfaceAssignment",
    "InterfaceRow",
    "PortRow",
    "RichRule",
    "ServiceRow",
    "TargetResult",
    "TargetStatus",
    "ZoneState",
]
