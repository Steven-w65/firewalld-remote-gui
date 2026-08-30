"""Private mutable server sessions and immutable GUI-safe views."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.config.models import ServerConfig
from app.models.enums import ConnectionStatus
from app.models.firewall import FirewallSnapshot


@dataclass(frozen=True, slots=True)
class ServerSessionView:
    """A frozen, credential-free copy of one server's visible state."""

    server_id: str
    name: str
    host: str
    port: int
    username: str
    sudo_enabled: bool
    generation: int
    status: ConnectionStatus
    snapshot: FirewallSnapshot | None
    latest_error: str | None
    busy_operation: str | None


@dataclass(slots=True)
class ServerSession:
    """Mutable controller-owned state; never hand this object to widgets."""

    config: ServerConfig = field(repr=False)
    generation: int = 0
    status: ConnectionStatus = ConnectionStatus.DISCONNECTED
    snapshot: FirewallSnapshot | None = None
    latest_error: str | None = field(default=None, repr=False)
    sudo_password: str | None = field(default=None, repr=False)
    busy_operation: str | None = None
    _ssh_manager: Any | None = field(default=None, repr=False)
    _service: Any | None = field(default=None, repr=False)
    _connection_attempt: Any | None = field(default=None, repr=False)

    def view(self) -> ServerSessionView:
        """Copy only immutable, credential-free values for presentation."""
        return ServerSessionView(
            server_id=self.config.id,
            name=self.config.name,
            host=self.config.host,
            port=self.config.port,
            username=self.config.username,
            sudo_enabled=self.config.sudo,
            generation=self.generation,
            status=self.status,
            snapshot=self.snapshot,
            latest_error=self.latest_error,
            busy_operation=self.busy_operation,
        )
