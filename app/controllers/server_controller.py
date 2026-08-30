"""Qt-thread orchestration for isolated remote-server sessions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any, Protocol, cast

from PySide6.QtCore import QObject, Qt, Signal, Slot

from app.config.config_manager import ConfigManager
from app.config.models import ApplicationConfig, ConfigDiff, LoadedConfig, ServerConfig
from app.controllers.session import ServerSession, ServerSessionView
from app.firewalld.service import ConnectionTestResult, FirewalldService
from app.models.enums import ConnectionStatus
from app.models.firewall import FirewallSnapshot
from app.utils.errors import (
    ChangedHostKeyError,
    CommandTimeoutError,
    ConfigurationError,
    FirewallCommandError,
    FirewallParseError,
    FirewalldNotInstalledError,
    FirewalldNotRunningError,
    HostKeyStoreError,
    InvalidHostTokenError,
    PermissionDeniedError,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHError,
    SudoAuthenticationError,
    SudoAuthenticationRequiredError,
    SystemProbeError,
    UnknownHostKeyError,
)
from app.workers.scheduler import JobHandle


class _ConfigLoader(Protocol):
    def load(self) -> LoadedConfig: ...


class _Manager(Protocol):
    def connect(self) -> None: ...

    def disconnect(self) -> None: ...


class _Service(Protocol):
    def load_snapshot(
        self, *, sudo_password: str | None = None
    ) -> FirewallSnapshot: ...

    def connection_test(
        self, *, sudo_password: str | None = None
    ) -> ConnectionTestResult: ...


class _Scheduler(Protocol):
    def submit(
        self,
        server_id: str,
        generation: int,
        operation: str,
        work: Callable[[], Any],
    ) -> JobHandle[Any]: ...

    def cancel_pending(self, server_id: str) -> None: ...


ManagerFactory = Callable[[ServerConfig, ApplicationConfig], _Manager]
ServiceFactory = Callable[[_Manager, str], _Service]


@dataclass(frozen=True, slots=True)
class SudoPasswordRequest:
    """Credential-free request identifying one resumable logical operation."""

    server_id: str
    generation: int
    operation: str


@dataclass(frozen=True, slots=True)
class _ConnectedResources:
    manager: _Manager
    service: _Service
    snapshot: FirewallSnapshot


_KNOWN_SAFE_ERRORS = (
    ChangedHostKeyError,
    CommandTimeoutError,
    ConfigurationError,
    FirewallCommandError,
    FirewallParseError,
    HostKeyStoreError,
    InvalidHostTokenError,
    SSHError,
    SystemProbeError,
    UnknownHostKeyError,
)


class ServerController(QObject):
    """Own isolated mutable sessions while publishing frozen state copies."""

    sessions_changed = Signal()
    selection_changed = Signal(str)
    session_changed = Signal(str)
    host_key_required = Signal(str, object)
    sudo_password_required = Signal(str, object)
    error_raised = Signal(str, object)

    def __init__(
        self,
        config_manager: _ConfigLoader,
        scheduler: _Scheduler,
        manager_factory: ManagerFactory,
        service_factory: ServiceFactory = FirewalldService,
    ) -> None:
        super().__init__()
        self._config_manager = config_manager
        self._scheduler = scheduler
        self._manager_factory = manager_factory
        self._service_factory = service_factory
        self._loaded = config_manager.load()
        self._sessions: dict[str, ServerSession] = {
            config.id: ServerSession(config=config)
            for config in self._loaded.servers
        }
        self._generations = {config.id: 0 for config in self._loaded.servers}
        self._order = tuple(config.id for config in self._loaded.servers)
        self._selected_server_id = self._order[0] if self._order else None

    @property
    def selected_server_id(self) -> str | None:
        return self._selected_server_id

    @property
    def application_config(self) -> ApplicationConfig:
        return self._loaded.application

    def sessions(self) -> tuple[ServerSessionView, ...]:
        return tuple(self._sessions[server_id].view() for server_id in self._order)

    def session_view(self, server_id: str) -> ServerSessionView:
        return self._session(server_id).view()

    def select(self, server_id: str) -> None:
        self._session(server_id)
        if self._selected_server_id == server_id:
            return
        self._selected_server_id = server_id
        self.selection_changed.emit(server_id)

    def provide_sudo_password(
        self, server_id: str, generation: int, password: str
    ) -> bool:
        """Cache a submitted password only for the matching active generation."""
        session = self._session(server_id)
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation != session.generation
            or not session.config.sudo
            or session.status is ConnectionStatus.DISCONNECTED
        ):
            return False
        if not isinstance(password, str) or not password:
            return False
        session.sudo_password = password
        return True

    def connect(self, server_id: str) -> JobHandle[_ConnectedResources]:
        session = self._session(server_id)
        allowed = {
            ConnectionStatus.DISCONNECTED,
            ConnectionStatus.AUTHENTICATION_FAILED,
            ConnectionStatus.CONNECTION_ERROR,
            ConnectionStatus.HOST_KEY_ERROR,
            ConnectionStatus.PERMISSION_ERROR,
            ConnectionStatus.FIREWALLD_NOT_INSTALLED,
            ConnectionStatus.FIREWALLD_NOT_RUNNING,
        }
        self._require_state(session, "connect", allowed, require_idle=True)
        if session._ssh_manager is not None or session._service is not None:
            raise RuntimeError(
                f"Cannot connect server '{server_id}' while it owns a live session; "
                "use reconnect."
            )
        session.status = ConnectionStatus.CONNECTING
        session.latest_error = None
        session.snapshot = None
        session.busy_operation = "connect"
        self.session_changed.emit(server_id)
        return cast(
            JobHandle[_ConnectedResources],
            self._submit_connection(session, "connect", manager_to_close=None),
        )

    def disconnect(self, server_id: str) -> JobHandle[None]:
        session = self._session(server_id)
        if session.status is ConnectionStatus.DISCONNECTED:
            raise RuntimeError(f"Cannot disconnect server '{server_id}' while disconnected.")
        manager = session._ssh_manager
        generation = self._advance_generation(session)
        self._scheduler.cancel_pending(server_id)
        self._detach(session, clear_snapshot=True)
        session.status = ConnectionStatus.DISCONNECTED
        session.busy_operation = "disconnect"
        self.session_changed.emit(server_id)
        return cast(
            JobHandle[None],
            self._submit(
                server_id,
                generation,
                "disconnect",
                (lambda: manager.disconnect()) if manager is not None else (lambda: None),
            ),
        )

    def reconnect(self, server_id: str) -> JobHandle[_ConnectedResources]:
        session = self._session(server_id)
        self._require_state(
            session,
            "reconnect",
            set(ConnectionStatus) - {ConnectionStatus.DISCONNECTED},
            require_idle=True,
        )
        old_manager = session._ssh_manager
        self._advance_generation(session)
        self._scheduler.cancel_pending(server_id)
        self._detach(session, clear_snapshot=True)
        session.status = ConnectionStatus.CONNECTING
        session.busy_operation = "reconnect"
        self.session_changed.emit(server_id)
        return cast(
            JobHandle[_ConnectedResources],
            self._submit_connection(session, "reconnect", old_manager),
        )

    def refresh(self, server_id: str) -> JobHandle[FirewallSnapshot]:
        session = self._live_idle_session(server_id, "refresh")
        service = cast(_Service, session._service)
        sudo_password = session.sudo_password
        return cast(
            JobHandle[FirewallSnapshot],
            self._start_service_job(
                session,
                "refresh",
                lambda: service.load_snapshot(sudo_password=sudo_password),
            ),
        )

    def test_connection(self, server_id: str) -> JobHandle[ConnectionTestResult]:
        session = self._live_idle_session(server_id, "test_connection")
        service = cast(_Service, session._service)
        sudo_password = session.sudo_password
        return cast(
            JobHandle[ConnectionTestResult],
            self._start_service_job(
                session,
                "test_connection",
                lambda: service.connection_test(sudo_password=sudo_password),
            ),
        )

    def reload_configuration(self) -> ConfigDiff | None:
        """Load then reconcile atomically; invalid input changes no session state."""
        try:
            loaded = self._config_manager.load()
        except ConfigurationError as error:
            self.error_raised.emit("", error)
            return None

        diff = ConfigManager.diff(self._loaded, loaded)
        old_sessions = self._sessions
        for server_id in (*diff.changed, *diff.removed):
            old = old_sessions[server_id]
            manager = old._ssh_manager
            generation = self._advance_generation(old)
            self._scheduler.cancel_pending(server_id)
            self._detach(old, clear_snapshot=True)
            if manager is not None:
                operation = (
                    "close_replaced_session"
                    if server_id in diff.changed
                    else "close_removed_session"
                )
                self._submit_close(server_id, generation, operation, manager)

        reconciled: dict[str, ServerSession] = {}
        for config in loaded.servers:
            if config.id in diff.unchanged:
                reconciled[config.id] = old_sessions[config.id]
            elif config.id in diff.changed:
                reconciled[config.id] = ServerSession(
                    config=config,
                    generation=old_sessions[config.id].generation,
                )
            else:
                reconciled[config.id] = ServerSession(
                    config=config,
                    generation=self._generation_for_added(config.id),
                )

        previous_selection = self._selected_server_id
        self._loaded = loaded
        self._sessions = reconciled
        self._order = tuple(config.id for config in loaded.servers)
        if previous_selection in reconciled:
            selected = previous_selection
        else:
            selected = self._order[0] if self._order else None
        self._selected_server_id = selected
        self.sessions_changed.emit()
        if selected != previous_selection:
            self.selection_changed.emit(selected or "")
        return diff

    def shutdown(self) -> tuple[JobHandle[None], ...]:
        """Invalidate every session and queue resource closure off the GUI thread."""
        handles: list[JobHandle[None]] = []
        for server_id in self._order:
            session = self._sessions[server_id]
            manager = session._ssh_manager
            generation = self._advance_generation(session)
            self._scheduler.cancel_pending(server_id)
            self._detach(session, clear_snapshot=True)
            session.status = ConnectionStatus.DISCONNECTED
            if manager is not None:
                handles.append(
                    cast(
                        JobHandle[None],
                        self._submit_close(
                            server_id, generation, "shutdown_disconnect", manager
                        ),
                    )
                )
        self.sessions_changed.emit()
        return tuple(handles)

    def _submit_connection(
        self,
        session: ServerSession,
        operation: str,
        manager_to_close: _Manager | None,
    ) -> JobHandle[Any]:
        server = session.config
        application = self._loaded.application
        sudo_password = session.sudo_password

        def work() -> _ConnectedResources:
            if manager_to_close is not None:
                manager_to_close.disconnect()
            manager = self._manager_factory(server, application)
            try:
                manager.connect()
                service = self._service_factory(manager, server.id)
                snapshot = service.load_snapshot(sudo_password=sudo_password)
                if not isinstance(snapshot, FirewallSnapshot):
                    raise TypeError("service must return FirewallSnapshot")
                return _ConnectedResources(manager, service, snapshot)
            except Exception:
                manager.disconnect()
                raise

        return self._submit(server.id, session.generation, operation, work)

    def _start_service_job(
        self, session: ServerSession, operation: str, work: Callable[[], Any]
    ) -> JobHandle[Any]:
        session.busy_operation = operation
        session.latest_error = None
        self.session_changed.emit(session.config.id)
        return self._submit(session.config.id, session.generation, operation, work)

    def _submit(
        self,
        server_id: str,
        generation: int,
        operation: str,
        work: Callable[[], Any],
    ) -> JobHandle[Any]:
        handle = self._scheduler.submit(server_id, generation, operation, work)
        queued = Qt.ConnectionType.QueuedConnection
        handle.started.connect(self._on_started, queued)
        handle.succeeded.connect(self._on_succeeded, queued)
        handle.failed.connect(self._on_failed, queued)
        handle.finished.connect(self._on_finished, queued)
        return handle

    def _submit_close(
        self,
        server_id: str,
        generation: int,
        operation: str,
        manager: _Manager,
    ) -> JobHandle[Any]:
        return self._scheduler.submit(
            server_id, generation, operation, manager.disconnect
        )

    @Slot(str, int, str)
    def _on_started(
        self, server_id: str, generation: int, operation: str
    ) -> None:
        if not self._is_current(server_id, generation):
            return
        session = self._sessions[server_id]
        if session.busy_operation != operation:
            return

    @Slot(str, int, str, object)
    def _on_succeeded(
        self,
        server_id: str,
        generation: int,
        operation: str,
        value: object,
    ) -> None:
        if not self._is_current(server_id, generation):
            if isinstance(value, _ConnectedResources):
                current_generation = (
                    self._sessions[server_id].generation
                    if server_id in self._sessions
                    else generation + 1
                )
                self._submit_close(
                    server_id,
                    current_generation,
                    "discard_stale_connection",
                    value.manager,
                )
            return
        session = self._sessions[server_id]
        if session.busy_operation != operation:
            return
        if operation in {"connect", "reconnect"}:
            if not isinstance(value, _ConnectedResources):
                self._apply_failure(
                    session, operation, TypeError("connection returned invalid state")
                )
                return
            session._ssh_manager = value.manager
            session._service = value.service
            session.snapshot = value.snapshot
            session.status = ConnectionStatus.CONNECTED
            session.latest_error = None
            self.session_changed.emit(server_id)
        elif operation == "refresh":
            if not isinstance(value, FirewallSnapshot):
                self._apply_failure(
                    session, operation, TypeError("refresh returned invalid state")
                )
                return
            session.snapshot = value
            session.latest_error = None
            self.session_changed.emit(server_id)
        elif operation == "test_connection":
            session.latest_error = None

    @Slot(str, int, str, object)
    def _on_failed(
        self,
        server_id: str,
        generation: int,
        operation: str,
        error: object,
    ) -> None:
        if not self._is_current(server_id, generation):
            return
        session = self._sessions[server_id]
        if session.busy_operation != operation:
            return
        actual = error if isinstance(error, Exception) else RuntimeError("Operation failed.")
        self._apply_failure(session, operation, actual)

    @Slot(str, int, str)
    def _on_finished(
        self, server_id: str, generation: int, operation: str
    ) -> None:
        if not self._is_current(server_id, generation):
            return
        session = self._sessions[server_id]
        if session.busy_operation != operation:
            return
        session.busy_operation = None
        self.session_changed.emit(server_id)

    def _apply_failure(
        self, session: ServerSession, operation: str, error: Exception
    ) -> None:
        public_error = self._public_error(session, error)
        if isinstance(error, (SSHAuthenticationError, SudoAuthenticationError)):
            session.sudo_password = None
        if isinstance(error, UnknownHostKeyError):
            session.status = ConnectionStatus.HOST_KEY_ERROR
            self.host_key_required.emit(session.config.id, error.challenge)
        elif isinstance(error, ChangedHostKeyError):
            session.status = ConnectionStatus.HOST_KEY_ERROR
        elif isinstance(error, SSHAuthenticationError):
            session.status = ConnectionStatus.AUTHENTICATION_FAILED
        elif isinstance(error, SudoAuthenticationRequiredError):
            session.status = ConnectionStatus.PERMISSION_ERROR
            request = SudoPasswordRequest(
                session.config.id, session.generation, error.operation
            )
            self.sudo_password_required.emit(session.config.id, request)
        elif isinstance(error, PermissionDeniedError):
            session.status = ConnectionStatus.PERMISSION_ERROR
        elif isinstance(error, FirewalldNotInstalledError):
            session.status = ConnectionStatus.FIREWALLD_NOT_INSTALLED
        elif isinstance(error, FirewalldNotRunningError):
            session.status = ConnectionStatus.FIREWALLD_NOT_RUNNING
        elif isinstance(error, SSHError):
            session.status = ConnectionStatus.CONNECTION_ERROR
        elif operation in {"connect", "reconnect"}:
            session.status = ConnectionStatus.CONNECTION_ERROR

        if operation == "refresh" and session.snapshot is not None:
            session.snapshot = replace(session.snapshot, stale=True)
        if isinstance(error, SSHConnectionError) and session._ssh_manager is not None:
            manager = cast(_Manager, session._ssh_manager)
            session._ssh_manager = None
            session._service = None
            session.sudo_password = None
            self._submit_close(
                session.config.id,
                session.generation,
                "close_failed_connection",
                manager,
            )
        session.latest_error = public_error
        self.error_raised.emit(session.config.id, public_error)
        self.session_changed.emit(session.config.id)

    def _public_error(self, session: ServerSession, error: Exception) -> Exception:
        if isinstance(error, _KNOWN_SAFE_ERRORS):
            return error
        message = str(error)
        for secret in (session.config.password, session.sudo_password):
            if secret:
                message = message.replace(secret, "[REDACTED]")
        return RuntimeError(message or "Operation failed.")

    def _live_idle_session(self, server_id: str, operation: str) -> ServerSession:
        session = self._session(server_id)
        self._require_state(
            session,
            operation,
            {ConnectionStatus.CONNECTED},
            require_idle=True,
        )
        if session._ssh_manager is None or session._service is None:
            raise RuntimeError(f"Server '{server_id}' has no live connection.")
        return session

    @staticmethod
    def _require_state(
        session: ServerSession,
        operation: str,
        allowed: set[ConnectionStatus],
        *,
        require_idle: bool,
    ) -> None:
        if session.status not in allowed:
            raise RuntimeError(
                f"Cannot {operation} server '{session.config.id}' from state "
                f"'{session.status.value}'."
            )
        if require_idle and session.busy_operation is not None:
            raise RuntimeError(
                f"Cannot {operation} server '{session.config.id}' while busy."
            )

    def _session(self, server_id: str) -> ServerSession:
        if not isinstance(server_id, str):
            raise TypeError("server_id must be a string")
        try:
            return self._sessions[server_id]
        except KeyError:
            raise KeyError(f"Unknown server id: {server_id}") from None

    def _advance_generation(self, session: ServerSession) -> int:
        server_id = session.config.id
        generation = self._generations.get(server_id, session.generation) + 1
        self._generations[server_id] = generation
        session.generation = generation
        return generation

    def _generation_for_added(self, server_id: str) -> int:
        if server_id not in self._generations:
            self._generations[server_id] = 0
            return 0
        generation = self._generations[server_id] + 1
        self._generations[server_id] = generation
        return generation

    def _is_current(self, server_id: str, generation: int) -> bool:
        session = self._sessions.get(server_id)
        return session is not None and session.generation == generation

    @staticmethod
    def _detach(session: ServerSession, *, clear_snapshot: bool) -> None:
        session._ssh_manager = None
        session._service = None
        session.sudo_password = None
        session.latest_error = None
        session.busy_operation = None
        if clear_snapshot:
            session.snapshot = None
