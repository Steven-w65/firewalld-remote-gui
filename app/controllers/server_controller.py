"""Qt-thread orchestration for isolated remote-server sessions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from threading import Event, Lock
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
    ConfigurationError,
    FirewallCommandError,
    FirewallParseError,
    FirewalldNotInstalledError,
    FirewalldNotRunningError,
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

    def wait_for_done(self, timeout_ms: int = -1) -> bool: ...


ManagerFactory = Callable[[ServerConfig, ApplicationConfig], _Manager]
ServiceFactory = Callable[[_Manager, str], _Service]


@dataclass(frozen=True, slots=True)
class SudoPasswordRequest:
    """Credential-free request identifying one resumable logical operation."""

    server_id: str
    generation: int
    operation: str


@dataclass(frozen=True, slots=True)
class ControllerOperationError:
    """A fixed, credential-free controller failure payload."""

    server_id: str
    operation: str
    category: str
    message: str


class ControllerJobHandle(QObject):
    """Public lifecycle facade that never owns scheduler work or resources."""

    started = Signal(str, int, str)
    succeeded = Signal(str, int, str, object)
    failed = Signal(str, int, str, object)
    finished = Signal(str, int, str)

    def __init__(self, server_id: str, generation: int, operation: str) -> None:
        super().__init__()
        self.server_id = server_id
        self.generation = generation
        self.operation = operation


class _ConnectionInvalidated(RuntimeError):
    """Private worker control flow; never published through the facade."""


class _ConnectionAttempt:
    """Synchronize invalidation with worker resource ownership."""

    def __init__(self) -> None:
        self._invalidated = Event()
        self._lock = Lock()
        self._manager: _Manager | None = None
        self._worker_finished = False
        self._close_claimed = False

    def register_manager(self, manager: _Manager) -> None:
        with self._lock:
            self._manager = manager

    def is_invalidated(self) -> bool:
        return self._invalidated.is_set()

    def commit_success(self) -> bool:
        """Return false when this worker must close instead of returning."""
        with self._lock:
            self._worker_finished = True
            if not self._invalidated.is_set():
                return True
            self._close_claimed = True
            return False

    def claim_failure_close(self) -> _Manager | None:
        with self._lock:
            self._worker_finished = True
            if self._manager is None or self._close_claimed:
                return None
            self._close_claimed = True
            return self._manager

    def invalidate(self) -> _Manager | None:
        """Invalidate first; claim a manager only after its worker returned."""
        self._invalidated.set()
        with self._lock:
            if (
                not self._worker_finished
                or self._manager is None
                or self._close_claimed
            ):
                return None
            self._close_claimed = True
            return self._manager


class _ManagerCloseToken:
    """Retain one detached manager until one worker closes it exactly once."""

    def __init__(self, server_id: str, manager: _Manager) -> None:
        self.server_id = server_id
        self.manager_identity = id(manager)
        self._manager: _Manager | None = manager
        self._lock = Lock()
        self._state = "open"

    def close_once(self) -> bool:
        with self._lock:
            if self._state != "open":
                return False
            self._state = "closing"
            manager = self._manager
        try:
            if manager is not None:
                manager.disconnect()
        finally:
            with self._lock:
                self._manager = None
                self._state = "closed"
        return True

    def is_open(self) -> bool:
        with self._lock:
            return self._state != "closed"

    def is_closed(self) -> bool:
        with self._lock:
            return self._state == "closed"


@dataclass(frozen=True, slots=True)
class _ConnectedResources:
    manager: _Manager
    service: _Service
    snapshot: FirewallSnapshot
    attempt: _ConnectionAttempt


@dataclass(slots=True)
class _PublicJobRecord:
    internal: JobHandle[Any]
    public: ControllerJobHandle


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
        self._jobs: dict[tuple[str, int, str], _PublicJobRecord] = {}
        self._private_close_handles: set[JobHandle[Any]] = set()
        self._close_token_lock = Lock()
        self._close_tokens: dict[str, dict[int, _ManagerCloseToken]] = {}

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

    def connect(self, server_id: str) -> ControllerJobHandle:
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
        attempt = _ConnectionAttempt()
        session._connection_attempt = attempt
        self.session_changed.emit(server_id)
        return self._submit_connection(
            session,
            "connect",
            tokens_to_close=(),
            attempt=attempt,
        )

    def disconnect(self, server_id: str) -> ControllerJobHandle:
        session = self._session(server_id)
        if session.status is ConnectionStatus.DISCONNECTED:
            raise RuntimeError(f"Cannot disconnect server '{server_id}' while disconnected.")
        attempt_manager = self._invalidate_attempt(session)
        manager = cast(_Manager | None, session._ssh_manager)
        self._register_close_tokens(server_id, manager, attempt_manager)
        generation = self._advance_generation(session)
        self._scheduler.cancel_pending(server_id)
        self._detach(session, clear_snapshot=True)
        session.status = ConnectionStatus.DISCONNECTED
        session.busy_operation = "disconnect"
        self.session_changed.emit(server_id)
        tokens = self._open_close_tokens(server_id)
        return self._submit(
            server_id,
            generation,
            "disconnect",
            lambda: self._close_token_batch(tokens),
        )

    def reconnect(self, server_id: str) -> ControllerJobHandle:
        session = self._session(server_id)
        self._require_state(
            session,
            "reconnect",
            set(ConnectionStatus) - {ConnectionStatus.DISCONNECTED},
            require_idle=True,
        )
        attempt_manager = self._invalidate_attempt(session)
        old_manager = cast(_Manager | None, session._ssh_manager)
        self._register_close_tokens(server_id, old_manager, attempt_manager)
        self._advance_generation(session)
        self._scheduler.cancel_pending(server_id)
        self._detach(session, clear_snapshot=True)
        session.status = ConnectionStatus.CONNECTING
        session.busy_operation = "reconnect"
        attempt = _ConnectionAttempt()
        session._connection_attempt = attempt
        self.session_changed.emit(server_id)
        return self._submit_connection(
            session,
            "reconnect",
            tokens_to_close=self._open_close_tokens(server_id),
            attempt=attempt,
        )

    def refresh(self, server_id: str) -> ControllerJobHandle:
        session = self._live_idle_session(server_id, "refresh")
        service = cast(_Service, session._service)
        sudo_password = session.sudo_password
        return self._start_service_job(
            session,
            "refresh",
            lambda: service.load_snapshot(sudo_password=sudo_password),
        )

    def test_connection(self, server_id: str) -> ControllerJobHandle:
        session = self._live_idle_session(server_id, "test_connection")
        service = cast(_Service, session._service)
        sudo_password = session.sudo_password
        return self._start_service_job(
            session,
            "test_connection",
            lambda: service.connection_test(sudo_password=sudo_password),
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
            attempt_manager = self._invalidate_attempt(old)
            manager = cast(_Manager | None, old._ssh_manager)
            self._register_close_tokens(server_id, manager, attempt_manager)
            generation = self._advance_generation(old)
            self._scheduler.cancel_pending(server_id)
            self._detach(old, clear_snapshot=True)
            tokens = self._open_close_tokens(server_id)
            if tokens:
                operation = (
                    "close_replaced_session"
                    if server_id in diff.changed
                    else "close_removed_session"
                )
                self._submit_close(server_id, generation, operation, tokens)

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

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        """Invalidate, queue closure, and boundedly drain remote work."""
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int):
            raise TypeError("timeout_ms must be an integer")
        if timeout_ms < 0:
            raise ValueError("timeout_ms must be non-negative")
        for server_id in self._order:
            session = self._sessions[server_id]
            attempt_manager = self._invalidate_attempt(session)
            manager = cast(_Manager | None, session._ssh_manager)
            self._register_close_tokens(server_id, manager, attempt_manager)
            generation = self._advance_generation(session)
            self._scheduler.cancel_pending(server_id)
            self._detach(session, clear_snapshot=True)
            session.status = ConnectionStatus.DISCONNECTED
            tokens = self._open_close_tokens(server_id)
            if tokens:
                self._submit_close(
                    server_id,
                    generation,
                    "shutdown_disconnect",
                    tokens,
                )
        active_ids = set(self._order)
        for server_id in sorted(self._close_token_server_ids() - active_ids):
            self._scheduler.cancel_pending(server_id)
            tokens = self._open_close_tokens(server_id)
            if tokens:
                self._submit_close(
                    server_id,
                    self._generations.get(server_id, 0),
                    "shutdown_disconnect",
                    tokens,
                )
        self.sessions_changed.emit()
        drained = self._scheduler.wait_for_done(timeout_ms)
        all_closed = not self._open_close_tokens()
        self._jobs.clear()
        self._private_close_handles.clear()
        return drained and all_closed

    def _submit_connection(
        self,
        session: ServerSession,
        operation: str,
        tokens_to_close: tuple[_ManagerCloseToken, ...],
        attempt: _ConnectionAttempt,
    ) -> ControllerJobHandle:
        server = session.config
        application = self._loaded.application
        sudo_password = session.sudo_password

        def work() -> _ConnectedResources:
            self._close_token_batch(tokens_to_close)
            try:
                if attempt.is_invalidated():
                    raise _ConnectionInvalidated()
                manager = self._manager_factory(server, application)
                attempt.register_manager(manager)
                if attempt.is_invalidated():
                    raise _ConnectionInvalidated()
                manager.connect()
                if attempt.is_invalidated():
                    raise _ConnectionInvalidated()
                service = self._service_factory(manager, server.id)
                if attempt.is_invalidated():
                    raise _ConnectionInvalidated()
                snapshot = service.load_snapshot(sudo_password=sudo_password)
                if not isinstance(snapshot, FirewallSnapshot):
                    raise TypeError("service must return FirewallSnapshot")
                if not attempt.commit_success():
                    manager.disconnect()
                    raise _ConnectionInvalidated()
                return _ConnectedResources(manager, service, snapshot, attempt)
            except Exception:
                manager_to_close = attempt.claim_failure_close()
                if manager_to_close is not None:
                    manager_to_close.disconnect()
                raise

        return self._submit(server.id, session.generation, operation, work)

    def _start_service_job(
        self, session: ServerSession, operation: str, work: Callable[[], Any]
    ) -> ControllerJobHandle:
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
    ) -> ControllerJobHandle:
        key = (server_id, generation, operation)
        if key in self._jobs:
            raise RuntimeError("A controller operation with this identity already exists.")
        internal = self._scheduler.submit(server_id, generation, operation, work)
        public = ControllerJobHandle(server_id, generation, operation)
        self._jobs[key] = _PublicJobRecord(internal=internal, public=public)
        queued = Qt.ConnectionType.QueuedConnection
        internal.started.connect(self._on_started, queued)
        internal.succeeded.connect(self._on_succeeded, queued)
        internal.failed.connect(self._on_failed, queued)
        internal.finished.connect(self._on_finished, queued)
        return public

    def _submit_close(
        self,
        server_id: str,
        generation: int,
        operation: str,
        tokens: tuple[_ManagerCloseToken, ...],
    ) -> JobHandle[Any]:
        handle = self._scheduler.submit(
            server_id,
            generation,
            operation,
            lambda: self._close_token_batch(tokens),
        )
        self._private_close_handles.add(handle)
        handle.finished.connect(
            lambda completed_server_id, completed_generation, completed_operation: (
                self._private_close_handles.discard(handle)
            ),
            Qt.ConnectionType.QueuedConnection,
        )
        return handle

    @Slot(str, int, str)
    def _on_started(
        self, server_id: str, generation: int, operation: str
    ) -> None:
        record = self._jobs.get((server_id, generation, operation))
        if record is None:
            return
        if not self._is_current(server_id, generation):
            return
        session = self._sessions[server_id]
        if session.busy_operation != operation:
            return
        record.public.started.emit(server_id, generation, operation)

    @Slot(str, int, str, object)
    def _on_succeeded(
        self,
        server_id: str,
        generation: int,
        operation: str,
        value: object,
    ) -> None:
        record = self._jobs.get((server_id, generation, operation))
        if record is None:
            return
        if not self._is_current(server_id, generation):
            if isinstance(value, _ConnectedResources):
                manager = value.attempt.invalidate()
                current_generation = (
                    self._sessions[server_id].generation
                    if server_id in self._sessions
                    else generation + 1
                )
                if manager is not None:
                    self._register_close_tokens(server_id, manager)
                    self._submit_close(
                        server_id,
                        current_generation,
                        "discard_stale_connection",
                        self._open_close_tokens(server_id),
                    )
            return
        session = self._sessions[server_id]
        if session.busy_operation != operation:
            return
        public_value: object = None
        if operation in {"connect", "reconnect"}:
            if not isinstance(value, _ConnectedResources):
                public_error = self._apply_failure(
                    session, operation, TypeError("connection returned invalid state")
                )
                record.public.failed.emit(
                    server_id, generation, operation, public_error
                )
                return
            session._ssh_manager = value.manager
            session._service = value.service
            session._connection_attempt = None
            session.snapshot = value.snapshot
            session.status = ConnectionStatus.CONNECTED
            session.latest_error = None
            self.session_changed.emit(server_id)
            public_value = session.view()
        elif operation == "refresh":
            if not isinstance(value, FirewallSnapshot):
                public_error = self._apply_failure(
                    session, operation, TypeError("refresh returned invalid state")
                )
                record.public.failed.emit(
                    server_id, generation, operation, public_error
                )
                return
            session.snapshot = value
            session.latest_error = None
            self.session_changed.emit(server_id)
            public_value = value
        elif operation == "test_connection":
            if not isinstance(value, ConnectionTestResult):
                public_error = self._apply_failure(
                    session,
                    operation,
                    TypeError("connection test returned invalid state"),
                )
                record.public.failed.emit(
                    server_id, generation, operation, public_error
                )
                return
            session.latest_error = None
            public_value = value
        record.public.succeeded.emit(
            server_id, generation, operation, public_value
        )

    @Slot(str, int, str, object)
    def _on_failed(
        self,
        server_id: str,
        generation: int,
        operation: str,
        error: object,
    ) -> None:
        record = self._jobs.get((server_id, generation, operation))
        if record is None:
            return
        if not self._is_current(server_id, generation):
            return
        session = self._sessions[server_id]
        if session.busy_operation != operation:
            return
        public_error = self._apply_failure(session, operation, error)
        record.public.failed.emit(server_id, generation, operation, public_error)

    @Slot(str, int, str)
    def _on_finished(
        self, server_id: str, generation: int, operation: str
    ) -> None:
        record = self._jobs.pop((server_id, generation, operation), None)
        if self._is_current(server_id, generation):
            session = self._sessions[server_id]
            if session.busy_operation == operation:
                session.busy_operation = None
                self.session_changed.emit(server_id)
        if record is not None:
            record.public.finished.emit(server_id, generation, operation)

    def _apply_failure(
        self, session: ServerSession, operation: str, error: object
    ) -> ControllerOperationError:
        public_error = self._public_error(session.config.id, operation, error)
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

        if operation in {"connect", "reconnect"}:
            session._connection_attempt = None

        if operation == "refresh" and session.snapshot is not None:
            session.snapshot = replace(session.snapshot, stale=True)
        if isinstance(error, SSHConnectionError) and session._ssh_manager is not None:
            manager = cast(_Manager, session._ssh_manager)
            self._register_close_tokens(session.config.id, manager)
            session._ssh_manager = None
            session._service = None
            session.sudo_password = None
            self._submit_close(
                session.config.id,
                session.generation,
                "close_failed_connection",
                self._open_close_tokens(session.config.id),
            )
        session.latest_error = public_error.message
        self.error_raised.emit(session.config.id, public_error)
        self.session_changed.emit(session.config.id)
        return public_error

    @staticmethod
    def _public_error(
        server_id: str, operation: str, error: object
    ) -> ControllerOperationError:
        if isinstance(error, UnknownHostKeyError):
            category, message = "host_key_required", "SSH host key confirmation is required."
        elif isinstance(error, ChangedHostKeyError):
            category, message = "host_key_changed", "The SSH host key has changed."
        elif isinstance(error, SSHAuthenticationError):
            category, message = "ssh_authentication", "SSH authentication failed."
        elif isinstance(error, SudoAuthenticationError):
            category, message = "sudo_authentication", "Sudo authentication failed."
        elif isinstance(error, SudoAuthenticationRequiredError):
            category, message = "sudo_required", "Sudo authentication is required."
        elif isinstance(error, PermissionDeniedError):
            category, message = "permission", "The remote operation was not authorized."
        elif isinstance(error, FirewalldNotInstalledError):
            category, message = "firewalld_missing", "Firewalld is not installed."
        elif isinstance(error, FirewalldNotRunningError):
            category, message = "firewalld_stopped", "Firewalld is not running."
        elif isinstance(error, SSHError):
            category, message = "ssh", "The SSH operation failed."
        elif isinstance(error, FirewallParseError):
            category, message = "firewalld_output", "Firewalld returned invalid output."
        elif isinstance(error, FirewallCommandError):
            category, message = "firewalld", "The firewalld operation failed."
        elif isinstance(error, SystemProbeError):
            category, message = "system_probe", "The remote system probe failed."
        else:
            category, message = "operation", "The remote operation failed."
        return ControllerOperationError(server_id, operation, category, message)

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

    @staticmethod
    def _invalidate_attempt(session: ServerSession) -> _Manager | None:
        attempt = cast(_ConnectionAttempt | None, session._connection_attempt)
        session._connection_attempt = None
        return None if attempt is None else attempt.invalidate()

    def _register_close_tokens(
        self, server_id: str, *managers: _Manager | None
    ) -> tuple[_ManagerCloseToken, ...]:
        registered: list[_ManagerCloseToken] = []
        with self._close_token_lock:
            server_tokens = self._close_tokens.setdefault(server_id, {})
            for manager in managers:
                if manager is None:
                    continue
                identity = id(manager)
                token = server_tokens.get(identity)
                if token is None or token.is_closed():
                    token = _ManagerCloseToken(server_id, manager)
                    server_tokens[identity] = token
                if token not in registered:
                    registered.append(token)
            if not server_tokens:
                self._close_tokens.pop(server_id, None)
        return tuple(registered)

    def _open_close_tokens(
        self, server_id: str | None = None
    ) -> tuple[_ManagerCloseToken, ...]:
        with self._close_token_lock:
            if server_id is not None:
                tokens = tuple(self._close_tokens.get(server_id, {}).values())
            else:
                tokens = tuple(
                    token
                    for server_tokens in self._close_tokens.values()
                    for token in server_tokens.values()
                )
        return tuple(token for token in tokens if token.is_open())

    def _close_token_server_ids(self) -> set[str]:
        with self._close_token_lock:
            return set(self._close_tokens)

    def _close_token_batch(
        self, tokens: tuple[_ManagerCloseToken, ...]
    ) -> None:
        first_error: Exception | None = None
        for token in tokens:
            try:
                token.close_once()
            except Exception as error:
                if first_error is None:
                    first_error = error
            finally:
                if token.is_closed():
                    self._release_close_token(token)
        if first_error is not None:
            raise first_error

    def _release_close_token(self, token: _ManagerCloseToken) -> None:
        with self._close_token_lock:
            server_tokens = self._close_tokens.get(token.server_id)
            if server_tokens is None:
                return
            if server_tokens.get(token.manager_identity) is token:
                del server_tokens[token.manager_identity]
            if not server_tokens:
                del self._close_tokens[token.server_id]

    def _is_current(self, server_id: str, generation: int) -> bool:
        session = self._sessions.get(server_id)
        return session is not None and session.generation == generation

    @staticmethod
    def _detach(session: ServerSession, *, clear_snapshot: bool) -> None:
        session._ssh_manager = None
        session._service = None
        session._connection_attempt = None
        session.sudo_password = None
        session.latest_error = None
        session.busy_operation = None
        if clear_snapshot:
            session.snapshot = None
