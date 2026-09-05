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
from app.models.command import CompositeOperationResult
from app.models.enums import ApplyTarget, ConnectionStatus
from app.models.firewall import FirewallSnapshot
from app.utils.errors import (
    ChangedHostKeyError,
    ConfigurationError,
    FirewallCommandError,
    FirewallParseError,
    FirewalldNotInstalledError,
    FirewalldNotRunningError,
    HostKeyStoreError,
    PermissionDeniedError,
    PostMutationError,
    PostMutationRefreshError,
    PostMutationVerificationError,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHError,
    SudoAuthenticationError,
    SudoAuthenticationRequiredError,
    SystemProbeError,
    UnknownHostKeyError,
)
from app.utils.validation import (
    validate_inventory_token,
    validate_port,
    validate_protocol,
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

    def reload_firewalld(
        self,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult: ...

    def add_port(
        self,
        zone: str,
        port: str,
        protocol: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult: ...

    def remove_port(
        self,
        zone: str,
        port: str,
        protocol: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult: ...

    def add_service(
        self,
        zone: str,
        service: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult: ...

    def remove_service(
        self,
        zone: str,
        service: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult: ...

    def set_default_zone(
        self,
        zone: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult: ...

    def change_interface_zone(
        self,
        interface: str,
        zone: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult: ...


class _HostKeyStore(Protocol):
    def trust(self, challenge: object) -> None: ...


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


@dataclass(frozen=True, slots=True)
class _PendingHostKey:
    server_id: str
    generation: int
    operation: str
    challenge: object


@dataclass(frozen=True, slots=True)
class _PendingSudo:
    request: SudoPasswordRequest


@dataclass(frozen=True, slots=True)
class _PendingTrustedRetry:
    server_id: str
    generation: int
    operation: str
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class _PortChangeIntent:
    server_id: str
    generation: int
    operation: str
    zone: str
    port: str
    protocol: str
    target: ApplyTarget


@dataclass(frozen=True, slots=True)
class _DefaultZoneChangeIntent:
    server_id: str
    generation: int
    operation: str
    zone: str
    target: ApplyTarget


@dataclass(frozen=True, slots=True)
class _ServiceChangeIntent:
    server_id: str
    generation: int
    operation: str
    zone: str
    service: str
    target: ApplyTarget


@dataclass(frozen=True, slots=True)
class _InterfaceChangeIntent:
    server_id: str
    generation: int
    operation: str
    interface: str
    zone: str
    target: ApplyTarget


_FirewallChangeIntent = (
    _PortChangeIntent
    | _ServiceChangeIntent
    | _DefaultZoneChangeIntent
    | _InterfaceChangeIntent
)


@dataclass(frozen=True, slots=True)
class _FirewallMutationOutcome:
    result: CompositeOperationResult
    snapshot: FirewallSnapshot | None
    refresh_error: ControllerOperationError | None = None
    terminal_transport: bool = False
    clear_sudo: bool = False


@dataclass(slots=True)
class _LogicalFirewallJob:
    intent: _FirewallChangeIntent
    public: ControllerJobHandle
    attempt: ControllerJobHandle | None = None
    last_error: ControllerOperationError | None = None
    started_emitted: bool = False
    outcome_emitted: bool = False
    completed: bool = False


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
        *,
        host_key_store: _HostKeyStore | None = None,
    ) -> None:
        super().__init__()
        self._config_manager = config_manager
        self._scheduler = scheduler
        self._manager_factory = manager_factory
        self._service_factory = service_factory
        self._host_key_store = host_key_store
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
        self._pending_host_keys: dict[str, _PendingHostKey] = {}
        self._pending_sudo: dict[str, _PendingSudo] = {}
        self._pending_trusted_retries: dict[
            tuple[str, int, str], _PendingTrustedRetry
        ] = {}
        self._accepted_sudo_retries: set[SudoPasswordRequest] = set()
        self._sudo_retry_jobs: set[tuple[str, int, str]] = set()
        self._firewall_jobs: dict[tuple[str, int, str], _LogicalFirewallJob] = {}

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
        self._pending_trusted_retries.clear()
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

    def resolve_host_key(
        self,
        server_id: str,
        generation: int,
        challenge: object,
        confirmed: bool,
    ) -> bool:
        """Consume one exact unknown-key decision and reconnect only if trusted."""
        pending = self._pending_host_keys.get(server_id)
        if (
            pending is None
            or pending.generation != generation
            or pending.challenge is not challenge
        ):
            return False
        if not confirmed:
            self._pending_host_keys.pop(server_id, None)
            return False
        session = self._sessions.get(server_id)
        if (
            session is None
            or session.generation != generation
            or session.config.host != getattr(challenge, "host", None)
            or session.config.port != getattr(challenge, "port", None)
            or self._host_key_store is None
        ):
            self._pending_host_keys.pop(server_id, None)
            return False

        self._pending_host_keys.pop(server_id, None)
        try:
            self._host_key_store.trust(challenge)
        except Exception as error:
            self._apply_failure(session, pending.operation, error)
            return False
        retry = _PendingTrustedRetry(
            server_id,
            generation,
            pending.operation,
            session.config.host,
            session.config.port,
        )
        key = (server_id, generation, pending.operation)
        self._pending_trusted_retries[key] = retry
        if key not in self._jobs:
            self._launch_trusted_retry(key)
        return True

    def resolve_sudo_password(
        self, request: SudoPasswordRequest, password: str | None
    ) -> bool:
        """Consume one exact password request and retry its logical operation once."""
        if not isinstance(request, SudoPasswordRequest):
            return False
        pending = self._pending_sudo.get(request.server_id)
        if pending is None or pending.request is not request:
            return False
        session = self._sessions.get(request.server_id)
        if (
            session is None
            or session.generation != request.generation
            or not session.config.sudo
            or session.status is ConnectionStatus.DISCONNECTED
        ):
            self._pending_sudo.pop(request.server_id, None)
            self._cancel_firewall_job(request)
            return False
        if not isinstance(password, str) or not password:
            self._pending_sudo.pop(request.server_id, None)
            self._cancel_firewall_job(request)
            return False

        session.sudo_password = password
        self._pending_sudo.pop(request.server_id, None)
        key = (request.server_id, request.generation, request.operation)
        if key in self._jobs:
            self._accepted_sudo_retries.add(request)
        else:
            self._retry_sudo_operation(request)
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
        self._clear_pending_decisions(server_id)
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
        self._clear_pending_decisions(server_id)
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
        self._clear_pending_trusted_retries(server_id)
        self._require_state(
            session,
            "reconnect",
            set(ConnectionStatus) - {ConnectionStatus.DISCONNECTED},
            require_idle=True,
        )
        self._clear_pending_decisions(server_id)
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

    def reload_firewalld(self, server_id: str) -> ControllerJobHandle:
        """Run one confirmed global reload, then publish one fresh snapshot."""
        session = self._live_idle_session(server_id, "reload_firewalld")
        service = cast(_Service, session._service)
        sudo_password = session.sudo_password

        def work() -> FirewallSnapshot:
            result = service.reload_firewalld(
                ApplyTarget.BOTH,
                sudo_password=sudo_password,
            )
            if (
                not isinstance(result, CompositeOperationResult)
                or result.operation != "reload_firewalld"
                or not result.is_success
            ):
                raise FirewallCommandError(server_id, "reload_firewalld")
            post_mutation_error: PostMutationRefreshError | None = None
            try:
                snapshot = service.load_snapshot(sudo_password=sudo_password)
            except (SudoAuthenticationError, SudoAuthenticationRequiredError):
                post_mutation_error = PostMutationRefreshError(
                    server_id, "reload_firewalld"
                )
            if post_mutation_error is not None:
                raise post_mutation_error
            return snapshot

        return self._start_service_job(session, "reload_firewalld", work)

    def _schedule_port_change(
        self,
        server_id: str,
        generation: int,
        operation: str,
        zone: str,
        port: str,
        protocol: str,
        target: ApplyTarget,
    ) -> ControllerJobHandle:
        """Schedule one validated port intent without exposing live resources."""
        session = self._live_idle_session(server_id, operation)
        if generation != session.generation:
            raise RuntimeError("The server session changed before the port operation.")
        if operation not in {"add_port", "remove_port"}:
            raise ValueError("Unsupported port operation.")
        if not isinstance(target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        intent = _PortChangeIntent(
            server_id=server_id,
            generation=generation,
            operation=operation,
            zone=validate_inventory_token("zone", zone),
            port=validate_port(port),
            protocol=validate_protocol(protocol),
            target=target,
        )
        key = (server_id, generation, operation)
        if key in self._firewall_jobs:
            raise RuntimeError("A matching port operation is already pending.")
        logical = _LogicalFirewallJob(
            intent=intent,
            public=ControllerJobHandle(server_id, generation, operation),
        )
        self._firewall_jobs[key] = logical
        self._launch_firewall_attempt(logical)
        return logical.public

    def _schedule_default_zone_change(
        self,
        server_id: str,
        generation: int,
        zone: str,
        target: ApplyTarget,
    ) -> ControllerJobHandle:
        """Schedule one validated global default-zone intent privately."""
        session = self._live_idle_session(server_id, "set_default_zone")
        if generation != session.generation:
            raise RuntimeError(
                "The server session changed before the default-zone operation."
            )
        if target is not ApplyTarget.BOTH:
            raise ValueError("Default-zone changes require both targets.")
        intent = _DefaultZoneChangeIntent(
            server_id=server_id,
            generation=generation,
            operation="set_default_zone",
            zone=validate_inventory_token("zone", zone),
            target=target,
        )
        key = (server_id, generation, intent.operation)
        if key in self._firewall_jobs:
            raise RuntimeError("A matching firewall operation is already pending.")
        logical = _LogicalFirewallJob(
            intent=intent,
            public=ControllerJobHandle(server_id, generation, intent.operation),
        )
        self._firewall_jobs[key] = logical
        self._launch_firewall_attempt(logical)
        return logical.public

    def _schedule_service_change(
        self,
        server_id: str,
        generation: int,
        operation: str,
        zone: str,
        service: str,
        target: ApplyTarget,
    ) -> ControllerJobHandle:
        """Schedule one validated service intent without exposing live resources."""
        session = self._live_idle_session(server_id, operation)
        if generation != session.generation:
            raise RuntimeError(
                "The server session changed before the service operation."
            )
        if operation not in {"add_service", "remove_service"}:
            raise ValueError("Unsupported service operation.")
        if not isinstance(target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        intent = _ServiceChangeIntent(
            server_id=server_id,
            generation=generation,
            operation=operation,
            zone=validate_inventory_token("zone", zone),
            service=validate_inventory_token("service", service),
            target=target,
        )
        key = (server_id, generation, operation)
        if key in self._firewall_jobs:
            raise RuntimeError("A matching service operation is already pending.")
        logical = _LogicalFirewallJob(
            intent=intent,
            public=ControllerJobHandle(server_id, generation, operation),
        )
        self._firewall_jobs[key] = logical
        self._launch_firewall_attempt(logical)
        return logical.public

    def _schedule_interface_change(
        self,
        server_id: str,
        generation: int,
        interface: str,
        zone: str,
        target: ApplyTarget,
    ) -> ControllerJobHandle:
        """Schedule one validated interface-zone intent without live resources."""
        operation = "change_interface_zone"
        session = self._live_idle_session(server_id, operation)
        if generation != session.generation:
            raise RuntimeError(
                "The server session changed before the interface operation."
            )
        if not isinstance(target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        intent = _InterfaceChangeIntent(
            server_id=server_id,
            generation=generation,
            operation=operation,
            interface=validate_inventory_token("interface", interface),
            zone=validate_inventory_token("zone", zone),
            target=target,
        )
        key = (server_id, generation, operation)
        if key in self._firewall_jobs:
            raise RuntimeError("A matching interface operation is already pending.")
        logical = _LogicalFirewallJob(
            intent=intent,
            public=ControllerJobHandle(server_id, generation, operation),
        )
        self._firewall_jobs[key] = logical
        self._launch_firewall_attempt(logical)
        return logical.public

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
            self._clear_pending_decisions(server_id)
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
            self._clear_pending_decisions(server_id)
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

    def _restart_connection(
        self,
        session: ServerSession,
        operation: str,
        *,
        retried_with_sudo: bool,
    ) -> ControllerJobHandle:
        generation = self._advance_generation(session)
        session.status = ConnectionStatus.CONNECTING
        session.latest_error = None
        session.snapshot = None
        session.busy_operation = operation
        attempt = _ConnectionAttempt()
        session._connection_attempt = attempt
        if retried_with_sudo:
            self._sudo_retry_jobs.add((session.config.id, generation, operation))
        self.session_changed.emit(session.config.id)
        return self._submit_connection(
            session,
            operation,
            tokens_to_close=(),
            attempt=attempt,
        )

    def _retry_sudo_operation(
        self, request: SudoPasswordRequest
    ) -> ControllerJobHandle | None:
        session = self._sessions.get(request.server_id)
        if session is None or session.generation != request.generation:
            return None
        if request.operation in {"connect", "reconnect"}:
            return self._restart_connection(
                session, request.operation, retried_with_sudo=True
            )
        if request.operation == "refresh":
            if session._service is None:
                return None
            session.status = ConnectionStatus.CONNECTED
            key = (request.server_id, request.generation, request.operation)
            self._sudo_retry_jobs.add(key)
            return self.refresh(request.server_id)
        if request.operation == "test_connection":
            if session._service is None:
                return None
            session.status = ConnectionStatus.CONNECTED
            key = (request.server_id, request.generation, request.operation)
            self._sudo_retry_jobs.add(key)
            return self.test_connection(request.server_id)
        if request.operation == "reload_firewalld":
            if session._service is None:
                return None
            session.status = ConnectionStatus.CONNECTED
            key = (request.server_id, request.generation, request.operation)
            self._sudo_retry_jobs.add(key)
            return self.reload_firewalld(request.server_id)
        if request.operation in {
            "add_port",
            "remove_port",
            "add_service",
            "remove_service",
            "set_default_zone",
            "change_interface_zone",
        }:
            logical = self._firewall_jobs.get(
                (request.server_id, request.generation, request.operation)
            )
            if logical is None or logical.completed or session._service is None:
                return None
            session.status = ConnectionStatus.CONNECTED
            key = (request.server_id, request.generation, request.operation)
            self._sudo_retry_jobs.add(key)
            return self._launch_firewall_attempt(logical)
        return None

    def _clear_pending_decisions(self, server_id: str) -> None:
        self._cancel_firewall_jobs(server_id)
        self._pending_host_keys.pop(server_id, None)
        self._pending_sudo.pop(server_id, None)
        self._clear_pending_trusted_retries(server_id)
        self._accepted_sudo_retries = {
            request
            for request in self._accepted_sudo_retries
            if request.server_id != server_id
        }
        self._sudo_retry_jobs = {
            key for key in self._sudo_retry_jobs if key[0] != server_id
        }

    def _clear_pending_trusted_retries(self, server_id: str) -> None:
        self._pending_trusted_retries = {
            key: retry
            for key, retry in self._pending_trusted_retries.items()
            if retry.server_id != server_id
        }

    def _launch_firewall_attempt(
        self, logical: _LogicalFirewallJob
    ) -> ControllerJobHandle:
        intent = logical.intent
        session = self._live_idle_session(intent.server_id, intent.operation)
        if session.generation != intent.generation:
            raise RuntimeError(
                "The server session changed before the firewall operation."
            )
        service = cast(_Service, session._service)
        sudo_password = session.sudo_password

        def work() -> _FirewallMutationOutcome:
            if isinstance(intent, _PortChangeIntent):
                method = (
                    service.add_port
                    if intent.operation == "add_port"
                    else service.remove_port
                )
                result = method(
                    intent.zone,
                    intent.port,
                    intent.protocol,
                    intent.target,
                    sudo_password=sudo_password,
                )
            elif isinstance(intent, _ServiceChangeIntent):
                method = (
                    service.add_service
                    if intent.operation == "add_service"
                    else service.remove_service
                )
                result = method(
                    intent.zone,
                    intent.service,
                    intent.target,
                    sudo_password=sudo_password,
                )
            elif isinstance(intent, _InterfaceChangeIntent):
                result = service.change_interface_zone(
                    intent.interface,
                    intent.zone,
                    intent.target,
                    sudo_password=sudo_password,
                )
            else:
                result = service.set_default_zone(
                    intent.zone,
                    intent.target,
                    sudo_password=sudo_password,
                )
            if (
                not isinstance(result, CompositeOperationResult)
                or result.operation != intent.operation
            ):
                raise FirewallCommandError(intent.server_id, intent.operation)
            post_mutation_auth_failure = any(
                target_result is not None
                and target_result.authentication_failed
                for target_result in (result.permanent, result.runtime)
            )
            try:
                snapshot = service.load_snapshot(sudo_password=sudo_password)
            except (SudoAuthenticationError, SudoAuthenticationRequiredError):
                return _FirewallMutationOutcome(
                    result=result,
                    snapshot=None,
                    refresh_error=ControllerOperationError(
                        intent.server_id,
                        intent.operation,
                        "post_mutation_refresh",
                        self._post_mutation_refresh_message(intent.operation),
                    ),
                    clear_sudo=True,
                )
            except Exception as error:
                return _FirewallMutationOutcome(
                    result=result,
                    snapshot=None,
                    refresh_error=ControllerOperationError(
                        intent.server_id,
                        intent.operation,
                        "post_mutation_refresh",
                        self._post_mutation_refresh_message(intent.operation),
                    ),
                    terminal_transport=isinstance(error, SSHConnectionError),
                    clear_sudo=(
                        post_mutation_auth_failure
                        or isinstance(error, SSHAuthenticationError)
                    ),
                )
            if not isinstance(snapshot, FirewallSnapshot):
                return _FirewallMutationOutcome(
                    result=result,
                    snapshot=None,
                    refresh_error=ControllerOperationError(
                        intent.server_id,
                        intent.operation,
                        "post_mutation_refresh",
                        self._post_mutation_refresh_message(intent.operation),
                    ),
                    clear_sudo=post_mutation_auth_failure,
                )
            return _FirewallMutationOutcome(
                result=result,
                snapshot=snapshot,
                clear_sudo=post_mutation_auth_failure,
            )

        attempt = self._start_service_job(session, intent.operation, work)
        logical.attempt = attempt
        attempt.started.connect(
            lambda server_id, generation, operation, current=attempt: (
                self._firewall_attempt_started(
                    logical, current, server_id, generation, operation
                )
            )
        )
        attempt.succeeded.connect(
            lambda server_id, generation, operation, value, current=attempt: (
                self._firewall_attempt_succeeded(
                    logical, current, server_id, generation, operation, value
                )
            )
        )
        attempt.failed.connect(
            lambda server_id, generation, operation, error, current=attempt: (
                self._firewall_attempt_failed(
                    logical, current, server_id, generation, operation, error
                )
            )
        )
        attempt.finished.connect(
            lambda server_id, generation, operation, current=attempt: (
                self._firewall_attempt_finished(
                    logical, current, server_id, generation, operation
                )
            )
        )
        return attempt

    @staticmethod
    def _matches_firewall_attempt(
        logical: _LogicalFirewallJob,
        attempt: ControllerJobHandle,
        server_id: str,
        generation: int,
        operation: str,
    ) -> bool:
        intent = logical.intent
        return (
            not logical.completed
            and logical.attempt is attempt
            and intent.server_id == server_id
            and intent.generation == generation
            and intent.operation == operation
        )

    @staticmethod
    def _post_mutation_refresh_message(operation: str) -> str:
        if operation == "set_default_zone":
            return (
                "The default-zone change completed, but fresh firewall data "
                "could not be loaded."
            )
        if operation == "change_interface_zone":
            return (
                "The interface-zone change completed, but fresh firewall data "
                "could not be loaded."
            )
        resource = (
            "service"
            if operation in {"add_service", "remove_service"}
            else "port"
        )
        return (
            f"The {resource} change completed, but fresh firewall data could not "
            "be loaded."
        )

    def _firewall_attempt_started(
        self,
        logical: _LogicalFirewallJob,
        attempt: ControllerJobHandle,
        server_id: str,
        generation: int,
        operation: str,
    ) -> None:
        if not self._matches_firewall_attempt(
            logical, attempt, server_id, generation, operation
        ):
            return
        if not logical.started_emitted:
            logical.started_emitted = True
            logical.public.started.emit(server_id, generation, operation)

    def _firewall_attempt_succeeded(
        self,
        logical: _LogicalFirewallJob,
        attempt: ControllerJobHandle,
        server_id: str,
        generation: int,
        operation: str,
        value: object,
    ) -> None:
        if not self._matches_firewall_attempt(
            logical, attempt, server_id, generation, operation
        ):
            return
        if not isinstance(value, CompositeOperationResult):
            logical.last_error = ControllerOperationError(
                server_id,
                operation,
                "operation",
                "The remote operation failed.",
            )
            logical.public.failed.emit(
                server_id, generation, operation, logical.last_error
            )
        else:
            logical.public.succeeded.emit(server_id, generation, operation, value)
        logical.outcome_emitted = True

    def _firewall_attempt_failed(
        self,
        logical: _LogicalFirewallJob,
        attempt: ControllerJobHandle,
        server_id: str,
        generation: int,
        operation: str,
        error: object,
    ) -> None:
        if not self._matches_firewall_attempt(
            logical, attempt, server_id, generation, operation
        ):
            return
        public_error = (
            error
            if isinstance(error, ControllerOperationError)
            else ControllerOperationError(
                server_id,
                operation,
                "operation",
                "The remote operation failed.",
            )
        )
        logical.last_error = public_error
        pending = self._pending_sudo.get(server_id)
        waiting = (
            public_error.category == "sudo_required"
            and (
                (
                    pending is not None
                    and pending.request.generation == generation
                    and pending.request.operation == operation
                )
                or any(
                    request.server_id == server_id
                    and request.generation == generation
                    and request.operation == operation
                    for request in self._accepted_sudo_retries
                )
            )
        )
        if waiting:
            return
        logical.public.failed.emit(server_id, generation, operation, public_error)
        logical.outcome_emitted = True

    def _firewall_attempt_finished(
        self,
        logical: _LogicalFirewallJob,
        attempt: ControllerJobHandle,
        server_id: str,
        generation: int,
        operation: str,
    ) -> None:
        if not self._matches_firewall_attempt(
            logical, attempt, server_id, generation, operation
        ):
            return
        if logical.outcome_emitted:
            self._finish_firewall_job(logical)
            return
        pending = self._pending_sudo.get(server_id)
        if (
            pending is not None
            and pending.request.generation == generation
            and pending.request.operation == operation
        ) or any(
            request.server_id == server_id
            and request.generation == generation
            and request.operation == operation
            for request in self._accepted_sudo_retries
        ):
            return
        if logical.last_error is not None:
            logical.public.failed.emit(
                server_id, generation, operation, logical.last_error
            )
            logical.outcome_emitted = True
            self._finish_firewall_job(logical)

    def _finish_firewall_job(self, logical: _LogicalFirewallJob) -> None:
        if logical.completed:
            return
        logical.completed = True
        intent = logical.intent
        key = (intent.server_id, intent.generation, intent.operation)
        if self._firewall_jobs.get(key) is logical:
            del self._firewall_jobs[key]
        self._sudo_retry_jobs.discard(key)
        logical.public.finished.emit(
            intent.server_id, intent.generation, intent.operation
        )

    def _cancel_firewall_job(self, request: SudoPasswordRequest) -> None:
        logical = self._firewall_jobs.get(
            (request.server_id, request.generation, request.operation)
        )
        if logical is None or logical.completed:
            return
        error = logical.last_error or ControllerOperationError(
            request.server_id,
            request.operation,
            "sudo_required",
            "Sudo authentication is required.",
        )
        logical.public.failed.emit(
            request.server_id, request.generation, request.operation, error
        )
        logical.outcome_emitted = True
        self._finish_firewall_job(logical)

    def _cancel_firewall_jobs(self, server_id: str) -> None:
        for logical in tuple(self._firewall_jobs.values()):
            if logical.intent.server_id != server_id or logical.completed:
                continue
            error = ControllerOperationError(
                server_id,
                logical.intent.operation,
                "operation",
                "The remote operation was cancelled because the server session changed.",
            )
            logical.public.failed.emit(
                server_id,
                logical.intent.generation,
                logical.intent.operation,
                error,
            )
            logical.outcome_emitted = True
            self._finish_firewall_job(logical)

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
        elif operation in {"refresh", "reload_firewalld"}:
            if not isinstance(value, FirewallSnapshot):
                public_error = self._apply_failure(
                    session,
                    operation,
                    TypeError(f"{operation} returned invalid state"),
                )
                record.public.failed.emit(
                    server_id, generation, operation, public_error
                )
                return
            session.snapshot = value
            session.latest_error = None
            self.session_changed.emit(server_id)
            public_value = value
        elif operation in {
            "add_port",
            "remove_port",
            "add_service",
            "remove_service",
            "set_default_zone",
            "change_interface_zone",
        }:
            if not isinstance(value, _FirewallMutationOutcome):
                public_error = self._apply_failure(
                    session,
                    operation,
                    TypeError("firewall operation returned invalid state"),
                )
                record.public.failed.emit(
                    server_id, generation, operation, public_error
                )
                return
            if value.snapshot is not None:
                session.snapshot = value.snapshot
            elif session.snapshot is not None:
                session.snapshot = replace(session.snapshot, stale=True)
            if value.clear_sudo:
                session.sudo_password = None
            if value.refresh_error is None:
                session.latest_error = None
            else:
                session.latest_error = value.refresh_error.message
                if value.terminal_transport and session._ssh_manager is not None:
                    manager = cast(_Manager, session._ssh_manager)
                    self._register_close_tokens(server_id, manager)
                    session._ssh_manager = None
                    session._service = None
                    session.sudo_password = None
                    session.status = ConnectionStatus.CONNECTION_ERROR
                    self._submit_close(
                        server_id,
                        generation,
                        "close_failed_connection",
                        self._open_close_tokens(server_id),
                    )
                self.error_raised.emit(server_id, value.refresh_error)
            self.session_changed.emit(server_id)
            public_value = value.result
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
        self._sudo_retry_jobs.discard((server_id, generation, operation))

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
        self._sudo_retry_jobs.discard((server_id, generation, operation))

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
            self._launch_trusted_retry((server_id, generation, operation))
        request = next(
            (
                candidate
                for candidate in self._accepted_sudo_retries
                if candidate.server_id == server_id
                and candidate.generation == generation
                and candidate.operation == operation
            ),
            None,
        )
        if request is not None:
            self._accepted_sudo_retries.discard(request)
            self._retry_sudo_operation(request)

    def _launch_trusted_retry(
        self, key: tuple[str, int, str]
    ) -> ControllerJobHandle | None:
        retry = self._pending_trusted_retries.pop(key, None)
        if retry is None:
            return None
        session = self._sessions.get(retry.server_id)
        if (
            session is None
            or session.generation != retry.generation
            or session.config.host != retry.host
            or session.config.port != retry.port
            or session.status is not ConnectionStatus.HOST_KEY_ERROR
            or session.busy_operation is not None
        ):
            return None
        return self._restart_connection(
            session, retry.operation, retried_with_sudo=False
        )

    def _apply_failure(
        self, session: ServerSession, operation: str, error: object
    ) -> ControllerOperationError:
        public_error = self._public_error(session.config.id, operation, error)
        if isinstance(
            error,
            (SSHAuthenticationError, SudoAuthenticationError, PostMutationError),
        ):
            session.sudo_password = None
        if isinstance(error, UnknownHostKeyError):
            session.status = ConnectionStatus.HOST_KEY_ERROR
            self._pending_sudo.pop(session.config.id, None)
            self._pending_host_keys[session.config.id] = _PendingHostKey(
                session.config.id,
                session.generation,
                operation,
                error.challenge,
            )
            self.host_key_required.emit(session.config.id, error.challenge)
        elif isinstance(error, ChangedHostKeyError):
            session.status = ConnectionStatus.HOST_KEY_ERROR
            self._pending_host_keys.pop(session.config.id, None)
        elif isinstance(error, SSHAuthenticationError):
            session.status = ConnectionStatus.AUTHENTICATION_FAILED
            self._pending_sudo.pop(session.config.id, None)
        elif isinstance(error, SudoAuthenticationError):
            session.status = ConnectionStatus.PERMISSION_ERROR
            self._pending_sudo.pop(session.config.id, None)
        elif isinstance(error, SudoAuthenticationRequiredError):
            session.status = ConnectionStatus.PERMISSION_ERROR
            key = (session.config.id, session.generation, operation)
            if key in self._sudo_retry_jobs:
                session.sudo_password = None
                self._pending_sudo.pop(session.config.id, None)
            else:
                request = SudoPasswordRequest(
                    session.config.id, session.generation, operation
                )
                self._pending_sudo[session.config.id] = _PendingSudo(request)
                self.sudo_password_required.emit(session.config.id, request)
        elif isinstance(error, PostMutationError):
            self._pending_sudo.pop(session.config.id, None)
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

        if (
            operation in {"refresh", "reload_firewalld"}
            and session.snapshot is not None
        ):
            session.snapshot = replace(session.snapshot, stale=True)
        if (
            operation
            in {
                "add_port",
                "remove_port",
                "add_service",
                "remove_service",
                "set_default_zone",
                "change_interface_zone",
            }
            and isinstance(error, (SSHConnectionError, PostMutationError))
            and session.snapshot is not None
        ):
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
        elif isinstance(error, PostMutationVerificationError):
            category = "post_mutation_verification"
            if operation == "set_default_zone":
                message = (
                    "The default-zone change completed, but the requested default "
                    "zone could not be verified."
                )
            elif operation in {"add_service", "remove_service"}:
                message = (
                    "The service change completed, but the requested firewall state "
                    "could not be verified."
                )
            elif operation in {"add_port", "remove_port"}:
                message = (
                    "The port change completed, but the requested firewall state "
                    "could not be verified."
                )
            elif operation == "change_interface_zone":
                message = (
                    "The interface-zone change completed, but the requested "
                    "firewall state could not be verified."
                )
            else:
                message = (
                    "Firewalld reloaded, but its running state could not be verified."
                )
        elif isinstance(error, PostMutationRefreshError):
            category = "post_mutation_refresh"
            if operation == "set_default_zone":
                message = (
                    "The default-zone change completed, but fresh firewall data could "
                    "not be loaded."
                )
            elif operation in {"add_service", "remove_service"}:
                message = (
                    "The service change completed, but fresh firewall data could not "
                    "be loaded."
                )
            elif operation in {"add_port", "remove_port"}:
                message = (
                    "The port change completed, but fresh firewall data could not be "
                    "loaded."
                )
            elif operation == "change_interface_zone":
                message = (
                    "The interface-zone change completed, but fresh firewall data "
                    "could not be loaded."
                )
            else:
                message = (
                    "Firewalld reloaded, but fresh firewall data could not be loaded."
                )
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
        elif isinstance(error, HostKeyStoreError):
            category, message = (
                "host_key_store",
                "The SSH trust store could not be updated safely.",
            )
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
