from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from threading import Event
from typing import Any

from PySide6.QtCore import QCoreApplication, QEvent, QEventLoop, QObject, QTimer, Signal

from app.config.models import ApplicationConfig, LoadedConfig, ServerConfig
from app.firewalld.service import ConnectionCheck, ConnectionTestResult, FirewalldInfo
from app.models.command import CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, TargetStatus
from app.models.firewall import FirewallSnapshot
from app.utils.errors import ConfigurationError


def make_server(
    server_id: str,
    *,
    name: str | None = None,
    host: str | None = None,
    password: str | None = None,
) -> ServerConfig:
    return ServerConfig(
        id=server_id,
        name=name or server_id.upper(),
        host=host or f"{server_id}.example.test",
        username="operator",
        password=password or f"ssh-{server_id}-secret",
        sudo=True,
    )


def make_loaded(*server_ids: str) -> LoadedConfig:
    return LoadedConfig(
        application=ApplicationConfig(),
        servers=tuple(make_server(server_id) for server_id in server_ids),
    )


def make_snapshot(
    *, server_id: str = "web01", default_zone: str = "public", stale: bool = False
) -> FirewallSnapshot:
    return FirewallSnapshot(
        hostname=server_id,
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone=default_zone,
        stale=stale,
    )


class FakeConfigManager:
    def __init__(self, loaded: LoadedConfig) -> None:
        self.current = loaded
        self.next_load_error: ConfigurationError | None = None
        self.load_calls = 0

    def load(self) -> LoadedConfig:
        self.load_calls += 1
        error = self.next_load_error
        self.next_load_error = None
        if error is not None:
            raise error
        return self.current


class ManualJobHandle(QObject):
    started = Signal(str, int, str)
    succeeded = Signal(str, int, str, object)
    failed = Signal(str, int, str, object)
    finished = Signal(str, int, str)

    def __init__(
        self,
        server_id: str,
        generation: int,
        operation: str,
        work: Callable[[], object],
    ) -> None:
        super().__init__()
        self.server_id = server_id
        self.generation = generation
        self.operation = operation
        self.work = work
        self.has_run = False

    def emit_started(self) -> None:
        self.started.emit(self.server_id, self.generation, self.operation)
        self._deliver_queued_signals()

    def emit_succeeded(self, value: object) -> None:
        self.succeeded.emit(
            self.server_id, self.generation, self.operation, value
        )
        self._deliver_queued_signals()

    def emit_failed(self, error: Exception) -> None:
        self.failed.emit(self.server_id, self.generation, self.operation, error)
        self._deliver_queued_signals()

    def emit_finished(self) -> None:
        self.finished.emit(self.server_id, self.generation, self.operation)
        self._deliver_queued_signals()

    @staticmethod
    def _deliver_queued_signals() -> None:
        application = QCoreApplication.instance()
        if application is not None:
            QCoreApplication.sendPostedEvents(None, QEvent.Type.MetaCall)
            application.processEvents()
            loop = QEventLoop()
            QTimer.singleShot(0, loop.quit)
            loop.exec()

    def run(self) -> object:
        self.has_run = True
        self.emit_started()
        try:
            value = self.work()
        except Exception as error:
            self.emit_failed(error)
            self.emit_finished()
            return error
        self.emit_succeeded(value)
        self.emit_finished()
        return value

    def run_synchronously_for_test(self) -> None:
        """Run one queued fake job while preserving its public signal lifecycle."""
        self.run()


class ManualScheduler:
    def __init__(self) -> None:
        self.handles: list[ManualJobHandle] = []
        self.cancelled: list[str] = []
        self.wait_timeouts: list[int] = []

    def submit(
        self,
        server_id: str,
        generation: int,
        operation: str,
        work: Callable[[], object],
    ) -> ManualJobHandle:
        handle = ManualJobHandle(server_id, generation, operation, work)
        self.handles.append(handle)
        return handle

    def cancel_pending(self, server_id: str) -> None:
        self.cancelled.append(server_id)

    def wait_for_done(self, timeout_ms: int = -1) -> bool:
        self.wait_timeouts.append(timeout_ms)
        while True:
            pending = [handle for handle in self.handles if not handle.has_run]
            if not pending:
                return True
            pending[0].run()

    def pending(
        self, server_id: str, operation: str | None = None
    ) -> ManualJobHandle:
        matches = [
            handle
            for handle in self.handles
            if handle.server_id == server_id
            and (operation is None or handle.operation == operation)
        ]
        if not matches:
            raise AssertionError(f"No pending job for {server_id!r} / {operation!r}")
        return matches[-1]


@dataclass
class FakeSSHManager:
    server_id: str
    connect_error: Exception | None = None
    connect_calls: int = 0
    disconnect_calls: int = 0
    connect_thread: object | None = None
    disconnect_thread: object | None = None
    connect_entered: Event | None = None
    connect_release: Event | None = None
    disconnect_entered: Event | None = None
    disconnect_release: Event | None = None

    def connect(self) -> None:
        from PySide6.QtCore import QThread

        self.connect_calls += 1
        self.connect_thread = QThread.currentThread()
        if self.connect_entered is not None:
            self.connect_entered.set()
        if self.connect_release is not None:
            assert self.connect_release.wait(3)
        if self.connect_error is not None:
            raise self.connect_error

    def disconnect(self) -> None:
        from PySide6.QtCore import QThread

        self.disconnect_calls += 1
        self.disconnect_thread = QThread.currentThread()
        if self.disconnect_entered is not None:
            self.disconnect_entered.set()
        if self.disconnect_release is not None:
            assert self.disconnect_release.wait(3)


class ManagerFactory:
    def __init__(self) -> None:
        self.instances: dict[str, list[FakeSSHManager]] = defaultdict(list)
        self.next_errors: dict[str, Exception] = {}
        self.connect_entered: dict[str, Event] = {}
        self.connect_release: dict[str, Event] = {}
        self.disconnect_entered: dict[str, Event] = {}
        self.disconnect_release: dict[str, Event] = {}

    def __call__(
        self, server: ServerConfig, application: ApplicationConfig
    ) -> FakeSSHManager:
        del application
        manager = FakeSSHManager(
            server_id=server.id,
            connect_error=self.next_errors.pop(server.id, None),
            connect_entered=self.connect_entered.get(server.id),
            connect_release=self.connect_release.get(server.id),
            disconnect_entered=self.disconnect_entered.get(server.id),
            disconnect_release=self.disconnect_release.get(server.id),
        )
        self.instances[server.id].append(manager)
        return manager


class FakeFirewalldService:
    def __init__(self, manager: FakeSSHManager, server_id: str) -> None:
        self.manager = manager
        self.server_id = server_id
        self.load_calls: list[str | None] = []
        self.test_calls: list[str | None] = []
        self.next_snapshot = make_snapshot(server_id=server_id)
        self.next_load_error: Exception | None = None
        self.next_test_error: Exception | None = None
        self.next_reload_error: Exception | None = None
        self.next_add_port_error: Exception | None = None
        self.next_remove_port_error: Exception | None = None
        self.next_add_service_error: Exception | None = None
        self.next_remove_service_error: Exception | None = None
        self.next_set_default_zone_error: Exception | None = None
        self.next_reload_result = CompositeOperationResult(
            operation="reload_firewalld",
            permanent=TargetResult(
                ApplyTarget.PERMANENT,
                TargetStatus.SUCCEEDED,
                TargetStatus.SUCCEEDED,
                None,
                "",
            ),
            runtime=TargetResult(
                ApplyTarget.RUNTIME,
                TargetStatus.SUCCEEDED,
                TargetStatus.SUCCEEDED,
                None,
                "",
            ),
        )
        self.load_threads: list[object] = []
        self.test_threads: list[object] = []
        self.reload_calls: list[tuple[ApplyTarget, str | None]] = []
        self.add_port_calls: list[
            tuple[str, str, str, ApplyTarget, str | None]
        ] = []
        self.remove_port_calls: list[
            tuple[str, str, str, ApplyTarget, str | None]
        ] = []
        self.add_service_calls: list[
            tuple[str, str, ApplyTarget, str | None]
        ] = []
        self.remove_service_calls: list[
            tuple[str, str, ApplyTarget, str | None]
        ] = []
        self.set_default_zone_calls: list[
            tuple[str, ApplyTarget, str | None]
        ] = []
        self.operation_trace: list[str] = []
        self.next_add_port_result = _successful_result("add_port")
        self.next_remove_port_result = _successful_result("remove_port")
        self.next_add_service_result = _successful_result("add_service")
        self.next_remove_service_result = _successful_result("remove_service")
        self.next_set_default_zone_result = _successful_result("set_default_zone")
        self.add_port_entered: Event | None = None
        self.add_port_release: Event | None = None
        self.add_service_entered: Event | None = None
        self.add_service_release: Event | None = None

    def load_snapshot(
        self, *, sudo_password: str | None = None
    ) -> FirewallSnapshot:
        from PySide6.QtCore import QThread

        self.load_threads.append(QThread.currentThread())
        self.load_calls.append(sudo_password)
        self.operation_trace.append("load_snapshot")
        if self.next_load_error is not None:
            error = self.next_load_error
            self.next_load_error = None
            raise error
        return self.next_snapshot

    def connection_test(
        self, *, sudo_password: str | None = None
    ) -> ConnectionTestResult:
        from PySide6.QtCore import QThread

        self.test_threads.append(QThread.currentThread())
        self.test_calls.append(sudo_password)
        self.operation_trace.append("connection_test")
        if self.next_test_error is not None:
            error = self.next_test_error
            self.next_test_error = None
            raise error
        return ConnectionTestResult(
            hostname=self.server_id,
            distribution="Test Linux",
            effective_uid=1000,
            firewalld=FirewalldInfo(True, True, "2.1.0"),
            checks=(ConnectionCheck("hostname", True, "ok"),),
        )

    def reload_firewalld(
        self,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        self.reload_calls.append((target, sudo_password))
        self.operation_trace.append("reload_firewalld")
        if self.next_reload_error is not None:
            error = self.next_reload_error
            self.next_reload_error = None
            raise error
        return self.next_reload_result

    def add_port(
        self,
        zone: str,
        port: str,
        protocol: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        self.add_port_calls.append((zone, port, protocol, target, sudo_password))
        self.operation_trace.append("add_port")
        if self.add_port_entered is not None:
            self.add_port_entered.set()
        if self.add_port_release is not None:
            assert self.add_port_release.wait(3)
        if self.next_add_port_error is not None:
            error = self.next_add_port_error
            self.next_add_port_error = None
            raise error
        return self.next_add_port_result

    def remove_port(
        self,
        zone: str,
        port: str,
        protocol: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        self.remove_port_calls.append((zone, port, protocol, target, sudo_password))
        self.operation_trace.append("remove_port")
        if self.next_remove_port_error is not None:
            error = self.next_remove_port_error
            self.next_remove_port_error = None
            raise error
        return self.next_remove_port_result

    def add_service(
        self,
        zone: str,
        service: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        self.add_service_calls.append((zone, service, target, sudo_password))
        self.operation_trace.append("add_service")
        if self.add_service_entered is not None:
            self.add_service_entered.set()
        if self.add_service_release is not None:
            assert self.add_service_release.wait(3)
        if self.next_add_service_error is not None:
            error = self.next_add_service_error
            self.next_add_service_error = None
            raise error
        return self.next_add_service_result

    def remove_service(
        self,
        zone: str,
        service: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        self.remove_service_calls.append((zone, service, target, sudo_password))
        self.operation_trace.append("remove_service")
        if self.next_remove_service_error is not None:
            error = self.next_remove_service_error
            self.next_remove_service_error = None
            raise error
        return self.next_remove_service_result

    def set_default_zone(
        self,
        zone: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        self.set_default_zone_calls.append((zone, target, sudo_password))
        self.operation_trace.append("set_default_zone")
        if self.next_set_default_zone_error is not None:
            error = self.next_set_default_zone_error
            self.next_set_default_zone_error = None
            raise error
        return self.next_set_default_zone_result


class ServiceFactory:
    def __init__(self) -> None:
        self.instances: dict[str, list[FakeFirewalldService]] = defaultdict(list)
        self.next_load_errors: dict[str, Exception] = {}
        self.next_test_errors: dict[str, Exception] = {}
        self.next_snapshots: dict[str, FirewallSnapshot] = {}

    def __call__(
        self, manager: FakeSSHManager, server_id: str
    ) -> FakeFirewalldService:
        service = FakeFirewalldService(manager, server_id)
        service.next_load_error = self.next_load_errors.pop(server_id, None)
        service.next_test_error = self.next_test_errors.pop(server_id, None)
        service.next_snapshot = self.next_snapshots.pop(
            server_id, service.next_snapshot
        )
        self.instances[server_id].append(service)
        return service


def secrets_in(value: Any) -> bool:
    return "secret" in repr(value)


def _successful_result(operation: str) -> CompositeOperationResult:
    return CompositeOperationResult(
        operation=operation,
        permanent=TargetResult(
            ApplyTarget.PERMANENT,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
            None,
            "",
        ),
        runtime=TargetResult(
            ApplyTarget.RUNTIME,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
            None,
            "",
        ),
    )
