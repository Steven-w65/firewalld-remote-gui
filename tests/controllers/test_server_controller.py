from __future__ import annotations

from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from threading import Event, Lock, Thread
from typing import Any

import pytest
from PySide6.QtCore import QThread

from app.config.models import LoadedConfig
from app.models.command import CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, ConnectionStatus, TargetStatus
from app.utils.errors import (
    ChangedHostKeyError,
    ConfigurationError,
    HostKeyStoreError,
    PostMutationVerificationError,
    SSHAuthenticationError,
    SSHConnectionError,
    SudoAuthenticationError,
    SudoAuthenticationRequiredError,
    UnknownHostKeyError,
)
from app.workers.scheduler import OperationScheduler
from tests.controllers.fakes import (
    FakeConfigManager,
    ManagerFactory,
    ManualScheduler,
    ServiceFactory,
    make_loaded,
    make_server,
    make_snapshot,
    secrets_in,
)


class RecordingHostKeyStore:
    def __init__(self) -> None:
        self.trust_calls: list[object] = []

    def trust(self, challenge: object) -> None:
        self.trust_calls.append(challenge)


@pytest.fixture
def dependencies():
    return (
        FakeConfigManager(make_loaded("web01", "db01")),
        ManualScheduler(),
        ManagerFactory(),
        ServiceFactory(),
    )


@pytest.fixture
def controller(dependencies, qapp):
    from app.controllers.server_controller import ServerController

    del qapp
    return ServerController(*dependencies)


def _finish_connect(controller, scheduler, server_id: str) -> None:
    scheduler.pending(server_id, "connect").run()
    assert controller.session_view(server_id).status is ConnectionStatus.CONNECTED


class _CancellationObservingScheduler(OperationScheduler):
    def __init__(self) -> None:
        super().__init__(max_threads=1)
        self._observation_lock = Lock()
        self.cancelled_ids: list[str] = []
        self.submitted_operations: list[tuple[str, str]] = []
        self.web_cancelled = Event()
        self.second_web_cancel = Event()

    def submit(self, server_id, generation, operation, work):
        with self._observation_lock:
            self.submitted_operations.append((server_id, operation))
        return super().submit(server_id, generation, operation, work)

    def cancel_pending(self, server_id: str) -> None:
        with self._observation_lock:
            self.cancelled_ids.append(server_id)
            if server_id == "web01":
                self.web_cancelled.set()
            if self.cancelled_ids.count("web01") >= 2:
                self.second_web_cancel.set()
        super().cancel_pending(server_id)


def _connected_real_controller(qtbot):
    from app.controllers.server_controller import ServerController

    config_manager = FakeConfigManager(make_loaded("web01"))
    scheduler = _CancellationObservingScheduler()
    manager_factory = ManagerFactory()
    service_factory = ServiceFactory()
    controller = ServerController(
        config_manager, scheduler, manager_factory, service_factory
    )
    controller.connect("web01")
    qtbot.waitUntil(
        lambda: controller.session_view("web01").status
        is ConnectionStatus.CONNECTED,
        timeout=3000,
    )
    assert scheduler.wait_for_done(3000)
    return controller, config_manager, scheduler, manager_factory


def _saturate_scheduler(scheduler):
    entered = Event()
    release = Event()

    def block_pool() -> None:
        entered.set()
        assert release.wait(3)

    scheduler.submit("pool-blocker", 0, "block_pool", block_pool)
    assert entered.wait(1)
    return release


def _release_after_second_web_cancel(scheduler, release: Event) -> None:
    if scheduler.second_web_cancel.wait(2):
        release.set()


def test_startup_preserves_configured_order_selects_first_and_does_not_connect(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, _ = dependencies
    assert tuple(view.server_id for view in controller.sessions()) == (
        "web01",
        "db01",
    )
    assert controller.selected_server_id == "web01"
    assert scheduler.handles == []
    assert manager_factory.instances == {}


def test_views_are_frozen_and_exclude_configuration_and_all_secrets(
    controller,
) -> None:
    view = controller.session_view("web01")
    assert view.name == "WEB01"
    assert view.host == "web01.example.test"
    assert not hasattr(view, "config")
    assert not hasattr(view, "password")
    assert not hasattr(view, "sudo_password")
    assert not hasattr(view, "ssh_manager")
    assert not hasattr(view, "service")
    assert not secrets_in(view)
    with pytest.raises(FrozenInstanceError):
        view.status = ConnectionStatus.CONNECTED


def test_each_connection_owns_a_distinct_manager_and_service(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, service_factory = dependencies
    controller.connect("web01")
    controller.connect("db01")
    _finish_connect(controller, scheduler, "web01")
    _finish_connect(controller, scheduler, "db01")

    assert manager_factory.instances["web01"][0] is not manager_factory.instances["db01"][0]
    assert service_factory.instances["web01"][0] is not service_factory.instances["db01"][0]


def test_connect_transitions_and_publishes_only_its_snapshot(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    service_factory_template = service_factory
    changed: list[str] = []
    controller.session_changed.connect(changed.append)

    handle = controller.connect("web01")
    assert handle is not scheduler.pending("web01", "connect")
    assert controller.session_view("web01").status is ConnectionStatus.CONNECTING
    assert controller.session_view("web01").busy_operation == "connect"
    assert controller.session_view("db01").status is ConnectionStatus.DISCONNECTED

    scheduler.pending("web01", "connect").run()
    service = service_factory_template.instances["web01"][0]
    assert service.load_calls == [None]
    assert controller.session_view("web01").snapshot == service.next_snapshot
    assert controller.session_view("web01").busy_operation is None
    assert changed


def test_public_handles_publish_only_safe_transformed_values(
    controller, dependencies
) -> None:
    from app.controllers.server_controller import ControllerJobHandle

    _, scheduler, _, _ = dependencies
    success_values: list[object] = []

    connect_handle = controller.connect("web01")
    assert isinstance(connect_handle, ControllerJobHandle)
    assert not hasattr(connect_handle, "work")
    connect_handle.succeeded.connect(
        lambda server_id, generation, operation, value: success_values.append(value)
    )
    scheduler.pending("web01", "connect").run()
    connected_value = success_values[-1]
    assert connected_value.server_id == "web01"
    assert connected_value.status is ConnectionStatus.CONNECTED
    assert connected_value.snapshot == controller.session_view("web01").snapshot
    published_values = [connected_value]

    for operation, request in (
        ("refresh", lambda: controller.refresh("web01")),
        ("test_connection", lambda: controller.test_connection("web01")),
        ("reload_firewalld", lambda: controller.reload_firewalld("web01")),
        ("reconnect", lambda: controller.reconnect("web01")),
        ("disconnect", lambda: controller.disconnect("web01")),
    ):
        handle = request()
        assert isinstance(handle, ControllerJobHandle)
        assert (handle.server_id, handle.operation) == ("web01", operation)
        assert not hasattr(handle, "work")
        emitted: list[object] = []
        handle.succeeded.connect(
            lambda server_id, generation, logical_operation, value: emitted.append(value)
        )
        scheduler.pending("web01", operation).run()
        assert len(emitted) == 1
        value = emitted[0]
        published_values.append(value)
        assert "secret" not in repr(value)
        assert not hasattr(value, "manager")
        assert not hasattr(value, "service")
        assert not hasattr(value, "config")
        assert not callable(value)

    for value in published_values:
        assert "secret" not in repr(value)
        assert not isinstance(value, Exception)
        for forbidden in (
            "manager",
            "service",
            "config",
            "password",
            "sudo_password",
            "work",
            "raw_error",
        ):
            assert not hasattr(value, forbidden)


def test_public_failure_payload_is_fresh_fixed_and_has_no_raw_exception_state(
    controller, dependencies
) -> None:
    from app.controllers.server_controller import ControllerJobHandle, ControllerOperationError

    _, scheduler, manager_factory, _ = dependencies
    raw = RuntimeError("raw ssh-web01-secret and sudo-web-secret")
    manager_factory.next_errors["web01"] = raw
    handle_errors: list[object] = []
    raised_errors: list[object] = []
    controller.error_raised.connect(
        lambda server_id, error: raised_errors.append(error)
    )

    handle = controller.connect("web01")
    assert isinstance(handle, ControllerJobHandle)
    handle.failed.connect(
        lambda server_id, generation, operation, error: handle_errors.append(error)
    )
    scheduler.pending("web01", "connect").run()

    assert len(handle_errors) == len(raised_errors) == 1
    for published in (*handle_errors, *raised_errors):
        assert isinstance(published, ControllerOperationError)
        assert published is not raw
        assert "secret" not in repr(published)
        assert "secret" not in published.message
        assert not hasattr(published, "args")
        assert not hasattr(published, "__traceback__")
        assert not hasattr(published, "__cause__")
        assert not hasattr(published, "__context__")
        assert not hasattr(published, "config")
        assert not hasattr(published, "raw_error")


@pytest.mark.parametrize("boundary", ["started", "succeeded", "failed", "finished"])
def test_every_old_generation_signal_boundary_is_ignored(
    controller, dependencies, boundary: str
) -> None:
    _, scheduler, _, _ = dependencies
    controller.connect("web01")
    old = scheduler.pending("web01", "connect")
    controller.disconnect("web01")
    before = controller.session_view("web01")
    changed: list[str] = []
    errors: list[tuple[str, object]] = []
    controller.session_changed.connect(changed.append)
    controller.error_raised.connect(lambda server_id, error: errors.append((server_id, error)))

    if boundary == "started":
        old.emit_started()
    elif boundary == "succeeded":
        old.emit_succeeded(make_snapshot(default_zone="internal"))
    elif boundary == "failed":
        old.emit_failed(SSHConnectionError("web01"))
    else:
        old.emit_finished()

    assert controller.session_view("web01") == before
    assert changed == []
    assert errors == []


def test_disconnect_increments_generation_cancels_and_clears_sudo_immediately(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, _ = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    old_generation = controller.session_view("web01").generation
    assert controller.provide_sudo_password("web01", old_generation, "sudo-web-secret")

    controller.disconnect("web01")
    view = controller.session_view("web01")
    assert view.generation == old_generation + 1
    assert view.status is ConnectionStatus.DISCONNECTED
    assert view.snapshot is None
    assert not secrets_in(view)
    assert scheduler.cancelled[-1] == "web01"

    scheduler.pending("web01", "disconnect").run()
    assert manager_factory.instances["web01"][0].disconnect_calls == 1


def test_invalidated_pending_connect_never_creates_or_adopts_manager(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, _ = dependencies
    controller.connect("web01")
    old = scheduler.pending("web01", "connect")
    controller.disconnect("web01")
    old.run()
    assert controller.session_view("web01").snapshot is None
    assert manager_factory.instances == {}


def test_reconnect_closes_old_manager_then_builds_a_new_connection(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    old_manager = manager_factory.instances["web01"][0]
    old_generation = controller.session_view("web01").generation

    controller.reconnect("web01")
    assert controller.session_view("web01").generation == old_generation + 1
    assert controller.session_view("web01").status is ConnectionStatus.CONNECTING
    scheduler.pending("web01", "reconnect").run()

    assert old_manager.disconnect_calls == 1
    assert len(manager_factory.instances["web01"]) == 2
    assert manager_factory.instances["web01"][1] is not old_manager
    assert len(service_factory.instances["web01"]) == 2
    assert controller.session_view("web01").status is ConnectionStatus.CONNECTED


def test_unknown_host_key_emits_only_safe_challenge_for_matching_server(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, _ = dependencies
    challenge = SimpleNamespace(
        host="web01.example.test",
        port=22,
        algorithm="ssh-ed25519",
        fingerprint_sha256="SHA256:safe-fingerprint",
    )
    manager_factory.next_errors["web01"] = UnknownHostKeyError(challenge)
    requests: list[tuple[str, object]] = []
    controller.host_key_required.connect(
        lambda server_id, value: requests.append((server_id, value))
    )

    controller.connect("web01")
    scheduler.pending("web01", "connect").run()

    assert requests == [("web01", challenge)]
    assert controller.session_view("web01").status is ConnectionStatus.HOST_KEY_ERROR
    assert not secrets_in(requests)


def test_sudo_required_emits_frozen_password_free_request(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    requests: list[tuple[str, object]] = []
    controller.sudo_password_required.connect(
        lambda server_id, request: requests.append((server_id, request))
    )
    controller.connect("web01")
    service_factory.next_load_errors["web01"] = SudoAuthenticationRequiredError(
        "web01", "load_snapshot"
    )
    scheduler.pending("web01", "connect").run()

    assert len(requests) == 1
    server_id, request = requests[0]
    assert server_id == "web01"
    assert request.server_id == "web01"
    assert request.operation == "connect"
    assert not hasattr(request, "password")
    assert not secrets_in(request)


def test_rejected_sudo_authentication_clears_cache_and_reports_permission_state(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    service_factory.next_load_errors["web01"] = SudoAuthenticationError(
        "web01", "load_snapshot"
    )
    controller.connect("web01")
    generation = controller.session_view("web01").generation
    controller.provide_sudo_password("web01", generation, "sudo-web-secret")
    scheduler.pending("web01", "connect").run()

    assert controller.session_view("web01").status is ConnectionStatus.PERMISSION_ERROR
    assert not secrets_in(controller.session_view("web01"))
    assert not controller.provide_sudo_password(
        "web01", generation - 1, "sudo-ignored-secret"
    )


def test_authentication_failure_changes_only_matching_session_and_clears_sudo(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, _ = dependencies
    controller.connect("db01")
    _finish_connect(controller, scheduler, "db01")
    manager_factory.next_errors["web01"] = SSHAuthenticationError("web01")
    errors: list[tuple[str, object]] = []
    controller.error_raised.connect(lambda server_id, error: errors.append((server_id, error)))

    controller.connect("web01")
    generation = controller.session_view("web01").generation
    controller.provide_sudo_password("web01", generation, "sudo-web-secret")
    scheduler.pending("web01", "connect").run()

    assert controller.session_view("web01").status is ConnectionStatus.AUTHENTICATION_FAILED
    assert controller.session_view("db01").status is ConnectionStatus.CONNECTED
    assert controller.session_view("db01").snapshot is not None
    assert errors and errors[-1][0] == "web01"
    assert not secrets_in(errors)


def test_refresh_preserves_independent_snapshot_and_marks_failure_stale(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    controller.connect("db01")
    _finish_connect(controller, scheduler, "web01")
    _finish_connect(controller, scheduler, "db01")
    db_before = controller.session_view("db01").snapshot
    web_service = service_factory.instances["web01"][0]
    web_service.next_load_error = RuntimeError("bounded read failed")

    controller.refresh("web01")
    scheduler.pending("web01", "refresh").run()

    assert controller.session_view("web01").snapshot is not None
    assert controller.session_view("web01").snapshot.stale
    assert controller.session_view("db01").snapshot == db_before


def test_refresh_ssh_disconnect_detaches_and_queues_manager_close(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    manager = manager_factory.instances["web01"][0]
    service_factory.instances["web01"][0].next_load_error = SSHConnectionError(
        "web01", "connection lost"
    )

    controller.refresh("web01")
    scheduler.pending("web01", "refresh").run()

    assert controller.session_view("web01").status is ConnectionStatus.CONNECTION_ERROR
    close = scheduler.pending("web01", "close_failed_connection")
    close.run()
    assert manager.disconnect_calls == 1
    controller.connect("web01")
    scheduler.pending("web01", "connect").run()
    assert len(manager_factory.instances["web01"]) == 2


def test_firewalld_read_failure_requires_reconnect_instead_of_overwriting_manager(
    controller, dependencies
) -> None:
    from app.utils.errors import FirewalldNotRunningError

    _, scheduler, manager_factory, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    old_manager = manager_factory.instances["web01"][0]
    service_factory.instances["web01"][0].next_load_error = FirewalldNotRunningError(
        "web01", "get_state"
    )
    controller.refresh("web01")
    scheduler.pending("web01", "refresh").run()

    assert controller.session_view("web01").status is ConnectionStatus.FIREWALLD_NOT_RUNNING
    with pytest.raises(RuntimeError):
        controller.connect("web01")

    controller.reconnect("web01")
    scheduler.pending("web01", "reconnect").run()
    assert old_manager.disconnect_calls == 1
    assert len(manager_factory.instances["web01"]) == 2


def test_reconnect_rejects_an_active_service_operation_without_cancelling_it(
    controller, dependencies
) -> None:
    _, scheduler, _, _ = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    refresh = controller.refresh("web01")

    with pytest.raises(RuntimeError):
        controller.reconnect("web01")

    assert scheduler.cancelled == []
    assert refresh is not scheduler.pending("web01", "refresh")


def test_test_connection_runs_on_live_service_without_replacing_snapshot(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    before = controller.session_view("web01").snapshot
    generation = controller.session_view("web01").generation
    controller.provide_sudo_password("web01", generation, "sudo-web-secret")

    results: list[object] = []
    handle = controller.test_connection("web01")
    handle.succeeded.connect(
        lambda server_id, generation, operation, value: results.append(value)
    )
    scheduler.pending("web01", "test_connection").run()

    assert results[0].hostname == "web01"
    assert service_factory.instances["web01"][0].test_calls == ["sudo-web-secret"]
    assert controller.session_view("web01").snapshot == before


def test_unknown_server_and_invalid_transitions_are_rejected_synchronously(
    controller, dependencies
) -> None:
    _, scheduler, _, _ = dependencies
    with pytest.raises(KeyError):
        controller.session_view("unknown")
    with pytest.raises(KeyError):
        controller.connect("unknown")
    with pytest.raises(RuntimeError):
        controller.disconnect("web01")
    controller.connect("web01")
    with pytest.raises(RuntimeError):
        controller.connect("web01")
    with pytest.raises(RuntimeError):
        controller.refresh("web01")
    assert len(scheduler.handles) == 1


def test_invalid_reload_is_transactional_and_emits_safe_error(
    controller, dependencies
) -> None:
    config_manager, scheduler, _, _ = dependencies
    before = controller.sessions()
    selected = controller.selected_server_id
    errors: list[tuple[str, object]] = []
    controller.error_raised.connect(lambda server_id, error: errors.append((server_id, error)))
    config_manager.next_load_error = ConfigurationError("invalid YAML")

    result = controller.reload_configuration()

    assert result is None
    assert controller.sessions() == before
    assert controller.selected_server_id == selected
    assert scheduler.handles == []
    assert len(errors) == 1
    assert errors[0][0] == ""
    assert isinstance(errors[0][1], ConfigurationError)


def test_valid_reload_preserves_unchanged_replaces_changed_and_orders_new_profiles(
    controller, dependencies
) -> None:
    config_manager, scheduler, manager_factory, service_factory = dependencies
    controller.connect("web01")
    controller.connect("db01")
    _finish_connect(controller, scheduler, "web01")
    _finish_connect(controller, scheduler, "db01")
    web_manager = manager_factory.instances["web01"][0]
    db_manager = manager_factory.instances["db01"][0]
    web_service = service_factory.instances["web01"][0]
    old_db_generation = controller.session_view("db01").generation
    config_manager.current = LoadedConfig(
        config_manager.current.application,
        (
            make_server("new01"),
            make_server("web01"),
            make_server("db01", host="db01-new.example.test"),
        ),
    )

    diff = controller.reload_configuration()

    assert diff is not None
    assert diff.unchanged == ("web01",)
    assert diff.changed == ("db01",)
    assert diff.added == ("new01",)
    assert tuple(view.server_id for view in controller.sessions()) == (
        "new01",
        "web01",
        "db01",
    )
    assert controller.session_view("web01").status is ConnectionStatus.CONNECTED
    assert controller.session_view("db01").generation == old_db_generation + 1
    assert controller.session_view("db01").status is ConnectionStatus.DISCONNECTED
    assert controller.session_view("db01").snapshot is None
    assert controller.session_view("new01").status is ConnectionStatus.DISCONNECTED
    assert manager_factory.instances["web01"] == [web_manager]
    assert service_factory.instances["web01"] == [web_service]
    assert manager_factory.instances["db01"] == [db_manager]
    assert scheduler.cancelled[-1] == "db01"
    scheduler.pending("db01", "close_replaced_session").run()
    assert db_manager.disconnect_calls == 1


def test_reload_removal_closes_resources_and_selects_first_remaining_profile(
    controller, dependencies
) -> None:
    config_manager, scheduler, manager_factory, _ = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    manager = manager_factory.instances["web01"][0]
    controller.select("web01")
    selected: list[str] = []
    controller.selection_changed.connect(selected.append)
    config_manager.current = make_loaded("db01", "new01")

    diff = controller.reload_configuration()

    assert diff is not None and diff.removed == ("web01",)
    assert controller.selected_server_id == "db01"
    assert selected == ["db01"]
    scheduler.pending("web01", "close_removed_session").run()
    assert manager.disconnect_calls == 1


def test_removed_then_readded_id_never_accepts_pre_removal_job_result(
    controller, dependencies
) -> None:
    config_manager, scheduler, manager_factory, _ = dependencies
    public_handle = controller.connect("web01")
    old_handle = scheduler.pending("web01", "connect")
    old_generation = public_handle.generation
    config_manager.current = make_loaded("db01")
    controller.reload_configuration()
    config_manager.current = make_loaded("web01", "db01")
    controller.reload_configuration()
    readded = controller.session_view("web01")
    assert readded.status is ConnectionStatus.DISCONNECTED
    assert readded.generation > old_generation

    old_handle.run()

    assert controller.session_view("web01").status is ConnectionStatus.DISCONNECTED
    assert controller.session_view("web01").snapshot is None
    assert manager_factory.instances == {}


def test_select_is_deterministic_and_does_not_connect(controller, dependencies) -> None:
    _, scheduler, _, _ = dependencies
    changed: list[str] = []
    controller.selection_changed.connect(changed.append)
    controller.select("db01")
    controller.select("db01")
    assert controller.selected_server_id == "db01"
    assert changed == ["db01"]
    assert scheduler.handles == []


def test_real_scheduler_keeps_remote_work_off_controller_thread_and_signals_on_it(
    qtbot: Any,
) -> None:
    from app.controllers.server_controller import ServerController

    config_manager = FakeConfigManager(make_loaded("web01"))
    scheduler = OperationScheduler(max_threads=1)
    manager_factory = ManagerFactory()
    service_factory = ServiceFactory()
    entered = Event()
    manager_factory.connect_entered["web01"] = entered
    controller = ServerController(
        config_manager, scheduler, manager_factory, service_factory
    )
    callback_threads: list[QThread] = []
    controller.session_changed.connect(
        lambda server_id: callback_threads.append(QThread.currentThread())
    )

    public_events: list[tuple[object, ...]] = []
    public_threads: list[QThread] = []
    handle = controller.connect("web01")
    handle.started.connect(
        lambda *event: (
            public_events.append(("started", *event)),
            public_threads.append(QThread.currentThread()),
        )
    )
    handle.succeeded.connect(
        lambda *event: (
            public_events.append(("succeeded", *event)),
            public_threads.append(QThread.currentThread()),
        )
    )
    handle.finished.connect(
        lambda *event: (
            public_events.append(("finished", *event)),
            public_threads.append(QThread.currentThread()),
        )
    )
    assert entered.wait(1)
    qtbot.waitUntil(
        lambda: controller.session_view("web01").status
        is ConnectionStatus.CONNECTED,
        timeout=3000,
    )
    assert scheduler.wait_for_done(3000)
    qtbot.waitUntil(lambda: len(public_events) == 3, timeout=3000)
    manager = manager_factory.instances["web01"][0]
    service = service_factory.instances["web01"][0]
    assert manager.connect_thread is not controller.thread()
    assert service.load_threads and all(
        thread is not controller.thread() for thread in service.load_threads
    )
    assert callback_threads and all(thread is controller.thread() for thread in callback_threads)
    assert [event[:4] for event in public_events] == [
        ("started", "web01", 0, "connect"),
        ("succeeded", "web01", 0, "connect"),
        ("finished", "web01", 0, "connect"),
    ]
    assert all(thread is controller.thread() for thread in public_threads)
    assert "secret" not in repr(public_events[1][4])

    controller.refresh("web01")
    qtbot.waitUntil(lambda: not scheduler.is_busy("web01"), timeout=3000)
    controller.test_connection("web01")
    qtbot.waitUntil(lambda: not scheduler.is_busy("web01"), timeout=3000)
    controller.disconnect("web01")
    qtbot.waitUntil(lambda: not scheduler.is_busy("web01"), timeout=3000)
    assert scheduler.wait_for_done(3000)
    assert len(service.load_threads) == 2
    assert service.test_threads and all(
        thread is not controller.thread() for thread in service.test_threads
    )
    assert manager.disconnect_thread is not controller.thread()


def test_disconnect_observably_drops_cached_sudo_before_next_connection(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    generation = controller.session_view("web01").generation
    assert controller.provide_sudo_password("web01", generation, "sudo-web-secret")
    controller.disconnect("web01")
    scheduler.pending("web01", "disconnect").run()

    controller.connect("web01")
    scheduler.pending("web01", "connect").run()

    assert service_factory.instances["web01"][1].load_calls == [None]


def test_shutdown_invalidates_all_sessions_clears_secrets_and_queues_closes(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, _ = dependencies
    for server_id in ("web01", "db01"):
        controller.connect(server_id)
        _finish_connect(controller, scheduler, server_id)
        generation = controller.session_view(server_id).generation
        controller.provide_sudo_password(server_id, generation, f"sudo-{server_id}-secret")

    drained = controller.shutdown(timeout_ms=123)

    assert drained
    assert all(view.status is ConnectionStatus.DISCONNECTED for view in controller.sessions())
    assert not secrets_in(controller.sessions())
    assert scheduler.wait_timeouts == [123]
    assert all(
        manager.disconnect_calls == 1
        for instances in manager_factory.instances.values()
        for manager in instances
    )


@pytest.mark.parametrize(
    "connect_error",
    [None, SSHConnectionError("web01", "connection failed")],
)
def test_shutdown_closes_inflight_connection_without_qt_callback_delivery(
    qtbot: Any, connect_error: Exception | None
) -> None:
    from app.controllers.server_controller import ServerController

    class ShutdownObservingScheduler(OperationScheduler):
        def __init__(self) -> None:
            super().__init__(max_threads=1)
            self.cancel_seen = Event()

        def cancel_pending(self, server_id: str) -> None:
            self.cancel_seen.set()
            super().cancel_pending(server_id)

    config_manager = FakeConfigManager(make_loaded("web01"))
    scheduler = ShutdownObservingScheduler()
    manager_factory = ManagerFactory()
    service_factory = ServiceFactory()
    entered = Event()
    release = Event()
    manager_factory.connect_entered["web01"] = entered
    manager_factory.connect_release["web01"] = release
    if connect_error is not None:
        manager_factory.next_errors["web01"] = connect_error
    controller = ServerController(
        config_manager, scheduler, manager_factory, service_factory
    )
    controller.connect("web01")
    assert entered.wait(1)

    def release_after_invalidation() -> None:
        assert scheduler.cancel_seen.wait(2)
        release.set()

    releaser = Thread(target=release_after_invalidation)
    releaser.start()
    assert controller.shutdown(timeout_ms=3000)
    releaser.join(2)
    assert not releaser.is_alive()

    manager = manager_factory.instances["web01"][0]
    assert manager.disconnect_calls == 1
    assert manager.disconnect_thread is not controller.thread()
    view = controller.session_view("web01")
    assert view.status is ConnectionStatus.DISCONNECTED
    assert view.snapshot is None
    assert not secrets_in(view)
    assert scheduler.wait_for_done(100)


def test_shutdown_reclaims_queued_disconnect_and_closes_manager_once(qtbot: Any) -> None:
    controller, _, scheduler, manager_factory = _connected_real_controller(qtbot)
    manager = manager_factory.instances["web01"][0]
    release_pool = _saturate_scheduler(scheduler)

    public_handle = controller.disconnect("web01")
    releaser = Thread(
        target=_release_after_second_web_cancel,
        args=(scheduler, release_pool),
    )
    releaser.start()

    assert controller.shutdown(timeout_ms=3000)
    releaser.join(2)
    assert not releaser.is_alive()
    disconnect_calls = manager.disconnect_calls
    assert disconnect_calls == 1
    assert manager.disconnect_thread is not controller.thread()
    assert not hasattr(public_handle, "work")
    assert not secrets_in(controller.sessions())
    assert controller._open_close_tokens("web01") == ()


def test_shutdown_reclaims_queued_reconnect_without_adopting_new_manager(
    qtbot: Any,
) -> None:
    controller, _, scheduler, manager_factory = _connected_real_controller(qtbot)
    old_manager = manager_factory.instances["web01"][0]
    release_pool = _saturate_scheduler(scheduler)

    public_handle = controller.reconnect("web01")
    releaser = Thread(
        target=_release_after_second_web_cancel,
        args=(scheduler, release_pool),
    )
    releaser.start()

    assert controller.shutdown(timeout_ms=3000)
    releaser.join(2)
    assert not releaser.is_alive()
    disconnect_calls = old_manager.disconnect_calls
    assert disconnect_calls == 1
    assert old_manager.disconnect_thread is not controller.thread()
    assert manager_factory.instances["web01"] == [old_manager]
    assert controller.session_view("web01").status is ConnectionStatus.DISCONNECTED
    assert not hasattr(public_handle, "work")
    assert controller._open_close_tokens("web01") == ()


def test_reload_resubmits_private_close_cancelled_by_later_reload(qtbot: Any) -> None:
    controller, config_manager, scheduler, manager_factory = (
        _connected_real_controller(qtbot)
    )
    manager = manager_factory.instances["web01"][0]
    release_pool = _saturate_scheduler(scheduler)
    config_manager.current = LoadedConfig(
        config_manager.current.application,
        (make_server("web01", host="replacement-one.example.test"),),
    )
    controller.reload_configuration()
    config_manager.current = make_loaded()
    controller.reload_configuration()
    release_pool.set()

    assert scheduler.wait_for_done(3000)
    disconnect_calls = manager.disconnect_calls
    assert disconnect_calls == 1
    assert manager.disconnect_thread is not controller.thread()
    assert controller._open_close_tokens("web01") == ()


def test_shutdown_duplicate_cleanup_after_cancel_start_race_closes_once(
    qtbot: Any,
) -> None:
    controller, _, scheduler, manager_factory = _connected_real_controller(qtbot)
    manager = manager_factory.instances["web01"][0]
    disconnect_entered = Event()
    disconnect_release = Event()
    manager.disconnect_entered = disconnect_entered
    manager.disconnect_release = disconnect_release

    controller.disconnect("web01")
    assert disconnect_entered.wait(1)

    def release_after_shutdown_resubmits() -> None:
        assert scheduler.second_web_cancel.wait(2)
        disconnect_release.set()

    releaser = Thread(target=release_after_shutdown_resubmits)
    releaser.start()
    assert controller.shutdown(timeout_ms=3000)
    releaser.join(2)
    assert not releaser.is_alive()

    disconnect_calls = manager.disconnect_calls
    assert disconnect_calls == 1
    assert manager.disconnect_thread is not controller.thread()
    assert ("web01", "shutdown_disconnect") in scheduler.submitted_operations
    assert controller._open_close_tokens("web01") == ()


def test_confirmed_unknown_host_key_is_revalidated_trusted_then_freshly_connected(
    qapp,
) -> None:
    from app.controllers.server_controller import ServerController

    del qapp
    config_manager = FakeConfigManager(make_loaded("web01"))
    scheduler = ManualScheduler()
    manager_factory = ManagerFactory()
    service_factory = ServiceFactory()
    host_keys = RecordingHostKeyStore()
    challenge = SimpleNamespace(
        host="web01.example.test",
        port=22,
        algorithm="ssh-ed25519",
        fingerprint_sha256="SHA256:safe-fingerprint",
    )
    manager_factory.next_errors["web01"] = UnknownHostKeyError(challenge)
    controller = ServerController(
        config_manager,
        scheduler,
        manager_factory,
        service_factory,
        host_key_store=host_keys,
    )
    requests: list[tuple[str, object]] = []
    controller.host_key_required.connect(
        lambda server_id, value: requests.append((server_id, value))
    )

    controller.connect("web01")
    scheduler.pending("web01", "connect").run()
    generation = controller.session_view("web01").generation

    assert requests == [("web01", challenge)]
    assert controller.resolve_host_key("web01", generation, challenge, True)
    assert host_keys.trust_calls == [challenge]
    assert controller.session_view("web01").generation == generation + 1
    assert len(manager_factory.instances["web01"]) == 1

    scheduler.pending("web01", "connect").run()
    assert len(manager_factory.instances["web01"]) == 2
    assert controller.session_view("web01").status is ConnectionStatus.CONNECTED


def _emit_unknown_host_failure_with_inline_trust(
    controller,
    scheduler: ManualScheduler,
    challenge: object,
) -> tuple[object, object, list[bool]]:
    resolutions: list[bool] = []
    controller.host_key_required.connect(
        lambda server_id, received: resolutions.append(
            controller.resolve_host_key(
                server_id,
                controller.session_view(server_id).generation,
                received,
                True,
            )
        )
    )
    public = controller.connect("web01")
    original = scheduler.pending("web01", "connect")
    original.has_run = True
    original.emit_started()
    with pytest.raises(UnknownHostKeyError) as raised:
        original.work()
    assert raised.value.challenge is challenge
    original.emit_failed(raised.value)
    return original, public, resolutions


def test_inline_host_key_acceptance_defers_one_fresh_connect_until_original_finish(
    qapp,
) -> None:
    from app.controllers.server_controller import ServerController

    del qapp
    scheduler = ManualScheduler()
    manager_factory = ManagerFactory()
    host_keys = RecordingHostKeyStore()
    challenge = SimpleNamespace(
        host="web01.example.test",
        port=22,
        algorithm="ssh-ed25519",
        fingerprint_sha256="SHA256:safe-fingerprint",
    )
    manager_factory.next_errors["web01"] = UnknownHostKeyError(challenge)
    controller = ServerController(
        FakeConfigManager(make_loaded("web01")),
        scheduler,
        manager_factory,
        ServiceFactory(),
        host_key_store=host_keys,
    )

    original, public, resolutions = _emit_unknown_host_failure_with_inline_trust(
        controller, scheduler, challenge
    )

    assert resolutions == [True]
    assert host_keys.trust_calls == [challenge]
    assert [handle.operation for handle in scheduler.handles] == ["connect"]
    assert controller.session_view("web01").generation == 0
    assert not controller.resolve_host_key("web01", 0, challenge, True)
    finished_job_counts: list[int] = []
    public.finished.connect(
        lambda *_event: finished_job_counts.append(len(scheduler.handles))
    )

    original.emit_finished()

    assert finished_job_counts == [1]
    assert [handle.operation for handle in scheduler.handles] == [
        "connect",
        "connect",
    ]
    view = controller.session_view("web01")
    assert view.generation == 1
    assert view.status is ConnectionStatus.CONNECTING
    assert view.latest_error is None
    retry_attempt = controller._sessions["web01"]._connection_attempt
    assert retry_attempt is not None

    original.emit_finished()
    assert len(scheduler.handles) == 2
    assert controller._sessions["web01"]._connection_attempt is retry_attempt


@pytest.mark.parametrize(
    "lifecycle",
    [
        "disconnect",
        "reconnect",
        "reload_changed",
        "reload_removed",
        "shutdown",
        "selection",
    ],
)
def test_lifecycle_before_original_finish_cancels_trusted_retry(
    qapp, lifecycle: str
) -> None:
    from app.controllers.server_controller import ServerController

    del qapp
    scheduler = ManualScheduler()
    manager_factory = ManagerFactory()
    host_keys = RecordingHostKeyStore()
    challenge = SimpleNamespace(
        host="web01.example.test",
        port=22,
        algorithm="ssh-ed25519",
        fingerprint_sha256="SHA256:safe-fingerprint",
    )
    manager_factory.next_errors["web01"] = UnknownHostKeyError(challenge)
    config_manager = FakeConfigManager(make_loaded("web01", "db01"))
    controller = ServerController(
        config_manager,
        scheduler,
        manager_factory,
        ServiceFactory(),
        host_key_store=host_keys,
    )
    original, _public, resolutions = _emit_unknown_host_failure_with_inline_trust(
        controller, scheduler, challenge
    )
    assert resolutions == [True]
    assert host_keys.trust_calls == [challenge]

    if lifecycle == "disconnect":
        controller.disconnect("web01")
    elif lifecycle == "reconnect":
        with pytest.raises(RuntimeError, match="while busy"):
            controller.reconnect("web01")
    elif lifecycle == "reload_changed":
        config_manager.current = LoadedConfig(
            config_manager.current.application,
            (
                make_server("web01", host="replacement.example.test"),
                make_server("db01"),
            ),
        )
        controller.reload_configuration()
    elif lifecycle == "reload_removed":
        config_manager.current = make_loaded("db01")
        controller.reload_configuration()
    elif lifecycle == "shutdown":
        assert controller.shutdown(timeout_ms=100)
    else:
        controller.select("db01")

    original.emit_finished()

    assert sum(handle.operation == "connect" for handle in scheduler.handles) == 1


def test_busy_reconnect_cancels_trusted_retry_without_consuming_sudo_request(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    service = service_factory.instances["web01"][0]
    service.next_load_error = SudoAuthenticationRequiredError(
        "web01", "list_runtime_zones"
    )
    requests: list[object] = []
    controller.sudo_password_required.connect(
        lambda _server_id, request: requests.append(request)
    )
    controller.refresh("web01")
    refresh = scheduler.pending("web01", "refresh")
    refresh.has_run = True
    refresh.emit_started()
    with pytest.raises(SudoAuthenticationRequiredError) as raised:
        refresh.work()
    refresh.emit_failed(raised.value)
    request = requests[0]

    with pytest.raises(RuntimeError, match="while busy"):
        controller.reconnect("web01")

    assert controller.resolve_sudo_password(request, "sudo-web-secret")


def _real_controller_with_blocked_trusted_retry(qtbot):
    from app.controllers.server_controller import ServerController

    scheduler = _CancellationObservingScheduler()
    manager_factory = ManagerFactory()
    host_keys = RecordingHostKeyStore()
    challenge = SimpleNamespace(
        host="web01.example.test",
        port=22,
        algorithm="ssh-ed25519",
        fingerprint_sha256="SHA256:safe-fingerprint",
    )
    manager_factory.next_errors["web01"] = UnknownHostKeyError(challenge)
    fresh_entered = Event()
    fresh_release = Event()
    controller = ServerController(
        FakeConfigManager(make_loaded("web01")),
        scheduler,
        manager_factory,
        ServiceFactory(),
        host_key_store=host_keys,
    )

    def trust_inline(server_id: str, received: object) -> None:
        manager_factory.connect_entered[server_id] = fresh_entered
        manager_factory.connect_release[server_id] = fresh_release
        assert controller.resolve_host_key(
            server_id,
            controller.session_view(server_id).generation,
            received,
            True,
        )

    controller.host_key_required.connect(trust_inline)
    controller.connect("web01")
    qtbot.waitUntil(fresh_entered.is_set, timeout=3000)
    qtbot.waitUntil(
        lambda: len(manager_factory.instances["web01"]) == 2,
        timeout=3000,
    )
    return controller, scheduler, manager_factory, fresh_release


def test_disconnect_invalidates_blocked_trusted_connect_and_worker_closes_once(
    qtbot,
) -> None:
    controller, scheduler, manager_factory, fresh_release = (
        _real_controller_with_blocked_trusted_retry(qtbot)
    )
    fresh_manager = manager_factory.instances["web01"][1]

    controller.disconnect("web01")
    fresh_release.set()

    assert scheduler.wait_for_done(3000)
    if fresh_manager.disconnect_calls != 1:
        pytest.fail(
            "blocked trusted reconnect was not closed exactly once by its worker; "
            f"disconnect calls: {fresh_manager.disconnect_calls}"
        )
    assert fresh_manager.disconnect_thread is not controller.thread()
    assert controller.session_view("web01").status is ConnectionStatus.DISCONNECTED
    assert controller._open_close_tokens("web01") == ()


def test_shutdown_invalidates_blocked_trusted_connect_without_qt_callback_cleanup(
    qtbot,
) -> None:
    controller, scheduler, manager_factory, fresh_release = (
        _real_controller_with_blocked_trusted_retry(qtbot)
    )
    fresh_manager = manager_factory.instances["web01"][1]

    def release_after_shutdown_cancels() -> None:
        assert scheduler.web_cancelled.wait(2)
        fresh_release.set()

    releaser = Thread(target=release_after_shutdown_cancels)
    releaser.start()
    assert controller.shutdown(timeout_ms=3000)
    releaser.join(2)
    assert not releaser.is_alive()

    if fresh_manager.disconnect_calls != 1:
        pytest.fail(
            "shutdown relied on a Qt callback to close the trusted reconnect; "
            f"disconnect calls: {fresh_manager.disconnect_calls}"
        )
    assert fresh_manager.disconnect_thread is not controller.thread()
    assert controller._open_close_tokens("web01") == ()


def test_host_key_cancel_stale_or_mismatched_decision_never_trusts_or_reconnects(
    qapp,
) -> None:
    from app.controllers.server_controller import ServerController

    del qapp
    config_manager = FakeConfigManager(make_loaded("web01"))
    scheduler = ManualScheduler()
    manager_factory = ManagerFactory()
    host_keys = RecordingHostKeyStore()
    challenge = SimpleNamespace(
        host="web01.example.test",
        port=22,
        algorithm="ssh-ed25519",
        fingerprint_sha256="SHA256:safe-fingerprint",
    )
    manager_factory.next_errors["web01"] = UnknownHostKeyError(challenge)
    controller = ServerController(
        config_manager,
        scheduler,
        manager_factory,
        ServiceFactory(),
        host_key_store=host_keys,
    )
    controller.connect("web01")
    scheduler.pending("web01", "connect").run()
    generation = controller.session_view("web01").generation
    initial_jobs = len(scheduler.handles)

    assert not controller.resolve_host_key("web01", generation, challenge, False)
    assert not controller.resolve_host_key(
        "web01",
        generation,
        SimpleNamespace(**vars(challenge)),
        True,
    )
    assert not controller.resolve_host_key("web01", generation - 1, challenge, True)
    assert host_keys.trust_calls == []
    assert len(scheduler.handles) == initial_jobs


def test_host_key_store_failure_is_sanitized_and_never_reconnects(qapp) -> None:
    from app.controllers.server_controller import ServerController

    del qapp
    config_manager = FakeConfigManager(make_loaded("web01"))
    scheduler = ManualScheduler()
    manager_factory = ManagerFactory()
    challenge = SimpleNamespace(
        host="web01.example.test",
        port=22,
        algorithm="ssh-ed25519",
        fingerprint_sha256="SHA256:safe-fingerprint",
    )
    manager_factory.next_errors["web01"] = UnknownHostKeyError(challenge)

    class FailingHostKeyStore:
        def trust(self, _challenge: object) -> None:
            raise HostKeyStoreError()

    controller = ServerController(
        config_manager,
        scheduler,
        manager_factory,
        ServiceFactory(),
        host_key_store=FailingHostKeyStore(),
    )
    errors: list[object] = []
    controller.error_raised.connect(lambda _server, error: errors.append(error))
    controller.connect("web01")
    scheduler.pending("web01", "connect").run()
    generation = controller.session_view("web01").generation
    initial_jobs = len(scheduler.handles)

    assert not controller.resolve_host_key("web01", generation, challenge, True)
    assert len(scheduler.handles) == initial_jobs
    assert errors[-1].category == "host_key_store"
    assert "known_hosts" not in errors[-1].message


def test_changed_host_key_never_emits_a_trust_capable_request(controller, dependencies):
    _, scheduler, manager_factory, _ = dependencies
    manager_factory.next_errors["web01"] = ChangedHostKeyError(
        "web01.example.test", 22, "SHA256:expected", "SHA256:actual"
    )
    trust_requests: list[object] = []
    errors: list[object] = []
    controller.host_key_required.connect(lambda _server, value: trust_requests.append(value))
    controller.error_raised.connect(lambda _server, error: errors.append(error))

    controller.connect("web01")
    scheduler.pending("web01", "connect").run()

    assert trust_requests == []
    assert errors[-1].category == "host_key_changed"
    assert "SHA256" not in errors[-1].message


def test_sudo_acceptance_retries_exact_connect_once_with_memory_only_password(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, service_factory = dependencies
    service_factory.next_load_errors["web01"] = SudoAuthenticationRequiredError(
        "web01", "load_snapshot"
    )
    requests: list[object] = []
    controller.sudo_password_required.connect(
        lambda _server_id, request: requests.append(request)
    )

    controller.connect("web01")
    scheduler.pending("web01", "connect").run()

    assert len(requests) == 1
    request = requests[0]
    assert request.operation == "connect"
    assert not hasattr(request, "password")
    assert controller.resolve_sudo_password(request, "sudo-web-secret")
    retry_handle = scheduler.pending("web01", "connect")
    assert retry_handle.generation == request.generation + 1
    assert "secret" not in repr(retry_handle)

    retry_handle.run()
    assert len(manager_factory.instances["web01"]) == 2
    assert service_factory.instances["web01"][1].load_calls == ["sudo-web-secret"]
    assert controller.session_view("web01").status is ConnectionStatus.CONNECTED


def test_sudo_cancel_wrong_request_and_stale_generation_do_not_store_or_retry(
    controller, dependencies
) -> None:
    from app.controllers.server_controller import SudoPasswordRequest

    _, scheduler, _, service_factory = dependencies
    service_factory.next_load_errors["web01"] = SudoAuthenticationRequiredError(
        "web01", "load_snapshot"
    )
    requests: list[object] = []
    controller.sudo_password_required.connect(
        lambda _server_id, request: requests.append(request)
    )
    controller.connect("web01")
    scheduler.pending("web01", "connect").run()
    request = requests[0]
    initial_jobs = len(scheduler.handles)

    assert not controller.resolve_sudo_password(
        SudoPasswordRequest(request.server_id, request.generation, "refresh"),
        "sudo-wrong-secret",
    )
    assert not controller.resolve_sudo_password(
        SudoPasswordRequest(request.server_id, request.generation - 1, request.operation),
        "sudo-stale-secret",
    )
    assert not controller.resolve_sudo_password(request, None)
    assert len(scheduler.handles) == initial_jobs

    controller.connect("web01")
    scheduler.pending("web01", "connect").run()
    assert service_factory.instances["web01"][1].load_calls == [None]


def test_sudo_authentication_failure_clears_cache_and_never_prompts_in_a_loop(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    service_factory.next_load_errors["web01"] = SudoAuthenticationRequiredError(
        "web01", "load_snapshot"
    )
    requests: list[object] = []
    controller.sudo_password_required.connect(
        lambda _server_id, request: requests.append(request)
    )
    controller.connect("web01")
    scheduler.pending("web01", "connect").run()
    request = requests[0]
    service_factory.next_load_errors["web01"] = SudoAuthenticationError(
        "web01", "load_snapshot"
    )

    assert controller.resolve_sudo_password(request, "sudo-bad-secret")
    scheduler.pending("web01", "connect").run()

    assert len(requests) == 1
    assert controller.session_view("web01").status is ConnectionStatus.PERMISSION_ERROR
    controller.connect("web01")
    scheduler.pending("web01", "connect").run()
    assert service_factory.instances["web01"][2].load_calls == [None]


def test_sudo_refresh_retry_uses_same_generation_and_exact_logical_operation(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    service = service_factory.instances["web01"][0]
    service.next_load_error = SudoAuthenticationRequiredError(
        "web01", "list_runtime_zones"
    )
    requests: list[object] = []
    controller.sudo_password_required.connect(
        lambda _server_id, request: requests.append(request)
    )

    controller.refresh("web01")
    scheduler.pending("web01", "refresh").run()
    request = requests[0]
    assert request.operation == "refresh"
    assert controller.resolve_sudo_password(request, "sudo-web-secret")

    retry = scheduler.pending("web01", "refresh")
    assert retry.generation == request.generation
    retry.run()
    assert service.load_calls == [None, None, "sudo-web-secret"]
    assert controller.session_view("web01").status is ConnectionStatus.CONNECTED


def test_reload_runs_one_global_write_then_one_refresh_and_publishes_updated_snapshot(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    service = service_factory.instances["web01"][0]
    service.operation_trace.clear()
    service.next_snapshot = make_snapshot(server_id="web01", default_zone="internal")
    observed: list[tuple[object, object]] = []

    handle = controller.reload_firewalld("web01")
    handle.succeeded.connect(
        lambda _server_id, _generation, _operation, value: observed.append(
            (value, controller.session_view("web01").snapshot)
        )
    )
    scheduler.pending("web01", "reload_firewalld").run()

    assert service.reload_calls == [(ApplyTarget.BOTH, None)]
    assert service.operation_trace == ["reload_firewalld", "load_snapshot"]
    assert observed == [(service.next_reload_result, service.next_snapshot)]
    assert controller.session_view("web01").snapshot == service.next_snapshot


def test_failed_reload_result_refreshes_once_and_is_published_without_retry(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    service = service_factory.instances["web01"][0]
    service.operation_trace.clear()
    service.next_reload_result = CompositeOperationResult(
        operation="reload_firewalld",
        permanent=TargetResult(
            ApplyTarget.PERMANENT,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
            None,
            "The firewalld change failed.",
        ),
        runtime=TargetResult(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
            None,
            "The firewalld change failed.",
        ),
    )
    results: list[object] = []

    handle = controller.reload_firewalld("web01")
    handle.succeeded.connect(
        lambda _server_id, _generation, _operation, value: results.append(value)
    )
    scheduler.pending("web01", "reload_firewalld").run()

    assert service.reload_calls == [(ApplyTarget.BOTH, None)]
    assert service.operation_trace == ["reload_firewalld", "load_snapshot"]
    assert results == [service.next_reload_result]
    assert controller.session_view("web01").snapshot is not None
    assert not controller.session_view("web01").snapshot.stale


def test_sudo_reload_retry_is_same_generation_exact_operation_and_happens_once(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    service = service_factory.instances["web01"][0]
    service.operation_trace.clear()
    service.next_reload_error = SudoAuthenticationRequiredError(
        "web01", "reload_firewalld"
    )
    requests: list[object] = []
    controller.sudo_password_required.connect(
        lambda _server_id, request: requests.append(request)
    )

    controller.reload_firewalld("web01")
    scheduler.pending("web01", "reload_firewalld").run()
    request = requests[0]
    assert request.operation == "reload_firewalld"
    assert controller.resolve_sudo_password(request, "sudo-web-secret")

    retry = scheduler.pending("web01", "reload_firewalld")
    assert retry.generation == request.generation
    retry.run()

    assert service.reload_calls == [
        (ApplyTarget.BOTH, None),
        (ApplyTarget.BOTH, "sudo-web-secret"),
    ]
    assert service.operation_trace == [
        "reload_firewalld",
        "reload_firewalld",
        "load_snapshot",
    ]
    assert requests == [request]


def test_reload_transport_failure_uses_existing_terminal_detach_and_close_path(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    manager = manager_factory.instances["web01"][0]
    service_factory.instances["web01"][0].next_reload_error = SSHConnectionError(
        "web01", "connection lost"
    )

    controller.reload_firewalld("web01")
    scheduler.pending("web01", "reload_firewalld").run()

    view = controller.session_view("web01")
    assert view.status is ConnectionStatus.CONNECTION_ERROR
    assert view.snapshot is not None and view.snapshot.stale
    scheduler.pending("web01", "close_failed_connection").run()
    assert manager.disconnect_calls == 1


@pytest.mark.parametrize(
    "refresh_error",
    (
        SudoAuthenticationRequiredError("web01", "load_snapshot"),
        SudoAuthenticationError("web01", "load_snapshot"),
    ),
)
def test_reload_post_mutation_refresh_auth_failure_never_prompts_or_reloads(
    controller, dependencies, refresh_error: Exception
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    service = service_factory.instances["web01"][0]
    before = controller.session_view("web01").snapshot
    generation = controller.session_view("web01").generation
    assert controller.provide_sudo_password(
        "web01", generation, "sudo-cached-secret"
    )
    service.operation_trace.clear()
    service.next_load_error = refresh_error
    requests: list[object] = []
    results: list[object] = []
    failures: list[object] = []
    controller.sudo_password_required.connect(
        lambda _server_id, request: requests.append(request)
    )

    handle = controller.reload_firewalld("web01")
    handle.succeeded.connect(
        lambda _server_id, _generation, _operation, value: results.append(value)
    )
    controller.error_raised.connect(
        lambda _server_id, error: failures.append(error)
    )
    scheduler.pending("web01", "reload_firewalld").run()

    assert service.reload_calls == [
        (ApplyTarget.BOTH, "sudo-cached-secret"),
    ]
    assert service.operation_trace == ["reload_firewalld", "load_snapshot"]
    assert requests == []
    assert results == [service.next_reload_result]
    assert len(failures) == 1
    assert failures[0].category == "post_mutation_refresh"
    assert "secret" not in repr(failures[0])
    view = controller.session_view("web01")
    assert view.status is ConnectionStatus.CONNECTED
    assert view.snapshot is not None and view.snapshot.stale
    assert view.snapshot == make_snapshot(server_id="web01", stale=True)
    assert before is not None

    service.next_snapshot = make_snapshot(server_id="web01", default_zone="internal")
    controller.refresh("web01")
    scheduler.pending("web01", "refresh").run()
    assert service.load_calls[-1] is None
    assert len(service.reload_calls) == 1


def test_reload_post_mutation_verification_error_never_prompts_or_reloads(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    service = service_factory.instances["web01"][0]
    generation = controller.session_view("web01").generation
    assert controller.provide_sudo_password(
        "web01", generation, "sudo-cached-secret"
    )
    service.operation_trace.clear()
    service.next_reload_error = PostMutationVerificationError(
        "web01", "reload_firewalld"
    )
    requests: list[object] = []
    failures: list[object] = []
    controller.sudo_password_required.connect(
        lambda _server_id, request: requests.append(request)
    )

    handle = controller.reload_firewalld("web01")
    handle.failed.connect(
        lambda _server_id, _generation, _operation, error: failures.append(error)
    )
    scheduler.pending("web01", "reload_firewalld").run()

    assert service.reload_calls == [
        (ApplyTarget.BOTH, "sudo-cached-secret"),
    ]
    assert service.operation_trace == ["reload_firewalld"]
    assert requests == []
    assert len(failures) == 1
    assert failures[0].category == "post_mutation_verification"
    assert failures[0].message == (
        "Firewalld reloaded, but its running state could not be verified."
    )
    assert "secret" not in repr(failures[0])
    assert not hasattr(failures[0], "raw_error")
    view = controller.session_view("web01")
    assert view.status is ConnectionStatus.CONNECTED
    assert view.snapshot is not None and view.snapshot.stale

    service.next_snapshot = make_snapshot(server_id="web01", default_zone="internal")
    controller.refresh("web01")
    scheduler.pending("web01", "refresh").run()
    assert service.load_calls[-1] is None
    assert len(service.reload_calls) == 1
