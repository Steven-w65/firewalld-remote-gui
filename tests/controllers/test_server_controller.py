from __future__ import annotations

from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from threading import Event
from typing import Any

import pytest
from PySide6.QtCore import QThread

from app.config.models import LoadedConfig
from app.models.enums import ConnectionStatus
from app.utils.errors import (
    ConfigurationError,
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
    assert handle is scheduler.pending("web01", "connect")
    assert controller.session_view("web01").status is ConnectionStatus.CONNECTING
    assert controller.session_view("web01").busy_operation == "connect"
    assert controller.session_view("db01").status is ConnectionStatus.DISCONNECTED

    handle.run()
    service = service_factory_template.instances["web01"][0]
    assert service.load_calls == [None]
    assert controller.session_view("web01").snapshot == service.next_snapshot
    assert controller.session_view("web01").busy_operation is None
    assert changed


@pytest.mark.parametrize("boundary", ["started", "succeeded", "failed", "finished"])
def test_every_old_generation_signal_boundary_is_ignored(
    controller, dependencies, boundary: str
) -> None:
    _, scheduler, _, _ = dependencies
    old = controller.connect("web01")
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

    handle = controller.disconnect("web01")
    view = controller.session_view("web01")
    assert view.generation == old_generation + 1
    assert view.status is ConnectionStatus.DISCONNECTED
    assert view.snapshot is None
    assert not secrets_in(view)
    assert scheduler.cancelled[-1] == "web01"

    handle.run()
    assert manager_factory.instances["web01"][0].disconnect_calls == 1


def test_old_connect_success_is_closed_without_becoming_current(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, _ = dependencies
    old = controller.connect("web01")
    controller.disconnect("web01")
    resources = old.work()
    old.emit_succeeded(resources)
    assert controller.session_view("web01").snapshot is None
    cleanup = scheduler.pending("web01", "discard_stale_connection")
    cleanup.run()
    assert manager_factory.instances["web01"][0].disconnect_calls == 1


def test_reconnect_closes_old_manager_then_builds_a_new_connection(
    controller, dependencies
) -> None:
    _, scheduler, manager_factory, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    old_manager = manager_factory.instances["web01"][0]
    old_generation = controller.session_view("web01").generation

    handle = controller.reconnect("web01")
    assert controller.session_view("web01").generation == old_generation + 1
    assert controller.session_view("web01").status is ConnectionStatus.CONNECTING
    handle.run()

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
    assert request.operation == "load_snapshot"
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
    assert refresh is scheduler.pending("web01", "refresh")


def test_test_connection_runs_on_live_service_without_replacing_snapshot(
    controller, dependencies
) -> None:
    _, scheduler, _, service_factory = dependencies
    controller.connect("web01")
    _finish_connect(controller, scheduler, "web01")
    before = controller.session_view("web01").snapshot
    generation = controller.session_view("web01").generation
    controller.provide_sudo_password("web01", generation, "sudo-web-secret")

    handle = controller.test_connection("web01")
    result = handle.run()

    assert result.hostname == "web01"
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
    old_handle = controller.connect("web01")
    old_generation = old_handle.generation
    config_manager.current = make_loaded("db01")
    controller.reload_configuration()
    config_manager.current = make_loaded("web01", "db01")
    controller.reload_configuration()
    readded = controller.session_view("web01")
    assert readded.status is ConnectionStatus.DISCONNECTED
    assert readded.generation > old_generation

    old_resources = old_handle.work()
    old_handle.emit_succeeded(old_resources)

    assert controller.session_view("web01").status is ConnectionStatus.DISCONNECTED
    assert controller.session_view("web01").snapshot is None
    scheduler.pending("web01", "discard_stale_connection").run()
    assert manager_factory.instances["web01"][0].disconnect_calls == 1


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

    controller.connect("web01")
    assert entered.wait(1)
    qtbot.waitUntil(
        lambda: controller.session_view("web01").status
        is ConnectionStatus.CONNECTED,
        timeout=3000,
    )
    assert scheduler.wait_for_done(3000)
    manager = manager_factory.instances["web01"][0]
    service = service_factory.instances["web01"][0]
    assert manager.connect_thread is not controller.thread()
    assert service.load_threads and all(
        thread is not controller.thread() for thread in service.load_threads
    )
    assert callback_threads and all(thread is controller.thread() for thread in callback_threads)

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

    handles = controller.shutdown()

    assert len(handles) == 2
    assert all(view.status is ConnectionStatus.DISCONNECTED for view in controller.sessions())
    assert not secrets_in(controller.sessions())
    for handle in handles:
        handle.run()
    assert all(
        manager.disconnect_calls == 1
        for instances in manager_factory.instances.values()
        for manager in instances
    )
