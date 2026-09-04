from __future__ import annotations

from dataclasses import replace

import pytest

from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ControllerOperationError, ServerController
from app.firewalld.lockout import RiskLevel
from app.models.command import CommandResult, CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, ConnectionStatus, TargetStatus
from app.models.firewall import FirewallPort, FirewallSnapshot, ZoneState
from app.models.port import AddPortRequest, PortRow
from app.utils.errors import (
    FirewallCommandError,
    SSHConnectionError,
    SudoAuthenticationRequiredError,
)
from tests.controllers.fakes import (
    FakeConfigManager,
    ManagerFactory,
    ManualScheduler,
    ServiceFactory,
    make_loaded,
)


def _snapshot(
    *,
    runtime_ports: tuple[str, ...] = ("22",),
    permanent_ports: tuple[str, ...] = ("22",),
    stale: bool = False,
    include_permanent_zone: bool = True,
) -> FirewallSnapshot:
    return FirewallSnapshot(
        hostname="web01",
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        runtime_zones=(
            ZoneState(
                "public",
                ports=tuple(
                    FirewallPort(port, "tcp", "public", True, False)
                    for port in runtime_ports
                ),
            ),
        ),
        permanent_zones=(
            (
                ZoneState(
                    "public",
                    ports=tuple(
                        FirewallPort(port, "tcp", "public", False, True)
                        for port in permanent_ports
                    ),
                    permanent=True,
                ),
            )
            if include_permanent_zone
            else ()
        ),
        stale=stale,
    )


def _target(
    target: ApplyTarget,
    execution: TargetStatus,
    verification: TargetStatus,
    *,
    authentication_failed: bool = False,
) -> TargetResult:
    return TargetResult(
        target,
        execution,
        verification,
        None,
        "",
        authentication_failed=authentication_failed,
    )


@pytest.fixture
def connected(qapp):
    del qapp
    scheduler = ManualScheduler()
    managers = ManagerFactory()
    services = ServiceFactory()
    services.next_snapshots["web01"] = _snapshot()
    server_controller = ServerController(
        FakeConfigManager(make_loaded("web01", "db01")),
        scheduler,
        managers,
        services,
    )
    firewall_controller = FirewallController(server_controller)
    server_controller.connect("web01")
    scheduler.pending("web01", "connect").run_synchronously_for_test()
    service = services.instances["web01"][0]
    return firewall_controller, server_controller, scheduler, service, managers


def test_add_port_uses_current_inventory_and_exact_preview(connected) -> None:
    firewall, _, _, _, _ = connected
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.BOTH)

    preview = firewall.preview_add_port("web01", request)

    assert preview.operation == "Add Firewall Port"
    assert preview.resource == "8080/tcp"
    assert preview.target is ApplyTarget.BOTH
    assert preview.server_id == "web01"
    assert preview.generation == 0
    assert preview.risk.level is RiskLevel.NONE
    assert "incomplete" in " ".join(preview.risk.reasons).lower()


def test_remove_management_port_contains_every_conservative_warning(connected) -> None:
    firewall, _, _, _, _ = connected

    preview = firewall.preview_remove_port(
        "web01", PortRow("22", "tcp", "public", True, True), ApplyTarget.BOTH
    )

    assert preview.risk.is_high
    warning = " ".join(preview.risk.reasons)
    assert "management port 22" in warning
    assert "incomplete" in warning.lower()


@pytest.mark.parametrize(
    ("snapshot", "case_request"),
    (
        (_snapshot(stale=True), AddPortRequest("public", "8080", "tcp", ApplyTarget.BOTH)),
        (_snapshot(), AddPortRequest("missing", "8080", "tcp", ApplyTarget.RUNTIME)),
        (_snapshot(include_permanent_zone=False), AddPortRequest("public", "8080", "tcp", ApplyTarget.BOTH)),
        (_snapshot(runtime_ports=("22", "8080")), AddPortRequest("public", "8080", "tcp", ApplyTarget.BOTH)),
    ),
)
def test_add_preview_rejects_stale_unknown_target_inventory_or_duplicate(
    connected, snapshot, case_request
) -> None:
    firewall, server, scheduler, service, _ = connected
    service.next_snapshot = snapshot
    server.refresh("web01")
    scheduler.pending("web01", "refresh").run_synchronously_for_test()

    with pytest.raises((RuntimeError, ValueError)):
        firewall.preview_add_port("web01", case_request)


def test_preview_rejects_disconnected_missing_row_and_absent_remove_target(
    connected,
) -> None:
    firewall, server, scheduler, _, _ = connected
    with pytest.raises(TypeError):
        firewall.preview_remove_port("web01", None, ApplyTarget.RUNTIME)
    with pytest.raises(ValueError):
        firewall.preview_remove_port(
            "web01", PortRow("22", "tcp", "public", False, True), ApplyTarget.RUNTIME
        )

    server.disconnect("web01")
    scheduler.pending("web01", "disconnect").run_synchronously_for_test()
    with pytest.raises(RuntimeError):
        firewall.preview_add_port(
            "web01", AddPortRequest("public", "8080", "tcp", ApplyTarget.RUNTIME)
        )


def test_apply_revalidates_busy_selection_generation_inventory_and_exact_preview(
    connected,
) -> None:
    firewall, server, scheduler, service, _ = connected
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.BOTH)
    preview = firewall.preview_add_port("web01", request)

    server.refresh("web01")
    with pytest.raises(RuntimeError, match="changed"):
        firewall.apply_add_port("web01", preview, request)
    scheduler.pending("web01", "refresh").run_synchronously_for_test()

    server.select("db01")
    with pytest.raises(RuntimeError, match="selected"):
        firewall.apply_add_port("web01", preview, request)
    server.select("web01")

    forged = replace(preview, resource="9090/tcp")
    with pytest.raises(RuntimeError, match="preview"):
        firewall.apply_add_port("web01", forged, request)

    service.next_snapshot = _snapshot(runtime_ports=("22", "8080"))
    server.refresh("web01")
    scheduler.pending("web01", "refresh").run_synchronously_for_test()
    with pytest.raises(RuntimeError, match="changed"):
        firewall.apply_add_port("web01", preview, request)


def test_apply_publishes_snapshot_before_verified_result_and_finishes_facade_once(
    connected,
) -> None:
    firewall, server, scheduler, service, _ = connected
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.BOTH)
    preview = firewall.preview_add_port("web01", request)
    service.next_snapshot = _snapshot(
        runtime_ports=("22", "8080"), permanent_ports=("22", "8080")
    )
    events: list[tuple[str, object]] = []
    firewall.snapshot_changed.connect(lambda _sid, value: events.append(("snapshot", value)))
    firewall.operation_result.connect(lambda _sid, value: events.append(("result", value)))

    handle = firewall.apply_add_port("web01", preview, request)
    succeeded: list[object] = []
    finished: list[str] = []
    handle.succeeded.connect(lambda _sid, _gen, _op, value: succeeded.append(value))
    handle.finished.connect(lambda _sid, _gen, op: finished.append(op))
    assert server.session_view("web01").busy_operation == "add_port"
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert [name for name, _ in events] == ["snapshot", "result"]
    assert succeeded == [events[-1][1]]
    assert finished == ["add_port"]
    assert server.session_view("web01").snapshot.has_port(
        "public", "8080", "tcp", False
    )
    assert service.operation_trace[-2:] == ["add_port", "load_snapshot"]


def test_partial_result_is_published_honestly_after_one_refresh(connected) -> None:
    firewall, _, scheduler, service, _ = connected
    service.next_add_port_result = CompositeOperationResult(
        "add_port",
        runtime=_target(ApplyTarget.RUNTIME, TargetStatus.FAILED, TargetStatus.NOT_RUN),
        permanent=_target(
            ApplyTarget.PERMANENT, TargetStatus.SUCCEEDED, TargetStatus.SUCCEEDED
        ),
    )
    service.next_snapshot = _snapshot(permanent_ports=("22", "8080"))
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.BOTH)
    preview = firewall.preview_add_port("web01", request)
    results: list[CompositeOperationResult] = []
    firewall.operation_result.connect(lambda _sid, value: results.append(value))

    firewall.apply_add_port("web01", preview, request)
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert len(service.add_port_calls) == 1
    assert service.load_calls[-1] is None
    assert len(results) == 1 and results[0].is_partial


def test_refresh_failure_preserves_stale_snapshot_but_still_publishes_result(
    connected,
) -> None:
    firewall, server, scheduler, service, _ = connected
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_port("web01", request)
    service.next_load_error = FirewallCommandError("web01", "hostname")
    events: list[str] = []
    firewall.error_raised.connect(lambda _sid, _error: events.append("error"))
    firewall.snapshot_changed.connect(lambda _sid, _value: events.append("snapshot"))
    firewall.operation_result.connect(lambda _sid, _value: events.append("result"))

    firewall.apply_add_port("web01", preview, request)
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert events[-2:] == ["snapshot", "result"]
    assert events.count("error") == 1
    assert server.session_view("web01").snapshot.stale
    assert len(service.add_port_calls) == 1
    assert service.operation_trace[-2:] == ["add_port", "load_snapshot"]


def test_public_result_strips_raw_command_stdout_stderr_and_backend_messages(
    connected,
) -> None:
    firewall, _, scheduler, service, _ = connected
    raw = CommandResult(
        True,
        0,
        "stdout-sudo-secret",
        "stderr-password-secret",
        "web01",
        "add_port_runtime",
        0.1,
    )
    service.next_add_port_result = CompositeOperationResult(
        "add_port",
        runtime=TargetResult(
            ApplyTarget.RUNTIME,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
            raw,
            "backend-secret-message",
        ),
    )
    service.next_snapshot = _snapshot(runtime_ports=("22", "8080"))
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_port("web01", request)
    results: list[CompositeOperationResult] = []
    firewall.operation_result.connect(lambda _sid, result: results.append(result))

    firewall.apply_add_port("web01", preview, request)
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert len(results) == 1
    assert results[0].runtime is not None
    assert results[0].runtime.result is None
    assert results[0].runtime.message == ""
    assert "secret" not in repr(results[0])


def test_pre_mutation_sudo_retry_reuses_one_facade_and_mutates_only_after_password(
    connected,
) -> None:
    firewall, server, scheduler, service, _ = connected
    service.next_add_port_error = SudoAuthenticationRequiredError("web01", "add_port")
    service.next_snapshot = _snapshot(runtime_ports=("22", "8080"))
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_port("web01", request)
    requests: list[object] = []
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))

    handle = firewall.apply_add_port("web01", preview, request)
    successes: list[object] = []
    failures: list[object] = []
    finishes: list[str] = []
    handle.succeeded.connect(lambda *_args: successes.append(_args[-1]))
    handle.failed.connect(lambda *_args: failures.append(_args[-1]))
    handle.finished.connect(lambda *_args: finishes.append(_args[-1]))
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert len(requests) == 1
    assert successes == failures == finishes == []
    assert server.resolve_sudo_password(requests[0], "sudo-one-use-secret")
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert [call[-1] for call in service.add_port_calls] == [
        None,
        "sudo-one-use-secret",
    ]
    assert len(successes) == 1
    assert failures == []
    assert finishes == ["add_port"]
    assert "secret" not in repr(handle)


def test_post_mutation_partial_never_prompts_or_reissues_write(connected) -> None:
    firewall, server, scheduler, service, _ = connected
    generation = server.session_view("web01").generation
    assert server.provide_sudo_password(
        "web01", generation, "sudo-rejected-secret"
    )
    service.next_remove_port_result = CompositeOperationResult(
        "remove_port",
        runtime=_target(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
            authentication_failed=True,
        ),
        permanent=_target(
            ApplyTarget.PERMANENT, TargetStatus.SUCCEEDED, TargetStatus.SUCCEEDED
        ),
    )
    service.next_snapshot = _snapshot(runtime_ports=("22",), permanent_ports=())
    requests: list[object] = []
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))
    row = PortRow("22", "tcp", "public", True, True)
    preview = firewall.preview_remove_port("web01", row, ApplyTarget.BOTH)

    firewall.apply_remove_port("web01", preview, row, ApplyTarget.BOTH)
    scheduler.pending("web01", "remove_port").run_synchronously_for_test()

    assert requests == []
    assert len(service.remove_port_calls) == 1
    assert service.remove_port_calls[0][-1] == "sudo-rejected-secret"

    server.refresh("web01")
    scheduler.pending("web01", "refresh").run_synchronously_for_test()
    assert service.load_calls[-1] is None


def test_terminal_transport_failure_uses_existing_detach_and_close_path(
    connected,
) -> None:
    firewall, server, scheduler, service, managers = connected
    service.next_remove_port_error = SSHConnectionError("web01", "connection lost")
    row = PortRow("22", "tcp", "public", True, True)
    preview = firewall.preview_remove_port("web01", row, ApplyTarget.BOTH)
    failures: list[ControllerOperationError] = []

    handle = firewall.apply_remove_port("web01", preview, row, ApplyTarget.BOTH)
    handle.failed.connect(lambda *_args: failures.append(_args[-1]))
    scheduler.pending("web01", "remove_port").run_synchronously_for_test()

    assert failures and failures[0].category == "ssh"
    assert server.session_view("web01").status is ConnectionStatus.CONNECTION_ERROR
    assert server.session_view("web01").snapshot.stale
    scheduler.pending("web01", "close_failed_connection").run_synchronously_for_test()
    assert managers.instances["web01"][0].disconnect_calls == 1


def test_old_generation_completion_never_updates_new_session_or_finishes_facade(
    connected,
) -> None:
    firewall, server, scheduler, service, _ = connected
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_port("web01", request)
    handle = firewall.apply_add_port("web01", preview, request)
    outcomes: list[object] = []
    handle.succeeded.connect(lambda *_args: outcomes.append(_args[-1]))

    server.disconnect("web01")
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert outcomes == []
    assert server.session_view("web01").status is ConnectionStatus.DISCONNECTED
    assert server.session_view("web01").snapshot is None
    assert len(service.add_port_calls) == 1


def test_old_internal_handle_cannot_complete_later_same_operation_intent(
    connected,
) -> None:
    """Catches callback matching that ignores the exact emitting attempt."""
    firewall, _, scheduler, service, _ = connected
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_port("web01", request)

    firewall.apply_add_port("web01", preview, request)
    key = ("web01", 0, "add_port")
    old_internal = firewall._pending[key].internal
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    current_preview = firewall.preview_add_port("web01", request)
    current_facade = firewall.apply_add_port("web01", current_preview, request)
    actual_result = CompositeOperationResult(
        "add_port",
        runtime=_target(
            ApplyTarget.RUNTIME,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
        ),
    )
    stale_result = CompositeOperationResult(
        "add_port",
        runtime=_target(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
        ),
    )
    service.next_add_port_result = actual_result
    published: list[CompositeOperationResult] = []
    succeeded: list[CompositeOperationResult] = []
    finished: list[str] = []
    firewall.operation_result.connect(lambda _sid, value: published.append(value))
    current_facade.succeeded.connect(
        lambda _sid, _generation, _operation, value: succeeded.append(value)
    )
    current_facade.finished.connect(
        lambda _sid, _generation, operation: finished.append(operation)
    )

    old_internal.succeeded.emit("web01", 0, "add_port", stale_result)
    old_internal.finished.emit("web01", 0, "add_port")

    assert published == []
    assert succeeded == []
    assert finished == []

    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert len(service.add_port_calls) == 2
    assert published == [actual_result]
    assert succeeded == [actual_result]
    assert finished == ["add_port"]
