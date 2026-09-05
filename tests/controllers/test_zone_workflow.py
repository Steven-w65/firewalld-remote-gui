from __future__ import annotations

from dataclasses import replace

import pytest

from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ControllerOperationError, ServerController
from app.models.command import CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, ConnectionStatus, TargetStatus
from app.models.firewall import FirewallSnapshot, ZoneState
from app.utils.errors import (
    FirewallCommandError,
    InvalidFirewallArgumentError,
    PostMutationVerificationError,
    SudoAuthenticationRequiredError,
)
from tests.controllers.fakes import (
    FakeConfigManager,
    ManagerFactory,
    ManualScheduler,
    ServiceFactory,
    make_loaded,
)


def _snapshot(*, default_zone: str = "public", stale: bool = False) -> FirewallSnapshot:
    return FirewallSnapshot(
        hostname="web01",
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone=default_zone,
        runtime_zones=(ZoneState("public", interfaces=("eth0",)), ZoneState("internal")),
        permanent_zones=(
            ZoneState("public", permanent=True),
            ZoneState("internal", permanent=True),
            ZoneState("dmz", permanent=True),
        ),
        stale=stale,
    )


def _target(
    target: ApplyTarget,
    execution: TargetStatus,
    verification: TargetStatus,
) -> TargetResult:
    return TargetResult(target, execution, verification, None, "unsafe-secret")


@pytest.fixture
def connected(qapp):
    del qapp
    scheduler = ManualScheduler()
    managers = ManagerFactory()
    services = ServiceFactory()
    services.next_snapshots["web01"] = _snapshot()
    server = ServerController(
        FakeConfigManager(make_loaded("web01", "db01")),
        scheduler,
        managers,
        services,
    )
    firewall = FirewallController(server)
    server.connect("web01")
    scheduler.pending("web01", "connect").run_synchronously_for_test()
    return firewall, server, scheduler, services.instances["web01"][0]


def test_default_zone_preview_names_current_and_new_zone(connected) -> None:
    firewall, _, _, _ = connected

    preview = firewall.preview_set_default_zone("web01", "internal")

    assert preview.operation == "Set Default Zone"
    assert preview.zone == "Global"
    assert preview.resource == "public → internal"
    assert preview.target is ApplyTarget.BOTH
    assert preview.server_id == "web01"
    assert preview.generation == 0


@pytest.mark.parametrize("new_zone", ["invented", "public", "internal;id"])
def test_unknown_current_or_invalid_default_zone_is_rejected(
    connected, new_zone
) -> None:
    firewall, _, _, _ = connected

    with pytest.raises(InvalidFirewallArgumentError):
        firewall.preview_set_default_zone("web01", new_zone)


def test_preview_requires_connected_idle_fresh_snapshot(connected) -> None:
    firewall, server, scheduler, service = connected
    service.next_snapshot = _snapshot(stale=True)
    server.refresh("web01")
    scheduler.pending("web01", "refresh").run_synchronously_for_test()
    with pytest.raises(RuntimeError, match="stale"):
        firewall.preview_set_default_zone("web01", "internal")


def test_apply_revalidates_exact_confirmed_preview_and_both_target(connected) -> None:
    firewall, server, scheduler, _, = connected
    preview = firewall.preview_set_default_zone("web01", "internal")

    with pytest.raises(InvalidFirewallArgumentError):
        firewall.apply_set_default_zone(
            "web01", preview, "internal", ApplyTarget.RUNTIME
        )
    with pytest.raises(RuntimeError, match="preview"):
        firewall.apply_set_default_zone(
            "web01",
            replace(preview, resource="public → dmz"),
            "internal",
            ApplyTarget.BOTH,
        )
    server.refresh("web01")
    with pytest.raises(RuntimeError, match="changed"):
        firewall.apply_set_default_zone(
            "web01", preview, "internal", ApplyTarget.BOTH
        )
    scheduler.pending("web01", "refresh").run_synchronously_for_test()


def test_success_publishes_snapshot_before_sanitized_result_and_refreshes_once(
    connected,
) -> None:
    firewall, server, scheduler, service = connected
    preview = firewall.preview_set_default_zone("web01", "internal")
    service.next_snapshot = _snapshot(default_zone="internal")
    events: list[tuple[str, object]] = []
    firewall.snapshot_changed.connect(lambda _sid, value: events.append(("snapshot", value)))
    firewall.operation_result.connect(lambda _sid, value: events.append(("result", value)))

    handle = firewall.apply_set_default_zone(
        "web01", preview, "internal", ApplyTarget.BOTH
    )
    succeeded: list[object] = []
    finished: list[str] = []
    handle.succeeded.connect(lambda *_args: succeeded.append(_args[-1]))
    handle.finished.connect(lambda *_args: finished.append(_args[-1]))
    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert [name for name, _ in events] == ["snapshot", "result"]
    assert succeeded == [events[-1][1]]
    assert finished == ["set_default_zone"]
    assert server.session_view("web01").snapshot.default_zone == "internal"
    assert service.set_default_zone_calls == [("internal", ApplyTarget.BOTH, None)]
    assert service.load_calls == [None, None]
    assert service.reload_calls == []


def test_failed_global_result_is_sanitized_and_still_refreshes_once(connected) -> None:
    firewall, _, scheduler, service = connected
    service.next_set_default_zone_result = CompositeOperationResult(
        "set_default_zone",
        permanent=_target(
            ApplyTarget.PERMANENT,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
        ),
        runtime=_target(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
        ),
    )
    preview = firewall.preview_set_default_zone("web01", "internal")
    results: list[CompositeOperationResult] = []
    firewall.operation_result.connect(lambda _sid, value: results.append(value))

    firewall.apply_set_default_zone("web01", preview, "internal", ApplyTarget.BOTH)
    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert len(results) == 1 and not results[0].is_success
    assert "secret" not in repr(results[0])
    assert service.operation_trace[-2:] == ["set_default_zone", "load_snapshot"]


def test_partial_global_result_is_published_honestly_after_one_refresh(
    connected,
) -> None:
    firewall, _, scheduler, service = connected
    service.next_set_default_zone_result = CompositeOperationResult(
        "set_default_zone",
        permanent=_target(
            ApplyTarget.PERMANENT,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
        ),
        runtime=_target(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
        ),
    )
    preview = firewall.preview_set_default_zone("web01", "internal")
    results: list[CompositeOperationResult] = []
    firewall.operation_result.connect(lambda _sid, value: results.append(value))

    firewall.apply_set_default_zone("web01", preview, "internal", ApplyTarget.BOTH)
    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert len(results) == 1 and results[0].is_partial
    assert "secret" not in repr(results[0])
    assert service.operation_trace[-2:] == ["set_default_zone", "load_snapshot"]


def test_refresh_failure_keeps_prior_snapshot_stale_and_uses_zone_specific_copy(
    connected,
) -> None:
    firewall, server, scheduler, service = connected
    preview = firewall.preview_set_default_zone("web01", "internal")
    service.next_load_error = FirewallCommandError("web01", "unsafe-secret")
    errors: list[ControllerOperationError] = []
    firewall.error_raised.connect(lambda _sid, error: errors.append(error))

    firewall.apply_set_default_zone("web01", preview, "internal", ApplyTarget.BOTH)
    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert server.session_view("web01").snapshot.stale
    assert errors[-1].category == "post_mutation_refresh"
    assert "default-zone change" in errors[-1].message.lower()
    assert "secret" not in errors[-1].message
    assert len(service.set_default_zone_calls) == 1


def test_pre_mutation_sudo_retry_reuses_one_facade_and_mutates_once_after_password(
    connected,
) -> None:
    firewall, server, scheduler, service = connected
    preview = firewall.preview_set_default_zone("web01", "internal")
    service.next_set_default_zone_error = SudoAuthenticationRequiredError(
        "web01", "set_default_zone"
    )
    service.next_snapshot = _snapshot(default_zone="internal")
    requests: list[object] = []
    server.sudo_password_required.connect(lambda _sid, request: requests.append(request))

    handle = firewall.apply_set_default_zone(
        "web01", preview, "internal", ApplyTarget.BOTH
    )
    successes: list[object] = []
    finishes: list[str] = []
    handle.succeeded.connect(lambda *_args: successes.append(_args[-1]))
    handle.finished.connect(lambda *_args: finishes.append(_args[-1]))
    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert len(requests) == 1
    assert successes == finishes == []
    assert server.resolve_sudo_password(requests[0], "sudo-one-use-secret")
    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert service.set_default_zone_calls == [
        ("internal", ApplyTarget.BOTH, None),
        ("internal", ApplyTarget.BOTH, "sudo-one-use-secret"),
    ]
    assert len(successes) == 1
    assert finishes == ["set_default_zone"]


def test_post_mutation_verification_failure_never_prompts_or_reissues_mutation(
    connected,
) -> None:
    firewall, server, scheduler, service = connected
    preview = firewall.preview_set_default_zone("web01", "internal")
    service.next_set_default_zone_error = PostMutationVerificationError(
        "web01", "set_default_zone"
    )
    requests: list[object] = []
    errors: list[ControllerOperationError] = []
    server.sudo_password_required.connect(lambda _sid, request: requests.append(request))
    firewall.error_raised.connect(lambda _sid, error: errors.append(error))

    firewall.apply_set_default_zone("web01", preview, "internal", ApplyTarget.BOTH)
    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert requests == []
    assert len(service.set_default_zone_calls) == 1
    assert errors[-1].category == "post_mutation_verification"
    assert "default zone" in errors[-1].message.lower()
    assert "reloaded" not in errors[-1].message.lower()


def test_old_generation_completion_cannot_publish_or_finish_facade(connected) -> None:
    firewall, server, scheduler, service = connected
    preview = firewall.preview_set_default_zone("web01", "internal")
    handle = firewall.apply_set_default_zone(
        "web01", preview, "internal", ApplyTarget.BOTH
    )
    outcomes: list[object] = []
    finishes: list[str] = []
    handle.succeeded.connect(lambda *_args: outcomes.append(_args[-1]))
    handle.finished.connect(lambda *_args: finishes.append(_args[-1]))

    server.disconnect("web01")
    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert outcomes == []
    assert finishes == ["set_default_zone"]
    assert server.session_view("web01").status is ConnectionStatus.DISCONNECTED
    assert server.session_view("web01").snapshot is None
    assert len(service.set_default_zone_calls) == 1


def test_old_internal_handle_cannot_complete_later_default_zone_intent(
    connected,
) -> None:
    firewall, _, scheduler, service = connected
    preview = firewall.preview_set_default_zone("web01", "internal")
    firewall.apply_set_default_zone(
        "web01", preview, "internal", ApplyTarget.BOTH
    )
    key = ("web01", 0, "set_default_zone")
    old_internal = firewall._pending[key].internal
    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    service.next_snapshot = _snapshot(default_zone="public")
    current_preview = firewall.preview_set_default_zone("web01", "internal")
    current_facade = firewall.apply_set_default_zone(
        "web01", current_preview, "internal", ApplyTarget.BOTH
    )
    stale_result = CompositeOperationResult(
        "set_default_zone",
        permanent=_target(
            ApplyTarget.PERMANENT,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
        ),
        runtime=_target(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
        ),
    )
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

    old_internal.succeeded.emit("web01", 0, "set_default_zone", stale_result)
    old_internal.finished.emit("web01", 0, "set_default_zone")

    assert published == []
    assert succeeded == []
    assert finished == []

    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert len(service.set_default_zone_calls) == 2
    assert len(published) == len(succeeded) == 1
    assert finished == ["set_default_zone"]
