from __future__ import annotations

import logging
from dataclasses import replace
from threading import Event

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtTest import QSignalSpy
from PySide6.QtWidgets import QApplication, QDialog

from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ControllerOperationError, ServerController
from app.gui.logs_tab import LogsTab
from app.gui.main_window import MainWindow
from app.models.command import CommandResult, CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, ConnectionStatus, TargetStatus
from app.utils.errors import (
    FirewallCommandError,
    PostMutationVerificationError,
    SudoAuthenticationRequiredError,
)
from app.utils.logging_setup import ServerLogBuffer
from app.workers.scheduler import OperationScheduler
from tests.controllers.fakes import (
    FakeConfigManager,
    ManagerFactory,
    ManualScheduler,
    ServiceFactory,
    make_loaded,
    make_snapshot,
)


@pytest.fixture
def reload_workflow(qapp):
    del qapp
    scheduler = ManualScheduler()
    managers = ManagerFactory()
    services = ServiceFactory()
    server = ServerController(
        FakeConfigManager(make_loaded("web01", "db01")),
        scheduler,
        managers,
        services,
    )
    firewall = FirewallController(server)
    server.connect("web01")
    scheduler.pending("web01", "connect").run_synchronously_for_test()
    return server, firewall, scheduler, services.instances["web01"][0]


def test_reload_preview_is_exact_and_warns_runtime_only_changes_can_disappear(
    reload_workflow,
) -> None:
    _server, firewall, _scheduler, _service = reload_workflow

    preview = firewall.preview_reload("web01")

    assert preview.server_id == "web01"
    assert preview.generation == 0
    assert preview.operation == "Reload firewalld"
    assert preview.zone == "Global"
    assert preview.resource == "firewalld daemon"
    assert preview.target is ApplyTarget.BOTH
    assert "runtime-only changes may disappear" in " ".join(
        preview.risk.reasons
    ).lower()


def test_reload_success_runs_one_global_mutation_then_refresh_and_publishes_in_order(
    reload_workflow,
) -> None:
    server, firewall, scheduler, service = reload_workflow
    preview = firewall.preview_reload("web01")
    service.next_snapshot = make_snapshot(server_id="web01", default_zone="internal")
    events: list[str] = []
    firewall.snapshot_changed.connect(lambda *_args: events.append("snapshot"))
    firewall.operation_result.connect(lambda *_args: events.append("result"))

    handle = firewall.apply_reload("web01", preview)
    succeeded: list[object] = []
    handle.succeeded.connect(lambda *_args: succeeded.append(_args[-1]))
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()

    assert service.reload_calls == [(ApplyTarget.BOTH, None)]
    assert service.operation_trace[-2:] == ["reload_firewalld", "load_snapshot"]
    assert server.session_view("web01").snapshot.default_zone == "internal"
    assert events == ["snapshot", "result"]
    assert len(succeeded) == 1


def test_reload_apply_revalidates_selection_and_exact_preview(
    reload_workflow,
) -> None:
    server, firewall, _scheduler, _service = reload_workflow
    preview = firewall.preview_reload("web01")

    with pytest.raises(RuntimeError, match="preview"):
        firewall.apply_reload("web01", replace(preview, resource="another daemon"))

    server.select("db01")
    with pytest.raises(RuntimeError, match="selected"):
        firewall.apply_reload("web01", preview)


def _unsafe_target(
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
        CommandResult(
            False,
            1,
            "stdout-ssh-secret",
            "stderr-sudo-secret",
            "web01",
            "reload-secret",
            0.1,
        ),
        "backend-password=reload-secret",
        authentication_failed=authentication_failed,
    )


def test_reload_failed_result_is_sanitized_and_still_refreshes_once(
    reload_workflow,
) -> None:
    _server, firewall, scheduler, service = reload_workflow
    service.next_reload_result = CompositeOperationResult(
        "reload_firewalld",
        permanent=_unsafe_target(
            ApplyTarget.PERMANENT, TargetStatus.FAILED, TargetStatus.NOT_RUN
        ),
        runtime=_unsafe_target(
            ApplyTarget.RUNTIME, TargetStatus.FAILED, TargetStatus.NOT_RUN
        ),
    )
    preview = firewall.preview_reload("web01")
    results: list[CompositeOperationResult] = []
    firewall.operation_result.connect(lambda _sid, value: results.append(value))

    firewall.apply_reload("web01", preview)
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()

    assert len(results) == 1 and not results[0].is_success
    assert "secret" not in repr(results[0])
    assert service.operation_trace[-2:] == ["reload_firewalld", "load_snapshot"]


@pytest.mark.parametrize(
    ("result", "expected"),
    (
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                permanent=_unsafe_target(
                    ApplyTarget.PERMANENT,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.SUCCEEDED,
                ),
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.SUCCEEDED,
                ),
            ),
            "Firewalld reload completed and verified.",
            id="success",
        ),
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                permanent=_unsafe_target(
                    ApplyTarget.PERMANENT,
                    TargetStatus.FAILED,
                    TargetStatus.NOT_RUN,
                ),
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.FAILED,
                    TargetStatus.NOT_RUN,
                ),
            ),
            (
                "Firewalld reload did not complete. Review the firewall data "
                "before retrying."
            ),
            id="failed-mutation",
        ),
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                permanent=_unsafe_target(
                    ApplyTarget.PERMANENT,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.FAILED,
                ),
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.FAILED,
                ),
            ),
            (
                "Firewalld reloaded, but verification did not confirm the "
                "requested firewall state."
            ),
            id="verification-failed",
        ),
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                permanent=_unsafe_target(
                    ApplyTarget.PERMANENT,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.SUCCEEDED,
                ),
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.FAILED,
                    TargetStatus.NOT_RUN,
                ),
            ),
            (
                "Firewalld reload partially completed. Review the Runtime and "
                "Permanent results before another change."
            ),
            id="partial",
        ),
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                permanent=_unsafe_target(
                    ApplyTarget.PERMANENT,
                    TargetStatus.FAILED,
                    TargetStatus.SUCCEEDED,
                ),
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.FAILED,
                    TargetStatus.NOT_RUN,
                ),
            ),
            (
                "Firewalld returned an inconsistent reload result. Refresh "
                "firewall data before retrying."
            ),
            id="inconsistent-phase-state",
        ),
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.SUCCEEDED,
                ),
            ),
            (
                "Firewalld returned an inconsistent reload result. Refresh "
                "firewall data before retrying."
            ),
            id="inconsistent-missing-global-target",
        ),
    ),
)
def test_overview_renders_each_safe_reload_composite(
    reload_workflow, qtbot, result, expected
) -> None:
    server, firewall, _scheduler, _service = reload_workflow
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)

    window.overview_tab.show_reload_result(result)

    assert window.overview_tab.reload_result_label.text() == expected
    assert "secret" not in window.overview_tab.reload_result_label.text()


def test_overview_reload_result_is_selected_server_generation_and_operation_isolated(
    reload_workflow, qtbot, monkeypatch
) -> None:
    server, firewall, _scheduler, service = reload_workflow
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)

    class AcceptedConfirmation:
        def __init__(self, _preview, parent=None):
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", AcceptedConfirmation
    )
    window.overview_tab.reload_button.click()
    facade = firewall._pending[("web01", 0, "reload_firewalld")].facade

    facade.succeeded.emit(
        "web01", 1, "reload_firewalld", service.next_reload_result
    )
    facade.succeeded.emit(
        "db01", 0, "reload_firewalld", service.next_reload_result
    )
    facade.succeeded.emit("web01", 0, "add_port", service.next_reload_result)

    assert window.overview_tab.reload_result_label.text() == ""
    facade.succeeded.emit(
        "web01", 0, "reload_firewalld", service.next_reload_result
    )
    expected = "Firewalld reload completed and verified."
    assert window.overview_tab.reload_result_label.text() == expected
    server.select("db01")
    assert window.overview_tab.reload_result_label.text() == ""
    facade.succeeded.emit(
        "web01", 0, "reload_firewalld", service.next_reload_result
    )
    assert window.overview_tab.reload_result_label.text() == ""


def test_reload_result_does_not_replace_stale_snapshot_warning(
    reload_workflow, qtbot
) -> None:
    server, firewall, _scheduler, _service = reload_workflow
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    view = server.session_view("web01")
    assert view.snapshot is not None
    window.overview_tab.set_session(
        replace(view, snapshot=replace(view.snapshot, stale=True))
    )
    failed = CompositeOperationResult(
        "reload_firewalld",
        permanent=_unsafe_target(
            ApplyTarget.PERMANENT,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
        ),
        runtime=_unsafe_target(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
        ),
    )

    window.overview_tab.show_reload_result(failed)

    assert window.overview_tab.snapshot_status_label.text() == "Stale firewall data"
    assert "did not complete" in window.overview_tab.reload_result_label.text()


def test_completed_reload_handle_cannot_overwrite_overview_with_late_same_generation_result(
    reload_workflow, qtbot, monkeypatch
) -> None:
    server, firewall, scheduler, service = reload_workflow
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)

    class AcceptedConfirmation:
        def __init__(self, _preview, parent=None):
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", AcceptedConfirmation
    )
    window.overview_tab.reload_button.click()
    facade = firewall._pending[("web01", 0, "reload_firewalld")].facade
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()
    expected = "Firewalld reload completed and verified."
    assert window.overview_tab.reload_result_label.text() == expected
    assert server.session_view("web01").busy_operation is None

    facade.succeeded.emit(
        "web01",
        0,
        "reload_firewalld",
        CompositeOperationResult(
            "reload_firewalld",
            runtime=_unsafe_target(
                ApplyTarget.RUNTIME,
                TargetStatus.FAILED,
                TargetStatus.NOT_RUN,
            ),
        ),
    )

    assert window.overview_tab.reload_result_label.text() == expected


def test_reload_refresh_failure_keeps_prior_snapshot_stale_and_safe_error(
    reload_workflow,
) -> None:
    server, firewall, scheduler, service = reload_workflow
    preview = firewall.preview_reload("web01")
    service.next_load_error = FirewallCommandError("web01", "reload-secret")
    errors: list[ControllerOperationError] = []
    results: list[CompositeOperationResult] = []
    firewall.error_raised.connect(lambda _sid, value: errors.append(value))
    firewall.operation_result.connect(lambda _sid, value: results.append(value))

    firewall.apply_reload("web01", preview)
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()

    assert server.session_view("web01").snapshot.stale
    assert len(service.reload_calls) == 1
    assert len(results) == 1
    assert errors[-1].category == "post_mutation_refresh"
    assert "reloaded" in errors[-1].message.lower()
    assert "secret" not in repr(errors[-1])


def test_reload_pre_mutation_sudo_retry_uses_one_facade(
    reload_workflow,
) -> None:
    server, firewall, scheduler, service = reload_workflow
    preview = firewall.preview_reload("web01")
    service.next_reload_error = SudoAuthenticationRequiredError(
        "web01", "reload_firewalld"
    )
    requests: list[object] = []
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))

    handle = firewall.apply_reload("web01", preview)
    successes: list[object] = []
    finishes: list[str] = []
    handle.succeeded.connect(lambda *_args: successes.append(_args[-1]))
    handle.finished.connect(lambda *_args: finishes.append(_args[-1]))
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()

    assert len(requests) == 1 and successes == finishes == []
    assert server.resolve_sudo_password(requests[0], "sudo-one-use-secret")
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()

    assert service.reload_calls == [
        (ApplyTarget.BOTH, None),
        (ApplyTarget.BOTH, "sudo-one-use-secret"),
    ]
    assert len(successes) == 1
    assert finishes == ["reload_firewalld"]


def test_reload_post_mutation_auth_failure_never_prompts_or_reissues(
    reload_workflow,
) -> None:
    server, firewall, scheduler, service = reload_workflow
    preview = firewall.preview_reload("web01")
    service.next_reload_error = PostMutationVerificationError(
        "web01", "reload_firewalld"
    )
    requests: list[object] = []
    errors: list[ControllerOperationError] = []
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))
    firewall.error_raised.connect(lambda _sid, value: errors.append(value))

    firewall.apply_reload("web01", preview)
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()

    assert requests == []
    assert len(service.reload_calls) == 1
    assert errors[-1].category == "post_mutation_verification"
    assert "reloaded" in errors[-1].message.lower()


def test_old_reload_attempt_cannot_complete_a_later_same_identity_intent(
    reload_workflow,
) -> None:
    _server, firewall, scheduler, service = reload_workflow
    preview = firewall.preview_reload("web01")
    firewall.apply_reload("web01", preview)
    old_internal = firewall._pending[("web01", 0, "reload_firewalld")].internal
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()

    current_preview = firewall.preview_reload("web01")
    current = firewall.apply_reload("web01", current_preview)
    published: list[object] = []
    finished: list[str] = []
    firewall.operation_result.connect(lambda _sid, value: published.append(value))
    current.finished.connect(lambda *_args: finished.append(_args[-1]))

    old_internal.succeeded.emit(
        "web01", 0, "reload_firewalld", service.next_reload_result
    )
    old_internal.finished.emit("web01", 0, "reload_firewalld")

    assert published == finished == []
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()
    assert len(published) == 1
    assert finished == ["reload_firewalld"]


def test_logs_tab_clear_is_view_only_and_actions_keep_exact_server_id(qtbot) -> None:
    tab = LogsTab()
    qtbot.addWidget(tab)
    tab.set_server("web01")
    tab.set_entries(("connected web01", "reload completed"))
    clears = QSignalSpy(tab.clear_requested)
    refreshes = QSignalSpy(tab.refresh_requested)

    tab.clear_button.click()
    tab.refresh_button.click()

    assert tab.toPlainText() == ""
    assert clears.count() == 1 and clears.at(0) == ["web01"]
    assert refreshes.count() == 1 and refreshes.at(0) == ["web01"]


def test_logs_tab_copy_uses_only_currently_visible_text(qtbot) -> None:
    tab = LogsTab()
    qtbot.addWidget(tab)
    tab.set_server("web01")
    tab.set_entries(("visible web01",))
    QApplication.clipboard().setText("old clipboard secret")

    tab.copy_button.click()

    assert QApplication.clipboard().text() == "visible web01"


def _record(message: str, *, server_id: str) -> logging.LogRecord:
    record = logging.LogRecord(
        "remote_firewalld_manager",
        logging.INFO,
        __file__,
        1,
        message,
        (),
        None,
    )
    record.server_id = server_id
    return record


def test_log_buffer_fixture_keeps_server_entries_sanitized_and_isolated() -> None:
    buffer = ServerLogBuffer(secrets=("ssh-secret",))
    buffer.append(_record("connected web01 ssh-secret", server_id="web01"))
    buffer.append(_record("connected db01", server_id="db01"))

    assert "web01" in buffer.entries("web01")[0]
    assert "ssh-secret" not in buffer.entries("web01")[0]
    assert "db01" not in "\n".join(buffer.entries("web01"))


def test_controller_events_append_fixed_sanitized_operation_metadata(qapp) -> None:
    del qapp
    buffer = ServerLogBuffer(secrets=("ssh-web01-secret",))
    scheduler = ManualScheduler()
    managers = ManagerFactory()
    services = ServiceFactory()
    server = ServerController(
        FakeConfigManager(make_loaded("web01", "db01")),
        scheduler,
        managers,
        services,
        log_buffer=buffer,
    )

    server.connect("web01")
    scheduler.pending("web01", "connect").run_synchronously_for_test()

    text = "\n".join(server.log_entries("web01"))
    assert "server=web01" in text
    assert "operation=connect" in text
    assert "target=none" in text
    assert "outcome=started" in text
    assert "outcome=succeeded" in text
    assert "duration=" in text
    assert "secret" not in text
    assert server.log_entries("db01") == ()


@pytest.mark.parametrize(
    ("result", "expected_outcome"),
    (
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                permanent=_unsafe_target(
                    ApplyTarget.PERMANENT,
                    TargetStatus.FAILED,
                    TargetStatus.NOT_RUN,
                ),
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.FAILED,
                    TargetStatus.NOT_RUN,
                ),
            ),
            "failed",
            id="failed",
        ),
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                permanent=_unsafe_target(
                    ApplyTarget.PERMANENT,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.SUCCEEDED,
                ),
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.FAILED,
                    TargetStatus.NOT_RUN,
                ),
            ),
            "partial",
            id="partial",
        ),
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                permanent=_unsafe_target(
                    ApplyTarget.PERMANENT,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.FAILED,
                ),
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.FAILED,
                ),
            ),
            "verification_failed",
            id="verification-failed",
        ),
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                permanent=_unsafe_target(
                    ApplyTarget.PERMANENT,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.SUCCEEDED,
                ),
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.SUCCEEDED,
                ),
            ),
            "succeeded",
            id="succeeded",
        ),
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                permanent=_unsafe_target(
                    ApplyTarget.PERMANENT,
                    TargetStatus.FAILED,
                    TargetStatus.SUCCEEDED,
                ),
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.FAILED,
                    TargetStatus.NOT_RUN,
                ),
            ),
            "inconsistent",
            id="inconsistent",
        ),
        pytest.param(
            CompositeOperationResult(
                "reload_firewalld",
                runtime=_unsafe_target(
                    ApplyTarget.RUNTIME,
                    TargetStatus.SUCCEEDED,
                    TargetStatus.SUCCEEDED,
                ),
            ),
            "inconsistent",
            id="inconsistent-missing-global-target",
        ),
    ),
)
def test_reload_log_classifies_sanitized_composite_phases(
    reload_workflow, result, expected_outcome
) -> None:
    server, _firewall, scheduler, service = reload_workflow
    service.next_reload_result = result

    server.reload_firewalld("web01")
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()

    reload_entries = tuple(
        entry
        for entry in server.log_entries("web01")
        if "operation=reload_firewalld" in entry
    )
    assert reload_entries[-1].endswith(f"outcome={expected_outcome}")
    assert "secret" not in reload_entries[-1]


def test_controller_augments_injected_buffer_with_current_profile_passwords(
    qapp,
) -> None:
    del qapp
    buffer = ServerLogBuffer()
    server = ServerController(
        FakeConfigManager(make_loaded("web01")),
        ManualScheduler(),
        ManagerFactory(),
        ServiceFactory(),
        log_buffer=buffer,
    )

    buffer.append_message("web01", "credential ssh-web01-secret")

    assert "ssh-web01-secret" not in "\n".join(server.log_entries("web01"))


def test_changed_profile_clears_old_generation_entries_and_redacts_new_password(
    qapp,
) -> None:
    del qapp
    initial = make_loaded("web01")
    config = FakeConfigManager(initial)
    buffer = ServerLogBuffer()
    server = ServerController(
        config,
        ManualScheduler(),
        ManagerFactory(),
        ServiceFactory(),
        log_buffer=buffer,
    )
    buffer.append_message("web01", "old generation entry")
    config.current = replace(
        initial,
        servers=(replace(initial.servers[0], password="new-profile-secret"),),
    )

    server.reload_configuration()
    buffer.append_message("web01", "credential new-profile-secret")

    text = "\n".join(server.log_entries("web01"))
    assert "old generation entry" not in text
    assert "new-profile-secret" not in text


@pytest.fixture
def logged_window(qtbot):
    log_buffer = ServerLogBuffer(secrets=("ssh-visible-secret",))
    scheduler = ManualScheduler()
    managers = ManagerFactory()
    services = ServiceFactory()
    server = ServerController(
        FakeConfigManager(make_loaded("web01", "db01")),
        scheduler,
        managers,
        services,
        log_buffer=log_buffer,
    )
    firewall = FirewallController(server)
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    return window, server, log_buffer


def test_main_window_logs_replace_only_placeholder_and_follow_exact_selection(
    logged_window,
) -> None:
    window, server, buffer = logged_window
    buffer.append_message("web01", "connected web01 ssh-visible-secret")
    buffer.append_message("db01", "connected db01")

    server.select("web01")
    assert window.tabs.count() == 7
    assert window.tabs.widget(6) is window.logs_tab
    assert "connected web01" in window.logs_tab.toPlainText()
    assert "ssh-visible-secret" not in window.logs_tab.toPlainText()
    assert "connected db01" not in window.logs_tab.toPlainText()

    server.select("db01")
    assert "connected db01" in window.logs_tab.toPlainText()
    assert "connected web01" not in window.logs_tab.toPlainText()


def test_late_other_server_log_event_never_changes_selected_view(logged_window) -> None:
    window, server, buffer = logged_window
    server.select("web01")
    buffer.append_message("web01", "web current")
    buffer.append_message("db01", "db late")

    assert window.logs_tab.toPlainText().endswith("web current")
    assert "db late" not in window.logs_tab.toPlainText()


def test_clear_view_preserves_source_buffer_and_refresh_restores_entries(
    logged_window,
) -> None:
    window, server, buffer = logged_window
    buffer.append_message("web01", "kept source entry")
    server.select("web01")

    window.logs_tab.clear_button.click()
    assert window.logs_tab.toPlainText() == ""
    assert "kept source entry" in "\n".join(buffer.entries("web01"))

    window.logs_tab.refresh_button.click()
    assert "kept source entry" in window.logs_tab.toPlainText()


def test_unknown_log_event_is_safe_noop_and_copy_is_visible_server_only(
    logged_window,
) -> None:
    window, server, buffer = logged_window
    buffer.append_message("web01", "visible web entry")
    buffer.append_message("db01", "hidden db entry")
    server.select("web01")
    window.logs_tab.copy_button.click()

    assert QApplication.clipboard().text().endswith("visible web entry")
    assert "hidden db entry" not in QApplication.clipboard().text()
    before = window.logs_tab.toPlainText()
    server.log_entries_changed.emit("unknown")
    assert window.logs_tab.toPlainText() == before


def test_reload_error_from_unselected_server_is_not_rendered(
    logged_window, monkeypatch
) -> None:
    window, server, _buffer = logged_window
    rendered: list[object] = []

    class RecordingDialog:
        def exec(self):
            rendered.append(self)

    monkeypatch.setattr(
        "app.gui.main_window.ErrorDialog.from_domain_error",
        lambda *_args, **_kwargs: RecordingDialog(),
    )
    server.select("web01")

    server.error_raised.emit(
        "db01",
        ControllerOperationError(
            "db01",
            "reload_firewalld",
            "post_mutation_refresh",
            "Firewalld reloaded, but fresh firewall data could not be loaded.",
        ),
    )

    assert rendered == []


def test_overview_reload_uses_one_confirmation_and_one_controller_route(
    reload_workflow, qtbot, monkeypatch
) -> None:
    server, firewall, scheduler, service = reload_workflow
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    confirmations: list[object] = []

    class AcceptedConfirmation:
        def __init__(self, preview, parent=None):
            confirmations.append(preview)
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", AcceptedConfirmation
    )
    window.overview_tab.show_reload_result(service.next_reload_result)
    assert window.overview_tab.reload_result_label.text()

    window.overview_tab.reload_button.click()

    assert window.overview_tab.reload_result_label.text() == ""
    assert len(confirmations) == 1
    assert "runtime-only changes may disappear" in " ".join(
        confirmations[0].risk.reasons
    ).lower()
    assert len(
        [item for item in scheduler.handles if item.operation == "reload_firewalld"]
    ) == 1
    scheduler.pending("web01", "reload_firewalld").run_synchronously_for_test()
    assert len(service.reload_calls) == 1
    assert (
        window.overview_tab.reload_result_label.text()
        == "Firewalld reload completed and verified."
    )


def test_cancelled_overview_reload_never_schedules_mutation(
    reload_workflow, qtbot, monkeypatch
) -> None:
    server, firewall, scheduler, service = reload_workflow
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)

    class CancelledConfirmation:
        def __init__(self, _preview, parent=None):
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Rejected

        def confirmed(self):
            return False

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", CancelledConfirmation
    )

    window.overview_tab.reload_button.click()

    assert service.reload_calls == []
    assert not any(item.operation == "reload_firewalld" for item in scheduler.handles)


def test_real_scheduler_keeps_gui_responsive_while_reload_is_blocked(
    qtbot, monkeypatch
) -> None:
    scheduler = OperationScheduler(max_threads=2)
    managers = ManagerFactory()
    services = ServiceFactory()
    server = ServerController(
        FakeConfigManager(make_loaded("web01")), scheduler, managers, services
    )
    firewall = FirewallController(server)
    server.connect("web01")
    qtbot.waitUntil(
        lambda: server.session_view("web01").status is ConnectionStatus.CONNECTED,
        timeout=3000,
    )
    service = services.instances["web01"][0]
    entered, release, gui_tick = Event(), Event(), Event()
    original_reload = service.reload_firewalld

    def blocked_reload(target, *, sudo_password=None):
        entered.set()
        assert release.wait(3)
        return original_reload(target, sudo_password=sudo_password)

    service.reload_firewalld = blocked_reload
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)

    class AcceptedConfirmation:
        def __init__(self, _preview, parent=None):
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", AcceptedConfirmation
    )

    window.overview_tab.reload_button.click()
    assert entered.wait(2)
    QTimer.singleShot(0, gui_tick.set)

    qtbot.waitUntil(gui_tick.is_set, timeout=500)
    assert not window.overview_tab.reload_button.isEnabled()
    release.set()
    qtbot.waitUntil(
        lambda: server.session_view("web01").busy_operation is None,
        timeout=3000,
    )
    assert scheduler.wait_for_done(3000)
