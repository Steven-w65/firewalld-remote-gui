from __future__ import annotations

from threading import Event

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QDialog

from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ServerController
from app.gui.main_window import MainWindow
from app.models.command import CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, TargetStatus
from app.models.firewall import FirewallPort, FirewallSnapshot, ZoneState
from app.models.port import AddPortRequest
from app.utils.errors import FirewallCommandError
from app.workers.scheduler import OperationScheduler
from tests.controllers.fakes import (
    FakeConfigManager,
    ManagerFactory,
    ManualScheduler,
    ServiceFactory,
    make_loaded,
)


def _snapshot(
    *,
    runtime: tuple[str, ...] = ("22",),
    permanent: tuple[str, ...] = ("22",),
    stale: bool = False,
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
                    FirewallPort(value, "tcp", "public", True, False)
                    for value in runtime
                ),
            ),
        ),
        permanent_zones=(
            ZoneState(
                "public",
                ports=tuple(
                    FirewallPort(value, "tcp", "public", False, True)
                    for value in permanent
                ),
                permanent=True,
            ),
        ),
        stale=stale,
    )


@pytest.fixture
def workflow(qtbot):
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
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    service = services.instances["web01"][0]
    return window, server, firewall, scheduler, service


def _accept_add(monkeypatch, *, target: ApplyTarget = ApplyTarget.BOTH) -> None:
    class AcceptedAddDialog:
        def __init__(self, zones, current_zone, parent):
            assert zones == ("public",)
            assert current_zone == "public"
            assert parent is not None

        def exec(self):
            return QDialog.DialogCode.Accepted

        def request(self):
            return AddPortRequest("public", "8080", "tcp", target)

    monkeypatch.setattr("app.gui.main_window.AddPortDialog", AcceptedAddDialog)


def _confirm(monkeypatch, captured: list[object] | None = None) -> None:
    class AcceptedConfirmation:
        def __init__(self, preview, parent):
            if captured is not None:
                captured.append(preview)
            assert parent is not None

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", AcceptedConfirmation
    )


def _ports(window: MainWindow) -> tuple[str, ...]:
    return tuple(
        window.ports_tab.source_model.row_at(row).port
        for row in range(window.ports_tab.source_model.rowCount())
    )


def test_add_requires_two_confirmations_then_refreshes_table_and_disables_busy_actions(
    workflow, monkeypatch
) -> None:
    window, server, _, scheduler, service = workflow
    previews: list[object] = []
    _accept_add(monkeypatch)
    _confirm(monkeypatch, previews)
    service.next_snapshot = _snapshot(
        runtime=("22", "8080"), permanent=("22", "8080")
    )

    window.ports_tab.add_button.click()

    assert len(previews) == 1
    assert previews[0].resource == "8080/tcp"
    assert previews[0].target is ApplyTarget.BOTH
    assert server.session_view("web01").busy_operation == "add_port"
    assert not window.ports_tab.add_button.isEnabled()
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert "8080" in _ports(window)
    assert window.ports_tab.add_button.isEnabled()
    assert "completed" in window.ports_tab.result_label.text().lower()


@pytest.mark.parametrize("cancel_stage", ("add", "confirmation"))
def test_cancel_at_either_modal_submits_no_port_change(
    workflow, monkeypatch, cancel_stage
) -> None:
    window, _, _, scheduler, service = workflow

    class CancelledAdd:
        def __init__(self, *_args):
            pass

        def exec(self):
            return QDialog.DialogCode.Rejected

        def request(self):
            return None

    class CancelledConfirmation:
        def __init__(self, *_args):
            pass

        def exec(self):
            return QDialog.DialogCode.Rejected

        def confirmed(self):
            return False

    if cancel_stage == "add":
        monkeypatch.setattr("app.gui.main_window.AddPortDialog", CancelledAdd)
    else:
        _accept_add(monkeypatch)
        monkeypatch.setattr(
            "app.gui.main_window.ConfirmationDialog", CancelledConfirmation
        )

    window.ports_tab.add_button.click()

    assert service.add_port_calls == []
    assert not any(
        handle.operation == "add_port" and not handle.has_run
        for handle in scheduler.handles
    )


def test_remove_derives_both_target_and_uses_high_risk_apply_anyway_preview(
    workflow, monkeypatch
) -> None:
    window, _, _, scheduler, service = workflow
    previews: list[object] = []
    _confirm(monkeypatch, previews)
    service.next_snapshot = _snapshot(runtime=(), permanent=())
    window.ports_tab.table.selectRow(0)

    window.ports_tab.remove_button.click()

    assert len(previews) == 1
    assert previews[0].target is ApplyTarget.BOTH
    assert previews[0].risk.is_high
    scheduler.pending("web01", "remove_port").run_synchronously_for_test()
    assert _ports(window) == ()


def test_selection_change_inside_confirmation_invalidates_add(workflow, monkeypatch) -> None:
    window, server, _, scheduler, service = workflow
    _accept_add(monkeypatch)

    class SwitchingConfirmation:
        def __init__(self, _preview, _parent):
            pass

        def exec(self):
            server.select("db01")
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", SwitchingConfirmation
    )

    window.ports_tab.add_button.click()

    assert window.current_server_id == "db01"
    assert service.add_port_calls == []
    assert not any(handle.operation == "add_port" for handle in scheduler.handles)


def test_partial_and_verification_failures_have_distinct_fixed_visible_copy(
    workflow, monkeypatch
) -> None:
    window, _, _, scheduler, service = workflow
    _accept_add(monkeypatch)
    _confirm(monkeypatch)
    service.next_add_port_result = CompositeOperationResult(
        "add_port",
        permanent=TargetResult(
            ApplyTarget.PERMANENT,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
            None,
            "",
        ),
        runtime=TargetResult(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
            None,
            "unsafe-secret detail",
        ),
    )
    service.next_snapshot = _snapshot(permanent=("22", "8080"))

    window.ports_tab.add_button.click()
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    text = window.ports_tab.result_label.text().lower()
    assert "partially" in text
    assert "unsafe-secret" not in text

    service.next_add_port_result = CompositeOperationResult(
        "add_port",
        runtime=TargetResult(
            ApplyTarget.RUNTIME,
            TargetStatus.SUCCEEDED,
            TargetStatus.FAILED,
            None,
            "unsafe-secret verification",
        ),
    )
    service.next_snapshot = _snapshot(runtime=("22",))
    _accept_add(monkeypatch, target=ApplyTarget.RUNTIME)
    window.ports_tab.add_button.click()
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert "verification" in window.ports_tab.result_label.text().lower()
    assert "unsafe-secret" not in window.ports_tab.result_label.text()


def test_refresh_failure_marks_visible_state_stale_and_uses_port_specific_safe_copy(
    workflow, monkeypatch
) -> None:
    window, server, _, scheduler, service = workflow
    _accept_add(monkeypatch, target=ApplyTarget.RUNTIME)
    _confirm(monkeypatch)
    service.next_load_error = FirewallCommandError("web01", "unsafe-secret")
    dialogs: list[object] = []

    class CapturedErrorDialog:
        @classmethod
        def from_domain_error(cls, error, parent=None):
            dialogs.append(error)
            assert parent is window
            return cls()

        def exec(self):
            return QDialog.DialogCode.Rejected

    monkeypatch.setattr("app.gui.main_window.ErrorDialog", CapturedErrorDialog)

    window.ports_tab.add_button.click()
    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert server.session_view("web01").snapshot.stale
    assert window.ports_tab.status_label.text() == "Stale firewall data"
    assert dialogs and dialogs[-1].category == "post_mutation_refresh"
    assert "secret" not in dialogs[-1].message


def test_search_persists_across_refresh_and_late_result_never_replaces_other_server(
    workflow, monkeypatch
) -> None:
    window, server, _, scheduler, service = workflow
    _accept_add(monkeypatch)
    _confirm(monkeypatch)
    window.ports_tab.search_edit.setText("8080")
    service.next_snapshot = _snapshot(
        runtime=("22", "8080"), permanent=("22", "8080")
    )
    window.ports_tab.add_button.click()
    server.select("db01")

    scheduler.pending("web01", "add_port").run_synchronously_for_test()

    assert window.current_server_id == "db01"
    assert window.ports_tab.source_model.rowCount() == 0
    assert window.ports_tab.search_edit.text() == "8080"
    server.select("web01")
    assert _ports(window) == ("22", "8080")
    assert window.ports_tab.proxy_model.rowCount() == 1


def test_real_scheduler_keeps_window_responsive_while_port_write_is_blocked(
    qtbot, monkeypatch
) -> None:
    scheduler = OperationScheduler(max_threads=2)
    managers = ManagerFactory()
    services = ServiceFactory()
    services.next_snapshots["web01"] = _snapshot()
    server = ServerController(
        FakeConfigManager(make_loaded("web01")), scheduler, managers, services
    )
    firewall = FirewallController(server)
    server.connect("web01")
    qtbot.waitUntil(
        lambda: server.session_view("web01").status.value == "connected",
        timeout=3000,
    )
    service = services.instances["web01"][0]
    service.next_snapshot = _snapshot(
        runtime=("22", "8080"), permanent=("22", "8080")
    )
    entered, release, gui_tick = Event(), Event(), Event()
    service.add_port_entered = entered
    service.add_port_release = release
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    _accept_add(monkeypatch)
    _confirm(monkeypatch)

    window.ports_tab.add_button.click()
    assert entered.wait(2)
    QTimer.singleShot(0, gui_tick.set)

    qtbot.waitUntil(gui_tick.is_set, timeout=500)
    assert not window.ports_tab.add_button.isEnabled()
    release.set()
    qtbot.waitUntil(lambda: window.ports_tab.contains("8080", "tcp"), timeout=3000)
    assert scheduler.wait_for_done(3000)
