from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from threading import Event

import pytest
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QDialog

from app.gui.dialogs.change_interface_dialog import ChangeInterfaceDialog
from app.gui.models.interfaces_model import InterfacesTableModel, interface_rows
from app.gui.interfaces_tab import InterfacesTab
from app.gui.main_window import MainWindow
from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ServerController
from app.models.enums import ApplyTarget, ConnectionStatus
from app.models.firewall import FirewallSnapshot, ZoneState
from app.models.interface import ChangeInterfaceRequest, InterfaceRow
from app.models.command import CompositeOperationResult, TargetResult
from app.models.enums import TargetStatus
from app.utils.errors import InvalidFirewallArgumentError
from app.utils.errors import (
    FirewallCommandError,
    PostMutationVerificationError,
    SudoAuthenticationRequiredError,
)
from app.workers.scheduler import OperationScheduler
from tests.controllers.fakes import (
    FakeConfigManager,
    ManagerFactory,
    ManualScheduler,
    ServiceFactory,
    make_loaded,
)


def _snapshot() -> FirewallSnapshot:
    return FirewallSnapshot(
        hostname="web01",
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        runtime_zones=(
            ZoneState("public", interfaces=("eth0", "eth2")),
            ZoneState("internal", interfaces=("eth1",)),
            ZoneState("dmz"),
        ),
        permanent_zones=(
            ZoneState("public", interfaces=("eth0",), permanent=True),
            ZoneState("internal", interfaces=("eth2",), permanent=True),
            ZoneState("dmz", interfaces=("eth3",), permanent=True),
        ),
    )


def test_interface_rows_merge_exact_assignments_and_active_state() -> None:
    rows = interface_rows(_snapshot())

    assert rows == (
        InterfaceRow("eth0", "public", "public", True),
        InterfaceRow("eth1", "internal", None, True),
        InterfaceRow("eth2", "public", "internal", True),
        InterfaceRow("eth3", None, "dmz", False),
    )
    with pytest.raises(FrozenInstanceError):
        rows[0].active = False


def test_interfaces_model_renders_unassigned_without_changing_row_value(qapp) -> None:
    del qapp
    model = InterfacesTableModel(interface_rows(_snapshot()))

    assert tuple(
        model.headerData(column, Qt.Orientation.Horizontal)
        for column in range(model.columnCount())
    ) == (
        "Interface",
        "Runtime Zone",
        "Permanent Zone",
        "Runtime Assigned",
    )
    assert model.data(model.index(1, 2)) == "Unassigned"
    assert model.row_at(1) == InterfaceRow("eth1", "internal", None, True)


def test_change_dialog_excludes_current_zone_and_is_cancel_default(qtbot) -> None:
    dialog = ChangeInterfaceDialog(
        "eth0", "public", ("public", "internal", "dmz")
    )
    qtbot.addWidget(dialog)

    assert dialog.available_zones() == ("internal", "dmz")
    assert dialog.defaultButton() is dialog.cancel_button
    assert dialog.request() is None


def test_change_dialog_returns_strict_immutable_request(qtbot) -> None:
    dialog = ChangeInterfaceDialog(
        "eth0",
        "public",
        ("public", "internal", "dmz"),
        target=ApplyTarget.RUNTIME,
    )
    qtbot.addWidget(dialog)
    dialog.zone_combo.setCurrentText("internal")
    dialog.accept()

    assert dialog.request() == ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.RUNTIME
    )


def test_change_dialog_requires_single_target_for_split_assignment(qtbot) -> None:
    row = InterfaceRow("eth2", "public", "internal", True)
    dialog = ChangeInterfaceDialog.for_row(
        row,
        ("public", "internal", "dmz"),
        ("public", "internal", "dmz"),
    )
    qtbot.addWidget(dialog)

    assert dialog.available_targets() == (
        ApplyTarget.RUNTIME,
        ApplyTarget.PERMANENT,
    )
    assert ApplyTarget.BOTH not in dialog.available_targets()
    assert dialog.current_zone() == "public"
    dialog.target_combo.setCurrentIndex(1)
    assert dialog.current_zone() == "internal"
    assert dialog.available_zones() == ("public", "dmz")


def test_interfaces_tab_is_snapshot_only_and_emits_selected_immutable_row(
    qtbot, connected
) -> None:
    tab = InterfacesTab()
    qtbot.addWidget(tab)
    _, server, _, _ = connected
    view = server.session_view("web01")
    tab.set_session(view)
    emitted: list[InterfaceRow] = []
    tab.change_requested.connect(emitted.append)

    tab.table.selectRow(0)
    tab.change_button.click()

    assert tab.rows() == interface_rows(_snapshot())
    assert emitted == [InterfaceRow("eth0", "public", "public", True)]


@pytest.fixture
def connected(qapp):
    del qapp
    scheduler = ManualScheduler()
    managers = ManagerFactory()
    services = ServiceFactory()
    services.next_snapshots["web01"] = _snapshot()
    loaded = make_loaded("web01", "db01")
    loaded = replace(
        loaded,
        servers=(replace(loaded.servers[0], port=2222), loaded.servers[1]),
    )
    server = ServerController(
        FakeConfigManager(loaded),
        scheduler,
        managers,
        services,
    )
    firewall = FirewallController(server)
    server.connect("web01")
    scheduler.pending("web01", "connect").run_synchronously_for_test()
    return firewall, server, scheduler, services.instances["web01"][0]


def test_preview_change_interface_zone_is_exact_and_active_is_high_risk(
    connected,
) -> None:
    firewall, _, _, _ = connected
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.BOTH
    )

    preview = firewall.preview_change_interface_zone("web01", request)

    assert preview.operation == "Change Interface Zone"
    assert preview.zone == "public → internal"
    assert preview.resource == "eth0"
    assert preview.target is ApplyTarget.BOTH
    assert preview.risk.is_high
    warning = " ".join(preview.risk.reasons).lower()
    assert "active interface" in warning
    assert "management port 2222" in warning
    assert "ssh route" in warning
    assert "cannot reliably identify" in warning
    assert "ssh-web01-secret" not in warning
    assert firewall.preview_change_interface_zone("web01", request) == preview


@pytest.mark.parametrize(
    "change_request",
    (
        ChangeInterfaceRequest("eth9", "public", "internal", ApplyTarget.RUNTIME),
        ChangeInterfaceRequest("eth0", "internal", "dmz", ApplyTarget.RUNTIME),
        ChangeInterfaceRequest("eth0", "public", "missing", ApplyTarget.RUNTIME),
        ChangeInterfaceRequest("eth2", "public", "dmz", ApplyTarget.BOTH),
    ),
)
def test_preview_rejects_undiscovered_stale_current_unknown_zone_and_ambiguous_both(
    connected, change_request
) -> None:
    firewall, _, _, _ = connected

    with pytest.raises(InvalidFirewallArgumentError):
        firewall.preview_change_interface_zone("web01", change_request)


def test_permanent_only_interface_is_not_reported_active_but_is_exactly_validated(
    connected,
) -> None:
    firewall, _, _, _ = connected
    request = ChangeInterfaceRequest(
        "eth3", "dmz", "public", ApplyTarget.PERMANENT
    )

    preview = firewall.preview_change_interface_zone("web01", request)

    assert not preview.risk.is_high
    assert preview.zone == "dmz → public"


def _target(
    target: ApplyTarget,
    execution: TargetStatus,
    verification: TargetStatus,
) -> TargetResult:
    return TargetResult(
        target,
        execution,
        verification,
        None,
        "unsafe-secret backend detail",
    )


def test_apply_revalidates_then_refreshes_once_and_publishes_snapshot_first(
    connected,
) -> None:
    firewall, server, scheduler, service = connected
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.BOTH
    )
    preview = firewall.preview_change_interface_zone("web01", request)
    service.next_snapshot = FirewallSnapshot(
        hostname="web01",
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        runtime_zones=(ZoneState("public"), ZoneState("internal", interfaces=("eth0",))),
        permanent_zones=(
            ZoneState("public", permanent=True),
            ZoneState("internal", interfaces=("eth0",), permanent=True),
        ),
    )
    events: list[str] = []
    firewall.snapshot_changed.connect(lambda *_: events.append("snapshot"))
    firewall.operation_result.connect(lambda *_: events.append("result"))

    handle = firewall.apply_change_interface_zone("web01", preview, request)
    succeeded: list[CompositeOperationResult] = []
    handle.succeeded.connect(lambda *_args: succeeded.append(_args[-1]))
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()

    assert events == ["snapshot", "result"]
    assert service.change_interface_zone_calls == [
        ("eth0", "internal", ApplyTarget.BOTH, None)
    ]
    assert service.load_calls == [None, None]
    assert service.reload_calls == []
    assert succeeded and succeeded[0].is_success
    assert server.session_view("web01").snapshot == service.next_snapshot


def test_partial_interface_result_is_sanitized_and_refreshes_once(connected) -> None:
    firewall, _, scheduler, service = connected
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.BOTH
    )
    preview = firewall.preview_change_interface_zone("web01", request)
    service.next_change_interface_zone_result = CompositeOperationResult(
        "change_interface_zone",
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
    published: list[CompositeOperationResult] = []
    firewall.operation_result.connect(lambda _sid, result: published.append(result))

    firewall.apply_change_interface_zone("web01", preview, request)
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()

    assert len(published) == 1 and published[0].is_partial
    assert "unsafe-secret" not in repr(published[0])
    assert service.load_calls == [None, None]


def _accept_interface(monkeypatch, request: ChangeInterfaceRequest) -> None:
    class AcceptedDialog:
        @classmethod
        def for_row(cls, row, runtime_zones, permanent_zones, parent=None):
            assert row.name == request.interface
            assert request.new_zone in runtime_zones
            assert request.new_zone in permanent_zones
            assert parent is not None
            return cls()

        def exec(self):
            return QDialog.DialogCode.Accepted

        def request(self):
            return request

    monkeypatch.setattr(
        "app.gui.main_window.ChangeInterfaceDialog", AcceptedDialog
    )


def _confirm(monkeypatch, captured: list[object] | None = None) -> None:
    class AcceptedConfirmation:
        def __init__(self, preview, parent=None):
            assert parent is not None
            if captured is not None:
                captured.append(preview)

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", AcceptedConfirmation
    )


def test_main_window_replaces_only_interfaces_placeholder_and_confirms_change(
    connected, qtbot, monkeypatch
) -> None:
    firewall, server, scheduler, service = connected
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.BOTH
    )
    _accept_interface(monkeypatch, request)
    previews: list[object] = []
    _confirm(monkeypatch, previews)
    service.next_snapshot = FirewallSnapshot(
        hostname="web01",
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        runtime_zones=(ZoneState("public"), ZoneState("internal", interfaces=("eth0",))),
        permanent_zones=(
            ZoneState("public", permanent=True),
            ZoneState("internal", interfaces=("eth0",), permanent=True),
        ),
    )

    assert window.tabs.widget(4) is window.interfaces_tab
    window.interfaces_tab.table.selectRow(0)
    window.interfaces_tab.change_button.click()
    assert previews and previews[0].risk.is_high
    confirmation_warning = " ".join(previews[0].risk.reasons).lower()
    assert "management port 2222" in confirmation_warning
    assert "ssh-web01-secret" not in confirmation_warning
    assert server.session_view("web01").busy_operation == "change_interface_zone"
    assert not window.interfaces_tab.change_button.isEnabled()
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()

    assert window.interfaces_tab.rows() == (
        InterfaceRow("eth0", "internal", "internal", True),
    )
    assert "completed" in window.interfaces_tab.result_label.text().lower()
    assert service.reload_calls == []


def test_cancelled_interface_dialog_schedules_no_remote_work(
    connected, qtbot, monkeypatch
) -> None:
    firewall, server, scheduler, service = connected
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)

    class CancelledDialog:
        @classmethod
        def for_row(cls, *_args, **_kwargs):
            return cls()

        def exec(self):
            return QDialog.DialogCode.Rejected

        def request(self):
            return None

    monkeypatch.setattr(
        "app.gui.main_window.ChangeInterfaceDialog", CancelledDialog
    )
    window.interfaces_tab.table.selectRow(0)
    window.interfaces_tab.change_button.click()

    assert service.change_interface_zone_calls == []
    assert not any(
        handle.operation == "change_interface_zone" for handle in scheduler.handles
    )


def test_interface_refresh_failure_marks_old_snapshot_stale_and_is_sanitized(
    connected,
) -> None:
    firewall, server, scheduler, service = connected
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_change_interface_zone("web01", request)
    service.next_load_error = FirewallCommandError("web01", "password-secret")
    errors: list[object] = []
    firewall.error_raised.connect(lambda _sid, error: errors.append(error))

    firewall.apply_change_interface_zone("web01", preview, request)
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()

    assert server.session_view("web01").snapshot.stale
    assert errors and errors[-1].category == "post_mutation_refresh"
    assert "interface-zone change" in errors[-1].message.lower()
    assert "secret" not in repr(errors[-1])
    assert len(service.change_interface_zone_calls) == 1


def test_interface_pre_mutation_sudo_retry_keeps_one_public_facade(connected) -> None:
    firewall, server, scheduler, service = connected
    service.next_change_interface_zone_error = SudoAuthenticationRequiredError(
        "web01", "change_interface_zone"
    )
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_change_interface_zone("web01", request)
    password_requests: list[object] = []
    server.sudo_password_required.connect(
        lambda _sid, value: password_requests.append(value)
    )

    handle = firewall.apply_change_interface_zone("web01", preview, request)
    outcomes: list[object] = []
    finished: list[str] = []
    handle.succeeded.connect(lambda *_args: outcomes.append(_args[-1]))
    handle.finished.connect(lambda *_args: finished.append(_args[-1]))
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()
    assert len(password_requests) == 1 and outcomes == finished == []

    assert server.resolve_sudo_password(password_requests[0], "sudo-secret")
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()

    assert [call[-1] for call in service.change_interface_zone_calls] == [
        None,
        "sudo-secret",
    ]
    assert len(outcomes) == 1 and finished == ["change_interface_zone"]
    assert "secret" not in repr(handle)


def test_old_generation_interface_completion_is_ignored(connected) -> None:
    firewall, server, scheduler, service = connected
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_change_interface_zone("web01", request)
    handle = firewall.apply_change_interface_zone("web01", preview, request)
    outcomes: list[object] = []
    handle.succeeded.connect(lambda *_args: outcomes.append(_args[-1]))

    server.disconnect("web01")
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()

    assert outcomes == []
    assert server.session_view("web01").snapshot is None
    assert len(service.change_interface_zone_calls) == 1


def test_real_scheduler_keeps_gui_responsive_during_interface_write(
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
        lambda: server.session_view("web01").status is ConnectionStatus.CONNECTED,
        timeout=3000,
    )
    service = services.instances["web01"][0]
    entered, release, gui_tick = Event(), Event(), Event()
    service.change_interface_entered = entered
    service.change_interface_release = release
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.RUNTIME
    )
    _accept_interface(monkeypatch, request)
    _confirm(monkeypatch)

    window.interfaces_tab.table.selectRow(0)
    window.interfaces_tab.change_button.click()
    assert entered.wait(2)
    QTimer.singleShot(0, gui_tick.set)
    qtbot.waitUntil(gui_tick.is_set, timeout=500)
    assert not window.interfaces_tab.change_button.isEnabled()
    release.set()
    qtbot.waitUntil(
        lambda: server.session_view("web01").busy_operation is None,
        timeout=3000,
    )
    assert scheduler.wait_for_done(3000)


def test_apply_rejects_changed_preview_selection_and_inventory(connected) -> None:
    firewall, server, scheduler, service = connected
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_change_interface_zone("web01", request)
    with pytest.raises(RuntimeError, match="preview"):
        firewall.apply_change_interface_zone(
            "web01", replace(preview, resource="eth2"), request
        )
    server.select("db01")
    with pytest.raises(RuntimeError, match="selected"):
        firewall.apply_change_interface_zone("web01", preview, request)
    server.select("web01")
    service.next_snapshot = FirewallSnapshot(
        hostname="web01",
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        runtime_zones=(ZoneState("public"), ZoneState("dmz", interfaces=("eth0",))),
        permanent_zones=_snapshot().permanent_zones,
    )
    server.refresh("web01")
    scheduler.pending("web01", "refresh").run_synchronously_for_test()
    with pytest.raises(RuntimeError, match="changed"):
        firewall.apply_change_interface_zone("web01", preview, request)


def test_post_mutation_interface_auth_result_never_prompts_or_reissues(connected) -> None:
    firewall, server, scheduler, service = connected
    generation = server.session_view("web01").generation
    assert server.provide_sudo_password("web01", generation, "sudo-secret")
    service.next_change_interface_zone_result = CompositeOperationResult(
        "change_interface_zone",
        permanent=_target(
            ApplyTarget.PERMANENT,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
        ),
        runtime=TargetResult(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
            None,
            "password-secret",
            authentication_failed=True,
        ),
    )
    requests: list[object] = []
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.BOTH
    )
    preview = firewall.preview_change_interface_zone("web01", request)

    firewall.apply_change_interface_zone("web01", preview, request)
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()

    assert requests == []
    assert len(service.change_interface_zone_calls) == 1
    assert service.change_interface_zone_calls[0][-1] == "sudo-secret"


def test_post_mutation_interface_verification_error_is_safe_and_not_retried(
    connected,
) -> None:
    firewall, server, scheduler, service = connected
    service.next_change_interface_zone_error = PostMutationVerificationError(
        "web01", "password-secret"
    )
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_change_interface_zone("web01", request)
    errors: list[object] = []
    requests: list[object] = []
    firewall.error_raised.connect(lambda _sid, error: errors.append(error))
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))

    firewall.apply_change_interface_zone("web01", preview, request)
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()

    assert requests == []
    assert len(service.change_interface_zone_calls) == 1
    assert errors[-1].category == "post_mutation_verification"
    assert "interface-zone change" in errors[-1].message.lower()
    assert "secret" not in repr(errors[-1])


def test_late_interface_result_cannot_replace_other_selected_server(
    connected, qtbot
) -> None:
    firewall, server, scheduler, service = connected
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    service.next_snapshot = FirewallSnapshot(
        hostname="web01",
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        runtime_zones=(ZoneState("internal", interfaces=("eth0",)),),
        permanent_zones=_snapshot().permanent_zones,
    )
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_change_interface_zone("web01", request)
    firewall.apply_change_interface_zone("web01", preview, request)

    server.select("db01")
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()

    assert window.current_server_id == "db01"
    assert window.interfaces_tab.rows() == ()
    server.select("web01")
    assert any(row.runtime_zone == "internal" for row in window.interfaces_tab.rows())


def test_old_internal_handle_cannot_complete_later_interface_intent(connected) -> None:
    firewall, _, scheduler, service = connected
    request = ChangeInterfaceRequest(
        "eth0", "public", "internal", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_change_interface_zone("web01", request)
    firewall.apply_change_interface_zone("web01", preview, request)
    old_internal = firewall._pending[("web01", 0, "change_interface_zone")].internal
    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()

    current_preview = firewall.preview_change_interface_zone("web01", request)
    facade = firewall.apply_change_interface_zone(
        "web01", current_preview, request
    )
    stale_result = CompositeOperationResult(
        "change_interface_zone",
        runtime=_target(
            ApplyTarget.RUNTIME, TargetStatus.FAILED, TargetStatus.NOT_RUN
        ),
    )
    published: list[object] = []
    succeeded: list[object] = []
    firewall.operation_result.connect(lambda _sid, value: published.append(value))
    facade.succeeded.connect(lambda *_args: succeeded.append(_args[-1]))

    old_internal.succeeded.emit("web01", 0, "change_interface_zone", stale_result)
    old_internal.finished.emit("web01", 0, "change_interface_zone")
    assert published == succeeded == []

    scheduler.pending("web01", "change_interface_zone").run_synchronously_for_test()
    assert len(service.change_interface_zone_calls) == 2
    assert len(published) == len(succeeded) == 1
