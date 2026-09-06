from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from threading import Event

import pytest
from PySide6.QtCore import QRect, Qt, QTimer
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QDialog, QProxyStyle, QStyle

from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ControllerOperationError, ServerController
from app.gui.dialogs.add_service_dialog import AddServiceDialog
from app.gui.main_window import MainWindow
from app.gui.models.services_model import (
    ServicePresenceFilter,
    ServicesFilterProxyModel,
    ServicesTableModel,
    merge_service_rows,
)
from app.models.command import CommandResult, CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, ConnectionStatus, TargetStatus
from app.models.firewall import FirewallSnapshot, ZoneState
from app.models.service import AddServiceRequest, ServiceRow
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


def _snapshot(
    *,
    runtime: tuple[str, ...] = ("ssh", "http"),
    permanent: tuple[str, ...] = ("ssh",),
    stale: bool = False,
) -> FirewallSnapshot:
    return FirewallSnapshot(
        hostname="web01",
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        runtime_zones=(ZoneState("public", services=runtime),),
        permanent_zones=(ZoneState("public", services=permanent, permanent=True),),
        available_services=("http", "https", "ssh"),
        stale=stale,
    )


def test_services_model_contract_is_exported_from_gui_models_package() -> None:
    from app.gui import models

    assert models.ServicesTableModel is ServicesTableModel
    assert models.ServiceRow is ServiceRow


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
        "unsafe-secret backend detail",
        authentication_failed=authentication_failed,
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
    return window, server, firewall, scheduler, services.instances["web01"][0]


def test_services_tab_centers_and_paints_status_indicators(workflow):
    class RecordingStyle(QProxyStyle):
        def __init__(self):
            super().__init__()
            self.checkbox_options: list[tuple[QRect, QStyle.StateFlag]] = []

        def drawPrimitive(self, element, option, painter, widget=None):
            if element is QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck:
                self.checkbox_options.append((QRect(option.rect), option.state))
            super().drawPrimitive(element, option, painter, widget)

    window, *_ = workflow
    tab = window.services_tab
    tab.resize(900, 400)
    recording_style = RecordingStyle()
    recording_style.setParent(tab)
    tab.table.setStyle(recording_style)
    tab.show()

    recording_style.checkbox_options.clear()
    pixmap = QPixmap(tab.table.viewport().size())
    tab.table.viewport().render(pixmap)

    http_row = next(
        row
        for row in range(tab.proxy_model.rowCount())
        if tab.proxy_model.data(tab.proxy_model.index(row, 0)) == "http"
    )
    for column, expected_state in (
        (2, QStyle.StateFlag.State_On),
        (3, QStyle.StateFlag.State_Off),
    ):
        cell_rect = tab.table.visualRect(tab.proxy_model.index(http_row, column))
        indicators = [
            (rect, state)
            for rect, state in recording_style.checkbox_options
            if cell_rect.contains(rect.center())
        ]
        assert len(indicators) == 1
        indicator_rect, indicator_state = indicators[0]
        assert indicator_rect.center() == cell_rect.center()
        assert indicator_state & expected_state


def _rows(window: MainWindow) -> tuple[ServiceRow, ...]:
    return tuple(
        row
        for index in range(window.services_tab.source_model.rowCount())
        if (row := window.services_tab.source_model.row_at(index)) is not None
    )


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

    monkeypatch.setattr("app.gui.main_window.ConfirmationDialog", AcceptedConfirmation)


def _accept_add(monkeypatch, target: ApplyTarget = ApplyTarget.BOTH) -> None:
    class AcceptedAdd:
        def __init__(
            self,
            services,
            zones,
            current_zone,
            rows,
            parent,
        ):
            assert services == ("http", "https", "ssh")
            assert zones == ("public",)
            assert current_zone == "public"
            assert tuple(row.name for row in rows) == ("http", "ssh")
            assert parent is not None

        def exec(self):
            return QDialog.DialogCode.Accepted

        def request(self):
            return AddServiceRequest("public", "https", target)

    monkeypatch.setattr("app.gui.main_window.AddServiceDialog", AcceptedAdd)


def test_service_rows_merge_runtime_and_permanent_and_are_immutable() -> None:
    rows = merge_service_rows(_snapshot(), "public")

    assert rows == (
        ServiceRow("http", "public", True, False),
        ServiceRow("ssh", "public", True, True),
    )
    with pytest.raises(FrozenInstanceError):
        rows[0].runtime = False


def test_services_model_search_and_presence_filter_real_rows(qapp) -> None:
    del qapp
    model = ServicesTableModel(merge_service_rows(_snapshot(), "public"))
    proxy = ServicesFilterProxyModel()
    proxy.setSourceModel(model)

    proxy.set_search_text("HTTP")
    assert proxy.rowCount() == 1
    assert proxy.service_row(proxy.index(0, 0)).name == "http"
    proxy.set_search_text("")
    proxy.set_presence_filter(ServicePresenceFilter.BOTH)
    assert proxy.rowCount() == 1
    assert proxy.service_row(proxy.index(0, 0)).name == "ssh"


def test_services_model_exposes_only_read_only_checkbox_status(qapp) -> None:
    del qapp
    model = ServicesTableModel(merge_service_rows(_snapshot(), "public"))
    http_row = next(
        row
        for row in range(model.rowCount())
        if model.data(model.index(row, 0)) == "http"
    )

    assert model.data(model.index(http_row, 2), Qt.ItemDataRole.DisplayRole) is None
    assert model.data(model.index(http_row, 3), Qt.ItemDataRole.DisplayRole) is None
    assert (
        model.data(model.index(http_row, 2), Qt.ItemDataRole.CheckStateRole)
        == Qt.CheckState.Checked
    )
    assert (
        model.data(model.index(http_row, 3), Qt.ItemDataRole.CheckStateRole)
        == Qt.CheckState.Unchecked
    )
    assert not (
        model.flags(model.index(http_row, 2)) & Qt.ItemFlag.ItemIsUserCheckable
    )


def test_add_service_dialog_lists_remote_inventory_only_and_filters_by_target(qtbot) -> None:
    rows = (
        ServiceRow("http", "public", True, False),
        ServiceRow("https", "public", False, True),
        ServiceRow("ssh", "public", True, True),
    )
    dialog = AddServiceDialog(
        ("http", "https", "ssh"), ("public",), "public", rows
    )
    qtbot.addWidget(dialog)

    assert dialog.service_names() == ("http", "https")
    dialog.target_combo.setCurrentIndex(0)
    assert dialog.target() is ApplyTarget.RUNTIME
    assert dialog.service_names() == ("https",)
    dialog.target_combo.setCurrentIndex(1)
    assert dialog.target() is ApplyTarget.PERMANENT
    assert dialog.service_names() == ("http",)
    assert dialog.defaultButton() is dialog.cancel_button


def test_dialog_returns_exact_validated_request(qtbot) -> None:
    dialog = AddServiceDialog(("https",), ("public",), "public", ())
    qtbot.addWidget(dialog)

    dialog.accept()

    assert dialog.request() == AddServiceRequest(
        "public", "https", ApplyTarget.BOTH
    )


def test_preview_validates_inventory_presence_and_ssh_lockout(workflow) -> None:
    _, _, firewall, _, _ = workflow

    add = firewall.preview_add_service(
        "web01", AddServiceRequest("public", "https", ApplyTarget.BOTH)
    )
    remove = firewall.preview_remove_service(
        "web01", ServiceRow("ssh", "public", True, True), ApplyTarget.BOTH
    )

    assert add.operation == "Add Firewall Service"
    assert add.resource == "https"
    assert add.risk.level.value == "none"
    assert remove.operation == "Remove Firewall Service"
    assert remove.risk.is_high
    assert "management port 22" in " ".join(remove.risk.reasons)


@pytest.mark.parametrize(
    "candidate",
    (
        AddServiceRequest("missing", "https", ApplyTarget.RUNTIME),
        AddServiceRequest("public", "invented", ApplyTarget.RUNTIME),
        AddServiceRequest("public", "ssh", ApplyTarget.BOTH),
    ),
)
def test_add_preview_rejects_unknown_inventory_or_fully_present_targets(
    workflow, candidate
) -> None:
    _, _, firewall, _, _ = workflow
    with pytest.raises((RuntimeError, ValueError)):
        firewall.preview_add_service("web01", candidate)


def test_partial_both_add_reconciles_only_missing_target_and_refreshes_once(
    workflow,
) -> None:
    _, server, firewall, scheduler, service = workflow
    request = AddServiceRequest("public", "http", ApplyTarget.BOTH)
    preview = firewall.preview_add_service("web01", request)
    service.next_snapshot = _snapshot(permanent=("ssh", "http"))
    events: list[str] = []
    firewall.snapshot_changed.connect(lambda *_args: events.append("snapshot"))
    firewall.operation_result.connect(lambda *_args: events.append("result"))

    handle = firewall.apply_add_service("web01", preview, request)
    finished: list[str] = []
    handle.finished.connect(lambda *_args: finished.append(_args[-1]))
    scheduler.pending("web01", "add_service").run_synchronously_for_test()

    assert service.add_service_calls == [
        ("public", "http", ApplyTarget.PERMANENT, None)
    ]
    assert service.operation_trace[-2:] == ["add_service", "load_snapshot"]
    assert service.load_calls == [None, None]
    assert events == ["snapshot", "result"]
    assert finished == ["add_service"]
    assert server.session_view("web01").snapshot.zone("public", True).services == (
        "ssh",
        "http",
    )
    assert service.reload_calls == []


def test_apply_revalidates_exact_preview_selection_and_inventory(workflow) -> None:
    _, server, firewall, scheduler, service = workflow
    request = AddServiceRequest("public", "https", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_service("web01", request)

    with pytest.raises(RuntimeError, match="preview"):
        firewall.apply_add_service(
            "web01", replace(preview, resource="ssh"), request
        )
    server.select("db01")
    with pytest.raises(RuntimeError, match="selected"):
        firewall.apply_add_service("web01", preview, request)
    server.select("web01")
    service.next_snapshot = _snapshot(runtime=("ssh", "http", "https"))
    server.refresh("web01")
    scheduler.pending("web01", "refresh").run_synchronously_for_test()
    with pytest.raises(RuntimeError, match="changed"):
        firewall.apply_add_service("web01", preview, request)


def test_remove_requires_exact_row_and_requested_presence(workflow) -> None:
    _, _, firewall, _, _ = workflow
    with pytest.raises(ValueError):
        firewall.preview_remove_service(
            "web01", ServiceRow("http", "public", False, True), ApplyTarget.RUNTIME
        )
    with pytest.raises(ValueError):
        firewall.preview_remove_service(
            "web01", ServiceRow("http", "public", True, False), ApplyTarget.BOTH
        )


def test_partial_and_raw_backend_results_are_sanitized_after_one_refresh(
    workflow,
) -> None:
    _, _, firewall, scheduler, service = workflow
    raw = CommandResult(
        True, 0, "stdout-secret", "stderr-password", "web01", "add_service", 0.1
    )
    service.next_add_service_result = CompositeOperationResult(
        "add_service",
        permanent=TargetResult(
            ApplyTarget.PERMANENT,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
            raw,
            "unsafe-secret",
        ),
        runtime=_target(
            ApplyTarget.RUNTIME, TargetStatus.FAILED, TargetStatus.NOT_RUN
        ),
    )
    service.next_snapshot = _snapshot(permanent=("ssh", "https"))
    request = AddServiceRequest("public", "https", ApplyTarget.BOTH)
    preview = firewall.preview_add_service("web01", request)
    published: list[CompositeOperationResult] = []
    firewall.operation_result.connect(lambda _sid, result: published.append(result))

    firewall.apply_add_service("web01", preview, request)
    scheduler.pending("web01", "add_service").run_synchronously_for_test()

    assert len(published) == 1 and published[0].is_partial
    assert published[0].permanent.result is None
    assert "secret" not in repr(published[0])
    assert service.operation_trace[-2:] == ["add_service", "load_snapshot"]


def test_refresh_failure_marks_snapshot_stale_and_publishes_safe_service_error(
    workflow, monkeypatch
) -> None:
    window, server, firewall, scheduler, service = workflow
    request = AddServiceRequest("public", "https", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_service("web01", request)
    service.next_load_error = FirewallCommandError("web01", "unsafe-secret")
    errors: list[ControllerOperationError] = []
    firewall.error_raised.connect(lambda _sid, error: errors.append(error))

    class CapturedErrorDialog:
        @classmethod
        def from_domain_error(cls, error, parent=None):
            assert parent is window
            return cls()

        def exec(self):
            return QDialog.DialogCode.Rejected

    monkeypatch.setattr("app.gui.main_window.ErrorDialog", CapturedErrorDialog)

    firewall.apply_add_service("web01", preview, request)
    scheduler.pending("web01", "add_service").run_synchronously_for_test()

    assert server.session_view("web01").snapshot.stale
    assert errors[-1].category == "post_mutation_refresh"
    assert "service change" in errors[-1].message.lower()
    assert "secret" not in errors[-1].message
    assert len(service.add_service_calls) == 1


def test_pre_mutation_sudo_retry_uses_one_public_facade(workflow) -> None:
    window, server, firewall, scheduler, service = workflow
    server.sudo_password_required.disconnect(window._sudo_password_required)
    service.next_add_service_error = SudoAuthenticationRequiredError(
        "web01", "add_service"
    )
    service.next_snapshot = _snapshot(runtime=("ssh", "http", "https"))
    request = AddServiceRequest("public", "https", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_service("web01", request)
    requests: list[object] = []
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))

    handle = firewall.apply_add_service("web01", preview, request)
    succeeded: list[object] = []
    finished: list[str] = []
    handle.succeeded.connect(lambda *_args: succeeded.append(_args[-1]))
    handle.finished.connect(lambda *_args: finished.append(_args[-1]))
    scheduler.pending("web01", "add_service").run_synchronously_for_test()
    assert len(requests) == 1 and succeeded == finished == []

    assert server.resolve_sudo_password(requests[0], "sudo-one-use-secret")
    scheduler.pending("web01", "add_service").run_synchronously_for_test()

    assert [call[-1] for call in service.add_service_calls] == [
        None,
        "sudo-one-use-secret",
    ]
    assert len(succeeded) == 1
    assert finished == ["add_service"]
    assert "secret" not in repr(handle)


def test_post_mutation_auth_partial_never_prompts_or_reissues_service(workflow) -> None:
    _, server, firewall, scheduler, service = workflow
    generation = server.session_view("web01").generation
    assert server.provide_sudo_password("web01", generation, "sudo-secret")
    service.next_remove_service_result = CompositeOperationResult(
        "remove_service",
        permanent=_target(
            ApplyTarget.PERMANENT,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
        ),
        runtime=_target(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
            authentication_failed=True,
        ),
    )
    service.next_snapshot = _snapshot(runtime=("ssh", "http"), permanent=())
    requests: list[object] = []
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))
    row = ServiceRow("ssh", "public", True, True)
    preview = firewall.preview_remove_service("web01", row, ApplyTarget.BOTH)

    firewall.apply_remove_service("web01", preview, row, ApplyTarget.BOTH)
    scheduler.pending("web01", "remove_service").run_synchronously_for_test()

    assert requests == []
    assert len(service.remove_service_calls) == 1
    assert service.remove_service_calls[0][-1] == "sudo-secret"


def test_typed_post_mutation_verification_error_is_service_specific_and_not_retried(
    workflow, monkeypatch
) -> None:
    window, server, firewall, scheduler, service = workflow
    service.next_add_service_error = PostMutationVerificationError(
        "web01", "add_service"
    )
    request = AddServiceRequest("public", "https", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_service("web01", request)
    errors: list[ControllerOperationError] = []
    firewall.error_raised.connect(lambda _sid, error: errors.append(error))
    requests: list[object] = []
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))

    class CapturedErrorDialog:
        @classmethod
        def from_domain_error(cls, error, parent=None):
            assert parent is window
            return cls()

        def exec(self):
            return QDialog.DialogCode.Rejected

    monkeypatch.setattr("app.gui.main_window.ErrorDialog", CapturedErrorDialog)

    firewall.apply_add_service("web01", preview, request)
    scheduler.pending("web01", "add_service").run_synchronously_for_test()

    assert requests == []
    assert len(service.add_service_calls) == 1
    assert errors[-1].category == "post_mutation_verification"
    assert "service change" in errors[-1].message.lower()
    assert "reloaded" not in errors[-1].message.lower()
    assert "secret" not in errors[-1].message.lower()


def test_main_window_replaces_only_services_placeholder_and_adds_verified_row(
    workflow, monkeypatch
) -> None:
    window, server, _, scheduler, service = workflow
    _accept_add(monkeypatch)
    previews: list[object] = []
    _confirm(monkeypatch, previews)
    service.next_snapshot = _snapshot(
        runtime=("ssh", "http", "https"), permanent=("ssh", "https")
    )

    assert window.tabs.widget(2) is window.services_tab
    window.services_tab.add_button.click()
    assert previews[0].resource == "https"
    assert server.session_view("web01").busy_operation == "add_service"
    assert not window.services_tab.add_button.isEnabled()
    scheduler.pending("web01", "add_service").run_synchronously_for_test()

    assert any(row.name == "https" and row.runtime and row.permanent for row in _rows(window))
    assert "completed" in window.services_tab.result_label.text().lower()
    assert service.add_service_calls == [
        ("public", "https", ApplyTarget.BOTH, None)
    ]
    assert service.reload_calls == []


def test_main_window_passes_all_zone_presence_to_target_aware_dialog(
    workflow, monkeypatch
) -> None:
    window, server, _, scheduler, service = workflow
    base = _snapshot()
    service.next_snapshot = replace(
        base,
        runtime_zones=base.runtime_zones
        + (ZoneState("internal", services=("https",)),),
        permanent_zones=base.permanent_zones
        + (ZoneState("internal", services=("https",), permanent=True),),
    )
    server.refresh("web01")
    scheduler.pending("web01", "refresh").run_synchronously_for_test()
    captured: list[tuple[ServiceRow, ...]] = []

    class CapturingDialog:
        def __init__(self, _services, _zones, _current, rows, _parent):
            captured.append(tuple(rows))

        def exec(self):
            return QDialog.DialogCode.Rejected

        def request(self):
            return None

    monkeypatch.setattr("app.gui.main_window.AddServiceDialog", CapturingDialog)

    window.services_tab.add_button.click()

    assert ServiceRow("https", "internal", True, True) in captured[0]


def test_remove_selected_service_derives_targets_and_confirms_ssh_risk(
    workflow, monkeypatch
) -> None:
    window, _, _, scheduler, service = workflow
    previews: list[object] = []
    _confirm(monkeypatch, previews)
    service.next_snapshot = _snapshot(runtime=("http",), permanent=())
    window.services_tab.table.selectRow(1)

    window.services_tab.remove_button.click()

    assert len(previews) == 1
    assert previews[0].resource == "ssh"
    assert previews[0].target is ApplyTarget.BOTH
    assert previews[0].risk.is_high
    scheduler.pending("web01", "remove_service").run_synchronously_for_test()
    assert service.remove_service_calls == [
        ("public", "ssh", ApplyTarget.BOTH, None)
    ]
    assert not any(row.name == "ssh" for row in _rows(window))


@pytest.mark.parametrize("cancel_stage", ("add", "confirmation"))
def test_cancelled_service_dialogs_submit_no_write(
    workflow, monkeypatch, cancel_stage
) -> None:
    window, _, _, scheduler, service = workflow

    class Cancelled:
        def __init__(self, *_args):
            pass

        def exec(self):
            return QDialog.DialogCode.Rejected

        def request(self):
            return None

        def confirmed(self):
            return False

    if cancel_stage == "add":
        monkeypatch.setattr("app.gui.main_window.AddServiceDialog", Cancelled)
    else:
        _accept_add(monkeypatch)
        monkeypatch.setattr("app.gui.main_window.ConfirmationDialog", Cancelled)

    window.services_tab.add_button.click()

    assert service.add_service_calls == []
    assert not any(handle.operation == "add_service" for handle in scheduler.handles)


def test_late_service_result_cannot_overwrite_other_selected_server(
    workflow, monkeypatch
) -> None:
    window, server, _, scheduler, service = workflow
    _accept_add(monkeypatch)
    _confirm(monkeypatch)
    service.next_snapshot = _snapshot(runtime=("ssh", "http", "https"))
    window.services_tab.search_edit.setText("https")

    window.services_tab.add_button.click()
    server.select("db01")
    scheduler.pending("web01", "add_service").run_synchronously_for_test()

    assert window.current_server_id == "db01"
    assert window.services_tab.source_model.rowCount() == 0
    assert window.services_tab.search_edit.text() == "https"
    server.select("web01")
    assert any(row.name == "https" for row in _rows(window))


def test_old_generation_service_completion_never_publishes(workflow) -> None:
    _, server, firewall, scheduler, service = workflow
    request = AddServiceRequest("public", "https", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_service("web01", request)
    handle = firewall.apply_add_service("web01", preview, request)
    outcomes: list[object] = []
    handle.succeeded.connect(lambda *_args: outcomes.append(_args[-1]))

    server.disconnect("web01")
    scheduler.pending("web01", "add_service").run_synchronously_for_test()

    assert outcomes == []
    assert server.session_view("web01").status is ConnectionStatus.DISCONNECTED
    assert server.session_view("web01").snapshot is None
    assert len(service.add_service_calls) == 1


def test_old_internal_handle_cannot_complete_later_service_intent(workflow) -> None:
    _, _, firewall, scheduler, service = workflow
    request = AddServiceRequest("public", "https", ApplyTarget.RUNTIME)
    preview = firewall.preview_add_service("web01", request)
    firewall.apply_add_service("web01", preview, request)
    old_internal = firewall._pending[("web01", 0, "add_service")].internal
    scheduler.pending("web01", "add_service").run_synchronously_for_test()

    current_preview = firewall.preview_add_service("web01", request)
    current_facade = firewall.apply_add_service("web01", current_preview, request)
    stale_result = CompositeOperationResult(
        "add_service",
        runtime=_target(
            ApplyTarget.RUNTIME, TargetStatus.FAILED, TargetStatus.NOT_RUN
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

    old_internal.succeeded.emit("web01", 0, "add_service", stale_result)
    old_internal.finished.emit("web01", 0, "add_service")
    assert published == succeeded == []
    assert finished == []

    scheduler.pending("web01", "add_service").run_synchronously_for_test()
    assert len(service.add_service_calls) == 2
    assert len(published) == len(succeeded) == 1
    assert finished == ["add_service"]


def test_real_scheduler_keeps_gui_responsive_while_service_write_is_blocked(
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
    service.next_snapshot = _snapshot(runtime=("ssh", "http", "https"))
    entered, release, gui_tick = Event(), Event(), Event()
    service.add_service_entered = entered
    service.add_service_release = release
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    _accept_add(monkeypatch, ApplyTarget.RUNTIME)
    _confirm(monkeypatch)

    window.services_tab.add_button.click()
    assert entered.wait(2)
    QTimer.singleShot(0, gui_tick.set)

    qtbot.waitUntil(gui_tick.is_set, timeout=500)
    assert not window.services_tab.add_button.isEnabled()
    release.set()
    qtbot.waitUntil(
        lambda: any(row.name == "https" for row in _rows(window)), timeout=3000
    )
    assert scheduler.wait_for_done(3000)
