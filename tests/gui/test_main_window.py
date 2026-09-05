from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import QDialog, QLabel

from app.controllers.server_controller import (
    ControllerJobHandle,
    ControllerOperationError,
    ServerController,
    SudoPasswordRequest,
)
from app.controllers.session import ServerSessionView
from app.firewalld.service import ConnectionCheck, ConnectionTestResult, FirewalldInfo
from app.gui.dialogs.confirmation_dialog import ConfirmationDialog
from app.gui.main_window import MainWindow
from app.models.enums import ConnectionStatus
from app.models.firewall import FirewallSnapshot
from app.utils.errors import FirewalldNotRunningError
from tests.controllers.fakes import (
    FakeConfigManager,
    ManagerFactory,
    ManualScheduler,
    ServiceFactory,
    make_loaded,
)


def snapshot(*, hostname: str, stale: bool = False) -> FirewallSnapshot:
    return FirewallSnapshot(
        hostname=hostname,
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        stale=stale,
    )


def view(
    server_id: str,
    name: str,
    status: ConnectionStatus = ConnectionStatus.DISCONNECTED,
    *,
    current_snapshot: FirewallSnapshot | None = None,
    latest_error: str | None = None,
    busy_operation: str | None = None,
) -> ServerSessionView:
    return ServerSessionView(
        server_id=server_id,
        name=name,
        host=f"{server_id}.example.test",
        port=22,
        username="operator",
        sudo_enabled=True,
        generation=0,
        status=status,
        snapshot=current_snapshot,
        latest_error=latest_error,
        busy_operation=busy_operation,
    )


class FakeServerController(QObject):
    sessions_changed = Signal()
    selection_changed = Signal(str)
    session_changed = Signal(str)
    host_key_required = Signal(str, object)
    sudo_password_required = Signal(str, object)
    error_raised = Signal(str, object)
    log_entries_changed = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        initial = (
            view("web01", "Production Web"),
            view(
                "db01",
                "Database Server",
                ConnectionStatus.CONNECTED,
                current_snapshot=snapshot(hostname="db01"),
            ),
            view("test01", "Test Server", ConnectionStatus.CONNECTION_ERROR),
        )
        self._views = {item.server_id: item for item in initial}
        self._order = tuple(item.server_id for item in initial)
        self.selected_server_id: str | None = "web01"
        self.connect_calls: list[str] = []
        self.disconnect_calls: list[str] = []
        self.reconnect_calls: list[str] = []
        self.refresh_calls: list[str] = []
        self.test_connection_calls: list[str] = []
        self.reload_firewalld_calls: list[str] = []
        self.operation_handles: list[ControllerJobHandle] = []
        self.reload_calls = 0
        self.shutdown_calls: list[int] = []
        self.host_key_decisions: list[tuple[str, int, object, bool]] = []
        self.sudo_decisions: list[tuple[object, str | None]] = []
        self._log_entries: dict[str, tuple[str, ...]] = {}

    def sessions(self) -> tuple[ServerSessionView, ...]:
        return tuple(self._views[server_id] for server_id in self._order)

    def session_view(self, server_id: str) -> ServerSessionView:
        return self._views[server_id]

    def log_entries(self, server_id: str) -> tuple[str, ...]:
        if server_id not in self._views:
            raise KeyError(server_id)
        return self._log_entries.get(server_id, ())

    def select(self, server_id: str) -> None:
        self.selected_server_id = server_id
        self.selection_changed.emit(server_id)

    def connect(self, server_id: str) -> None:
        self.connect_calls.append(server_id)

    def disconnect(self, server_id: str) -> None:
        self.disconnect_calls.append(server_id)

    def reconnect(self, server_id: str) -> ControllerJobHandle:
        self.reconnect_calls.append(server_id)
        return self._handle(server_id, "reconnect")

    def refresh(self, server_id: str) -> None:
        self.refresh_calls.append(server_id)

    def test_connection(self, server_id: str) -> ControllerJobHandle:
        self.test_connection_calls.append(server_id)
        return self._handle(server_id, "test_connection")

    def reload_firewalld(self, server_id: str) -> ControllerJobHandle:
        self.reload_firewalld_calls.append(server_id)
        return self._handle(server_id, "reload_firewalld")

    def _schedule_reload(
        self, server_id: str, generation: int
    ) -> ControllerJobHandle:
        if self._views[server_id].generation != generation:
            raise RuntimeError("stale generation")
        return self.reload_firewalld(server_id)

    def reload_configuration(self) -> None:
        self.reload_calls += 1

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        self.shutdown_calls.append(timeout_ms)
        return True

    def resolve_host_key(
        self, server_id: str, generation: int, challenge: object, confirmed: bool
    ) -> bool:
        self.host_key_decisions.append(
            (server_id, generation, challenge, confirmed)
        )
        return confirmed

    def resolve_sudo_password(
        self, request: object, password: str | None
    ) -> bool:
        self.sudo_decisions.append((request, password))
        return password is not None

    def publish(self, replacement: ServerSessionView) -> None:
        self._views[replacement.server_id] = replacement
        self.session_changed.emit(replacement.server_id)

    def _handle(self, server_id: str, operation: str) -> ControllerJobHandle:
        handle = ControllerJobHandle(
            server_id,
            self._views[server_id].generation,
            operation,
        )
        self.operation_handles.append(handle)
        return handle


@pytest.fixture
def controller() -> FakeServerController:
    return FakeServerController()


@pytest.fixture
def window(qtbot, controller) -> MainWindow:
    result = MainWindow(controller)
    qtbot.addWidget(result)
    return result


def test_window_lists_profiles_without_connecting(window, controller):
    assert window.server_sidebar.server_ids() == ("web01", "db01", "test01")
    assert controller.connect_calls == []


def test_selecting_server_routes_only_its_frozen_view(window):
    window.server_sidebar.select_server("db01")

    assert window.current_server_id == "db01"
    assert window.header_title.text() == "Database Server"
    assert window.logs_tab.server_id == "db01"


def test_unselected_session_update_does_not_replace_visible_content(
    window, controller
):
    selected_before = window.logs_tab.toPlainText()

    controller.publish(
        view(
            "db01",
            "Database Server",
            ConnectionStatus.CONNECTED,
            current_snapshot=snapshot(hostname="changed-db", stale=True),
        )
    )

    assert window.current_server_id == "web01"
    assert window.header_title.text() == "Production Web"
    assert window.logs_tab.toPlainText() == selected_before


def test_shell_has_exact_tab_order_and_real_management_tabs(window):
    assert tuple(
        window.tabs.tabText(index) for index in range(window.tabs.count())
    ) == (
        "Overview",
        "Ports",
        "Services",
        "Zones",
        "Interfaces",
        "Rich Rules",
        "Logs",
    )
    assert window.tabs.widget(0) is window.overview_tab
    assert window.tabs.widget(2) is window.services_tab
    assert window.tabs.widget(3) is window.zones_tab
    assert window.tabs.widget(4) is window.interfaces_tab
    assert window.tabs.widget(5) is window.rich_rules_tab
    assert window.tabs.widget(6) is window.logs_tab
    assert window.overview_tab.accessibleName() == "Server overview"
    assert window.logs_tab.accessibleName() == "Server logs"
    assert window.state_panels == []


def test_menu_and_sidebar_actions_route_selected_id_to_public_controller(
    window, controller
):
    window.reload_configuration_action.trigger()
    window.server_sidebar.connect_button.click()
    window.server_sidebar.select_server("db01")
    window.refresh_action.trigger()
    window.server_sidebar.disconnect_button.click()

    assert controller.reload_calls == 1
    assert controller.connect_calls == ["web01"]
    assert controller.refresh_calls == ["db01"]
    assert controller.disconnect_calls == ["db01"]


def test_sidebar_connect_reconnects_live_firewalld_error_session(
    qtbot, monkeypatch
):
    monkeypatch.setattr(
        "app.gui.main_window.ErrorDialog.exec",
        lambda self: QDialog.DialogCode.Rejected,
    )
    scheduler = ManualScheduler()
    manager_factory = ManagerFactory()
    service_factory = ServiceFactory()
    controller = ServerController(
        FakeConfigManager(make_loaded("web01")),
        scheduler,
        manager_factory,
        service_factory,
    )
    window = MainWindow(controller)
    qtbot.addWidget(window)

    controller.connect("web01")
    scheduler.pending("web01", "connect").run()
    service_factory.instances["web01"][0].next_load_error = (
        FirewalldNotRunningError("web01", "get_state")
    )
    controller.refresh("web01")
    scheduler.pending("web01", "refresh").run()

    assert (
        controller.session_view("web01").status
        is ConnectionStatus.FIREWALLD_NOT_RUNNING
    )
    assert window.server_sidebar.connect_button.isEnabled()

    window.server_sidebar.connect_button.click()

    current = controller.session_view("web01")
    assert current.status is ConnectionStatus.CONNECTING
    assert current.busy_operation == "reconnect"
    assert scheduler.pending("web01", "reconnect").operation == "reconnect"


def test_sidebar_connect_uses_connect_for_disconnected_session(qtbot):
    scheduler = ManualScheduler()
    controller = ServerController(
        FakeConfigManager(make_loaded("web01")),
        scheduler,
        ManagerFactory(),
        ServiceFactory(),
    )
    window = MainWindow(controller)
    qtbot.addWidget(window)

    window.server_sidebar.connect_button.click()

    current = controller.session_view("web01")
    assert current.status is ConnectionStatus.CONNECTING
    assert current.busy_operation == "connect"
    assert scheduler.pending("web01", "connect").operation == "connect"


def test_overview_actions_route_the_exact_selected_server(window, controller):
    window.server_sidebar.select_server("db01")

    window.overview_tab.refresh_button.click()
    window.overview_tab.test_connection_button.click()
    window.overview_tab.reconnect_button.click()
    window.overview_tab.disconnect_button.click()

    assert controller.refresh_calls == ["db01"]
    assert controller.test_connection_calls == ["db01"]
    assert controller.reconnect_calls == ["db01"]
    assert controller.disconnect_calls == ["db01"]


def test_connection_test_result_renders_only_for_matching_selection_and_generation(
    window, controller
):
    result = ConnectionTestResult(
        hostname="db01",
        distribution="Test Linux",
        effective_uid=1000,
        firewalld=FirewalldInfo(True, True, "2.1.0"),
        checks=(ConnectionCheck("ssh_connection", True, "SSH succeeded."),),
    )
    window.server_sidebar.select_server("db01")
    window.overview_tab.test_connection_button.click()
    first = controller.operation_handles[-1]

    window.server_sidebar.select_server("web01")
    first.succeeded.emit("db01", first.generation, "test_connection", result)
    assert window.overview_tab.test_results.rowCount() == 0

    window.server_sidebar.select_server("db01")
    window.overview_tab.test_connection_button.click()
    second = controller.operation_handles[-1]
    second.succeeded.emit("db01", second.generation + 1, "test_connection", result)
    assert window.overview_tab.test_results.rowCount() == 0

    second.succeeded.emit("db01", second.generation, "test_connection", result)
    assert window.overview_tab.test_results.rowCount() == 1
    assert window.overview_tab.test_results.item(0, 0).text() == "PASS"


def test_connection_test_is_read_only_and_does_not_replace_snapshot(
    window, controller
):
    window.server_sidebar.select_server("db01")
    before = controller.session_view("db01").snapshot

    window.overview_tab.test_connection_button.click()

    assert controller.test_connection_calls == ["db01"]
    assert controller.reload_firewalld_calls == []
    assert controller.session_view("db01").snapshot is before


def test_reload_confirmation_is_cancel_default_and_cancel_submits_nothing(
    window, controller, monkeypatch
):
    previews: list[object] = []

    class CancellingDialog:
        def __init__(self, preview, parent):
            previews.append(preview)
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Rejected

        def confirmed(self):
            return False

    monkeypatch.setattr("app.gui.main_window.ConfirmationDialog", CancellingDialog)
    window.server_sidebar.select_server("db01")

    window.overview_tab.reload_button.click()

    assert len(previews) == 1
    assert previews[0].operation == "Reload firewalld"
    assert previews[0].target.value == "both"
    assert not previews[0].risk.is_high
    assert controller.reload_firewalld_calls == []


def test_reload_confirmation_visibly_warns_runtime_only_changes_may_be_discarded(
    window, controller, monkeypatch
):
    rendered_text: list[str] = []

    class InspectingDialog(ConfirmationDialog):
        def exec(self):
            rendered_text.append(
                " ".join(label.text() for label in self.findChildren(QLabel))
            )
            self.reject()
            return QDialog.DialogCode.Rejected

    monkeypatch.setattr("app.gui.main_window.ConfirmationDialog", InspectingDialog)
    window.server_sidebar.select_server("db01")

    window.overview_tab.reload_button.click()

    assert "runtime-only changes may disappear" in rendered_text[0]
    assert controller.reload_firewalld_calls == []


def test_accepted_reload_revalidates_exact_server_and_generation_before_submit(
    window, controller, monkeypatch
):
    class AcceptingDialog:
        def __init__(self, preview, parent):
            assert preview.server_name == "Database Server"
            assert preview.host == "db01.example.test"
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr("app.gui.main_window.ConfirmationDialog", AcceptingDialog)
    window.server_sidebar.select_server("db01")

    window.overview_tab.reload_button.click()

    assert controller.reload_firewalld_calls == ["db01"]


def test_reload_acceptance_is_ignored_if_selection_changes_inside_dialog(
    window, controller, monkeypatch
):
    class SwitchingDialog:
        def __init__(self, preview, parent):
            del preview, parent

        def exec(self):
            window.server_sidebar.select_server("web01")
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr("app.gui.main_window.ConfirmationDialog", SwitchingDialog)
    window.server_sidebar.select_server("db01")

    window.overview_tab.reload_button.click()

    assert controller.reload_firewalld_calls == []


def test_reload_acceptance_is_ignored_if_generation_changes_inside_dialog(
    window, controller, monkeypatch
):
    class ReplacingDialog:
        def __init__(self, preview, parent):
            del preview, parent

        def exec(self):
            current = controller.session_view("db01")
            controller.publish(replace(current, generation=current.generation + 1))
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr("app.gui.main_window.ConfirmationDialog", ReplacingDialog)
    window.server_sidebar.select_server("db01")

    window.overview_tab.reload_button.click()

    assert controller.reload_firewalld_calls == []


def test_status_bar_busy_message_tracks_selected_view_and_clears(
    window, controller
):
    controller.publish(
        view(
            "web01",
            "Production Web",
            ConnectionStatus.CONNECTED,
            current_snapshot=snapshot(hostname="web01"),
            busy_operation="refresh",
        )
    )
    assert "Refresh in progress" in window.statusBar().currentMessage()

    controller.publish(
        view(
            "web01",
            "Production Web",
            ConnectionStatus.CONNECTED,
            current_snapshot=snapshot(hostname="web01"),
        )
    )
    assert window.statusBar().currentMessage() == "Ready"


def test_no_sessions_renders_no_selection_state(qtbot):
    controller = FakeServerController()
    controller._views.clear()
    controller._order = ()
    controller.selected_server_id = None
    window = MainWindow(controller)
    qtbot.addWidget(window)

    assert window.current_server_id is None
    assert window.header_title.text() == "No server selected"
    assert window.logs_tab.server_id is None
    assert window.logs_tab.toPlainText() == ""


def test_shutdown_is_bounded_and_invoked_exactly_once(window, controller):
    window.shutdown_once()
    window.shutdown_once()
    window.close()

    assert controller.shutdown_calls == [5000]


def test_unknown_host_signal_uses_gui_thread_dialog_and_exact_decision(
    window, controller, monkeypatch
):
    challenge = SimpleNamespace(
        host="web01.example.test",
        port=22,
        algorithm="ssh-ed25519",
        fingerprint_sha256="SHA256:safe",
    )
    dialog_threads: list[object] = []

    class AcceptingHostDialog:
        def __init__(self, received, parent):
            assert received is challenge
            assert parent is window
            dialog_threads.append(QThread.currentThread())

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr("app.gui.main_window.HostKeyDialog", AcceptingHostDialog)

    controller.host_key_required.emit("web01", challenge)

    assert dialog_threads == [window.thread()]
    assert controller.host_key_decisions == [("web01", 0, challenge, True)]


def test_closed_sudo_dialog_cancels_exact_waiting_request(
    window, controller, monkeypatch
):
    request = SudoPasswordRequest("web01", 0, "refresh")

    class ClosingSudoDialog:
        def __init__(self, server_name, parent):
            assert server_name == "Production Web"
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Rejected

        def confirmed(self):
            return False

        def take_password(self):
            raise AssertionError("cancelled dialog must not transfer a password")

    monkeypatch.setattr("app.gui.main_window.SudoPasswordDialog", ClosingSudoDialog)

    controller.sudo_password_required.emit("web01", request)

    assert controller.sudo_decisions == [(request, None)]


def test_accepted_sudo_dialog_transfers_secret_once_without_widget_or_signal_copy(
    window, controller, monkeypatch
):
    request = SudoPasswordRequest("web01", 0, "refresh")
    takes = 0

    class AcceptingSudoDialog:
        def __init__(self, server_name, parent):
            assert server_name == "Production Web"
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

        def take_password(self):
            nonlocal takes
            takes += 1
            return "sudo-secret"

    monkeypatch.setattr("app.gui.main_window.SudoPasswordDialog", AcceptingSudoDialog)

    controller.sudo_password_required.emit("web01", request)

    assert takes == 1
    assert controller.sudo_decisions == [(request, "sudo-secret")]
    assert "sudo-secret" not in window.statusBar().currentMessage()


def test_changed_key_error_opens_only_fixed_error_dialog_on_gui_thread(
    window, controller, monkeypatch
):
    error = ControllerOperationError(
        "web01", "connect", "host_key_changed", "unsafe-secret-host-data"
    )
    captured: list[tuple[object, object]] = []

    class CapturingErrorDialog:
        @classmethod
        def from_domain_error(cls, received, parent=None):
            captured.append((received, QThread.currentThread()))
            assert parent is window
            return cls()

        def exec(self):
            return QDialog.DialogCode.Rejected

    monkeypatch.setattr("app.gui.main_window.ErrorDialog", CapturingErrorDialog)

    controller.error_raised.emit("web01", error)

    assert captured == [(error, window.thread())]
    assert controller.host_key_decisions == []
