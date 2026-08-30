from __future__ import annotations

from dataclasses import replace

import pytest
from PySide6.QtCore import QObject, Signal

from app.controllers.session import ServerSessionView
from app.gui.main_window import MainWindow
from app.models.enums import ConnectionStatus
from app.models.firewall import FirewallSnapshot


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
        self.refresh_calls: list[str] = []
        self.reload_calls = 0
        self.shutdown_calls: list[int] = []

    def sessions(self) -> tuple[ServerSessionView, ...]:
        return tuple(self._views[server_id] for server_id in self._order)

    def session_view(self, server_id: str) -> ServerSessionView:
        return self._views[server_id]

    def select(self, server_id: str) -> None:
        self.selected_server_id = server_id
        self.selection_changed.emit(server_id)

    def connect(self, server_id: str) -> None:
        self.connect_calls.append(server_id)

    def disconnect(self, server_id: str) -> None:
        self.disconnect_calls.append(server_id)

    def refresh(self, server_id: str) -> None:
        self.refresh_calls.append(server_id)

    def reload_configuration(self) -> None:
        self.reload_calls += 1

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        self.shutdown_calls.append(timeout_ms)
        return True

    def publish(self, replacement: ServerSessionView) -> None:
        self._views[replacement.server_id] = replacement
        self.session_changed.emit(replacement.server_id)


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
    assert window.state_panels[0].state_key == "connected"


def test_unselected_session_update_does_not_replace_visible_content(
    window, controller
):
    selected_before = window.state_panels[0].message_label.text()

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
    assert window.state_panels[0].message_label.text() == selected_before


def test_shell_has_exact_tab_order_and_accessible_state_panels(window):
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
    assert len(window.state_panels) == 7
    assert all(panel.accessibleName() for panel in window.state_panels)


@pytest.mark.parametrize(
    ("replacement", "state_key", "text"),
    [
        (view("web01", "Web"), "disconnected", "Disconnected"),
        (
            view(
                "web01",
                "Web",
                ConnectionStatus.CONNECTING,
                busy_operation="connect",
            ),
            "busy",
            "Connecting",
        ),
        (
            view("web01", "Web", ConnectionStatus.CONNECTED),
            "empty",
            "No firewall data",
        ),
        (
            view(
                "web01",
                "Web",
                ConnectionStatus.CONNECTED,
                current_snapshot=snapshot(hostname="web01"),
            ),
            "connected",
            "Connected",
        ),
        (
            view(
                "web01",
                "Web",
                ConnectionStatus.CONNECTED,
                current_snapshot=snapshot(hostname="web01", stale=True),
            ),
            "stale",
            "Stale data",
        ),
        (
            view(
                "web01",
                "Web",
                ConnectionStatus.CONNECTION_ERROR,
                latest_error="unsafe ssh-secret details",
            ),
            "error",
            "Connection error",
        ),
    ],
)
def test_state_panels_render_safe_icon_and_text(
    window, controller, replacement, state_key, text
):
    controller.publish(replacement)

    panel = window.state_panels[0]
    assert panel.state_key == state_key
    assert text in panel.message_label.text()
    assert panel.icon_label.pixmap() is not None
    assert not panel.icon_label.pixmap().isNull()
    assert "ssh-secret" not in panel.message_label.text()


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
    assert window.state_panels[0].state_key == "no_selection"


def test_shutdown_is_bounded_and_invoked_exactly_once(window, controller):
    window.shutdown_once()
    window.shutdown_once()
    window.close()

    assert controller.shutdown_calls == [5000]

