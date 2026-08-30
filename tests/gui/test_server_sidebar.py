from __future__ import annotations

from dataclasses import replace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QSignalSpy

from app.controllers.session import ServerSessionView
from app.gui.server_sidebar import ServerSidebar
from app.models.enums import ConnectionStatus


def make_view(
    server_id: str,
    name: str,
    status: ConnectionStatus = ConnectionStatus.DISCONNECTED,
    *,
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
        snapshot=None,
        latest_error=None,
        busy_operation=busy_operation,
    )


def test_sidebar_preserves_configured_order_and_selection_without_emitting(qtbot):
    sidebar = ServerSidebar()
    qtbot.addWidget(sidebar)
    selected = QSignalSpy(sidebar.server_selected)
    sessions = (
        make_view("web01", "Production Web"),
        make_view("db01", "Database Server"),
        make_view("test01", "Test Server"),
    )

    sidebar.set_sessions(sessions, "db01")

    assert sidebar.server_ids() == ("web01", "db01", "test01")
    assert sidebar.selected_server_id() == "db01"
    assert selected.count() == 0


@pytest.mark.parametrize(
    ("status", "expected_text"),
    [
        (ConnectionStatus.DISCONNECTED, "Disconnected"),
        (ConnectionStatus.CONNECTING, "Connecting"),
        (ConnectionStatus.CONNECTED, "Connected"),
        (ConnectionStatus.AUTHENTICATION_FAILED, "Authentication failed"),
        (ConnectionStatus.CONNECTION_ERROR, "Connection error"),
        (ConnectionStatus.HOST_KEY_ERROR, "Host key error"),
        (ConnectionStatus.PERMISSION_ERROR, "Permission denied"),
        (ConnectionStatus.FIREWALLD_NOT_INSTALLED, "firewalld not installed"),
        (ConnectionStatus.FIREWALLD_NOT_RUNNING, "firewalld not running"),
    ],
)
def test_every_connection_state_has_readable_text_and_icon(
    qtbot, status, expected_text
):
    sidebar = ServerSidebar()
    qtbot.addWidget(sidebar)

    sidebar.set_sessions((make_view("web01", "Web", status),), "web01")

    item = sidebar.server_list.item(0)
    assert expected_text in item.text()
    assert not item.icon().isNull()
    assert item.data(Qt.ItemDataRole.AccessibleTextRole) == f"Web, {expected_text}"


def test_sidebar_actions_emit_exact_selected_server_id(qtbot):
    sidebar = ServerSidebar()
    qtbot.addWidget(sidebar)
    disconnected = make_view("web01", "Web")
    connected = replace(
        make_view("db01", "Database"), status=ConnectionStatus.CONNECTED
    )
    sidebar.set_sessions((disconnected, connected), "web01")
    connect_spy = QSignalSpy(sidebar.connect_requested)
    disconnect_spy = QSignalSpy(sidebar.disconnect_requested)
    reload_spy = QSignalSpy(sidebar.reload_requested)

    sidebar.connect_button.click()
    sidebar.select_server("db01")
    sidebar.disconnect_button.click()
    sidebar.reload_button.click()

    assert connect_spy.count() == 1
    assert connect_spy.at(0) == ["web01"]
    assert disconnect_spy.count() == 1
    assert disconnect_spy.at(0) == ["db01"]
    assert reload_spy.count() == 1


def test_busy_state_disables_connect_but_keeps_disconnect_available(qtbot):
    sidebar = ServerSidebar()
    qtbot.addWidget(sidebar)
    view = make_view(
        "web01",
        "Web",
        ConnectionStatus.CONNECTING,
        busy_operation="connect",
    )

    sidebar.set_sessions((view,), "web01")

    assert not sidebar.connect_button.isEnabled()
    assert sidebar.disconnect_button.isEnabled()

