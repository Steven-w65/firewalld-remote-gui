from __future__ import annotations

from dataclasses import replace

import pytest
from PySide6.QtCore import Qt

from app.controllers.session import ServerSessionView
from app.firewalld.service import (
    ConnectionCheck,
    ConnectionTestResult,
    FirewalldInfo,
)
from app.gui.overview_tab import OverviewTab
from app.models.enums import ConnectionStatus
from app.models.firewall import FirewallSnapshot, ZoneState


def _snapshot(*, stale: bool = False) -> FirewallSnapshot:
    return FirewallSnapshot(
        hostname="web01",
        distribution="Example Linux 10",
        firewalld_running=True,
        firewalld_version="2.2.1",
        default_zone="public",
        runtime_zones=(
            ZoneState("public", interfaces=("eth0",), sources=("10.0.0.0/24",)),
            ZoneState("internal"),
        ),
        stale=stale,
    )


def _view(
    status: ConnectionStatus = ConnectionStatus.CONNECTED,
    *,
    snapshot: FirewallSnapshot | None = None,
    busy_operation: str | None = None,
    generation: int = 4,
) -> ServerSessionView:
    return ServerSessionView(
        server_id="web01",
        name="Production Web",
        host="192.0.2.10",
        port=2222,
        username="operator",
        sudo_enabled=True,
        generation=generation,
        status=status,
        snapshot=_snapshot() if snapshot is None and status is ConnectionStatus.CONNECTED else snapshot,
        latest_error=None,
        busy_operation=busy_operation,
    )


def test_overview_renders_connected_snapshot_without_inventing_inactive_zones(qtbot):
    tab = OverviewTab()
    qtbot.addWidget(tab)

    tab.set_session(_view())

    assert tab.server_value.text() == "Production Web"
    assert tab.host_value.text() == "192.0.2.10"
    assert tab.port_value.text() == "2222"
    assert tab.user_value.text() == "operator"
    assert tab.connection_value.text() == "Connected"
    assert tab.hostname_value.text() == "web01"
    assert tab.distribution_value.text() == "Example Linux 10"
    assert tab.firewalld_value.text() == "Running"
    assert tab.firewalld_version_value.text() == "2.2.1"
    assert tab.default_zone_value.text() == "public"
    assert tab.active_zones_value.text() == "public"
    assert tab.interfaces_value.text() == "eth0 (public)"
    assert tab.snapshot_status_label.text() == "Current firewall data"
    assert not tab.snapshot_status_icon.pixmap().isNull()


@pytest.mark.parametrize(
    ("view", "firewalld", "hostname"),
    (
        (_view(ConnectionStatus.DISCONNECTED), "Unknown", "Not available"),
        (_view(ConnectionStatus.FIREWALLD_NOT_INSTALLED), "Not installed", "Not available"),
        (_view(ConnectionStatus.FIREWALLD_NOT_RUNNING), "Stopped", "Not available"),
        (
            _view(
                ConnectionStatus.CONNECTED,
                snapshot=replace(_snapshot(), firewalld_running=False),
            ),
            "Stopped",
            "web01",
        ),
    ),
)
def test_overview_renders_unknown_missing_and_stopped_states_honestly(
    qtbot, view, firewalld, hostname
):
    tab = OverviewTab()
    qtbot.addWidget(tab)

    tab.set_session(view)

    assert tab.firewalld_value.text() == firewalld
    assert tab.hostname_value.text() == hostname


def test_stale_snapshot_is_visible_with_text_and_warning_icon(qtbot):
    tab = OverviewTab()
    qtbot.addWidget(tab)

    tab.set_session(_view(snapshot=_snapshot(stale=True)))

    assert tab.snapshot_status_label.text() == "Stale firewall data"
    assert not tab.snapshot_status_icon.pixmap().isNull()
    assert "stale" in tab.snapshot_status_label.accessibleName().lower()


@pytest.mark.parametrize(
    ("status", "busy", "enabled"),
    (
        (ConnectionStatus.DISCONNECTED, None, (True, False, False, False, False, False)),
        (ConnectionStatus.CONNECTING, "connect", (False, True, False, False, False, False)),
        (ConnectionStatus.CONNECTED, None, (False, True, True, True, True, True)),
        (ConnectionStatus.CONNECTED, "refresh", (False, True, False, False, False, False)),
        (ConnectionStatus.CONNECTION_ERROR, None, (False, True, True, False, False, False)),
    ),
)
def test_action_matrix_is_derived_only_from_session_state(qtbot, status, busy, enabled):
    tab = OverviewTab()
    qtbot.addWidget(tab)

    tab.set_session(_view(status, busy_operation=busy))

    buttons = (
        tab.connect_button,
        tab.disconnect_button,
        tab.reconnect_button,
        tab.refresh_button,
        tab.reload_button,
        tab.test_connection_button,
    )
    assert tuple(button.isEnabled() for button in buttons) == enabled


def test_no_selection_disables_every_action_and_shows_unknown_values(qtbot):
    tab = OverviewTab()
    qtbot.addWidget(tab)

    tab.set_session(None)

    assert tab.server_value.text() == "Not available"
    assert tab.connection_value.text() == "No selection"
    assert not any(
        button.isEnabled()
        for button in (
            tab.connect_button,
            tab.disconnect_button,
            tab.reconnect_button,
            tab.refresh_button,
            tab.reload_button,
            tab.test_connection_button,
        )
    )


def test_connection_result_uses_icon_and_readable_pass_fail_text(qtbot):
    tab = OverviewTab()
    qtbot.addWidget(tab)
    tab.set_session(_view())
    result = ConnectionTestResult(
        hostname="web01",
        distribution="Example Linux 10",
        effective_uid=1000,
        firewalld=FirewalldInfo(True, True, None),
        checks=(
            ConnectionCheck("ssh_connection", True, "SSH connection succeeded."),
            ConnectionCheck("firewalld_version", False, "Version was not available."),
        ),
    )

    tab.show_connection_test(result)

    assert tab.test_results.rowCount() == 2
    assert tab.test_results.item(0, 0).text() == "PASS"
    assert tab.test_results.item(1, 0).text() == "FAIL"
    assert tab.test_results.item(1, 2).text() == "Version was not available."
    assert not tab.test_results.item(0, 0).icon().isNull()
    assert not tab.test_results.item(1, 0).icon().isNull()
    assert tab.test_summary_label.text() == "Firewalld state: Running; version: Unknown"


def test_unknown_firewalld_connection_result_is_not_rendered_as_stopped(qtbot):
    tab = OverviewTab()
    qtbot.addWidget(tab)
    tab.set_session(_view())

    tab.show_connection_test(
        ConnectionTestResult(
            hostname=None,
            distribution=None,
            effective_uid=None,
            firewalld=None,
            checks=(ConnectionCheck("firewalld_state", False, "State probe failed."),),
        )
    )

    assert tab.test_summary_label.text() == "Firewalld state: Unknown; version: Unknown"


def test_session_identity_change_clears_previous_connection_result(qtbot):
    tab = OverviewTab()
    qtbot.addWidget(tab)
    tab.set_session(_view(generation=4))
    tab.show_connection_test(
        ConnectionTestResult(
            hostname="web01",
            distribution="Example Linux 10",
            effective_uid=1000,
            firewalld=FirewalldInfo(True, True, "2.2.1"),
            checks=(ConnectionCheck("ssh_connection", True, "ok"),),
        )
    )

    tab.set_session(_view(generation=5))

    assert tab.test_results.rowCount() == 0
    assert tab.test_summary_label.text() == "No connection test has been run."


def test_buttons_emit_only_intentions(qtbot):
    tab = OverviewTab()
    qtbot.addWidget(tab)
    tab.set_session(_view())
    emitted: list[str] = []
    tab.disconnect_requested.connect(lambda: emitted.append("disconnect"))
    tab.reconnect_requested.connect(lambda: emitted.append("reconnect"))
    tab.refresh_requested.connect(lambda: emitted.append("refresh"))
    tab.reload_firewalld_requested.connect(lambda: emitted.append("reload"))
    tab.test_connection_requested.connect(lambda: emitted.append("test"))

    for button in (
        tab.disconnect_button,
        tab.reconnect_button,
        tab.refresh_button,
        tab.reload_button,
        tab.test_connection_button,
    ):
        qtbot.mouseClick(button, Qt.MouseButton.LeftButton)

    assert emitted == ["disconnect", "reconnect", "refresh", "reload", "test"]
