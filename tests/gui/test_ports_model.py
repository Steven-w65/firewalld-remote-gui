from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from PySide6.QtCore import QModelIndex, QRect, QSortFilterProxyModel, Qt
from PySide6.QtGui import QPixmap
from PySide6.QtTest import QSignalSpy
from PySide6.QtWidgets import QProxyStyle, QStyle

from app.controllers.session import ServerSessionView
from app.gui.models.ports_model import (
    PortPresenceFilter,
    PortsFilterProxyModel,
    PortsTableModel,
    merge_port_rows,
)
from app.gui.ports_tab import PortsTab
from app.models.enums import ConnectionStatus
from app.models.firewall import FirewallPort, FirewallSnapshot, ZoneState
from app.models.port import PortRow
from app.utils.errors import InvalidFirewallArgumentError


_DEFAULT_SNAPSHOT = object()


def _snapshot(*, stale: bool = False) -> FirewallSnapshot:
    return FirewallSnapshot(
        hostname="web01",
        distribution="Example Linux 10",
        firewalld_running=True,
        firewalld_version="2.2.1",
        default_zone="public",
        runtime_zones=(
            ZoneState(
                "public",
                ports=(
                    FirewallPort("100", "tcp", "public", True, False),
                    FirewallPort("22", "TCP", "public", False, True),
                    FirewallPort("22", "tcp", "public", True, False),
                ),
            ),
            ZoneState(
                "internal",
                ports=(FirewallPort("53", "udp", "internal", True, False),),
            ),
        ),
        permanent_zones=(
            ZoneState(
                "public",
                ports=(
                    FirewallPort("22", "tcp", "public", False, True),
                    FirewallPort("8000-8100", "tcp", "public", False, True),
                ),
                permanent=True,
            ),
            ZoneState("dmz", permanent=True),
        ),
        stale=stale,
    )


def _view(
    status: ConnectionStatus = ConnectionStatus.CONNECTED,
    *,
    snapshot: FirewallSnapshot | None | object = _DEFAULT_SNAPSHOT,
    busy_operation: str | None = None,
    server_id: str = "web01",
) -> ServerSessionView:
    return ServerSessionView(
        server_id=server_id,
        name="Production Web",
        host="192.0.2.10",
        port=22,
        username="operator",
        sudo_enabled=True,
        generation=4,
        status=status,
        snapshot=(
            _snapshot()
            if snapshot is _DEFAULT_SNAPSHOT and status is ConnectionStatus.CONNECTED
            else None if snapshot is _DEFAULT_SNAPSHOT else snapshot
        ),
        latest_error=None,
        busy_operation=busy_operation,
    )


def _visible_ports(proxy: QSortFilterProxyModel) -> tuple[str, ...]:
    return tuple(
        str(proxy.data(proxy.index(row, 0), Qt.ItemDataRole.DisplayRole))
        for row in range(proxy.rowCount())
    )


def test_port_row_is_frozen_validated_and_normalized():
    row = PortRow("8000-8100", "TCP", "public", True, False)

    assert row == PortRow("8000-8100", "tcp", "public", True, False)
    with pytest.raises(FrozenInstanceError):
        row.port = "22"
    with pytest.raises(InvalidFirewallArgumentError):
        PortRow("22; id", "tcp", "public", True, False)
    with pytest.raises(InvalidFirewallArgumentError):
        PortRow("22", "icmp", "public", True, False)
    with pytest.raises(TypeError):
        PortRow("22", "tcp", "public", 1, False)
    with pytest.raises(ValueError, match="runtime or permanent"):
        PortRow("22", "tcp", "public", False, False)


def test_merge_marks_membership_from_target_inventories_and_collapses_duplicates():
    rows = merge_port_rows(_snapshot(), "public")
    by_port = {(row.port, row.protocol): row for row in rows}

    assert len(rows) == 3
    assert by_port[("22", "tcp")].runtime
    assert by_port[("22", "tcp")].permanent
    assert by_port[("100", "tcp")].runtime
    assert not by_port[("100", "tcp")].permanent
    assert not by_port[("8000-8100", "tcp")].runtime
    assert by_port[("8000-8100", "tcp")].permanent


def test_merge_sorts_numeric_ports_and_ranges_deterministically():
    rows = merge_port_rows(_snapshot(), "public")

    assert [(row.port, row.protocol, row.zone) for row in rows] == [
        ("22", "tcp", "public"),
        ("100", "tcp", "public"),
        ("8000-8100", "tcp", "public"),
    ]


def test_merge_returns_empty_for_missing_zone_and_rejects_unsafe_snapshot_values():
    assert merge_port_rows(_snapshot(), "trusted") == ()
    with pytest.raises(InvalidFirewallArgumentError):
        merge_port_rows(_snapshot(), "public; id")

    malformed = FirewallSnapshot(
        hostname="web01",
        distribution="Linux",
        firewalld_running=True,
        firewalld_version=None,
        default_zone="public",
        runtime_zones=(
            ZoneState(
                "public",
                ports=(FirewallPort("8100-8000", "tcp", "public", True, False),),
            ),
        ),
    )
    with pytest.raises(InvalidFirewallArgumentError):
        merge_port_rows(malformed, "public")


def test_model_exposes_required_columns_safe_empty_roles_and_accessible_booleans(qtbot):
    model = PortsTableModel((PortRow("22", "tcp", "public", True, False),))

    assert [
        model.headerData(i, Qt.Orientation.Horizontal)
        for i in range(model.columnCount())
    ] == ["Port", "Protocol", "Zone", "Runtime", "Permanent"]
    assert model.data(QModelIndex(), Qt.ItemDataRole.DisplayRole) is None
    assert model.data(model.index(0, 0), Qt.ItemDataRole.UserRole) is None
    assert model.data(model.index(0, 3), Qt.ItemDataRole.DisplayRole) is None
    assert model.data(model.index(0, 4), Qt.ItemDataRole.DisplayRole) is None
    assert model.data(model.index(0, 3), Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.Checked
    assert model.data(model.index(0, 4), Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.Unchecked
    assert model.data(model.index(0, 3), Qt.ItemDataRole.AccessibleTextRole) == "Runtime: Yes"
    assert model.data(model.index(0, 4), Qt.ItemDataRole.AccessibleTextRole) == "Permanent: No"
    assert not (model.flags(model.index(0, 3)) & Qt.ItemFlag.ItemIsUserCheckable)


def test_ports_tab_centers_the_only_status_indicator_in_boolean_columns(qtbot):
    class RecordingStyle(QProxyStyle):
        def __init__(self):
            super().__init__()
            self.checkbox_rects: list[QRect] = []

        def drawPrimitive(self, element, option, painter, widget=None):
            if element is QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck:
                self.checkbox_rects.append(QRect(option.rect))
            super().drawPrimitive(element, option, painter, widget)

    tab = PortsTab()
    qtbot.addWidget(tab)
    tab.resize(900, 400)
    tab.set_session(_view())
    recording_style = RecordingStyle()
    recording_style.setParent(tab)
    tab.table.setStyle(recording_style)
    tab.show()

    recording_style.checkbox_rects.clear()
    pixmap = QPixmap(tab.table.viewport().size())
    tab.table.viewport().render(pixmap)

    for column in (3, 4):
        cell_rect = tab.table.visualRect(tab.proxy_model.index(0, column))
        indicators = [
            rect for rect in recording_style.checkbox_rects if cell_rect.contains(rect.center())
        ]
        assert len(indicators) == 1
        assert indicators[0].center() == cell_rect.center()


def test_set_rows_resets_model_and_sort_uses_numeric_port_bounds(qtbot):
    model = PortsTableModel()
    reset = QSignalSpy(model.modelReset)

    model.set_rows(
        (
            PortRow("100", "udp", "public", True, False),
            PortRow("22", "tcp", "public", True, True),
            PortRow("100", "tcp", "public", False, True),
            PortRow("22-30", "udp", "internal", True, False),
        )
    )
    model.sort(0, Qt.SortOrder.AscendingOrder)

    assert reset.count() == 1
    assert [model.row_at(row) for row in range(model.rowCount())] == [
        PortRow("22", "tcp", "public", True, True),
        PortRow("22-30", "udp", "internal", True, False),
        PortRow("100", "tcp", "public", False, True),
        PortRow("100", "udp", "public", True, False),
    ]

    model.sort(0, Qt.SortOrder.DescendingOrder)
    assert tuple(model.row_at(row).port for row in range(model.rowCount())) == (
        "100",
        "100",
        "22-30",
        "22",
    )


def test_proxy_searches_three_text_columns_case_insensitively_and_filters_presence(qtbot):
    source = PortsTableModel(
        (
            PortRow("22", "tcp", "public", True, True),
            PortRow("53", "udp", "internal", True, False),
            PortRow("8000-8100", "tcp", "public", False, True),
        )
    )
    proxy = PortsFilterProxyModel()
    proxy.setSourceModel(source)

    proxy.set_search_text("PUB")
    assert _visible_ports(proxy) == ("22", "8000-8100")
    proxy.set_search_text("UDP")
    assert _visible_ports(proxy) == ("53",)
    proxy.set_search_text("8100")
    assert _visible_ports(proxy) == ("8000-8100",)

    proxy.set_search_text("")
    for presence, expected in (
        (PortPresenceFilter.ALL, ("22", "53", "8000-8100")),
        (PortPresenceFilter.RUNTIME, ("22", "53")),
        (PortPresenceFilter.PERMANENT, ("22", "8000-8100")),
        (PortPresenceFilter.BOTH, ("22",)),
    ):
        proxy.set_presence_filter(presence)
        assert _visible_ports(proxy) == expected

    with pytest.raises(TypeError):
        proxy.set_presence_filter("Runtime")


def test_proxy_numeric_sort_and_row_mapping_preserve_exact_source_row(qtbot):
    source = PortsTableModel(
        (
            PortRow("100", "tcp", "public", True, False),
            PortRow("22", "udp", "internal", False, True),
        )
    )
    proxy = PortsFilterProxyModel()
    proxy.setSourceModel(source)

    proxy.sort(0, Qt.SortOrder.AscendingOrder)

    assert _visible_ports(proxy) == ("22", "100")
    assert proxy.port_row(proxy.index(0, 0)) == PortRow(
        "22", "udp", "internal", False, True
    )
    assert proxy.port_row(QModelIndex()) is None


def test_ports_tab_applies_every_plain_string_presence_choice_without_mutating_source(
    qtbot,
):
    tab = PortsTab()
    qtbot.addWidget(tab)
    tab.set_session(_view())
    source_before = tuple(
        tab.source_model.row_at(row)
        for row in range(tab.source_model.rowCount())
    )

    for index, expected in (
        (1, ("22", "100")),
        (2, ("22", "8000-8100")),
        (3, ("22",)),
        (0, ("22", "100", "8000-8100")),
    ):
        tab.table.selectRow(0)
        assert tab.selected_row() is not None
        assert tab.remove_button.isEnabled()

        tab.view_combo.setCurrentIndex(index)

        assert type(tab.view_combo.currentData()) is str
        assert _visible_ports(tab.proxy_model) == expected
        assert tab.selected_row() is None
        assert not tab.remove_button.isEnabled()
        assert tuple(
            tab.source_model.row_at(row)
            for row in range(tab.source_model.rowCount())
        ) == source_before


def test_ports_tab_invalid_presence_data_fails_safe_to_all_instead_of_staying_stale(
    qtbot,
):
    tab = PortsTab()
    qtbot.addWidget(tab)
    tab.set_session(_view())
    tab.view_combo.setCurrentIndex(1)
    tab.proxy_model.set_presence_filter(PortPresenceFilter.RUNTIME)
    assert _visible_ports(tab.proxy_model) == ("22", "100")
    tab.table.selectRow(0)

    tab.view_combo.setItemData(0, "")
    tab.view_combo.setCurrentIndex(0)

    assert _visible_ports(tab.proxy_model) == ("22", "100", "8000-8100")
    assert tab.selected_row() is None


def test_ports_tab_uses_snapshot_zone_union_and_emits_exact_intentions(qtbot):
    tab = PortsTab()
    qtbot.addWidget(tab)
    tab.set_session(_view())
    refreshed = QSignalSpy(tab.refresh_requested)
    added = QSignalSpy(tab.add_requested)
    removed = QSignalSpy(tab.remove_requested)

    assert tuple(tab.zone_combo.itemText(i) for i in range(tab.zone_combo.count())) == (
        "public",
        "internal",
        "dmz",
    )
    assert tab.zone_combo.currentText() == "public"
    assert _visible_ports(tab.proxy_model) == ("22", "100", "8000-8100")
    assert tab.status_label.text() == "3 ports in public"

    tab.refresh_button.click()
    tab.add_button.click()
    tab.proxy_model.sort(0, Qt.SortOrder.DescendingOrder)
    tab.table.selectRow(0)
    assert tab.selected_row() == PortRow("8000-8100", "tcp", "public", False, True)
    tab.remove_button.click()

    assert refreshed.at(0) == ["public"]
    assert added.count() == 1
    assert removed.count() == 1
    assert removed.at(0)[0] == PortRow("8000-8100", "tcp", "public", False, True)


@pytest.mark.parametrize(
    ("view", "status_text", "refresh_enabled", "add_enabled"),
    (
        (None, "No server selected", False, False),
        (_view(ConnectionStatus.DISCONNECTED), "Disconnected", False, False),
        (
            _view(ConnectionStatus.CONNECTED, snapshot=None),
            "No firewall data is available",
            False,
            False,
        ),
        (
            _view(busy_operation="refresh"),
            "Refresh in progress",
            False,
            False,
        ),
        (
            _view(snapshot=_snapshot(stale=True)),
            "Stale firewall data",
            True,
            False,
        ),
    ),
)
def test_ports_tab_renders_explicit_states_and_derives_action_availability(
    qtbot, view, status_text, refresh_enabled, add_enabled
):
    tab = PortsTab()
    qtbot.addWidget(tab)

    tab.set_session(view)

    assert tab.status_label.text() == status_text
    assert tab.refresh_button.isEnabled() is refresh_enabled
    assert tab.add_button.isEnabled() is add_enabled
    assert not tab.remove_button.isEnabled()


def test_ports_tab_empty_zone_state_and_search_are_honest(qtbot):
    empty = FirewallSnapshot(
        hostname="web01",
        distribution="Linux",
        firewalld_running=True,
        firewalld_version=None,
        default_zone="public",
    )
    tab = PortsTab()
    qtbot.addWidget(tab)

    tab.set_session(_view(snapshot=empty))
    assert tab.zone_combo.count() == 0
    assert tab.status_label.text() == "No zones are available in this snapshot"
    assert not tab.add_button.isEnabled()

    tab.set_session(_view())
    tab.search_edit.setText("not-present")
    assert tab.status_label.text() == "No ports match the current filters"
    assert not tab.remove_button.isEnabled()


def test_ports_tab_clears_selection_when_filter_or_session_changes(qtbot):
    tab = PortsTab()
    qtbot.addWidget(tab)
    tab.set_session(_view())
    tab.table.selectRow(0)
    assert tab.remove_button.isEnabled()

    tab.search_edit.setText("not-present")
    assert tab.selected_row() is None
    assert not tab.remove_button.isEnabled()

    tab.set_session(_view(server_id="db01"))
    assert tab.selected_row() is None
    assert not tab.remove_button.isEnabled()
