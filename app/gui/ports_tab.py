"""Snapshot-only Ports presentation and user-intention signals."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from app.controllers.session import ServerSessionView
from app.gui.models.ports_model import (
    PortPresenceFilter,
    PortsFilterProxyModel,
    PortsTableModel,
    merge_port_rows,
)
from app.gui.server_sidebar import status_presentation
from app.models.enums import ConnectionStatus
from app.models.firewall import FirewallSnapshot
from app.models.port import PortRow
from app.utils.validation import validate_inventory_token


class PortsTab(QWidget):
    """Render immutable port state and emit no more than exact intentions."""

    refresh_requested = Signal(str)
    add_requested = Signal()
    remove_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName("Firewall ports")
        self._session: ServerSessionView | None = None
        self._server_id: str | None = None

        self.zone_combo = QComboBox()
        self.zone_combo.setAccessibleName("Port zone")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search port, protocol, or zone")
        self.search_edit.setAccessibleName("Search ports")
        self.view_combo = QComboBox()
        self.view_combo.setAccessibleName("Port presence filter")
        for label, presence in (
            ("All", PortPresenceFilter.ALL),
            ("Runtime", PortPresenceFilter.RUNTIME),
            ("Permanent", PortPresenceFilter.PERMANENT),
            ("Both", PortPresenceFilter.BOTH),
        ):
            self.view_combo.addItem(label, presence)

        filters = QHBoxLayout()
        filters.addWidget(QLabel("Zone"))
        filters.addWidget(self.zone_combo)
        filters.addWidget(QLabel("Search"))
        filters.addWidget(self.search_edit, 1)
        filters.addWidget(QLabel("View"))
        filters.addWidget(self.view_combo)

        self.source_model = PortsTableModel(parent=self)
        self.proxy_model = PortsFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.source_model)
        self.table = QTableView()
        self.table.setAccessibleName("Firewall ports table")
        self.table.setModel(self.proxy_model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.proxy_model.sort(0)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setAccessibleName("Ports status")
        self.refresh_button = QPushButton("Refresh")
        self.add_button = QPushButton("Add Port")
        self.remove_button = QPushButton("Remove Port")
        actions = QHBoxLayout()
        actions.addWidget(self.status_label, 1)
        actions.addWidget(self.refresh_button)
        actions.addWidget(self.add_button)
        actions.addWidget(self.remove_button)

        layout = QVBoxLayout(self)
        layout.addLayout(filters)
        layout.addWidget(self.table, 1)
        layout.addLayout(actions)

        self.zone_combo.currentTextChanged.connect(self._zone_changed)
        self.search_edit.textChanged.connect(self._search_changed)
        self.view_combo.currentIndexChanged.connect(self._presence_changed)
        self.table.selectionModel().selectionChanged.connect(
            self._selection_changed
        )
        self.refresh_button.clicked.connect(self._emit_refresh)
        self.add_button.clicked.connect(self.add_requested)
        self.remove_button.clicked.connect(self._emit_remove)
        self.set_session(None)

    def set_session(self, view: ServerSessionView | None) -> None:
        previous_zone = self.zone_combo.currentText()
        same_server = view is not None and view.server_id == self._server_id
        self._session = view
        self._server_id = None if view is None else view.server_id
        snapshot = None if view is None else view.snapshot
        zones = self._snapshot_zones(snapshot)

        self.zone_combo.blockSignals(True)
        self.zone_combo.clear()
        self.zone_combo.addItems(zones)
        preferred = ""
        if same_server and previous_zone in zones:
            preferred = previous_zone
        elif snapshot is not None and snapshot.default_zone in zones:
            preferred = snapshot.default_zone
        elif zones:
            preferred = zones[0]
        if preferred:
            self.zone_combo.setCurrentText(preferred)
        self.zone_combo.blockSignals(False)
        self.table.clearSelection()
        self._load_selected_zone()

    def selected_row(self) -> PortRow | None:
        selected = self.table.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        return self.proxy_model.port_row(selected[0])

    @staticmethod
    def _snapshot_zones(snapshot: FirewallSnapshot | None) -> tuple[str, ...]:
        if snapshot is None:
            return ()
        result: list[str] = []
        for zone in snapshot.runtime_zones + snapshot.permanent_zones:
            name = validate_inventory_token("zone", zone.name)
            if name not in result:
                result.append(name)
        return tuple(result)

    def _load_selected_zone(self) -> None:
        view = self._session
        zone = self.zone_combo.currentText()
        if view is None or view.snapshot is None or not zone:
            self.source_model.set_rows(())
        else:
            self.source_model.set_rows(merge_port_rows(view.snapshot, zone))
        self._update_state()

    def _zone_changed(self) -> None:
        self.table.clearSelection()
        self._load_selected_zone()

    def _search_changed(self, text: str) -> None:
        self.table.clearSelection()
        self.proxy_model.set_search_text(text)
        self._update_state()

    def _presence_changed(self) -> None:
        self.table.clearSelection()
        presence = self.view_combo.currentData()
        if isinstance(presence, PortPresenceFilter):
            self.proxy_model.set_presence_filter(presence)
        self._update_state()

    def _selection_changed(self) -> None:
        self._update_actions()

    def _connected_idle(self) -> bool:
        view = self._session
        return bool(
            view is not None
            and view.status is ConnectionStatus.CONNECTED
            and view.busy_operation is None
            and view.snapshot is not None
            and self.zone_combo.currentText()
        )

    def _update_state(self) -> None:
        view = self._session
        if view is None:
            text = "No server selected"
        elif view.busy_operation or view.status is ConnectionStatus.CONNECTING:
            operation = (
                "Connecting"
                if view.status is ConnectionStatus.CONNECTING
                else (view.busy_operation or "operation").replace("_", " ").title()
            )
            text = f"{operation} in progress"
        elif view.status is ConnectionStatus.DISCONNECTED:
            text = "Disconnected"
        elif view.status is not ConnectionStatus.CONNECTED:
            text = status_presentation(view.status)[0]
        elif view.snapshot is None:
            text = "No firewall data is available"
        elif self.zone_combo.count() == 0:
            text = "No zones are available in this snapshot"
        elif view.snapshot.stale:
            text = "Stale firewall data"
        elif self.proxy_model.rowCount() == 0 and self.source_model.rowCount() > 0:
            text = "No ports match the current filters"
        elif self.source_model.rowCount() == 0:
            text = f"No ports configured in {self.zone_combo.currentText()}"
        else:
            count = self.proxy_model.rowCount()
            noun = "port" if count == 1 else "ports"
            text = f"{count} {noun} in {self.zone_combo.currentText()}"
        self.status_label.setText(text)
        self.status_label.setAccessibleDescription(text)
        self._update_actions()

    def _update_actions(self) -> None:
        enabled = self._connected_idle()
        self.refresh_button.setEnabled(enabled)
        self.add_button.setEnabled(enabled)
        self.remove_button.setEnabled(enabled and self.selected_row() is not None)

    def _emit_refresh(self) -> None:
        if self._connected_idle():
            self.refresh_requested.emit(self.zone_combo.currentText())

    def _emit_remove(self) -> None:
        row = self.selected_row()
        if self._connected_idle() and row is not None:
            self.remove_requested.emit(row)


__all__ = ["PortsTab"]
