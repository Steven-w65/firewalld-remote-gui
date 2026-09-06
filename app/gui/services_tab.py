"""Snapshot-only Services presentation and exact intention signals."""

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
from app.gui.models.services_model import (
    ServicePresenceFilter,
    ServicesFilterProxyModel,
    ServicesTableModel,
    merge_service_rows,
)
from app.gui.server_sidebar import status_presentation
from app.gui.widgets.checkbox_delegate import CenteredCheckBoxDelegate
from app.models.command import CompositeOperationResult
from app.models.enums import ApplyTarget, ConnectionStatus, TargetStatus
from app.models.firewall import FirewallSnapshot
from app.models.service import ServiceRow
from app.utils.validation import validate_inventory_token


class ServicesTab(QWidget):
    """Render immutable service state and emit only validated row intentions."""

    refresh_requested = Signal(str)
    add_requested = Signal()
    remove_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName("Firewall services")
        self._session: ServerSessionView | None = None
        self._server_id: str | None = None

        self.zone_combo = QComboBox()
        self.zone_combo.setAccessibleName("Service zone")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search service or zone")
        self.search_edit.setAccessibleName("Search services")
        self.view_combo = QComboBox()
        self.view_combo.setAccessibleName("Service presence filter")
        for label, presence in (
            ("All", ServicePresenceFilter.ALL),
            ("Runtime", ServicePresenceFilter.RUNTIME),
            ("Permanent", ServicePresenceFilter.PERMANENT),
            ("Both", ServicePresenceFilter.BOTH),
        ):
            self.view_combo.addItem(label, presence)

        filters = QHBoxLayout()
        filters.addWidget(QLabel("Zone"))
        filters.addWidget(self.zone_combo)
        filters.addWidget(QLabel("Search"))
        filters.addWidget(self.search_edit, 1)
        filters.addWidget(QLabel("View"))
        filters.addWidget(self.view_combo)

        self.source_model = ServicesTableModel(parent=self)
        self.proxy_model = ServicesFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.source_model)
        self.table = QTableView()
        self.table.setAccessibleName("Firewall services table")
        self.table.setModel(self.proxy_model)
        self._presence_delegate = CenteredCheckBoxDelegate(self.table)
        self.table.setItemDelegateForColumn(2, self._presence_delegate)
        self.table.setItemDelegateForColumn(3, self._presence_delegate)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.proxy_model.sort(0)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setAccessibleName("Services status")
        self.result_label = QLabel()
        self.result_label.setWordWrap(True)
        self.result_label.setAccessibleName("Latest service operation result")
        self.refresh_button = QPushButton("Refresh")
        self.add_button = QPushButton("Add Service")
        self.remove_button = QPushButton("Remove Service")
        actions = QHBoxLayout()
        actions.addWidget(self.status_label, 1)
        actions.addWidget(self.refresh_button)
        actions.addWidget(self.add_button)
        actions.addWidget(self.remove_button)

        layout = QVBoxLayout(self)
        layout.addLayout(filters)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.result_label)
        layout.addLayout(actions)

        self.zone_combo.currentTextChanged.connect(self._zone_changed)
        self.search_edit.textChanged.connect(self._search_changed)
        self.view_combo.currentIndexChanged.connect(self._presence_changed)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        self.refresh_button.clicked.connect(self._emit_refresh)
        self.add_button.clicked.connect(self.add_requested)
        self.remove_button.clicked.connect(self._emit_remove)
        self.set_session(None)

    def set_session(self, view: ServerSessionView | None) -> None:
        previous_zone = self.zone_combo.currentText()
        previous_generation = None if self._session is None else self._session.generation
        same_server = view is not None and view.server_id == self._server_id
        same_session = (
            same_server and view is not None and view.generation == previous_generation
        )
        self._session = view
        self._server_id = None if view is None else view.server_id
        if not same_session:
            self.result_label.clear()
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

    def available_zones(self) -> tuple[str, ...]:
        return tuple(
            self.zone_combo.itemText(index)
            for index in range(self.zone_combo.count())
        )

    def rows(self) -> tuple[ServiceRow, ...]:
        return self.source_model.rows()

    def inventory_rows(self) -> tuple[ServiceRow, ...]:
        view = self._session
        if view is None or view.snapshot is None:
            return ()
        return tuple(
            row
            for zone in self._snapshot_zones(view.snapshot)
            for row in merge_service_rows(view.snapshot, zone)
        )

    def contains(self, service: str, zone: str | None = None) -> bool:
        return any(
            row.name == service and (zone is None or row.zone == zone)
            for row in self.source_model.rows()
        )

    def show_operation_result(self, result: CompositeOperationResult) -> None:
        if not isinstance(result, CompositeOperationResult) or result.operation not in {
            "add_service",
            "remove_service",
        }:
            return
        targets = tuple(
            item for item in (result.permanent, result.runtime) if item is not None
        )
        verification_failed = any(
            item.execution_status is TargetStatus.SUCCEEDED
            and item.verification_status is TargetStatus.FAILED
            for item in targets
        )
        if result.is_success:
            text = "Service change completed and verified."
        elif result.is_partial:
            text = (
                "Service change partially completed. Review the Runtime and Permanent "
                "results before another change."
            )
        elif verification_failed:
            text = (
                "The service command completed, but verification did not confirm "
                "the requested firewall state."
            )
        else:
            text = "The service change did not complete. Firewall state was refreshed."
        self.result_label.setText(text)
        self.result_label.setAccessibleDescription(text)

    @staticmethod
    def target_for_row(row: ServiceRow) -> ApplyTarget:
        if not isinstance(row, ServiceRow):
            raise TypeError("row must be a ServiceRow")
        if row.runtime and row.permanent:
            return ApplyTarget.BOTH
        if row.runtime:
            return ApplyTarget.RUNTIME
        return ApplyTarget.PERMANENT

    def selected_row(self) -> ServiceRow | None:
        selected = self.table.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        return self.proxy_model.service_row(selected[0])

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
            self.source_model.set_rows(merge_service_rows(view.snapshot, zone))
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
        try:
            presence = ServicePresenceFilter(self.view_combo.currentData())
        except (TypeError, ValueError):
            presence = ServicePresenceFilter.ALL
        self.proxy_model.set_presence_filter(presence)
        self._update_state()

    def _selection_changed(self) -> None:
        self._update_actions()

    def _can_refresh(self) -> bool:
        view = self._session
        return bool(
            view is not None
            and view.status is ConnectionStatus.CONNECTED
            and view.busy_operation is None
            and view.snapshot is not None
            and self.zone_combo.currentText()
        )

    def _can_modify(self) -> bool:
        return bool(
            self._can_refresh()
            and self._session is not None
            and self._session.snapshot is not None
            and not self._session.snapshot.stale
            and self._session.snapshot.available_services
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
        elif not view.snapshot.available_services:
            text = "No remote services are available in this snapshot"
        elif self.proxy_model.rowCount() == 0 and self.source_model.rowCount() > 0:
            text = "No services match the current filters"
        elif self.source_model.rowCount() == 0:
            text = f"No services configured in {self.zone_combo.currentText()}"
        else:
            count = self.proxy_model.rowCount()
            noun = "service" if count == 1 else "services"
            text = f"{count} {noun} in {self.zone_combo.currentText()}"
        self.status_label.setText(text)
        self.status_label.setAccessibleDescription(text)
        self._update_actions()

    def _update_actions(self) -> None:
        self.refresh_button.setEnabled(self._can_refresh())
        enabled = self._can_modify()
        self.add_button.setEnabled(enabled)
        self.remove_button.setEnabled(enabled and self.selected_row() is not None)

    def _emit_refresh(self) -> None:
        if self._can_refresh():
            self.refresh_requested.emit(self.zone_combo.currentText())

    def _emit_remove(self) -> None:
        row = self.selected_row()
        if self._can_modify() and row is not None:
            self.remove_requested.emit(row)


__all__ = ["ServicesTab"]
