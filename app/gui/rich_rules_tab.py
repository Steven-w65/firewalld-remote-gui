"""Snapshot-only structured Rich Rules presentation and intentions."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from app.controllers.session import ServerSessionView
from app.gui.models.rich_rules_model import RichRulesTableModel, merge_rich_rule_rows
from app.gui.server_sidebar import status_presentation
from app.models.command import CompositeOperationResult
from app.models.enums import ApplyTarget, ConnectionStatus, TargetStatus
from app.models.firewall import FirewallSnapshot
from app.models.rich_rule import RichRuleRow
from app.utils.validation import validate_inventory_token


class RichRulesTab(QWidget):
    refresh_requested = Signal()
    add_requested = Signal()
    remove_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName("Structured rich rules")
        self._session: ServerSessionView | None = None
        self._server_id: str | None = None

        self.zone_combo = QComboBox()
        self.zone_combo.setAccessibleName("Rich-rule zone")
        filters = QHBoxLayout()
        filters.addWidget(QLabel("Zone"))
        filters.addWidget(self.zone_combo)
        filters.addStretch(1)

        self.model = RichRulesTableModel(parent=self)
        self.table = QTableView()
        self.table.setAccessibleName("Firewall rich rules table")
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.result_label = QLabel()
        self.result_label.setWordWrap(True)
        self.refresh_button = QPushButton("Refresh")
        self.add_button = QPushButton("Add Rule")
        self.remove_button = QPushButton("Remove Rule")
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

        self.zone_combo.currentTextChanged.connect(self._load_selected_zone)
        self.table.selectionModel().selectionChanged.connect(self._update_actions)
        self.refresh_button.clicked.connect(self._emit_refresh)
        self.add_button.clicked.connect(self.add_requested)
        self.remove_button.clicked.connect(self._emit_remove)
        self.set_session(None)

    def set_session(self, view: ServerSessionView | None) -> None:
        previous_zone = self.zone_combo.currentText()
        previous_generation = None if self._session is None else self._session.generation
        same_server = view is not None and view.server_id == self._server_id
        same_session = bool(
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

    def rows(self) -> tuple[RichRuleRow, ...]:
        return self.model.rows()

    def selected_row(self) -> RichRuleRow | None:
        selected = self.table.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        return self.model.row_at(selected[0].row())

    @staticmethod
    def target_for_row(row: RichRuleRow) -> ApplyTarget:
        if not isinstance(row, RichRuleRow):
            raise TypeError("row must be a RichRuleRow")
        if row.runtime and row.permanent:
            return ApplyTarget.BOTH
        if row.runtime:
            return ApplyTarget.RUNTIME
        return ApplyTarget.PERMANENT

    def show_operation_result(self, result: CompositeOperationResult) -> None:
        if not isinstance(result, CompositeOperationResult) or result.operation not in {
            "add_rich_rule",
            "remove_rich_rule",
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
            text = "Rich-rule change completed and verified."
        elif result.is_partial:
            text = "Rich-rule change partially completed. Review both target results."
        elif verification_failed:
            text = "The rich-rule command completed, but verification failed."
        else:
            text = "The rich-rule change did not complete. Firewall state was refreshed."
        self.result_label.setText(text)
        self.result_label.setAccessibleDescription(text)

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
            self.model.set_rows(())
        else:
            self.model.set_rows(merge_rich_rule_rows(view.snapshot, zone))
        self.table.clearSelection()
        self._update_state()

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
        elif not self.zone_combo.count():
            text = "No zones are available in this snapshot"
        elif view.snapshot.stale:
            text = "Stale firewall data"
        elif not self.model.rowCount():
            text = f"No rich rules configured in {self.zone_combo.currentText()}"
        else:
            count = self.model.rowCount()
            text = f"{count} {'rich rule' if count == 1 else 'rich rules'}"
        self.status_label.setText(text)
        self.status_label.setAccessibleDescription(text)
        self._update_actions()

    def _update_actions(self) -> None:
        self.refresh_button.setEnabled(self._can_refresh())
        enabled = self._can_modify()
        self.add_button.setEnabled(enabled)
        row = self.selected_row()
        self.remove_button.setEnabled(
            enabled and row is not None and row.supported
        )

    def _emit_refresh(self) -> None:
        if self._can_refresh():
            self.refresh_requested.emit()

    def _emit_remove(self) -> None:
        row = self.selected_row()
        if self._can_modify() and row is not None and row.supported:
            self.remove_requested.emit(row)


__all__ = ["RichRulesTab"]
