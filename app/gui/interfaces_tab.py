"""Snapshot-only Interfaces presentation and exact row intentions."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from app.controllers.session import ServerSessionView
from app.gui.models.interfaces_model import InterfacesTableModel, interface_rows
from app.gui.server_sidebar import status_presentation
from app.models.command import CompositeOperationResult
from app.models.enums import ConnectionStatus, TargetStatus
from app.models.interface import InterfaceRow


class InterfacesTab(QWidget):
    """Render immutable assignments and emit only the selected immutable row."""

    refresh_requested = Signal()
    change_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName("Firewall interfaces")
        self._session: ServerSessionView | None = None
        self._server_id: str | None = None

        self.model = InterfacesTableModel(parent=self)
        self.table = QTableView()
        self.table.setAccessibleName("Firewall interfaces table")
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.sortByColumn(0, self.table.horizontalHeader().sortIndicatorOrder())

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setAccessibleName("Interfaces status")
        self.result_label = QLabel()
        self.result_label.setWordWrap(True)
        self.result_label.setAccessibleName("Latest interface operation result")
        self.refresh_button = QPushButton("Refresh")
        self.change_button = QPushButton("Change Zone")

        actions = QHBoxLayout()
        actions.addWidget(self.status_label, 1)
        actions.addWidget(self.refresh_button)
        actions.addWidget(self.change_button)
        layout = QVBoxLayout(self)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.result_label)
        layout.addLayout(actions)

        self.table.selectionModel().selectionChanged.connect(self._update_actions)
        self.refresh_button.clicked.connect(self._emit_refresh)
        self.change_button.clicked.connect(self._emit_change)
        self.set_session(None)

    def set_session(self, view: ServerSessionView | None) -> None:
        previous_generation = None if self._session is None else self._session.generation
        same_session = bool(
            view is not None
            and view.server_id == self._server_id
            and view.generation == previous_generation
        )
        self._session = view
        self._server_id = None if view is None else view.server_id
        if not same_session:
            self.result_label.clear()
        snapshot = None if view is None else view.snapshot
        self.model.set_rows(() if snapshot is None else interface_rows(snapshot))
        self.table.clearSelection()
        self._update_state()

    def rows(self) -> tuple[InterfaceRow, ...]:
        return self.model.rows()

    def selected_row(self) -> InterfaceRow | None:
        selected = self.table.selectionModel().selectedRows()
        if len(selected) != 1:
            return None
        return self.model.row_at(selected[0].row())

    def show_operation_result(self, result: CompositeOperationResult) -> None:
        if (
            not isinstance(result, CompositeOperationResult)
            or result.operation != "change_interface_zone"
        ):
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
            text = "Interface-zone change completed and verified."
        elif result.is_partial:
            text = (
                "Interface-zone change partially completed. Review the Runtime and "
                "Permanent results before another change."
            )
        elif verification_failed:
            text = (
                "The interface command completed, but verification did not confirm "
                "the requested firewall state."
            )
        else:
            text = "The interface-zone change did not complete. Firewall state was refreshed."
        self.result_label.setText(text)
        self.result_label.setAccessibleDescription(text)

    def _can_refresh(self) -> bool:
        view = self._session
        return bool(
            view is not None
            and view.status is ConnectionStatus.CONNECTED
            and view.busy_operation is None
            and view.snapshot is not None
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
        elif view.snapshot.stale:
            text = "Stale firewall data"
        elif not self.model.rowCount():
            text = "No interfaces are assigned in this snapshot"
        else:
            count = self.model.rowCount()
            text = f"{count} {'interface' if count == 1 else 'interfaces'}"
        self.status_label.setText(text)
        self.status_label.setAccessibleDescription(text)
        self._update_actions()

    def _update_actions(self) -> None:
        self.refresh_button.setEnabled(self._can_refresh())
        self.change_button.setEnabled(
            self._can_modify() and self.selected_row() is not None
        )

    def _emit_refresh(self) -> None:
        if self._can_refresh():
            self.refresh_requested.emit()

    def _emit_change(self) -> None:
        row = self.selected_row()
        if self._can_modify() and row is not None:
            self.change_requested.emit(row)


__all__ = ["InterfacesTab"]
