"""Runtime/permanent zone inspection and default-zone intention controls."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from app.controllers.session import ServerSessionView
from app.gui.models.zones_model import ZoneRow, ZonesModel
from app.gui.server_sidebar import status_presentation
from app.gui.widgets.checkbox_delegate import CenteredCheckBoxDelegate
from app.models.command import CompositeOperationResult
from app.models.enums import ConnectionStatus, TargetStatus
from app.models.firewall import FirewallSnapshot


_EMPTY = "—"


class ZonesTab(QWidget):
    """Render one immutable zone inventory view and emit exact user intentions."""

    refresh_requested = Signal()
    set_default_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName("Firewall zones")
        self._session: ServerSessionView | None = None
        self._snapshot: FirewallSnapshot | None = None
        self._unit_actionable = False
        self._server_id: str | None = None

        self.view_combo = QComboBox()
        self.view_combo.setAccessibleName("Zone configuration view")
        self.view_combo.addItems(("Runtime", "Permanent"))
        self.activity_note = QLabel(
            "Active status is runtime-derived; Permanent details remain permanent-only."
        )
        self.activity_note.setWordWrap(True)
        filters = QHBoxLayout()
        filters.addWidget(QLabel("View"))
        filters.addWidget(self.view_combo)
        filters.addWidget(self.activity_note, 1)

        self.model = ZonesModel(self)
        self.table = QTableView()
        self.table.setAccessibleName("Firewall zones table")
        self.table.setModel(self.model)
        self._active_delegate = CenteredCheckBoxDelegate(self.table)
        self.table.setItemDelegateForColumn(1, self._active_delegate)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)

        details_box = QGroupBox("Selected zone details")
        details_box.setAccessibleName("Selected zone details")
        details = QFormLayout(details_box)
        self.active_value = self._detail_value(details, "Runtime active")
        self.interfaces_value = self._detail_value(details, "Interfaces")
        self.sources_value = self._detail_value(details, "Sources")
        self.services_value = self._detail_value(details, "Services")
        self.ports_value = self._detail_value(details, "Ports")
        self.protocols_value = self._detail_value(details, "Protocols")
        self.masquerade_value = self._detail_value(details, "Masquerade")
        self.forwarding_value = self._detail_value(details, "Forwarding")
        self.rich_rules_value = self._detail_value(details, "Rich rules")

        inventory = QGroupBox("Default zone")
        inventory_layout = QHBoxLayout(inventory)
        self.current_default_value = QLabel(_EMPTY)
        self.current_default_value.setAccessibleName("Current default zone")
        self.default_zone_combo = QComboBox()
        self.default_zone_combo.setAccessibleName("New default zone")
        self.set_default_button = QPushButton("Set Default Zone")
        inventory_layout.addWidget(QLabel("Current"))
        inventory_layout.addWidget(self.current_default_value)
        inventory_layout.addWidget(QLabel("New"))
        inventory_layout.addWidget(self.default_zone_combo, 1)
        inventory_layout.addWidget(self.set_default_button)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setAccessibleName("Zones status")
        self.result_label = QLabel()
        self.result_label.setWordWrap(True)
        self.result_label.setAccessibleName("Latest default-zone operation result")
        self.refresh_button = QPushButton("Refresh")
        actions = QHBoxLayout()
        actions.addWidget(self.status_label, 1)
        actions.addWidget(self.refresh_button)

        layout = QVBoxLayout(self)
        layout.addLayout(filters)
        layout.addWidget(self.table, 1)
        layout.addWidget(details_box)
        layout.addWidget(inventory)
        layout.addWidget(self.result_label)
        layout.addLayout(actions)

        self.view_combo.currentTextChanged.connect(self._load_view)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        self.default_zone_combo.currentTextChanged.connect(self._update_actions)
        self.refresh_button.clicked.connect(self._emit_refresh)
        self.set_default_button.clicked.connect(self._emit_set_default)
        self.set_snapshot(None)

    @staticmethod
    def _detail_value(form: QFormLayout, label: str) -> QLabel:
        value = QLabel(_EMPTY)
        value.setTextInteractionFlags(value.textInteractionFlags())
        value.setWordWrap(True)
        value.setAccessibleName(f"Zone {label.lower()}")
        form.addRow(label, value)
        return value

    def set_session(self, view: ServerSessionView | None) -> None:
        previous_generation = (
            None if self._session is None else self._session.generation
        )
        same_session = bool(
            view is not None
            and view.server_id == self._server_id
            and view.generation == previous_generation
        )
        self._session = view
        self._server_id = None if view is None else view.server_id
        self._unit_actionable = False
        if not same_session:
            self.result_label.clear()
        self._set_snapshot(None if view is None else view.snapshot)

    def set_snapshot(self, snapshot: FirewallSnapshot | None) -> None:
        if snapshot is not None and not isinstance(snapshot, FirewallSnapshot):
            raise TypeError("snapshot must be a FirewallSnapshot or None")
        self._session = None
        self._server_id = None
        self._unit_actionable = snapshot is not None
        self.result_label.clear()
        self._set_snapshot(snapshot)

    def _set_snapshot(self, snapshot: FirewallSnapshot | None) -> None:
        previous_choice = self.default_zone_combo.currentText()
        self._snapshot = snapshot
        zones = self.available_zone_names(snapshot)
        self.default_zone_combo.blockSignals(True)
        self.default_zone_combo.clear()
        self.default_zone_combo.addItems(zones)
        preferred = ""
        if previous_choice in zones:
            preferred = previous_choice
        elif snapshot is not None and snapshot.default_zone in zones:
            preferred = snapshot.default_zone
        elif zones:
            preferred = zones[0]
        if preferred:
            self.default_zone_combo.setCurrentText(preferred)
        self.default_zone_combo.blockSignals(False)
        self.current_default_value.setText(
            snapshot.default_zone if snapshot is not None else _EMPTY
        )
        self._load_view()

    @staticmethod
    def available_zone_names(
        snapshot: FirewallSnapshot | None,
    ) -> tuple[str, ...]:
        if snapshot is None:
            return ()
        return tuple(
            dict.fromkeys(
                zone.name
                for zone in snapshot.runtime_zones + snapshot.permanent_zones
            )
        )

    def _load_view(self) -> None:
        snapshot = self._snapshot
        zones = ()
        active_names: tuple[str, ...] = ()
        if snapshot is not None:
            zones = (
                snapshot.permanent_zones
                if self.view_combo.currentText() == "Permanent"
                else snapshot.runtime_zones
            )
            active_names = tuple(
                zone.name
                for zone in snapshot.runtime_zones
                if zone.active
            )
        self.table.clearSelection()
        self.model.set_zones(zones, active_zone_names=active_names)
        self._show_details(None)
        self._update_state()

    def _selection_changed(self) -> None:
        selected = self.table.selectionModel().selectedRows()
        row = self.model.row_at(selected[0].row()) if len(selected) == 1 else None
        self._show_details(row)

    def _show_details(self, row: ZoneRow | None) -> None:
        if row is None:
            values = (_EMPTY,) * 9
        else:
            values = (
                "Yes" if row.active else "No",
                self._list_text(row.interfaces),
                self._list_text(row.sources),
                self._list_text(row.services),
                self._list_text(row.ports),
                self._list_text(row.protocols),
                "Yes" if row.masquerade else "No",
                "Yes" if row.forwarding else "No",
                str(row.rich_rule_count),
            )
        for label, value in zip(
            (
                self.active_value,
                self.interfaces_value,
                self.sources_value,
                self.services_value,
                self.ports_value,
                self.protocols_value,
                self.masquerade_value,
                self.forwarding_value,
                self.rich_rules_value,
            ),
            values,
            strict=True,
        ):
            label.setText(value)

    @staticmethod
    def _list_text(values: tuple[str, ...]) -> str:
        return ", ".join(values) if values else _EMPTY

    def show_operation_result(self, result: CompositeOperationResult) -> None:
        if not isinstance(result, CompositeOperationResult):
            return
        if result.operation != "set_default_zone":
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
            text = "Default-zone change completed and verified."
        elif result.is_partial:
            text = "Default-zone change returned inconsistent target results."
        elif verification_failed:
            text = (
                "The default-zone command completed, but verification did not "
                "confirm the requested firewall state."
            )
        else:
            text = "The default-zone change did not complete. Firewall state was refreshed."
        self.result_label.setText(text)
        self.result_label.setAccessibleDescription(text)

    def _can_refresh(self) -> bool:
        if self._session is None:
            return self._unit_actionable and self._snapshot is not None
        return bool(
            self._session.status is ConnectionStatus.CONNECTED
            and self._session.busy_operation is None
            and self._snapshot is not None
        )

    def _can_modify(self) -> bool:
        return bool(
            self._can_refresh()
            and self._snapshot is not None
            and not self._snapshot.stale
        )

    def _update_state(self) -> None:
        view = self._session
        if view is not None and (
            view.busy_operation or view.status is ConnectionStatus.CONNECTING
        ):
            operation = (
                "Connecting"
                if view.status is ConnectionStatus.CONNECTING
                else (view.busy_operation or "operation").replace("_", " ").title()
            )
            text = f"{operation} in progress"
        elif view is not None and view.status is ConnectionStatus.DISCONNECTED:
            text = "Disconnected"
        elif view is not None and view.status is not ConnectionStatus.CONNECTED:
            text = status_presentation(view.status)[0]
        elif self._snapshot is None:
            text = "No firewall data is available"
        elif self._snapshot.stale:
            text = "Stale firewall data"
        elif self.model.rowCount() == 0:
            text = f"No {self.view_combo.currentText().lower()} zones are available"
        else:
            count = self.model.rowCount()
            text = f"{count} {'zone' if count == 1 else 'zones'}"
        self.status_label.setText(text)
        self.status_label.setAccessibleDescription(text)
        self._update_actions()

    def _update_actions(self) -> None:
        self.refresh_button.setEnabled(self._can_refresh())
        snapshot = self._snapshot
        choice = self.default_zone_combo.currentText()
        self.default_zone_combo.setEnabled(self._can_modify())
        self.set_default_button.setEnabled(
            bool(
                self._can_modify()
                and snapshot is not None
                and choice
                and choice != snapshot.default_zone
            )
        )

    def _emit_refresh(self) -> None:
        if self._can_refresh():
            self.refresh_requested.emit()

    def _emit_set_default(self) -> None:
        if self.set_default_button.isEnabled():
            self.set_default_requested.emit(self.default_zone_combo.currentText())


__all__ = ["ZonesTab"]
