"""Credential-free presentation of one remote server overview."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.controllers.session import ServerSessionView
from app.gui.server_sidebar import status_presentation
from app.models.command import CompositeOperationResult, classify_composite_outcome
from app.models.enums import ConnectionStatus

if TYPE_CHECKING:
    from app.firewalld.service import ConnectionTestResult, FirewalldInfo


_NOT_AVAILABLE = "Not available"
_UNKNOWN = "Unknown"


class OverviewTab(QWidget):
    """Render immutable session data and emit only user intentions."""

    connect_requested = Signal()
    disconnect_requested = Signal()
    reconnect_requested = Signal()
    refresh_requested = Signal()
    reload_firewalld_requested = Signal()
    test_connection_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName("Server overview")
        self._identity: tuple[str, int] | None = None
        self._reload_busy = False

        summary = QGroupBox("Server summary")
        summary_form = QFormLayout(summary)
        self.server_value = self._add_value(summary_form, "Server")
        self.host_value = self._add_value(summary_form, "Host")
        self.port_value = self._add_value(summary_form, "SSH port")
        self.user_value = self._add_value(summary_form, "User")
        self.connection_value = self._add_value(summary_form, "Connection")
        self.hostname_value = self._add_value(summary_form, "Remote hostname")
        self.distribution_value = self._add_value(summary_form, "Distribution")
        self.firewalld_value = self._add_value(summary_form, "Firewalld")
        self.firewalld_version_value = self._add_value(
            summary_form, "Firewalld version"
        )
        self.default_zone_value = self._add_value(summary_form, "Default zone")
        self.active_zones_value = self._add_value(
            summary_form, "Active runtime zones"
        )
        self.interfaces_value = self._add_value(
            summary_form, "Assigned interfaces"
        )

        self.snapshot_status_icon = QLabel()
        self.snapshot_status_icon.setAccessibleName("Firewall data status icon")
        self.snapshot_status_label = QLabel()
        snapshot_status = QHBoxLayout()
        snapshot_status.addWidget(self.snapshot_status_icon)
        snapshot_status.addWidget(self.snapshot_status_label)
        snapshot_status.addStretch(1)

        self.reload_result_label = QLabel()
        self.reload_result_label.setWordWrap(True)
        self.reload_result_label.setAccessibleName("Latest firewalld reload result")

        self.connect_button = QPushButton("Connect")
        self.disconnect_button = QPushButton("Disconnect")
        self.reconnect_button = QPushButton("Reconnect")
        self.refresh_button = QPushButton("Refresh")
        self.reload_button = QPushButton("Reload firewalld")
        self.test_connection_button = QPushButton("Test connection")
        self.connect_button.clicked.connect(self.connect_requested)
        self.disconnect_button.clicked.connect(self.disconnect_requested)
        self.reconnect_button.clicked.connect(self.reconnect_requested)
        self.refresh_button.clicked.connect(self.refresh_requested)
        self.reload_button.clicked.connect(self.reload_firewalld_requested)
        self.test_connection_button.clicked.connect(self.test_connection_requested)
        actions = QHBoxLayout()
        for button in (
            self.connect_button,
            self.disconnect_button,
            self.reconnect_button,
            self.refresh_button,
            self.reload_button,
            self.test_connection_button,
        ):
            actions.addWidget(button)
        actions.addStretch(1)

        tests = QGroupBox("Connection test")
        tests_layout = QVBoxLayout(tests)
        self.test_summary_label = QLabel("No connection test has been run.")
        self.test_summary_label.setWordWrap(True)
        self.test_results = QTableWidget(0, 3)
        self.test_results.setHorizontalHeaderLabels(("Result", "Check", "Message"))
        self.test_results.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.test_results.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.test_results.setAccessibleName("Connection test checks")
        self.test_results.horizontalHeader().setStretchLastSection(True)
        tests_layout.addWidget(self.test_summary_label)
        tests_layout.addWidget(self.test_results)

        layout = QVBoxLayout(self)
        layout.addWidget(summary)
        layout.addLayout(snapshot_status)
        layout.addWidget(self.reload_result_label)
        layout.addLayout(actions)
        layout.addWidget(tests, 1)
        self.set_session(None)

    @staticmethod
    def _add_value(form: QFormLayout, label: str) -> QLabel:
        value = QLabel(_NOT_AVAILABLE)
        value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        value.setWordWrap(True)
        value.setAccessibleName(label)
        form.addRow(label, value)
        return value

    def set_session(self, view: ServerSessionView | None) -> None:
        identity = None if view is None else (view.server_id, view.generation)
        if identity != self._identity:
            self._clear_connection_test()
            self.reload_result_label.clear()
        reload_busy = bool(
            view is not None and view.busy_operation == "reload_firewalld"
        )
        if reload_busy and not self._reload_busy:
            self.reload_result_label.clear()
        self._reload_busy = reload_busy
        self._identity = identity

        if view is None:
            self._render_no_selection()
            self._set_actions(None)
            return

        connection_text, _ = status_presentation(view.status)
        self.server_value.setText(view.name)
        self.host_value.setText(view.host)
        self.port_value.setText(str(view.port))
        self.user_value.setText(view.username)
        self.connection_value.setText(connection_text)
        snapshot = view.snapshot
        self.hostname_value.setText(
            snapshot.hostname if snapshot is not None else _NOT_AVAILABLE
        )
        self.distribution_value.setText(
            snapshot.distribution if snapshot is not None else _NOT_AVAILABLE
        )
        self.firewalld_value.setText(self._firewalld_state(view))
        self.firewalld_version_value.setText(
            snapshot.firewalld_version
            if snapshot is not None and snapshot.firewalld_version
            else _UNKNOWN
        )
        self.default_zone_value.setText(
            snapshot.default_zone if snapshot is not None else _UNKNOWN
        )
        if snapshot is None:
            self.active_zones_value.setText(_UNKNOWN)
            self.interfaces_value.setText(_NOT_AVAILABLE)
            self._set_snapshot_status(
                "Firewall data is not available",
                QStyle.StandardPixmap.SP_MessageBoxInformation,
                "Firewall data unavailable",
            )
        else:
            active = tuple(
                zone.name
                for zone in snapshot.runtime_zones
                if zone.interfaces or zone.sources
            )
            interfaces = tuple(
                f"{interface} ({zone.name})"
                for zone in snapshot.runtime_zones
                for interface in zone.interfaces
            )
            self.active_zones_value.setText(", ".join(active) or "None reported")
            self.interfaces_value.setText(", ".join(interfaces) or "None reported")
            if snapshot.stale:
                self._set_snapshot_status(
                    "Stale firewall data",
                    QStyle.StandardPixmap.SP_MessageBoxWarning,
                    "Stale firewall data warning",
                )
            else:
                self._set_snapshot_status(
                    "Current firewall data",
                    QStyle.StandardPixmap.SP_DialogApplyButton,
                    "Current firewall data",
                )
        self._set_actions(view)

    def show_connection_test(self, result: ConnectionTestResult) -> None:
        state, version = self._test_firewalld_state(result.firewalld)
        self.test_summary_label.setText(
            f"Firewalld state: {state}; version: {version}"
        )
        self.test_results.setRowCount(len(result.checks))
        for row, check in enumerate(result.checks):
            result_text = "PASS" if check.passed else "FAIL"
            icon_type = (
                QStyle.StandardPixmap.SP_DialogApplyButton
                if check.passed
                else QStyle.StandardPixmap.SP_MessageBoxCritical
            )
            result_item = QTableWidgetItem(
                self.style().standardIcon(icon_type), result_text
            )
            result_item.setData(
                Qt.ItemDataRole.AccessibleTextRole,
                f"{result_text}: {check.name}",
            )
            self.test_results.setItem(row, 0, result_item)
            self.test_results.setItem(row, 1, QTableWidgetItem(check.name))
            self.test_results.setItem(row, 2, QTableWidgetItem(check.message))

    def show_reload_result(self, result: CompositeOperationResult) -> None:
        """Render only fixed text derived from sanitized reload phase states."""
        if (
            not isinstance(result, CompositeOperationResult)
            or result.operation != "reload_firewalld"
        ):
            return
        outcome = classify_composite_outcome(result)
        if outcome == "succeeded":
            text = "Firewalld reload completed and verified."
        elif outcome == "partial":
            text = (
                "Firewalld reload partially completed. Review the Runtime and "
                "Permanent results before another change."
            )
        elif outcome == "verification_failed":
            text = (
                "Firewalld reloaded, but verification did not confirm the "
                "requested firewall state."
            )
        elif outcome == "failed":
            text = (
                "Firewalld reload did not complete. Review the firewall data "
                "before retrying."
            )
        else:
            text = (
                "Firewalld returned an inconsistent reload result. Refresh "
                "firewall data before retrying."
            )
        self.reload_result_label.setText(text)
        self.reload_result_label.setAccessibleDescription(text)

    def _render_no_selection(self) -> None:
        for label in (
            self.server_value,
            self.host_value,
            self.port_value,
            self.user_value,
            self.hostname_value,
            self.distribution_value,
            self.firewalld_version_value,
            self.interfaces_value,
        ):
            label.setText(_NOT_AVAILABLE)
        self.connection_value.setText("No selection")
        self.firewalld_value.setText(_UNKNOWN)
        self.default_zone_value.setText(_UNKNOWN)
        self.active_zones_value.setText(_UNKNOWN)
        self._set_snapshot_status(
            "No server selected",
            QStyle.StandardPixmap.SP_MessageBoxInformation,
            "No server selected",
        )

    def _set_actions(self, view: ServerSessionView | None) -> None:
        enabled = [False] * 6
        if view is not None:
            disconnected = view.status is ConnectionStatus.DISCONNECTED
            disconnectable = not disconnected
            busy = bool(view.busy_operation) or view.status is ConnectionStatus.CONNECTING
            enabled[1] = disconnectable
            if not busy:
                if disconnected:
                    enabled[0] = True
                elif view.status is ConnectionStatus.CONNECTED:
                    enabled[2:] = [True, True, True, True]
                else:
                    enabled[2] = True
        for button, is_enabled in zip(
            (
                self.connect_button,
                self.disconnect_button,
                self.reconnect_button,
                self.refresh_button,
                self.reload_button,
                self.test_connection_button,
            ),
            enabled,
            strict=True,
        ):
            button.setEnabled(is_enabled)

    def _set_snapshot_status(
        self,
        text: str,
        icon_type: QStyle.StandardPixmap,
        accessible_name: str,
    ) -> None:
        self.snapshot_status_label.setText(text)
        self.snapshot_status_label.setAccessibleName(accessible_name)
        self.snapshot_status_icon.setPixmap(
            self.style().standardIcon(icon_type).pixmap(20, 20)
        )

    def _clear_connection_test(self) -> None:
        self.test_results.setRowCount(0)
        self.test_summary_label.setText("No connection test has been run.")

    @staticmethod
    def _firewalld_state(view: ServerSessionView) -> str:
        if view.status is ConnectionStatus.FIREWALLD_NOT_INSTALLED:
            return "Not installed"
        if view.status is ConnectionStatus.FIREWALLD_NOT_RUNNING:
            return "Stopped"
        if view.snapshot is None:
            return _UNKNOWN
        return "Running" if view.snapshot.firewalld_running else "Stopped"

    @staticmethod
    def _test_firewalld_state(
        info: FirewalldInfo | None,
    ) -> tuple[str, str]:
        if info is None:
            return _UNKNOWN, _UNKNOWN
        if not info.installed:
            state = "Not installed"
        elif not info.running:
            state = "Stopped"
        else:
            state = "Running"
        return state, info.version or _UNKNOWN


__all__ = ["OverviewTab"]
