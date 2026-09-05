"""Main desktop shell and selected-server routing."""

from __future__ import annotations

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QSplitter,
    QStyle,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.controllers.server_controller import (
    ControllerOperationError,
    ServerController,
    SudoPasswordRequest,
)
from app.controllers.firewall_controller import FirewallController
from app.controllers.session import ServerSessionView
from app.firewalld.lockout import LockoutRisk, RiskLevel
from app.firewalld.service import ConnectionTestResult
from app.gui.dialogs import (
    AddPortDialog,
    ConfirmationDialog,
    ErrorDialog,
    HostKeyDialog,
    SudoPasswordDialog,
)
from app.gui.overview_tab import OverviewTab
from app.gui.ports_tab import PortsTab
from app.gui.server_sidebar import ServerSidebar, status_presentation
from app.gui.widgets.state_panel import StatePanel
from app.gui.zones_tab import ZonesTab
from app.models.change import ChangePreview
from app.models.enums import ApplyTarget, ConnectionStatus
from app.models.command import CompositeOperationResult
from app.models.firewall import FirewallSnapshot
from app.models.port import PortRow


_TAB_NAMES = (
    "Overview",
    "Ports",
    "Services",
    "Zones",
    "Interfaces",
    "Rich Rules",
    "Logs",
)

_RECONNECTABLE_STATUSES = frozenset(
    {
        ConnectionStatus.AUTHENTICATION_FAILED,
        ConnectionStatus.CONNECTION_ERROR,
        ConnectionStatus.HOST_KEY_ERROR,
        ConnectionStatus.PERMISSION_ERROR,
        ConnectionStatus.FIREWALLD_NOT_INSTALLED,
        ConnectionStatus.FIREWALLD_NOT_RUNNING,
    }
)


class MainWindow(QMainWindow):
    """Render controller snapshots and forward user intentions by server ID."""

    def __init__(
        self,
        controller: ServerController,
        firewall_controller: FirewallController | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._controller = controller
        self._firewall_controller = firewall_controller or FirewallController(
            controller
        )
        self._shutdown_complete = False
        self._shutdown_result = True
        self.current_server_id: str | None = controller.selected_server_id
        self.setWindowTitle("Remote firewalld Manager")
        self.resize(1100, 720)

        self.server_sidebar = ServerSidebar()
        self.header_icon = QLabel()
        self.header_icon.setAccessibleName("Selected server status icon")
        self.header_title = QLabel()
        self.header_title.setAccessibleName("Selected server name")
        self.header_status = QLabel()
        self.header_status.setAccessibleName("Selected server connection status")
        self.tabs = QTabWidget()
        self.tabs.setAccessibleName("Firewall management sections")
        self.overview_tab = OverviewTab()
        self.ports_tab = PortsTab()
        self.zones_tab = ZonesTab()
        self.state_panels: list[StatePanel] = []

        header = QHBoxLayout()
        header.addWidget(self.header_icon)
        header.addWidget(self.header_title)
        header.addStretch(1)
        header.addWidget(self.header_status)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.addLayout(header)
        content_layout.addWidget(self.tabs, 1)
        self.tabs.addTab(self.overview_tab, _TAB_NAMES[0])
        self.tabs.addTab(self.ports_tab, _TAB_NAMES[1])
        for tab_name in _TAB_NAMES[2:]:
            if tab_name == "Zones":
                self.tabs.addTab(self.zones_tab, tab_name)
            else:
                panel = StatePanel(tab_name)
                self.state_panels.append(panel)
                self.tabs.addTab(panel, tab_name)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setObjectName("mainSplitter")
        splitter.addWidget(self.server_sidebar)
        splitter.addWidget(content)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([260, 840])
        self.setCentralWidget(splitter)

        server_menu = self.menuBar().addMenu("Server")
        self.refresh_action = QAction("Refresh Selected Server", self)
        self.refresh_action.setObjectName("refreshSelectedServerAction")
        self.reload_configuration_action = QAction("Reload Configuration", self)
        self.reload_configuration_action.setObjectName("reloadConfigurationAction")
        server_menu.addAction(self.refresh_action)
        server_menu.addAction(self.reload_configuration_action)

        self.server_sidebar.server_selected.connect(self._controller.select)
        self.server_sidebar.connect_requested.connect(self._connect_server)
        self.server_sidebar.disconnect_requested.connect(self._controller.disconnect)
        self.server_sidebar.reload_requested.connect(
            self._controller.reload_configuration
        )
        self.overview_tab.connect_requested.connect(self._connect_selected)
        self.overview_tab.disconnect_requested.connect(self._disconnect_selected)
        self.overview_tab.reconnect_requested.connect(self._reconnect_selected)
        self.overview_tab.refresh_requested.connect(self._refresh_selected)
        self.overview_tab.reload_firewalld_requested.connect(
            self._reload_firewalld_selected
        )
        self.overview_tab.test_connection_requested.connect(
            self._test_connection_selected
        )
        self.ports_tab.refresh_requested.connect(self._ports_refresh_requested)
        self.ports_tab.add_requested.connect(self._add_port_selected)
        self.ports_tab.remove_requested.connect(self._remove_port_selected)
        self.zones_tab.refresh_requested.connect(self._refresh_selected)
        self.zones_tab.set_default_requested.connect(
            self._set_default_zone_selected
        )
        self.refresh_action.triggered.connect(self._refresh_selected)
        self.reload_configuration_action.triggered.connect(
            self._controller.reload_configuration
        )
        self._controller.sessions_changed.connect(self._sessions_changed)
        self._controller.selection_changed.connect(self._selection_changed)
        self._controller.session_changed.connect(self._session_changed)
        self._controller.host_key_required.connect(self._host_key_required)
        self._controller.sudo_password_required.connect(
            self._sudo_password_required
        )
        self._controller.error_raised.connect(self._error_raised)
        self._firewall_controller.snapshot_changed.connect(
            self._firewall_snapshot_changed
        )
        self._firewall_controller.operation_result.connect(
            self._firewall_operation_result
        )

        self._sessions_changed()

    @Slot()
    def _sessions_changed(self) -> None:
        sessions = self._controller.sessions()
        selected = self._controller.selected_server_id
        self.server_sidebar.set_sessions(sessions, selected)
        self.current_server_id = selected if any(
            view.server_id == selected for view in sessions
        ) else None
        self._render_selected()

    @Slot(str)
    def _selection_changed(self, server_id: str) -> None:
        self.current_server_id = server_id or None
        self.server_sidebar.set_sessions(
            self._controller.sessions(), self.current_server_id
        )
        self._render_selected()

    @Slot(str)
    def _session_changed(self, server_id: str) -> None:
        self.server_sidebar.set_sessions(
            self._controller.sessions(), self.current_server_id
        )
        if server_id == self.current_server_id:
            self._render_selected()

    @Slot()
    def _refresh_selected(self) -> None:
        if self.current_server_id is not None:
            self._controller.refresh(self.current_server_id)

    @Slot()
    def _connect_selected(self) -> None:
        if self.current_server_id is not None:
            self._controller.connect(self.current_server_id)

    @Slot(str)
    def _connect_server(self, server_id: str) -> None:
        try:
            view = self._controller.session_view(server_id)
        except KeyError:
            return
        if view.busy_operation is not None:
            return
        if view.status is ConnectionStatus.DISCONNECTED:
            self._controller.connect(server_id)
        elif view.status in _RECONNECTABLE_STATUSES:
            self._controller.reconnect(server_id)

    @Slot()
    def _disconnect_selected(self) -> None:
        if self.current_server_id is not None:
            self._controller.disconnect(self.current_server_id)

    @Slot()
    def _reconnect_selected(self) -> None:
        if self.current_server_id is not None:
            self._controller.reconnect(self.current_server_id)

    @Slot()
    def _test_connection_selected(self) -> None:
        view = self._selected_view()
        if view is None:
            return
        handle = self._controller.test_connection(view.server_id)
        handle.succeeded.connect(self._connection_test_succeeded)

    @Slot(str, int, str, object)
    def _connection_test_succeeded(
        self,
        server_id: str,
        generation: int,
        operation: str,
        result: object,
    ) -> None:
        if operation != "test_connection" or not isinstance(
            result, ConnectionTestResult
        ):
            return
        view = self._selected_view()
        if (
            view is None
            or server_id != self.current_server_id
            or view.server_id != server_id
            or view.generation != generation
        ):
            return
        self.overview_tab.show_connection_test(result)

    @Slot()
    def _reload_firewalld_selected(self) -> None:
        view = self._selected_view()
        if (
            view is None
            or view.status is not ConnectionStatus.CONNECTED
            or view.busy_operation is not None
        ):
            return
        preview = ChangePreview(
            server_name=view.name,
            host=view.host,
            operation="Reload firewalld",
            zone="Global",
            resource="firewalld daemon",
            target=ApplyTarget.BOTH,
            risk=LockoutRisk(
                RiskLevel.NONE,
                (
                    "Reloading firewalld loads the permanent configuration into "
                    "runtime and may discard runtime-only changes.",
                ),
            ),
        )
        server_id = view.server_id
        generation = view.generation
        dialog = ConfirmationDialog(preview, self)
        dialog.exec()
        if not dialog.confirmed():
            return
        current = self._selected_view()
        if (
            current is None
            or current.server_id != server_id
            or current.generation != generation
            or current.status is not ConnectionStatus.CONNECTED
            or current.busy_operation is not None
        ):
            return
        self._controller.reload_firewalld(server_id)

    @Slot(str)
    def _ports_refresh_requested(self, zone: str) -> None:
        del zone
        self._refresh_selected()

    @Slot()
    def _add_port_selected(self) -> None:
        view = self._selected_view()
        if not self._port_view_is_actionable(view):
            return
        assert view is not None and view.snapshot is not None
        dialog = AddPortDialog(
            self.ports_tab.available_zones(),
            self.ports_tab.zone_combo.currentText(),
            self,
        )
        dialog.exec()
        request = dialog.request()
        if request is None:
            return
        try:
            preview = self._firewall_controller.preview_add_port(
                view.server_id, request
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            self._show_port_intent_error(view.server_id, "add_port")
            return
        confirmation = ConfirmationDialog(preview, self)
        confirmation.exec()
        if not confirmation.confirmed():
            return
        try:
            self._firewall_controller.apply_add_port(
                view.server_id, preview, request
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            return

    @Slot(object)
    def _remove_port_selected(self, row: object) -> None:
        view = self._selected_view()
        if not self._port_view_is_actionable(view) or not isinstance(row, PortRow):
            return
        target = self.ports_tab.target_for_row(row)
        try:
            preview = self._firewall_controller.preview_remove_port(
                view.server_id, row, target
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            self._show_port_intent_error(view.server_id, "remove_port")
            return
        confirmation = ConfirmationDialog(preview, self)
        confirmation.exec()
        if not confirmation.confirmed():
            return
        try:
            self._firewall_controller.apply_remove_port(
                view.server_id, preview, row, target
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            return

    @Slot(str)
    def _set_default_zone_selected(self, new_zone: str) -> None:
        view = self._selected_view()
        if not self._port_view_is_actionable(view):
            return
        assert view is not None
        try:
            preview = self._firewall_controller.preview_set_default_zone(
                view.server_id, new_zone
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            self._show_firewall_intent_error(
                view.server_id,
                "set_default_zone",
                "The selected default zone is no longer available.",
            )
            return
        confirmation = ConfirmationDialog(preview, self)
        confirmation.exec()
        if not confirmation.confirmed():
            return
        try:
            self._firewall_controller.apply_set_default_zone(
                view.server_id,
                preview,
                new_zone,
                ApplyTarget.BOTH,
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            return

    @Slot(str, object)
    def _firewall_snapshot_changed(
        self, server_id: str, snapshot: object
    ) -> None:
        if not isinstance(snapshot, FirewallSnapshot):
            return
        if server_id == self.current_server_id:
            self._render_selected()

    @Slot(str, object)
    def _firewall_operation_result(self, server_id: str, result: object) -> None:
        if (
            server_id == self.current_server_id
            and isinstance(result, CompositeOperationResult)
        ):
            self.ports_tab.show_operation_result(result)
            self.zones_tab.show_operation_result(result)

    @staticmethod
    def _port_view_is_actionable(view: ServerSessionView | None) -> bool:
        return bool(
            view is not None
            and view.status is ConnectionStatus.CONNECTED
            and view.busy_operation is None
            and view.snapshot is not None
            and not view.snapshot.stale
        )

    def _show_port_intent_error(self, server_id: str, operation: str) -> None:
        self._show_firewall_intent_error(
            server_id,
            operation,
            "The confirmed firewall state changed before submission.",
        )

    def _show_firewall_intent_error(
        self, server_id: str, operation: str, message: str
    ) -> None:
        ErrorDialog.from_domain_error(
            ControllerOperationError(
                server_id,
                operation,
                "operation",
                message,
            ),
            self,
        ).exec()

    @Slot(str, object)
    def _host_key_required(self, server_id: str, challenge: object) -> None:
        try:
            generation = self._controller.session_view(server_id).generation
        except KeyError:
            return
        dialog = HostKeyDialog(challenge, self)
        dialog.exec()
        self._controller.resolve_host_key(
            server_id,
            generation,
            challenge,
            dialog.confirmed(),
        )

    @Slot(str, object)
    def _sudo_password_required(self, server_id: str, request: object) -> None:
        if not isinstance(request, SudoPasswordRequest):
            return
        try:
            view = self._controller.session_view(server_id)
        except KeyError:
            return
        if request.server_id != server_id or request.generation != view.generation:
            self._controller.resolve_sudo_password(request, None)
            return
        dialog = SudoPasswordDialog(view.name, self)
        dialog.exec()
        password = dialog.take_password() if dialog.confirmed() else None
        self._controller.resolve_sudo_password(request, password)
        password = None

    @Slot(str, object)
    def _error_raised(self, server_id: str, error: object) -> None:
        del server_id
        if isinstance(error, ControllerOperationError) and error.category in {
            "host_key_required",
            "sudo_required",
        }:
            return
        ErrorDialog.from_domain_error(error, self).exec()

    def _render_selected(self) -> None:
        view = self._selected_view()
        self.overview_tab.set_session(view)
        self.ports_tab.set_session(view)
        self.zones_tab.set_session(view)
        for panel in self.state_panels:
            panel.set_session(view)
        if view is None:
            self.header_title.setText("No server selected")
            self.header_status.setText("No selection")
            self.header_icon.setPixmap(
                self.style()
                .standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation)
                .pixmap(24, 24)
            )
            self.statusBar().showMessage("Ready")
            self.refresh_action.setEnabled(False)
            return

        status_text, standard_icon = status_presentation(view.status)
        self.header_title.setText(view.name)
        self.header_status.setText(status_text)
        self.header_icon.setPixmap(
            self.style().standardIcon(standard_icon).pixmap(24, 24)
        )
        self.refresh_action.setEnabled(
            view.status.value == "connected" and not view.busy_operation
        )
        if view.busy_operation:
            operation = view.busy_operation.replace("_", " ").title()
            self.statusBar().showMessage(f"{operation} in progress")
        else:
            self.statusBar().showMessage("Ready")

    def _selected_view(self) -> ServerSessionView | None:
        if self.current_server_id is None:
            return None
        try:
            return self._controller.session_view(self.current_server_id)
        except KeyError:
            return None

    def shutdown_once(self) -> bool:
        if not self._shutdown_complete:
            self._shutdown_result = self._controller.shutdown(timeout_ms=5000)
            self._shutdown_complete = True
        return self._shutdown_result

    def closeEvent(self, event: QCloseEvent) -> None:
        self.shutdown_once()
        event.accept()
