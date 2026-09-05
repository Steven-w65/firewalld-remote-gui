"""Main desktop shell and selected-server routing."""

from __future__ import annotations

from functools import partial

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
from app.controllers.firewall_controller import (
    FirewallController,
    FirewallJobHandle,
)
from app.controllers.session import ServerSessionView
from app.firewalld.service import ConnectionTestResult
from app.gui.dialogs import (
    AddPortDialog,
    AddServiceDialog,
    ChangeInterfaceDialog,
    ConfirmationDialog,
    ErrorDialog,
    HostKeyDialog,
    RichRuleDialog,
    SudoPasswordDialog,
)
from app.gui.overview_tab import OverviewTab
from app.gui.logs_tab import LogsTab
from app.gui.ports_tab import PortsTab
from app.gui.services_tab import ServicesTab
from app.gui.interfaces_tab import InterfacesTab
from app.gui.rich_rules_tab import RichRulesTab
from app.gui.server_sidebar import ServerSidebar, status_presentation
from app.gui.widgets.state_panel import StatePanel
from app.gui.zones_tab import ZonesTab
from app.models.enums import ApplyTarget, ConnectionStatus
from app.models.command import CompositeOperationResult
from app.models.firewall import FirewallSnapshot
from app.models.port import PortRow
from app.models.service import ServiceRow
from app.models.interface import InterfaceRow
from app.models.rich_rule import RichRuleRow


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
        self._reload_facades: dict[tuple[str, int, str], FirewallJobHandle] = {}
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
        self.services_tab = ServicesTab()
        self.zones_tab = ZonesTab()
        self.interfaces_tab = InterfacesTab()
        self.rich_rules_tab = RichRulesTab()
        self.logs_tab = LogsTab()
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
            if tab_name == "Services":
                self.tabs.addTab(self.services_tab, tab_name)
            elif tab_name == "Zones":
                self.tabs.addTab(self.zones_tab, tab_name)
            elif tab_name == "Interfaces":
                self.tabs.addTab(self.interfaces_tab, tab_name)
            elif tab_name == "Rich Rules":
                self.tabs.addTab(self.rich_rules_tab, tab_name)
            elif tab_name == "Logs":
                self.tabs.addTab(self.logs_tab, tab_name)
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
        self.services_tab.refresh_requested.connect(
            self._services_refresh_requested
        )
        self.services_tab.add_requested.connect(self._add_service_selected)
        self.services_tab.remove_requested.connect(self._remove_service_selected)
        self.zones_tab.refresh_requested.connect(self._refresh_selected)
        self.zones_tab.set_default_requested.connect(
            self._set_default_zone_selected
        )
        self.interfaces_tab.refresh_requested.connect(self._refresh_selected)
        self.interfaces_tab.change_requested.connect(
            self._change_interface_zone_selected
        )
        self.rich_rules_tab.refresh_requested.connect(self._refresh_selected)
        self.rich_rules_tab.add_requested.connect(self._add_rich_rule_selected)
        self.rich_rules_tab.remove_requested.connect(
            self._remove_rich_rule_selected
        )
        self.logs_tab.clear_requested.connect(self._clear_logs_view)
        self.logs_tab.refresh_requested.connect(self._refresh_logs_view)
        self.logs_tab.copy_requested.connect(self._copy_logs_view)
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
        self._controller.log_entries_changed.connect(self._log_entries_changed)
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
        try:
            preview = self._firewall_controller.preview_reload(view.server_id)
        except (KeyError, TypeError, RuntimeError, ValueError):
            return
        server_id = view.server_id
        dialog = ConfirmationDialog(preview, self)
        dialog.exec()
        if not dialog.confirmed():
            return
        try:
            handle = self._firewall_controller.apply_reload(server_id, preview)
        except (KeyError, TypeError, RuntimeError, ValueError):
            return
        key = (handle.server_id, handle.generation, handle.operation)
        self._reload_facades[key] = handle
        handle.succeeded.connect(partial(self._reload_operation_result, handle))
        handle.finished.connect(partial(self._reload_operation_finished, handle))

    def _reload_operation_result(
        self,
        handle: FirewallJobHandle,
        server_id: str,
        generation: int,
        operation: str,
        result: object,
    ) -> None:
        key = (server_id, generation, operation)
        view = self._selected_view()
        if (
            self._reload_facades.get(key) is not handle
            or (handle.server_id, handle.generation, handle.operation) != key
            or view is None
            or server_id != self.current_server_id
            or view.server_id != server_id
            or view.generation != generation
            or view.busy_operation != operation
            or operation != "reload_firewalld"
            or not isinstance(result, CompositeOperationResult)
            or result.operation != operation
        ):
            return
        self.overview_tab.show_reload_result(result)

    def _reload_operation_finished(
        self,
        handle: FirewallJobHandle,
        server_id: str,
        generation: int,
        operation: str,
    ) -> None:
        key = (server_id, generation, operation)
        if (
            self._reload_facades.get(key) is handle
            and (handle.server_id, handle.generation, handle.operation) == key
        ):
            self._reload_facades.pop(key, None)

    @Slot(str)
    def _clear_logs_view(self, server_id: str) -> None:
        if server_id != self.current_server_id:
            return
        if self.logs_tab.server_id != server_id:
            return

    @Slot(str)
    def _refresh_logs_view(self, server_id: str) -> None:
        if server_id != self.current_server_id:
            return
        if self.logs_tab.server_id != server_id:
            return
        try:
            entries = self._controller.log_entries(server_id)
        except KeyError:
            return
        self.logs_tab.set_entries(entries)

    @Slot(str)
    def _copy_logs_view(self, server_id: str) -> None:
        if server_id != self.current_server_id:
            return
        if self.logs_tab.server_id != server_id:
            return

    @Slot(str)
    def _log_entries_changed(self, server_id: str) -> None:
        self._refresh_logs_view(server_id)

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
    def _services_refresh_requested(self, zone: str) -> None:
        del zone
        self._refresh_selected()

    @Slot()
    def _add_service_selected(self) -> None:
        view = self._selected_view()
        if not self._port_view_is_actionable(view):
            return
        assert view is not None and view.snapshot is not None
        dialog = AddServiceDialog(
            view.snapshot.available_services,
            self.services_tab.available_zones(),
            self.services_tab.zone_combo.currentText(),
            self.services_tab.inventory_rows(),
            self,
        )
        dialog.exec()
        request = dialog.request()
        if request is None:
            return
        current = self._selected_view()
        if (
            current is None
            or current.server_id != view.server_id
            or current.generation != view.generation
        ):
            return
        try:
            preview = self._firewall_controller.preview_add_service(
                view.server_id, request
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            self._show_service_intent_error(view.server_id, "add_service")
            return
        confirmation = ConfirmationDialog(preview, self)
        confirmation.exec()
        if not confirmation.confirmed():
            return
        try:
            self._firewall_controller.apply_add_service(
                view.server_id, preview, request
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            return

    @Slot(object)
    def _remove_service_selected(self, row: object) -> None:
        view = self._selected_view()
        if not self._port_view_is_actionable(view) or not isinstance(
            row, ServiceRow
        ):
            return
        target = self.services_tab.target_for_row(row)
        try:
            preview = self._firewall_controller.preview_remove_service(
                view.server_id, row, target
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            self._show_service_intent_error(view.server_id, "remove_service")
            return
        confirmation = ConfirmationDialog(preview, self)
        confirmation.exec()
        if not confirmation.confirmed():
            return
        try:
            self._firewall_controller.apply_remove_service(
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

    @Slot(object)
    def _change_interface_zone_selected(self, row: object) -> None:
        view = self._selected_view()
        if not self._port_view_is_actionable(view) or not isinstance(
            row, InterfaceRow
        ):
            return
        assert view is not None and view.snapshot is not None
        runtime_zones = tuple(zone.name for zone in view.snapshot.runtime_zones)
        permanent_zones = tuple(zone.name for zone in view.snapshot.permanent_zones)
        try:
            dialog = ChangeInterfaceDialog.for_row(
                row, runtime_zones, permanent_zones, self
            )
        except (TypeError, ValueError):
            self._show_interface_intent_error(view.server_id)
            return
        dialog.exec()
        request = dialog.request()
        if request is None:
            return
        current = self._selected_view()
        if (
            current is None
            or current.server_id != view.server_id
            or current.generation != view.generation
        ):
            return
        try:
            preview = self._firewall_controller.preview_change_interface_zone(
                view.server_id, request
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            self._show_interface_intent_error(view.server_id)
            return
        confirmation = ConfirmationDialog(preview, self)
        confirmation.exec()
        if not confirmation.confirmed():
            return
        try:
            self._firewall_controller.apply_change_interface_zone(
                view.server_id, preview, request
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            return

    @Slot()
    def _add_rich_rule_selected(self) -> None:
        view = self._selected_view()
        if not self._port_view_is_actionable(view):
            return
        assert view is not None and view.snapshot is not None
        dialog = RichRuleDialog(
            self.rich_rules_tab.available_zones(),
            view.snapshot.available_services,
            self.rich_rules_tab.zone_combo.currentText(),
            self,
        )
        dialog.exec()
        request = dialog.request()
        if request is None:
            return
        current = self._selected_view()
        if (
            current is None
            or current.server_id != view.server_id
            or current.generation != view.generation
        ):
            return
        try:
            preview = self._firewall_controller.preview_add_rich_rule(
                view.server_id, request
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            self._show_rich_rule_intent_error(view.server_id, "add_rich_rule")
            return
        confirmation = ConfirmationDialog(preview, self)
        confirmation.exec()
        if not confirmation.confirmed():
            return
        try:
            self._firewall_controller.apply_add_rich_rule(
                view.server_id, preview, request
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            return

    @Slot(object)
    def _remove_rich_rule_selected(self, row: object) -> None:
        view = self._selected_view()
        if not self._port_view_is_actionable(view) or not isinstance(
            row, RichRuleRow
        ):
            return
        target = self.rich_rules_tab.target_for_row(row)
        try:
            preview = self._firewall_controller.preview_remove_rich_rule(
                view.server_id, row, target
            )
        except (KeyError, TypeError, RuntimeError, ValueError):
            self._show_rich_rule_intent_error(view.server_id, "remove_rich_rule")
            return
        confirmation = ConfirmationDialog(preview, self)
        confirmation.exec()
        if not confirmation.confirmed():
            return
        try:
            self._firewall_controller.apply_remove_rich_rule(
                view.server_id, preview, row, target
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
            self.services_tab.show_operation_result(result)
            self.zones_tab.show_operation_result(result)
            self.interfaces_tab.show_operation_result(result)
            self.rich_rules_tab.show_operation_result(result)

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

    def _show_service_intent_error(self, server_id: str, operation: str) -> None:
        self._show_firewall_intent_error(
            server_id,
            operation,
            "The selected service or firewall state changed before submission.",
        )

    def _show_interface_intent_error(self, server_id: str) -> None:
        self._show_firewall_intent_error(
            server_id,
            "change_interface_zone",
            "The selected interface or firewall state changed before submission.",
        )

    def _show_rich_rule_intent_error(
        self, server_id: str, operation: str
    ) -> None:
        self._show_firewall_intent_error(
            server_id,
            operation,
            "The selected rich rule or firewall state changed before submission.",
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
        if server_id and server_id != self.current_server_id:
            return
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
        self.services_tab.set_session(view)
        self.zones_tab.set_session(view)
        self.interfaces_tab.set_session(view)
        self.rich_rules_tab.set_session(view)
        self.logs_tab.set_server(None if view is None else view.server_id)
        if view is not None:
            try:
                self.logs_tab.set_entries(self._controller.log_entries(view.server_id))
            except KeyError:
                self.logs_tab.set_entries(())
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
