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

from app.controllers.server_controller import ServerController
from app.controllers.session import ServerSessionView
from app.gui.server_sidebar import ServerSidebar, status_presentation
from app.gui.widgets.state_panel import StatePanel


_TAB_NAMES = (
    "Overview",
    "Ports",
    "Services",
    "Zones",
    "Interfaces",
    "Rich Rules",
    "Logs",
)


class MainWindow(QMainWindow):
    """Render controller snapshots and forward user intentions by server ID."""

    def __init__(
        self,
        controller: ServerController,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._controller = controller
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
        for tab_name in _TAB_NAMES:
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
        self.server_sidebar.connect_requested.connect(self._controller.connect)
        self.server_sidebar.disconnect_requested.connect(self._controller.disconnect)
        self.server_sidebar.reload_requested.connect(
            self._controller.reload_configuration
        )
        self.refresh_action.triggered.connect(self._refresh_selected)
        self.reload_configuration_action.triggered.connect(
            self._controller.reload_configuration
        )
        self._controller.sessions_changed.connect(self._sessions_changed)
        self._controller.selection_changed.connect(self._selection_changed)
        self._controller.session_changed.connect(self._session_changed)

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

    def _render_selected(self) -> None:
        view = self._selected_view()
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
