"""Server navigation with text-and-icon connection states."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import QSignalBlocker, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from app.controllers.session import ServerSessionView
from app.models.enums import ConnectionStatus


_STATUS_PRESENTATION = {
    ConnectionStatus.DISCONNECTED: (
        "Disconnected",
        QStyle.StandardPixmap.SP_MessageBoxInformation,
    ),
    ConnectionStatus.CONNECTING: (
        "Connecting",
        QStyle.StandardPixmap.SP_BrowserReload,
    ),
    ConnectionStatus.CONNECTED: (
        "Connected",
        QStyle.StandardPixmap.SP_DialogApplyButton,
    ),
    ConnectionStatus.AUTHENTICATION_FAILED: (
        "Authentication failed",
        QStyle.StandardPixmap.SP_MessageBoxCritical,
    ),
    ConnectionStatus.CONNECTION_ERROR: (
        "Connection error",
        QStyle.StandardPixmap.SP_MessageBoxCritical,
    ),
    ConnectionStatus.HOST_KEY_ERROR: (
        "Host key error",
        QStyle.StandardPixmap.SP_MessageBoxCritical,
    ),
    ConnectionStatus.PERMISSION_ERROR: (
        "Permission denied",
        QStyle.StandardPixmap.SP_MessageBoxCritical,
    ),
    ConnectionStatus.FIREWALLD_NOT_INSTALLED: (
        "firewalld not installed",
        QStyle.StandardPixmap.SP_MessageBoxWarning,
    ),
    ConnectionStatus.FIREWALLD_NOT_RUNNING: (
        "firewalld not running",
        QStyle.StandardPixmap.SP_MessageBoxWarning,
    ),
}


def status_presentation(
    status: ConnectionStatus,
) -> tuple[str, QStyle.StandardPixmap]:
    return _STATUS_PRESENTATION[status]


class ServerSidebar(QWidget):
    server_selected = Signal(str)
    connect_requested = Signal(str)
    disconnect_requested = Signal(str)
    reload_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumWidth(240)
        self.setAccessibleName("Server navigation")
        self._views: dict[str, ServerSessionView] = {}

        title = QLabel("Servers")
        title.setAccessibleName("Servers heading")
        self.server_list = QListWidget()
        self.server_list.setObjectName("serverList")
        self.server_list.setAccessibleName("Configured servers")
        self.server_list.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.server_list.currentItemChanged.connect(self._current_item_changed)

        self.connect_button = QPushButton("Connect")
        self.connect_button.setObjectName("connectServerButton")
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.setObjectName("disconnectServerButton")
        self.reload_button = QPushButton("Reload Config")
        self.reload_button.setObjectName("reloadConfigurationButton")
        self.connect_button.clicked.connect(self._request_connect)
        self.disconnect_button.clicked.connect(self._request_disconnect)
        self.reload_button.clicked.connect(self.reload_requested)

        action_row = QHBoxLayout()
        action_row.addWidget(self.connect_button)
        action_row.addWidget(self.disconnect_button)
        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(self.server_list, 1)
        layout.addLayout(action_row)
        layout.addWidget(self.reload_button)
        self._update_actions()

    def set_sessions(
        self,
        sessions: Sequence[ServerSessionView],
        selected_id: str | None,
    ) -> None:
        blocker = QSignalBlocker(self.server_list)
        self.server_list.clear()
        self._views = {view.server_id: view for view in sessions}
        selected_item: QListWidgetItem | None = None
        for view in sessions:
            status_text, standard_icon = status_presentation(view.status)
            item = QListWidgetItem(f"{view.name}\n{status_text}")
            item.setData(Qt.ItemDataRole.UserRole, view.server_id)
            item.setData(
                Qt.ItemDataRole.AccessibleTextRole,
                f"{view.name}, {status_text}",
            )
            item.setIcon(self.style().standardIcon(standard_icon))
            self.server_list.addItem(item)
            if view.server_id == selected_id:
                selected_item = item
        if selected_item is not None:
            self.server_list.setCurrentItem(selected_item)
        else:
            self.server_list.setCurrentRow(-1)
        del blocker
        self._update_actions()

    def server_ids(self) -> tuple[str, ...]:
        return tuple(
            self.server_list.item(index).data(Qt.ItemDataRole.UserRole)
            for index in range(self.server_list.count())
        )

    def selected_server_id(self) -> str | None:
        item = self.server_list.currentItem()
        return None if item is None else item.data(Qt.ItemDataRole.UserRole)

    def select_server(self, server_id: str) -> None:
        for index in range(self.server_list.count()):
            item = self.server_list.item(index)
            if item.data(Qt.ItemDataRole.UserRole) == server_id:
                self.server_list.setCurrentItem(item)
                return
        raise KeyError(server_id)

    def _current_item_changed(
        self,
        current: QListWidgetItem | None,
        previous: QListWidgetItem | None,
    ) -> None:
        del previous
        self._update_actions()
        if current is not None:
            self.server_selected.emit(current.data(Qt.ItemDataRole.UserRole))

    def _request_connect(self) -> None:
        server_id = self.selected_server_id()
        if server_id is not None:
            self.connect_requested.emit(server_id)

    def _request_disconnect(self) -> None:
        server_id = self.selected_server_id()
        if server_id is not None:
            self.disconnect_requested.emit(server_id)

    def _update_actions(self) -> None:
        server_id = self.selected_server_id()
        view = self._views.get(server_id) if server_id is not None else None
        if view is None:
            self.connect_button.setEnabled(False)
            self.disconnect_button.setEnabled(False)
            return
        connectable = view.status in {
            ConnectionStatus.DISCONNECTED,
            ConnectionStatus.AUTHENTICATION_FAILED,
            ConnectionStatus.CONNECTION_ERROR,
            ConnectionStatus.HOST_KEY_ERROR,
            ConnectionStatus.PERMISSION_ERROR,
            ConnectionStatus.FIREWALLD_NOT_INSTALLED,
            ConnectionStatus.FIREWALLD_NOT_RUNNING,
        }
        self.connect_button.setEnabled(connectable and not view.busy_operation)
        self.disconnect_button.setEnabled(
            view.status is not ConnectionStatus.DISCONNECTED
        )
