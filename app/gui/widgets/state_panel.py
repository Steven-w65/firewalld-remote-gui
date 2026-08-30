"""Accessible placeholder states shared by management tabs."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QStyle, QVBoxLayout, QWidget

from app.controllers.session import ServerSessionView
from app.models.enums import ConnectionStatus


_ERROR_TEXT = {
    ConnectionStatus.AUTHENTICATION_FAILED: "Authentication failed",
    ConnectionStatus.CONNECTION_ERROR: "Connection error",
    ConnectionStatus.HOST_KEY_ERROR: "Host key error",
    ConnectionStatus.PERMISSION_ERROR: "Permission denied",
    ConnectionStatus.FIREWALLD_NOT_INSTALLED: "firewalld not installed",
    ConnectionStatus.FIREWALLD_NOT_RUNNING: "firewalld not running",
}


class StatePanel(QWidget):
    """Render one credential-safe state for a selected server."""

    def __init__(self, panel_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._panel_name = panel_name
        self.state_key = "no_selection"
        self.setAccessibleName(f"{panel_name} status")

        self.icon_label = QLabel()
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label.setAccessibleName(f"{panel_name} status icon")
        self.message_label = QLabel()
        self.message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.message_label.setWordWrap(True)
        self.message_label.setAccessibleName(f"{panel_name} status message")

        layout = QVBoxLayout(self)
        layout.addStretch(1)
        layout.addWidget(self.icon_label)
        layout.addWidget(self.message_label)
        layout.addStretch(1)
        self.set_session(None)

    def set_session(self, view: ServerSessionView | None) -> None:
        if view is None:
            self._show(
                "no_selection",
                "No server selected",
                QStyle.StandardPixmap.SP_MessageBoxInformation,
            )
            return
        if view.busy_operation or view.status is ConnectionStatus.CONNECTING:
            operation = (
                "Connecting"
                if view.status is ConnectionStatus.CONNECTING
                else (view.busy_operation or "operation").replace("_", " ").title()
            )
            self._show(
                "busy",
                f"{operation} in progress",
                QStyle.StandardPixmap.SP_BrowserReload,
            )
            return
        if view.status is ConnectionStatus.CONNECTED:
            if view.snapshot is None:
                self._show(
                    "empty",
                    "No firewall data is available yet",
                    QStyle.StandardPixmap.SP_MessageBoxInformation,
                )
            elif view.snapshot.stale:
                self._show(
                    "stale",
                    "Stale data — refresh to try again",
                    QStyle.StandardPixmap.SP_MessageBoxWarning,
                )
            else:
                self._show(
                    "connected",
                    "Connected — management content will appear here",
                    QStyle.StandardPixmap.SP_DialogApplyButton,
                )
            return
        if view.status is ConnectionStatus.DISCONNECTED:
            self._show(
                "disconnected",
                "Disconnected",
                QStyle.StandardPixmap.SP_MessageBoxInformation,
            )
            return
        self._show(
            "error",
            _ERROR_TEXT.get(view.status, "Server unavailable"),
            QStyle.StandardPixmap.SP_MessageBoxCritical,
        )

    def _show(
        self,
        state_key: str,
        message: str,
        icon: QStyle.StandardPixmap,
    ) -> None:
        self.state_key = state_key
        self.message_label.setText(message)
        pixmap = self.style().standardIcon(icon).pixmap(48, 48)
        self.icon_label.setPixmap(pixmap)
        self.setAccessibleDescription(message)
