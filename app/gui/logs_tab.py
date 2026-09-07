"""Read-only presentation of sanitized in-memory entries for one server."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class LogsTab(QWidget):
    """Display pre-sanitized text without exposing a filesystem input surface."""

    clear_requested = Signal(str)
    refresh_requested = Signal(str)
    copy_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._server_id: str | None = None
        self.setAccessibleName("Application logs")

        self.status_label = QLabel("No server selected")
        self.status_label.setAccessibleName("Application logs status")
        self.text_view = QPlainTextEdit()
        self.text_view.setReadOnly(True)
        self.text_view.setAccessibleName("Sanitized application log entries")
        self.text_view.setPlaceholderText("No sanitized log entries are available.")

        self.clear_button = QPushButton("Clear view")
        self.copy_button = QPushButton("Copy visible text")
        self.refresh_button = QPushButton("Refresh")
        self.clear_button.clicked.connect(self._clear_view)
        self.copy_button.clicked.connect(self._copy_visible)
        self.refresh_button.clicked.connect(self._request_refresh)

        actions = QHBoxLayout()
        actions.addWidget(self.clear_button)
        actions.addWidget(self.copy_button)
        actions.addWidget(self.refresh_button)
        actions.addStretch(1)
        layout = QVBoxLayout(self)
        layout.addWidget(self.status_label)
        layout.addWidget(self.text_view, 1)
        layout.addLayout(actions)
        self._update_actions()

    @property
    def server_id(self) -> str | None:
        return self._server_id

    def set_server(self, server_id: str | None) -> None:
        if server_id is not None and (
            not isinstance(server_id, str) or not server_id
        ):
            raise TypeError("server_id must be a nonempty string or None")
        if server_id != self._server_id:
            self.text_view.clear()
        self._server_id = server_id
        self.status_label.setText(
            "No server selected"
            if server_id is None
            else f"Sanitized in-memory entries for {server_id}"
        )
        self._update_actions()

    def set_entries(self, entries: Sequence[str]) -> None:
        if isinstance(entries, (str, bytes)) or any(
            not isinstance(entry, str) for entry in entries
        ):
            raise TypeError("entries must be a sequence of strings")
        self.text_view.setPlainText("\n".join(entries))
        self._update_actions()

    def toPlainText(self) -> str:
        return self.text_view.toPlainText()

    def _clear_view(self) -> None:
        server_id = self._server_id
        if server_id is None:
            return
        self.text_view.clear()
        self.clear_requested.emit(server_id)
        self._update_actions()

    def _copy_visible(self) -> None:
        server_id = self._server_id
        if server_id is None:
            return
        QApplication.clipboard().setText(self.text_view.toPlainText())
        self.copy_requested.emit(server_id)

    def _request_refresh(self) -> None:
        server_id = self._server_id
        if server_id is not None:
            self.refresh_requested.emit(server_id)

    def _update_actions(self) -> None:
        selected = self._server_id is not None
        has_text = bool(self.text_view.toPlainText())
        self.clear_button.setEnabled(selected and has_text)
        self.copy_button.setEnabled(selected and has_text)
        self.refresh_button.setEnabled(selected)


__all__ = ["LogsTab"]
