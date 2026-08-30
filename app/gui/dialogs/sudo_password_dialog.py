"""Masked, memory-only sudo password entry dialog."""

from __future__ import annotations

from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class SudoPasswordDialog(QDialog):
    """Collect a sudo password without copying it into presentation text."""

    def __init__(self, server_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._cancelled = False
        self.setWindowTitle("Sudo Authentication Required")
        self.setModal(True)

        explanation = QLabel(
            f"Enter the sudo password for {server_name}. It is retained only in "
            "this server's in-memory session and is cleared on disconnect."
        )
        explanation.setWordWrap(True)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setAccessibleName("Sudo password")
        self.password_edit.setPlaceholderText("Sudo password")

        buttons = QDialogButtonBox()
        self.submit_button = buttons.addButton(
            "Continue", QDialogButtonBox.ButtonRole.AcceptRole
        )
        self.cancel_button = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.cancel_button.setDefault(True)
        self.cancel_button.setAutoDefault(True)
        self.submit_button.setDefault(False)
        self.submit_button.setAutoDefault(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(explanation)
        layout.addWidget(self.password_edit)
        layout.addWidget(buttons)

    def defaultButton(self) -> QPushButton:
        return self.cancel_button

    def confirmed(self) -> bool:
        return not self._cancelled and self.result() == QDialog.DialogCode.Accepted

    def take_password(self) -> str | None:
        if self._cancelled:
            self.password_edit.clear()
            return None
        password = self.password_edit.text()
        self.password_edit.clear()
        return password or None

    def reject(self) -> None:
        self._cancelled = True
        self.password_edit.clear()
        super().reject()

    def done(self, result: int) -> None:
        if result != int(QDialog.DialogCode.Accepted):
            self._cancelled = True
            self.password_edit.clear()
        super().done(result)

    def closeEvent(self, event: QCloseEvent) -> None:
        self._cancelled = True
        self.password_edit.clear()
        super().closeEvent(event)

    def __del__(self) -> None:
        try:
            self.password_edit.clear()
        except (AttributeError, RuntimeError):
            pass


__all__ = ["SudoPasswordDialog"]
