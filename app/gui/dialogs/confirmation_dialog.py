"""Exact normal and high-risk firewall change confirmation."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.models.change import ChangePreview
from app.models.enums import ApplyTarget


_TARGET_TEXT = {
    ApplyTarget.RUNTIME: "Runtime",
    ApplyTarget.PERMANENT: "Permanent",
    ApplyTarget.BOTH: "Runtime + Permanent",
}


class ConfirmationDialog(QDialog):
    """Render immutable preview data and return only the user's decision."""

    def __init__(
        self, preview: ChangePreview, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm Firewall Change")
        self.setModal(True)

        form = QFormLayout()
        form.addRow("Server", QLabel(preview.server_name))
        form.addRow("Host", QLabel(preview.host))
        form.addRow("Operation", QLabel(preview.operation))
        form.addRow("Zone", QLabel(preview.zone))
        form.addRow("Resource", QLabel(preview.resource))
        form.addRow("Target", QLabel(_TARGET_TEXT[preview.target]))

        warning = QLabel("\n".join(preview.risk.reasons))
        warning.setWordWrap(True)
        warning.setAccessibleName(
            "High risk warning" if preview.risk.is_high else "Change safety notice"
        )

        buttons = QDialogButtonBox()
        self.apply_button = buttons.addButton(
            "Apply Anyway" if preview.risk.is_high else "Apply",
            QDialogButtonBox.ButtonRole.AcceptRole,
        )
        self.cancel_button = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.cancel_button.setDefault(True)
        self.cancel_button.setAutoDefault(True)
        self.apply_button.setDefault(False)
        self.apply_button.setAutoDefault(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(warning)
        layout.addWidget(buttons)

    def defaultButton(self) -> QPushButton:
        return self.cancel_button

    def confirmed(self) -> bool:
        return self.result() == QDialog.DialogCode.Accepted


__all__ = ["ChangePreview", "ConfirmationDialog"]
