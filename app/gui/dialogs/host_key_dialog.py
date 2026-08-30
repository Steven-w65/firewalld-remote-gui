"""Explicit confirmation for a previously unknown SSH host key."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.ssh.host_keys import HostKeyChallenge


class HostKeyDialog(QDialog):
    """Render one safe host-key challenge and return an explicit decision."""

    def __init__(
        self, challenge: HostKeyChallenge, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Trust New SSH Host Key")
        self.setModal(True)

        introduction = QLabel(
            "This server is not yet in the application's trusted host list. "
            "Verify the fingerprint through a separate trusted channel before "
            "continuing."
        )
        introduction.setWordWrap(True)
        host_label = QLabel(f"{challenge.host}:{challenge.port}")
        self.algorithm_label = QLabel(challenge.algorithm)
        self.fingerprint_label = QLabel(challenge.fingerprint_sha256)
        self.fingerprint_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        form = QFormLayout()
        form.addRow("Host", host_label)
        form.addRow("Algorithm", self.algorithm_label)
        form.addRow("SHA-256 fingerprint", self.fingerprint_label)

        buttons = QDialogButtonBox()
        self.trust_button = buttons.addButton(
            "Trust and Connect", QDialogButtonBox.ButtonRole.AcceptRole
        )
        self.cancel_button = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.cancel_button.setDefault(True)
        self.cancel_button.setAutoDefault(True)
        self.trust_button.setDefault(False)
        self.trust_button.setAutoDefault(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(introduction)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def defaultButton(self) -> QPushButton:
        return self.cancel_button

    def confirmed(self) -> bool:
        return self.result() == QDialog.DialogCode.Accepted


__all__ = ["HostKeyDialog"]
