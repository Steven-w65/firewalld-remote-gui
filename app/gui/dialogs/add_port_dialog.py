"""Cancel-default dialog that creates only validated add-port intentions."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.models.enums import ApplyTarget
from app.models.port import AddPortRequest
from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import validate_inventory_token


class AddPortDialog(QDialog):
    """Collect a bounded port request without exposing rejected widget state."""

    INVALID_PORT_MESSAGE = (
        "Enter a single port from 1 to 65535 or an ascending inclusive range."
    )

    def __init__(
        self,
        zones: tuple[str, ...],
        current_zone: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        validated_zones = tuple(
            dict.fromkeys(validate_inventory_token("zone", zone) for zone in zones)
        )
        if not validated_zones:
            raise ValueError("at least one snapshot zone is required")
        self._request: AddPortRequest | None = None
        self.setWindowTitle("Add Firewall Port")
        self.setModal(True)

        self.zone_combo = QComboBox()
        self.zone_combo.addItems(validated_zones)
        if current_zone in validated_zones:
            self.zone_combo.setCurrentText(current_zone)
        self.port_edit = QLineEdit()
        self.port_edit.setPlaceholderText("For example: 443 or 8000-8100")
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItem("TCP", "tcp")
        self.protocol_combo.addItem("UDP", "udp")
        self.target_combo = QComboBox()
        self.target_combo.addItem("Runtime", ApplyTarget.RUNTIME)
        self.target_combo.addItem("Permanent", ApplyTarget.PERMANENT)
        self.target_combo.addItem("Runtime + Permanent", ApplyTarget.BOTH)
        self.target_combo.setCurrentIndex(2)
        for widget, name in (
            (self.zone_combo, "Zone"),
            (self.port_edit, "Port or range"),
            (self.protocol_combo, "Protocol"),
            (self.target_combo, "Apply target"),
        ):
            widget.setAccessibleName(name)

        form = QFormLayout()
        form.addRow("Zone", self.zone_combo)
        form.addRow("Port or range", self.port_edit)
        form.addRow("Protocol", self.protocol_combo)
        form.addRow("Apply to", self.target_combo)
        self.validation_label = QLabel(self.INVALID_PORT_MESSAGE)
        self.validation_label.setWordWrap(True)
        self.validation_label.setAccessibleName("Port validation message")

        buttons = QDialogButtonBox()
        self.add_button = buttons.addButton(
            "Add", QDialogButtonBox.ButtonRole.AcceptRole
        )
        self.cancel_button = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.cancel_button.setDefault(True)
        self.cancel_button.setAutoDefault(True)
        self.add_button.setDefault(False)
        self.add_button.setAutoDefault(False)
        self.add_button.setEnabled(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.validation_label)
        layout.addWidget(buttons)

        self.port_edit.textChanged.connect(self._validate)
        self.zone_combo.currentIndexChanged.connect(self._validate)
        self.protocol_combo.currentIndexChanged.connect(self._validate)
        self.target_combo.currentIndexChanged.connect(self._validate)
        self._validate()

    def defaultButton(self) -> QPushButton:
        return self.cancel_button

    def target(self) -> ApplyTarget:
        target = self.target_combo.currentData()
        try:
            return ApplyTarget(target)
        except (TypeError, ValueError):
            raise TypeError("target selection must be an ApplyTarget")

    def request(self) -> AddPortRequest | None:
        if self.result() != QDialog.DialogCode.Accepted:
            return None
        return self._request

    def accept(self) -> None:
        candidate = self._candidate()
        if candidate is None:
            self._request = None
            return
        self._request = candidate
        super().accept()

    def reject(self) -> None:
        self._request = None
        super().reject()

    def _candidate(self) -> AddPortRequest | None:
        try:
            return AddPortRequest(
                self.zone_combo.currentText(),
                self.port_edit.text(),
                self.protocol_combo.currentData(),
                self.target(),
            )
        except (InvalidFirewallArgumentError, TypeError, ValueError):
            return None

    def _validate(self) -> None:
        valid = self._candidate() is not None
        self.add_button.setEnabled(valid)
        self.validation_label.setText("" if valid else self.INVALID_PORT_MESSAGE)


__all__ = ["AddPortDialog", "AddPortRequest"]
