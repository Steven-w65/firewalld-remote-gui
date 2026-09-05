"""Cancel-default dialog for one structured rich-rule addition."""

from __future__ import annotations

from collections.abc import Sequence

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
from app.models.rich_rule import RichRuleRequest
from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import validate_inventory_token


class RichRuleDialog(QDialog):
    def __init__(
        self,
        zones: Sequence[str],
        services: Sequence[str],
        current_zone: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._zones = tuple(
            dict.fromkeys(validate_inventory_token("zone", value) for value in zones)
        )
        self._services = tuple(
            dict.fromkeys(
                validate_inventory_token("service", value) for value in services
            )
        )
        if not self._zones:
            raise ValueError("at least one snapshot zone is required")
        self._request: RichRuleRequest | None = None
        self.setWindowTitle("Add Structured Rich Rule")
        self.setModal(True)

        self.zone_combo = QComboBox()
        self.zone_combo.addItems(self._zones)
        if current_zone in self._zones:
            self.zone_combo.setCurrentText(current_zone)
        self.source_edit = QLineEdit()
        self.destination_edit = QLineEdit()
        self.service_combo = QComboBox()
        self.service_combo.addItem("")
        self.service_combo.addItems(self._services)
        self.port_edit = QLineEdit()
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(("tcp", "udp"))
        self.action_combo = QComboBox()
        self.action_combo.addItems(("accept", "reject", "drop"))
        self.target_combo = QComboBox()
        self.target_combo.addItem("Runtime", ApplyTarget.RUNTIME)
        self.target_combo.addItem("Permanent", ApplyTarget.PERMANENT)
        self.target_combo.addItem("Runtime + Permanent", ApplyTarget.BOTH)
        self.target_combo.setCurrentIndex(2)

        form = QFormLayout()
        form.addRow("Zone", self.zone_combo)
        form.addRow("Source network (optional)", self.source_edit)
        form.addRow("Destination network (optional)", self.destination_edit)
        form.addRow("Service", self.service_combo)
        form.addRow("Port", self.port_edit)
        form.addRow("Protocol", self.protocol_combo)
        form.addRow("Action", self.action_combo)
        form.addRow("Apply to", self.target_combo)
        self.validation_label = QLabel()
        self.validation_label.setWordWrap(True)
        buttons = QDialogButtonBox()
        self.add_button = buttons.addButton(
            "Continue", QDialogButtonBox.ButtonRole.AcceptRole
        )
        self.cancel_button = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.cancel_button.setDefault(True)
        self.cancel_button.setAutoDefault(True)
        self.add_button.setDefault(False)
        self.add_button.setAutoDefault(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.validation_label)
        layout.addWidget(buttons)

        for widget in (
            self.zone_combo,
            self.source_edit,
            self.destination_edit,
            self.service_combo,
            self.port_edit,
            self.protocol_combo,
            self.action_combo,
            self.target_combo,
        ):
            signal = (
                widget.textChanged
                if isinstance(widget, QLineEdit)
                else widget.currentIndexChanged
            )
            signal.connect(self._validate)
        self._validate()

    def defaultButton(self) -> QPushButton:
        return self.cancel_button

    def target(self) -> ApplyTarget:
        try:
            return ApplyTarget(self.target_combo.currentData())
        except (TypeError, ValueError):
            raise TypeError("target selection must be an ApplyTarget") from None

    def request(self) -> RichRuleRequest | None:
        return self._request if self.result() == QDialog.DialogCode.Accepted else None

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

    def _candidate(self) -> RichRuleRequest | None:
        source = self.source_edit.text() or None
        destination = self.destination_edit.text() or None
        service = self.service_combo.currentText() or None
        port = self.port_edit.text() or None
        protocol = self.protocol_combo.currentText() if port is not None else None
        try:
            return RichRuleRequest(
                self.zone_combo.currentText(),
                source,
                destination,
                service,
                port,
                protocol,
                self.action_combo.currentText(),
                self.target(),
            )
        except (InvalidFirewallArgumentError, TypeError, ValueError):
            return None

    def _validate(self) -> None:
        valid = self._candidate() is not None
        self.add_button.setEnabled(valid)
        self.validation_label.setText(
            ""
            if valid
            else "Choose exactly one remote service or valid port/protocol; networks must use one address family."
        )


__all__ = ["RichRuleDialog", "RichRuleRequest"]
