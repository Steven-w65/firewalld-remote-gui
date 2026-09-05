"""Remote-inventory-only dialog for validated add-service intentions."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.models.enums import ApplyTarget
from app.models.service import AddServiceRequest, ServiceRow
from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import validate_inventory_token


class AddServiceDialog(QDialog):
    """Collect a service request using only the current remote inventory."""

    def __init__(
        self,
        services: Sequence[str],
        zones: Sequence[str],
        current_zone: str,
        rows: Sequence[ServiceRow] = (),
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._services = tuple(
            dict.fromkeys(
                validate_inventory_token("service", value) for value in services
            )
        )
        self._zones = tuple(
            dict.fromkeys(validate_inventory_token("zone", value) for value in zones)
        )
        self._rows = tuple(rows)
        if not self._services:
            raise ValueError("at least one remote service is required")
        if not self._zones:
            raise ValueError("at least one snapshot zone is required")
        if any(not isinstance(row, ServiceRow) for row in self._rows):
            raise TypeError("rows must contain only ServiceRow values")
        self._request: AddServiceRequest | None = None
        self.setWindowTitle("Add Firewall Service")
        self.setModal(True)

        self.zone_combo = QComboBox()
        self.zone_combo.addItems(self._zones)
        if current_zone in self._zones:
            self.zone_combo.setCurrentText(current_zone)
        self.service_combo = QComboBox()
        self.target_combo = QComboBox()
        self.target_combo.addItem("Runtime", ApplyTarget.RUNTIME)
        self.target_combo.addItem("Permanent", ApplyTarget.PERMANENT)
        self.target_combo.addItem("Runtime + Permanent", ApplyTarget.BOTH)
        self.target_combo.setCurrentIndex(2)
        self.zone_combo.setAccessibleName("Zone")
        self.service_combo.setAccessibleName("Remote service")
        self.target_combo.setAccessibleName("Apply target")

        form = QFormLayout()
        form.addRow("Zone", self.zone_combo)
        form.addRow("Service", self.service_combo)
        form.addRow("Apply to", self.target_combo)
        self.validation_label = QLabel()
        self.validation_label.setWordWrap(True)
        self.validation_label.setAccessibleName("Service availability message")

        buttons = QDialogButtonBox()
        self.add_button = buttons.addButton(
            "Add", QDialogButtonBox.ButtonRole.AcceptRole
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

        self.zone_combo.currentTextChanged.connect(self._reload_services)
        self.target_combo.currentIndexChanged.connect(self._reload_services)
        self.service_combo.currentIndexChanged.connect(self._validate)
        self._reload_services()

    def defaultButton(self) -> QPushButton:
        return self.cancel_button

    def target(self) -> ApplyTarget:
        try:
            return ApplyTarget(self.target_combo.currentData())
        except (TypeError, ValueError):
            raise TypeError("target selection must be an ApplyTarget") from None

    def service_names(self) -> tuple[str, ...]:
        return tuple(
            self.service_combo.itemText(index)
            for index in range(self.service_combo.count())
        )

    def request(self) -> AddServiceRequest | None:
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

    def _present(self, service: str, permanent: bool) -> bool:
        row = next(
            (
                item
                for item in self._rows
                if item.zone == self.zone_combo.currentText() and item.name == service
            ),
            None,
        )
        return bool(row is not None and (row.permanent if permanent else row.runtime))

    def _eligible(self, service: str) -> bool:
        target = self.target()
        runtime = self._present(service, False)
        permanent = self._present(service, True)
        if target is ApplyTarget.RUNTIME:
            return not runtime
        if target is ApplyTarget.PERMANENT:
            return not permanent
        return not (runtime and permanent)

    def _reload_services(self) -> None:
        previous = self.service_combo.currentText()
        eligible = tuple(value for value in self._services if self._eligible(value))
        self.service_combo.blockSignals(True)
        self.service_combo.clear()
        self.service_combo.addItems(eligible)
        if previous in eligible:
            self.service_combo.setCurrentText(previous)
        self.service_combo.blockSignals(False)
        self._validate()

    def _candidate(self) -> AddServiceRequest | None:
        if not self.service_combo.currentText():
            return None
        try:
            return AddServiceRequest(
                self.zone_combo.currentText(),
                self.service_combo.currentText(),
                self.target(),
            )
        except (InvalidFirewallArgumentError, TypeError, ValueError):
            return None

    def _validate(self) -> None:
        valid = self._candidate() is not None
        self.add_button.setEnabled(valid)
        self.validation_label.setText(
            "" if valid else "No remote service is available for the selected targets."
        )


__all__ = ["AddServiceDialog", "AddServiceRequest"]
