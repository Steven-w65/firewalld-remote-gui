"""Cancel-default dialog for one inventory-selected interface-zone change."""

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
from app.models.interface import ChangeInterfaceRequest, InterfaceRow
from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import validate_inventory_token


class ChangeInterfaceDialog(QDialog):
    """Collect a strictly validated change from a supplied snapshot inventory."""

    def __init__(
        self,
        interface: str,
        current_zone: str | None,
        zones: Sequence[str],
        parent: QWidget | None = None,
        *,
        target: ApplyTarget = ApplyTarget.BOTH,
    ) -> None:
        super().__init__(parent)
        self._interface = validate_inventory_token("interface", interface)
        self._current_zone = (
            None
            if current_zone is None
            else validate_inventory_token("zone", current_zone)
        )
        if not isinstance(target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        inventory = tuple(
            dict.fromkeys(validate_inventory_token("zone", value) for value in zones)
        )
        self._target_options: tuple[
            tuple[ApplyTarget, str | None, tuple[str, ...]], ...
        ] = ((target, self._current_zone, inventory),)
        self._target = target
        self._zones: tuple[str, ...] = ()
        self._request: ChangeInterfaceRequest | None = None
        self.setWindowTitle("Change Interface Zone")
        self.setModal(True)

        self.interface_label = QLabel(self._interface)
        self.current_zone_label = QLabel(self._current_zone or "Unassigned")
        self.target_combo = QComboBox()
        self.target_combo.setAccessibleName("Interface change target")
        self.zone_combo = QComboBox()
        self.zone_combo.addItems(self._zones)
        self.zone_combo.setAccessibleName("New interface zone")

        form = QFormLayout()
        form.addRow("Interface", self.interface_label)
        form.addRow("Apply to", self.target_combo)
        form.addRow("Current zone", self.current_zone_label)
        form.addRow("New zone", self.zone_combo)

        self.validation_label = QLabel()
        self.validation_label.setWordWrap(True)
        self.validation_label.setAccessibleName("Interface zone validation message")
        buttons = QDialogButtonBox()
        self.apply_button = buttons.addButton(
            "Continue", QDialogButtonBox.ButtonRole.AcceptRole
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
        layout.addWidget(self.validation_label)
        layout.addWidget(buttons)
        self.zone_combo.currentTextChanged.connect(self._validate)
        self.target_combo.currentIndexChanged.connect(self._target_changed)
        self._load_target_options()

    @classmethod
    def for_row(
        cls,
        row: InterfaceRow,
        runtime_zones: Sequence[str],
        permanent_zones: Sequence[str],
        parent: QWidget | None = None,
    ) -> ChangeInterfaceDialog:
        """Build target choices and zone inventories from one snapshot row."""
        if not isinstance(row, InterfaceRow):
            raise TypeError("row must be an InterfaceRow")
        runtime = tuple(
            dict.fromkeys(
                validate_inventory_token("zone", zone) for zone in runtime_zones
            )
        )
        permanent = tuple(
            dict.fromkeys(
                validate_inventory_token("zone", zone) for zone in permanent_zones
            )
        )
        options: list[tuple[ApplyTarget, str | None, tuple[str, ...]]] = []
        if row.runtime_zone == row.permanent_zone:
            both_zones = tuple(zone for zone in permanent if zone in runtime)
            if both_zones:
                options.append((ApplyTarget.BOTH, row.runtime_zone, both_zones))
        if runtime:
            options.append((ApplyTarget.RUNTIME, row.runtime_zone, runtime))
        if permanent:
            options.append((ApplyTarget.PERMANENT, row.permanent_zone, permanent))
        if not options:
            raise InvalidFirewallArgumentError(
                "zone", "no target zone inventory is available"
            )
        initial_target, initial_current, initial_zones = options[0]
        dialog = cls(
            row.name,
            initial_current,
            initial_zones,
            parent,
            target=initial_target,
        )
        dialog._target_options = tuple(options)
        dialog._load_target_options()
        return dialog

    def defaultButton(self) -> QPushButton:
        return self.cancel_button

    def available_zones(self) -> tuple[str, ...]:
        return tuple(
            self.zone_combo.itemText(index)
            for index in range(self.zone_combo.count())
        )

    def available_targets(self) -> tuple[ApplyTarget, ...]:
        return tuple(option[0] for option in self._target_options)

    def current_zone(self) -> str | None:
        return self._current_zone

    def request(self) -> ChangeInterfaceRequest | None:
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

    def _candidate(self) -> ChangeInterfaceRequest | None:
        if not self.zone_combo.currentText():
            return None
        try:
            return ChangeInterfaceRequest(
                self._interface,
                self._current_zone,
                self.zone_combo.currentText(),
                self._target,
            )
        except (InvalidFirewallArgumentError, TypeError, ValueError):
            return None

    def _validate(self) -> None:
        valid = self._candidate() is not None
        self.apply_button.setEnabled(valid)
        self.validation_label.setText(
            "" if valid else "No different zone is available for this target."
        )

    def _load_target_options(self) -> None:
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        for target, _current, _zones in self._target_options:
            self.target_combo.addItem(target.value.title(), target)
        self.target_combo.blockSignals(False)
        self._target_changed()

    def _target_changed(self) -> None:
        index = self.target_combo.currentIndex()
        if not 0 <= index < len(self._target_options):
            self._zones = ()
            self.zone_combo.clear()
            self._validate()
            return
        self._target, self._current_zone, inventory = self._target_options[index]
        self._zones = tuple(
            zone for zone in inventory if zone != self._current_zone
        )
        self.current_zone_label.setText(self._current_zone or "Unassigned")
        self.zone_combo.blockSignals(True)
        self.zone_combo.clear()
        self.zone_combo.addItems(self._zones)
        self.zone_combo.blockSignals(False)
        self._validate()


__all__ = ["ChangeInterfaceDialog", "ChangeInterfaceRequest"]
