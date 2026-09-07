"""Pure interface assignment merging and an accessible read-only table model."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from app.models.firewall import FirewallSnapshot, ZoneState
from app.models.interface import InterfaceRow
from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import validate_inventory_token


_HEADERS = (
    "Interface",
    "Runtime Zone",
    "Permanent Zone",
    "Runtime Assigned",
)


def _assignments(
    zones: Sequence[ZoneState],
) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for zone in zones:
        zone_name = validate_inventory_token("zone", zone.name)
        for value in zone.interfaces:
            interface = validate_inventory_token("interface", value)
            previous = assignments.get(interface)
            if previous is not None and previous != zone_name:
                raise InvalidFirewallArgumentError(
                    "interface", "has multiple zone assignments in one inventory"
                )
            assignments[interface] = zone_name
    return assignments


def interface_rows(snapshot: FirewallSnapshot) -> tuple[InterfaceRow, ...]:
    """Merge exact runtime/permanent assignments from one immutable snapshot."""
    if not isinstance(snapshot, FirewallSnapshot):
        raise TypeError("snapshot must be a FirewallSnapshot")
    runtime = _assignments(snapshot.runtime_zones)
    permanent = _assignments(snapshot.permanent_zones)
    return tuple(
        InterfaceRow(
            name,
            runtime.get(name),
            permanent.get(name),
            name in runtime,
        )
        for name in sorted(runtime.keys() | permanent.keys(), key=str.casefold)
    )


class InterfacesTableModel(QAbstractTableModel):
    """Read-only table model for immutable interface rows."""

    def __init__(self, rows: Sequence[InterfaceRow] = (), parent=None) -> None:
        super().__init__(parent)
        self._rows: tuple[InterfaceRow, ...] = ()
        self.set_rows(rows)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(_HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ):
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
            and 0 <= section < len(_HEADERS)
        ):
            return _HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if (
            not index.isValid()
            or not 0 <= index.row() < len(self._rows)
            or not 0 <= index.column() < len(_HEADERS)
        ):
            return None
        row = self._rows[index.row()]
        values = (
            row.name,
            row.runtime_zone or "Unassigned",
            row.permanent_zone or "Unassigned",
            "Yes" if row.active else "No",
        )
        if role in (
            Qt.ItemDataRole.DisplayRole,
            Qt.ItemDataRole.AccessibleTextRole,
        ):
            return values[index.column()]
        if role == Qt.ItemDataRole.ToolTipRole:
            return values[index.column()]
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def set_rows(self, rows: Sequence[InterfaceRow]) -> None:
        values = tuple(rows)
        if any(not isinstance(row, InterfaceRow) for row in values):
            raise TypeError("rows must contain only InterfaceRow values")
        self.beginResetModel()
        self._rows = values
        self.endResetModel()

    def rows(self) -> tuple[InterfaceRow, ...]:
        return self._rows

    def row_at(self, row: int) -> InterfaceRow | None:
        if not isinstance(row, int) or not 0 <= row < len(self._rows):
            return None
        return self._rows[row]


__all__ = ["InterfaceRow", "InterfacesTableModel", "interface_rows"]
