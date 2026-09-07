"""Immutable zone rows and a compact read-only Qt table model."""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from app.models.firewall import FirewallSnapshot, ZoneState


_HEADERS = ("Zone", "Runtime Active")


@dataclass(frozen=True, slots=True)
class ZoneRow:
    """One target-specific zone plus activity derived from runtime state."""

    name: str
    active: bool
    interfaces: tuple[str, ...]
    sources: tuple[str, ...]
    services: tuple[str, ...]
    ports: tuple[str, ...]
    protocols: tuple[str, ...]
    masquerade: bool
    forwarding: bool
    rich_rule_count: int


def _active_zone_names(snapshot: FirewallSnapshot) -> frozenset[str]:
    return frozenset(
        zone.name
        for zone in snapshot.runtime_zones
        if zone.active
    )


def _row(zone: ZoneState, active_zone_names: Collection[str]) -> ZoneRow:
    return ZoneRow(
        name=zone.name,
        active=zone.name in active_zone_names,
        interfaces=zone.interfaces,
        sources=zone.sources,
        services=zone.services,
        ports=tuple(f"{item.port}/{item.protocol}" for item in zone.ports),
        protocols=zone.protocols,
        masquerade=zone.masquerade,
        forwarding=zone.forwarding,
        rich_rule_count=len(zone.rich_rules),
    )


def zone_rows(
    snapshot: FirewallSnapshot, *, permanent: bool
) -> tuple[ZoneRow, ...]:
    """Return one view's details while deriving activity only from runtime data."""
    if not isinstance(snapshot, FirewallSnapshot):
        raise TypeError("snapshot must be a FirewallSnapshot")
    zones = snapshot.permanent_zones if permanent else snapshot.runtime_zones
    active = _active_zone_names(snapshot)
    return tuple(sorted((_row(zone, active) for zone in zones), key=lambda row: row.name))


class ZonesModel(QAbstractTableModel):
    """Read-only zone selector; full details remain available through ``row_at``."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._zones: tuple[ZoneState, ...] = ()
        self._rows: tuple[ZoneRow, ...] = ()

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
        if index.column() == 0:
            if role in (
                Qt.ItemDataRole.DisplayRole,
                Qt.ItemDataRole.AccessibleTextRole,
            ):
                return row.name
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return None
        if role == Qt.ItemDataRole.CheckStateRole:
            return Qt.CheckState.Checked if row.active else Qt.CheckState.Unchecked
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return f"Active: {'Yes' if row.active else 'No'}"
        if role == Qt.ItemDataRole.ToolTipRole:
            return "Runtime active" if row.active else "Not runtime active"
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignCenter
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def set_zones(
        self,
        zones: Sequence[ZoneState],
        *,
        active_zone_names: Collection[str] | None = None,
    ) -> None:
        values = tuple(zones)
        if any(not isinstance(zone, ZoneState) for zone in values):
            raise TypeError("zones must contain only ZoneState values")
        active = (
            frozenset(active_zone_names)
            if active_zone_names is not None
            else frozenset(
                zone.name for zone in values if zone.active
            )
        )
        self.beginResetModel()
        self._zones = tuple(sorted(values, key=lambda zone: zone.name))
        self._rows = tuple(
            sorted((_row(zone, active) for zone in values), key=lambda row: row.name)
        )
        self.endResetModel()

    def zones(self) -> tuple[ZoneState, ...]:
        return self._zones

    def row_at(self, row: int) -> ZoneRow | None:
        if not isinstance(row, int) or not 0 <= row < len(self._rows):
            return None
        return self._rows[row]


__all__ = ["ZoneRow", "ZonesModel", "zone_rows"]
