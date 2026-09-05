"""Pure service merging plus accessible Qt table and filter models."""

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt

from app.models.firewall import FirewallSnapshot
from app.models.service import ServiceRow
from app.utils.validation import validate_inventory_token


_HEADERS = ("Service", "Zone", "Runtime", "Permanent")


class ServicePresenceFilter(str, Enum):
    ALL = "all"
    RUNTIME = "runtime"
    PERMANENT = "permanent"
    BOTH = "both"


def _row_sort_key(row: ServiceRow) -> tuple[str, str]:
    return row.name.casefold(), row.zone.casefold()


def _column_sort_key(row: ServiceRow, column: int) -> tuple[object, ...]:
    fallback = _row_sort_key(row)
    if column == 0:
        return fallback
    if column == 1:
        return (row.zone.casefold(), *fallback)
    if column == 2:
        return (row.runtime, *fallback)
    if column == 3:
        return (row.permanent, *fallback)
    return fallback


def merge_service_rows(
    snapshot: FirewallSnapshot, zone: str
) -> tuple[ServiceRow, ...]:
    """Merge service membership for one exact zone without parsing display text."""
    if not isinstance(snapshot, FirewallSnapshot):
        raise TypeError("snapshot must be a FirewallSnapshot")
    zone = validate_inventory_token("zone", zone)
    membership: dict[str, list[bool]] = {}
    for permanent, zones in (
        (False, snapshot.runtime_zones),
        (True, snapshot.permanent_zones),
    ):
        state = next((candidate for candidate in zones if candidate.name == zone), None)
        if state is None:
            continue
        for value in state.services:
            service = validate_inventory_token("service", value)
            present = membership.setdefault(service, [False, False])
            present[1 if permanent else 0] = True
    return tuple(
        sorted(
            (
                ServiceRow(name, zone, runtime, permanent)
                for name, (runtime, permanent) in membership.items()
            ),
            key=_row_sort_key,
        )
    )


class ServicesTableModel(QAbstractTableModel):
    """Read-only table model for validated service rows."""

    def __init__(self, rows: Sequence[ServiceRow] = (), parent=None) -> None:
        super().__init__(parent)
        self._rows: tuple[ServiceRow, ...] = ()
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
        column = index.column()
        if column < 2:
            value = (row.name, row.zone)[column]
            if role in (
                Qt.ItemDataRole.DisplayRole,
                Qt.ItemDataRole.AccessibleTextRole,
            ):
                return value
            return None
        present = row.runtime if column == 2 else row.permanent
        if role == Qt.ItemDataRole.DisplayRole:
            return "✓" if present else ""
        if role == Qt.ItemDataRole.CheckStateRole:
            return Qt.CheckState.Checked if present else Qt.CheckState.Unchecked
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return f"{_HEADERS[column]}: {'Yes' if present else 'No'}"
        if role == Qt.ItemDataRole.ToolTipRole:
            return "Yes" if present else "No"
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignCenter
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def set_rows(self, rows: Sequence[ServiceRow]) -> None:
        values = tuple(rows)
        if any(not isinstance(row, ServiceRow) for row in values):
            raise TypeError("rows must contain only ServiceRow values")
        self.beginResetModel()
        self._rows = values
        self.endResetModel()

    def row_at(self, row: int) -> ServiceRow | None:
        if not isinstance(row, int) or not 0 <= row < len(self._rows):
            return None
        return self._rows[row]

    def rows(self) -> tuple[ServiceRow, ...]:
        return self._rows

    def sort(
        self,
        column: int,
        order: Qt.SortOrder = Qt.SortOrder.AscendingOrder,
    ) -> None:
        if not 0 <= column < len(_HEADERS):
            return
        self.layoutAboutToBeChanged.emit()
        self._rows = tuple(
            sorted(
                self._rows,
                key=lambda row: _column_sort_key(row, column),
                reverse=order == Qt.SortOrder.DescendingOrder,
            )
        )
        self.layoutChanged.emit()


class ServicesFilterProxyModel(QSortFilterProxyModel):
    """Fixed-string search and target-presence filtering for services."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._search_text = ""
        self._presence = ServicePresenceFilter.ALL
        self.setDynamicSortFilter(True)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_search_text(self, text: str) -> None:
        if not isinstance(text, str):
            raise TypeError("search text must be a string")
        self.beginFilterChange()
        self._search_text = text.casefold()
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def set_presence_filter(self, presence: ServicePresenceFilter) -> None:
        if not isinstance(presence, ServicePresenceFilter):
            raise TypeError("presence must be a ServicePresenceFilter")
        self.beginFilterChange()
        self._presence = presence
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        source = self.sourceModel()
        if not isinstance(source, ServicesTableModel):
            return False
        row = source.row_at(source_row)
        if row is None:
            return False
        if self._search_text and not any(
            self._search_text in value.casefold() for value in (row.name, row.zone)
        ):
            return False
        if self._presence is ServicePresenceFilter.RUNTIME:
            return row.runtime
        if self._presence is ServicePresenceFilter.PERMANENT:
            return row.permanent
        if self._presence is ServicePresenceFilter.BOTH:
            return row.runtime and row.permanent
        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        source = self.sourceModel()
        if not isinstance(source, ServicesTableModel):
            return super().lessThan(left, right)
        left_row = source.row_at(left.row())
        right_row = source.row_at(right.row())
        if left_row is None or right_row is None:
            return super().lessThan(left, right)
        return _column_sort_key(left_row, left.column()) < _column_sort_key(
            right_row, right.column()
        )

    def service_row(self, proxy_index: QModelIndex) -> ServiceRow | None:
        if not proxy_index.isValid():
            return None
        source = self.sourceModel()
        if not isinstance(source, ServicesTableModel):
            return None
        return source.row_at(self.mapToSource(proxy_index).row())


__all__ = [
    "ServicePresenceFilter",
    "ServiceRow",
    "ServicesFilterProxyModel",
    "ServicesTableModel",
    "merge_service_rows",
]
