"""Exact rich-rule merging and an accessible read-only table model."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from app.models.firewall import FirewallSnapshot, RichRule
from app.models.rich_rule import (
    RichRuleRow,
    structured_rule_summary,
    validate_structured_rule,
)
from app.utils.validation import validate_inventory_token


_HEADERS = ("Rule", "Zone", "Runtime", "Permanent", "Support")


def _identity(rule: RichRule) -> tuple[object, ...]:
    structured = validate_structured_rule(rule)
    return ("raw", rule.rule) if structured is None else ("structured", *structured)


def merge_rich_rule_rows(
    snapshot: FirewallSnapshot, zone: str
) -> tuple[RichRuleRow, ...]:
    """Merge target presence using canonical structure, never display summaries."""
    if not isinstance(snapshot, FirewallSnapshot):
        raise TypeError("snapshot must be a FirewallSnapshot")
    validated_zone = validate_inventory_token("zone", zone)
    merged: dict[tuple[object, ...], list[object]] = {}
    for permanent in (False, True):
        state = snapshot.zone(validated_zone, permanent)
        if state is None:
            continue
        for rule in state.rich_rules:
            key = _identity(rule)
            entry = merged.get(key)
            if entry is None:
                entry = [rule, False, False]
                merged[key] = entry
            entry[2 if permanent else 1] = True
    rows = tuple(
        RichRuleRow(
            validated_zone,
            structured_rule_summary(entry[0]),
            bool(entry[1]),
            bool(entry[2]),
            entry[0],
        )
        for entry in merged.values()
    )
    return tuple(
        sorted(rows, key=lambda row: (row.summary.casefold(), repr(_identity(row.rule))))
    )


class RichRulesTableModel(QAbstractTableModel):
    def __init__(self, rows: Sequence[RichRuleRow] = (), parent=None) -> None:
        super().__init__(parent)
        self._rows: tuple[RichRuleRow, ...] = ()
        self.set_rows(rows)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(_HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
            and 0 <= section < len(_HEADERS)
        ):
            return _HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if (
            not index.isValid()
            or not 0 <= index.row() < len(self._rows)
            or not 0 <= index.column() < len(_HEADERS)
        ):
            return None
        row = self._rows[index.row()]
        values = (
            row.summary,
            row.zone,
            "Yes" if row.runtime else "No",
            "Yes" if row.permanent else "No",
            "Structured" if row.supported else "Display only",
        )
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole):
            return values[index.column()]
        if role == Qt.ItemDataRole.ToolTipRole:
            return row.rule.rule if index.column() == 0 else values[index.column()]
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def set_rows(self, rows: Sequence[RichRuleRow]) -> None:
        values = tuple(rows)
        if any(not isinstance(row, RichRuleRow) for row in values):
            raise TypeError("rows must contain only RichRuleRow values")
        self.beginResetModel()
        self._rows = values
        self.endResetModel()

    def rows(self) -> tuple[RichRuleRow, ...]:
        return self._rows

    def row_at(self, row: int) -> RichRuleRow | None:
        if not isinstance(row, int) or not 0 <= row < len(self._rows):
            return None
        return self._rows[row]


__all__ = ["RichRuleRow", "RichRulesTableModel", "merge_rich_rule_rows"]
