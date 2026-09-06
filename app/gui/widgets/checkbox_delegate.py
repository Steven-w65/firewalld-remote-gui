"""Shared read-only checkbox presentation for firewall status tables."""

from __future__ import annotations

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import (
    QApplication,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
)


class CenteredCheckBoxDelegate(QStyledItemDelegate):
    """Paint one native checkbox in the center of an item-view cell."""

    def paint(self, painter: QPainter, option, index) -> None:
        view_option = QStyleOptionViewItem(option)
        self.initStyleOption(view_option, index)
        widget = option.widget
        style = widget.style() if widget is not None else QApplication.style()

        background_option = QStyleOptionViewItem(view_option)
        background_option.features &= ~QStyleOptionViewItem.ViewItemFeature.HasCheckIndicator
        background_option.text = ""
        style.drawControl(
            QStyle.ControlElement.CE_ItemViewItem,
            background_option,
            painter,
            widget,
        )

        indicator = style.subElementRect(
            QStyle.SubElement.SE_ItemViewItemCheckIndicator,
            view_option,
            widget,
        )
        centered = QRect(0, 0, indicator.width(), indicator.height())
        centered.moveCenter(option.rect.center())
        checkbox_option = QStyleOptionViewItem(view_option)
        checkbox_option.rect = centered
        checkbox_option.state |= (
            QStyle.StateFlag.State_On
            if view_option.checkState == Qt.CheckState.Checked
            else QStyle.StateFlag.State_Off
        )
        style.drawPrimitive(
            QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck,
            checkbox_option,
            painter,
            widget,
        )


__all__ = ["CenteredCheckBoxDelegate"]
