from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QLabel, QHeaderView,
)
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt

from core.base_connector import DeviceNode
from core.validators import SecureInputValidator


class PropertiesPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._title = QLabel("Select a device to view properties")
        self._title.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self._title.setStyleSheet("color:#58a6ff; padding:6px;")
        layout.addWidget(self._title)

        self._table = QTableWidget(0, 2)
        self._table.setHorizontalHeaderLabels(["Property", "Value"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.setFont(QFont("Monospace", 9))
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(
            "QTableWidget {background:#0d1117; color:#e6edf3; border:1px solid #30363d;"
            "alternate-background-color:#161b22;}"
            "QHeaderView::section {background:#161b22; color:#8b949e; border:none; padding:4px; font-weight:bold;}"
        )
        layout.addWidget(self._table)

    def display(self, node: DeviceNode):
        self._title.setText(SecureInputValidator.sanitize_for_display(node.name))
        self._table.setRowCount(0)

        rows = [
            ("Name", node.name),
            ("Type", node.device_type),
            ("Status", node.status),
            ("Path", node.raw_path),
        ]
        for k, v in node.properties.items():
            rows.append((k, str(v)[:512]))

        for prop, val in rows:
            row = self._table.rowCount()
            self._table.insertRow(row)
            key_item = QTableWidgetItem(str(prop))
            key_item.setForeground(QColor("#8b949e"))
            val_item = QTableWidgetItem(SecureInputValidator.sanitize_for_display(str(val)))
            self._table.setItem(row, 0, key_item)
            self._table.setItem(row, 1, val_item)

    def clear(self):
        self._table.setRowCount(0)
        self._title.setText("Select a device to view properties")
