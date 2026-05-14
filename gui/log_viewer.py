from typing import List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLineEdit, QLabel, QComboBox, QHeaderView,
)
from PyQt6.QtCore import Qt, QSortFilterProxyModel
from PyQt6.QtGui import QFont, QColor

from core.base_connector import LogEntry


LEVEL_COLORS = {
    "Critical": "#da3633",
    "Error": "#f85149",
    "Warning": "#d29922",
    "Information": "#58a6ff",
    "Verbose": "#8b949e",
    "INFO": "#58a6ff",
    "WARN": "#d29922",
    "ERROR": "#f85149",
}


class LogViewerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_entries: List[LogEntry] = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        # Toolbar
        toolbar = QHBoxLayout()
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter logs...")
        self._search.setStyleSheet("background:#161b22; color:#e6edf3; border:1px solid #30363d; padding:4px;")
        self._search.textChanged.connect(self._apply_filter)
        toolbar.addWidget(QLabel("Filter:"))
        toolbar.addWidget(self._search)

        self._level_filter = QComboBox()
        self._level_filter.addItems(["All Levels", "Critical", "Error", "Warning", "Information", "INFO", "WARN"])
        self._level_filter.currentTextChanged.connect(self._apply_filter)
        self._level_filter.setStyleSheet("background:#161b22; color:#e6edf3; border:1px solid #30363d;")
        toolbar.addWidget(QLabel("Level:"))
        toolbar.addWidget(self._level_filter)

        self._count_label = QLabel("0 entries")
        self._count_label.setStyleSheet("color:#8b949e;")
        toolbar.addWidget(self._count_label)
        layout.addLayout(toolbar)

        # Table
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Timestamp", "Source", "Level", "Message"])
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setFont(QFont("Monospace", 9))
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(
            "QTableWidget {background:#0d1117; color:#e6edf3; border:1px solid #30363d;"
            "alternate-background-color:#161b22; gridline-color:#21262d;}"
            "QHeaderView::section {background:#161b22; color:#8b949e; border:none; padding:4px; font-weight:bold;}"
            "QTableWidget::item:selected {background:#1f6feb;}"
        )
        layout.addWidget(self._table)

    def load_entries(self, entries: List[LogEntry]):
        self._all_entries = entries
        self._apply_filter()

    def _apply_filter(self):
        search = self._search.text().lower()
        level = self._level_filter.currentText()
        filtered = [
            e for e in self._all_entries
            if (not search or search in e.message.lower() or search in e.source.lower())
            and (level == "All Levels" or e.level == level)
        ]
        self._table.setRowCount(0)
        for entry in filtered[:5000]:
            row = self._table.rowCount()
            self._table.insertRow(row)
            for col, text in enumerate([entry.timestamp, entry.source, entry.level, entry.message]):
                item = QTableWidgetItem(str(text)[:256])
                if col == 2:
                    color = LEVEL_COLORS.get(entry.level, "#8b949e")
                    item.setForeground(QColor(color))
                self._table.setItem(row, col, item)
        self._count_label.setText(f"{len(filtered)} entries")
