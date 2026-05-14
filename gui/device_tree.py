from typing import List, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem,
    QHeaderView, QMenu, QAbstractItemView,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QBrush, QAction

from core.base_connector import DeviceNode


STATUS_COLORS = {
    "ok": "#2ea043",
    "present": "#2ea043",
    "OK": "#2ea043",
    "error": "#da3633",
    "Error": "#da3633",
    "disabled": "#848d97",
    "Disabled": "#848d97",
    "unknown": "#d29922",
    "Unknown": "#d29922",
}


class DeviceTreeWidget(QWidget):
    device_selected = pyqtSignal(object)
    enable_requested = pyqtSignal(object)
    disable_requested = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Device", "Type", "Status"])
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._tree.setFont(QFont("Monospace", 9))
        self._tree.setAlternatingRowColors(True)
        self._tree.setStyleSheet(
            "QTreeWidget {"
            "background: #0d1117; color: #e6edf3; border: 1px solid #30363d;"
            "alternate-background-color: #161b22;}"
            "QTreeWidget::item:selected {background: #1f6feb;}"
            "QHeaderView::section {background: #161b22; color: #8b949e;"
            "border: none; padding: 4px; font-weight: bold;}"
        )
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._tree.itemSelectionChanged.connect(self._on_selection_changed)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)

        layout.addWidget(self._tree)
        self._node_map: dict[QTreeWidgetItem, DeviceNode] = {}

    def populate(self, devices: List[DeviceNode]):
        self._tree.clear()
        self._node_map.clear()

        categories: dict[str, QTreeWidgetItem] = {}
        for device in devices:
            cat = device.device_type or "Other"
            if cat not in categories:
                cat_item = QTreeWidgetItem([cat, "", ""])
                cat_item.setFont(0, QFont("Monospace", 9, QFont.Weight.Bold))
                cat_item.setForeground(0, QBrush(QColor("#58a6ff")))
                self._tree.addTopLevelItem(cat_item)
                categories[cat] = cat_item

            item = QTreeWidgetItem([device.name, device.device_type, device.status])
            color = STATUS_COLORS.get(device.status, "#8b949e")
            item.setForeground(2, QBrush(QColor(color)))
            categories[cat].addChild(item)
            self._node_map[item] = device

        self._tree.expandAll()

    def _on_selection_changed(self):
        items = self._tree.selectedItems()
        if items and items[0] in self._node_map:
            self.device_selected.emit(self._node_map[items[0]])

    def _show_context_menu(self, pos):
        item = self._tree.itemAt(pos)
        if not item or item not in self._node_map:
            return
        node = self._node_map[item]
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu {background:#161b22; color:#e6edf3; border:1px solid #30363d;}"
            "QMenu::item:selected {background:#1f6feb;}"
        )
        enable_act = QAction("Enable Device", self)
        enable_act.triggered.connect(lambda: self.enable_requested.emit(node))
        disable_act = QAction("Disable Device", self)
        disable_act.triggered.connect(lambda: self.disable_requested.emit(node))
        menu.addAction(enable_act)
        menu.addAction(disable_act)
        menu.exec(self._tree.viewport().mapToGlobal(pos))

    def get_selected_node(self) -> Optional[DeviceNode]:
        items = self._tree.selectedItems()
        if items and items[0] in self._node_map:
            return self._node_map[items[0]]
        return None
