"""Deep Log Analysis GUI tab."""
from typing import List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QPushButton,
    QLabel, QComboBox, QTextEdit, QHeaderView,
    QProgressBar, QMessageBox,
)
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QBrush

from core.base_connector import LogEntry
from core.log_analyzer import DeepLogAnalyzer, Finding
from core.audit import audit

SEV_COLORS = {
    "Critical": "#da3633",
    "High":     "#f85149",
    "Medium":   "#d29922",
    "Low":      "#58a6ff",
    "Info":     "#8b949e",
}


class AnalysisWorker(QThread):
    finished = pyqtSignal(list)
    error    = pyqtSignal(str)

    def __init__(self, entries: List[LogEntry], os_type: str):
        super().__init__()
        self._entries = entries
        self._os_type = os_type

    def run(self):
        try:
            analyzer = DeepLogAnalyzer(self._os_type)
            findings = analyzer.analyze(self._entries)
            self.finished.emit(findings)
        except Exception as exc:
            self.error.emit(str(exc))


class AnalysisTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._entries: List[LogEntry] = []
        self._findings: List[Finding] = []
        self._worker = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        # Toolbar
        toolbar = QHBoxLayout()
        self._os_combo = QComboBox()
        self._os_combo.addItems(["Linux", "Windows"])
        self._os_combo.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:4px;")
        toolbar.addWidget(QLabel("Target OS:"))
        toolbar.addWidget(self._os_combo)

        self._analyze_btn = QPushButton("Run Deep Analysis")
        self._analyze_btn.setStyleSheet("background:#da3633;color:#fff;font-weight:bold;padding:6px 18px;")
        self._analyze_btn.clicked.connect(self._run_analysis)
        toolbar.addWidget(self._analyze_btn)

        self._export_btn = QPushButton("Export JSON")
        self._export_btn.setStyleSheet("background:#238636;color:#fff;padding:6px 14px;")
        self._export_btn.clicked.connect(self._export)
        self._export_btn.setEnabled(False)
        toolbar.addWidget(self._export_btn)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setMaximumWidth(160)
        self._progress.setVisible(False)
        toolbar.addWidget(self._progress)

        self._summary_label = QLabel("Load logs first, then run analysis")
        self._summary_label.setStyleSheet("color:#8b949e;")
        toolbar.addStretch()
        toolbar.addWidget(self._summary_label)
        layout.addLayout(toolbar)

        # Splitter: findings table | evidence panel
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Findings table
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Severity", "ATT&CK", "Title", "Count", "Source"])
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setFont(QFont("Monospace", 9))
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(
            "QTableWidget{background:#0d1117;color:#e6edf3;border:1px solid #30363d;"
            "alternate-background-color:#161b22;gridline-color:#21262d;}"
            "QHeaderView::section{background:#161b22;color:#8b949e;border:none;padding:4px;font-weight:bold;}"
            "QTableWidget::item:selected{background:#1f6feb;}"
        )
        self._table.itemSelectionChanged.connect(self._on_select)
        splitter.addWidget(self._table)

        # Evidence + recommendation panel
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(4, 0, 0, 0)
        rl.addWidget(QLabel("Evidence & Recommendation"))
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setFont(QFont("Monospace", 9))
        self._detail.setStyleSheet(
            "background:#0d1117;color:#e6edf3;border:1px solid #30363d;"
        )
        rl.addWidget(self._detail)
        splitter.addWidget(right)
        splitter.setSizes([700, 400])
        layout.addWidget(splitter)

    def load_entries(self, entries: List[LogEntry]):
        self._entries = entries
        count = len(entries)
        self._summary_label.setText(f"{count:,} entries loaded — ready for analysis")

    def _run_analysis(self):
        if not self._entries:
            QMessageBox.information(self, "Analysis", "No log entries loaded.\nCollect logs first from a session.")
            return
        self._analyze_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._table.setRowCount(0)
        self._detail.clear()
        os_type = self._os_combo.currentText().lower()
        audit("ANALYSIS_START", detail=f"entries={len(self._entries)} os={os_type}")
        self._worker = AnalysisWorker(self._entries, os_type)
        self._worker.finished.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_done(self, findings: List[Finding]):
        self._findings = findings
        self._progress.setVisible(False)
        self._analyze_btn.setEnabled(True)
        self._export_btn.setEnabled(bool(findings))

        crit = sum(1 for f in findings if f.severity == "Critical")
        high = sum(1 for f in findings if f.severity == "High")
        self._summary_label.setText(
            f"{len(findings)} findings — "
            f"Critical: {crit}  High: {high}"
        )
        self._summary_label.setStyleSheet(
            f"color:{'#da3633' if crit > 0 else '#d29922' if high > 0 else '#2ea043'};"
            "font-weight:bold;"
        )

        self._table.setRowCount(0)
        for f in findings:
            row = self._table.rowCount()
            self._table.insertRow(row)
            sev_item = QTableWidgetItem(f.severity)
            sev_item.setForeground(QBrush(QColor(SEV_COLORS.get(f.severity, "#8b949e"))))
            sev_item.setFont(QFont("Monospace", 9, QFont.Weight.Bold))
            self._table.setItem(row, 0, sev_item)
            self._table.setItem(row, 1, QTableWidgetItem(f.technique))
            self._table.setItem(row, 2, QTableWidgetItem(f.title))
            cnt_item = QTableWidgetItem(str(f.count))
            cnt_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 3, cnt_item)
            self._table.setItem(row, 4, QTableWidgetItem(f.source[:40]))

        audit("ANALYSIS_DONE", detail=f"findings={len(findings)} critical={crit}")

    def _on_error(self, err: str):
        self._progress.setVisible(False)
        self._analyze_btn.setEnabled(True)
        QMessageBox.critical(self, "Analysis Error", err)

    def _on_select(self):
        rows = self._table.selectedItems()
        if not rows:
            return
        row = self._table.currentRow()
        if row >= len(self._findings):
            return
        f = self._findings[row]
        text = (
            f"TITLE:      {f.title}\n"
            f"TECHNIQUE:  {f.technique}\n"
            f"SEVERITY:   {f.severity}\n"
            f"COUNT:      {f.count}\n"
            f"FIRST SEEN: {f.first_seen}\n"
            f"LAST SEEN:  {f.last_seen}\n"
            f"SOURCE:     {f.source}\n\n"
            f"EVIDENCE ({len(f.evidence)} samples):\n"
            + "\n".join(f"  {i+1}. {e}" for i, e in enumerate(f.evidence))
            + f"\n\nRECOMMENDATION:\n  {f.recommendation}"
        )
        self._detail.setPlainText(text)

    def _export(self):
        if not self._findings:
            return
        from core.log_analyzer import DeepLogAnalyzer
        analyzer = DeepLogAnalyzer(self._os_combo.currentText().lower())
        path = analyzer.export_json(self._findings)
        QMessageBox.information(self, "Export", f"Analysis saved to:\n{path}")
