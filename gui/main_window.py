import datetime
import os
from typing import Optional, Dict

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QToolBar, QPushButton,
    QLabel, QStatusBar, QMessageBox, QMenuBar, QMenu,
    QDialog, QProgressBar,
)
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal
from PyQt6.QtGui import QFont, QAction, QColor

from core.base_connector import BaseConnector, DeviceNode
from core.connector_factory import create_connector
from core.log_collector import LogCollector
from core.ssh_connector import SSHConnector
from gui.connection_dialog import ConnectionDialog
from gui.device_tree import DeviceTreeWidget
from gui.properties_panel import PropertiesPanel
from gui.log_viewer import LogViewerWidget
from gui.terminal_widget import TerminalWidget
from gui.reverse_shell_tab import ReverseShellTab
from gui.exploit_launcher_tab import ExploitLauncherTab
from gui.analysis_tab import AnalysisTab
from gui.redteam_tab import RedTeamTab
from gui.reference_tab import ReferenceTab
from config.settings import APP_NAME, APP_VERSION

# Number of permanent (non-closable) tabs prepended to the tab bar
_PERMANENT_TABS = 5

DARK_STYLE = (
    "QMainWindow,QWidget{background:#0d1117;color:#e6edf3;}"
    "QTabWidget::pane{border:1px solid #30363d;background:#0d1117;}"
    "QTabBar::tab{background:#161b22;color:#8b949e;padding:6px 14px;border:1px solid #30363d;}"
    "QTabBar::tab:selected{background:#1f6feb;color:#fff;}"
    "QToolBar{background:#161b22;border-bottom:1px solid #30363d;spacing:4px;padding:4px;}"
    "QPushButton{background:#21262d;color:#e6edf3;border:1px solid #30363d;padding:4px 12px;border-radius:4px;}"
    "QPushButton:hover{background:#30363d;}"
    "QStatusBar{background:#161b22;color:#8b949e;}"
    "QMenuBar{background:#161b22;color:#e6edf3;}"
    "QMenuBar::item:selected{background:#1f6feb;}"
    "QMenu{background:#161b22;color:#e6edf3;border:1px solid #30363d;}"
    "QMenu::item:selected{background:#1f6feb;}"
    "QSplitter::handle{background:#30363d;}"
    "QProgressBar{border:1px solid #30363d;background:#161b22;color:#e6edf3;text-align:center;}"
    "QProgressBar::chunk{background:#1f6feb;}"
    "QScrollBar:vertical{background:#161b22;width:10px;}"
    "QScrollBar::handle:vertical{background:#30363d;border-radius:4px;}"
)


class WorkerSignals(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)


class ConnectionWorker(QThread):
    def __init__(self, connector):
        super().__init__()
        self.connector = connector
        self.signals = WorkerSignals()

    def run(self):
        try:
            self.connector.connect()
            devices = self.connector.get_devices()
            self.signals.finished.emit(devices)
        except Exception as exc:
            self.signals.error.emit(str(exc))


class LogWorker(QThread):
    def __init__(self, collector, os_type):
        super().__init__()
        self.collector = collector
        self.os_type = os_type
        self.signals = WorkerSignals()

    def run(self):
        try:
            results = self.collector.collect_all(self.os_type)
            all_entries = [e for entries in results.values() for e in entries]
            self.signals.finished.emit(all_entries)
        except Exception as exc:
            self.signals.error.emit(str(exc))


class SessionTab(QWidget):
    def __init__(self, connector, os_type, parent=None):
        super().__init__(parent)
        self.connector = connector
        self.os_type = os_type
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        lbl = QLabel("Devices")
        lbl.setStyleSheet("color:#8b949e;font-size:11px;padding:4px;")
        ll.addWidget(lbl)
        self.device_tree = DeviceTreeWidget()
        ll.addWidget(self.device_tree)
        splitter.addWidget(left)

        self._right_tabs = QTabWidget()
        self.properties = PropertiesPanel()
        self._right_tabs.addTab(self.properties, "Properties")
        self.log_viewer = LogViewerWidget()
        self._right_tabs.addTab(self.log_viewer, "Logs")
        self._term_placeholder = QLabel("Open terminal via Tools menu")
        self._term_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._term_placeholder.setStyleSheet("color:#8b949e;")
        self._right_tabs.addTab(self._term_placeholder, "Terminal")
        splitter.addWidget(self._right_tabs)
        splitter.setSizes([300, 700])
        layout.addWidget(splitter)

        self.device_tree.device_selected.connect(self.properties.display)
        self.device_tree.enable_requested.connect(self._enable_device)
        self.device_tree.disable_requested.connect(self._disable_device)

    def _enable_device(self, node):
        ok = self.connector.enable_device(node)
        QMessageBox.information(self, "Device", f"{'Enabled' if ok else 'Failed to enable'}: {node.name}")

    def _disable_device(self, node):
        ok = self.connector.disable_device(node)
        QMessageBox.information(self, "Device", f"{'Disabled' if ok else 'Failed to disable'}: {node.name}")

    def open_terminal(self):
        if not isinstance(self.connector, SSHConnector):
            QMessageBox.warning(self, "Terminal", "Interactive terminal requires SSH.")
            return
        try:
            channel = self.connector.open_interactive_shell()
            term = TerminalWidget(channel, self)
            idx = self._right_tabs.indexOf(self._term_placeholder)
            if idx >= 0:
                self._right_tabs.removeTab(idx)
            self._right_tabs.addTab(term, "Terminal")
            self._right_tabs.setCurrentWidget(term)
        except Exception as exc:
            QMessageBox.critical(self, "Terminal Error", str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(1280, 800)
        self.setStyleSheet(DARK_STYLE)
        self._sessions: Dict[QWidget, tuple] = {}
        self._workers: list = []
        self._build_ui()

    def _build_ui(self):
        self._build_menubar()
        self._build_toolbar()

        self._tabs = QTabWidget()
        self._tabs.setTabsClosable(True)
        self._tabs.tabCloseRequested.connect(self._close_tab)

        # ── Permanent tabs (indices 0-4, never closable) ───────────────────
        self._reverse_shell_tab = ReverseShellTab()
        self._exploit_tab       = ExploitLauncherTab()
        self._redteam_tab       = RedTeamTab()
        self._analysis_tab      = AnalysisTab()
        self._reference_tab     = ReferenceTab()

        for widget, label in [
            (self._reverse_shell_tab, "Reverse Shells"),
            (self._exploit_tab,       "Exploit Launcher"),
            (self._redteam_tab,       "Red Team"),
            (self._analysis_tab,      "Analysis"),
            (self._reference_tab,     "Reference"),
        ]:
            idx = self._tabs.addTab(widget, label)
            self._tabs.tabBar().setTabButton(
                idx, self._tabs.tabBar().ButtonPosition.RightSide, None
            )

        # ── Welcome tab for new sessions ──────────────────────────────────
        welcome = QLabel(f"{APP_NAME}  |  Authorized Red Team & Forensics Platform\n\nSession > New Connection to start")
        welcome.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome.setFont(QFont("Monospace", 13))
        welcome.setStyleSheet("color:#8b949e;")
        self._tabs.addTab(welcome, "Welcome")
        self._tabs.tabBar().setTabButton(
            _PERMANENT_TABS, self._tabs.tabBar().ButtonPosition.RightSide, None
        )
        # Tab color hints for permanent tabs
        _tab_colors = ["#6e40c9", "#da3633", "#2ea043", "#d29922", "#58a6ff"]
        for i, color in enumerate(_tab_colors):
            self._tabs.tabBar().setTabTextColor(i, QColor(color))
        self.setCentralWidget(self._tabs)

        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._progress = QProgressBar()
        self._progress.setMaximumWidth(200)
        self._progress.setVisible(False)
        self._status.addPermanentWidget(self._progress)
        self._status.showMessage("Ready")

    def _build_menubar(self):
        mb = self.menuBar()
        s = mb.addMenu("Session")
        for label, shortcut, slot in [
            ("New Connection", "Ctrl+N", self._new_connection),
            ("Quit", "Ctrl+Q", self.close),
        ]:
            act = QAction(label, self)
            act.setShortcut(shortcut)
            act.triggered.connect(slot)
            s.addAction(act)

        t = mb.addMenu("Tools")
        for label, shortcut, slot in [
            ("Refresh Devices",    "F5",     self._refresh_devices),
            ("Collect All Logs",   "Ctrl+L", self._collect_logs),
            ("Open Terminal",      "Ctrl+T", self._open_terminal),
            ("Reverse Shells",     "Ctrl+R", lambda: self._tabs.setCurrentIndex(0)),
            ("Exploit Launcher",   "Ctrl+E", lambda: self._tabs.setCurrentIndex(1)),
            ("Red Team Ops",       "Ctrl+G", lambda: self._tabs.setCurrentIndex(2)),
            ("Deep Analysis",      "Ctrl+A", self._open_analysis),
            ("Reference",          "Ctrl+H", lambda: self._tabs.setCurrentIndex(4)),
        ]:
            act = QAction(label, self)
            act.setShortcut(shortcut)
            act.triggered.connect(slot)
            t.addAction(act)

        e = mb.addMenu("Export")
        for label, slot in [
            ("Export Logs as PDF",  self._export_pdf),
            ("Export Logs as JSON", self._export_json),
            ("Export Analysis JSON", self._export_analysis),
        ]:
            act = QAction(label, self)
            act.triggered.connect(slot)
            e.addAction(act)

    def _build_toolbar(self):
        tb = QToolBar()
        tb.setMovable(False)
        self.addToolBar(tb)
        btn_specs = [
            ("New Connection", "#238636", self._new_connection),
            ("Refresh",        "#21262d", self._refresh_devices),
            ("Collect Logs",   "#1f6feb", self._collect_logs),
            ("Terminal",       "#21262d", self._open_terminal),
            ("Reverse Shells", "#6e40c9", lambda: self._tabs.setCurrentIndex(0)),
            ("Exploits",       "#b62324", lambda: self._tabs.setCurrentIndex(1)),
            ("Red Team",       "#2ea043", lambda: self._tabs.setCurrentIndex(2)),
            ("Analysis",       "#d29922", self._open_analysis),
            ("Reference",      "#58a6ff", lambda: self._tabs.setCurrentIndex(4)),
        ]
        for label, bg, slot in btn_specs:
            btn = QPushButton(label)
            btn.setStyleSheet(f"background:{bg};color:#fff;font-weight:bold;padding:4px 14px;")
            btn.clicked.connect(slot)
            tb.addWidget(btn)
        tb.addSeparator()
        self._host_label = QLabel("  No active session")
        self._host_label.setStyleSheet("color:#8b949e;")
        tb.addWidget(self._host_label)

    def _new_connection(self):
        dlg = ConnectionDialog(self)
        dlg.setStyleSheet(DARK_STYLE)
        if dlg.exec() != QDialog.DialogCode.Accepted or not dlg.profile:
            return
        profile = dlg.profile
        os_hint = dlg.os_hint
        connector = create_connector(profile)
        label = f"{profile.protocol.upper()}:{profile.host}"
        tab = SessionTab(connector, os_hint, self)
        idx = self._tabs.addTab(tab, label)
        self._tabs.setCurrentIndex(idx)
        self._sessions[tab] = (connector, os_hint)
        self._status.showMessage(f"Connecting to {profile.host}...")
        self._progress.setVisible(True)
        self._progress.setRange(0, 0)
        worker = ConnectionWorker(connector)
        worker.signals.finished.connect(lambda devices, i=idx: self._on_devices_loaded(i, devices))
        worker.signals.error.connect(self._on_error)
        worker.finished.connect(lambda w=worker: self._reap_worker(w))
        self._workers.append(worker)
        worker.start()

    def _on_devices_loaded(self, idx, devices):
        self._progress.setVisible(False)
        tab = self._tabs.widget(idx)
        if isinstance(tab, SessionTab):
            tab.device_tree.populate(devices)
            host = tab.connector.profile.host
            self._host_label.setText(f"  {host}")
            self._status.showMessage(f"Connected — {len(devices)} devices")

    def _on_error(self, err):
        self._progress.setVisible(False)
        self._status.showMessage(f"Error: {err}")
        QMessageBox.critical(self, "Error", err)

    def _current_tab(self) -> Optional["SessionTab"]:
        w = self._tabs.currentWidget()
        return w if isinstance(w, SessionTab) else None

    def _refresh_devices(self):
        tab = self._current_tab()
        if not tab:
            return
        self._progress.setVisible(True)
        self._progress.setRange(0, 0)
        idx = self._tabs.currentIndex()
        worker = ConnectionWorker(tab.connector)
        worker.signals.finished.connect(lambda d, i=idx: self._on_devices_loaded(i, d))
        worker.signals.error.connect(self._on_error)
        worker.finished.connect(lambda w=worker: self._reap_worker(w))
        self._workers.append(worker)
        worker.start()

    def _collect_logs(self):
        tab = self._current_tab()
        if not tab:
            QMessageBox.information(self, "Info", "No active session.")
            return
        collector = LogCollector(tab.connector)
        self._progress.setVisible(True)
        self._progress.setRange(0, 0)
        self._status.showMessage("Collecting all logs...")
        worker = LogWorker(collector, tab.os_type)
        worker.signals.finished.connect(lambda entries: self._on_logs(tab, entries, collector))
        worker.signals.error.connect(self._on_error)
        worker.finished.connect(lambda w=worker: self._reap_worker(w))
        self._workers.append(worker)
        worker.start()

    def _on_logs(self, tab, entries, collector):
        self._progress.setVisible(False)
        tab.log_viewer.load_entries(entries)
        # Feed collected entries into the Analysis tab so they're ready to scan
        self._analysis_tab.load_entries(entries)
        self._status.showMessage(
            f"{len(entries)} log entries — saved to {collector.session_dir} — "
            "switch to Analysis tab to run deep scan"
        )

    def _open_terminal(self):
        tab = self._current_tab()
        if tab:
            tab.open_terminal()

    def _export_pdf(self):
        tab = self._current_tab()
        if not tab or not tab.log_viewer._all_entries:
            QMessageBox.information(self, "Export", "No logs loaded.")
            return
        from reports.pdf_report import export_logs_pdf
        path = export_logs_pdf(tab.log_viewer._all_entries, tab.connector.profile.host)
        QMessageBox.information(self, "Export", f"PDF saved:\n{path}")

    def _export_json(self):
        tab = self._current_tab()
        if not tab or not tab.log_viewer._all_entries:
            QMessageBox.information(self, "Export", "No logs loaded.")
            return
        collector = LogCollector(tab.connector)
        path = collector.export_json(tab.log_viewer._all_entries, tab.connector.profile.host)
        QMessageBox.information(self, "Export", f"JSON saved:\n{path}")

    def _open_analysis(self):
        """Switch to the Analysis tab (index 3). Logs are auto-fed from _on_logs."""
        self._tabs.setCurrentIndex(3)

    def _export_analysis(self):
        self._analysis_tab._export()

    def _reap_worker(self, worker: QThread) -> None:
        try:
            self._workers.remove(worker)
        except ValueError:
            pass

    def _close_tab(self, idx):
        # Protect permanent tabs (0–3) and welcome tab (4)
        if idx <= _PERMANENT_TABS:
            return
        tab_widget = self._tabs.widget(idx)
        connector, _ = self._sessions.pop(tab_widget, (None, None))
        if connector:
            try:
                connector.disconnect()
            except Exception:
                pass
        self._tabs.removeTab(idx)
        if self._tabs.count() <= _PERMANENT_TABS + 1:
            self._host_label.setText("  No active session")

    def closeEvent(self, event):
        for connector, _ in list(self._sessions.values()):
            try:
                connector.disconnect()
            except Exception:
                pass
        for w in list(self._workers):
            w.quit()
            w.wait(2000)
        super().closeEvent(event)
