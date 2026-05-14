"""Reverse Shell Manager GUI tab."""
from __future__ import annotations

import threading
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QLineEdit, QComboBox, QSpinBox, QTextEdit, QGroupBox,
    QHeaderView, QMessageBox, QTabWidget, QPlainTextEdit,
    QCheckBox,
)
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QBrush, QTextCursor

from core.reverse_shell import (
    ReverseShellManager, PayloadGenerator, MsfvenomWrapper,
    Session, Listener, PROTO_TCP, PROTO_SSL, PROTO_HTTP, SUPPORTED_PROTOCOLS,
)
from core.validators import SecureInputValidator
from core.audit import audit
from core.evasion import (
    EvasionConfig, apply_evasion_to_payload, DetectionTimer, DetectionEvent,
)
import socket


SESSION_STATUS_COLORS = {
    "active":     "#2ea043",
    "closed":     "#da3633",
    "connecting": "#d29922",
}


class SessionTerminal(QWidget):
    """Embedded terminal for a reverse shell session."""

    def __init__(self, session: Session, parent=None):
        super().__init__(parent)
        self._session = session
        self._build_ui()
        session.attach_output(self._on_output)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)

        info = QLabel(
            f"Session: {self._session.session_id[:8]}  |  "
            f"Peer: {self._session.peer_addr[0]}:{self._session.peer_addr[1]}  |  "
            f"Protocol: {self._session.protocol.upper()}"
        )
        info.setStyleSheet("color:#58a6ff;font-weight:bold;padding:4px;")
        layout.addWidget(info)

        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont("Monospace", 10))
        self._output.setMaximumBlockCount(8000)
        self._output.setStyleSheet(
            "background:#0d1117;color:#39ff14;border:1px solid #30363d;"
        )
        layout.addWidget(self._output)

        row = QHBoxLayout()
        self._input = QLineEdit()
        self._input.setPlaceholderText("Command...")
        self._input.setFont(QFont("Monospace", 10))
        self._input.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:4px;")
        self._input.returnPressed.connect(self._send)

        send_btn = QPushButton("Send")
        send_btn.setStyleSheet("background:#238636;color:#fff;padding:4px 12px;")
        send_btn.clicked.connect(self._send)

        ctrlc_btn = QPushButton("Ctrl+C")
        ctrlc_btn.setStyleSheet("background:#da3633;color:#fff;padding:4px 8px;")
        ctrlc_btn.clicked.connect(lambda: self._session.send("\x03"))

        kill_btn = QPushButton("Kill Session")
        kill_btn.setStyleSheet("background:#6e40c9;color:#fff;padding:4px 10px;")
        kill_btn.clicked.connect(self._kill)

        row.addWidget(self._input)
        row.addWidget(send_btn)
        row.addWidget(ctrlc_btn)
        row.addWidget(kill_btn)
        layout.addLayout(row)

    def _on_output(self, text: str):
        cursor = self._output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        self._output.setTextCursor(cursor)
        self._output.ensureCursorVisible()

    def _send(self):
        cmd = self._input.text()
        self._input.clear()
        self._session.send(cmd + "\n")

    def _kill(self):
        self._session.close()


class ReverseShellTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._manager = ReverseShellManager()
        self._session_tabs: Dict[str, SessionTerminal] = {}
        self._detection_timer = DetectionTimer()
        self._manager.set_callbacks(
            on_session_started=self._on_session_open,
            on_session_ended=self._on_session_close,
        )
        self._build_ui()

        # Refresh table every 2 seconds
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_tables)
        self._timer.start(2000)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # ── Top: Listener + Sessions ──
        top = QWidget()
        top_layout = QHBoxLayout(top)

        # Listener panel
        listener_box = QGroupBox("Listeners")
        listener_box.setStyleSheet("QGroupBox{color:#58a6ff;border:1px solid #30363d;padding:8px;margin-top:8px;}"
                                   "QGroupBox::title{subcontrol-origin:margin;left:8px;}")
        lb_layout = QVBoxLayout(listener_box)

        cfg_row = QHBoxLayout()
        self._lhost = QLineEdit()
        self._lhost.setPlaceholderText("LHOST (0.0.0.0)")
        self._lhost.setText("0.0.0.0")
        self._lhost.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:4px;")
        self._lport = QSpinBox()
        self._lport.setRange(1, 65535)
        self._lport.setValue(4444)
        self._lport.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;")
        self._proto = QComboBox()
        self._proto.addItems([p.upper() for p in SUPPORTED_PROTOCOLS])
        self._proto.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;")
        start_btn = QPushButton("Start Listener")
        start_btn.setStyleSheet("background:#238636;color:#fff;font-weight:bold;padding:4px 12px;")
        start_btn.clicked.connect(self._start_listener)
        stop_btn = QPushButton("Stop Selected")
        stop_btn.setStyleSheet("background:#da3633;color:#fff;padding:4px 10px;")
        stop_btn.clicked.connect(self._stop_listener)

        cfg_row.addWidget(QLabel("LHOST:"))
        cfg_row.addWidget(self._lhost)
        cfg_row.addWidget(QLabel("Port:"))
        cfg_row.addWidget(self._lport)
        cfg_row.addWidget(QLabel("Proto:"))
        cfg_row.addWidget(self._proto)
        cfg_row.addWidget(start_btn)
        cfg_row.addWidget(stop_btn)
        lb_layout.addLayout(cfg_row)

        self._listener_table = QTableWidget(0, 4)
        self._listener_table.setHorizontalHeaderLabels(["ID", "Protocol", "LHOST:LPORT", "Status"])
        self._listener_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._listener_table.setFont(QFont("Monospace", 9))
        self._listener_table.setMaximumHeight(120)
        self._listener_table.setStyleSheet(
            "QTableWidget{background:#0d1117;color:#e6edf3;border:1px solid #30363d;}"
            "QHeaderView::section{background:#161b22;color:#8b949e;border:none;padding:3px;}"
        )
        lb_layout.addWidget(self._listener_table)
        top_layout.addWidget(listener_box, 2)

        # Sessions panel
        sessions_box = QGroupBox("Active Sessions")
        sessions_box.setStyleSheet("QGroupBox{color:#39ff14;border:1px solid #30363d;padding:8px;margin-top:8px;}"
                                   "QGroupBox::title{subcontrol-origin:margin;left:8px;}")
        sb_layout = QVBoxLayout(sessions_box)
        self._session_table = QTableWidget(0, 5)
        self._session_table.setHorizontalHeaderLabels(["ID", "Peer IP", "Port", "Protocol", "Status"])
        self._session_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._session_table.setFont(QFont("Monospace", 9))
        self._session_table.setStyleSheet(
            "QTableWidget{background:#0d1117;color:#e6edf3;border:1px solid #30363d;}"
            "QHeaderView::section{background:#161b22;color:#8b949e;border:none;padding:3px;}"
            "QTableWidget::item:selected{background:#1f6feb;}"
        )
        self._session_table.doubleClicked.connect(self._open_session_terminal)
        open_btn = QPushButton("Open Terminal")
        open_btn.setStyleSheet("background:#1f6feb;color:#fff;padding:4px 12px;")
        open_btn.clicked.connect(self._open_session_terminal)
        sb_layout.addWidget(self._session_table)
        sb_layout.addWidget(open_btn)
        top_layout.addWidget(sessions_box, 3)
        splitter.addWidget(top)

        # ── Bottom: session terminals + payload generator ──
        bottom_tabs = QTabWidget()
        bottom_tabs.setStyleSheet(
            "QTabWidget::pane{border:1px solid #30363d;background:#0d1117;}"
            "QTabBar::tab{background:#161b22;color:#8b949e;padding:5px 12px;border:1px solid #30363d;}"
            "QTabBar::tab:selected{background:#1f6feb;color:#fff;}"
        )
        self._session_area = bottom_tabs

        # Payload generator tab
        payload_widget = self._build_payload_tab()
        bottom_tabs.addTab(payload_widget, "Payload Generator")
        splitter.addWidget(bottom_tabs)
        splitter.setSizes([280, 420])
        layout.addWidget(splitter)

    def _build_payload_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(6)

        # ── Payload generator row ──────────────────────────────────────
        row = QHBoxLayout()
        self._payload_type = QComboBox()
        self._payload_type.addItems(PayloadGenerator.SUPPORTED_TYPES)
        self._payload_type.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;")
        self._payload_lhost = QLineEdit()
        self._payload_lhost.setPlaceholderText("LHOST")
        self._payload_lhost.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:4px;")
        self._payload_lport = QSpinBox()
        self._payload_lport.setRange(1, 65535)
        self._payload_lport.setValue(4444)
        self._payload_lport.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;")
        gen_btn = QPushButton("Generate")
        gen_btn.setStyleSheet("background:#d29922;color:#000;font-weight:bold;padding:4px 14px;")
        gen_btn.clicked.connect(self._generate_payload)
        row.addWidget(QLabel("Type:"))
        row.addWidget(self._payload_type)
        row.addWidget(QLabel("LHOST:"))
        row.addWidget(self._payload_lhost)
        row.addWidget(QLabel("LPORT:"))
        row.addWidget(self._payload_lport)
        row.addWidget(gen_btn)
        layout.addLayout(row)

        # msfvenom row
        msf_row = QHBoxLayout()
        self._msf_format = QComboBox()
        self._msf_format.addItems(["elf", "exe", "raw", "python", "bash", "psh"])
        self._msf_format.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;")
        self._msf_payload = QComboBox()
        self._msf_payload.addItems([
            "linux/x64/shell_reverse_tcp",
            "linux/x86/shell_reverse_tcp",
            "windows/x64/meterpreter/reverse_tcp",
            "windows/meterpreter/reverse_tcp",
            "windows/x64/shell_reverse_tcp",
            "cmd/unix/reverse_bash",
            "php/reverse_php",
        ])
        self._msf_payload.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;")
        msf_gen_btn = QPushButton("msfvenom Generate")
        msf_gen_btn.setStyleSheet("background:#6e40c9;color:#fff;padding:4px 14px;")
        msf_gen_btn.clicked.connect(self._msf_generate)
        msf_row.addWidget(QLabel("Payload:"))
        msf_row.addWidget(self._msf_payload)
        msf_row.addWidget(QLabel("Format:"))
        msf_row.addWidget(self._msf_format)
        msf_row.addWidget(msf_gen_btn)
        layout.addLayout(msf_row)

        # ── Evasion panel ──────────────────────────────────────────────
        evasion_box = QGroupBox("Evasion (Purple Team)")
        evasion_box.setStyleSheet(
            "QGroupBox{color:#d29922;border:1px solid #30363d;padding:8px;margin-top:8px;}"
            "QGroupBox::title{subcontrol-origin:margin;left:8px;}"
        )
        ev_layout = QVBoxLayout(evasion_box)
        ev_row1 = QHBoxLayout()
        self._ev_b64    = QCheckBox("Base64 wrap")
        self._ev_xor    = QCheckBox("XOR wrap")
        self._ev_psencode = QCheckBox("PS -EncodedCommand")
        self._ev_concat = QCheckBox("String concat")
        self._ev_psvar  = QCheckBox("Randomize PS vars")
        for cb in (self._ev_b64, self._ev_xor, self._ev_psencode, self._ev_concat, self._ev_psvar):
            cb.setStyleSheet("color:#e6edf3;")
            ev_row1.addWidget(cb)
        ev_row1.addStretch()
        ev_layout.addLayout(ev_row1)

        ev_row2 = QHBoxLayout()
        self._ev_procmasq = QCheckBox("Process masquerade")
        self._ev_procmasq.setStyleSheet("color:#e6edf3;")
        self._ev_masqname = QLineEdit()
        self._ev_masqname.setPlaceholderText("Process name (e.g. kworker/u4:2)")
        self._ev_masqname.setText("kworker/u4:2")
        self._ev_masqname.setMaximumWidth(200)
        self._ev_masqname.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:3px;")
        self._ev_jitter   = QCheckBox("Beacon jitter")
        self._ev_jitter.setStyleSheet("color:#e6edf3;")
        self._ev_jitter_min = QSpinBox()
        self._ev_jitter_min.setRange(1, 300)
        self._ev_jitter_min.setValue(5)
        self._ev_jitter_min.setMaximumWidth(70)
        self._ev_jitter_min.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;")
        self._ev_jitter_max = QSpinBox()
        self._ev_jitter_max.setRange(1, 3600)
        self._ev_jitter_max.setValue(30)
        self._ev_jitter_max.setMaximumWidth(70)
        self._ev_jitter_max.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;")
        self._ev_tlsjitter = QCheckBox("JA3 cipher shuffle")
        self._ev_tlsjitter.setStyleSheet("color:#e6edf3;")
        ev_row2.addWidget(self._ev_procmasq)
        ev_row2.addWidget(self._ev_masqname)
        ev_row2.addSpacing(12)
        ev_row2.addWidget(self._ev_jitter)
        ev_row2.addWidget(QLabel("min:"))
        ev_row2.addWidget(self._ev_jitter_min)
        ev_row2.addWidget(QLabel("max:"))
        ev_row2.addWidget(self._ev_jitter_max)
        ev_row2.addSpacing(12)
        ev_row2.addWidget(self._ev_tlsjitter)
        ev_row2.addStretch()
        ev_layout.addLayout(ev_row2)

        # Detection timer controls
        ev_row3 = QHBoxLayout()
        self._ev_timer_btn   = QPushButton("Start Detection Timer")
        self._ev_timer_btn.setStyleSheet("background:#1f6feb;color:#fff;padding:3px 10px;")
        self._ev_timer_btn.clicked.connect(self._start_detection_timer)
        self._ev_detected_btn = QPushButton("Mark Detected")
        self._ev_detected_btn.setStyleSheet("background:#2ea043;color:#fff;padding:3px 10px;")
        self._ev_detected_btn.clicked.connect(self._mark_detected)
        self._ev_missed_btn  = QPushButton("Mark Missed (Gap)")
        self._ev_missed_btn.setStyleSheet("background:#da3633;color:#fff;padding:3px 10px;")
        self._ev_missed_btn.clicked.connect(self._mark_missed)
        self._ev_report_btn  = QPushButton("Detection Report")
        self._ev_report_btn.setStyleSheet("background:#6e40c9;color:#fff;padding:3px 10px;")
        self._ev_report_btn.clicked.connect(self._show_detection_report)
        ev_row3.addWidget(self._ev_timer_btn)
        ev_row3.addWidget(self._ev_detected_btn)
        ev_row3.addWidget(self._ev_missed_btn)
        ev_row3.addWidget(self._ev_report_btn)
        ev_row3.addStretch()
        ev_layout.addLayout(ev_row3)
        layout.addWidget(evasion_box)

        # ── Output ─────────────────────────────────────────────────────
        self._payload_output = QTextEdit()
        self._payload_output.setFont(QFont("Monospace", 10))
        self._payload_output.setReadOnly(True)
        self._payload_output.setStyleSheet(
            "background:#0d1117;color:#39ff14;border:1px solid #30363d;"
        )
        layout.addWidget(self._payload_output)
        return w

    def _start_listener(self):
        try:
            lhost = self._lhost.text().strip() or "0.0.0.0"
            lport = self._lport.value()
            proto = self._proto.currentText().lower()
            lid = self._manager.start_listener(proto, lhost, lport)
            self._refresh_tables()
        except Exception as exc:
            QMessageBox.critical(self, "Listener Error", str(exc))

    def _stop_listener(self):
        rows = self._listener_table.selectedItems()
        if not rows:
            return
        lid = self._listener_table.item(self._listener_table.currentRow(), 0)
        if lid:
            self._manager.stop_listener(lid.text())
            self._refresh_tables()

    def _refresh_tables(self):
        # Listeners
        listeners = self._manager.list_listeners()
        self._listener_table.setRowCount(len(listeners))
        for i, lst in enumerate(listeners):
            self._listener_table.setItem(i, 0, QTableWidgetItem(lst.lid[:8]))
            self._listener_table.setItem(i, 1, QTableWidgetItem(lst.protocol.upper()))
            self._listener_table.setItem(i, 2, QTableWidgetItem(f"{lst.lhost}:{lst.lport}"))
            status = "running" if lst.running else "stopped"
            si = QTableWidgetItem(status)
            si.setForeground(QBrush(QColor("#2ea043" if lst.running else "#da3633")))
            self._listener_table.setItem(i, 3, si)

        # Sessions
        sessions = self._manager.list_sessions()
        self._session_table.setRowCount(len(sessions))
        for i, s in enumerate(sessions):
            self._session_table.setItem(i, 0, QTableWidgetItem(s.session_id[:8]))
            self._session_table.setItem(i, 1, QTableWidgetItem(s.peer_addr[0]))
            self._session_table.setItem(i, 2, QTableWidgetItem(str(s.peer_addr[1])))
            self._session_table.setItem(i, 3, QTableWidgetItem(s.protocol.upper()))
            status = "active" if s.alive else "closed"
            si = QTableWidgetItem(status)
            si.setForeground(QBrush(QColor(SESSION_STATUS_COLORS.get(status, "#8b949e"))))
            self._session_table.setItem(i, 4, si)

    def _on_session_open(self, session: Session):
        self._refresh_tables()

    def _on_session_close(self, session_id: str):
        self._refresh_tables()

    def _open_session_terminal(self):
        row = self._session_table.currentRow()
        sessions = self._manager.list_sessions()
        if row < 0 or row >= len(sessions):
            return
        s = sessions[row]
        sid = s.session_id
        if sid in self._session_tabs:
            # Switch to existing tab
            for i in range(self._session_area.count()):
                if self._session_area.tabText(i).startswith(sid[:8]):
                    self._session_area.setCurrentIndex(i)
                    return
        term = SessionTerminal(s, self)
        self._session_tabs[sid] = term
        idx = self._session_area.addTab(term, f"{sid[:8]} | {s.peer_addr[0]}")
        self._session_area.setCurrentIndex(idx)

    def _build_evasion_config(self) -> EvasionConfig:
        return EvasionConfig(
            obfuscate_base64=self._ev_b64.isChecked(),
            obfuscate_xor=self._ev_xor.isChecked(),
            obfuscate_ps_encode=self._ev_psencode.isChecked(),
            obfuscate_concat=self._ev_concat.isChecked(),
            randomize_varnames=self._ev_psvar.isChecked(),
            process_masquerade=self._ev_procmasq.isChecked(),
            process_masquerade_name=self._ev_masqname.text().strip() or "kworker/u4:2",
            jitter_enabled=self._ev_jitter.isChecked(),
            jitter_min_s=float(self._ev_jitter_min.value()),
            jitter_max_s=float(self._ev_jitter_max.value()),
            tls_randomize_ciphers=self._ev_tlsjitter.isChecked(),
        )

    def _generate_payload(self):
        try:
            lhost = SecureInputValidator.validate_host(self._payload_lhost.text())
            lport = self._payload_lport.value()
            ptype = self._payload_type.currentText()
            os_type = "windows" if "powershell" in ptype.lower() else "linux"
            raw = PayloadGenerator.generate(ptype, lhost, lport)
            cfg = self._build_evasion_config()
            result = apply_evasion_to_payload(raw, cfg, os_type)
            self._payload_output.setPlainText(result)
            evasion_tags = [
                k for k, v in {
                    "b64": cfg.obfuscate_base64, "xor": cfg.obfuscate_xor,
                    "ps_enc": cfg.obfuscate_ps_encode, "concat": cfg.obfuscate_concat,
                    "masq": cfg.process_masquerade,
                }.items() if v
            ]
            audit("PAYLOAD_GENERATED",
                  detail=f"type={ptype} lhost={lhost} lport={lport} evasion={evasion_tags}")
        except Exception as exc:
            QMessageBox.warning(self, "Payload Error", str(exc))

    def _start_detection_timer(self):
        ptype = self._payload_type.currentText()
        label = f"{ptype}_{self._payload_lport.value()}"
        self._detection_timer.record_send(label)
        self._payload_output.append(f"\n[Detection timer started: {label}]")

    def _mark_detected(self):
        ptype = self._payload_type.currentText()
        label = f"{ptype}_{self._payload_lport.value()}"
        ev = self._detection_timer.mark_detected(label, alert_detail="manual")
        if ev and ev.latency_ms is not None:
            self._payload_output.append(
                f"[DETECTED — latency: {ev.latency_ms:.0f}ms]"
            )

    def _mark_missed(self):
        ptype = self._payload_type.currentText()
        label = f"{ptype}_{self._payload_lport.value()}"
        self._detection_timer.mark_missed(label)
        self._payload_output.append(f"[MISSED — detection gap recorded for: {label}]")

    def _show_detection_report(self):
        report = self._detection_timer.report()
        self._payload_output.setPlainText(report)

    def _msf_generate(self):
        try:
            lhost = SecureInputValidator.validate_host(self._payload_lhost.text())
            lport = self._payload_lport.value()
            payload = self._msf_payload.currentText()
            fmt = self._msf_format.currentText()
            result = MsfvenomWrapper.generate(payload, lhost, lport, fmt)
            if result.artifacts:
                self._payload_output.setPlainText(
                    f"Command: {result.command_str}\n"
                    f"Output: {result.artifacts[0] if result.artifacts else 'N/A'}"
                )
            else:
                self._payload_output.setPlainText(f"Command: {result.command_str}\n(dry-run)")
        except Exception as exc:
            QMessageBox.critical(self, "msfvenom Error", str(exc))

    def closeEvent(self, event):
        self._timer.stop()
        self._manager.shutdown()
        super().closeEvent(event)
