"""Red Team Operations GUI tab."""
from __future__ import annotations

import subprocess
from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QSpinBox,
    QComboBox, QCheckBox, QTextEdit, QGroupBox,
    QFormLayout, QStackedWidget, QMessageBox,
    QApplication, QTabWidget,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from core.redteam import (
    ADEnumerator, NetworkAttacker, ReconRunner,
    WebAttacker, PostExploitRunner, TunnelRunner,
)
from core.exploit_launcher import ToolResult
from core.audit import audit


# ── Shared output reader (same pattern as exploit_launcher_tab) ───────────

class OutputReader(QThread):
    line_received = pyqtSignal(str)
    finished      = pyqtSignal(int)

    def __init__(self, proc: subprocess.Popen):
        super().__init__()
        self._proc = proc

    def run(self):
        try:
            for line in self._proc.stdout:
                self.line_received.emit(line.rstrip("\n"))
            rc = self._proc.wait()
        except Exception as exc:
            self.line_received.emit(f"[reader error] {exc}")
            rc = -1
        self.finished.emit(rc)

    def stop(self):
        try:
            self._proc.terminate()
        except Exception:
            pass
        self.quit()
        self.wait(3000)


# ── Widget helpers ────────────────────────────────────────────────────────

def _le(ph: str = "", w: int = 240) -> QLineEdit:
    e = QLineEdit()
    e.setPlaceholderText(ph)
    e.setMaximumWidth(w)
    e.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:4px;")
    return e


def _cb(items, w: int = 180) -> QComboBox:
    c = QComboBox()
    c.addItems(items)
    c.setMaximumWidth(w)
    c.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:4px;")
    return c


def _spin(lo: int, hi: int, val: int, w: int = 90) -> QSpinBox:
    s = QSpinBox()
    s.setRange(lo, hi)
    s.setValue(val)
    s.setMaximumWidth(w)
    s.setStyleSheet("background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:4px;")
    return s


def _chk(label: str) -> QCheckBox:
    c = QCheckBox(label)
    c.setStyleSheet("color:#e6edf3;")
    return c


# ── Per-category form panels ──────────────────────────────────────────────

class ADForm(QWidget):
    TOOLS = ["Kerberoast", "AS-REP Roast", "BloodHound", "ldapdomaindump",
             "Kerbrute UserEnum", "Certipy Find", "DCSync"]

    def __init__(self):
        super().__init__()
        fl = QFormLayout(self)
        fl.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.tool     = _cb(self.TOOLS)
        self.domain   = _le("corp.local")
        self.username = _le("user")
        self.password = _le("password")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.dc_ip    = _le("DC IP")
        self.userfile = _le("/tmp/users.txt", w=300)
        self.wordlist = _le("/usr/share/seclists/Usernames/Names/names.txt", w=300)
        fl.addRow("Tool:", self.tool)
        fl.addRow("Domain:", self.domain)
        fl.addRow("Username:", self.username)
        fl.addRow("Password:", self.password)
        fl.addRow("DC IP:", self.dc_ip)
        fl.addRow("Userfile:", self.userfile)
        fl.addRow("Wordlist:", self.wordlist)

    def build(self, dry_run: bool) -> ToolResult:
        tool = self.tool.currentText()
        dom  = self.domain.text().strip()
        user = self.username.text().strip()
        pw   = self.password.text()
        dc   = self.dc_ip.text().strip()
        uf   = self.userfile.text().strip()
        wl   = self.wordlist.text().strip()
        if tool == "Kerberoast":
            return ADEnumerator.kerberoast(dom, user, pw, dc, dry_run)
        if tool == "AS-REP Roast":
            return ADEnumerator.asrep_roast(dom, dc, uf, dry_run)
        if tool == "BloodHound":
            return ADEnumerator.bloodhound(dom, user, pw, dc, dry_run=dry_run)
        if tool == "ldapdomaindump":
            return ADEnumerator.ldapdomaindump(dom, user, pw, dc, dry_run)
        if tool == "Kerbrute UserEnum":
            return ADEnumerator.kerbrute_userenum(dom, wl, dc, dry_run)
        if tool == "Certipy Find":
            return ADEnumerator.certipy_find(dom, user, pw, dc, dry_run)
        if tool == "DCSync":
            return ADEnumerator.dcsync(dom, user, pw, dc, dry_run=dry_run)
        raise ValueError(f"Unknown tool: {tool}")


class NetworkForm(QWidget):
    TOOLS = ["Responder", "ntlmrelayx", "mitm6", "PetitPotam"]

    def __init__(self):
        super().__init__()
        fl = QFormLayout(self)
        fl.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.tool      = _cb(self.TOOLS)
        self.interface = _le("eth0")
        self.domain    = _le("corp.local")
        self.targets   = _le("/tmp/targets.txt", w=300)
        self.exec_cmd  = _le("whoami", w=300)
        self.listener  = _le("attacker IP")
        self.target_ip = _le("DC IP")
        self.wpad      = _chk("WPAD (-w)")
        self.passive   = _chk("Passive (-A)")
        self.smb2      = _chk("SMB2 support")
        self.smb2.setChecked(True)
        self.socks     = _chk("SOCKS mode")
        self.adcs      = _chk("ADCS mode")
        fl.addRow("Tool:", self.tool)
        fl.addRow("Interface:", self.interface)
        fl.addRow("Domain:", self.domain)
        fl.addRow("Targets file:", self.targets)
        fl.addRow("Exec cmd:", self.exec_cmd)
        fl.addRow("Listener IP:", self.listener)
        fl.addRow("Target IP:", self.target_ip)
        fl.addRow("", self.wpad)
        fl.addRow("", self.passive)
        fl.addRow("", self.smb2)
        fl.addRow("", self.socks)
        fl.addRow("", self.adcs)

    def build(self, dry_run: bool) -> ToolResult:
        tool = self.tool.currentText()
        if tool == "Responder":
            return NetworkAttacker.responder(
                self.interface.text().strip(),
                wpad=self.wpad.isChecked(),
                passive=self.passive.isChecked(),
                dry_run=dry_run,
            )
        if tool == "ntlmrelayx":
            return NetworkAttacker.ntlmrelayx(
                self.targets.text().strip(),
                smb2=self.smb2.isChecked(),
                exec_cmd=self.exec_cmd.text().strip() or None,
                socks=self.socks.isChecked(),
                adcs=self.adcs.isChecked(),
                dry_run=dry_run,
            )
        if tool == "mitm6":
            return NetworkAttacker.mitm6(
                self.domain.text().strip(),
                self.interface.text().strip(),
                dry_run=dry_run,
            )
        if tool == "PetitPotam":
            return NetworkAttacker.petitpotam(
                self.listener.text().strip(),
                self.target_ip.text().strip(),
                dry_run=dry_run,
            )
        raise ValueError(f"Unknown tool: {tool}")


class ReconForm(QWidget):
    TOOLS = ["theHarvester", "subfinder", "amass", "nikto",
             "gobuster dir", "feroxbuster"]

    def __init__(self):
        super().__init__()
        fl = QFormLayout(self)
        fl.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.tool     = _cb(self.TOOLS)
        self.domain   = _le("target.com")
        self.target   = _le("http://target.com", w=300)
        self.wordlist = _le("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", w=380)
        self.ext      = _le("php,html,txt,bak")
        self.port     = _spin(1, 65535, 80)
        self.ssl      = _chk("SSL")
        self.passive  = _chk("Passive mode (amass)")
        self.passive.setChecked(True)
        fl.addRow("Tool:", self.tool)
        fl.addRow("Domain:", self.domain)
        fl.addRow("URL:", self.target)
        fl.addRow("Wordlist:", self.wordlist)
        fl.addRow("Extensions:", self.ext)
        fl.addRow("Port:", self.port)
        fl.addRow("", self.ssl)
        fl.addRow("", self.passive)

    def build(self, dry_run: bool) -> ToolResult:
        tool = self.tool.currentText()
        if tool == "theHarvester":
            return ReconRunner.theharvester(self.domain.text().strip(), dry_run=dry_run)
        if tool == "subfinder":
            return ReconRunner.subfinder(self.domain.text().strip(), dry_run=dry_run)
        if tool == "amass":
            return ReconRunner.amass(self.domain.text().strip(),
                                     passive=self.passive.isChecked(), dry_run=dry_run)
        if tool == "nikto":
            return ReconRunner.nikto(self.domain.text().strip(),
                                     port=self.port.value(),
                                     use_ssl=self.ssl.isChecked(), dry_run=dry_run)
        if tool == "gobuster dir":
            return ReconRunner.gobuster_dir(
                self.target.text().strip(),
                self.wordlist.text().strip(),
                extensions=self.ext.text().strip(),
                dry_run=dry_run,
            )
        if tool == "feroxbuster":
            return ReconRunner.feroxbuster(
                self.target.text().strip(),
                self.wordlist.text().strip(),
                dry_run=dry_run,
            )
        raise ValueError(f"Unknown tool: {tool}")


class WebForm(QWidget):
    TOOLS = ["sqlmap", "ffuf", "nuclei"]

    def __init__(self):
        super().__init__()
        fl = QFormLayout(self)
        fl.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.tool     = _cb(self.TOOLS)
        self.url      = _le("https://target.com/page?id=1", w=380)
        self.data     = _le("user=admin&pass=test (POST body)", w=380)
        self.wordlist = _le("/usr/share/seclists/Discovery/Web-Content/common.txt", w=380)
        self.level    = _spin(1, 5, 1)
        self.risk     = _spin(1, 3, 1)
        self.severity = _le("medium,high,critical")
        fl.addRow("Tool:", self.tool)
        fl.addRow("URL:", self.url)
        fl.addRow("POST data:", self.data)
        fl.addRow("Wordlist:", self.wordlist)
        fl.addRow("Level:", self.level)
        fl.addRow("Risk:", self.risk)
        fl.addRow("Nuclei severity:", self.severity)

    def build(self, dry_run: bool) -> ToolResult:
        tool = self.tool.currentText()
        if tool == "sqlmap":
            return WebAttacker.sqlmap(
                self.url.text().strip(),
                data=self.data.text().strip() or None,
                level=self.level.value(),
                risk=self.risk.value(),
                dry_run=dry_run,
            )
        if tool == "ffuf":
            return WebAttacker.ffuf(
                self.url.text().strip(),
                self.wordlist.text().strip(),
                dry_run=dry_run,
            )
        if tool == "nuclei":
            return WebAttacker.nuclei(
                self.url.text().strip(),
                severity=self.severity.text().strip(),
                dry_run=dry_run,
            )
        raise ValueError(f"Unknown tool: {tool}")


class PostExploitForm(QWidget):
    TOOLS = ["LinPEAS (local)", "pspy", "SUDO_KILLER", "Find SUID/SGID"]

    def __init__(self):
        super().__init__()
        fl = QFormLayout(self)
        fl.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.tool = _cb(self.TOOLS)
        fl.addRow("Tool:", self.tool)
        fl.addRow("", QLabel("Runs on LOCAL machine for assessment."))

    def build(self, dry_run: bool) -> ToolResult:
        tool = self.tool.currentText()
        if tool == "LinPEAS (local)":
            return PostExploitRunner.linpeas_local(dry_run)
        if tool == "pspy":
            return PostExploitRunner.pspy(dry_run)
        if tool == "SUDO_KILLER":
            return PostExploitRunner.sudo_killer(dry_run)
        if tool == "Find SUID/SGID":
            return PostExploitRunner.find_suid(dry_run)
        raise ValueError(f"Unknown tool: {tool}")


class TunnelForm(QWidget):
    TOOLS = ["Chisel Server", "Chisel Client", "Ligolo Proxy", "SSH SOCKS"]

    def __init__(self):
        super().__init__()
        fl = QFormLayout(self)
        fl.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.tool       = _cb(self.TOOLS)
        self.server     = _le("attacker IP / chisel server")
        self.port       = _spin(1, 65535, 8080)
        self.local_port = _spin(1, 65535, 1080)
        self.forward    = _le("R:1080:socks", w=280)
        self.ssh_user   = _le("user")
        self.ssh_host   = _le("pivot host")
        self.ssh_port   = _spin(1, 65535, 22)
        self.reverse    = _chk("Reverse (--reverse)")
        self.reverse.setChecked(True)
        self.selfcert   = _chk("Self-signed cert (ligolo)")
        self.selfcert.setChecked(True)
        fl.addRow("Tool:", self.tool)
        fl.addRow("Server/Host:", self.server)
        fl.addRow("Port:", self.port)
        fl.addRow("Local port:", self.local_port)
        fl.addRow("Forward spec:", self.forward)
        fl.addRow("SSH user:", self.ssh_user)
        fl.addRow("SSH host:", self.ssh_host)
        fl.addRow("SSH port:", self.ssh_port)
        fl.addRow("", self.reverse)
        fl.addRow("", self.selfcert)

    def build(self, dry_run: bool) -> ToolResult:
        tool = self.tool.currentText()
        if tool == "Chisel Server":
            return TunnelRunner.chisel_server(
                port=self.port.value(),
                reverse=self.reverse.isChecked(),
                dry_run=dry_run,
            )
        if tool == "Chisel Client":
            return TunnelRunner.chisel_client(
                server=self.server.text().strip(),
                server_port=self.port.value(),
                forward=self.forward.text().strip(),
                dry_run=dry_run,
            )
        if tool == "Ligolo Proxy":
            return TunnelRunner.ligolo_proxy(
                port=self.port.value(),
                selfcert=self.selfcert.isChecked(),
                dry_run=dry_run,
            )
        if tool == "SSH SOCKS":
            return TunnelRunner.ssh_socks(
                user=self.ssh_user.text().strip(),
                host=self.ssh_host.text().strip(),
                port=self.ssh_port.value(),
                local_port=self.local_port.value(),
                dry_run=dry_run,
            )
        raise ValueError(f"Unknown tool: {tool}")


# ── Category tabs mapping ─────────────────────────────────────────────────

CATEGORY_COLORS = {
    "AD Enumeration": "#6e40c9",
    "Network Attacks": "#da3633",
    "Reconnaissance": "#1f6feb",
    "Web Attacks":    "#d29922",
    "Post-Exploit":   "#2ea043",
    "Tunneling":      "#58a6ff",
}


# ── Main tab widget ───────────────────────────────────────────────────────

class RedTeamTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._result: Optional[ToolResult] = None
        self._reader: Optional[OutputReader] = None
        self._build_ui()

    def _build_ui(self):
        root = QHBoxLayout(self)
        root.setSpacing(8)

        # ── Left: category tabs + forms ────────────────────────────────
        left = QWidget()
        left.setMaximumWidth(520)
        ll = QVBoxLayout(left)
        ll.setSpacing(4)

        cat_tabs = QTabWidget()
        cat_tabs.setStyleSheet(
            "QTabWidget::pane{border:1px solid #30363d;background:#0d1117;}"
            "QTabBar::tab{background:#161b22;color:#8b949e;padding:5px 10px;border:1px solid #30363d;}"
            "QTabBar::tab:selected{color:#fff;font-weight:bold;}"
        )

        self._forms = {
            "AD Enumeration": ADForm(),
            "Network Attacks": NetworkForm(),
            "Reconnaissance": ReconForm(),
            "Web Attacks":    WebForm(),
            "Post-Exploit":   PostExploitForm(),
            "Tunneling":      TunnelForm(),
        }
        for cat, form in self._forms.items():
            color = CATEGORY_COLORS.get(cat, "#8b949e")
            cat_tabs.addTab(form, cat)
            idx = cat_tabs.indexOf(form)
            cat_tabs.tabBar().setTabTextColor(idx, _qcolor(color))

        ll.addWidget(cat_tabs)
        self._cat_tabs = cat_tabs

        # Dry-run + action buttons
        self._dry_run = QCheckBox("Dry-run (preview command only)")
        self._dry_run.setStyleSheet("color:#e6edf3;")
        self._dry_run.setChecked(False)
        ll.addWidget(self._dry_run)

        btn_row = QHBoxLayout()
        self._run_btn = QPushButton("Launch")
        self._run_btn.setStyleSheet(
            "background:#da3633;color:#fff;font-weight:bold;padding:8px 20px;"
        )
        self._run_btn.clicked.connect(self._launch)
        btn_row.addWidget(self._run_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setStyleSheet("background:#6e7681;color:#fff;padding:8px 20px;")
        self._stop_btn.clicked.connect(self._stop)
        self._stop_btn.setEnabled(False)
        btn_row.addWidget(self._stop_btn)

        self._copy_btn = QPushButton("Copy CMD")
        self._copy_btn.setStyleSheet("background:#238636;color:#fff;padding:8px 16px;")
        self._copy_btn.clicked.connect(self._copy)
        self._copy_btn.setEnabled(False)
        btn_row.addWidget(self._copy_btn)
        btn_row.addStretch()
        ll.addLayout(btn_row)
        ll.addStretch()
        root.addWidget(left)

        # ── Right: live output ─────────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setSpacing(4)

        hdr = QHBoxLayout()
        hdr.addWidget(QLabel("Live Output"))
        hdr.addStretch()
        self._cmd_label = QLabel("")
        self._cmd_label.setStyleSheet("color:#58a6ff;font-size:10px;")
        self._cmd_label.setWordWrap(True)
        hdr.addWidget(self._cmd_label)
        rl.addLayout(hdr)

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont("Monospace", 9))
        self._output.setStyleSheet(
            "background:#0d1117;color:#3fb950;border:1px solid #30363d;"
        )
        rl.addWidget(self._output)

        clr = QPushButton("Clear")
        clr.setMaximumWidth(80)
        clr.setStyleSheet("background:#21262d;color:#e6edf3;padding:4px;")
        clr.clicked.connect(self._output.clear)
        rl.addWidget(clr, alignment=Qt.AlignmentFlag.AlignRight)
        root.addWidget(right)

    def _current_form(self):
        return list(self._forms.values())[self._cat_tabs.currentIndex()]

    def _launch(self):
        dry  = self._dry_run.isChecked()
        form = self._current_form()
        try:
            result = form.build(dry_run=dry)
        except (ValueError, FileNotFoundError) as exc:
            QMessageBox.critical(self, "Launch Error", str(exc))
            return

        self._result = result
        self._cmd_label.setText(result.command_str)
        self._copy_btn.setEnabled(True)
        self._output.append(f"\n{'─'*60}")
        self._output.append(f"CMD: {result.command_str}")
        self._output.append(f"{'─'*60}")

        if dry:
            self._output.append("[DRY-RUN — not executed]")
            return

        if result.process is None:
            self._output.append("[No process — check tool is installed]")
            return

        self._run_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._reader = OutputReader(result.process)
        self._reader.line_received.connect(self._on_line)
        self._reader.finished.connect(self._on_done)
        self._reader.start()

    def _stop(self):
        if self._reader:
            self._reader.stop()
            self._output.append("[terminated by user]")
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)

    def _copy(self):
        if self._result:
            QApplication.clipboard().setText(self._result.command_str)

    def _on_line(self, line: str):
        self._output.append(line)
        sb = self._output.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_done(self, rc: int):
        self._output.append(f"\n[exited — return code {rc}]")
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._reader = None

    def closeEvent(self, event):
        if self._reader:
            self._reader.stop()
        super().closeEvent(event)


def _qcolor(hex_color: str):
    from PyQt6.QtGui import QColor
    return QColor(hex_color)
