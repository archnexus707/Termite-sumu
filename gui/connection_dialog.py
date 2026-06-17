from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QComboBox, QSpinBox, QCheckBox,
    QPushButton, QLabel, QTabWidget, QWidget,
    QFileDialog, QMessageBox,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from core.base_connector import ConnectionProfile
from core.validators import SecureInputValidator


class ConnectionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Connection")
        self.setMinimumWidth(480)
        self.setModal(True)
        self._profile: ConnectionProfile | None = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Remote Connection")
        title.setFont(QFont("Monospace", 13, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._basic_tab(), "Connection")
        tabs.addTab(self._auth_tab(), "Authentication")
        layout.addWidget(tabs)

        btn_row = QHBoxLayout()
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.setStyleSheet("background:#00ff88;color:#000;font-weight:bold;padding:6px 20px;")
        self._connect_btn.clicked.connect(self._on_connect)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(self._connect_btn)
        layout.addLayout(btn_row)

    def _basic_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._host = QLineEdit()
        self._host.setPlaceholderText("IP address or hostname")
        form.addRow("Host:", self._host)

        self._protocol = QComboBox()
        self._protocol.addItems(["SSH", "WinRM", "SMB", "Telnet"])
        self._protocol.currentTextChanged.connect(self._on_protocol_changed)
        form.addRow("Protocol:", self._protocol)

        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(22)
        form.addRow("Port:", self._port)

        self._os_type = QComboBox()
        self._os_type.addItems(["Linux", "Windows"])
        form.addRow("Target OS:", self._os_type)

        self._use_tls = QCheckBox("Use TLS/HTTPS")
        form.addRow("", self._use_tls)

        return w

    def _auth_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._username = QLineEdit()
        self._username.setPlaceholderText("Username")
        form.addRow("Username:", self._username)

        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._password.setPlaceholderText("Password (leave blank for key auth)")
        form.addRow("Password:", self._password)

        self._domain = QLineEdit()
        self._domain.setPlaceholderText("DOMAIN (Windows only)")
        form.addRow("Domain:", self._domain)

        key_row = QHBoxLayout()
        self._key_path = QLineEdit()
        self._key_path.setPlaceholderText("SSH private key path (optional)")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_key)
        key_row.addWidget(self._key_path)
        key_row.addWidget(browse_btn)
        form.addRow("SSH Key:", key_row)

        return w

    def _on_protocol_changed(self, protocol: str):
        port_map = {"SSH": 22, "WinRM": 5985, "SMB": 445, "Telnet": 23}
        self._port.setValue(port_map.get(protocol, 22))

    def _browse_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "All Files (*)")
        if path:
            self._key_path.setText(path)

    def _on_connect(self):
        try:
            host = SecureInputValidator.validate_host(self._host.text())
            port = SecureInputValidator.validate_port(self._port.value())
            username = self._username.text().strip()
            if username:
                username = SecureInputValidator.validate_username(username)
        except ValueError as exc:
            QMessageBox.warning(self, "Validation Error", str(exc))
            return

        self._profile = ConnectionProfile(
            host=host,
            port=port,
            username=username,
            password=self._password.text() or None,
            key_path=self._key_path.text().strip() or None,
            domain=self._domain.text().strip() or None,
            protocol=self._protocol.currentText().lower(),
            use_tls=self._use_tls.isChecked(),
        )
        self._os_hint = self._os_type.currentText().lower()
        self.accept()

    @property
    def profile(self) -> ConnectionProfile | None:
        return self._profile

    @property
    def os_hint(self) -> str:
        return getattr(self, "_os_hint", "linux")
