import threading
from typing import Optional

import paramiko
from PyQt6.QtWidgets import QPlainTextEdit, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QLabel
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QObject
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCursor


class ShellReader(QObject):
    data_received = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, channel: paramiko.Channel):
        super().__init__()
        self._channel = channel
        self._running = True

    def run(self):
        while self._running and not self._channel.closed:
            if self._channel.recv_ready():
                data = self._channel.recv(4096).decode(errors="replace")
                if data:
                    self.data_received.emit(data)
            elif self._channel.exit_status_ready():
                break
        self.finished.emit()

    def stop(self):
        self._running = False


class TerminalWidget(QWidget):
    """
    SSH interactive terminal embedded in PyQt6.
    Reads from paramiko shell channel; writes user input back to channel.
    """

    def __init__(self, channel: paramiko.Channel, parent=None):
        super().__init__(parent)
        self._channel = channel
        self._reader: Optional[ShellReader] = None
        self._thread: Optional[QThread] = None
        self._build_ui()
        self._start_reader()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(4, 4, 4, 4)

        header = QLabel("Interactive Shell Session")
        header.setStyleSheet("color: #00ff88; font-weight: bold;")
        layout.addWidget(header)

        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont("Monospace", 10))
        self._output.setStyleSheet(
            "background:#0d1117; color:#e6edf3; border:1px solid #30363d;"
        )
        self._output.setMaximumBlockCount(5000)
        layout.addWidget(self._output)

        input_row = QHBoxLayout()
        self._input = QLineEdit()
        self._input.setFont(QFont("Monospace", 10))
        self._input.setPlaceholderText("Type command and press Enter...")
        self._input.setStyleSheet("background:#161b22; color:#e6edf3; border:1px solid #30363d; padding:4px;")
        self._input.returnPressed.connect(self._send_input)

        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self._send_input)
        send_btn.setStyleSheet("background:#238636; color:#fff; padding:4px 12px;")

        ctrl_c_btn = QPushButton("Ctrl+C")
        ctrl_c_btn.clicked.connect(self._send_interrupt)
        ctrl_c_btn.setStyleSheet("background:#da3633; color:#fff; padding:4px 8px;")

        input_row.addWidget(self._input)
        input_row.addWidget(send_btn)
        input_row.addWidget(ctrl_c_btn)
        layout.addLayout(input_row)

    def _start_reader(self):
        self._thread = QThread()
        self._reader = ShellReader(self._channel)
        self._reader.moveToThread(self._thread)
        self._thread.started.connect(self._reader.run)
        self._reader.data_received.connect(self._append_output)
        self._reader.finished.connect(self._on_shell_closed)
        self._thread.start()

    def _append_output(self, text: str):
        cursor = self._output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        self._output.setTextCursor(cursor)
        self._output.ensureCursorVisible()

    def _send_input(self):
        text = self._input.text()
        self._input.clear()
        if self._channel and not self._channel.closed:
            self._channel.send(text + "\n")

    def _send_interrupt(self):
        if self._channel and not self._channel.closed:
            self._channel.send("\x03")

    def _on_shell_closed(self):
        self._append_output("\n[Session closed]\n")

    def closeEvent(self, event):
        if self._reader:
            self._reader.stop()
        if self._thread:
            self._thread.quit()
            self._thread.wait(3000)
        if self._channel and not self._channel.closed:
            self._channel.close()
        super().closeEvent(event)
