"""
Shared QThread reader that streams Popen stdout line-by-line into the GUI.

Used by ExploitLauncherTab and RedTeamTab — both tabs spawn external tools
and need identical live-output behaviour.
"""
from __future__ import annotations

import subprocess

from PyQt6.QtCore import QThread, pyqtSignal


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
