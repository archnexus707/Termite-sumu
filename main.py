#!/usr/bin/env python3
"""Termite-sumu - Authorized Red Team & Forensics Platform | Author: C7aWL3R"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.umask(0o077)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from gui.main_window import MainWindow
from config.settings import APP_NAME


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("C7aWL3R")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
