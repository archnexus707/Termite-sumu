"""Shared pytest configuration — sets offscreen Qt platform for headless CI."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
