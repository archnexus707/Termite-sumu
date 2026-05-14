"""
GUI smoke tests — verify all tab widgets instantiate without crashing.
Requires a display.  On headless CI set:  export QT_QPA_PLATFORM=offscreen
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# Skip entire module if Qt display not available
pytest.importorskip("PyQt6.QtWidgets")


@pytest.fixture(scope="module")
def qapp():
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def test_reverse_shell_tab(qapp):
    from gui.reverse_shell_tab import ReverseShellTab
    w = ReverseShellTab()
    assert w is not None


def test_exploit_launcher_tab(qapp):
    from gui.exploit_launcher_tab import ExploitLauncherTab
    w = ExploitLauncherTab()
    assert w is not None


def test_redteam_tab(qapp):
    from gui.redteam_tab import RedTeamTab
    w = RedTeamTab()
    assert w is not None


def test_analysis_tab(qapp):
    from gui.analysis_tab import AnalysisTab
    w = AnalysisTab()
    assert w is not None


def test_reference_tab(qapp):
    from gui.reference_tab import ReferenceTab
    w = ReferenceTab()
    assert w is not None


def test_reference_tab_search(qapp):
    from gui.reference_tab import ReferenceTab
    w = ReferenceTab()
    w._search.setText("nmap")
    assert w._tree.topLevelItemCount() > 0


def test_connection_dialog(qapp):
    from gui.connection_dialog import ConnectionDialog
    d = ConnectionDialog()
    assert d is not None


def test_log_viewer(qapp):
    from gui.log_viewer import LogViewerWidget
    w = LogViewerWidget()
    assert w is not None


def test_main_window_title(qapp):
    from gui.main_window import MainWindow
    w = MainWindow()
    assert "Termite-sumu" in w.windowTitle()
    w.close()


def test_main_window_permanent_tabs(qapp):
    from gui.main_window import MainWindow, _PERMANENT_TABS
    w = MainWindow()
    assert _PERMANENT_TABS == 5
    # Total tabs = 5 permanent + 1 welcome
    assert w._tabs.count() == 6
    w.close()
