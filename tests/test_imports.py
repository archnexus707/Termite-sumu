"""Smoke-test every module imports without error — catches missing deps early."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_config_settings():
    from config import settings
    assert settings.APP_NAME == "Termite-sumu"
    assert settings.APP_VERSION


def test_core_validators():
    from core import validators
    assert hasattr(validators, "SecureInputValidator")


def test_core_base_connector():
    from core import base_connector
    assert hasattr(base_connector, "BaseConnector")
    assert hasattr(base_connector, "DeviceNode")


def test_core_connector_factory():
    from core import connector_factory
    assert hasattr(connector_factory, "create_connector")


def test_core_log_analyzer():
    from core import log_analyzer
    assert hasattr(log_analyzer, "LogAnalyzer")


def test_core_log_collector():
    from core import log_collector
    assert hasattr(log_collector, "LogCollector")


def test_core_evasion():
    from core import evasion
    assert hasattr(evasion, "EvasionConfig")
    assert hasattr(evasion, "apply_evasion_to_payload")


def test_core_redteam():
    from core import redteam
    assert hasattr(redteam, "bloodhound")
    assert hasattr(redteam, "nuclei")
    assert hasattr(redteam, "amass")


def test_core_reverse_shell():
    from core import reverse_shell
    assert hasattr(reverse_shell, "ReverseShellManager")


def test_core_audit():
    from core import audit
    assert hasattr(audit, "audit")


def test_reports():
    from reports import pdf_report
    assert hasattr(pdf_report, "export_logs_pdf")
