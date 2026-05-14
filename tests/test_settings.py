"""Settings and environment variable behaviour tests."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_app_name():
    from config.settings import APP_NAME
    assert APP_NAME == "Termite-sumu"


def test_app_version_format():
    from config.settings import APP_VERSION
    parts = APP_VERSION.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


def test_dry_run_off_by_default(monkeypatch):
    monkeypatch.delenv("TERMITE_SUMU_DRY_RUN", raising=False)
    import importlib
    import config.settings as s
    importlib.reload(s)
    assert s.DRY_RUN is False


def test_dry_run_enabled_by_env(monkeypatch):
    monkeypatch.setenv("TERMITE_SUMU_DRY_RUN", "1")
    import importlib
    import config.settings as s
    importlib.reload(s)
    assert s.DRY_RUN is True


def test_ip_regex_valid():
    from config.settings import ALLOWED_IP_RE
    assert ALLOWED_IP_RE.match("192.168.1.1")
    assert ALLOWED_IP_RE.match("10.0.0.1")
    assert ALLOWED_IP_RE.match("255.255.255.255")


def test_ip_regex_invalid():
    from config.settings import ALLOWED_IP_RE
    assert not ALLOWED_IP_RE.match("256.0.0.1")
    assert not ALLOWED_IP_RE.match("hostname")
    assert not ALLOWED_IP_RE.match("http://10.0.0.1")


def test_hostname_regex_valid():
    from config.settings import ALLOWED_HOSTNAME_RE
    assert ALLOWED_HOSTNAME_RE.match("dc01")
    assert ALLOWED_HOSTNAME_RE.match("dc01.corp.local")
    assert ALLOWED_HOSTNAME_RE.match("my-server.example.com")


def test_hostname_regex_rejects_scheme():
    from config.settings import ALLOWED_HOSTNAME_RE
    assert not ALLOWED_HOSTNAME_RE.match("http://target.com")


def test_log_dirs_exist():
    from config.settings import LOGS_DIR, EXPORTS_DIR
    assert os.path.isdir(LOGS_DIR)
    assert os.path.isdir(EXPORTS_DIR)
