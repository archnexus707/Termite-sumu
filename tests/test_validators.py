"""Validator unit tests — no network, no subprocess, no GUI."""
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.validators import SecureInputValidator as V


# ── Host ─────────────────────────────────────────────────────────────────────
class TestHost:
    def test_valid_ipv4(self):
        assert V.validate_host("192.168.1.1") == "192.168.1.1"

    def test_valid_hostname(self):
        assert V.validate_host("dc01.corp.local") == "dc01.corp.local"

    def test_strips_whitespace(self):
        assert V.validate_host("  10.0.0.1  ") == "10.0.0.1"

    def test_rejects_none(self):
        with pytest.raises(ValueError):
            V.validate_host(None)

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            V.validate_host("   ")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            V.validate_host("a" * 254)

    def test_rejects_url_with_scheme(self):
        with pytest.raises(ValueError):
            V.validate_host("http://10.0.0.1")


# ── Port ─────────────────────────────────────────────────────────────────────
class TestPort:
    def test_valid_int(self):
        assert V.validate_port(22) == 22

    def test_valid_string(self):
        assert V.validate_port("8080") == 8080

    def test_rejects_zero(self):
        with pytest.raises(ValueError):
            V.validate_port(0)

    def test_rejects_above_65535(self):
        with pytest.raises(ValueError):
            V.validate_port(65536)

    def test_rejects_non_numeric(self):
        with pytest.raises(ValueError):
            V.validate_port("abc")


# ── Username ──────────────────────────────────────────────────────────────────
class TestUsername:
    def test_simple(self):
        assert V.validate_username("admin") == "admin"

    def test_domain_user(self):
        assert V.validate_username("CORP\\jsmith") == "CORP\\jsmith"

    def test_upn(self):
        assert V.validate_username("user@corp.local") == "user@corp.local"

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError):
            V.validate_username("user;rm -rf /")

    def test_rejects_none(self):
        with pytest.raises(ValueError):
            V.validate_username(None)


# ── Path ─────────────────────────────────────────────────────────────────────
class TestPath:
    def test_valid_unix(self):
        result = V.validate_path("/var/log/syslog")
        assert "syslog" in result

    def test_valid_windows(self):
        result = V.validate_path("C:\\Windows\\System32\\cmd.exe")
        assert "cmd.exe" in result

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError):
            V.validate_path("/tmp/fi\x00le")

    def test_rejects_traversal(self):
        with pytest.raises(ValueError):
            V.validate_path("../../../../etc/passwd")

    def test_normalized_path_no_traversal(self):
        # /tmp/../var/log normalises to /var/log — no traversal, should pass
        result = V.validate_path("/tmp/../var/log")
        assert result is not None

    def test_rejects_shell_metachar(self):
        with pytest.raises(ValueError):
            V.validate_path("/tmp/file;rm -rf /")


# ── URL ───────────────────────────────────────────────────────────────────────
class TestURL:
    def test_valid_https(self):
        assert V.validate_url("https://target.com") == "https://target.com"

    def test_valid_http_with_path(self):
        assert V.validate_url("http://10.0.0.1/login") == "http://10.0.0.1/login"

    def test_valid_bare_host(self):
        assert V.validate_url("target.corp.local") == "target.corp.local"

    def test_valid_bare_ip(self):
        assert V.validate_url("10.10.10.5") == "10.10.10.5"

    def test_rejects_javascript_scheme(self):
        with pytest.raises(ValueError):
            V.validate_url("javascript://evil")

    def test_rejects_file_scheme(self):
        with pytest.raises(ValueError):
            V.validate_url("file:///etc/passwd")

    def test_rejects_data_scheme(self):
        with pytest.raises(ValueError):
            V.validate_url("data:text/html,<script>alert(1)</script>")

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError):
            V.validate_url("https://target.com/\x00evil")

    def test_rejects_newline(self):
        with pytest.raises(ValueError):
            V.validate_url("https://target.com/\nX-Injected: header")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            V.validate_url("")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            V.validate_url("https://target.com/" + "a" * 2048)


# ── Device ID ─────────────────────────────────────────────────────────────────
class TestDeviceID:
    def test_usb_device(self):
        d = "USB\\VID_045E&PID_0719\\5&24AFAB68&0&1"
        assert V.validate_device_id(d) == d

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError):
            V.validate_device_id("USB\\VID;evil")


# ── Safe filename fragment ────────────────────────────────────────────────────
class TestSafeFilename:
    def test_normal(self):
        assert V.safe_filename_fragment("dc01.corp.local") == "dc01.corp.local"

    def test_replaces_spaces(self):
        assert "_" in V.safe_filename_fragment("my host")

    def test_dot_dot_returns_unknown(self):
        assert V.safe_filename_fragment("..") == "unknown"

    def test_empty_returns_unknown(self):
        assert V.safe_filename_fragment("") == "unknown"

    def test_truncates_long(self):
        assert len(V.safe_filename_fragment("a" * 200)) == 128


# ── Sanitize for display ──────────────────────────────────────────────────────
class TestSanitize:
    def test_strips_control_chars(self):
        result = V.sanitize_for_display("hello\x01world")
        assert "\x01" not in result

    def test_escapes_html(self):
        result = V.sanitize_for_display("<script>alert(1)</script>")
        assert "<script>" not in result
        assert "&lt;" in result

    def test_non_string_coerced(self):
        result = V.sanitize_for_display(42)
        assert result == "42"
