import re
import os
from config.settings import ALLOWED_HOSTNAME_RE, ALLOWED_IP_RE


class SecureInputValidator:
    """
    Single source of truth for every user-supplied or remote-supplied string
    that flows into a command, file path, log file path or PowerShell snippet.

    All validators raise ValueError on rejection; callers must never silently
    fall back to the raw value.
    """

    SAFE_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-\.\\@]{1,256}$')
    # SAFE_PATH_RE is intentionally narrow. It excludes shell metacharacters and
    # path-traversal sequences, while permitting Windows paths (backslash, colon).
    SAFE_PATH_RE = re.compile(r'^[a-zA-Z0-9_\-\./\\: ]{1,512}$')
    # Windows Plug-and-Play DeviceID / InstanceID — restricted set used in
    # PowerShell Enable-PnpDevice / Disable-PnpDevice. Allows the characters
    # used by Microsoft device IDs (USB\VID_xxxx&PID_yyyy\serial style).
    SAFE_DEVICE_ID_RE = re.compile(r'^[A-Za-z0-9_\-\\&{}\.\#]{1,512}$')
    # Windows Event Log channel name — letters, digits, dash, slash, space.
    SAFE_EVTLOG_NAME_RE = re.compile(r'^[A-Za-z0-9_\-/\\ ]{1,256}$')
    # Safe file-name fragment for session subdirectories.
    SAFE_FILENAME_FRAGMENT_RE = re.compile(r'^[A-Za-z0-9_\-\.]{1,128}$')
    SAFE_DOMAIN_RE = re.compile(r'^[A-Za-z0-9_\-\.]{1,128}$')
    SAFE_PORT_RANGE = (1, 65535)

    @staticmethod
    def validate_host(host: str) -> str:
        if host is None:
            raise ValueError("Host cannot be None")
        host = host.strip()
        if not host:
            raise ValueError("Host cannot be empty")
        if len(host) > 253:
            raise ValueError("Host too long")
        if ALLOWED_IP_RE.match(host) or ALLOWED_HOSTNAME_RE.match(host):
            return host
        raise ValueError(f"Invalid host: {host!r}")

    @staticmethod
    def validate_port(port) -> int:
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ValueError(f"Port must be an integer, got {port!r}")
        lo, hi = SecureInputValidator.SAFE_PORT_RANGE
        if not (lo <= port <= hi):
            raise ValueError(f"Port {port} out of range {lo}-{hi}")
        return port

    @staticmethod
    def validate_username(username: str) -> str:
        if username is None:
            raise ValueError("Username cannot be None")
        username = username.strip()
        if not SecureInputValidator.SAFE_USERNAME_RE.match(username):
            raise ValueError(f"Invalid username: {username!r}")
        return username

    @staticmethod
    def validate_domain(domain: str) -> str:
        if domain is None:
            raise ValueError("Domain cannot be None")
        domain = domain.strip()
        if not SecureInputValidator.SAFE_DOMAIN_RE.match(domain):
            raise ValueError(f"Invalid domain: {domain!r}")
        return domain

    @staticmethod
    def validate_path(path: str) -> str:
        if path is None:
            raise ValueError("Path cannot be None")
        path = path.strip()
        if not path:
            raise ValueError("Path cannot be empty")
        # Reject NUL byte — POSIX path-truncation attack vector.
        if "\x00" in path:
            raise ValueError("Path contains NUL byte")
        if not SecureInputValidator.SAFE_PATH_RE.match(path):
            raise ValueError(f"Path contains illegal characters: {path!r}")
        normalized = os.path.normpath(path)
        # Reject anywhere ``..`` survives normalization (i.e. relative escape).
        parts = normalized.replace("\\", "/").split("/")
        if ".." in parts:
            raise ValueError("Path traversal detected")
        return normalized

    @staticmethod
    def validate_device_id(device_id: str) -> str:
        """Validate a Windows PnP DeviceID / InstanceID for PowerShell consumption."""
        if device_id is None:
            raise ValueError("Device ID cannot be None")
        device_id = device_id.strip()
        if not SecureInputValidator.SAFE_DEVICE_ID_RE.match(device_id):
            raise ValueError(f"Invalid device ID: {device_id!r}")
        return device_id

    @staticmethod
    def validate_evtlog_name(name: str) -> str:
        """Validate a Windows Event Log channel name."""
        if name is None:
            raise ValueError("Event log name cannot be None")
        name = name.strip()
        if not SecureInputValidator.SAFE_EVTLOG_NAME_RE.match(name):
            raise ValueError(f"Invalid event log name: {name!r}")
        return name

    @staticmethod
    def safe_filename_fragment(text: str) -> str:
        """
        Coerce a string into a safe filesystem fragment for log session dirs
        and exported file names. Always succeeds (no exception) because this
        is only ever consumed by us, never the caller.
        """
        if not text:
            return "unknown"
        # Replace everything outside the safe set with underscore.
        cleaned = re.sub(r"[^A-Za-z0-9_\-\.]", "_", text)
        # Block names that resolve to parent dir.
        if cleaned in (".", "..", ""):
            return "unknown"
        return cleaned[:128]

    @staticmethod
    def validate_url(url: str) -> str:
        """
        Validate a URL safe to pass as a CLI argument (never via shell=True).

        Accepts:
          - Full URLs with http:// / https:// / ftp:// scheme
          - Bare hostnames or IPv4 addresses (with optional port / path)
        Rejects:
          - Empty strings, NUL bytes, newlines (control char injection)
          - Anything longer than 2 048 characters
          - Strings that are neither a recognised scheme nor a valid host
        """
        if not url:
            raise ValueError("URL cannot be empty")
        url = url.strip()
        if len(url) > 2048:
            raise ValueError("URL exceeds 2048 characters")
        if any(c in url for c in ('\x00', '\n', '\r')):
            raise ValueError("URL contains illegal control characters")
        _SCHEMES = ('http://', 'https://', 'ftp://')
        if '://' in url:
            # Has a scheme component — must be one of the approved schemes.
            # Anything else (javascript://, file://, data://, etc.) is rejected.
            if not any(url.startswith(s) for s in _SCHEMES):
                raise ValueError(f"Unsupported URL scheme: {url!r}")
            return url
        # No scheme — must be a bare hostname or IP (with optional :port / path)
        bare = url.split(':')[0].split('/')[0]
        if ALLOWED_IP_RE.match(bare) or ALLOWED_HOSTNAME_RE.match(bare):
            return url
        raise ValueError(f"Invalid URL or host: {url!r}")

    @staticmethod
    def sanitize_for_display(text: str) -> str:
        if not isinstance(text, str):
            text = str(text)
        # Strip control characters that could break terminal rendering and
        # escape HTML metacharacters in case a widget later renders as rich.
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        return (
            text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;")
        )
