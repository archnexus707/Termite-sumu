"""
Local security audit logger.

Every connection attempt, command execution, log collection, enable/disable
operation, dry-run invocation and credential lifecycle event MUST be written
through ``audit()``. The audit log is the forensic record of operator action
on this workstation and is the only way to reconstruct what was done against
a target after the fact.

File: ``logs/audit.log``
Permissions: 0o600 (owner read/write only)
Format: ISO-8601 UTC timestamp | actor | action | host | target_user | detail
The file is opened append-only with a per-write lock so concurrent threads in
the GUI cannot interleave partial records.

Never write raw credentials, tokens, key material or PII through this logger.
``detail`` strings are best-effort scrubbed of common secret patterns, but the
calling code is responsible for not passing secrets in the first place.
"""

from __future__ import annotations

import datetime
import getpass
import os
import re
import threading
from typing import Optional

from config.settings import AUDIT_LOG_PATH, SENSITIVE_FILE_PERMS

_LOCK = threading.Lock()

# Best-effort scrubbing patterns. We never want a password landing in the log.
_SCRUB_PATTERNS = [
    (re.compile(r'(password\s*[:=]\s*)\S+', re.IGNORECASE), r'\1***REDACTED***'),
    (re.compile(r'(pwd\s*[:=]\s*)\S+', re.IGNORECASE), r'\1***REDACTED***'),
    (re.compile(r'(token\s*[:=]\s*)\S+', re.IGNORECASE), r'\1***REDACTED***'),
    (re.compile(r'(api[_-]?key\s*[:=]\s*)\S+', re.IGNORECASE), r'\1***REDACTED***'),
    # user%password style (smbclient)
    (re.compile(r'(-U\s+\S+)%\S+'), r'\1%***REDACTED***'),
    # user:password@host style
    (re.compile(r'([A-Za-z0-9_.\-\\]+):\S+@'), r'\1:***REDACTED***@'),
]


def _scrub(text: str) -> str:
    if not text:
        return ""
    out = text
    for pat, repl in _SCRUB_PATTERNS:
        out = pat.sub(repl, out)
    # Hard cap so a runaway message can't fill the audit log
    return out[:2048].replace("\n", " ").replace("\r", " ")


def _ensure_log_file() -> None:
    """Create the audit log with restrictive perms on first use."""
    if not os.path.exists(AUDIT_LOG_PATH):
        # os.open with O_CREAT|O_EXCL is race-safe vs. symlink-replace.
        try:
            fd = os.open(
                AUDIT_LOG_PATH,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                SENSITIVE_FILE_PERMS,
            )
            os.close(fd)
        except FileExistsError:
            pass
    # Re-enforce perms on every call in case the file was touched externally.
    try:
        os.chmod(AUDIT_LOG_PATH, SENSITIVE_FILE_PERMS)
    except OSError:
        pass


def audit(
    action: str,
    host: str = "-",
    target_user: str = "-",
    detail: str = "",
    actor: Optional[str] = None,
) -> None:
    """
    Write one audit record. Never raises; failure here must not break the app
    flow, but is itself logged to stderr so it's still visible to the operator.
    """
    try:
        _ensure_log_file()
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        local_actor = actor or getpass.getuser()
        line = (
            f"{ts} | actor={local_actor} | action={action} | "
            f"host={_scrub(host)} | target_user={_scrub(target_user)} | "
            f"detail={_scrub(detail)}\n"
        )
        with _LOCK:
            # O_APPEND ensures atomic append on POSIX even with concurrent writers.
            fd = os.open(
                AUDIT_LOG_PATH,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                SENSITIVE_FILE_PERMS,
            )
            try:
                os.write(fd, line.encode("utf-8", errors="replace"))
            finally:
                os.close(fd)
    except Exception as exc:
        # Last resort: at least surface that auditing failed.
        import sys
        print(f"[AUDIT-FAIL] {action}: {exc}", file=sys.stderr)
