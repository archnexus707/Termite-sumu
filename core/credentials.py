"""
Credential lifecycle helpers.

Python strings are immutable, so true memory zeroing of a ``str`` is not
possible without ctypes hacks that violate CPython's invariants. The next
best thing is:

  1. Hold credentials in a ``bytearray`` we can zero with ``zero_bytes()``.
  2. Use ``SecretBytes`` as a context manager so the buffer is wiped at the
     end of the ``with`` block even on exception.
  3. Encourage callers to convert to bytearray as early as possible and to
     drop their string reference (``password = None``) once the bytearray
     exists, so the GC can reclaim the original.

This does NOT defeat a memory-resident attacker — only forensic recovery from
a memory dump captured *after* the secret was wiped. That is still meaningful
for our threat model (lost laptop, hibernation file, swap, core dump).
"""

from __future__ import annotations

from typing import Optional


def zero_bytes(buf: Optional[bytearray]) -> None:
    """Overwrite every byte of a mutable buffer with 0x00."""
    if buf is None:
        return
    if not isinstance(buf, bytearray):
        # We can't reliably zero a non-mutable type; silently no-op.
        return
    for i in range(len(buf)):
        buf[i] = 0


class SecretBytes:
    """Mutable credential buffer that wipes itself on context exit."""

    __slots__ = ("_buf",)

    def __init__(self, value):
        if value is None:
            self._buf: Optional[bytearray] = None
        elif isinstance(value, bytearray):
            self._buf = value
        elif isinstance(value, (bytes, str)):
            data = value.encode("utf-8") if isinstance(value, str) else value
            self._buf = bytearray(data)
        else:
            raise TypeError(f"Unsupported secret type: {type(value).__name__}")

    def get(self) -> str:
        """Return the secret as ``str`` for libs that require it (paramiko, winrm).

        The caller MUST minimise the lifetime of the returned string. Prefer to
        pass straight into the consuming API and let it go out of scope.
        """
        if self._buf is None:
            return ""
        return self._buf.decode("utf-8", errors="replace")

    def is_empty(self) -> bool:
        return self._buf is None or len(self._buf) == 0

    def wipe(self) -> None:
        zero_bytes(self._buf)
        self._buf = None

    def __enter__(self) -> "SecretBytes":
        return self

    def __exit__(self, *_exc):
        self.wipe()

    def __repr__(self) -> str:
        return "SecretBytes(***REDACTED***)"

    # Defensive: prevent accidental logging
    def __str__(self) -> str:
        return "***REDACTED***"
