"""
Go Backend Bridge — thin client for termite-go-backend REST API.

The Go binary handles all concurrent socket I/O (listeners, sessions,
payload generation).  This module is the Python-side client consumed by
the PyQt6 GUI.  It speaks plain JSON over HTTP to 127.0.0.1:9120.

Usage::

    from core.go_bridge import GoBackend

    go = GoBackend()
    go.start()            # launches the Go binary as a subprocess

    go.health()           # → {"status": "ok", ...}
    lid = go.start_listener("tcp", "0.0.0.0", 4444)
    go.stop_listener(lid)

    payload = go.generate_payload("bash", "10.0.0.1", 4444)
    ses = go.list_sessions()
    go.send_to_session(ses_id, "whoami")
    lines = go.drain_session(ses_id)

    go.shutdown()         # SIGTERM the Go process
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

import requests

from core.validators import SecureInputValidator
from config.settings import BASE_DIR


class GoBackend:
    """Client for the termite-go-backend REST API.

    The Go binary is launched as a subprocess on first use.  All calls
    are synchronous HTTP requests to ``127.0.0.1:9120``.
    """

    DEFAULT_ADDR = "http://127.0.0.1:9120"
    BINARY_NAME = "termite-go-backend"
    STARTUP_TIMEOUT = 5.0

    def __init__(self):
        self._proc: Optional[subprocess.Popen] = None
        self._addr = self.DEFAULT_ADDR
        self._binary = self._find_binary()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _find_binary(self) -> str:
        """Locate the compiled Go binary."""
        candidates = [
            os.path.join(BASE_DIR, "gobackend", self.BINARY_NAME),
            os.path.join(BASE_DIR, self.BINARY_NAME),
        ]
        found = shutil.which(self.BINARY_NAME)
        if found:
            candidates.insert(0, found)
        for c in candidates:
            if os.path.exists(c):
                return c
        raise FileNotFoundError(
            f"{self.BINARY_NAME} not found. Build it: "
            f"cd gobackend && go build -o {self.BINARY_NAME} ."
        )

    def start(self) -> bool:
        """Launch the Go server if not already running."""
        if self._proc is not None and self._proc.poll() is None:
            return True
        self._proc = subprocess.Popen(
            [self._binary],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + self.STARTUP_TIMEOUT
        while time.time() < deadline:
            try:
                r = requests.get(f"{self._addr}/health", timeout=1)
                if r.status_code == 200:
                    return True
            except requests.ConnectionError:
                pass
            time.sleep(0.2)
        return False

    def shutdown(self) -> None:
        """Graceful shutdown: SIGTERM, fallback SIGKILL after 5s."""
        if self._proc is None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        self._proc = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        r = requests.get(f"{self._addr}/health", timeout=3)
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Listeners
    # ------------------------------------------------------------------

    def list_listeners(self) -> List[Dict[str, Any]]:
        r = requests.get(f"{self._addr}/listeners", timeout=3)
        r.raise_for_status()
        return r.json()

    def start_listener(self, protocol: str, host: str, port: int) -> str:
        SecureInputValidator.validate_host(host)
        SecureInputValidator.validate_port(port)
        r = requests.post(
            f"{self._addr}/listeners",
            params={"protocol": protocol, "host": host, "port": str(port)},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()["id"]

    def stop_listener(self, listener_id: str) -> None:
        r = requests.delete(f"{self._addr}/listeners/{listener_id}", timeout=3)
        r.raise_for_status()

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def list_sessions(self) -> List[Dict[str, Any]]:
        r = requests.get(f"{self._addr}/sessions", timeout=3)
        r.raise_for_status()
        return r.json()

    def drain_session(self, session_id: str) -> Dict[str, Any]:
        r = requests.get(
            f"{self._addr}/sessions/{session_id}/output", timeout=3
        )
        r.raise_for_status()
        return r.json()

    def send_to_session(self, session_id: str, command: str) -> bool:
        r = requests.post(
            f"{self._addr}/sessions/{session_id}/send",
            data=command.encode("utf-8"),
            timeout=3,
        )
        return r.status_code == 200

    def kill_session(self, session_id: str) -> None:
        r = requests.delete(f"{self._addr}/sessions/{session_id}", timeout=3)
        r.raise_for_status()

    # ------------------------------------------------------------------
    # Payloads
    # ------------------------------------------------------------------

    def payload_types(self) -> List[str]:
        r = requests.get(f"{self._addr}/payloads/types", timeout=3)
        r.raise_for_status()
        return r.json()

    def generate_payload(self, ptype: str, lhost: str, lport: int) -> str:
        SecureInputValidator.validate_host(lhost)
        r = requests.get(
            f"{self._addr}/payloads/generate",
            params={"type": ptype, "lhost": lhost, "lport": str(lport)},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()["payload"]
