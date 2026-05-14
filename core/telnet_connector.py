import socket
import time
from typing import List, Optional

from core.base_connector import BaseConnector, ConnectionProfile, DeviceNode, LogEntry
from core.validators import SecureInputValidator
from config.settings import TELNET_DEFAULT_PORT


class TelnetConnector(BaseConnector):
    """
    Raw Telnet connector for legacy devices (routers, switches, embedded systems).
    WARNING: Telnet is unencrypted. Use only on isolated/lab networks.
    """

    BUFFER_SIZE = 4096
    READ_TIMEOUT = 3.0

    def __init__(self, profile: ConnectionProfile):
        super().__init__(profile)
        self._sock: Optional[socket.socket] = None
        self._banner: str = ""

    def connect(self) -> bool:
        host = SecureInputValidator.validate_host(self.profile.host)
        port = SecureInputValidator.validate_port(self.profile.port or TELNET_DEFAULT_PORT)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.profile.timeout)
            sock.connect((host, port))
            self._sock = sock
            self._banner = self._read_until_prompt(timeout=4.0)

            # Attempt login if credentials provided
            if self.profile.username:
                self._send(self.profile.username + "\r\n")
                time.sleep(0.5)
                self._read_until_prompt()
            if self.profile.password:
                self._send(self.profile.password + "\r\n")
                time.sleep(0.5)
                self._read_until_prompt()

            self._connected = True
            return True
        except (socket.timeout, OSError, ConnectionRefusedError) as exc:
            self._connected = False
            raise ConnectionError(f"Telnet connect failed: {exc}") from exc

    def _send(self, data: str) -> None:
        if self._sock:
            self._sock.sendall(data.encode("ascii", errors="replace"))

    def _read_until_prompt(self, timeout: float = READ_TIMEOUT) -> str:
        if not self._sock:
            return ""
        self._sock.settimeout(timeout)
        buf = b""
        try:
            while True:
                chunk = self._sock.recv(self.BUFFER_SIZE)
                if not chunk:
                    break
                buf += chunk
                # Stop on common prompts
                decoded = buf.decode(errors="replace")
                if any(decoded.endswith(p) for p in ["$ ", "# ", "> ", "$ \n", "# \n", "login: ", "Password: "]):
                    break
        except socket.timeout:
            pass
        return buf.decode(errors="replace")

    def disconnect(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._connected = False

    def execute_command(self, command: List[str]) -> tuple[int, str, str]:
        if not self._sock:
            raise RuntimeError("Not connected")
        # Join safely — Telnet is inherently a string protocol on legacy devices
        safe_cmd = " ".join(command) + "\r\n"
        self._send(safe_cmd)
        time.sleep(0.5)
        out = self._read_until_prompt()
        return 0, out, ""

    def get_raw_socket(self) -> Optional[socket.socket]:
        return self._sock

    def get_devices(self) -> List[DeviceNode]:
        # Telnet targets are typically network devices — get interface list
        _, out, _ = self.execute_command(["show", "interfaces"])
        devices = []
        if out:
            devices.append(DeviceNode(
                name="Interfaces",
                device_type="network",
                status="ok",
                properties={"output": out[:2048]},
            ))
        return devices

    def enable_device(self, device: DeviceNode) -> bool:
        return False

    def disable_device(self, device: DeviceNode) -> bool:
        return False

    def get_logs(self, sources: Optional[List[str]] = None) -> List[LogEntry]:
        _, out, _ = self.execute_command(["show", "log"])
        entries = []
        for line in out.splitlines():
            entries.append(LogEntry(
                timestamp="",
                source=f"telnet:{self.profile.host}",
                level="INFO",
                message=line,
                raw=line,
            ))
        return entries
