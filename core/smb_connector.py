import os
import subprocess
from typing import List, Optional

from core.base_connector import BaseConnector, ConnectionProfile, DeviceNode, LogEntry
from core.validators import SecureInputValidator
from config.settings import SMB_DEFAULT_PORT


class SMBConnector(BaseConnector):
    """
    SMB connector using impacket CLI tools (smbclient, psexec, wmiexec).
    Provides remote command execution and log retrieval via SMB shares.
    """

    def __init__(self, profile: ConnectionProfile):
        super().__init__(profile)
        self._target: str = ""

    def connect(self) -> bool:
        host = SecureInputValidator.validate_host(self.profile.host)
        port = SecureInputValidator.validate_port(self.profile.port or SMB_DEFAULT_PORT)
        self._target = host

        # Test SMB reachability with smbclient -L
        cmd = self._build_smbclient_cmd(["-L", f"//{host}/", "-p", str(port)])
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.profile.timeout,
            )
            self._connected = result.returncode == 0 or "Sharename" in result.stdout
            return self._connected
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            raise ConnectionError(f"SMB connect failed: {exc}") from exc

    def _build_smbclient_cmd(self, extra_args: List[str]) -> List[str]:
        username = SecureInputValidator.validate_username(self.profile.username)
        cmd = ["smbclient", "--no-pass"]
        if self.profile.password:
            cmd = ["smbclient"]
            cmd += ["-U", f"{username}%{self.profile.password}"]
        else:
            cmd += ["-U", username]
        if self.profile.domain:
            cmd += ["-W", self.profile.domain]
        cmd += extra_args
        return cmd

    def _build_wmiexec_cmd(self, command: str) -> List[str]:
        username = SecureInputValidator.validate_username(self.profile.username)
        host = self._target
        if self.profile.domain:
            target = f"{self.profile.domain}/{username}:{self.profile.password or ''}@{host}"
        else:
            target = f"{username}:{self.profile.password or ''}@{host}"
        return ["impacket-wmiexec", "-nointeractive", target, command]

    def disconnect(self) -> None:
        self._connected = False

    def execute_command(self, command: List[str]) -> tuple[int, str, str]:
        if not self._connected:
            raise RuntimeError("Not connected")
        cmd_str = " ".join(command)
        full_cmd = self._build_wmiexec_cmd(cmd_str)
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode, result.stdout, result.stderr

    def get_devices(self) -> List[DeviceNode]:
        code, out, _ = self.execute_command(
            ["wmic", "path", "Win32_PnPEntity", "get", "Name,DeviceID,Status,Manufacturer", "/format:csv"]
        )
        devices = []
        if code == 0:
            for line in out.splitlines()[1:]:
                parts = line.split(",")
                if len(parts) >= 4:
                    devices.append(DeviceNode(
                        name=parts[1].strip() if len(parts) > 1 else "Unknown",
                        device_type="PnP",
                        status=parts[3].strip() if len(parts) > 3 else "Unknown",
                        properties={"DeviceID": parts[2].strip() if len(parts) > 2 else ""},
                        raw_path=parts[2].strip() if len(parts) > 2 else "",
                    ))
        return devices

    def enable_device(self, device: DeviceNode) -> bool:
        return False  # Enable/disable via SMB not supported — use WinRM

    def disable_device(self, device: DeviceNode) -> bool:
        return False

    def get_logs(self, sources: Optional[List[str]] = None) -> List[LogEntry]:
        entries = []
        code, out, _ = self.execute_command(
            ["wevtutil", "qe", "System", "/c:1000", "/rd:true", "/f:Text"]
        )
        if code == 0:
            for line in out.splitlines():
                entries.append(LogEntry(
                    timestamp="",
                    source="System(SMB)",
                    level="INFO",
                    message=line,
                    raw=line,
                ))
        return entries

    def list_shares(self) -> List[str]:
        host = SecureInputValidator.validate_host(self._target)
        cmd = self._build_smbclient_cmd(["-L", f"//{host}/"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        shares = []
        for line in result.stdout.splitlines():
            if "Disk" in line or "IPC" in line:
                parts = line.split()
                if parts:
                    shares.append(parts[0])
        return shares

    def open_psexec_shell(self) -> subprocess.Popen:
        username = SecureInputValidator.validate_username(self.profile.username)
        host = SecureInputValidator.validate_host(self._target)
        if self.profile.domain:
            target = f"{self.profile.domain}/{username}:{self.profile.password or ''}@{host}"
        else:
            target = f"{username}:{self.profile.password or ''}@{host}"
        cmd = ["impacket-psexec", target]
        return subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
