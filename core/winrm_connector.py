import re
from typing import List, Optional

import winrm

from core.base_connector import BaseConnector, ConnectionProfile, DeviceNode, LogEntry
from core.validators import SecureInputValidator
from config.settings import WINDOWS_LOG_SOURCES, WINRM_HTTP_PORT, WINRM_HTTPS_PORT


class WinRMConnector(BaseConnector):
    def __init__(self, profile: ConnectionProfile):
        super().__init__(profile)
        self._session: Optional[winrm.Session] = None

    def connect(self) -> bool:
        host = SecureInputValidator.validate_host(self.profile.host)
        port = SecureInputValidator.validate_port(self.profile.port or (WINRM_HTTPS_PORT if self.profile.use_tls else WINRM_HTTP_PORT))
        username = SecureInputValidator.validate_username(self.profile.username)

        scheme = "https" if self.profile.use_tls else "http"
        endpoint = f"{scheme}://{host}:{port}/wsman"

        try:
            self._session = winrm.Session(
                endpoint,
                auth=(username, self.profile.password or ""),
                transport="ntlm",
                server_cert_validation="ignore" if self.profile.use_tls else "ignore",
            )
            # Test connection
            result = self._session.run_cmd("echo", ["connected"])
            self._connected = result.status_code == 0
            return self._connected
        except Exception as exc:
            self._connected = False
            raise ConnectionError(f"WinRM connect failed: {exc}") from exc

    def disconnect(self) -> None:
        self._session = None
        self._connected = False

    def execute_command(self, command: List[str]) -> tuple[int, str, str]:
        if not self._session:
            raise RuntimeError("Not connected")
        if not command:
            raise ValueError("Command list cannot be empty")
        exe = command[0]
        args = command[1:]
        result = self._session.run_cmd(exe, args)
        return (
            result.status_code,
            result.std_out.decode(errors="replace"),
            result.std_err.decode(errors="replace"),
        )

    def run_ps(self, script: str) -> tuple[int, str, str]:
        if not self._session:
            raise RuntimeError("Not connected")
        result = self._session.run_ps(script)
        return (
            result.status_code,
            result.std_out.decode(errors="replace"),
            result.std_err.decode(errors="replace"),
        )

    def get_devices(self) -> List[DeviceNode]:
        devices = []
        ps_script = (
            "Get-PnpDevice | Select-Object -Property Name,Class,Status,DeviceID,Manufacturer,HardwareID "
            "| ConvertTo-Json -Depth 2"
        )
        code, out, _ = self.run_ps(ps_script)
        if code == 0 and out.strip():
            import json
            try:
                raw = json.loads(out)
                if isinstance(raw, dict):
                    raw = [raw]
                for item in raw:
                    node = DeviceNode(
                        name=item.get("Name", "Unknown"),
                        device_type=item.get("Class", "Unknown"),
                        status=item.get("Status", "Unknown"),
                        properties={
                            "DeviceID": str(item.get("DeviceID", "")),
                            "Manufacturer": str(item.get("Manufacturer", "")),
                            "HardwareID": str(item.get("HardwareID", "")),
                        },
                        raw_path=str(item.get("DeviceID", "")),
                    )
                    devices.append(node)
            except Exception:
                pass
        return devices

    def enable_device(self, device: DeviceNode) -> bool:
        if not device.raw_path:
            return False
        safe_id = re.sub(r"[^a-zA-Z0-9_\-\\&{}]", "", device.raw_path)
        code, _, _ = self.run_ps(f"Enable-PnpDevice -InstanceId '{safe_id}' -Confirm:$false")
        return code == 0

    def disable_device(self, device: DeviceNode) -> bool:
        if not device.raw_path:
            return False
        safe_id = re.sub(r"[^a-zA-Z0-9_\-\\&{}]", "", device.raw_path)
        code, _, _ = self.run_ps(f"Disable-PnpDevice -InstanceId '{safe_id}' -Confirm:$false")
        return code == 0

    def get_logs(self, sources: Optional[List[str]] = None) -> List[LogEntry]:
        if sources is None:
            sources = WINDOWS_LOG_SOURCES
        entries = []
        for source in sources:
            safe_source = re.sub(r"[^a-zA-Z0-9_\-/\\ ]", "", source)
            ps_script = (
                f"Get-WinEvent -LogName '{safe_source}' -MaxEvents 2000 -ErrorAction SilentlyContinue "
                f"| Select-Object TimeCreated,LevelDisplayName,Message "
                f"| ConvertTo-Json -Depth 1"
            )
            code, out, _ = self.run_ps(ps_script)
            if code == 0 and out.strip():
                import json
                try:
                    raw = json.loads(out)
                    if isinstance(raw, dict):
                        raw = [raw]
                    for item in raw:
                        entries.append(LogEntry(
                            timestamp=str(item.get("TimeCreated", "")),
                            source=source,
                            level=str(item.get("LevelDisplayName", "INFO")),
                            message=str(item.get("Message", ""))[:512],
                            raw=str(item),
                        ))
                except Exception:
                    pass
        return entries

    def open_interactive_shell(self) -> None:
        raise NotImplementedError("Use SSH or SMB for interactive shell on Windows")
