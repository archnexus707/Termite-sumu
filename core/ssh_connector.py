import os
import shlex
import socket
import threading
from typing import List, Optional

import paramiko

from core.base_connector import BaseConnector, ConnectionProfile, DeviceNode, LogEntry
from core.validators import SecureInputValidator
from config.settings import LINUX_LOG_SOURCES, CONNECTION_TIMEOUT


class SSHConnector(BaseConnector):
    def __init__(self, profile: ConnectionProfile):
        super().__init__(profile)
        self._client: Optional[paramiko.SSHClient] = None
        self._shell: Optional[paramiko.Channel] = None
        self._lock = threading.Lock()

    def connect(self) -> bool:
        host = SecureInputValidator.validate_host(self.profile.host)
        port = SecureInputValidator.validate_port(self.profile.port)
        username = SecureInputValidator.validate_username(self.profile.username)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        known_hosts = os.path.expanduser("~/.ssh/known_hosts")
        if os.path.exists(known_hosts):
            client.load_host_keys(known_hosts)
        else:
            # Accept on first connect, then pin — warn user
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = dict(
            hostname=host,
            port=port,
            username=username,
            timeout=CONNECTION_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )

        if self.profile.key_path:
            key_path = SecureInputValidator.validate_path(self.profile.key_path)
            connect_kwargs["key_filename"] = key_path
        elif self.profile.password:
            connect_kwargs["password"] = self.profile.password

        try:
            client.connect(**connect_kwargs)
            self._client = client
            self._connected = True
            return True
        except (paramiko.AuthenticationException,
                paramiko.SSHException,
                socket.timeout,
                OSError) as exc:
            self._connected = False
            raise ConnectionError(f"SSH connect failed: {exc}") from exc

    def disconnect(self) -> None:
        if self._shell:
            try:
                self._shell.close()
            except Exception:
                pass
            self._shell = None
        if self._client:
            self._client.close()
            self._client = None
        self._connected = False

    def execute_command(self, command: List[str]) -> tuple[int, str, str]:
        if not self._client:
            raise RuntimeError("Not connected")
        safe_cmd = " ".join(shlex.quote(arg) for arg in command)
        with self._lock:
            _, stdout, stderr = self._client.exec_command(safe_cmd, timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            return exit_code, stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace")

    def open_interactive_shell(self) -> paramiko.Channel:
        if not self._client:
            raise RuntimeError("Not connected")
        transport = self._client.get_transport()
        channel = transport.open_session()
        channel.get_pty(term="xterm-256color", width=220, height=50)
        channel.invoke_shell()
        self._shell = channel
        return channel

    def get_devices(self) -> List[DeviceNode]:
        devices = []
        categories = {
            "PCI": ["/usr/bin/lspci", "-vmm"],
            "USB": ["/usr/bin/lsusb", "-v"],
            "Block": ["/bin/lsblk", "-J", "-o", "NAME,TYPE,SIZE,MODEL,VENDOR,STATE,TRAN"],
            "Network": ["/sbin/ip", "-j", "link", "show"],
        }
        for cat, cmd in categories.items():
            try:
                code, out, _ = self.execute_command(cmd)
                if code == 0 and out.strip():
                    node = DeviceNode(
                        name=cat,
                        device_type="category",
                        status="ok",
                        properties={"raw_output": out[:4096]},
                    )
                    devices.append(node)
            except Exception:
                pass

        # udev tree
        code, out, _ = self.execute_command(["find", "/sys/bus", "-name", "uevent", "-maxdepth", "5"])
        if code == 0:
            for line in out.splitlines()[:200]:
                path = line.strip().replace("/uevent", "")
                node = DeviceNode(
                    name=os.path.basename(path),
                    device_type="udev",
                    status="present",
                    raw_path=path,
                )
                devices.append(node)
        return devices

    def enable_device(self, device: DeviceNode) -> bool:
        if not device.raw_path:
            return False
        path = SecureInputValidator.validate_path(device.raw_path)
        bind_path = f"{path}/driver/bind"
        device_id = os.path.basename(path)
        code, _, _ = self.execute_command(["bash", "-c", f"echo {shlex.quote(device_id)} > {shlex.quote(bind_path)}"])
        return code == 0

    def disable_device(self, device: DeviceNode) -> bool:
        if not device.raw_path:
            return False
        path = SecureInputValidator.validate_path(device.raw_path)
        unbind_path = f"{path}/driver/unbind"
        device_id = os.path.basename(path)
        code, _, _ = self.execute_command(["bash", "-c", f"echo {shlex.quote(device_id)} > {shlex.quote(unbind_path)}"])
        return code == 0

    def get_logs(self, sources: Optional[List[str]] = None) -> List[LogEntry]:
        if sources is None:
            sources = LINUX_LOG_SOURCES
        entries = []
        for log_path in sources:
            safe_path = SecureInputValidator.validate_path(log_path)
            code, out, _ = self.execute_command(["tail", "-n", "1000", safe_path])
            if code == 0:
                for line in out.splitlines():
                    entries.append(LogEntry(
                        timestamp="",
                        source=log_path,
                        level="INFO",
                        message=line,
                        raw=line,
                    ))
        # journalctl
        code, out, _ = self.execute_command(["journalctl", "-n", "5000", "--no-pager", "-o", "short-iso"])
        if code == 0:
            for line in out.splitlines():
                entries.append(LogEntry(
                    timestamp=line[:25] if len(line) > 25 else "",
                    source="journalctl",
                    level="INFO",
                    message=line,
                    raw=line,
                ))
        return entries
