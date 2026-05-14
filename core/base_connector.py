from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class ConnectionProfile:
    host: str
    port: int
    username: str
    password: Optional[str] = None
    key_path: Optional[str] = None
    domain: Optional[str] = None
    protocol: str = "ssh"
    timeout: int = 10
    use_tls: bool = False


@dataclass
class DeviceNode:
    name: str
    device_type: str
    status: str
    properties: Dict[str, str] = field(default_factory=dict)
    children: List["DeviceNode"] = field(default_factory=list)
    raw_path: str = ""


@dataclass
class LogEntry:
    timestamp: str
    source: str
    level: str
    message: str
    raw: str = ""


class BaseConnector(ABC):
    def __init__(self, profile: ConnectionProfile):
        self.profile = profile
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    @abstractmethod
    def connect(self) -> bool:
        pass

    @abstractmethod
    def disconnect(self) -> None:
        pass

    @abstractmethod
    def get_devices(self) -> List[DeviceNode]:
        pass

    @abstractmethod
    def enable_device(self, device: DeviceNode) -> bool:
        pass

    @abstractmethod
    def disable_device(self, device: DeviceNode) -> bool:
        pass

    @abstractmethod
    def get_logs(self, sources: List[str]) -> List[LogEntry]:
        pass

    @abstractmethod
    def execute_command(self, command: List[str]) -> tuple[int, str, str]:
        """Returns (exit_code, stdout, stderr). Command must be a list — no shell=True."""
        pass

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()
