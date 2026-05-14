from core.base_connector import BaseConnector, ConnectionProfile
from core.ssh_connector import SSHConnector
from core.winrm_connector import WinRMConnector
from core.smb_connector import SMBConnector
from core.telnet_connector import TelnetConnector


PROTOCOL_MAP = {
    "ssh": SSHConnector,
    "winrm": WinRMConnector,
    "smb": SMBConnector,
    "telnet": TelnetConnector,
}


def create_connector(profile: ConnectionProfile) -> BaseConnector:
    protocol = profile.protocol.lower().strip()
    cls = PROTOCOL_MAP.get(protocol)
    if cls is None:
        raise ValueError(f"Unsupported protocol: {protocol!r}. Choose from: {list(PROTOCOL_MAP)}")
    return cls(profile)
