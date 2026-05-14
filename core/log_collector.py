import datetime
import json
import os
from typing import List, Dict, Any, Optional

from core.base_connector import BaseConnector, LogEntry
from config.settings import LOGS_DIR, WINDOWS_LOG_SOURCES, LINUX_LOG_SOURCES, SENSITIVE_FILE_PERMS


class LogCollector:
    def __init__(self, connector: BaseConnector):
        self.connector = connector
        self._session_dir = os.path.join(
            LOGS_DIR,
            f"{connector.profile.host}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        )
        os.makedirs(self._session_dir, mode=0o700, exist_ok=True)

    def collect_all(self, os_type: str = "linux") -> Dict[str, List[LogEntry]]:
        sources = WINDOWS_LOG_SOURCES if os_type == "windows" else LINUX_LOG_SOURCES
        results: Dict[str, List[LogEntry]] = {}
        for source in sources:
            try:
                entries = self.connector.get_logs([source])
                if entries:
                    results[source] = entries
                    self._save_log(source, entries)
            except Exception:
                pass
        return results

    def _save_log(self, source: str, entries: List[LogEntry]) -> None:
        safe_name = source.replace("/", "_").replace("\\", "_").replace(" ", "_").replace(":", "_")
        path = os.path.join(self._session_dir, f"{safe_name}.json")
        data = [
            {"timestamp": e.timestamp, "source": e.source, "level": e.level, "message": e.message}
            for e in entries
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.chmod(path, SENSITIVE_FILE_PERMS)

    def collect_windows_evtx(self) -> List[LogEntry]:
        """Collect Windows event logs via WinRM PowerShell."""
        all_entries: List[LogEntry] = []
        for source in WINDOWS_LOG_SOURCES:
            try:
                entries = self.connector.get_logs([source])
                all_entries.extend(entries)
            except Exception:
                pass
        return all_entries

    def collect_sysmon(self) -> List[LogEntry]:
        """Dedicated Sysmon event log collector."""
        return self.connector.get_logs(["Microsoft-Windows-Sysmon/Operational"])

    def collect_security(self) -> List[LogEntry]:
        return self.connector.get_logs(["Security"])

    def collect_powershell(self) -> List[LogEntry]:
        return self.connector.get_logs(["Microsoft-Windows-PowerShell/Operational"])

    def export_json(self, entries: List[LogEntry], label: str = "export") -> str:
        from config.settings import EXPORTS_DIR
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(EXPORTS_DIR, f"logs_{label}_{ts}.json")
        data = [
            {"timestamp": e.timestamp, "source": e.source, "level": e.level, "message": e.message}
            for e in entries
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.chmod(path, SENSITIVE_FILE_PERMS)
        return path

    @property
    def session_dir(self) -> str:
        return self._session_dir
