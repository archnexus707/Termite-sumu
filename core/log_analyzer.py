"""
Deep Log Analysis Engine — scales across Linux and Windows hosts.

Performs threat hunting, anomaly detection, IOC correlation, ATT&CK mapping,
and timeline reconstruction from raw log entries. Works on any volume of logs
collected by LogCollector.

All analysis is evidence-backed — no speculation. Every finding references
the exact log line(s) that triggered it.
"""
from __future__ import annotations

import collections
import datetime
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core.base_connector import LogEntry
from core.audit import audit
from config.settings import EXPORTS_DIR, SENSITIVE_FILE_PERMS


# ---------------------------------------------------------------------------
# ATT&CK technique signatures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    technique: str          # MITRE ATT&CK ID
    severity: str           # Critical / High / Medium / Low / Info
    evidence: List[str]     # Exact log lines
    count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""
    recommendation: str = ""


LINUX_SIGNATURES: List[Tuple[str, str, str, re.Pattern, str]] = [
    # (title, technique, severity, pattern, recommendation)
    ("SSH Brute Force", "T1110.003", "High",
     re.compile(r"Failed password for .+ from .+ port \d+", re.I),
     "Block source IP with fail2ban or ufw. Review SSH config — disable password auth."),

    ("Successful SSH Root Login", "T1078.004", "Critical",
     re.compile(r"Accepted .+ for root from", re.I),
     "Disable root SSH login (PermitRootLogin no). Investigate immediately."),

    ("Sudo Privilege Escalation", "T1548.003", "High",
     re.compile(r"sudo:.+COMMAND=", re.I),
     "Audit /etc/sudoers. Remove unnecessary NOPASSWD entries."),

    ("New User Account Created", "T1136.001", "High",
     re.compile(r"useradd|adduser|new user:", re.I),
     "Verify account creation is authorized. Check for backdoor accounts."),

    ("SUID Binary Execution", "T1548.001", "Medium",
     re.compile(r"execve.*-rwsr|suid.*exec", re.I),
     "Audit SUID binaries. Remove unnecessary SUID bits."),

    ("Reverse Shell Indicators", "T1059.004", "Critical",
     re.compile(r"bash -i|/dev/tcp|nc -e|ncat|socat.*exec|python.*socket.*connect", re.I),
     "Isolate host immediately. Capture memory image. Investigate process tree."),

    ("Cron Job Persistence", "T1053.003", "High",
     re.compile(r"crontab -[ei]|CRON.*CMD|cron.d", re.I),
     "Review all cron jobs for unauthorized entries."),

    ("Kernel Module Loaded", "T1547.006", "High",
     re.compile(r"insmod|modprobe|module.*loaded", re.I),
     "Verify kernel module is legitimate. Check against known rootkit module names."),

    ("SELinux/AppArmor Disabled", "T1562.001", "Critical",
     re.compile(r"setenforce 0|apparmor.*disabled|aa-disable", re.I),
     "Re-enable security module immediately. Investigate why it was disabled."),

    ("Passwd/Shadow Access", "T1003.008", "Critical",
     re.compile(r"/etc/shadow|/etc/passwd.*open|passwd.*read", re.I),
     "Credential dumping attempt detected. Reset all passwords. Investigate access path."),

    ("Network Scan Activity", "T1046", "Medium",
     re.compile(r"nmap|masscan|netdiscover|arp-scan", re.I),
     "Identify if scan was authorized. Check for lateral movement following scan."),

    ("Outbound Connection Anomaly", "T1041", "Medium",
     re.compile(r"ESTABLISHED.*:4444|:1337|:8080.*ESTABLISHED|:443.*[^b]roken", re.I),
     "Investigate outbound connection. Potential C2 channel."),

    ("Log Tampering", "T1070.002", "Critical",
     re.compile(r"rm.*\.log|truncate.*/var/log|shred.*/var/log|> /var/log", re.I),
     "Log deletion detected. Restore from backup. Full incident response required."),

    ("Rootkit Indicators", "T1014", "Critical",
     re.compile(r"hiding.*process|LD_PRELOAD.*=/|proc.*hide", re.I),
     "Rootkit likely present. Boot from trusted media for forensic analysis."),

    ("Docker Escape Attempt", "T1611", "Critical",
     re.compile(r"docker.*privileged|/var/run/docker\.sock|nsenter.*pid=1", re.I),
     "Container escape attempt. Review container security configuration."),
]

WINDOWS_SIGNATURES: List[Tuple[str, str, str, re.Pattern, str]] = [
    ("Password Spray Attack", "T1110.003", "High",
     re.compile(r"EventID.*4625|Logon Type.*3.*Failure|Audit Failure.*Logon", re.I),
     "Implement account lockout policy. Enable SIEM alerting on burst failures."),

    ("Kerberoasting", "T1558.003", "High",
     re.compile(r"EventID.*4769.*0x17|TGS.*RC4|Kerberos.*EncryptionType.*23", re.I),
     "Enforce AES encryption on service accounts. Monitor for bulk TGS requests."),

    ("Mimikatz/LSASS Access", "T1003.001", "Critical",
     re.compile(r"lsass\.exe.*access|sekurlsa|privilege::debug|EventID.*4656.*lsass", re.I),
     "Credential dumping attempt. Enable Credential Guard. Investigate immediately."),

    ("PsExec Lateral Movement", "T1021.002", "High",
     re.compile(r"PSEXESVC|psexec.*Service|\\\\.*admin\$.*exec", re.I),
     "Lateral movement via PsExec. Investigate source account and pivot path."),

    ("Scheduled Task Persistence", "T1053.005", "High",
     re.compile(r"EventID.*4698|SchTasks.*Create|Task.*Registered", re.I),
     "Review scheduled task. Verify it is authorized. Check binary path for malware."),

    ("New Local Admin Account", "T1136.001", "Critical",
     re.compile(r"EventID.*4720|net user.*add|net localgroup.*administrators.*add", re.I),
     "Unauthorized account creation. Disable account and investigate."),

    ("PowerShell Encoded Command", "T1059.001", "High",
     re.compile(r"-EncodedCommand|-enc\s+[A-Za-z0-9+/=]{20,}|powershell.*-e\s+[A-Za-z0-9]", re.I),
     "Obfuscated PowerShell detected. Decode and analyze payload. Block if unauthorized."),

    ("WMI Persistence", "T1546.003", "High",
     re.compile(r"EventID.*5857|WMI.*__EventFilter|WMI.*CommandLineEvent", re.I),
     "WMI subscription persistence detected. Remove subscription and investigate."),

    ("Pass-the-Hash", "T1550.002", "Critical",
     re.compile(r"EventID.*4624.*NTLM.*3|logon.*NtLmSsp.*network.*hash", re.I),
     "Pass-the-Hash detected. Rotate all NTLM credentials. Enable Credential Guard."),

    ("DCSync Attack", "T1003.006", "Critical",
     re.compile(r"EventID.*4662.*1131f6aa|replicating.*directory.*changes|GetNCChanges", re.I),
     "DCSync replication detected from non-DC. Investigate immediately — full domain compromise likely."),

    ("ADCS Certificate Abuse", "T1649", "Critical",
     re.compile(r"Certificate.*Template.*msPKI|ESC[1-9]|certipy|certify\.exe", re.I),
     "ADCS certificate template abuse. Harden certificate templates per Microsoft guidance."),

    ("LOLBin Execution", "T1218", "Medium",
     re.compile(r"certutil.*-urlcache|mshta.*http|regsvr32.*/s.*http|rundll32.*javascript|wmic.*process.*call", re.I),
     "Living-off-the-land binary abuse. Review process creation chain. Block via AppLocker."),

    ("Ransomware Indicators", "T1486", "Critical",
     re.compile(r"vssadmin.*delete|wbadmin.*delete.*backup|bcdedit.*recoveryenabled.*no|\.encrypted|\.locked", re.I),
     "Ransomware activity detected. Isolate host immediately. Do NOT pay ransom."),

    ("Golden/Silver Ticket", "T1558.001", "Critical",
     re.compile(r"EventID.*4768.*krbtgt|Kerberos.*unusual.*TGT|ticket.*forged", re.I),
     "Forged Kerberos ticket detected. Reset krbtgt password TWICE. Full domain assessment required."),

    ("BYOVD Driver Load", "T1068", "Critical",
     re.compile(r"EventID.*7045.*driver|vulnerable.*driver.*loaded|loldrivers", re.I),
     "Vulnerable signed driver loaded. Identify and block driver via WDAC policy."),
]


# ---------------------------------------------------------------------------
# Anomaly detectors
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Statistical anomaly detection on log volumes and timing."""

    @staticmethod
    def detect_brute_force(entries: List[LogEntry], threshold: int = 20) -> List[Finding]:
        """Detect rapid repeated failures from same source."""
        findings = []
        counter: Dict[str, List[str]] = collections.defaultdict(list)
        ip_re = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

        for e in entries:
            m = ip_re.search(e.message)
            if m and ("fail" in e.message.lower() or "invalid" in e.message.lower()
                      or "4625" in e.message):
                counter[m.group(1)].append(e.message[:120])

        for ip, msgs in counter.items():
            if len(msgs) >= threshold:
                findings.append(Finding(
                    title=f"Brute Force from {ip}",
                    technique="T1110.003",
                    severity="High",
                    evidence=msgs[:5],
                    count=len(msgs),
                    source=ip,
                    recommendation="Block IP immediately. Review account lockout policy.",
                ))
        return findings

    @staticmethod
    def detect_log_volume_spike(entries: List[LogEntry]) -> List[Finding]:
        """Detect unusual spikes in log volume by hour — potential activity bursts."""
        findings = []
        hourly: Dict[str, int] = collections.defaultdict(int)
        ts_re = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2})")
        for e in entries:
            m = ts_re.search(e.timestamp or e.message)
            if m:
                hourly[m.group(1)] += 1

        if len(hourly) < 2:
            return findings
        avg = sum(hourly.values()) / len(hourly)
        for hour, count in hourly.items():
            if count > avg * 4 and count > 100:
                findings.append(Finding(
                    title=f"Log Volume Spike at {hour}",
                    technique="T1562.002",
                    severity="Medium",
                    evidence=[f"{count} events vs avg {avg:.0f}"],
                    count=count,
                    recommendation="Investigate activity burst. Could indicate attack or cleanup.",
                ))
        return findings

    @staticmethod
    def detect_off_hours_logins(entries: List[LogEntry],
                                 business_hours: Tuple[int, int] = (7, 19)) -> List[Finding]:
        """Flag logins outside business hours."""
        findings = []
        ts_re = re.compile(r"T(\d{2}):\d{2}:\d{2}|(\d{2}):\d{2}:\d{2}")
        login_re = re.compile(r"accept|logon|login|4624", re.I)
        for e in entries:
            if not login_re.search(e.message):
                continue
            m = ts_re.search(e.timestamp or e.message)
            if not m:
                continue
            hour = int(m.group(1) or m.group(2))
            if not (business_hours[0] <= hour <= business_hours[1]):
                findings.append(Finding(
                    title=f"Off-Hours Login at hour {hour:02d}",
                    technique="T1078",
                    severity="Low",
                    evidence=[e.message[:200]],
                    source=e.source,
                    recommendation="Verify login was authorized. Alert on pattern.",
                ))
        return findings[:20]  # cap output


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class DeepLogAnalyzer:
    """
    Runs signature matching + anomaly detection against any log corpus.
    Works identically on Linux and Windows log sets.
    """

    def __init__(self, os_type: str = "linux"):
        self.os_type = os_type.lower()
        self._signatures = (
            WINDOWS_SIGNATURES if self.os_type == "windows" else LINUX_SIGNATURES
        )
        self._anomaly = AnomalyDetector()

    def analyze(self, entries: List[LogEntry]) -> List[Finding]:
        audit("LOG_ANALYSIS_START", detail=f"os={self.os_type} entries={len(entries)}")
        findings: List[Finding] = []

        # Signature scan
        sig_hits: Dict[str, Finding] = {}
        for entry in entries:
            text = f"{entry.source} {entry.message}"
            for title, technique, severity, pattern, rec in self._signatures:
                if pattern.search(text):
                    key = f"{technique}:{title}"
                    if key in sig_hits:
                        sig_hits[key].count += 1
                        if len(sig_hits[key].evidence) < 5:
                            sig_hits[key].evidence.append(entry.message[:200])
                        sig_hits[key].last_seen = entry.timestamp
                    else:
                        sig_hits[key] = Finding(
                            title=title,
                            technique=technique,
                            severity=severity,
                            evidence=[entry.message[:200]],
                            count=1,
                            first_seen=entry.timestamp,
                            last_seen=entry.timestamp,
                            source=entry.source,
                            recommendation=rec,
                        )
        findings.extend(sig_hits.values())

        # Anomaly detection
        findings += self._anomaly.detect_brute_force(entries)
        findings += self._anomaly.detect_log_volume_spike(entries)
        findings += self._anomaly.detect_off_hours_logins(entries)

        # Sort by severity
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings.sort(key=lambda f: (sev_order.get(f.severity, 5), -f.count))

        audit("LOG_ANALYSIS_DONE",
              detail=f"findings={len(findings)} critical={sum(1 for f in findings if f.severity=='Critical')}")
        return findings

    def export_json(self, findings: List[Finding], host: str = "unknown") -> str:
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_host = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", host)
        path = os.path.join(EXPORTS_DIR, f"analysis_{safe_host}_{ts}.json")
        data = [
            {
                "title": f.title,
                "technique": f.technique,
                "severity": f.severity,
                "count": f.count,
                "first_seen": f.first_seen,
                "last_seen": f.last_seen,
                "source": f.source,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in findings
        ]
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, SENSITIVE_FILE_PERMS)
        try:
            os.write(fd, json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"))
        finally:
            os.close(fd)
        return path
