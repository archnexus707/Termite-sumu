"""
Defensive / Blue Team Analysis Engine.

Provides: YARA rule scanning, IOC matching, file integrity checking,
and threat intelligence correlation stubs.
Read-only defensive analysis — never modifies target systems.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.audit import audit
from core.validators import SecureInputValidator
from config.settings import LOGS_DIR, SENSITIVE_FILE_PERMS


# Built-in IOC patterns — extendable
_IOC_PATTERNS = [
    (re.compile(r"(?:cobaltstrike|metasploit|meterpreter|covenant|sliver|brute ratel|havoc)", re.I), "C2 Framework"),
    (re.compile(r"(?:mimikatz|sekurlsa|pypykatz|lsadump|procdump)", re.I), "Credential Dumper"),
    (re.compile(r"(?:eternalblue|bluekeep|zerologon|log4shell|proxyshell|proxylogon)", re.I), "Known Exploit"),
    (re.compile(r"(?:ransom|encrypt|decrypt|\.locked|\.encrypted|readme.*bitcoin)", re.I), "Ransomware"),
    (re.compile(r"(?:keylog|hook.*keyboard|GetAsyncKeyState|SetWindowsHookEx)", re.I), "Keylogger"),
    (re.compile(r"(?:rat|backdoor|trojan|downloader|dropper|injector|binder)", re.I), "Malware Category"),
    (re.compile(r"(?:sandbox|vmware|virtualbox|vbox|qemu|debugger|ida|ollydbg|x64dbg|windbg)", re.I), "Anti-Analysis"),
    (re.compile(r"(?:bitcoin|monero|ethereum|wallet|0x[a-fA-F0-9]{40})", re.I), "Cryptocurrency"),
]


@dataclass
class DefenseReport:
    path: str
    size: int
    hashes: Dict[str, str] = field(default_factory=dict)
    ioc_matches: List[Dict] = field(default_factory=list)
    yara_matches: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    threat_score: int = 0  # 0-100
    verdict: str = ""
    recommendations: List[str] = field(default_factory=list)


class DefenseScanner:
    """Defensive analysis engine — YARA, IOC, threat scoring."""

    @staticmethod
    def _run(cmd: List[str], timeout: int = 30) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip()
        except Exception:
            return ""

    @classmethod
    def scan_file(cls, filepath: str) -> DefenseReport:
        path = SecureInputValidator.validate_path(filepath)
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")

        report = DefenseReport(path=path, size=os.path.getsize(path))
        audit("DEFENSE_SCAN", detail=f"path={path}")

        # Hashes
        with open(path, "rb") as f:
            data = f.read()
        report.hashes = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

        # Strings extraction
        strings_out = cls._run(["strings", "-n", "6", path])

        # IOC matching
        for line in strings_out.split("\n"):
            for pat, cat in _IOC_PATTERNS:
                m = pat.search(line)
                if m:
                    match = {"category": cat, "match": m.group(0), "line": line.strip()[:200]}
                    if match not in report.ioc_matches:
                        report.ioc_matches.append(match)
                    if match["match"] not in report.suspicious_strings:
                        report.suspicious_strings.append(match["match"])

        # YARA scan if yara is installed
        if shutil.which("yara"):
            cls._yara_scan(path, report)

        # Threat scoring
        score = 0
        categories = set(m["category"] for m in report.ioc_matches)
        if "C2 Framework" in categories: score += 30
        if "Credential Dumper" in categories: score += 25
        if "Known Exploit" in categories: score += 20
        if "Ransomware" in categories: score += 30
        if "Keylogger" in categories: score += 15
        if "Malware Category" in categories: score += 20
        if "Anti-Analysis" in categories: score += 5
        if report.yara_matches: score += 20
        report.threat_score = min(score, 100)

        if score >= 70:
            report.verdict = "CRITICAL — multiple high-confidence threat indicators"
        elif score >= 40:
            report.verdict = "HIGH — significant threat indicators detected"
        elif score >= 15:
            report.verdict = "MEDIUM — suspicious indicators"
        elif score > 0:
            report.verdict = "LOW — minor indicators"
        else:
            report.verdict = "Clean — no threat indicators detected"

        # Recommendations
        if "C2 Framework" in categories:
            report.recommendations.append("Block identified C2 domains/IPs at firewall")
        if "Credential Dumper" in categories:
            report.recommendations.append("Rotate all credentials; enable Credential Guard")
        if "Ransomware" in categories:
            report.recommendations.append("Isolate host immediately; verify backups")
        if report.threat_score >= 50:
            report.recommendations.append("Escalate to incident response team")
        if not report.recommendations:
            report.recommendations.append("No immediate action required")

        return report

    @classmethod
    def _yara_scan(cls, path: str, report: DefenseReport) -> None:
        """Run YARA rules against the target file."""
        # Use any .yar files in the project's rules directory
        rules_dir = os.path.join(os.path.dirname(os.path.dirname(path)), "rules")
        if not os.path.isdir(rules_dir):
            rules_dir = os.path.join(LOGS_DIR, "rules")
        if not os.path.isdir(rules_dir):
            return  # No rules directory — skip YARA
        for root, dirs, files in os.walk(rules_dir):
            for fn in files:
                if fn.endswith((".yar", ".yara")):
                    rule_path = os.path.join(root, fn)
                    out = cls._run(["yara", "-s", rule_path, path])
                    if out.strip():
                        report.yara_matches.append(f"{fn}: {out[:300]}")

    @classmethod
    def scan_directory(cls, dirpath: str) -> List[DefenseReport]:
        reports = []
        path = SecureInputValidator.validate_path(dirpath)
        if not os.path.isdir(path):
            raise NotADirectoryError(f"Not a directory: {path}")
        for root, dirs, files in os.walk(path):
            for fn in files:
                fp = os.path.join(root, fn)
                try:
                    r = cls.scan_file(fp)
                    if r.threat_score > 0:
                        reports.append(r)
                except Exception:
                    pass
        return reports

    @classmethod
    def export_report(cls, report: DefenseReport, out_dir: Optional[str] = None) -> str:
        import json, datetime
        out_dir = out_dir or os.path.join(LOGS_DIR, "reports")
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = f"defense_report_{os.path.basename(report.path)}_{ts}.json"
        out_path = os.path.join(out_dir, fname)
        with open(out_path, "w") as f:
            json.dump(report.__dict__, f, indent=2, default=str, ensure_ascii=False)
        return out_path
