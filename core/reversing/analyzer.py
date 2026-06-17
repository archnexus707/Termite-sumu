"""
Binary Reverse Engineering Engine — static analysis, unpacker detection,
import/export enumeration, entropy profiling, and disassembler integration.

All analysis is read-only and local — never executes target binaries.
Integrates with system tools: strings, objdump, readelf, xxd, file, radare2.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core.audit import audit
from core.validators import SecureInputValidator
from config.settings import LOGS_DIR, SENSITIVE_FILE_PERMS


@dataclass
class BinaryReport:
    path: str
    size: int
    hashes: Dict[str, str] = field(default_factory=dict)
    file_type: str = ""
    architecture: str = ""
    sections: List[Dict] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    strings_of_interest: List[str] = field(default_factory=list)
    entropy: float = 0.0
    entropy_verdict: str = ""
    packer_hints: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class BinaryAnalyzer:
    """Static binary analysis engine for PE, ELF, Mach-O files."""

    @staticmethod
    def _run(cmd: List[str], timeout: int = 30) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip() + "\n" + r.stderr.strip()
        except Exception:
            return ""

    @staticmethod
    def _require(tool: str) -> str:
        path = shutil.which(tool)
        if not path:
            raise FileNotFoundError(f"{tool!r} not found in PATH")
        return path

    @classmethod
    def analyze(cls, filepath: str) -> BinaryReport:
        path = SecureInputValidator.validate_path(filepath)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Binary not found: {path}")

        report = BinaryReport(path=path, size=os.path.getsize(path))
        audit("RE_ANALYZE", detail=f"path={path}")

        # Hashes
        with open(path, "rb") as f:
            data = f.read()
        report.hashes = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

        # File type
        ft = cls._run(["file", "-b", path])
        report.file_type = ft.split("\n")[0] if ft else "unknown"

        # Architecture
        if "ELF" in ft:
            arch = cls._run(["readelf", "-h", path])
            m = re.search(r"Machine:\s+(.+)", arch)
            report.architecture = m.group(1) if m else "ELF"
            # Sections
            sec = cls._run(["readelf", "-S", path])
            for line in sec.split("\n"):
                parts = line.split()
                if len(parts) >= 6 and parts[0].startswith("[") and parts[0].endswith("]"):
                    name = parts[1] if len(parts) > 1 else ""
                    report.sections.append({
                        "name": name, "type": parts[0], "addr": parts[3] if len(parts) > 3 else ""
                    })
            # Imports
            imp = cls._run(["readelf", "-r", path])
            for line in imp.split("\n"):
                m2 = re.search(r"(\w+@\w+|\w+)", line)
                if m2 and len(m2.group(1)) > 2:
                    report.imports.append(m2.group(1))

        elif "PE" in ft:
            report.architecture = "PE"
            obj = cls._run(["objdump", "-x", path])
            for line in obj.split("\n"):
                if "DLL Name:" in line:
                    dll = line.split("DLL Name:")[-1].strip()
                    if dll:
                        report.imports.append(dll)
                elif "vma" in line.lower() and "name" in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        report.sections.append({"name": parts[-1], "type": "", "addr": parts[0]})

        elif "Mach-O" in ft:
            report.architecture = "Mach-O"

        # Strings analysis
        strings_out = cls._run(["strings", "-n", "6", path])
        interesting = []
        patterns = [
            (r"http[s]?://[^\s]+", "URL"),
            (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP"),
            (r"[\w\.-]+@[\w\.-]+\.\w+", "Email"),
            (r"(cmd\.exe|powershell|/bin/bash|/bin/sh)", "Shell"),
            (r"(CreateProcess|VirtualAlloc|WriteProcessMemory|OpenProcess)", "WinAPI"),
            (r"(socket|connect|send|recv|bind)", "Network"),
            (r"(AES|RC4|XOR|base64|encrypt|decrypt)", "Crypto"),
            (r"(UPX|ASPack|Themida|VMProtect|Enigma)", "Packer"),
        ]
        for line in strings_out.split("\n")[:5000]:
            for pat, cat in patterns:
                m = re.search(pat, line, re.I)
                if m:
                    found = m.group(0).strip()[:120]
                    if found not in report.strings_of_interest:
                        report.strings_of_interest.append(found)
                    if cat == "Packer" and found not in report.packer_hints:
                        report.packer_hints.append(found)
                    if cat == "Network" and "Network" not in report.capabilities:
                        report.capabilities.append("Network communication")
                    if cat == "WinAPI" and "Process Injection" not in report.capabilities:
                        report.capabilities.append("Process Injection")

        # Entropy (packer detection)
        report.entropy = cls._shannon_entropy(data[:65536])  # first 64KB
        if report.entropy > 7.5:
            report.entropy_verdict = "Highly packed / encrypted"
            report.packer_hints.append(f"Entropy={report.entropy:.2f} (>7.5)")
        elif report.entropy > 6.8:
            report.entropy_verdict = "Possibly packed"
        elif report.entropy > 5.0:
            report.entropy_verdict = "Normal (compressed data possible)"
        else:
            report.entropy_verdict = "Low entropy — likely not packed"

        # Capability mapping
        for s in report.strings_of_interest:
            s_l = s.lower()
            if any(k in s_l for k in ("registry", "regkey", "hkcu", "hklm")) and "Registry access" not in report.capabilities:
                report.capabilities.append("Registry access")
            if any(k in s_l for k in ("createservice", "scmanager", "startservice")) and "Service manipulation" not in report.capabilities:
                report.capabilities.append("Service manipulation")
            if any(k in s_l for k in ("antidebug", "isdebuggerpresent", "checkremotedebugger")) and "Anti-debug" not in report.capabilities:
                report.capabilities.append("Anti-debugging")

        # Recommendations
        if report.packer_hints:
            report.recommendations.append("Unpack before further analysis (UPX -d, or manual)")
        if report.entropy > 7.0:
            report.recommendations.append("High entropy — use dynamic analysis (sandbox)")
        if any("http" in s for s in report.strings_of_interest):
            report.recommendations.append("Extract C2 domains; block at firewall; check threat intel")
        if "Process Injection" in report.capabilities:
            report.recommendations.append("Likely malicious capability — isolate and investigate")

        return report

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counter.values())

    @classmethod
    def export_report(cls, report: BinaryReport, out_dir: Optional[str] = None) -> str:
        import json, datetime
        out_dir = out_dir or os.path.join(LOGS_DIR, "reports")
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = f"re_report_{os.path.basename(report.path)}_{ts}.json"
        out_path = os.path.join(out_dir, fname)
        with open(out_path, "w") as f:
            json.dump(report.__dict__, f, indent=2, default=str)
        return out_path
