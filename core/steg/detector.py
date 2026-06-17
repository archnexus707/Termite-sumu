"""
Steganography Detection & Extraction Engine.

Integrates: steghide, binwalk, LSB pixel analysis, audio spectrogram
generation, strings-based hidden-data search, and file carving.
Read-only analysis — never embeds or injects data.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.audit import audit
from core.validators import SecureInputValidator
from config.settings import LOGS_DIR, SENSITIVE_FILE_PERMS


@dataclass
class StegoReport:
    path: str
    size: int
    file_type: str = ""
    steghide_embedded: bool = False
    steghide_detail: str = ""
    binwalk_findings: List[str] = field(default_factory=list)
    lsb_anomaly: bool = False
    lsb_entropy: float = 0.0
    spectrogram_path: str = ""
    hidden_strings: List[str] = field(default_factory=list)
    verdict: str = "Clean — no steganography detected"
    recommendations: List[str] = field(default_factory=list)


class StegoDetector:
    """Static steganography detection pipeline."""

    @staticmethod
    def _run(cmd: List[str], timeout: int = 60) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip() + "\n" + r.stderr.strip()
        except Exception:
            return ""

    @classmethod
    def analyze(cls, filepath: str) -> StegoReport:
        path = SecureInputValidator.validate_path(filepath)
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")

        report = StegoReport(path=path, size=os.path.getsize(path))
        audit("STEG_ANALYZE", detail=f"path={path}")
        base = os.path.basename(path)
        out_dir = os.path.join(LOGS_DIR, "stego", base + "_analysis")
        try:
            os.makedirs(out_dir, mode=SENSITIVE_FILE_PERMS, exist_ok=True)
        except (OSError, PermissionError):
            out_dir = tempfile.mkdtemp(prefix="stego_")

        # File type
        ft = cls._run(["file", "-b", path])
        report.file_type = ft.split("\n")[0] if ft else "unknown"

        # Steghide check
        if shutil.which("steghide"):
            out = cls._run(["steghide", "info", path, "-p", ""])
            if "embedded" in out.lower() or "capacity" in out.lower():
                report.steghide_embedded = True
                report.steghide_detail = out[:500]
            else:
                report.steghide_detail = "No embedded data detected by steghide"

        # Binwalk — extract embedded files
        if shutil.which("binwalk"):
            bin_dir = os.path.join(out_dir, "binwalk_extracted")
            try:
                os.makedirs(bin_dir, exist_ok=True)
                out = cls._run(["binwalk", "-e", "-q", f"--directory={bin_dir}", path])
                for line in out.split("\n"):
                    if any(k in line for k in ("Zlib", "JPEG", "PNG", "Gzip", "Zip", "ELF", "PE", "XML", "JSON")):
                        report.binwalk_findings.append(line.strip()[:200])
                for root, dirs, files in os.walk(bin_dir):
                    for fn in files:
                        fp = os.path.join(root, fn)
                        if os.path.getsize(fp) > 0:
                            report.binwalk_findings.append(f"EXTRACTED: {os.path.relpath(fp, out_dir)} ({os.path.getsize(fp)} bytes)")
            except (OSError, PermissionError):
                report.binwalk_findings.append("Binwalk extraction skipped — permission denied")

        # LSB analysis for images
        if any(k in report.file_type.lower() for k in ("png", "jpeg", "bmp", "gif", "image")):
            cls._lsb_check(path, report)

        # Audio spectrogram
        if any(k in report.file_type.lower() for k in ("audio", "wav", "mp3", "flac", "ogg")):
            spec_path = os.path.join(out_dir, "spectrogram.png")
            cls._run(["ffmpeg", "-y", "-i", path, "-lavfi",
                      "showspectrumpic=s=1024x512:legend=disabled",
                      spec_path])
            if os.path.exists(spec_path):
                report.spectrogram_path = spec_path

        # Strings search for stego/hidden markers
        strings_out = cls._run(["strings", "-n", "4", path])
        patterns = [
            (r"(hidden|secret|embed|steg|payload|passwd|password)", "Stego marker"),
            (r"(-----BEGIN|-----END) (RSA |CERTIFICATE|PRIVATE KEY|PUBLIC KEY)", "Key material"),
            (r"[\w\.-]+@[\w\.-]+\.\w+", "Email in binary"),
        ]
        for line in strings_out.split("\n")[:3000]:
            for pat, cat in patterns:
                m = re.search(pat, line, re.I)
                if m and m.group(0) not in report.hidden_strings:
                    report.hidden_strings.append(f"[{cat}] {m.group(0)[:200]}")

        # Verdict
        issues = sum([
            report.steghide_embedded,
            len(report.binwalk_findings) > 0,
            report.lsb_anomaly,
            len(report.hidden_strings) > 3,
        ])
        if issues >= 3:
            report.verdict = "HIGH — multiple steganography indicators detected"
            report.recommendations.append("Full forensic analysis recommended")
        elif issues >= 1:
            report.verdict = "MEDIUM — potential hidden data"
            report.recommendations.append("Manual review of findings")
        else:
            report.verdict = "Low — no significant stego indicators"

        return report

    @classmethod
    def _lsb_check(cls, path: str, report: StegoReport) -> None:
        """Check LSB plane for anomalies using pixel statistics."""
        try:
            from PIL import Image
            img = Image.open(path).convert("RGB")
            pixels = list(img.getdata())
            if len(pixels) < 100:
                return
            # Sample LSB plane statistics
            lsb_vals = [(r & 1, g & 1, b & 1) for r, g, b in pixels[:10000]]
            ones = sum(sum(t) for t in lsb_vals)
            total = len(lsb_vals) * 3
            ratio = ones / total if total > 0 else 0
            report.lsb_entropy = ratio
            # LSB should be ~0.5 for natural images. Significant deviation = anomaly
            if ratio < 0.35 or ratio > 0.65:
                report.lsb_anomaly = True
        except ImportError:
            pass

    @classmethod
    def export_report(cls, report: StegoReport, out_dir: Optional[str] = None) -> str:
        import json, datetime
        out_dir = out_dir or os.path.join(LOGS_DIR, "reports")
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = f"stego_report_{os.path.basename(report.path)}_{ts}.json"
        out_path = os.path.join(out_dir, fname)
        with open(out_path, "w") as f:
            json.dump(report.__dict__, f, indent=2, default=str, ensure_ascii=False)
        return out_path
