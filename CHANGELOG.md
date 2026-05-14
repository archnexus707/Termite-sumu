# Changelog

## [1.0.0] — 2025

### Added
- PyQt6 dark-theme GUI with persistent permanent tabs (Reverse Shells, Exploit Launcher, Red Team, Analysis, Reference)
- SSH and WinRM session management with live device tree
- Interactive SSH terminal widget
- Log collector for 20+ Linux and Windows log sources
- MITRE ATT&CK log analysis engine (30 signatures, 3 anomaly detectors)
- PDF and JSON report export via reportlab
- Evasion engine: Base64, XOR, PowerShell -Enc, string concat, process masquerade, JA3 shuffle, HTTP beacon
- Detection-latency timer for blue team assessment
- Exploit Launcher: Nmap, CrackMapExec, evil-winrm, Impacket, Metasploit resource scripts, Hydra
- Red Team tab: BloodHound, Kerberoasting, AS-REP, DCSync, PtH, NTLM relay, mitm6, PetitPotam, pspy, Amass, Nuclei, theHarvester, WhatWeb, Gobuster, ffuf, SQLMap, SSTI/tplmap, XSS/Arjun, SUID finder, WinPEAS/LinPEAS, Mimikatz guide, Chisel, SSH tunnels, Ligolo-ng, netsh portproxy
- Searchable in-app Reference tab (50+ topics, 12 categories, real-time tree filter)
- SecureInputValidator with scheme-allowlist URL validation
- SafeCommandBuilder — zero string interpolation into shell commands
- Dry-run mode (TERMITE_SUMU_DRY_RUN=1)
- Atomic audit log with O_APPEND writes
- umask(0o077) at startup, 0o600/0o700 for all created files/dirs
