<p align="center">
  <img src="assets/banner.png" alt="Termite-sumu" width="700"/>
</p>

<p align="center">
  <b>Termite-sumu</b> — Authorized Red Team & Purple Team Operations Platform<br>
  <sub>Silent. Methodical. Lethal — like the insect it is named after.</sub>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#screenshots">Screenshots</a> •
  <a href="#installation">Install</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#mitre-attck">MITRE ATT&CK</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.2.0-red?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/platform-Kali%20Linux-purple?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/contributor-archnexus707-orange?style=flat-square" alt="Contributor">
</p>

---

## ⚠️ Legal Notice

This tool is intended **exclusively** for authorized penetration testing, red team operations, and
security research. Unauthorized use against systems you do not own or have explicit written
permission to test is illegal. The authors assume no liability for misuse.

---

## Features

### 🎯 Multi-Protocol Session Management
| Protocol | Purpose |
|----------|---------|
| **SSH** | Encrypted remote shell, device enumeration, log collection |
| **WinRM** | Windows remote management via PowerShell |
| **SMB** | Windows file share access + remote command execution |
| **Telnet** | Legacy device connectivity (lab only) |

### 🔴 Red Team Operations
| Domain | Tools Integrated |
|--------|-----------------|
| **Active Directory** | BloodHound, Kerberoasting, AS-REP roast, DCSync, Kerbrute, Certipy, ldapdomaindump |
| **Network Attacks** | Responder, ntlmrelayx, mitm6, PetitPotam |
| **Reconnaissance** | theHarvester, subfinder, amass, nikto, gobuster, feroxbuster |
| **Web Attacks** | sqlmap, ffuf, nuclei |
| **Post-Exploitation** | LinPEAS, WinPEAS, pspy, SUDO_KILLER, SUID enumeration, TS Privesc Enum |

### 🟣 Purple Team / Evasion
- **6 obfuscation transforms**: Base64, XOR, PowerShell EncodedCommand, string concatenation, variable randomization
- **JA3 TLS cipher shuffle** — evades JA3 fingerprint-based detection
- **HTTP beacon disguise** — C2 traffic masquerading as legitimate HTTP POST
- **Process masquerade** — `exec -a` renaming
- **Detection timer** — measure EDR/SIEM detection latency for purple team exercises

### 🔵 Blue Team / Defense
- **30 MITRE ATT&CK signatures** — 15 Linux + 15 Windows
- **3 anomaly detectors** — brute force, log volume spike, off-hours login
- **IOC matching** — 8 categories (C2, credential dumper, ransomware, etc.)
- **YARA rule scanning** — integrate custom `.yar` rules
- **Threat scoring** — 0-100 weighted score with recommendations

### 🔧 Reverse Engineering
- **Binary static analysis** — file type, architecture, sections, imports/exports
- **Entropy profiling** — packer/crypter detection (Shannon entropy)
- **Capability mapping** — Process Injection, Registry, Anti-debug, Network, Crypto
- **String extraction** — URLs, IPs, emails, WinAPI calls, shell commands

### 🕵️ Steganography Detection
- **steghide** — embedded data detection
- **binwalk** — file carving and extraction
- **LSB pixel analysis** — entropy-based anomaly detection in images
- **Audio spectrograms** — visual analysis for hidden signals
- **Hidden string search** — keys, certificates, emails in binary data

### ⚡ High-Concurrency Go Backend
- **11 payload types** generated server-side
- **TCP / SSL / HTTP-beacon** multi-protocol listeners
- **Goroutine-per-connection** — 10K+ concurrent sessions
- **REST API** on `127.0.0.1:9120` consumed by Python GUI
- **0 external Go dependencies** — stdlib only

### 🖥️ C++ Native Windows Exploitation
- **CreateRemoteThread** injection (T1055.001)
- **LSASS memory dump** via MiniDumpWriteDump (T1003.001)
- **AMSI in-memory patch** (T1562.001)
- **SYSTEM token steal** via DuplicateTokenEx (T1134.001)
- **Shellcode executor** with RWX heap allocation
- Cross-compile from Kali: `make -C cpp_native`

### 🛡️ Security Posture
- **Zero `shell=True`** — every subprocess uses list-based argv
- **SecureInputValidator** — all user input validated before command execution
- **Race-free file creation** — `O_CREAT|O_EXCL` prevents symlink attacks
- **`os.umask(0o077)`** — no world-readable files
- **Atomic append-only audit log** — every operator action recorded
- **Dry-run mode** — `TERMITE_SUMU_DRY_RUN=1` prints commands, executes nothing

---

## Screenshots

<p align="center">
  <sub><i>Place screenshot here — Main Window with all tabs</i></sub>
</p>

| Reverse Shells | Exploit Launcher | Red Team |
|:---:|:---:|:---:|
| <sub>Listener + payload generator</sub> | <sub>Nmap, CME, Impacket, MSF, Hydra</sub> | <sub>AD, Network, Recon, Web, Post-Exploit</sub> |

| Analysis | Reference | Post-Exploit |
|:---:|:---:|:---:|
| <sub>30 ATT&CK signatures</sub> | <sub>50+ searchable topics</sub> | <sub>RE, Stego, Defense scan</sub> |

---

## Installation

### Prerequisites
```bash
# System deps (Kali/Debian)
sudo apt install -y libsmbclient-dev python3-venv python3-pip mingw-w64

# Python deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Go Backend (optional — for high-concurrency listeners)
```bash
cd gobackend
go build -o termite-go-backend .
```

### C++ Native Module (optional — for Windows exploitation)
```bash
cd cpp_native
make    # requires x86_64-w64-mingw32-g++
```

### Launch
```bash
python main.py
```

### Safe Demo Mode
```bash
export TERMITE_SUMU_DRY_RUN=1
python main.py
```

### Environment Variables
| Variable | Default | Purpose |
|----------|---------|---------|
| `TERMITE_SUMU_DRY_RUN` | `0` | Print commands without executing |
| `TERMITE_SUMU_SSH_TOFU` | `0` | Allow interactive SSH host-key prompting |
| `TERMITE_SUMU_WINRM_INSECURE_TLS` | `0` | Skip WinRM TLS cert validation (lab only) |

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | New Connection |
| `Ctrl+L` | Collect All Logs |
| `Ctrl+T` | Open Terminal |
| `Ctrl+R` | Reverse Shells tab |
| `Ctrl+E` | Exploit Launcher tab |
| `Ctrl+G` | Red Team Ops tab |
| `Ctrl+A` | Deep Analysis tab |
| `Ctrl+H` | Reference tab |
| `Ctrl+Q` | Quit |

---

## Architecture

```
Termite-sumu/                         v1.2.0
├── main.py                           Entry point (Qt6 app)
├── config/settings.py                App constants, env toggles
├── core/
│   ├── reverse_shell.py              Listener manager + 11 payload types
│   ├── exploit_launcher.py           Nmap, CME, evil-winrm, Impacket, MSF, Hydra
│   ├── redteam.py                    AD, Network, Recon, Web, Post-Exploit, Tunnel
│   ├── evasion.py                    6 obfuscation transforms + detection timer
│   ├── log_analyzer.py               30 ATT&CK sigs + 3 anomaly detectors
│   ├── validators.py                 SecureInputValidator
│   ├── audit.py                      Atomic append-only audit logger
│   ├── go_bridge.py                  Python ↔ Go backend client
│   ├── reversing/                    Binary static analysis engine
│   ├── steg/                         Steganography detection pipeline
│   └── defense/                      IOC + YARA defense scanner
├── gobackend/                        Go high-concurrency engine
│   ├── main.go                       HTTP server (127.0.0.1:9120)
│   ├── listener/manager.go           TCP/TLS listener pool (goroutines)
│   ├── session/manager.go            Per-connection session tracker
│   └── payload/generator.go          11 reverse-shell one-liners
├── cpp_native/                       C++ Windows exploitation
│   ├── injector.cpp                  6 techniques (injection, dump, AMSI, token)
│   └── Makefile                      Cross-compile via mingw-w64
├── gui/
│   ├── main_window.py                Main window, tabs, toolbar
│   ├── reverse_shell_tab.py          Listener + payload + evasion UI
│   ├── exploit_launcher_tab.py       Tool launcher with live output
│   ├── redteam_tab.py                6-category red team dashboard
│   ├── analysis_tab.py               Log analysis + ATT&CK findings
│   ├── reference_tab.py              1,147-line searchable reference
│   ├── connection_dialog.py          SSH/WinRM/SMB/Telnet connection wizard
│   ├── terminal_widget.py            SSH interactive terminal
│   └── output_reader.py              Shared QThread subprocess reader
├── scripts/post_exploit/
│   └── linux_privesc_enum.sh         10-point Linux privilege escalation check
├── reports/pdf_report.py             reportlab PDF generator
└── HUNTED_BUGS_AND_ERRORS.txt        Full audit: 46 bugs found + fixed
```

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| **Initial Access** | T1190, T1566, T1078 |
| **Execution** | T1059, T1218, T1053, T1059.001, T1059.004 |
| **Persistence** | T1547.001, T1543.003, T1546.003, T1053.003, T1053.005, T1136.001, T1547.006 |
| **Privilege Escalation** | T1548.001, T1068, T1134, T1134.001, T1548.003 |
| **Defense Evasion** | T1027, T1553.002, T1070, T1562, T1562.001, T1055.001, T1055.012 |
| **Credential Access** | T1003, T1558.003, T1558.004, T1110, T1003.001, T1003.006, T1003.008, T1558.001 |
| **Discovery** | T1087, T1083, T1057, T1046, T1082 |
| **Lateral Movement** | T1021, T1550.002, T1572, T1021.002 |
| **Collection** | T1005, T1564.003 |
| **Command & Control** | T1071, T1071.001, T1041 |
| **Exfiltration** | T1048 |
| **Impact** | T1486 |

---

## Authors

| Role | Name | GitHub |
|------|------|--------|
| **Author** | C7aWL3R | [@C7aWL3R](https://github.com/C7aWL3R) |
| **Contributor** | archnexus707 | [@archnexus707](https://github.com/archnexus707) |

### Contributions by archnexus707 (v1.2.0)
- **46 bug fixes** across core, GUI, payload, and session management
- **Go backend** — high-concurrency listener/session/payload engine
- **C++ native module** — 6 Windows exploitation techniques
- **Reverse engineering engine** — binary static analysis + entropy + capability mapping
- **Steganography detection** — steghide, binwalk, LSB, spectrograms
- **Defensive scanner** — IOC matching, YARA integration, threat scoring
- **Cross-platform protocol fixes** — CRLF line endings, thread safety, Qt signal marshalling
- **Full 8,500-line code audit** — documented in `HUNTED_BUGS_AND_ERRORS.txt`

---

## License

MIT — see [LICENSE](LICENSE)

> **Responsible Disclosure**: If you discover a security issue in this tool itself, please
> report it privately before public disclosure.

---

<p align="center">
  <sub>Built with ❤️ for the offensive security community</sub>
</p>
