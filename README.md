# Termite-sumu v1.0.0

**Termite-sumu** is an authorized red team / purple team desktop application for security professionals.  
Silent. Methodical. Lethal — like the insect it is named after.  
It combines device management, log forensics, exploitation tooling, evasion engineering, and detection-latency measurement into a single dark-themed PyQt6 GUI running on Kali Linux.

> **Legal Notice** — This tool is intended exclusively for authorized penetration testing, red team operations, and security research. Unauthorized use against systems you do not own or have explicit written permission to test is illegal. The author assumes no liability for misuse.

---

## Features

| Tab | Purpose |
|---|---|
| **Reverse Shells** | Listener management (nc/socat/pwncat/msf) + one-liner generator + evasion transforms |
| **Exploit Launcher** | GUI front-ends for Nmap, CrackMapExec, evil-winrm, Impacket, Metasploit, Hydra |
| **Red Team** | BloodHound, Kerberoasting, DCSync, NTLM relay, Responder, mitm6, PetitPotam, Amass, Nuclei, SQLMap, SSTI, Post-exploit enumeration, Chisel/Ligolo tunneling |
| **Analysis** | MITRE ATT&CK log analysis (30 signatures, 3 anomaly detectors), PDF/JSON export |
| **Reference** | Searchable in-app command reference (50+ topics, 12 categories) |
| **Sessions** | SSH + WinRM device management, device tree, property inspector, live terminal, log collection |

### Evasion Engine
- Base64 encoding
- XOR obfuscation (random key, self-decoding Python stub)
- PowerShell `-EncodedCommand` wrapping
- String concatenation splitting
- Process masquerade (`exec -a`)
- JA3 TLS cipher shuffle
- HTTP beacon disguise with jitter

### Security Posture
- Zero `shell=True` subprocess calls — all commands use list args
- `SecureInputValidator` on every user-supplied string before any subprocess invocation
- `SafeCommandBuilder` for PowerShell command construction
- Race-free file creation via `os.open(O_CREAT|O_EXCL, 0o600)`
- `os.umask(0o077)` at startup — no world-readable files
- Atomic append-only audit log
- Dry-run mode (`TERMITE_SUMU_DRY_RUN=1`) — prints exact command, executes nothing

---

## Requirements

- **OS**: Kali Linux (or any Debian/Ubuntu-based distro)
- **Python**: 3.10+
- **Display**: X11 or Wayland desktop (PyQt6 GUI)

External tools (must be on `PATH`):
```
nmap, crackmapexec, evil-winrm, impacket (Python package),
msfconsole, hydra, bloodhound-python, responder, mitm6,
amass, nuclei, whatweb, gobuster, ffuf, tplmap, sqlmap,
chisel, ligolo-ng, pspy / pspy64
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/C7aWL3R/Termite-sumu.git
cd Termite-sumu

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Run
python main.py
```

### Dry-run mode (safe for demos)
```bash
export TERMITE_SUMU_DRY_RUN=1
python main.py
```

### Environment variables
| Variable | Default | Purpose |
|---|---|---|
| `TERMITE_SUMU_DRY_RUN` | `0` | Set to `1` to print commands without executing |
| `TERMITE_SUMU_SSH_TOFU` | `0` | Set to `1` to allow interactive SSH host-key prompting |
| `TERMITE_SUMU_WINRM_INSECURE_TLS` | `0` | Set to `1` to skip WinRM TLS cert validation (lab only) |

---

## Usage

### Starting a session
1. **Session > New Connection** (`Ctrl+N`)
2. Set protocol (SSH / WinRM), host, port, credentials, OS type
3. Click **Connect** — device tree populates automatically

### Collecting logs
- **Tools > Collect All Logs** (`Ctrl+L`)
- Logs are saved to `logs/<session>/<timestamp>/` and auto-loaded into the Analysis tab

### Running a deep scan
- Switch to the **Analysis** tab (`Ctrl+A`)
- Click **Run Deep Scan** — applies 30 ATT&CK signatures to collected logs
- Export findings via **Export > Export Analysis JSON**

### In-app reference
- Press `Ctrl+H` or click **Reference** in the toolbar
- Use the search bar to filter 50+ topics across 12 categories
- Click any topic to read the full usage guide; click **Copy** to grab the content

---

## Directory Structure

```
Termite-sumu/
├── main.py                  Entry point; sets umask, starts Qt app
├── config/
│   └── settings.py          App constants, regex validators, env var toggles
├── core/
│   ├── validators.py        SecureInputValidator — single gate for all input
│   ├── base_connector.py    Abstract connector + DeviceNode dataclass
│   ├── connector_factory.py Protocol dispatch (SSH / WinRM)
│   ├── ssh_connector.py     Paramiko-based SSH + SCP + interactive shell
│   ├── winrm_connector.py   pywinrm-based WinRM connector
│   ├── log_collector.py     Remote log retrieval (Linux + Windows)
│   ├── log_analyzer.py      MITRE ATT&CK signature engine (30 rules)
│   ├── redteam.py           Tool wrappers: BloodHound, Impacket, Responder…
│   ├── evasion.py           Evasion transform pipeline
│   └── safe_commands.py     SafeCommandBuilder — no string interpolation
├── gui/
│   ├── main_window.py       Top-level window, tab management, session state
│   ├── reverse_shell_tab.py Listener + one-liner + evasion UI
│   ├── exploit_launcher_tab.py  Nmap / CME / evil-winrm / Impacket / MSF / Hydra
│   ├── redteam_tab.py       AD / Network / Recon / Web / Post-Exploit / Tunnel
│   ├── analysis_tab.py      Log analysis UI, findings table, export
│   ├── reference_tab.py     Searchable in-app command reference
│   ├── connection_dialog.py New-connection wizard
│   ├── device_tree.py       QTreeWidget for device enumeration
│   ├── log_viewer.py        Log display with filtering
│   ├── properties_panel.py  Device property inspector
│   └── terminal_widget.py   SSH interactive terminal widget
└── reports/
    └── pdf_report.py        reportlab PDF generator
```

---

## MITRE ATT&CK Coverage

| Category | Techniques |
|---|---|
| Initial Access | T1190, T1566, T1078 |
| Execution | T1059, T1218, T1053 |
| Persistence | T1547.001, T1543.003, T1546.003 |
| Privilege Escalation | T1548.001, T1068, T1134 |
| Defense Evasion | T1027, T1553.002, T1070, T1562 |
| Credential Access | T1003, T1558.003, T1558.004, T1110 |
| Discovery | T1087, T1083, T1057 |
| Lateral Movement | T1021, T1550.002, T1572 |
| Collection | T1005 |
| Exfiltration | T1048, T1071 |

---

## License

MIT — see [LICENSE](LICENSE)

> **Responsible Disclosure**: If you discover a security issue in this tool itself, please report it privately before public disclosure.
