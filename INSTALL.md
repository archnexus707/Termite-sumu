# Installation Guide

## Prerequisites

### System
- Kali Linux 2023.x or later (recommended)
- Python 3.10+
- X11 or Wayland desktop session

### External tools
Install missing tools with:
```bash
sudo apt update
sudo apt install -y nmap crackmapexec evil-winrm hydra amass gobuster whatweb \
    sqlmap responder mitm6 bloodhound-python ffuf

# Impacket (Python)
pip install impacket

# Metasploit
sudo apt install -y metasploit-framework

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# or: sudo apt install nuclei

# Chisel (tunneling)
# Download from https://github.com/jpillora/chisel/releases

# pspy (Linux process monitor)
# Download pspy64 from https://github.com/DominicBreuker/pspy/releases
# Place in /usr/local/bin/pspy64 and chmod +x
```

## Python environment

```bash
git clone https://github.com/C7aWL3R/Termite-sumu.git
cd Termite-sumu

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

## Running

```bash
# Activate venv first
source .venv/bin/activate

# Normal mode
python main.py

# Dry-run (no commands executed — safe for demos)
TERMITE_SUMU_DRY_RUN=1 python main.py
```

## Kali-specific notes

- `evil-winrm` requires Ruby: `sudo gem install evil-winrm`
- `bloodhound-python`: `pip install bloodhound` (separate from apt package)
- Responder requires root: run the tool as root or with `sudo` when using the Responder form
- mitm6 requires root or `CAP_NET_ADMIN`: `sudo setcap cap_net_admin+eip $(which mitm6)`

## Permissions

The app enforces `umask 077` at startup — all created files are readable only by the
current user. Log directories are created with `0o700` permissions.

Run as a non-root user where possible. Tools that require root (Responder, mitm6, nmap -sS)
will prompt for `sudo` in the output pane if permissions are insufficient.
