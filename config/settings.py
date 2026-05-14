import os
import re

APP_NAME = "Termite-sumu"
APP_VERSION = "1.0.0"
APP_AUTHOR = "C7aWL3R"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
EXPORTS_DIR = os.path.join(BASE_DIR, "exports")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
AUDIT_LOG_PATH = os.path.join(LOGS_DIR, "audit.log")

SSH_DEFAULT_PORT = 22
SMB_DEFAULT_PORT = 445
WINRM_HTTP_PORT = 5985
WINRM_HTTPS_PORT = 5986
TELNET_DEFAULT_PORT = 23
WMI_DEFAULT_PORT = 135

CONNECTION_TIMEOUT = 10
COMMAND_TIMEOUT = 30
MAX_LOG_LINES = 50000

SENSITIVE_FILE_PERMS = 0o600
SENSITIVE_DIR_PERMS = 0o700

# Global dry-run toggle. Honour env var TERMITE_SUMU_DRY_RUN=1 by default.
DRY_RUN = os.environ.get("TERMITE_SUMU_DRY_RUN", "0") == "1"

# Allow caller to opt-in to interactive host-key TOFU prompting in SSH connector.
# Default: STRICT — refuse unknown host keys. Set TERMITE_SUMU_SSH_TOFU=1 to be prompted.
SSH_HOSTKEY_TOFU = os.environ.get("TERMITE_SUMU_SSH_TOFU", "0") == "1"

# Allow caller to opt-in to WinRM with disabled cert validation (lab use only).
# Default: STRICT — require valid cert when use_tls=True.
WINRM_ALLOW_INSECURE_TLS = os.environ.get("TERMITE_SUMU_WINRM_INSECURE_TLS", "0") == "1"

ALLOWED_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)
ALLOWED_IP_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

WINDOWS_LOG_SOURCES = [
    "System",
    "Application",
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Bits-Client/Operational",
    "Microsoft-Windows-DNS-Client/Operational",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "Microsoft-Windows-SMBClient/Security",
    "Microsoft-Windows-SMBServer/Security",
    "Microsoft-Windows-Kernel-PnP/Configuration",
    "Microsoft-Windows-DeviceSetupManager/Admin",
    "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-Firewall With Advanced Security/Firewall",
]

LINUX_LOG_SOURCES = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/kern.log",
    "/var/log/daemon.log",
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/audit/audit.log",
    "/var/log/dpkg.log",
    "/var/log/apt/history.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/mysql/error.log",
    "/var/log/postgresql/postgresql*.log",
    "/var/log/ufw.log",
    "/var/log/fail2ban.log",
    "/var/log/cron.log",
    "/var/log/boot.log",
    "/var/log/dmesg",
]

for _d in [LOGS_DIR, EXPORTS_DIR]:
    os.makedirs(_d, mode=SENSITIVE_DIR_PERMS, exist_ok=True)
    try:
        os.chmod(_d, SENSITIVE_DIR_PERMS)
    except OSError:
        pass
