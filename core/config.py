"""Konfigurasi global."""
import os
from pathlib import Path
from dotenv import load_dotenv
import certifi

load_dotenv()

os.environ.setdefault("REQUESTS_CA_BUNDLE", certifi.where())
os.environ.setdefault("SSL_CERT_FILE", certifi.where())

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

APP_NAME = "CyberShield CLI"
APP_VERSION = "5.0.0"

DB_PATH = os.getenv("CYBERSHIELD_DB_PATH", str(DATA_DIR / "cybershield.db"))
LOG_PATH = os.getenv("CYBERSHIELD_LOG_PATH", str(LOG_DIR / "cybershield.log"))

DEFAULT_TIMEOUT = 8
DEFAULT_MAX_WORKERS = 50
DEFAULT_RATE_LIMIT_MS = 50

# Port presets
PORT_PRESETS = {
    "top20": [21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443],
    "top100": [
        7, 9, 13, 21, 22, 23, 25, 53, 79, 80, 81, 88, 106, 110, 111, 113,
        119, 135, 139, 143, 179, 389, 443, 445, 465, 513, 514, 515, 543,
        544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
        1027, 1028, 1029, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
        2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
        5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
        6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999,
        10000, 32768, 49152, 49153, 49154, 49155,
    ],
    "web": [80, 81, 443, 8000, 8008, 8080, 8081, 8082, 8088, 8090, 8443, 8888, 9000, 9443],
    "db": [1433, 1521, 3306, 5000, 5432, 5984, 6379, 7474, 8086, 9042, 9200, 11211, 27017],
    "well-known": list(range(1, 1025)),
    "all": list(range(1, 65536)),
}

SERVICE_NAME_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB",
}

RISK_PORT_WEIGHTS = {
    23: 40, 21: 25, 445: 30, 1433: 20, 3306: 25, 5432: 25,
    6379: 40, 9200: 35, 11211: 30, 27017: 35, 2375: 50,
    3389: 20, 5900: 25,
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "X-Frame-Options": "Anti-Clickjacking",
    "X-Content-Type-Options": "Anti MIME-sniff",
    "Content-Security-Policy": "Anti XSS",
    "Referrer-Policy": "Referrer control",
    "Permissions-Policy": "Feature control",
}

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "Drupal": [r"Drupal\.settings"],
    "Joomla": [r"/components/com_"],
    "React": [r"react(?:-dom)?[.\-]"],
    "Vue.js": [r"vue(?:\.min)?\.js"],
    "Angular": [r"ng-version="],
    "jQuery": [r"jquery[.\-][\d.]+"],
    "Bootstrap": [r"bootstrap[.\-][\d.]"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache/"],
    "IIS": [r"Microsoft-IIS"],
    "Cloudflare": [r"cloudflare"],
    "PHP": [r"PHP/[\d.]"],
}

VULN_DB = {
    "Apache/2.4.49": ("CVE-2021-41773", "CRITICAL", "Path traversal RCE"),
    "Apache/2.4.50": ("CVE-2021-42013", "CRITICAL", "Path traversal RCE"),
    "PHP/7.4": ("EOL", "HIGH", "PHP 7.4 EOL"),
    "PHP/8.0": ("EOL", "HIGH", "PHP 8.0 EOL"),
}

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "dev", "test", "staging", "prod", "api", "app", "admin",
    "blog", "shop", "cdn", "static", "vpn", "portal", "docs",
]

DIRECTORY_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "wp-admin",
    "api", "v1", "v2", "graphql", "swagger", "docs",
    "backup", "backups", "bak", "old", "test", "dev",
    ".git", ".env", ".htaccess", "config.php", "config.json",
    "robots.txt", "sitemap.xml", "phpinfo.php", "server-status",
    "uploads", "files", "static", "assets",
]

SENSITIVE_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "CRITICAL"),
    (r"-----BEGIN.*PRIVATE KEY-----", "Private Key", "CRITICAL"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Token", "CRITICAL"),
    (r"sk-[A-Za-z0-9]{48}", "OpenAI Key", "HIGH"),
    (r"mysql://[^:]+:[^@]+@", "MySQL URI", "CRITICAL"),
    (r"mongodb\+srv://[^:]+:[^@]+@", "MongoDB URI", "CRITICAL"),
]
