# src/domain_blocklist.py
import urllib.request
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from config import DATA_RAW

BLOCKLIST_PATH = DATA_RAW / "phishing_domains.txt"
BLOCKLIST_URL  = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt"

_blocklist_set = None


def load_blocklist() -> set:
    global _blocklist_set
    if _blocklist_set is not None:
        return _blocklist_set

    if not BLOCKLIST_PATH.exists():
        print("  Downloading hagezi phishing domain blocklist (~10MB)...")
        BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            urllib.request.urlretrieve(BLOCKLIST_URL, BLOCKLIST_PATH)
            print("  Blocklist downloaded")
        except Exception as e:
            print(f"  Blocklist download failed: {e} — skipping")
            _blocklist_set = set()
            return _blocklist_set

    domains = set()
    with open(BLOCKLIST_PATH, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.add(line.lower())

    _blocklist_set = domains
    print(f"  Blocklist loaded: {len(domains):,} known phishing domains")
    return domains


def is_known_phishing_domain(domain: str) -> bool:
    """Check if domain is in the hagezi phishing blocklist."""
    if not domain:
        return False
    blocklist = load_blocklist()
    domain    = domain.lower().strip()
    return (domain in blocklist or
            ".".join(domain.split(".")[-2:]) in blocklist)