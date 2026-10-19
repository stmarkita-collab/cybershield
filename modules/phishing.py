"""Phishing detector."""
import re
import urllib.parse
from core.utils import levenshtein


def calculate_phishing_risk(url: str) -> tuple:
    reasons = []
    risk = 0
    p = urllib.parse.urlparse(url)
    host = (p.netloc or p.path).split(":")[0]
    base = host.split(".")[0] if host else ""

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        reasons.append("IP-based domain")
        risk += 20

    if len(url) > 75:
        reasons.append(f"URL terlalu panjang ({len(url)})")
        risk += 10

    if url.startswith("http://"):
        reasons.append("Tidak HTTPS")
        risk += 25

    if "@" in url:
        reasons.append("Mengandung '@' (trick)")
        risk += 25

    kw = ["login", "verify", "secure", "banking", "giveaway", "free"]
    found = [k for k in kw if k in url.lower()]
    if found:
        reasons.append(f"Keyword: {', '.join(found)}")
        risk += min(30, len(found) * 8)

    brands = ["google", "facebook", "paypal", "amazon", "bank",
              "microsoft", "apple", "netflix"]
    for brand in brands:
        if brand not in base and len(base) >= 4:
            if levenshtein(base.lower(), brand) <= 2:
                reasons.append(f"Mirip '{brand}' (typosquat)")
                risk += 30
                break

    return reasons, min(100, risk)
