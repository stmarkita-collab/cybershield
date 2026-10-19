"""Tech fingerprinting."""
import re
from core.config import TECH_SIGNATURES


def fingerprint_technology(engine, url, ignore_ssl=False):
    resp, _, _ = engine.safe_get(url, ignore_ssl=ignore_ssl)
    text = (resp.text or "")[:500_000]
    headers_str = str(resp.headers)

    detected = []
    for tech, patterns in TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, text, re.I) or re.search(pat, headers_str, re.I):
                detected.append(tech)
                break

    return {
        "url": url,
        "status": resp.status_code,
        "server": resp.headers.get("Server"),
        "powered_by": resp.headers.get("X-Powered-By"),
        "detected": sorted(set(detected)),
        "count": len(set(detected)),
  }
