"""Vulnerability checker."""
from core.config import SECURITY_HEADERS, VULN_DB


def check_vulnerabilities(engine, url, ignore_ssl=False):
    resp, _, _ = engine.safe_get(url, ignore_ssl=ignore_ssl)
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    banner = headers_lower.get("server", "") or headers_lower.get("x-powered-by", "")

    findings = []
    for version, (cve, sev, desc) in VULN_DB.items():
        if version.lower() in banner.lower():
            findings.append({"type": "Vulnerable Software", "severity": sev,
                             "detail": f"{version} → {cve}: {desc}"})

    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    if len(missing) >= 4:
        findings.append({
            "type": "Missing Headers", "severity": "MEDIUM",
            "detail": f"{len(missing)} headers absent",
        })

    return {"url": url, "findings": findings,
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH")}
