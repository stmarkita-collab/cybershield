"""Web server auditor."""
from core.config import SECURITY_HEADERS


def audit_web(engine, url, ignore_ssl=False):
    resp, ssl_ok, ssl_err = engine.safe_get(url, ignore_ssl=ignore_ssl)
    headers = resp.headers

    found = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = [h for h in SECURITY_HEADERS if h not in headers]

    risk = 0
    if not headers.get("Strict-Transport-Security"):
        risk += 15
    if not headers.get("Content-Security-Policy"):
        risk += 20
    if not headers.get("X-Frame-Options"):
        risk += 15
    if headers.get("Server"):
        risk += 15
    if headers.get("X-Powered-By"):
        risk += 10

    return {
        "url": url,
        "status": resp.status_code,
        "ssl_verified": ssl_ok,
        "ssl_error": ssl_err,
        "server": headers.get("Server"),
        "x_powered_by": headers.get("X-Powered-By"),
        "headers_found": list(found.keys()),
        "headers_missing": missing,
        "risk_score": min(100, risk),
    }
