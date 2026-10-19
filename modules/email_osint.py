"""Email/Domain OSINT."""
import dns.resolver


def _q(domain, rtype):
    try:
        return [str(r) for r in dns.resolver.resolve(domain, rtype, lifetime=8)]
    except Exception:
        return []


def domain_osint(domain: str) -> dict:
    clean = domain.replace("https://", "").replace("http://", "").split("/")[0]
    results = {
        "domain": clean,
        "MX": _q(clean, "MX"),
        "TXT": _q(clean, "TXT"),
        "NS": _q(clean, "NS"),
    }

    spf = [t for t in results["TXT"] if t.startswith('"v=spf1')]
    results["spf_status"] = (
        "STRICT" if spf and "-all" in spf[0]
        else "SOFT" if spf and "~all" in spf[0]
        else "PERMISSIVE" if spf else "MISSING"
    )

    dmarc = [d for d in _q(f"_dmarc.{clean}", "TXT") if "v=DMARC1" in d]
    results["dmarc_status"] = (
        "STRICT" if dmarc and "p=reject" in dmarc[0]
        else "MEDIUM" if dmarc and "p=quarantine" in dmarc[0]
        else "WEAK" if dmarc else "MISSING"
    )

    risk = 0
    if results["spf_status"] == "MISSING":
        risk += 30
    elif results["spf_status"] == "PERMISSIVE":
        risk += 20
    if results["dmarc_status"] == "MISSING":
        risk += 40
    elif results["dmarc_status"] == "WEAK":
        risk += 20

    results["risk_score"] = min(100, risk)
    return results
