"""Subdomain enumerator."""
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import SUBDOMAIN_WORDLIST


def _resolve(domain, sub):
    host = f"{sub}.{domain}"
    try:
        return host, socket.gethostbyname(host)
    except Exception:
        return host, None


def _crtsh(domain, timeout=15):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout)
        if r.status_code != 200:
            return []
        subs = set()
        for item in r.json():
            for name in item.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith("." + domain) and " " not in name:
                    subs.add(name)
        return sorted(subs)
    except Exception:
        return []


def enumerate_subdomains(domain: str, use_crtsh: bool = True,
                          max_workers: int = 30) -> dict:
    clean = domain.replace("https://", "").replace("http://", "").split("/")[0]
    results = {"domain": clean, "found": [], "crtsh_count": 0}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_resolve, clean, s): s for s in SUBDOMAIN_WORDLIST}
        for fut in as_completed(futures):
            host, ip = fut.result()
            if ip:
                results["found"].append({"host": host, "ip": ip, "source": "wordlist"})

    if use_crtsh:
        crtsh = _crtsh(clean)
        results["crtsh_count"] = len(crtsh)
        existing = {i["host"] for i in results["found"]}
        for sub in crtsh:
            if sub not in existing:
                try:
                    ip = socket.gethostbyname(sub)
                except Exception:
                    ip = None
                results["found"].append({"host": sub, "ip": ip, "source": "crt.sh"})

    results["total"] = len(results["found"])
    return results
