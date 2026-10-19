"""DNS & IP intel."""
import socket
import requests


def dns_lookup(domain: str) -> dict:
    clean = domain.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(clean)
    except socket.gaierror:
        return {"error": "DNS resolution failed"}

    result = {"domain": clean, "ip": ip}

    try:
        result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        result["reverse_dns"] = None

    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=8).json()
        if geo.get("status") == "success":
            result["country"] = geo.get("country")
            result["city"] = geo.get("city")
            result["isp"] = geo.get("isp")
            result["asn"] = geo.get("as")
    except Exception:
        pass

    return result
