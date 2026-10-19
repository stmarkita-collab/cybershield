"""API routes."""
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import APIRouter, HTTPException
from api.models import (
    PasswordRequest, PhishingRequest, PortScanRequest, DNSRequest,
    WebAuditRequest, SSLRequest, SubdomainRequest, DirectoryRequest,
    TechRequest, VulnRequest, EmailRequest, APIResponse,
)

from core.config import PORT_PRESETS
from core.database import save_scan, get_scans, clear_scans
from core.http_engine import HTTPEngine
from core.utils import clean_target, normalize_url

from modules.password import analyze_password, check_hibp
from modules.phishing_pro import analyze_url, batch_analyze
from modules.port_scan import run_scan
from modules.dns_intel import dns_lookup
from modules.web_audit import audit_web
from modules.ssl_tls import inspect_ssl
from modules.subdomain import enumerate_subdomains
from modules.directory import brute_directory
from modules.tech_fingerprint import fingerprint_technology
from modules.vuln_check import check_vulnerabilities
from modules.email_osint import domain_osint


router = APIRouter(prefix="/api")


def _handle(fn, *args, **kwargs):
    """Wrapper untuk error handling."""
    try:
        result = fn(*args, **kwargs)
        return {"success": True, "data": result}
    except Exception as e:
        traceback.print_exc()
        return {"success": False, "error": str(e)}


# =========================================================
# PASSWORD
# =========================================================
@router.post("/password")
def api_password(req: PasswordRequest):
    result = analyze_password(req.password)
    if req.check_hibp and not result.get("error"):
        result["hibp"] = check_hibp(req.password)
    save_scan("Password", "***", result)
    return {"success": True, "data": result}


# =========================================================
# PHISHING
# =========================================================
@router.post("/phishing")
def api_phishing(req: PhishingRequest):
    report = analyze_url(req.url, skip_network=req.fast)
    save_scan("PhishingPro", req.url, report.to_dict(), report.risk_score)
    return {"success": True, "data": report.to_dict()}


@router.post("/phishing/batch")
def api_phishing_batch(urls: List[str]):
    results = batch_analyze(urls)
    return {"success": True, "data": [r.to_dict() for r in results]}


# =========================================================
# PORT SCAN
# =========================================================
@router.post("/scan/port")
def api_port_scan(req: PortScanRequest):
    if req.ports:
        port_list = []
        for part in req.ports.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-")
                port_list.extend(range(int(a), int(b) + 1))
            else:
                port_list.append(int(part))
    else:
        port_list = PORT_PRESETS.get(req.preset, PORT_PRESETS["top100"])

    report = run_scan(
        clean_target(req.target), port_list,
        max_workers=req.workers, timeout=req.timeout,
    )
    save_scan("PortScan", req.target, report.to_dict(), report.risk_score)
    return {"success": True, "data": report.to_dict()}


# =========================================================
# DNS
# =========================================================
@router.post("/dns")
def api_dns(req: DNSRequest):
    result = dns_lookup(req.domain)
    save_scan("DNS", req.domain, result)
    return {"success": True, "data": result}


# =========================================================
# WEB AUDIT
# =========================================================
@router.post("/web-audit")
def api_web_audit(req: WebAuditRequest):
    engine = HTTPEngine()
    result = audit_web(engine, normalize_url(req.url), ignore_ssl=req.ignore_ssl)
    save_scan("WebAudit", req.url, result, result.get("risk_score", 0))
    return {"success": True, "data": result}


# =========================================================
# SSL
# =========================================================
@router.post("/ssl")
def api_ssl(req: SSLRequest):
    result = inspect_ssl(req.host, req.port)
    save_scan("SSL", req.host, result)
    return {"success": True, "data": result}


# =========================================================
# SUBDOMAIN
# =========================================================
@router.post("/subdomain")
def api_subdomain(req: SubdomainRequest):
    result = enumerate_subdomains(clean_target(req.domain),
                                   use_crtsh=req.use_crtsh)
    save_scan("Subdomain", req.domain, result)
    return {"success": True, "data": result}


# =========================================================
# DIRECTORY
# =========================================================
@router.post("/directory")
def api_directory(req: DirectoryRequest):
    engine = HTTPEngine()
    result = brute_directory(engine, normalize_url(req.url),
                             ignore_ssl=req.ignore_ssl)
    save_scan("Directory", req.url, result)
    return {"success": True, "data": result}


# =========================================================
# TECH
# =========================================================
@router.post("/tech")
def api_tech(req: TechRequest):
    engine = HTTPEngine()
    result = fingerprint_technology(engine, normalize_url(req.url),
                                     ignore_ssl=req.ignore_ssl)
    save_scan("TechFingerprint", req.url, result)
    return {"success": True, "data": result}


# =========================================================
# VULN
# =========================================================
@router.post("/vuln")
def api_vuln(req: VulnRequest):
    engine = HTTPEngine()
    result = check_vulnerabilities(engine, normalize_url(req.url),
                                    ignore_ssl=req.ignore_ssl)
    save_scan("VulnCheck", req.url, result)
    return {"success": True, "data": result}


# =========================================================
# EMAIL OSINT
# =========================================================
@router.post("/email")
def api_email(req: EmailRequest):
    result = domain_osint(clean_target(req.domain))
    save_scan("EmailOSINT", req.domain, result, result.get("risk_score", 0))
    return {"success": True, "data": result}


# =========================================================
# HISTORY
# =========================================================
@router.get("/history")
def api_history(limit: int = 50, module: str = None):
    scans = get_scans(limit=limit, module=module)
    return {"success": True, "data": scans}


@router.delete("/history")
def api_clear_history():
    clear_scans()
    return {"success": True, "data": {"message": "History cleared"}}


# =========================================================
# STATS
# =========================================================
@router.get("/stats")
def api_stats():
    scans = get_scans(limit=10000)
    total = len(scans)
    by_module = {}
    for s in scans:
        by_module[s["module"]] = by_module.get(s["module"], 0) + 1
    avg_risk = sum(s["risk_score"] for s in scans) / total if total else 0
    return {
        "success": True,
        "data": {
            "total_scans": total,
            "by_module": by_module,
            "avg_risk_score": round(avg_risk, 1),
        },
  }
