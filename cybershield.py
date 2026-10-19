#!/usr/bin/env python3
"""
CyberShield CLI v5.0 — Terminal-based cybersecurity toolkit.

⚠️  ETIKA: Gunakan hanya pada sistem milik sendiri atau dengan izin tertulis.
"""

import os
import sys
import json
import click
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.config import (
    APP_NAME, APP_VERSION, PORT_PRESETS, DB_PATH, DEFAULT_TIMEOUT,
)
from core.database import init_db, save_scan, get_scans, clear_scans, log_event
from core.http_engine import HTTPEngine
from core.utils import clean_target, normalize_url, to_json
from core.output import (
    console, banner, section, success, error, warn, info,
    print_json, print_markdown, result_table, metric_row,
    progress_context,
)

from modules.password import analyze_password, check_hibp
from modules.phishing import calculate_phishing_risk
from modules.port_scan import run_scan
from modules.dns_intel import dns_lookup
from modules.web_audit import audit_web
from modules.ssl_tls import inspect_ssl
from modules.subdomain import enumerate_subdomains
from modules.directory import brute_directory
from modules.tech_fingerprint import fingerprint_technology
from modules.vuln_check import check_vulnerabilities
from modules.email_osint import domain_osint


@click.group()
@click.version_option(APP_VERSION, prog_name=APP_NAME)
def cli():
    """🛡️  CyberShield CLI — Professional Cybersecurity Toolkit.

    \b
    ⚠️  ETIKA: Gunakan hanya pada sistem milik sendiri
        atau dengan izin tertulis.
    """
    init_db()


@cli.command()
def version():
    """Show version."""
    banner()
    console.print(f"[bold]Version:[/bold] {APP_VERSION}")
    console.print(f"[bold]Database:[/bold] {DB_PATH}")


# =========================================================
# PASSWORD
# =========================================================
@cli.command()
@click.option("--password", "-p", prompt=True, hide_input=True,
              help="Password to analyze")
@click.option("--hibp", is_flag=True, help="Check HaveIBeenPwned")
def password(password, hibp):
    """Analyze password strength."""
    section("Password Analyzer")

    result = analyze_password(password)

    metric_row({
        "Entropy": f"{result['entropy']} bits",
        "Length": f"{result['length']} chars",
        "Crack time": result["crack_time"],
    })

    if result["category"] == "SANGAT KUAT":
        success(f"Category: {result['category']}")
    elif result["category"] == "SEDANG":
        warn(f"Category: {result['category']}")
    else:
        error(f"Category: {result['category']}")

    for fb in result["feedback"]:
        info(fb)

    if hibp:
        section("HaveIBeenPwned Check")
        r = check_hibp(password)
        if r.get("error"):
            error(f"Error: {r['error']}")
        elif r.get("found"):
            error(f"FOUND in {r['count']} breaches!")
        else:
            success("Not found in HIBP")

    save_scan("Password", "***", result)


# =========================================================
# PHISHING
# =========================================================
@cli.command()
@click.argument("url")
def phishing(url):
    """Detect phishing indicators in URL."""
    section(f"Phishing Analysis: {url}")

    reasons, risk = calculate_phishing_risk(url)

    if risk >= 70:
        error(f"Risk: {risk}/100 — HIGH")
    elif risk >= 40:
        warn(f"Risk: {risk}/100 — MEDIUM")
    else:
        success(f"Risk: {risk}/100 — LOW")

    if reasons:
        section("Indicators")
        for r in reasons:
            console.print(f"  • {r}")

    save_scan("Phishing", url, {"risk": risk, "reasons": reasons}, risk)


# =========================================================
# PORT SCAN
# =========================================================
@cli.command()
@click.argument("target")
@click.option("--preset", "-P", default="top100",
              type=click.Choice(list(PORT_PRESETS.keys())),
              help="Port preset")
@click.option("--ports", "-p", help="Custom ports (e.g. 22,80,443 or 1-1000)")
@click.option("--workers", "-w", default=100, help="Concurrent workers")
@click.option("--timeout", "-t", default=1.0, type=float, help="Port timeout")
@click.option("--json-output", "-j", is_flag=True, help="Output JSON")
def scan(target, preset, ports, workers, timeout, json_output):
    """Scan ports on target."""
    if ports:
        port_list = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-")
                port_list.extend(range(int(a), int(b) + 1))
            else:
                port_list.append(int(part))
    else:
        port_list = PORT_PRESETS[preset]

    section(f"Port Scan: {target} ({len(port_list)} ports)")

    last_open = []
    with progress_context("Scanning", len(port_list)) as progress:
        task = progress.add_task("Scanning", total=len(port_list))

        def on_progress(done, total, r):
            if r:
                last_open.append(r)
                progress.update(task, description=f"Found port {r.port}")
            progress.update(task, completed=done)

        report = run_scan(clean_target(target), port_list,
                          max_workers=workers, timeout=timeout,
                          progress_cb=on_progress)

    if json_output:
        print_json(report.to_dict())
        return

    if report.errors:
        error(", ".join(report.errors))
        return

    metric_row({
        "IP": report.ip,
        "Open": len(report.open_ports),
        "Risk": f"{report.risk_score}/100",
        "Duration": f"{report.duration_sec}s",
    })

    if report.os_guess:
        info(f"OS: {report.os_guess.get('os')} (TTL {report.os_guess.get('ttl')})")

    if report.open_ports:
        section("Open Ports")
        result_table(
            "Results",
            ["Port", "Service", "Banner"],
            [[p.port, p.service, p.banner[:60] or "-"]
             for p in report.open_ports],
        )
    else:
        success("No open ports found")

    save_scan("PortScan", target, report.to_dict(), report.risk_score)


# =========================================================
# DNS
# =========================================================
@cli.command()
@click.argument("domain")
@click.option("--json-output", "-j", is_flag=True)
def dns(domain, json_output):
    """DNS & IP intelligence."""
    section(f"DNS Lookup: {domain}")
    result = dns_lookup(domain)

    if json_output:
        print_json(result)
        return

    if result.get("error"):
        error(result["error"])
        return

    metric_row({
        "Domain": result["domain"],
        "IP": result["ip"],
        "Country": result.get("country", "-"),
    })

    if result.get("reverse_dns"):
        info(f"Reverse DNS: {result['reverse_dns']}")
    if result.get("isp"):
        info(f"ISP: {result['isp']}")
    if result.get("asn"):
        info(f"ASN: {result['asn']}")

    save_scan("DNS", domain, result)


# =========================================================
# WEB AUDIT
# =========================================================
@cli.command()
@click.argument("url")
@click.option("--ignore-ssl", is_flag=True)
@click.option("--json-output", "-j", is_flag=True)
def web_audit(url, ignore_ssl, json_output):
    """Audit HTTP security headers."""
    section(f"Web Audit: {url}")
    engine = HTTPEngine()
    result = audit_web(engine, normalize_url(url), ignore_ssl=ignore_ssl)

    if json_output:
        print_json(result)
        return

    metric_row({
        "Status": result["status"],
        "SSL": "valid" if result["ssl_verified"] else "invalid",
        "Risk": f"{result['risk_score']}/100",
    })

    if result["server"]:
        warn(f"Server banner: {result['server']}")
    if result["x_powered_by"]:
        warn(f"X-Powered-By: {result['x_powered_by']}")

    if result["headers_found"]:
        success(f"Found {len(result['headers_found'])} security headers")
    if result["headers_missing"]:
        section("Missing Headers")
        for h in result["headers_missing"]:
            warn(h)

    save_scan("WebAudit", url, result, result["risk_score"])


# =========================================================
# SSL
# =========================================================
@cli.command()
@click.argument("host")
@click.option("--port", "-p", default=443)
def ssl(host, port):
    """Inspect SSL/TLS certificate."""
    section(f"SSL/TLS: {host}:{port}")
    result = inspect_ssl(host, port)

    if result.get("error"):
        error(result["error"])
        return

    metric_row({
        "TLS": result["tls_version"],
        "Cipher": result["cipher"],
        "CN": result["cn"],
    })

    info(f"Issuer: {result['issuer']}")
    info(f"Valid: {result['valid_from']} → {result['valid_until']}")

    if result["sans"]:
        section(f"SANs ({len(result['sans'])})")
        for san in result["sans"][:20]:
            console.print(f"  • {san}")

    save_scan("SSL", host, result)


# =========================================================
# SUBDOMAIN
# =========================================================
@cli.command()
@click.argument("domain")
@click.option("--no-crtsh", is_flag=True)
@click.option("--json-output", "-j", is_flag=True)
def subdomain(domain, no_crtsh, json_output):
    """Enumerate subdomains."""
    section(f"Subdomain Enum: {domain}")
    result = enumerate_subdomains(clean_target(domain),
                                   use_crtsh=not no_crtsh)

    if json_output:
        print_json(result)
        return

    success(f"Found {result['total']} subdomains (crt.sh: {result['crtsh_count']})")

    if result["found"]:
        result_table(
            "Subdomains",
            ["Host", "IP", "Source"],
            [[i["host"], i["ip"] or "-", i["source"]]
             for i in result["found"]],
        )

    save_scan("Subdomain", domain, result)


# =========================================================
# DIRECTORY
# =========================================================
@cli.command()
@click.argument("url")
@click.option("--ignore-ssl", is_flag=True)
@click.option("--json-output", "-j", is_flag=True)
def directory(url, ignore_ssl, json_output):
    """Brute-force directories."""
    section(f"Directory Brute: {url}")
    engine = HTTPEngine()
    result = brute_directory(engine, normalize_url(url),
                             ignore_ssl=ignore_ssl)

    if json_output:
        print_json(result)
        return

    metric_row({
        "Scanned": result["scanned"],
        "Hits": result["total"],
    })

    if result["hits"]:
        result_table(
            "Found Paths",
            ["Path", "Status", "Size"],
            [[h["path"], h["status"], f"{h['size']}B"]
             for h in result["hits"]],
        )
    else:
        success("No paths found")

    save_scan("Directory", url, result)


# =========================================================
# TECH
# =========================================================
@cli.command()
@click.argument("url")
@click.option("--ignore-ssl", is_flag=True)
def tech(url, ignore_ssl):
    """Fingerprint web technologies."""
    section(f"Tech Fingerprint: {url}")
    engine = HTTPEngine()
    result = fingerprint_technology(engine, normalize_url(url),
                                     ignore_ssl=ignore_ssl)

    metric_row({"Detected": result["count"]})

    if result["server"]:
        info(f"Server: {result['server']}")
    if result["powered_by"]:
        info(f"Powered by: {result['powered_by']}")

    for tech_name in result["detected"]:
        success(tech_name)

    save_scan("TechFingerprint", url, result)


# =========================================================
# VULN
# =========================================================
@cli.command()
@click.argument("url")
@click.option("--ignore-ssl", is_flag=True)
def vuln(url, ignore_ssl):
    """Check common vulnerabilities."""
    section(f"Vulnerability Check: {url}")
    engine = HTTPEngine()
    result = check_vulnerabilities(engine, normalize_url(url),
                                    ignore_ssl=ignore_ssl)

    metric_row({
        "Critical": result["critical"],
        "High": result["high"],
    })

    if not result["findings"]:
        success("No common vulnerabilities found")
    else:
        result_table(
            "Findings",
            ["Severity", "Type", "Detail"],
            [[f["severity"], f["type"], f["detail"][:60]]
             for f in result["findings"]],
            severity_col="Severity",
        )

    save_scan("VulnCheck", url, result)


# =========================================================
# EMAIL OSINT
# =========================================================
@cli.command()
@click.argument("domain")
def email(domain):
    """Email security (SPF/DMARC/DKIM)."""
    section(f"Email OSINT: {domain}")
    result = domain_osint(clean_target(domain))

    metric_row({
        "SPF": result["spf_status"],
        "DMARC": result["dmarc_status"],
        "Risk": f"{result['risk_score']}/100",
    })

    save_scan("EmailOSINT", domain, result, result["risk_score"])


# =========================================================
# HISTORY
# =========================================================
@cli.command()
@click.option("--limit", "-l", default=20)
@click.option("--module", "-m", help="Filter by module")
def history(limit, module):
    """Show scan history."""
    section("Scan History")
    scans = get_scans(limit=limit, module=module)

    if not scans:
        info("No scans yet.")
        return

    result_table(
        "History",
        ["ID", "Time", "Module", "Target", "Risk"],
        [[s["id"], s["timestamp"][:19], s["module"],
          s["target"][:30], s["risk_score"]]
         for s in scans],
        severity_col="Risk",
    )


# =========================================================
# REPORTS
# =========================================================
@cli.command()
@click.option("--format", "-f", default="json",
              type=click.Choice(["json", "md"]))
@click.option("--output", "-o", help="Output file")
def report(format, output):
    """Export scan history."""
    scans = get_scans(limit=1000)

    if format == "json":
        content = to_json(scans)
        ext = "json"
    else:
        lines = [f"# {APP_NAME} Report",
                 f"_Generated: {__import__('datetime').datetime.now()}_", ""]
        for s in scans:
            lines.append(f"## [{s['timestamp'][:19]}] {s['module']} → {s['target']}")
            lines.append(f"- **Risk:** {s['risk_score']}/100")
            lines.append(f"- **Data:** `{s['data'][:200]}`")
            lines.append("")
        content = "\n".join(lines)
        ext = "md"

    if output:
        Path(output).write_text(content)
        success(f"Report saved: {output}")
    else:
        if format == "json":
            print_json(scans)
        else:
            print_markdown(content)


# =========================================================
# BATCH SCAN
# =========================================================
@cli.command()
@click.argument("targets_file", type=click.Path(exists=True))
@click.option("--preset", "-P", default="web",
              type=click.Choice(list(PORT_PRESETS.keys())))
def batch(targets_file, preset):
    """Scan multiple targets from file (1 per line)."""
    section(f"Batch Scan: {targets_file}")

    with open(targets_file) as f:
        targets = [line.strip() for line in f if line.strip()]

    info(f"Loaded {len(targets)} targets")

    port_list = PORT_PRESETS[preset]
    results = []

    for i, t in enumerate(targets, 1):
        console.print(f"\n[bold][{i}/{len(targets)}] Scanning {t}...[/bold]")
        try:
            report = run_scan(clean_target(t), port_list, max_workers=100)
            results.append(report)
            if report.open_ports:
                ports = ", ".join(str(p.port) for p in report.open_ports[:10])
                success(f"{t}: {len(report.open_ports)} open ({ports})")
            else:
                info(f"{t}: no open ports")
        except Exception as e:
            error(f"{t}: {e}")

    # Summary
    section("Batch Summary")
    result_table(
        "Summary",
        ["Target", "IP", "Open", "Risk"],
        [[r.target, r.ip, len(r.open_ports), r.risk_score] for r in results],
    )

    save_scan("BatchScan", targets_file, {
        "total_targets": len(targets),
        "results": [r.to_dict() for r in results],
    })


# =========================================================
# INTERACTIVE MODE
# =========================================================
@cli.command()
def interactive():
    """Launch interactive menu."""
    banner()

    while True:
        console.print("\n[bold cyan]═══════ MAIN MENU ═══════[/bold cyan]")
        console.print("  1. 🔒 Password Analyzer")
        console.print("  2. 🌐 Phishing Detector")
        console.print("  3. 📡 Port Scanner")
        console.print("  4. 🔍 DNS Lookup")
        console.print("  5. 💻 Web Audit")
        console.print("  6. 🔐 SSL/TLS Inspector")
        console.print("  7. 🕷️  Subdomain Enum")
        console.print("  8. 📂 Directory Brute")
        console.print("  9. 🧬 Tech Fingerprint")
        console.print(" 10. 🛡️  Vuln Checker")
        console.print(" 11. 📧 Email OSINT")
        console.print(" 12. 📊 Scan History")
        console.print("  0. 🚪 Exit")

        choice = click.prompt("\nPilih menu", type=str).strip()

        try:
            if choice == "1":
                pwd = click.prompt("Password", hide_input=True)
                analyze_password_display(pwd)
            elif choice == "2":
                url = click.prompt("URL")
                phishing.callback(url)
            elif choice == "3":
                target = click.prompt("Target (host/IP)")
                preset = click.prompt(
                    "Preset (top20/top100/web/db/well-known)",
                    default="top100"
                )
                if preset in PORT_PRESETS:
                    scan.callback(target, preset, None, 100, 1.0, False)
                else:
                    error("Invalid preset")
            elif choice == "4":
                domain = click.prompt("Domain")
                dns.callback(domain, False)
            elif choice == "5":
                url = click.prompt("URL")
                web_audit.callback(url, False, False)
            elif choice == "6":
                host = click.prompt("Host")
                ssl.callback(host, 443)
            elif choice == "7":
                domain = click.prompt("Domain")
                subdomain.callback(domain, False, False)
            elif choice == "8":
                url = click.prompt("URL")
                directory.callback(url, False, False)
            elif choice == "9":
                url = click.prompt("URL")
                tech.callback(url, False)
            elif choice == "10":
                url = click.prompt("URL")
                vuln.callback(url, False)
            elif choice == "11":
                domain = click.prompt("Domain")
                email.callback(domain)
            elif choice == "12":
                history.callback(20, None)
            elif choice == "0":
                info("Goodbye! 👋")
                break
            else:
                error("Invalid choice")
        except Exception as e:
            error(f"Error: {e}")

        click.prompt("\n[Enter untuk lanjut]", default="", show_default=False)


def analyze_password_display(pwd):
    """Helper for interactive password display."""
    result = analyze_password(pwd)
    metric_row({
        "Entropy": f"{result['entropy']} bits",
        "Category": result["category"],
        "Crack": result["crack_time"],
    })
    for fb in result["feedback"]:
        info(fb)


# =========================================================
# ENTRY POINT
# =========================================================
if __name__ == "__main__":
    cli()
