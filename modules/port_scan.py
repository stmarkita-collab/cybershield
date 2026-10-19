"""Port scanner."""
import ssl
import time
import socket
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from core.config import SERVICE_NAME_MAP, RISK_PORT_WEIGHTS


@dataclass
class PortResult:
    port: int
    state: str = "closed"
    service: str = ""
    banner: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class PortScanReport:
    target: str
    ip: str
    started: str = ""
    finished: str = ""
    duration_sec: float = 0.0
    total_ports: int = 0
    open_ports: list = field(default_factory=list)
    os_guess: dict = field(default_factory=dict)
    risk_score: int = 0
    errors: list = field(default_factory=list)

    def to_dict(self):
        return {
            "target": self.target, "ip": self.ip, "started": self.started,
            "finished": self.finished, "duration_sec": self.duration_sec,
            "total_ports": self.total_ports,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "os_guess": self.os_guess, "risk_score": self.risk_score,
            "errors": self.errors,
        }


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    if port in (80, 8080, 8000):
        probe = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
    elif port in (443, 8443):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    subj = dict(x[0] for x in cert.get("subject", ()))
                    return f"TLS {ssock.version()}, CN={subj.get('commonName', '-')}"
        except Exception:
            return ""
    elif port in (21, 22, 110):
        probe = b""
    else:
        probe = b"\r\n"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if probe:
            s.send(probe)
        s.settimeout(1.5)
        try:
            banner = s.recv(2048).decode(errors="ignore").strip()
        except socket.timeout:
            banner = ""
        s.close()
        return banner[:200]
    except Exception:
        return ""


def _scan_port(ip: str, port: int, timeout: float = 1.0) -> PortResult:
    result = PortResult(port=port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((ip, port))
        s.close()
        if rc == 0:
            result.state = "open"
            result.banner = _grab_banner(ip, port)
            result.service = SERVICE_NAME_MAP.get(port, "unknown")
    except Exception:
        result.state = "filtered"
    return result


def os_fingerprint(ip: str) -> dict:
    result = {"os": "Unknown", "ttl": None, "confidence": "low"}
    for port in [80, 443, 22]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            try:
                result["ttl"] = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                s.close()
                break
            except Exception:
                s.close()
        except Exception:
            continue

    ttl = result["ttl"]
    if ttl is None:
        return result
    if ttl <= 32:
        result["os"] = "Embedded/IoT"
    elif ttl <= 64:
        result["os"] = "Linux / Unix / macOS"
        result["confidence"] = "high" if ttl >= 60 else "medium"
    elif ttl <= 128:
        result["os"] = "Windows"
        result["confidence"] = "high" if ttl >= 120 else "medium"
    elif ttl <= 255:
        result["os"] = "Network device"
        result["confidence"] = "medium"
    return result


def run_scan(target: str, ports: list, max_workers: int = 100,
             timeout: float = 1.0, progress_cb=None) -> PortScanReport:
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        return PortScanReport(target=target, ip="", errors=[str(e)])

    started = datetime.now().isoformat()
    t0 = time.perf_counter()

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_scan_port, ip, p, timeout): p for p in ports}
        done = 0
        for fut in as_completed(futures):
            r = fut.result()
            if r.state == "open":
                open_ports.append(r)
                if progress_cb:
                    progress_cb(done, len(ports), r)
            done += 1
            if progress_cb:
                progress_cb(done, len(ports), None)

    elapsed = time.perf_counter() - t0
    os_guess = os_fingerprint(ip) if open_ports else {}

    risk = min(100, sum(RISK_PORT_WEIGHTS.get(p.port, 0) for p in open_ports))

    return PortScanReport(
        target=target, ip=ip, started=started,
        finished=datetime.now().isoformat(),
        duration_sec=round(elapsed, 2), total_ports=len(ports),
        open_ports=sorted(open_ports, key=lambda x: x.port),
        os_guess=os_guess, risk_score=risk,
      )
