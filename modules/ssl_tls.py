"""SSL/TLS inspector."""
import ssl
import socket


def inspect_ssl(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    clean = host.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                ver = ssock.version()

        subj = dict(x[0] for x in cert.get("subject", ()))
        iss = dict(x[0] for x in cert.get("issuer", ()))
        sans = [x[1] for x in cert.get("subjectAltName", ())]

        return {
            "host": clean, "tls_version": ver,
            "cipher": cipher[0] if cipher else None,
            "cn": subj.get("commonName"),
            "issuer": iss.get("organizationName"),
            "valid_from": cert.get("notBefore"),
            "valid_until": cert.get("notAfter"),
            "sans": sans,
        }
    except Exception as e:
        return {"error": str(e)}
