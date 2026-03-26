"""
ssl_checker.py – Checks SSL certificate validity for a domain.
"""
from __future__ import annotations

import ssl
import socket
import datetime
from typing import TypedDict


class SSLResult(TypedDict):
    valid: bool
    issuer: str
    subject: str
    expires_in_days: int
    status: str          # "valid" | "invalid" | "unreachable" | "no_ssl"
    error: str


def check_ssl(domain: str) -> SSLResult:
    domain = domain.split(":")[0]
    if not domain:
        return _error_result(domain, "invalid", "Empty domain")

    # First: check if domain even resolves (DNS)
    try:
        socket.setdefaulttimeout(5)
        socket.getaddrinfo(domain, 443)
    except socket.gaierror:
        return _error_result(domain, "unreachable", "Domain does not resolve (DNS failure — likely a dead or fake domain)")
    except Exception as e:
        return _error_result(domain, "unreachable", f"Network error: {type(e).__name__}")

    # Try SSL connection
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=7),
            server_hostname=domain
        ) as ssock:
            cert = ssock.getpeercert()

        expire_str = cert.get("notAfter", "")
        expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        expire_dt = expire_dt.replace(tzinfo=datetime.timezone.utc)
        days_left = (expire_dt - datetime.datetime.now(datetime.timezone.utc)).days

        def parse_rdns(rdns_seq) -> str:
            parts = []
            for rdn in rdns_seq:
                for attr in rdn:
                    if attr[0] in ("O", "CN", "organizationName", "commonName"):
                        parts.append(str(attr[1]))
            return ", ".join(parts[:2]) if parts else ""

        issuer = parse_rdns(cert.get("issuer", []))
        subject = parse_rdns(cert.get("subject", []))

        return {
            "valid": days_left > 0,
            "issuer": issuer or "Unknown CA",
            "subject": subject or domain,
            "expires_in_days": max(days_left, 0),
            "status": "valid" if days_left > 0 else "expired",
            "error": ""
        }

    except ssl.SSLCertVerificationError:
        return _error_result(domain, "invalid", "Certificate is UNTRUSTED — self-signed or fake CA")
    except ssl.SSLError as e:
        msg = str(e)
        short = msg[:80] if len(msg) > 80 else msg
        return _error_result(domain, "invalid", f"SSL handshake failed: {short}")
    except (socket.timeout, ConnectionRefusedError):
        return _error_result(domain, "no_ssl", "Port 443 refused — site may not support HTTPS")
    except Exception as e:
        return _error_result(domain, "unknown", f"{type(e).__name__}: {str(e)[:60]}")


def _error_result(domain: str, status: str, error: str) -> SSLResult:
    return {
        "valid": False,
        "issuer": "",
        "subject": domain,
        "expires_in_days": 0,
        "status": status,
        "error": error
    }
