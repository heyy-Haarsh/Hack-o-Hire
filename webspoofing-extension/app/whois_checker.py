"""
whois_checker.py – WHOIS with clean error messages and DNS pre-check.
"""
from __future__ import annotations

import socket
import datetime
from typing import TypedDict


class WHOISResult(TypedDict):
    age_days: int
    registrar: str
    creation_date: str
    expiration_date: str
    country: str
    domain_resolvable: bool
    status: str   # "ok" | "dns_failed" | "whois_failed" | "new_domain"
    error: str


def check_whois(domain: str) -> WHOISResult:
    domain = domain.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    # Pre-check: does DNS resolve?
    dns_ok = False
    try:
        socket.setdefaulttimeout(5)
        socket.getaddrinfo(domain, 80)
        dns_ok = True
    except Exception:
        dns_ok = False

    if not dns_ok:
        return {
            "age_days": 0,
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "country": "Unknown",
            "domain_resolvable": False,
            "status": "dns_failed",
            "error": "Domain does not resolve — unregistered, expired, or taken down"
        }

    try:
        import whois
        data = whois.whois(domain)

        creation = data.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        expiration = data.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        now = datetime.datetime.now()
        if creation and isinstance(creation, datetime.datetime):
            if creation.tzinfo is not None:
                now = datetime.datetime.now(datetime.timezone.utc)
            age_days = max((now - creation).days, 0)
        else:
            age_days = 0

        creation_str = creation.strftime("%Y-%m-%d") if isinstance(creation, datetime.datetime) else "Unknown"
        expiration_str = expiration.strftime("%Y-%m-%d") if isinstance(expiration, datetime.datetime) else "Unknown"
        registrar = str(data.registrar or "Unknown")[:60]
        country = str(data.country or "Unknown")

        status = "new_domain" if age_days < 30 else "ok"

        return {
            "age_days": age_days,
            "registrar": registrar,
            "creation_date": creation_str,
            "expiration_date": expiration_str,
            "country": country,
            "domain_resolvable": True,
            "status": status,
            "error": ""
        }

    except Exception as e:
        short_err = str(e)[:80]
        return {
            "age_days": 0,
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "country": "Unknown",
            "domain_resolvable": True,
            "status": "whois_failed",
            "error": f"WHOIS query failed: {short_err}"
        }
