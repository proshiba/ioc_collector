"""enrich_domain.py

Enriches a domain IOC with DNS resolution and registration data.

Registration lookup order for a given input domain:
  1. WHOIS (port 43 via python-whois)
  2. RDAP  (HTTPS via rdap.org bootstrap)
  3. If both fail, extract the registered domain using tldextract (handles
     multi-part public suffixes such as co.jp) and retry steps 1-2.
"""

import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver
import requests
import tldextract
import whois

_EMPTY_REGISTRATION: Dict[str, Optional[str]] = {
    "registrant_name": None,
    "registrant_email": None,
    "registrar": None,
    "creation_date": None,
    "expiration_date": None,
}


def _normalise(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        value = next((v for v in value if v is not None), None)
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def resolve_dns(domain: str) -> List[str]:
    """Return a sorted list of IPv4 addresses for *domain*."""
    try:
        answers = dns.resolver.resolve(domain, "A")
        return sorted(str(rdata) for rdata in answers)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
        dns.exception.DNSException,
    ) as exc:
        print(f"DNS resolution failed for {domain!r}: {exc}", file=sys.stderr)
        return []


def _try_whois(domain: str) -> Optional[Dict[str, Optional[str]]]:
    """Return parsed WHOIS fields, or None if the lookup raised an exception."""
    try:
        w = whois.whois(domain)
        return {
            "registrant_name": _normalise(
                w.get("registrant_name") or w.get("name")
            ),
            "registrant_email": _normalise(
                w.get("registrant_email") or w.get("emails")
            ),
            "registrar": _normalise(w.get("registrar")),
            "creation_date": _normalise(w.get("creation_date")),
            "expiration_date": _normalise(w.get("expiration_date")),
        }
    except Exception:
        return None


def _parse_rdap(data: dict) -> Dict[str, Optional[str]]:
    """Extract registration fields from an RDAP domain response."""
    result: Dict[str, Optional[str]] = dict(_EMPTY_REGISTRATION)

    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard_fields = entity.get("vcardArray", [None, []])[1]

        if "registrar" in roles:
            for field in vcard_fields:
                if field[0] == "fn":
                    result["registrar"] = field[3] or None

        if "registrant" in roles:
            for field in vcard_fields:
                if field[0] == "fn":
                    result["registrant_name"] = field[3] or None
                elif field[0] == "email":
                    result["registrant_email"] = field[3] or None

    for event in data.get("events", []):
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action == "registration":
            result["creation_date"] = date
        elif action == "expiration":
            result["expiration_date"] = date

    return result


def _try_rdap(domain: str) -> Optional[Dict[str, Optional[str]]]:
    """Return parsed RDAP fields, or None if the request failed."""
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=10,
            headers={"Accept": "application/rdap+json"},
        )
        r.raise_for_status()
        return _parse_rdap(r.json())
    except Exception:
        return None


def _registered_domain(domain: str) -> Optional[str]:
    """Return the registered domain for *domain* using the Public Suffix List.

    Handles multi-part suffixes (e.g. co.jp, com.br) correctly.
    Returns None when extraction fails or the result equals the input.
    """
    ext = tldextract.extract(domain)
    rd = ext.top_domain_under_public_suffix
    if rd and rd != domain:
        return rd
    return None


def fetch_whois(domain: str) -> Dict[str, Optional[str]]:
    """Return registration info for *domain*.

    Lookup order:
      1. WHOIS for *domain*
      2. RDAP  for *domain*
      3. Extract registered domain via tldextract, then retry WHOIS → RDAP
    """
    result = _try_whois(domain) or _try_rdap(domain)
    if result is not None:
        return result

    rd = _registered_domain(domain)
    if rd:
        result = _try_whois(rd) or _try_rdap(rd)

    return result or dict(_EMPTY_REGISTRATION)


def enrich_domain(domain: str) -> Dict[str, Any]:
    """Enrich a domain IOC with DNS and registration data."""
    return {
        "domain": domain,
        "dns": resolve_dns(domain),
        "whois": fetch_whois(domain),
    }
