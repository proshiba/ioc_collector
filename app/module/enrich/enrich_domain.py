"""enrich_domain.py

Enriches a domain IOC with DNS resolution and WHOIS registration data.
"""

import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver
import whois


def _normalise(value: Any) -> Optional[str]:
    """Normalise a WHOIS field value to a string or None.

    WHOIS fields can be None, a single value, or a list.  When a list is
    returned the first non-None element is used.  ``datetime`` objects are
    serialised to ISO-8601 strings.
    """
    if value is None:
        return None
    if isinstance(value, list):
        # Pick the first non-None entry.
        value = next((v for v in value if v is not None), None)
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def resolve_dns(domain: str) -> List[str]:
    """Return a sorted list of IPv4 addresses for *domain*.

    Returns an empty list when resolution fails (NXDOMAIN, timeout, etc.).
    """
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


def fetch_whois(domain: str) -> Dict[str, Optional[str]]:
    """Return selected WHOIS fields for *domain*.

    The returned dict always contains these keys (values may be None when the
    field is absent in the WHOIS record):

    - ``registrant_name``
    - ``registrant_email``
    - ``registrar``
    - ``creation_date``
    - ``expiration_date``
    """
    result: Dict[str, Optional[str]] = {
        "registrant_name": None,
        "registrant_email": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
    }
    try:
        w = whois.whois(domain)
        # Registrant name: prefer dedicated field, fall back to generic "name".
        result["registrant_name"] = _normalise(
            w.get("registrant_name") or w.get("name")
        )
        # Registrant email: prefer dedicated field, fall back to first in "emails".
        result["registrant_email"] = _normalise(
            w.get("registrant_email") or w.get("emails")
        )
        result["registrar"] = _normalise(w.get("registrar"))
        result["creation_date"] = _normalise(w.get("creation_date"))
        result["expiration_date"] = _normalise(w.get("expiration_date"))
    except Exception as exc:
        print(f"WHOIS lookup failed for {domain!r}: {exc}", file=sys.stderr)
    return result


def enrich_domain(domain: str) -> Dict[str, Any]:
    """Enrich a domain IOC with DNS and WHOIS data.

    Args:
        domain: The domain name to enrich (e.g. ``"example.com"``).

    Returns:
        A dict with the following structure::

            {
                "domain": "example.com",
                "dns": ["93.184.216.34"],
                "whois": {
                    "registrant_name": "...",
                    "registrant_email": "...",
                    "registrar": "...",
                    "creation_date": "1995-08-14T04:00:00",
                    "expiration_date": "2025-08-13T04:00:00",
                },
            }
    """
    return {
        "domain": domain,
        "dns": resolve_dns(domain),
        "whois": fetch_whois(domain),
    }
