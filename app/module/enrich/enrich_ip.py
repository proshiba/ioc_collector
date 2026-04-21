"""enrich_ip.py

Enriches an IP address IOC with ASN (Autonomous System Number / organisation)
and country information using MaxMind GeoLite2 local databases.

The two required .mmdb files are:
  - GeoLite2-ASN.mmdb   (autonomous system data)
  - GeoLite2-Country.mmdb (country data)

These can be downloaded with ``app/download_maxmind_db.py``.
"""

import sys
from typing import Any, Dict, Optional

import geoip2.database
import geoip2.errors


DEFAULT_ASN_DB_PATH = "data/maxmind/GeoLite2-ASN.mmdb"
DEFAULT_COUNTRY_DB_PATH = "data/maxmind/GeoLite2-Country.mmdb"


def fetch_asn(
    ip: str,
    asn_db_path: str = DEFAULT_ASN_DB_PATH,
) -> Dict[str, Optional[Any]]:
    """Look up ASN information for *ip* using the GeoLite2-ASN database.

    Args:
        ip: IPv4 or IPv6 address string (e.g. ``"1.2.3.4"``).
        asn_db_path: Path to the ``GeoLite2-ASN.mmdb`` file.

    Returns:
        A dict with the following keys (values may be ``None`` on lookup failure):

        - ``asn``  – Autonomous System Number as an integer (e.g. ``15169``).
        - ``org``  – Autonomous System Organisation name (e.g. ``"GOOGLE"``).
    """
    result: Dict[str, Optional[Any]] = {"asn": None, "org": None}
    try:
        with geoip2.database.Reader(asn_db_path) as reader:
            response = reader.asn(ip)
            result["asn"] = response.autonomous_system_number
            result["org"] = response.autonomous_system_organization
    except FileNotFoundError:
        print(
            f"ASN database not found at {asn_db_path!r}. "
            "Run download_maxmind_db.py first.",
            file=sys.stderr,
        )
    except geoip2.errors.AddressNotFoundError:
        print(f"IP address {ip!r} not found in ASN database.", file=sys.stderr)
    except Exception as exc:
        print(f"ASN lookup failed for {ip!r}: {exc}", file=sys.stderr)
    return result


def fetch_country(
    ip: str,
    country_db_path: str = DEFAULT_COUNTRY_DB_PATH,
) -> Dict[str, Optional[str]]:
    """Look up country information for *ip* using the GeoLite2-Country database.

    Args:
        ip: IPv4 or IPv6 address string.
        country_db_path: Path to the ``GeoLite2-Country.mmdb`` file.

    Returns:
        A dict with the following keys (values may be ``None`` on lookup failure):

        - ``country_code``  – ISO 3166-1 alpha-2 country code (e.g. ``"US"``).
        - ``country_name``  – English country name (e.g. ``"United States"``).
    """
    result: Dict[str, Optional[str]] = {"country_code": None, "country_name": None}
    try:
        with geoip2.database.Reader(country_db_path) as reader:
            response = reader.country(ip)
            result["country_code"] = response.country.iso_code
            result["country_name"] = response.country.name
    except FileNotFoundError:
        print(
            f"Country database not found at {country_db_path!r}. "
            "Run download_maxmind_db.py first.",
            file=sys.stderr,
        )
    except geoip2.errors.AddressNotFoundError:
        print(f"IP address {ip!r} not found in Country database.", file=sys.stderr)
    except Exception as exc:
        print(f"Country lookup failed for {ip!r}: {exc}", file=sys.stderr)
    return result


def enrich_ip(
    ip: str,
    asn_db_path: str = DEFAULT_ASN_DB_PATH,
    country_db_path: str = DEFAULT_COUNTRY_DB_PATH,
) -> Dict[str, Any]:
    """Enrich an IP address IOC with ASN and country data.

    Args:
        ip: IPv4 or IPv6 address string (e.g. ``"1.2.3.4"``).
        asn_db_path: Path to the ``GeoLite2-ASN.mmdb`` file.
        country_db_path: Path to the ``GeoLite2-Country.mmdb`` file.

    Returns:
        A dict with the following structure::

            {
                "ip": "1.2.3.4",
                "asn": 15169,
                "org": "GOOGLE",
                "country_code": "US",
                "country_name": "United States",
            }
    """
    asn_info = fetch_asn(ip, asn_db_path=asn_db_path)
    country_info = fetch_country(ip, country_db_path=country_db_path)
    return {
        "ip": ip,
        "asn": asn_info["asn"],
        "org": asn_info["org"],
        "country_code": country_info["country_code"],
        "country_name": country_info["country_name"],
    }
