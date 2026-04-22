"""virustotal.py

Enriches IOCs (IP addresses, domains, and file hashes) using the VirusTotal
API v3.  For each indicator type the following data is collected:

* **Detection stats** – counts of malicious / suspicious / harmless /
  undetected verdicts from the last analysis.
* **Relations** – files communicating with the indicator, resolved hosts /
  IPs, files downloaded from the indicator (IP/domain), or network
  infrastructure contacted by the file (hash).
* **Behavior** – key items from sandbox behaviour reports (processes created,
  network connections, DNS lookups, dropped files) for file hashes.

The VirusTotal API key is read from the ``VIRUSTOTAL_API_KEY`` environment
variable.  All public functions accept an optional ``api_key`` parameter that
overrides the environment variable.
"""

import os
import sys
from typing import Any, Dict, List, Optional

import requests

VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"

# Maximum number of relation items to collect per relationship type.
_MAX_RELATION_ITEMS = 10


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_api_key(api_key: Optional[str]) -> str:
    """Return *api_key* if provided, else read ``VIRUSTOTAL_API_KEY`` env var."""
    if api_key:
        return api_key
    return os.environ.get("VIRUSTOTAL_API_KEY", "")


def _vt_get(
    path: str,
    api_key: str,
    params: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Perform a GET request against the VirusTotal v3 API.

    Args:
        path: API path relative to the base URL (e.g. ``"/ip_addresses/1.2.3.4"``).
        api_key: VirusTotal API key.
        params: Optional query parameters.

    Returns:
        Parsed JSON response dict, or ``None`` on any error.
    """
    url = f"{VIRUSTOTAL_API_BASE}{path}"
    try:
        response = requests.get(
            url,
            headers={"x-apikey": api_key},
            params=params,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()
    except requests.HTTPError as exc:
        print(
            f"VirusTotal API HTTP error for {url!r}: {exc}",
            file=sys.stderr,
        )
    except requests.RequestException as exc:
        print(
            f"VirusTotal API request failed for {url!r}: {exc}",
            file=sys.stderr,
        )
    except Exception as exc:
        print(
            f"Unexpected error fetching {url!r}: {exc}",
            file=sys.stderr,
        )
    return None


def _extract_stats(attributes: Dict[str, Any]) -> Dict[str, Optional[int]]:
    """Extract last_analysis_stats from an attributes dict."""
    stats = attributes.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
    }


def _extract_relation_files(data: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return a summarised list of file objects from a relationship response."""
    if not data:
        return []
    items = []
    for entry in data.get("data", [])[:_MAX_RELATION_ITEMS]:
        attrs = entry.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        items.append(
            {
                "sha256": attrs.get("sha256"),
                "meaningful_name": attrs.get("meaningful_name"),
                "type_description": attrs.get("type_description"),
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
            }
        )
    return items


# ---------------------------------------------------------------------------
# IP enrichment
# ---------------------------------------------------------------------------


def enrich_ip(
    ip: str,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Enrich an IP address IOC with VirusTotal data.

    Collected information:

    * Detection stats (malicious / suspicious / harmless / undetected)
    * ASN, country, owner, network
    * Relation: files that communicated with this IP (up to
      :data:`_MAX_RELATION_ITEMS`)
    * Relation: files downloaded from this IP (up to
      :data:`_MAX_RELATION_ITEMS`)

    Args:
        ip: IPv4 or IPv6 address string.
        api_key: VirusTotal API key.  Falls back to the
            ``VIRUSTOTAL_API_KEY`` environment variable when omitted.

    Returns:
        A dict with keys ``ip``, ``stats``, ``asn``, ``country``, ``owner``,
        ``network``, ``communicating_files``, and ``downloaded_files``.
        Values are ``None`` when the lookup fails.
    """
    key = _get_api_key(api_key)
    result: Dict[str, Any] = {
        "ip": ip,
        "stats": None,
        "asn": None,
        "country": None,
        "owner": None,
        "network": None,
        "communicating_files": [],
        "downloaded_files": [],
    }

    # --- Main IP object ---
    data = _vt_get(f"/ip_addresses/{ip}", key)
    if data:
        attrs = data.get("data", {}).get("attributes", {})
        result["stats"] = _extract_stats(attrs)
        result["asn"] = attrs.get("asn")
        result["country"] = attrs.get("country")
        result["owner"] = attrs.get("as_owner")
        result["network"] = attrs.get("network")

    # --- Relation: communicating files ---
    comm_data = _vt_get(
        f"/ip_addresses/{ip}/communicating_files",
        key,
        params={"limit": _MAX_RELATION_ITEMS},
    )
    result["communicating_files"] = _extract_relation_files(comm_data)

    # --- Relation: downloaded files ---
    dl_data = _vt_get(
        f"/ip_addresses/{ip}/downloaded_files",
        key,
        params={"limit": _MAX_RELATION_ITEMS},
    )
    result["downloaded_files"] = _extract_relation_files(dl_data)

    return result


# ---------------------------------------------------------------------------
# Domain enrichment
# ---------------------------------------------------------------------------


def enrich_domain(
    domain: str,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Enrich a domain IOC with VirusTotal data.

    Collected information:

    * Detection stats
    * Categories assigned by various vendors
    * Creation and last update dates
    * Relation: resolutions (IP addresses the domain resolved to, up to
      :data:`_MAX_RELATION_ITEMS`)
    * Relation: files that communicated with this domain (up to
      :data:`_MAX_RELATION_ITEMS`)

    Args:
        domain: Fully-qualified domain name.
        api_key: VirusTotal API key.

    Returns:
        A dict with keys ``domain``, ``stats``, ``categories``,
        ``creation_date``, ``last_update_date``, ``resolutions``, and
        ``communicating_files``.
    """
    key = _get_api_key(api_key)
    result: Dict[str, Any] = {
        "domain": domain,
        "stats": None,
        "categories": {},
        "creation_date": None,
        "last_update_date": None,
        "resolutions": [],
        "communicating_files": [],
    }

    # --- Main domain object ---
    data = _vt_get(f"/domains/{domain}", key)
    if data:
        attrs = data.get("data", {}).get("attributes", {})
        result["stats"] = _extract_stats(attrs)
        result["categories"] = attrs.get("categories", {})
        result["creation_date"] = attrs.get("creation_date")
        result["last_update_date"] = attrs.get("last_update_date")

    # --- Relation: resolutions ---
    res_data = _vt_get(
        f"/domains/{domain}/resolutions",
        key,
        params={"limit": _MAX_RELATION_ITEMS},
    )
    if res_data:
        for entry in res_data.get("data", [])[:_MAX_RELATION_ITEMS]:
            attrs = entry.get("attributes", {})
            result["resolutions"].append(
                {
                    "ip_address": attrs.get("ip_address"),
                    "date": attrs.get("date"),
                }
            )

    # --- Relation: communicating files ---
    comm_data = _vt_get(
        f"/domains/{domain}/communicating_files",
        key,
        params={"limit": _MAX_RELATION_ITEMS},
    )
    result["communicating_files"] = _extract_relation_files(comm_data)

    return result


# ---------------------------------------------------------------------------
# Hash enrichment
# ---------------------------------------------------------------------------


def _extract_behavior_summary(behaviors: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate key behavioral indicators across all sandbox reports.

    Collected items (all de-duplicated, order preserved):

    * ``processes_created`` – command lines of spawned processes
    * ``network_connections`` – ``"ip:port"`` strings of TCP/UDP connections
    * ``dns_lookups`` – hostnames queried
    * ``files_dropped`` – paths of files written to disk
    * ``mutexes_created`` – mutex names created

    Args:
        behaviors: List of behavior summary objects from
            ``GET /files/{hash}/behaviours``.

    Returns:
        A dict with the keys listed above, each containing a de-duplicated
        list (up to :data:`_MAX_RELATION_ITEMS` entries each).
    """
    seen_processes: List[str] = []
    seen_connections: List[str] = []
    seen_dns: List[str] = []
    seen_files: List[str] = []
    seen_mutexes: List[str] = []

    def _add_unique(target: List[str], values: List[Any]) -> None:
        for v in values:
            s = str(v) if v is not None else None
            if s and s not in target and len(target) < _MAX_RELATION_ITEMS:
                target.append(s)

    for sandbox in behaviors:
        attrs = sandbox.get("attributes", {})

        _add_unique(
            seen_processes,
            attrs.get("processes_created", []),
        )

        for conn in attrs.get("network_tcp", []) + attrs.get("network_udp", []):
            dest = conn.get("destination_ip") or conn.get("ip")
            port = conn.get("destination_port") or conn.get("port")
            if dest:
                entry = f"{dest}:{port}" if port else dest
                if entry not in seen_connections and len(seen_connections) < _MAX_RELATION_ITEMS:
                    seen_connections.append(entry)

        _add_unique(seen_dns, attrs.get("dns_lookups", []))
        _add_unique(seen_files, attrs.get("files_dropped", []))
        _add_unique(seen_mutexes, attrs.get("mutexes_created", []))

    return {
        "processes_created": seen_processes,
        "network_connections": seen_connections,
        "dns_lookups": seen_dns,
        "files_dropped": seen_files,
        "mutexes_created": seen_mutexes,
    }


def enrich_hash(
    file_hash: str,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Enrich a file hash IOC with VirusTotal data.

    Supports MD5, SHA-1, and SHA-256 hashes.

    Collected information:

    * Detection stats
    * File metadata (type, size, common name)
    * Relation: IP addresses contacted by the file (up to
      :data:`_MAX_RELATION_ITEMS`)
    * Relation: domains contacted by the file (up to
      :data:`_MAX_RELATION_ITEMS`)
    * Behavior: aggregated sandbox data (processes, network connections, DNS
      lookups, dropped files, mutexes)

    Args:
        file_hash: MD5, SHA-1, or SHA-256 hash string.
        api_key: VirusTotal API key.

    Returns:
        A dict with keys ``hash``, ``stats``, ``type_description``, ``size``,
        ``meaningful_name``, ``contacted_ips``, ``contacted_domains``, and
        ``behavior``.
    """
    key = _get_api_key(api_key)
    result: Dict[str, Any] = {
        "hash": file_hash,
        "stats": None,
        "type_description": None,
        "size": None,
        "meaningful_name": None,
        "contacted_ips": [],
        "contacted_domains": [],
        "behavior": None,
    }

    # --- Main file object ---
    data = _vt_get(f"/files/{file_hash}", key)
    if data:
        attrs = data.get("data", {}).get("attributes", {})
        result["stats"] = _extract_stats(attrs)
        result["type_description"] = attrs.get("type_description")
        result["size"] = attrs.get("size")
        result["meaningful_name"] = attrs.get("meaningful_name")

    # --- Relation: contacted IPs ---
    ip_data = _vt_get(
        f"/files/{file_hash}/contacted_ips",
        key,
        params={"limit": _MAX_RELATION_ITEMS},
    )
    if ip_data:
        for entry in ip_data.get("data", [])[:_MAX_RELATION_ITEMS]:
            attrs = entry.get("attributes", {})
            ip_stats = attrs.get("last_analysis_stats", {})
            result["contacted_ips"].append(
                {
                    "ip": entry.get("id"),
                    "country": attrs.get("country"),
                    "owner": attrs.get("as_owner"),
                    "malicious": ip_stats.get("malicious"),
                }
            )

    # --- Relation: contacted domains ---
    domain_data = _vt_get(
        f"/files/{file_hash}/contacted_domains",
        key,
        params={"limit": _MAX_RELATION_ITEMS},
    )
    if domain_data:
        for entry in domain_data.get("data", [])[:_MAX_RELATION_ITEMS]:
            attrs = entry.get("attributes", {})
            dom_stats = attrs.get("last_analysis_stats", {})
            result["contacted_domains"].append(
                {
                    "domain": entry.get("id"),
                    "malicious": dom_stats.get("malicious"),
                    "categories": attrs.get("categories", {}),
                }
            )

    # --- Behavior: sandbox reports ---
    behavior_data = _vt_get(f"/files/{file_hash}/behaviours", key)
    if behavior_data:
        sandboxes = behavior_data.get("data", [])
        result["behavior"] = _extract_behavior_summary(sandboxes)

    return result
