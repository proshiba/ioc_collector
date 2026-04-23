#!/usr/bin/env python3
"""
enrich_iocs.py

Reads saved IOC files from ``iocs/`` (or a custom directory), extracts IP
addresses and/or domain names, enriches them with ASN/country/DNS/WHOIS
data, and saves the results to ``enriched_ioc/``.

After a file is successfully enriched and saved, the original IOC file is
automatically deleted.

Usage:
    python app/bin/enrich_iocs.py [--type {ip,domain,all}]
                                   [--ioc-dir IOCS_DIR]
                                   [--output-dir ENRICHED_DIR]

Options:
    --type       Type of IOC to enrich: ip, domain, or all (default: all)
    --ioc-dir    Directory containing collected IOC JSON files (default: iocs)
    --output-dir Directory to save enriched results (default: enriched_ioc)
"""

import argparse
import ipaddress
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Make `module.*` importable regardless of how this script is invoked.
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from module.enrich.enrich_ip import enrich_ip  # noqa: E402
from module.enrich.enrich_domain import enrich_domain  # noqa: E402

IOC_DIR = "iocs"
OUTPUT_DIR = "enriched_ioc"


def _extract_hostname(url: str) -> Optional[str]:
    """Return the hostname component of *url*, or ``None`` on failure."""
    try:
        host = urlparse(url).hostname
        return host if host else None
    except Exception:
        return None


def _is_ip(value: str) -> bool:
    """Return True when *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_iocs_from_entries(entries: List[dict]) -> Tuple[List[str], List[str]]:
    """Extract unique IP addresses and domain names from a list of IOC entries.

    Supports the following source formats automatically:

    * **ThreatFox** – entries with ``ioc_type`` and ``ioc`` fields.
    * **PhishTank** – entries with a ``url`` field and optional
      ``details[].ip_address`` sub-fields.
    * **MalwareBazaar** – entries contain only file hashes; no IPs or
      domains are extracted.

    Args:
        entries: List of IOC entry dicts from the ``data`` key of a saved file.

    Returns:
        A tuple ``(ips, domains)`` where each element is a sorted list of
        unique values.
    """
    ips: set = set()
    domains: set = set()

    for entry in entries:
        ioc_type: str = entry.get("ioc_type", "")
        ioc: str = entry.get("ioc", "")

        if ioc_type:
            # ThreatFox-style entry
            if ioc_type == "ip:port" and ioc:
                # e.g. "198.51.100.42:4444" or "[::1]:80"
                host = ioc.rsplit(":", 1)[0].strip("[]")
                if host and _is_ip(host):
                    ips.add(host)
            elif ioc_type == "ip" and ioc:
                if _is_ip(ioc):
                    ips.add(ioc)
            elif ioc_type == "domain" and ioc:
                domains.add(ioc)
            elif ioc_type == "url" and ioc:
                host = _extract_hostname(ioc)
                if host:
                    if _is_ip(host):
                        ips.add(host)
                    else:
                        domains.add(host)
        else:
            # PhishTank-style entry (no ioc_type field)
            url: str = entry.get("url", "")
            if url:
                host = _extract_hostname(url)
                if host:
                    if _is_ip(host):
                        ips.add(host)
                    else:
                        domains.add(host)

            # PhishTank details may carry resolved IP addresses
            for detail in entry.get("details", []):
                ip_addr: str = detail.get("ip_address", "")
                if ip_addr and _is_ip(ip_addr):
                    ips.add(ip_addr)

    return sorted(ips), sorted(domains)


def enrich_file(
    ioc_path: str,
    output_dir: str,
    enrich_type: str = "all",
) -> str:
    """Enrich the IOCs in *ioc_path* and save the result under *output_dir*.

    Args:
        ioc_path: Path to the collected IOC JSON file.
        output_dir: Directory where the enriched file will be saved.
        enrich_type: One of ``"ip"``, ``"domain"``, or ``"all"``.

    Returns:
        The path of the written enriched file.
    """
    with open(ioc_path, encoding="utf-8") as fh:
        data = json.load(fh)

    entries: List[dict] = data.get("data", [])
    all_ips, all_domains = extract_iocs_from_entries(entries)

    enriched_ips: List[Dict] = []
    enriched_domains: List[Dict] = []

    if enrich_type in ("ip", "all"):
        for ip in all_ips:
            print(f"  Enriching IP: {ip}")
            enriched_ips.append(enrich_ip(ip))

    if enrich_type in ("domain", "all"):
        for domain in all_domains:
            print(f"  Enriching domain: {domain}")
            enriched_domains.append(enrich_domain(domain))

    result = {
        "source_file": ioc_path,
        "enriched_at": datetime.now(tz=timezone.utc).isoformat(),
        "ips": enriched_ips,
        "domains": enriched_domains,
    }

    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.basename(ioc_path)
    output_path = os.path.join(output_dir, filename)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    return output_path


def main(argv: Optional[List[str]] = None, ioc_dir: str = IOC_DIR, output_dir: str = OUTPUT_DIR) -> None:
    parser = argparse.ArgumentParser(
        description="Enrich IOC data (IPs and/or domains) from saved IOC files."
    )
    parser.add_argument(
        "--type",
        dest="enrich_type",
        choices=["ip", "domain", "all"],
        default="all",
        help="Type of IOC to enrich (default: all)",
    )
    parser.add_argument(
        "--ioc-dir",
        default=None,
        help=f"Directory containing collected IOC JSON files (default: {IOC_DIR})",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help=f"Directory to save enriched results (default: {OUTPUT_DIR})",
    )
    args = parser.parse_args(argv)

    effective_ioc_dir = args.ioc_dir if args.ioc_dir is not None else ioc_dir
    effective_output_dir = args.output_dir if args.output_dir is not None else output_dir

    if not os.path.isdir(effective_ioc_dir):
        print(f"IOC directory not found: {effective_ioc_dir!r}", file=sys.stderr)
        sys.exit(1)

    ioc_files = sorted(
        os.path.join(effective_ioc_dir, f)
        for f in os.listdir(effective_ioc_dir)
        if f.endswith(".json")
    )

    if not ioc_files:
        print(f"No IOC files found in {effective_ioc_dir!r}.")
        return

    print(f"Found {len(ioc_files)} IOC file(s) to process.")

    for ioc_path in ioc_files:
        print(f"Processing {ioc_path} …")
        try:
            output_path = enrich_file(ioc_path, effective_output_dir, args.enrich_type)
            print(f"  Saved enriched data to {output_path}")
            os.remove(ioc_path)
            print(f"  Deleted original file {ioc_path}")
        except Exception as exc:
            print(f"  Failed to process {ioc_path}: {exc}", file=sys.stderr)

    print("Done.")


if __name__ == "__main__":
    main()
