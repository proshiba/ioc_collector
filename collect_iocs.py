#!/usr/bin/env python3
"""
collect_iocs.py

Retrieves IOCs from ThreatFox for the past day and saves them to
iocs/<yyyymmdd>.json (one file per run date).

Usage:
    python collect_iocs.py

The script creates the `iocs/` directory if it does not already exist.
"""

import json
import os
import sys
from datetime import datetime, timezone

import requests

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
OUTPUT_DIR = "iocs"


def fetch_daily_iocs() -> dict:
    """Call the ThreatFox API and return the JSON response for the last day."""
    payload = {
        "query": "get_iocs",
        "days": 1,
    }
    try:
        response = requests.post(
            THREATFOX_API_URL,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"ThreatFox API request failed: {exc}", file=sys.stderr)
        raise
    return response.json()


def save_iocs(data: dict, output_path: str) -> None:
    """Write *data* to *output_path* as pretty-printed JSON."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def main() -> None:
    today = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
    output_path = os.path.join(OUTPUT_DIR, f"{today}.json")

    print("Fetching IOCs from ThreatFox for the last day …")
    data = fetch_daily_iocs()

    query_status = data.get("query_status", "")
    if query_status != "ok":
        print(f"ThreatFox returned an unexpected status: {query_status}", file=sys.stderr)
        sys.exit(1)

    iocs = data.get("data", [])
    print(f"Retrieved {len(iocs)} IOC(s).")

    save_iocs(data, output_path)
    print(f"Saved to {output_path}")


if __name__ == "__main__":
    main()
