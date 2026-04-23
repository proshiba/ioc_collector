#!/usr/bin/env python3
"""
collect_iocs.py

Collects IOCs from the specified source and saves them to
iocs/<yyyymmdd>.json (one file per run date).

Usage:
    python app/bin/collect_iocs.py [--source {threatfox,phishtank}]

The `iocs/` output directory is created automatically if it does not exist.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

# Make `module.*` importable regardless of how this script is invoked.
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from module.fetch.threatfox import fetch_daily_iocs as _fetch_threatfox  # noqa: E402
from module.fetch.phishtank import fetch_iocs as _fetch_phishtank  # noqa: E402

OUTPUT_DIR = "iocs"

# Registry of available sources.  Add new sources here.
SOURCES: Dict[str, Callable[[], dict]] = {
    "threatfox": _fetch_threatfox,
    "phishtank": _fetch_phishtank,
}


def save_iocs(data: dict, output_path: str) -> None:
    """Write *data* to *output_path* as pretty-printed JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def main(argv: Optional[List[str]] = None, output_dir: str = OUTPUT_DIR) -> None:
    parser = argparse.ArgumentParser(
        description="Collect daily IOCs from a threat intelligence source."
    )
    parser.add_argument(
        "--source",
        choices=list(SOURCES.keys()),
        default="threatfox",
        help="IOC data source to collect from (default: threatfox)",
    )
    args = parser.parse_args(argv)

    fetch_fn = SOURCES[args.source]

    today = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
    output_path = os.path.join(output_dir, f"{today}.json")

    print(f"Fetching IOCs from {args.source} for the last day …")
    data = fetch_fn()

    query_status = data.get("query_status", "")
    if query_status != "ok":
        print(
            f"{args.source} returned an unexpected status: {query_status}",
            file=sys.stderr,
        )
        sys.exit(1)

    iocs = data.get("data", [])
    print(f"Retrieved {len(iocs)} IOC(s).")

    save_iocs(data, output_path)
    print(f"Saved to {output_path}")


if __name__ == "__main__":
    main()
