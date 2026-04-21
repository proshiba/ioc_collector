#!/usr/bin/env python3
"""
download_maxmind_db.py

Downloads the MaxMind GeoLite2-ASN and GeoLite2-Country databases and saves
the .mmdb files to the specified output directory.

Usage:
    python app/bin/download_maxmind_db.py [--dest-dir data/maxmind]

The MaxMind license key must be set via the ``MAXMIND_LICENSE_KEY`` environment
variable.  A free license key can be obtained by registering at
https://www.maxmind.com/en/geolite2/signup.
"""

import argparse
import os
import sys
from typing import Optional, List

# Make `module.*` importable regardless of how this script is invoked.
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from module.fetch.maxmind_db import DEFAULT_DB_DIR, download_maxmind_dbs  # noqa: E402


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Download MaxMind GeoLite2 IP databases (ASN and Country)."
    )
    parser.add_argument(
        "--dest-dir",
        default=DEFAULT_DB_DIR,
        help=f"Directory to save the .mmdb files (default: {DEFAULT_DB_DIR})",
    )
    args = parser.parse_args(argv)

    license_key = os.environ.get("MAXMIND_LICENSE_KEY")
    if not license_key:
        print(
            "Error: MAXMIND_LICENSE_KEY environment variable is not set.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Downloading MaxMind GeoLite2 databases to '{args.dest_dir}' ...")
    try:
        paths = download_maxmind_dbs(dest_dir=args.dest_dir, license_key=license_key)
    except Exception as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        sys.exit(1)

    for edition, path in paths.items():
        print(f"  {edition}: {path}")
    print("Done.")


if __name__ == "__main__":
    main()
