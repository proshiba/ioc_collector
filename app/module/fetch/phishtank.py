"""phishtank.py

Fetches active phishing IOCs from the PhishTank data feed
(https://www.phishtank.com/developer_info.php).
"""

import os
import sys

import requests

PHISHTANK_DATA_URL = "https://data.phishtank.com/data/{api_key}online-valid.json"


def fetch_iocs() -> dict:
    """Download the PhishTank online-valid feed and return a normalised response.

    The returned dict always has the shape::

        {
            "query_status": "ok",
            "data": [ <phishtank entry>, ... ]
        }

    Set the environment variable ``PHISHTANK_API_KEY`` to your PhishTank
    application key.  When the variable is absent or empty the key-less URL is
    used instead (rate-limited to one request per hour by PhishTank).
    """
    api_key = os.environ.get("PHISHTANK_API_KEY", "")
    key_segment = f"{api_key}/" if api_key else ""
    url = PHISHTANK_DATA_URL.format(api_key=key_segment)

    try:
        response = requests.get(
            url,
            headers={
                "User-Agent": "phishtank/ioc_collector",
            },
            timeout=120,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"PhishTank request failed: {exc}", file=sys.stderr)
        raise

    entries = response.json()
    return {
        "query_status": "ok",
        "data": entries,
    }
