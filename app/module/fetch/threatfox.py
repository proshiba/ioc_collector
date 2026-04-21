"""threatfox.py

Fetches daily IOCs from the ThreatFox API (https://threatfox.abuse.ch).
"""

import os
import sys

import requests

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_daily_iocs() -> dict:
    """Call the ThreatFox API and return the JSON response for the last day."""
    api_key = os.environ.get("THREATFOX_API_KEY", "")
    payload = {
        "query": "get_iocs",
        "days": 1,
    }
    try:
        response = requests.post(
            THREATFOX_API_URL,
            headers={"Content-Type": "application/json", "Auth-Key": api_key},
            json=payload,
            timeout=60,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"ThreatFox API request failed: {exc}", file=sys.stderr)
        raise
    return response.json()
