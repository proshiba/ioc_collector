"""maxmind_db.py

Downloads the MaxMind GeoLite2 free databases (ASN and Country) and extracts
the .mmdb files to a local directory.

A valid MaxMind license key is required.  Sign up for a free account at
https://www.maxmind.com/en/geolite2/signup and generate a license key.

The license key is read from the ``MAXMIND_LICENSE_KEY`` environment variable,
or can be supplied directly as a function argument.
"""

import os
import tarfile
import tempfile
from typing import Optional

import requests

MAXMIND_DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id={edition_id}&license_key={license_key}&suffix=tar.gz"
)

EDITION_ASN = "GeoLite2-ASN"
EDITION_COUNTRY = "GeoLite2-Country"

DEFAULT_DB_DIR = "data/maxmind"


def _download_and_extract(edition_id: str, license_key: str, dest_dir: str) -> str:
    """Download a GeoLite2 edition and extract the .mmdb file into *dest_dir*.

    Returns the full path to the extracted .mmdb file.
    """
    url = MAXMIND_DOWNLOAD_URL.format(
        edition_id=edition_id, license_key=license_key
    )
    response = requests.get(url, timeout=120, stream=True)
    response.raise_for_status()

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp_path = tmp.name
        for chunk in response.iter_content(chunk_size=65536):
            tmp.write(chunk)

    try:
        with tarfile.open(tmp_path, "r:gz") as tar:
            mmdb_member = next(
                (m for m in tar.getmembers() if m.name.endswith(".mmdb")),
                None,
            )
            if mmdb_member is None:
                raise FileNotFoundError(
                    f"No .mmdb file found in the downloaded archive for {edition_id}"
                )
            # Strip the directory prefix so the file lands directly in dest_dir.
            mmdb_member.name = os.path.basename(mmdb_member.name)
            tar.extract(mmdb_member, path=dest_dir, filter="data")
    finally:
        os.unlink(tmp_path)

    return os.path.join(dest_dir, mmdb_member.name)


def download_maxmind_dbs(
    dest_dir: str = DEFAULT_DB_DIR,
    license_key: Optional[str] = None,
) -> dict:
    """Download GeoLite2-ASN and GeoLite2-Country databases to *dest_dir*.

    Args:
        dest_dir: Directory where the .mmdb files will be saved.
                  Created automatically if it does not exist.
        license_key: MaxMind license key.  Falls back to the
                     ``MAXMIND_LICENSE_KEY`` environment variable when omitted.

    Returns:
        A dict mapping edition IDs to the paths of the extracted .mmdb files::

            {
                "GeoLite2-ASN": "/path/to/GeoLite2-ASN.mmdb",
                "GeoLite2-Country": "/path/to/GeoLite2-Country.mmdb",
            }

    Raises:
        ValueError: When no license key is available.
        requests.HTTPError: When the download fails (e.g. invalid key, network error).
        FileNotFoundError: When the downloaded archive contains no .mmdb file.
    """
    if license_key is None:
        license_key = os.environ.get("MAXMIND_LICENSE_KEY")
    if not license_key:
        raise ValueError(
            "A MaxMind license key is required.  "
            "Set the MAXMIND_LICENSE_KEY environment variable or pass license_key=<your_key>."
        )

    os.makedirs(dest_dir, exist_ok=True)

    result = {}
    for edition_id in (EDITION_ASN, EDITION_COUNTRY):
        path = _download_and_extract(edition_id, license_key, dest_dir)
        result[edition_id] = path

    return result
