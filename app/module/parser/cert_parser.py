"""cert_parser.py

Parses raw TLS certificate bytes (DER format) into structured certificate
information.  The raw bytes are obtained by ``module.fetch.fetch_http``.
"""

import sys
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes


def _name_to_dict(name: x509.Name) -> Dict[str, str]:
    """Convert an :class:`x509.Name` into a plain dict keyed by OID short name."""
    result: Dict[str, str] = {}
    for attr in name:
        short_name = attr.oid._name  # e.g. "commonName", "organizationName"
        result[short_name] = attr.value
    return result


def parse_certificate(der_bytes: bytes) -> Optional[Dict[str, Any]]:
    """Parse a DER-encoded X.509 certificate into structured data.

    Args:
        der_bytes: Raw DER certificate bytes.

    Returns:
        A dict with the following keys, or ``None`` if parsing fails:

        - ``subject``             – Dict of subject name attributes.
        - ``issuer``              – Dict of issuer name attributes.
        - ``serial_number``       – Serial number as a decimal string.
        - ``not_valid_before``    – ISO 8601 timestamp string (UTC).
        - ``not_valid_after``     – ISO 8601 timestamp string (UTC).
        - ``subject_alt_names``   – List of SAN strings (e.g. ``"DNS:example.com"``).
        - ``fingerprint_sha256``  – SHA-256 fingerprint as a lowercase hex string.
    """
    try:
        cert = x509.load_der_x509_certificate(der_bytes)

        sans: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            sans = [str(name) for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass

        fingerprint = cert.fingerprint(hashes.SHA256()).hex()

        return {
            "subject": _name_to_dict(cert.subject),
            "issuer": _name_to_dict(cert.issuer),
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "subject_alt_names": sans,
            "fingerprint_sha256": fingerprint,
        }
    except Exception as exc:
        print(f"Certificate parse failed: {exc}", file=sys.stderr)
        return None
