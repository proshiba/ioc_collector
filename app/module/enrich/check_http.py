"""check_http.py

Checks HTTP (tcp/80) and HTTPS (tcp/443) accessibility and collects TLS
certificate information for a given IP address or domain name.
The connection/read timeout is 3 seconds by default.

HTTP fetching is delegated to ``module.fetch.fetch_http``.
Response and certificate parsing is delegated to ``module.parser``.
"""

from typing import Any, Dict, Optional

from module.fetch.fetch_http import _TIMEOUT, fetch_certificate_der, fetch_http_response
from module.parser.cert_parser import parse_certificate
from module.parser.http_parser import parse_http_response


def check_http(
    target: str,
    timeout: int = _TIMEOUT,
) -> Dict[str, Any]:
    """Check HTTP/HTTPS accessibility and collect TLS certificate info for *target*.

    Args:
        target: IPv4/IPv6 address or domain name.
        timeout: Connection/read timeout in seconds (default: 3).

    Returns:
        A dict with the following structure::

            {
                "target": "example.com",
                "http": {
                    "accessible": True,
                    "status_code": 200,
                    "headers": {"Content-Type": "text/html", ...},
                    "size": 1256,
                    "title": "Example Domain",
                    "body_preview": "<!doctype html>...",
                },
                "https": {
                    "accessible": False,
                    "status_code": None,
                    "headers": None,
                    "size": None,
                    "title": None,
                    "body_preview": None,
                },
                "certificate": {
                    "available": True,
                    "data": {
                        "subject": {"commonName": "example.com", ...},
                        "issuer": {"commonName": "Example CA", ...},
                        "serial_number": "12345",
                        "not_valid_before": "2024-01-01T00:00:00+00:00",
                        "not_valid_after": "2025-01-01T00:00:00+00:00",
                        "subject_alt_names": ["DNS:example.com", ...],
                        "fingerprint_sha256": "ab12cd...",
                    },
                },
            }
    """
    http_raw = fetch_http_response("http", target, timeout=timeout)
    https_raw = fetch_http_response("https", target, timeout=timeout)

    cert_der = fetch_certificate_der(target, timeout=timeout)
    cert_data: Optional[Dict[str, Any]] = None
    if cert_der is not None:
        cert_data = parse_certificate(cert_der)

    return {
        "target": target,
        "http": parse_http_response(http_raw),
        "https": parse_http_response(https_raw),
        "certificate": {
            "available": cert_data is not None,
            "data": cert_data,
        },
    }
