"""fetch_http.py

Fetches raw HTTP/HTTPS response data and TLS certificate bytes for a given target.
The actual interpretation/parsing of these raw values is handled by the parser
module (``module.parser``).
"""

import socket
import ssl
import sys
from typing import Any, Dict, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 3
_PREVIEW_SIZE = 1024
_USER_AGENT = "ioc-collector/1.0"


def fetch_http_response(
    scheme: str,
    target: str,
    timeout: int = _TIMEOUT,
) -> Dict[str, Any]:
    """Attempt an HTTP GET against ``scheme://target`` and return raw response data.

    Args:
        scheme: Either ``"http"`` or ``"https"``.
        target: IP address or domain name (no path).
        timeout: Connection/read timeout in seconds.

    Returns:
        A dict with the following keys:

        - ``accessible``   – ``True`` if the server returned any response.
        - ``status_code``  – HTTP status code (int), or ``None``.
        - ``headers``      – Response headers as a plain dict, or ``None``.
        - ``body_chunk``   – First ``_PREVIEW_SIZE`` bytes of the body, or ``None``.
    """
    result: Dict[str, Any] = {
        "accessible": False,
        "status_code": None,
        "headers": None,
        "body_chunk": None,
    }
    url = f"{scheme}://{target}"
    try:
        with requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            stream=True,
            headers={"User-Agent": _USER_AGENT},
        ) as resp:
            result["accessible"] = True
            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)
            chunk = next(resp.iter_content(chunk_size=_PREVIEW_SIZE), b"")
            result["body_chunk"] = chunk[:_PREVIEW_SIZE]
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except Exception as exc:
        print(f"HTTP fetch failed for {url!r}: {exc}", file=sys.stderr)
    return result


def fetch_certificate_der(
    target: str,
    port: int = 443,
    timeout: int = _TIMEOUT,
) -> Optional[bytes]:
    """Fetch the raw DER-encoded TLS certificate from ``target:port``.

    Args:
        target: IP address or domain name.
        port: TCP port to connect to (default: 443).
        timeout: Connection timeout in seconds.

    Returns:
        DER-encoded certificate bytes, or ``None`` if the connection failed.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                return ssock.getpeercert(binary_form=True)
    except Exception as exc:
        print(
            f"Certificate fetch failed for {target}:{port}: {exc}", file=sys.stderr
        )
        return None
