"""check_http.py

Checks HTTP (tcp/80) and HTTPS (tcp/443) accessibility for a given IP address
or domain name.  The connection/read timeout is 3 seconds by default.

On a successful connection the following response data are extracted:

- HTTP response headers
- HTTP status code
- Content size in bytes  (``Content-Length`` header when present, otherwise the
  number of bytes actually received in the first chunk)
- Page title (parsed from the first 1 KB of the response body)
- First 1 KB of the response body (decoded as UTF-8, with replacement chars for
  invalid bytes)
"""

import sys
from html.parser import HTMLParser
from typing import Any, Dict, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 3
_PREVIEW_SIZE = 1024
_USER_AGENT = "ioc-collector/1.0"


class _TitleParser(HTMLParser):
    """Minimal HTML parser that extracts the text of the first <title> element."""

    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self.title: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and self.title is None:
            stripped = data.strip()
            if stripped:
                self.title = stripped


def _parse_title(html: str) -> Optional[str]:
    """Return the content of the first ``<title>`` tag in *html*, or ``None``."""
    parser = _TitleParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.title


def _check_protocol(
    scheme: str,
    target: str,
    timeout: int,
) -> Dict[str, Any]:
    """Attempt an HTTP GET against ``scheme://target`` and return parsed data.

    Args:
        scheme: Either ``"http"`` or ``"https"``.
        target: IP address or domain name (no path).
        timeout: Connection/read timeout in seconds.

    Returns:
        A dict with the following keys:

        - ``accessible``   – ``True`` if the server returned any response.
        - ``status_code``  – HTTP status code (int), or ``None``.
        - ``headers``      – Response headers as a plain dict, or ``None``.
        - ``size``         – Content size in bytes from the ``Content-Length``
                             header, or the number of bytes read if the header
                             is absent, or ``None`` on failure.
        - ``title``        – HTML page title extracted from the first 1 KB of
                             the body, or ``None``.
        - ``body_preview`` – First ``_PREVIEW_SIZE`` bytes of the body decoded
                             as UTF-8 (``errors="replace"``), or ``None``.
    """
    result: Dict[str, Any] = {
        "accessible": False,
        "status_code": None,
        "headers": None,
        "size": None,
        "title": None,
        "body_preview": None,
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

            cl = resp.headers.get("Content-Length")
            if cl is not None:
                try:
                    result["size"] = int(cl)
                except ValueError:
                    pass

            chunk = next(resp.iter_content(chunk_size=_PREVIEW_SIZE), b"")
            chunk = chunk[:_PREVIEW_SIZE]

            if chunk:
                preview = chunk.decode("utf-8", errors="replace")
                result["body_preview"] = preview
                result["title"] = _parse_title(preview)
                if result["size"] is None:
                    result["size"] = len(chunk)

    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except Exception as exc:
        print(f"HTTP check failed for {url!r}: {exc}", file=sys.stderr)

    return result


def check_http(
    target: str,
    timeout: int = _TIMEOUT,
) -> Dict[str, Any]:
    """Check HTTP and HTTPS accessibility for *target*.

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
            }
    """
    return {
        "target": target,
        "http": _check_protocol("http", target, timeout=timeout),
        "https": _check_protocol("https", target, timeout=timeout),
    }
