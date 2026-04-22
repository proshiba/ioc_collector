"""http_parser.py

Parses raw HTTP response data (produced by ``module.fetch.fetch_http``) into
structured information suitable for downstream enrichment.
"""

from html.parser import HTMLParser
from typing import Any, Dict, Optional

_PREVIEW_SIZE = 1024


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


def parse_http_response(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Parse raw HTTP response data into a structured result dict.

    Args:
        raw: A dict from ``fetch_http_response`` with the following keys:
             ``accessible``, ``status_code``, ``headers``, ``body_chunk``.

    Returns:
        A dict with the following keys:

        - ``accessible``   – ``True`` if the server returned any response.
        - ``status_code``  – HTTP status code (int), or ``None``.
        - ``headers``      – Response headers as a plain dict, or ``None``.
        - ``size``         – Content size in bytes from the ``Content-Length``
                             header, or the number of bytes in *body_chunk* if
                             the header is absent, or ``None`` on failure.
        - ``title``        – HTML page title extracted from *body_chunk*, or ``None``.
        - ``body_preview`` – Body chunk decoded as UTF-8 (``errors="replace"``),
                             or ``None``.
    """
    result: Dict[str, Any] = {
        "accessible": raw.get("accessible", False),
        "status_code": raw.get("status_code"),
        "headers": raw.get("headers"),
        "size": None,
        "title": None,
        "body_preview": None,
    }

    if not result["accessible"]:
        return result

    headers = result["headers"] or {}
    cl = headers.get("Content-Length")
    if cl is not None:
        try:
            result["size"] = int(cl)
        except ValueError:
            pass

    chunk: bytes = raw.get("body_chunk") or b""
    if chunk:
        preview = chunk.decode("utf-8", errors="replace")
        result["body_preview"] = preview
        result["title"] = _parse_title(preview)
        if result["size"] is None:
            result["size"] = len(chunk)

    return result
