"""Tests for app/module/parser/http_parser.py"""

from module.parser.http_parser import (
    _PREVIEW_SIZE,
    _TitleParser,
    _parse_title,
    parse_http_response,
)


# ---------------------------------------------------------------------------
# _TitleParser
# ---------------------------------------------------------------------------


class TestTitleParser:
    def test_extracts_title(self):
        p = _TitleParser()
        p.feed("<html><head><title>Hello World</title></head></html>")
        assert p.title == "Hello World"

    def test_strips_whitespace(self):
        p = _TitleParser()
        p.feed("<title>  Padded  </title>")
        assert p.title == "Padded"

    def test_returns_none_when_no_title(self):
        p = _TitleParser()
        p.feed("<html><body><p>No title here</p></body></html>")
        assert p.title is None

    def test_captures_only_first_title(self):
        p = _TitleParser()
        p.feed("<title>First</title><title>Second</title>")
        assert p.title == "First"

    def test_empty_title_tag_returns_none(self):
        p = _TitleParser()
        p.feed("<title>   </title>")
        assert p.title is None

    def test_title_with_whitespace_only_content_returns_none(self):
        p = _TitleParser()
        p.feed("<title>\n\t</title>")
        assert p.title is None


# ---------------------------------------------------------------------------
# _parse_title
# ---------------------------------------------------------------------------


class TestParseTitle:
    def test_extracts_title_from_html(self):
        html = "<!doctype html><html><head><title>My Page</title></head></html>"
        assert _parse_title(html) == "My Page"

    def test_returns_none_when_no_title(self):
        assert _parse_title("<html><body>text</body></html>") is None

    def test_returns_none_on_empty_string(self):
        assert _parse_title("") is None

    def test_handles_malformed_html_gracefully(self):
        result = _parse_title("<title>Partial")
        assert result in ("Partial", None)


# ---------------------------------------------------------------------------
# parse_http_response
# ---------------------------------------------------------------------------


class TestParseHttpResponse:
    _HTML = b"<html><head><title>Test Page</title></head><body>Hello</body></html>"

    def _raw(self, accessible=True, status_code=200, headers=None, body_chunk=None):
        return {
            "accessible": accessible,
            "status_code": status_code,
            "headers": headers or {},
            "body_chunk": body_chunk,
        }

    def test_accessible_true_propagated(self):
        raw = self._raw(accessible=True, body_chunk=self._HTML)
        result = parse_http_response(raw)
        assert result["accessible"] is True

    def test_status_code_propagated(self):
        raw = self._raw(status_code=404, body_chunk=b"Not Found")
        result = parse_http_response(raw)
        assert result["status_code"] == 404

    def test_headers_propagated(self):
        headers = {"Content-Type": "text/html", "Server": "nginx"}
        raw = self._raw(headers=headers, body_chunk=self._HTML)
        result = parse_http_response(raw)
        assert result["headers"] == headers

    def test_title_parsed_from_body_chunk(self):
        raw = self._raw(body_chunk=self._HTML)
        result = parse_http_response(raw)
        assert result["title"] == "Test Page"

    def test_body_preview_is_decoded_utf8(self):
        raw = self._raw(body_chunk=self._HTML)
        result = parse_http_response(raw)
        assert isinstance(result["body_preview"], str)
        assert "Hello" in result["body_preview"]

    def test_size_from_content_length_header(self):
        raw = self._raw(headers={"Content-Length": "5000"}, body_chunk=self._HTML)
        result = parse_http_response(raw)
        assert result["size"] == 5000

    def test_size_falls_back_to_chunk_length_when_no_content_length(self):
        body = b"A" * 512
        raw = self._raw(body_chunk=body)
        result = parse_http_response(raw)
        assert result["size"] == 512

    def test_body_preview_truncated_to_preview_size(self):
        large_body = b"B" * (2 * _PREVIEW_SIZE)
        raw = self._raw(body_chunk=large_body[:_PREVIEW_SIZE])
        result = parse_http_response(raw)
        assert len(result["body_preview"]) <= _PREVIEW_SIZE

    def test_no_body_chunk_returns_none_preview_title_and_size(self):
        raw = self._raw(body_chunk=None)
        result = parse_http_response(raw)
        assert result["body_preview"] is None
        assert result["title"] is None
        assert result["size"] is None

    def test_invalid_content_length_ignored(self):
        body = b"hello"
        raw = self._raw(headers={"Content-Length": "not-a-number"}, body_chunk=body)
        result = parse_http_response(raw)
        assert result["size"] == len(body)

    def test_inaccessible_returns_all_none_fields(self):
        raw = {
            "accessible": False,
            "status_code": None,
            "headers": None,
            "body_chunk": None,
        }
        result = parse_http_response(raw)
        assert result["accessible"] is False
        assert result["status_code"] is None
        assert result["headers"] is None
        assert result["size"] is None
        assert result["title"] is None
        assert result["body_preview"] is None
