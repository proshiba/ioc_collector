"""Tests for app/module/enrich/check_http.py"""

from unittest.mock import MagicMock, call, patch

import pytest
import requests

from module.enrich.check_http import (
    _PREVIEW_SIZE,
    _TIMEOUT,
    _TitleParser,
    _check_protocol,
    _parse_title,
    check_http,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(
    status_code: int = 200,
    headers: dict | None = None,
    body: bytes = b"",
) -> MagicMock:
    """Build a mock requests.Response that works as a context manager."""
    if headers is None:
        headers = {}
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers
    mock_resp.iter_content.return_value = iter([body] if body else [])
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


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
        # Should not raise; may or may not find a title
        result = _parse_title("<title>Partial")
        # Either "Partial" or None is acceptable – the key requirement is no exception
        assert result in ("Partial", None)


# ---------------------------------------------------------------------------
# _check_protocol – successful access
# ---------------------------------------------------------------------------


class TestCheckProtocolSuccess:
    _HTML = b"<html><head><title>Test Page</title></head><body>Hello</body></html>"

    def test_accessible_true_on_200(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("http", "example.com", timeout=3)
        assert result["accessible"] is True

    def test_status_code_returned(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("http", "example.com", timeout=3)
        assert result["status_code"] == 200

    def test_headers_returned_as_dict(self):
        headers = {"Content-Type": "text/html", "Server": "nginx"}
        mock_resp = _make_response(200, headers=headers, body=self._HTML)
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("http", "example.com", timeout=3)
        assert result["headers"] == headers

    def test_title_parsed_from_body(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("http", "example.com", timeout=3)
        assert result["title"] == "Test Page"

    def test_body_preview_is_decoded_utf8(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("http", "example.com", timeout=3)
        assert isinstance(result["body_preview"], str)
        assert "Hello" in result["body_preview"]

    def test_size_from_content_length_header(self):
        headers = {"Content-Length": "5000"}
        mock_resp = _make_response(200, headers=headers, body=self._HTML)
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("https", "example.com", timeout=3)
        assert result["size"] == 5000

    def test_size_falls_back_to_body_length_when_no_content_length(self):
        body = b"A" * 512
        mock_resp = _make_response(200, body=body)
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("http", "example.com", timeout=3)
        assert result["size"] == 512

    def test_body_preview_truncated_to_preview_size(self):
        large_body = b"B" * (2 * _PREVIEW_SIZE)
        mock_resp = _make_response(200, body=large_body)
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("http", "example.com", timeout=3)
        assert len(result["body_preview"]) <= _PREVIEW_SIZE

    def test_url_uses_correct_scheme(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp) as mock_get:
            _check_protocol("https", "1.2.3.4", timeout=3)
        called_url = mock_get.call_args[0][0]
        assert called_url == "https://1.2.3.4"

    def test_verify_false_for_https(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp) as mock_get:
            _check_protocol("https", "example.com", timeout=3)
        assert mock_get.call_args[1].get("verify") is False

    def test_timeout_forwarded(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp) as mock_get:
            _check_protocol("http", "example.com", timeout=5)
        assert mock_get.call_args[1].get("timeout") == 5

    def test_non_200_status_still_accessible(self):
        mock_resp = _make_response(404, body=b"Not Found")
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("http", "example.com", timeout=3)
        assert result["accessible"] is True
        assert result["status_code"] == 404

    def test_no_body_returns_none_preview_and_title(self):
        mock_resp = _make_response(200, body=b"")
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("http", "example.com", timeout=3)
        assert result["body_preview"] is None
        assert result["title"] is None

    def test_invalid_content_length_ignored(self):
        headers = {"Content-Length": "not-a-number"}
        body = b"hello"
        mock_resp = _make_response(200, headers=headers, body=body)
        with patch("requests.get", return_value=mock_resp):
            result = _check_protocol("http", "example.com", timeout=3)
        # Falls back to len(chunk)
        assert result["size"] == len(body)


# ---------------------------------------------------------------------------
# _check_protocol – failures
# ---------------------------------------------------------------------------


class TestCheckProtocolFailure:
    def _inaccessible_result(self) -> dict:
        return {
            "accessible": False,
            "status_code": None,
            "headers": None,
            "size": None,
            "title": None,
            "body_preview": None,
        }

    def test_timeout_returns_inaccessible(self):
        with patch("requests.get", side_effect=requests.exceptions.Timeout("timed out")):
            result = _check_protocol("http", "10.0.0.1", timeout=3)
        assert result == self._inaccessible_result()

    def test_connection_error_returns_inaccessible(self):
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = _check_protocol("http", "10.0.0.1", timeout=3)
        assert result == self._inaccessible_result()

    def test_generic_exception_returns_inaccessible(self, capsys):
        with patch("requests.get", side_effect=Exception("unexpected")):
            result = _check_protocol("http", "example.com", timeout=3)
        assert result["accessible"] is False
        captured = capsys.readouterr()
        assert "HTTP check failed" in captured.err


# ---------------------------------------------------------------------------
# check_http
# ---------------------------------------------------------------------------


class TestCheckHttp:
    _HTML = b"<html><head><title>IoC Page</title></head><body>data</body></html>"

    def _mock_protocol(self, accessible: bool) -> dict:
        if accessible:
            return {
                "accessible": True,
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "size": len(self._HTML),
                "title": "IoC Page",
                "body_preview": self._HTML.decode(),
            }
        return {
            "accessible": False,
            "status_code": None,
            "headers": None,
            "size": None,
            "title": None,
            "body_preview": None,
        }

    def test_returns_target_in_result(self):
        with patch("module.enrich.check_http._check_protocol", return_value=self._mock_protocol(False)):
            result = check_http("example.com")
        assert result["target"] == "example.com"

    def test_contains_http_and_https_keys(self):
        with patch("module.enrich.check_http._check_protocol", return_value=self._mock_protocol(False)):
            result = check_http("1.2.3.4")
        assert "http" in result
        assert "https" in result

    def test_both_accessible(self):
        with patch(
            "module.enrich.check_http._check_protocol",
            return_value=self._mock_protocol(True),
        ):
            result = check_http("example.com")
        assert result["http"]["accessible"] is True
        assert result["https"]["accessible"] is True

    def test_http_accessible_https_not(self):
        accessible_result = self._mock_protocol(True)
        inaccessible_result = self._mock_protocol(False)
        with patch(
            "module.enrich.check_http._check_protocol",
            side_effect=[accessible_result, inaccessible_result],
        ):
            result = check_http("example.com")
        assert result["http"]["accessible"] is True
        assert result["https"]["accessible"] is False

    def test_default_timeout_is_3(self):
        with patch("module.enrich.check_http._check_protocol", return_value=self._mock_protocol(False)) as mock_proto:
            check_http("example.com")
        calls = mock_proto.call_args_list
        assert all(c[1].get("timeout") == _TIMEOUT or c[0][2] == _TIMEOUT for c in calls)

    def test_custom_timeout_forwarded(self):
        with patch("module.enrich.check_http._check_protocol", return_value=self._mock_protocol(False)) as mock_proto:
            check_http("example.com", timeout=10)
        calls = mock_proto.call_args_list
        for c in calls:
            assert c[1].get("timeout") == 10 or c[0][2] == 10

    def test_check_protocol_called_with_http_and_https(self):
        with patch(
            "module.enrich.check_http._check_protocol",
            return_value=self._mock_protocol(False),
        ) as mock_proto:
            check_http("1.2.3.4")
        schemes = [c[0][0] for c in mock_proto.call_args_list]
        assert "http" in schemes
        assert "https" in schemes
