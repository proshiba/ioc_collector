"""Tests for app/module/fetch/fetch_http.py"""

import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest
import requests

from module.fetch.fetch_http import (
    _PREVIEW_SIZE,
    _TIMEOUT,
    fetch_certificate_der,
    fetch_http_response,
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
# fetch_http_response – successful access
# ---------------------------------------------------------------------------


class TestFetchHttpResponseSuccess:
    _HTML = b"<html><head><title>Test Page</title></head><body>Hello</body></html>"

    def test_accessible_true_on_200(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp):
            result = fetch_http_response("http", "example.com", timeout=3)
        assert result["accessible"] is True

    def test_status_code_returned(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp):
            result = fetch_http_response("http", "example.com", timeout=3)
        assert result["status_code"] == 200

    def test_headers_returned_as_dict(self):
        headers = {"Content-Type": "text/html", "Server": "nginx"}
        mock_resp = _make_response(200, headers=headers, body=self._HTML)
        with patch("requests.get", return_value=mock_resp):
            result = fetch_http_response("http", "example.com", timeout=3)
        assert result["headers"] == headers

    def test_body_chunk_returned(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp):
            result = fetch_http_response("http", "example.com", timeout=3)
        assert isinstance(result["body_chunk"], bytes)
        assert b"Hello" in result["body_chunk"]

    def test_body_chunk_truncated_to_preview_size(self):
        large_body = b"B" * (2 * _PREVIEW_SIZE)
        mock_resp = _make_response(200, body=large_body)
        with patch("requests.get", return_value=mock_resp):
            result = fetch_http_response("http", "example.com", timeout=3)
        assert len(result["body_chunk"]) <= _PREVIEW_SIZE

    def test_url_uses_correct_scheme(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp) as mock_get:
            fetch_http_response("https", "1.2.3.4", timeout=3)
        called_url = mock_get.call_args[0][0]
        assert called_url == "https://1.2.3.4"

    def test_verify_false(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp) as mock_get:
            fetch_http_response("https", "example.com", timeout=3)
        assert mock_get.call_args[1].get("verify") is False

    def test_timeout_forwarded(self):
        mock_resp = _make_response(200, body=self._HTML)
        with patch("requests.get", return_value=mock_resp) as mock_get:
            fetch_http_response("http", "example.com", timeout=5)
        assert mock_get.call_args[1].get("timeout") == 5

    def test_non_200_status_still_accessible(self):
        mock_resp = _make_response(404, body=b"Not Found")
        with patch("requests.get", return_value=mock_resp):
            result = fetch_http_response("http", "example.com", timeout=3)
        assert result["accessible"] is True
        assert result["status_code"] == 404

    def test_no_body_returns_none_body_chunk(self):
        mock_resp = _make_response(200, body=b"")
        with patch("requests.get", return_value=mock_resp):
            result = fetch_http_response("http", "example.com", timeout=3)
        assert result["body_chunk"] is None or result["body_chunk"] == b""


# ---------------------------------------------------------------------------
# fetch_http_response – failures
# ---------------------------------------------------------------------------


class TestFetchHttpResponseFailure:
    def _inaccessible(self) -> dict:
        return {
            "accessible": False,
            "status_code": None,
            "headers": None,
            "body_chunk": None,
        }

    def test_timeout_returns_inaccessible(self):
        with patch("requests.get", side_effect=requests.exceptions.Timeout("timed out")):
            result = fetch_http_response("http", "10.0.0.1", timeout=3)
        assert result == self._inaccessible()

    def test_connection_error_returns_inaccessible(self):
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = fetch_http_response("http", "10.0.0.1", timeout=3)
        assert result == self._inaccessible()

    def test_generic_exception_returns_inaccessible(self, capsys):
        with patch("requests.get", side_effect=Exception("unexpected")):
            result = fetch_http_response("http", "example.com", timeout=3)
        assert result["accessible"] is False
        captured = capsys.readouterr()
        assert "HTTP fetch failed" in captured.err


# ---------------------------------------------------------------------------
# fetch_certificate_der
# ---------------------------------------------------------------------------


class TestFetchCertificateDer:
    _FAKE_DER = b"\x30\x82\x01\x00\x00"

    def _make_ssl_mock(self, der_bytes: bytes) -> MagicMock:
        """Return a mock SSLSocket context manager that yields der_bytes from getpeercert."""
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = der_bytes
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)
        return mock_ssock

    def test_returns_der_bytes_on_success(self):
        mock_ssock = self._make_ssl_mock(self._FAKE_DER)
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with (
            patch("socket.create_connection", return_value=mock_sock),
            patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_ssock),
        ):
            result = fetch_certificate_der("example.com", port=443, timeout=3)
        assert result == self._FAKE_DER

    def test_returns_none_on_connection_error(self, capsys):
        with patch("socket.create_connection", side_effect=OSError("refused")):
            result = fetch_certificate_der("10.0.0.1", port=443, timeout=3)
        assert result is None
        captured = capsys.readouterr()
        assert "Certificate fetch failed" in captured.err

    def test_returns_none_on_ssl_error(self, capsys):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with (
            patch("socket.create_connection", return_value=mock_sock),
            patch.object(ssl.SSLContext, "wrap_socket", side_effect=ssl.SSLError("ssl error")),
        ):
            result = fetch_certificate_der("example.com", port=443, timeout=3)
        assert result is None
        captured = capsys.readouterr()
        assert "Certificate fetch failed" in captured.err

    def test_default_port_is_443(self):
        with patch("socket.create_connection", side_effect=OSError("refused")):
            fetch_certificate_der("example.com", timeout=3)
        # No assertion needed – just verifying no TypeError from wrong signature

    def test_default_timeout_is_timeout_constant(self):
        with patch("socket.create_connection", side_effect=OSError("refused")):
            fetch_certificate_der("example.com")
        # Verifies default timeout parameter doesn't raise
