"""Tests for app/module/enrich/check_http.py"""

from unittest.mock import MagicMock, patch

from module.enrich.check_http import check_http
from module.fetch.fetch_http import _TIMEOUT


# ---------------------------------------------------------------------------
# check_http
# ---------------------------------------------------------------------------


class TestCheckHttp:
    _HTML = b"<html><head><title>IoC Page</title></head><body>data</body></html>"

    def _mock_http_result(self, accessible: bool) -> dict:
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

    def _patch_all(self, http_accessible=False, https_accessible=False, cert_der=None):
        """Return a context-manager stack that patches fetch + parse + cert."""
        from contextlib import ExitStack

        stack = ExitStack()
        http_result = self._mock_http_result(http_accessible)
        https_result = self._mock_http_result(https_accessible)

        stack.enter_context(
            patch(
                "module.enrich.check_http.fetch_http_response",
                side_effect=[
                    {"accessible": http_accessible, "status_code": 200 if http_accessible else None, "headers": None, "body_chunk": self._HTML if http_accessible else None},
                    {"accessible": https_accessible, "status_code": 200 if https_accessible else None, "headers": None, "body_chunk": self._HTML if https_accessible else None},
                ],
            )
        )
        stack.enter_context(
            patch(
                "module.enrich.check_http.parse_http_response",
                side_effect=[http_result, https_result],
            )
        )
        stack.enter_context(
            patch(
                "module.enrich.check_http.fetch_certificate_der",
                return_value=cert_der,
            )
        )
        stack.enter_context(
            patch(
                "module.enrich.check_http.parse_certificate",
                return_value=None,
            )
        )
        return stack

    def test_returns_target_in_result(self):
        with self._patch_all():
            result = check_http("example.com")
        assert result["target"] == "example.com"

    def test_contains_http_https_and_certificate_keys(self):
        with self._patch_all():
            result = check_http("1.2.3.4")
        assert "http" in result
        assert "https" in result
        assert "certificate" in result

    def test_both_http_accessible(self):
        with self._patch_all(http_accessible=True, https_accessible=True):
            result = check_http("example.com")
        assert result["http"]["accessible"] is True
        assert result["https"]["accessible"] is True

    def test_http_accessible_https_not(self):
        with self._patch_all(http_accessible=True, https_accessible=False):
            result = check_http("example.com")
        assert result["http"]["accessible"] is True
        assert result["https"]["accessible"] is False

    def test_certificate_available_when_der_returned(self):
        fake_der = b"\x30\x82\x01\x00"
        fake_cert_data = {
            "subject": {"commonName": "example.com"},
            "issuer": {"commonName": "Example CA"},
            "serial_number": "123",
            "not_valid_before": "2024-01-01T00:00:00+00:00",
            "not_valid_after": "2025-01-01T00:00:00+00:00",
            "subject_alt_names": ["DNS:example.com"],
            "fingerprint_sha256": "ab12cd",
        }
        with self._patch_all(cert_der=fake_der) as stack:
            # Override parse_certificate to return fake data
            stack._exit_callbacks.clear()  # reset so we can re-patch
        # Use a simpler approach
        with (
            patch("module.enrich.check_http.fetch_http_response", return_value={"accessible": False, "status_code": None, "headers": None, "body_chunk": None}),
            patch("module.enrich.check_http.parse_http_response", return_value=self._mock_http_result(False)),
            patch("module.enrich.check_http.fetch_certificate_der", return_value=fake_der),
            patch("module.enrich.check_http.parse_certificate", return_value=fake_cert_data),
        ):
            result = check_http("example.com")
        assert result["certificate"]["available"] is True
        assert result["certificate"]["data"] == fake_cert_data

    def test_certificate_unavailable_when_no_der(self):
        with (
            patch("module.enrich.check_http.fetch_http_response", return_value={"accessible": False, "status_code": None, "headers": None, "body_chunk": None}),
            patch("module.enrich.check_http.parse_http_response", return_value=self._mock_http_result(False)),
            patch("module.enrich.check_http.fetch_certificate_der", return_value=None),
            patch("module.enrich.check_http.parse_certificate", return_value=None),
        ):
            result = check_http("example.com")
        assert result["certificate"]["available"] is False
        assert result["certificate"]["data"] is None

    def test_default_timeout_forwarded_to_fetch(self):
        with (
            patch("module.enrich.check_http.fetch_http_response", return_value={"accessible": False, "status_code": None, "headers": None, "body_chunk": None}) as mock_fetch,
            patch("module.enrich.check_http.parse_http_response", return_value=self._mock_http_result(False)),
            patch("module.enrich.check_http.fetch_certificate_der", return_value=None) as mock_cert,
            patch("module.enrich.check_http.parse_certificate", return_value=None),
        ):
            check_http("example.com")
        for call in mock_fetch.call_args_list:
            assert call[1].get("timeout") == _TIMEOUT or call[0][2] == _TIMEOUT

    def test_custom_timeout_forwarded(self):
        with (
            patch("module.enrich.check_http.fetch_http_response", return_value={"accessible": False, "status_code": None, "headers": None, "body_chunk": None}) as mock_fetch,
            patch("module.enrich.check_http.parse_http_response", return_value=self._mock_http_result(False)),
            patch("module.enrich.check_http.fetch_certificate_der", return_value=None) as mock_cert,
            patch("module.enrich.check_http.parse_certificate", return_value=None),
        ):
            check_http("example.com", timeout=10)
        for call in mock_fetch.call_args_list:
            assert call[1].get("timeout") == 10 or call[0][2] == 10

    def test_fetch_called_with_http_and_https_schemes(self):
        with (
            patch("module.enrich.check_http.fetch_http_response", return_value={"accessible": False, "status_code": None, "headers": None, "body_chunk": None}) as mock_fetch,
            patch("module.enrich.check_http.parse_http_response", return_value=self._mock_http_result(False)),
            patch("module.enrich.check_http.fetch_certificate_der", return_value=None),
            patch("module.enrich.check_http.parse_certificate", return_value=None),
        ):
            check_http("1.2.3.4")
        schemes = [c[0][0] for c in mock_fetch.call_args_list]
        assert "http" in schemes
        assert "https" in schemes
