"""Tests for app/module/enrich_domain.py"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from module.enrich_domain import _normalise, enrich_domain, fetch_whois, resolve_dns


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_dns_answer(addresses):
    """Build a mock dns.resolver.Answer whose iteration yields rdata objects."""
    rdatas = [MagicMock(spec=["__str__"], **{"__str__.return_value": a}) for a in addresses]
    mock_answer = MagicMock()
    mock_answer.__iter__ = MagicMock(return_value=iter(rdatas))
    return mock_answer


def _make_whois(data: dict) -> MagicMock:
    """Return a mock whois result that behaves like a dict."""
    mock_w = MagicMock()
    mock_w.get.side_effect = lambda key, default=None: data.get(key, default)
    return mock_w


# ---------------------------------------------------------------------------
# _normalise
# ---------------------------------------------------------------------------


class TestNormalise:
    def test_none_returns_none(self):
        assert _normalise(None) is None

    def test_string_returned_as_is(self):
        assert _normalise("ACME Corp") == "ACME Corp"

    def test_datetime_to_iso_string(self):
        dt = datetime(2020, 1, 15, 12, 0, 0)
        assert _normalise(dt) == "2020-01-15T12:00:00"

    def test_list_uses_first_non_none(self):
        assert _normalise([None, "second", "third"]) == "second"

    def test_list_of_datetimes(self):
        dt1 = datetime(2020, 1, 1)
        dt2 = datetime(2021, 1, 1)
        assert _normalise([dt1, dt2]) == "2020-01-01T00:00:00"

    def test_empty_list_returns_none(self):
        assert _normalise([]) is None

    def test_list_of_all_none_returns_none(self):
        assert _normalise([None, None]) is None

    def test_non_string_coerced_to_string(self):
        assert _normalise(42) == "42"


# ---------------------------------------------------------------------------
# resolve_dns
# ---------------------------------------------------------------------------


class TestResolveDns:
    def test_success_returns_sorted_ips(self):
        with patch("dns.resolver.resolve", return_value=_make_dns_answer(["1.2.3.4", "5.6.7.8"])):
            result = resolve_dns("example.com")
        assert result == ["1.2.3.4", "5.6.7.8"]

    def test_results_are_sorted(self):
        with patch("dns.resolver.resolve", return_value=_make_dns_answer(["9.9.9.9", "1.1.1.1"])):
            result = resolve_dns("example.com")
        assert result == ["1.1.1.1", "9.9.9.9"]

    def test_nxdomain_returns_empty_list(self):
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            result = resolve_dns("nonexistent.invalid")
        assert result == []

    def test_noanswer_returns_empty_list(self):
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()):
            result = resolve_dns("example.com")
        assert result == []

    def test_timeout_returns_empty_list(self):
        with patch("dns.resolver.resolve", side_effect=dns.resolver.Timeout()):
            result = resolve_dns("example.com")
        assert result == []

    def test_dns_exception_returns_empty_list(self):
        with patch("dns.resolver.resolve", side_effect=dns.exception.DNSException("error")):
            result = resolve_dns("example.com")
        assert result == []


# ---------------------------------------------------------------------------
# fetch_whois
# ---------------------------------------------------------------------------


class TestFetchWhois:
    _FULL_DATA = {
        "registrant_name": "ACME Corp",
        "registrant_email": "admin@example.com",
        "registrar": "Example Registrar, Inc.",
        "creation_date": datetime(1995, 8, 14, 4, 0, 0),
        "expiration_date": datetime(2025, 8, 13, 4, 0, 0),
    }

    def test_full_whois_data(self):
        with patch("whois.whois", return_value=_make_whois(self._FULL_DATA)):
            result = fetch_whois("example.com")

        assert result["registrant_name"] == "ACME Corp"
        assert result["registrant_email"] == "admin@example.com"
        assert result["registrar"] == "Example Registrar, Inc."
        assert result["creation_date"] == "1995-08-14T04:00:00"
        assert result["expiration_date"] == "2025-08-13T04:00:00"

    def test_falls_back_to_name_when_registrant_name_absent(self):
        data = {**self._FULL_DATA, "registrant_name": None, "name": "Fallback Corp"}
        with patch("whois.whois", return_value=_make_whois(data)):
            result = fetch_whois("example.com")
        assert result["registrant_name"] == "Fallback Corp"

    def test_falls_back_to_emails_when_registrant_email_absent(self):
        data = {**self._FULL_DATA, "registrant_email": None, "emails": ["info@example.com"]}
        with patch("whois.whois", return_value=_make_whois(data)):
            result = fetch_whois("example.com")
        assert result["registrant_email"] == "info@example.com"

    def test_missing_fields_return_none(self):
        with patch("whois.whois", return_value=_make_whois({})):
            result = fetch_whois("example.com")
        assert result == {
            "registrant_name": None,
            "registrant_email": None,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
        }

    def test_list_dates_use_first_value(self):
        dt1 = datetime(2020, 1, 1)
        dt2 = datetime(2021, 1, 1)
        data = {**self._FULL_DATA, "creation_date": [dt1, dt2]}
        with patch("whois.whois", return_value=_make_whois(data)):
            result = fetch_whois("example.com")
        assert result["creation_date"] == "2020-01-01T00:00:00"

    def test_exception_returns_none_fields(self):
        with patch("whois.whois", side_effect=Exception("WHOIS failed")):
            result = fetch_whois("example.com")
        assert result == {
            "registrant_name": None,
            "registrant_email": None,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
        }


# ---------------------------------------------------------------------------
# enrich_domain
# ---------------------------------------------------------------------------


class TestEnrichDomain:
    def test_returns_expected_structure(self):
        with (
            patch("module.enrich_domain.resolve_dns", return_value=["93.184.216.34"]) as mock_dns,
            patch(
                "module.enrich_domain.fetch_whois",
                return_value={
                    "registrant_name": "ACME",
                    "registrant_email": "admin@example.com",
                    "registrar": "Some Registrar",
                    "creation_date": "1995-08-14T04:00:00",
                    "expiration_date": "2025-08-13T04:00:00",
                },
            ) as mock_whois,
        ):
            result = enrich_domain("example.com")

        assert result["domain"] == "example.com"
        assert result["dns"] == ["93.184.216.34"]
        assert result["whois"]["registrant_name"] == "ACME"
        mock_dns.assert_called_once_with("example.com")
        mock_whois.assert_called_once_with("example.com")

    def test_dns_failure_yields_empty_dns_list(self):
        with (
            patch("module.enrich_domain.resolve_dns", return_value=[]),
            patch("module.enrich_domain.fetch_whois", return_value={
                "registrant_name": None,
                "registrant_email": None,
                "registrar": None,
                "creation_date": None,
                "expiration_date": None,
            }),
        ):
            result = enrich_domain("nxdomain.invalid")

        assert result["dns"] == []
        assert result["domain"] == "nxdomain.invalid"
