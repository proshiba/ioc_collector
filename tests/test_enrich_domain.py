"""Tests for app/module/enrich/enrich_domain.py"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest
import requests

from module.enrich.enrich_domain import (
    _normalise,
    _parse_rdap,
    _registered_domain,
    _try_rdap,
    _try_whois,
    enrich_domain,
    fetch_whois,
    resolve_dns,
)


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
# _try_whois
# ---------------------------------------------------------------------------


class TestTryWhois:
    _FULL_DATA = {
        "registrant_name": "ACME Corp",
        "registrant_email": "admin@example.com",
        "registrar": "Example Registrar, Inc.",
        "creation_date": datetime(1995, 8, 14, 4, 0, 0),
        "expiration_date": datetime(2025, 8, 13, 4, 0, 0),
    }

    def test_returns_parsed_fields_on_success(self):
        with patch("whois.whois", return_value=_make_whois(self._FULL_DATA)):
            result = _try_whois("example.com")

        assert result is not None
        assert result["registrant_name"] == "ACME Corp"
        assert result["registrant_email"] == "admin@example.com"
        assert result["registrar"] == "Example Registrar, Inc."
        assert result["creation_date"] == "1995-08-14T04:00:00"
        assert result["expiration_date"] == "2025-08-13T04:00:00"

    def test_returns_none_on_exception(self):
        with patch("whois.whois", side_effect=Exception("WHOIS unavailable")):
            result = _try_whois("example.com")
        assert result is None

    def test_falls_back_to_name_field(self):
        data = {**self._FULL_DATA, "registrant_name": None, "name": "Fallback Name"}
        with patch("whois.whois", return_value=_make_whois(data)):
            result = _try_whois("example.com")
        assert result["registrant_name"] == "Fallback Name"

    def test_falls_back_to_emails_field(self):
        data = {**self._FULL_DATA, "registrant_email": None, "emails": ["info@example.com"]}
        with patch("whois.whois", return_value=_make_whois(data)):
            result = _try_whois("example.com")
        assert result["registrant_email"] == "info@example.com"


# ---------------------------------------------------------------------------
# _parse_rdap
# ---------------------------------------------------------------------------


class TestParseRdap:
    def _make_vcard(self, fields: list) -> list:
        """Build a vcardArray structure: ["vcard", [fields...]]."""
        return ["vcard", [["version", {}, "text", "4.0"]] + fields]

    def test_parses_registrar_name(self):
        data = {
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": self._make_vcard([["fn", {}, "text", "ACME Registrar"]]),
                }
            ],
            "events": [],
        }
        result = _parse_rdap(data)
        assert result["registrar"] == "ACME Registrar"

    def test_parses_registrant_name_and_email(self):
        data = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": self._make_vcard([
                        ["fn", {}, "text", "John Doe"],
                        ["email", {}, "text", "john@example.com"],
                    ]),
                }
            ],
            "events": [],
        }
        result = _parse_rdap(data)
        assert result["registrant_name"] == "John Doe"
        assert result["registrant_email"] == "john@example.com"

    def test_parses_registration_and_expiration_events(self):
        data = {
            "entities": [],
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ],
        }
        result = _parse_rdap(data)
        assert result["creation_date"] == "2020-01-01T00:00:00Z"
        assert result["expiration_date"] == "2030-01-01T00:00:00Z"

    def test_empty_data_returns_all_none(self):
        result = _parse_rdap({})
        assert result == {
            "registrant_name": None,
            "registrant_email": None,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
        }

    def test_parses_multiple_entity_roles(self):
        data = {
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": self._make_vcard([["fn", {}, "text", "Registrar Inc."]]),
                },
                {
                    "roles": ["registrant"],
                    "vcardArray": self._make_vcard([["fn", {}, "text", "Domain Owner"]]),
                },
            ],
            "events": [],
        }
        result = _parse_rdap(data)
        assert result["registrar"] == "Registrar Inc."
        assert result["registrant_name"] == "Domain Owner"


# ---------------------------------------------------------------------------
# _try_rdap
# ---------------------------------------------------------------------------


class TestTryRdap:
    _RDAP_RESPONSE = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "RDAP Registrar"],
                ]],
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
        ],
    }

    def _make_http_response(self, json_data: dict, status_code: int = 200) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.json.return_value = json_data
        if status_code >= 400:
            mock_resp.raise_for_status.side_effect = requests.HTTPError(
                f"{status_code} Error"
            )
        else:
            mock_resp.raise_for_status.return_value = None
        return mock_resp

    def test_returns_parsed_fields_on_success(self):
        with patch("requests.get", return_value=self._make_http_response(self._RDAP_RESPONSE)):
            result = _try_rdap("example.com")

        assert result is not None
        assert result["registrar"] == "RDAP Registrar"
        assert result["creation_date"] == "2020-01-01T00:00:00Z"

    def test_returns_none_on_http_error(self):
        with patch("requests.get", return_value=self._make_http_response({}, status_code=404)):
            result = _try_rdap("example.com")
        assert result is None

    def test_returns_none_on_connection_error(self):
        with patch("requests.get", side_effect=requests.ConnectionError("unreachable")):
            result = _try_rdap("example.com")
        assert result is None

    def test_returns_none_on_timeout(self):
        with patch("requests.get", side_effect=requests.Timeout("timed out")):
            result = _try_rdap("example.com")
        assert result is None

    def test_sends_request_to_rdap_org(self):
        with patch("requests.get", return_value=self._make_http_response(self._RDAP_RESPONSE)) as mock_get:
            _try_rdap("example.com")
        call_url = mock_get.call_args[0][0]
        assert call_url.startswith("https://rdap.org/domain/")


# ---------------------------------------------------------------------------
# _registered_domain
# ---------------------------------------------------------------------------


class TestRegisteredDomain:
    def test_extracts_registered_domain_from_subdomain(self):
        result = _registered_domain("sub.example.com")
        assert result == "example.com"

    def test_returns_none_when_input_is_already_registered_domain(self):
        result = _registered_domain("example.com")
        assert result is None

    def test_handles_multi_level_subdomain(self):
        result = _registered_domain("a.b.c.example.com")
        assert result == "example.com"

    def test_handles_multi_part_public_suffix(self):
        result = _registered_domain("sub.example.co.jp")
        assert result == "example.co.jp"

    def test_returns_none_for_tld_only(self):
        result = _registered_domain("com")
        assert result is None




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
        with (
            patch("module.enrich.enrich_domain._try_whois", return_value=None),
            patch("module.enrich.enrich_domain._try_rdap", return_value=None),
            patch("module.enrich.enrich_domain._registered_domain", return_value=None),
        ):
            result = fetch_whois("example.com")
        assert result == {
            "registrant_name": None,
            "registrant_email": None,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
        }

    def test_falls_back_to_rdap_when_whois_fails(self):
        rdap_result = {
            "registrant_name": "RDAP Corp",
            "registrant_email": "rdap@example.com",
            "registrar": "RDAP Registrar",
            "creation_date": "2020-01-01T00:00:00Z",
            "expiration_date": "2030-01-01T00:00:00Z",
        }
        with (
            patch("module.enrich.enrich_domain._try_whois", return_value=None),
            patch("module.enrich.enrich_domain._try_rdap", return_value=rdap_result),
        ):
            result = fetch_whois("example.com")
        assert result == rdap_result

    def test_falls_back_to_registered_domain_when_direct_lookups_fail(self):
        registered_result = {
            "registrant_name": "Root Domain Owner",
            "registrant_email": None,
            "registrar": "Some Registrar",
            "creation_date": "2010-01-01T00:00:00Z",
            "expiration_date": None,
        }
        # _try_whois returns None for the subdomain on the first call,
        # then returns registered_result for the registered domain on the second call.
        with (
            patch(
                "module.enrich.enrich_domain._try_whois",
                side_effect=[None, registered_result],
            ),
            patch("module.enrich.enrich_domain._try_rdap", return_value=None),
            patch(
                "module.enrich.enrich_domain._registered_domain",
                return_value="example.com",
            ),
        ):
            result = fetch_whois("sub.example.com")
        assert result["registrant_name"] == "Root Domain Owner"

    def test_returns_empty_when_all_fallbacks_fail(self):
        with (
            patch("module.enrich.enrich_domain._try_whois", return_value=None),
            patch("module.enrich.enrich_domain._try_rdap", return_value=None),
            patch("module.enrich.enrich_domain._registered_domain", return_value="example.com"),
        ):
            result = fetch_whois("sub.example.com")
        assert result == {
            "registrant_name": None,
            "registrant_email": None,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
        }

    def test_skips_registered_domain_retry_when_no_subdomain(self):
        """When _registered_domain returns None, RDAP fallback is still the last step."""
        with (
            patch("module.enrich.enrich_domain._try_whois", return_value=None),
            patch("module.enrich.enrich_domain._try_rdap", return_value=None),
            patch("module.enrich.enrich_domain._registered_domain", return_value=None),
        ):
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
            patch("module.enrich.enrich_domain.resolve_dns", return_value=["93.184.216.34"]) as mock_dns,
            patch(
                "module.enrich.enrich_domain.fetch_whois",
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
            patch("module.enrich.enrich_domain.resolve_dns", return_value=[]),
            patch("module.enrich.enrich_domain.fetch_whois", return_value={
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
