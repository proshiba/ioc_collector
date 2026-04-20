"""Tests for app/module/enrich/enrich_ip.py"""

from unittest.mock import MagicMock, patch

import geoip2.errors
import pytest

from module.enrich.enrich_ip import (
    DEFAULT_ASN_DB_PATH,
    DEFAULT_COUNTRY_DB_PATH,
    enrich_ip,
    fetch_asn,
    fetch_country,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_asn_response(asn_number: int, asn_org: str) -> MagicMock:
    mock = MagicMock()
    mock.autonomous_system_number = asn_number
    mock.autonomous_system_organization = asn_org
    return mock


def _make_country_response(iso_code: str, name: str) -> MagicMock:
    mock = MagicMock()
    mock.country.iso_code = iso_code
    mock.country.name = name
    return mock


# ---------------------------------------------------------------------------
# fetch_asn
# ---------------------------------------------------------------------------


class TestFetchAsn:
    def test_returns_asn_and_org(self):
        mock_reader = MagicMock()
        mock_reader.__enter__ = MagicMock(return_value=mock_reader)
        mock_reader.__exit__ = MagicMock(return_value=False)
        mock_reader.asn.return_value = _make_asn_response(15169, "GOOGLE")

        with patch("geoip2.database.Reader", return_value=mock_reader):
            result = fetch_asn("8.8.8.8", asn_db_path="/fake/GeoLite2-ASN.mmdb")

        assert result == {"asn": 15169, "org": "GOOGLE"}

    def test_file_not_found_returns_none_values(self):
        with patch("geoip2.database.Reader", side_effect=FileNotFoundError("no file")):
            result = fetch_asn("1.2.3.4", asn_db_path="/nonexistent.mmdb")

        assert result == {"asn": None, "org": None}

    def test_address_not_found_returns_none_values(self):
        mock_reader = MagicMock()
        mock_reader.__enter__ = MagicMock(return_value=mock_reader)
        mock_reader.__exit__ = MagicMock(return_value=False)
        mock_reader.asn.side_effect = geoip2.errors.AddressNotFoundError("not found")

        with patch("geoip2.database.Reader", return_value=mock_reader):
            result = fetch_asn("0.0.0.0", asn_db_path="/fake/GeoLite2-ASN.mmdb")

        assert result == {"asn": None, "org": None}

    def test_generic_exception_returns_none_values(self):
        mock_reader = MagicMock()
        mock_reader.__enter__ = MagicMock(return_value=mock_reader)
        mock_reader.__exit__ = MagicMock(return_value=False)
        mock_reader.asn.side_effect = Exception("unexpected error")

        with patch("geoip2.database.Reader", return_value=mock_reader):
            result = fetch_asn("1.2.3.4", asn_db_path="/fake/GeoLite2-ASN.mmdb")

        assert result == {"asn": None, "org": None}


# ---------------------------------------------------------------------------
# fetch_country
# ---------------------------------------------------------------------------


class TestFetchCountry:
    def test_returns_country_code_and_name(self):
        mock_reader = MagicMock()
        mock_reader.__enter__ = MagicMock(return_value=mock_reader)
        mock_reader.__exit__ = MagicMock(return_value=False)
        mock_reader.country.return_value = _make_country_response("US", "United States")

        with patch("geoip2.database.Reader", return_value=mock_reader):
            result = fetch_country("8.8.8.8", country_db_path="/fake/GeoLite2-Country.mmdb")

        assert result == {"country_code": "US", "country_name": "United States"}

    def test_file_not_found_returns_none_values(self):
        with patch("geoip2.database.Reader", side_effect=FileNotFoundError("no file")):
            result = fetch_country("1.2.3.4", country_db_path="/nonexistent.mmdb")

        assert result == {"country_code": None, "country_name": None}

    def test_address_not_found_returns_none_values(self):
        mock_reader = MagicMock()
        mock_reader.__enter__ = MagicMock(return_value=mock_reader)
        mock_reader.__exit__ = MagicMock(return_value=False)
        mock_reader.country.side_effect = geoip2.errors.AddressNotFoundError("not found")

        with patch("geoip2.database.Reader", return_value=mock_reader):
            result = fetch_country("0.0.0.0", country_db_path="/fake/GeoLite2-Country.mmdb")

        assert result == {"country_code": None, "country_name": None}

    def test_generic_exception_returns_none_values(self):
        mock_reader = MagicMock()
        mock_reader.__enter__ = MagicMock(return_value=mock_reader)
        mock_reader.__exit__ = MagicMock(return_value=False)
        mock_reader.country.side_effect = Exception("unexpected error")

        with patch("geoip2.database.Reader", return_value=mock_reader):
            result = fetch_country("1.2.3.4", country_db_path="/fake/GeoLite2-Country.mmdb")

        assert result == {"country_code": None, "country_name": None}


# ---------------------------------------------------------------------------
# enrich_ip
# ---------------------------------------------------------------------------


class TestEnrichIp:
    def test_returns_expected_structure(self):
        with (
            patch(
                "module.enrich.enrich_ip.fetch_asn",
                return_value={"asn": 15169, "org": "GOOGLE"},
            ) as mock_asn,
            patch(
                "module.enrich.enrich_ip.fetch_country",
                return_value={"country_code": "US", "country_name": "United States"},
            ) as mock_country,
        ):
            result = enrich_ip(
                "8.8.8.8",
                asn_db_path="/fake/GeoLite2-ASN.mmdb",
                country_db_path="/fake/GeoLite2-Country.mmdb",
            )

        assert result == {
            "ip": "8.8.8.8",
            "asn": 15169,
            "org": "GOOGLE",
            "country_code": "US",
            "country_name": "United States",
        }
        mock_asn.assert_called_once_with("8.8.8.8", asn_db_path="/fake/GeoLite2-ASN.mmdb")
        mock_country.assert_called_once_with("8.8.8.8", country_db_path="/fake/GeoLite2-Country.mmdb")

    def test_failed_lookups_yield_none_values(self):
        with (
            patch(
                "module.enrich.enrich_ip.fetch_asn",
                return_value={"asn": None, "org": None},
            ),
            patch(
                "module.enrich.enrich_ip.fetch_country",
                return_value={"country_code": None, "country_name": None},
            ),
        ):
            result = enrich_ip("0.0.0.0")

        assert result == {
            "ip": "0.0.0.0",
            "asn": None,
            "org": None,
            "country_code": None,
            "country_name": None,
        }
