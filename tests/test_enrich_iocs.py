"""Tests for app/bin/enrich_iocs.py"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

import enrich_iocs
from enrich_iocs import extract_iocs_from_entries


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

THREATFOX_ENTRIES = [
    {"ioc_type": "ip:port", "ioc": "198.51.100.42:4444"},
    {"ioc_type": "ip:port", "ioc": "203.0.113.7:80"},
    {"ioc_type": "domain", "ioc": "evil.example.com"},
    {"ioc_type": "url", "ioc": "http://malicious.example.org/payload"},
    {"ioc_type": "md5_hash", "ioc": "d41d8cd98f00b204e9800998ecf8427e"},
]

PHISHTANK_ENTRIES = [
    {
        "phish_id": "12345",
        "url": "http://phishing.example.net/login",
        "details": [{"ip_address": "192.0.2.1"}],
        "target": "PayPal",
    },
    {
        "phish_id": "67890",
        "url": "http://192.0.2.200/steal",
        "details": [],
        "target": "Bank",
    },
]

MALWARE_BAZAAR_ENTRIES = [
    {
        "sha256_hash": "a" * 64,
        "md5_hash": "b" * 32,
        "file_name": "malware.exe",
        "signature": "Win.Trojan.Generic",
        "tags": ["trojan"],
    }
]

FAKE_ENRICH_IP_RESULT = {
    "ip": "198.51.100.42",
    "asn": 64496,
    "org": "TEST-ORG",
    "country_code": "US",
    "country_name": "United States",
}

FAKE_ENRICH_DOMAIN_RESULT = {
    "domain": "evil.example.com",
    "dns": ["198.51.100.1"],
    "whois": {
        "registrant_name": None,
        "registrant_email": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
    },
}


def _write_ioc_file(path: str, entries: list) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"query_status": "ok", "data": entries}, fh)


# ---------------------------------------------------------------------------
# extract_iocs_from_entries
# ---------------------------------------------------------------------------


class TestExtractIocsFromEntries:
    def test_threatfox_ip_port(self):
        ips, domains = extract_iocs_from_entries(
            [{"ioc_type": "ip:port", "ioc": "198.51.100.42:4444"}]
        )
        assert "198.51.100.42" in ips
        assert domains == []

    def test_threatfox_ip(self):
        ips, domains = extract_iocs_from_entries(
            [{"ioc_type": "ip", "ioc": "10.0.0.1"}]
        )
        assert "10.0.0.1" in ips

    def test_threatfox_domain(self):
        ips, domains = extract_iocs_from_entries(
            [{"ioc_type": "domain", "ioc": "evil.example.com"}]
        )
        assert "evil.example.com" in domains
        assert ips == []

    def test_threatfox_url_extracts_domain(self):
        ips, domains = extract_iocs_from_entries(
            [{"ioc_type": "url", "ioc": "http://malicious.example.org/path"}]
        )
        assert "malicious.example.org" in domains

    def test_threatfox_url_extracts_ip(self):
        ips, domains = extract_iocs_from_entries(
            [{"ioc_type": "url", "ioc": "http://192.0.2.1/path"}]
        )
        assert "192.0.2.1" in ips
        assert domains == []

    def test_threatfox_hash_ignored(self):
        ips, domains = extract_iocs_from_entries(
            [{"ioc_type": "md5_hash", "ioc": "d41d8cd98f00b204e9800998ecf8427e"}]
        )
        assert ips == []
        assert domains == []

    def test_phishtank_url_extracted(self):
        ips, domains = extract_iocs_from_entries(
            [{"url": "http://phishing.example.net/login", "details": []}]
        )
        assert "phishing.example.net" in domains

    def test_phishtank_ip_in_url(self):
        ips, domains = extract_iocs_from_entries(
            [{"url": "http://192.0.2.200/steal", "details": []}]
        )
        assert "192.0.2.200" in ips
        assert domains == []

    def test_phishtank_details_ip(self):
        ips, domains = extract_iocs_from_entries(
            [
                {
                    "url": "http://phishing.example.net/login",
                    "details": [{"ip_address": "192.0.2.1"}],
                }
            ]
        )
        assert "192.0.2.1" in ips

    def test_malware_bazaar_no_ips_or_domains(self):
        ips, domains = extract_iocs_from_entries(MALWARE_BAZAAR_ENTRIES)
        assert ips == []
        assert domains == []

    def test_results_are_deduplicated(self):
        entries = [
            {"ioc_type": "ip:port", "ioc": "10.0.0.1:80"},
            {"ioc_type": "ip:port", "ioc": "10.0.0.1:443"},
        ]
        ips, _ = extract_iocs_from_entries(entries)
        assert ips.count("10.0.0.1") == 1

    def test_results_are_sorted(self):
        entries = [
            {"ioc_type": "domain", "ioc": "z.example.com"},
            {"ioc_type": "domain", "ioc": "a.example.com"},
        ]
        _, domains = extract_iocs_from_entries(entries)
        assert domains == sorted(domains)

    def test_empty_entries_returns_empty(self):
        ips, domains = extract_iocs_from_entries([])
        assert ips == []
        assert domains == []

    def test_ipv6_ip_port(self):
        ips, domains = extract_iocs_from_entries(
            [{"ioc_type": "ip:port", "ioc": "[::1]:80"}]
        )
        assert "::1" in ips


# ---------------------------------------------------------------------------
# enrich_file
# ---------------------------------------------------------------------------


class TestEnrichFile:
    def test_creates_enriched_file(self, tmp_path):
        ioc_path = str(tmp_path / "iocs" / "20240115.json")
        _write_ioc_file(ioc_path, THREATFOX_ENTRIES)
        out_dir = str(tmp_path / "enriched_ioc")

        with (
            patch("enrich_iocs.enrich_ip", return_value=FAKE_ENRICH_IP_RESULT),
            patch("enrich_iocs.enrich_domain", return_value=FAKE_ENRICH_DOMAIN_RESULT),
        ):
            output_path = enrich_iocs.enrich_file(ioc_path, out_dir)

        assert os.path.exists(output_path)
        assert os.path.basename(output_path) == "20240115.json"

    def test_enriched_file_contains_ips_and_domains(self, tmp_path):
        ioc_path = str(tmp_path / "iocs" / "20240115.json")
        _write_ioc_file(ioc_path, THREATFOX_ENTRIES)
        out_dir = str(tmp_path / "enriched_ioc")

        with (
            patch("enrich_iocs.enrich_ip", return_value=FAKE_ENRICH_IP_RESULT),
            patch("enrich_iocs.enrich_domain", return_value=FAKE_ENRICH_DOMAIN_RESULT),
        ):
            output_path = enrich_iocs.enrich_file(ioc_path, out_dir)

        with open(output_path, encoding="utf-8") as fh:
            result = json.load(fh)

        assert "ips" in result
        assert "domains" in result
        assert result["source_file"] == ioc_path
        assert "enriched_at" in result

    def test_type_ip_only_enriches_ips(self, tmp_path):
        ioc_path = str(tmp_path / "iocs" / "20240115.json")
        _write_ioc_file(ioc_path, THREATFOX_ENTRIES)
        out_dir = str(tmp_path / "enriched_ioc")

        mock_ip = MagicMock(return_value=FAKE_ENRICH_IP_RESULT)
        mock_domain = MagicMock(return_value=FAKE_ENRICH_DOMAIN_RESULT)

        with (
            patch("enrich_iocs.enrich_ip", mock_ip),
            patch("enrich_iocs.enrich_domain", mock_domain),
        ):
            enrich_iocs.enrich_file(ioc_path, out_dir, enrich_type="ip")

        mock_ip.assert_called()
        mock_domain.assert_not_called()

    def test_type_domain_only_enriches_domains(self, tmp_path):
        ioc_path = str(tmp_path / "iocs" / "20240115.json")
        _write_ioc_file(ioc_path, THREATFOX_ENTRIES)
        out_dir = str(tmp_path / "enriched_ioc")

        mock_ip = MagicMock(return_value=FAKE_ENRICH_IP_RESULT)
        mock_domain = MagicMock(return_value=FAKE_ENRICH_DOMAIN_RESULT)

        with (
            patch("enrich_iocs.enrich_ip", mock_ip),
            patch("enrich_iocs.enrich_domain", mock_domain),
        ):
            enrich_iocs.enrich_file(ioc_path, out_dir, enrich_type="domain")

        mock_ip.assert_not_called()
        mock_domain.assert_called()

    def test_creates_output_dir_if_missing(self, tmp_path):
        ioc_path = str(tmp_path / "iocs" / "20240115.json")
        _write_ioc_file(ioc_path, [])
        out_dir = str(tmp_path / "nested" / "enriched_ioc")

        with (
            patch("enrich_iocs.enrich_ip", return_value=FAKE_ENRICH_IP_RESULT),
            patch("enrich_iocs.enrich_domain", return_value=FAKE_ENRICH_DOMAIN_RESULT),
        ):
            enrich_iocs.enrich_file(ioc_path, out_dir)

        assert os.path.isdir(out_dir)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


class TestMain:
    def test_processes_ioc_files_and_deletes_originals(self, tmp_path):
        ioc_dir = str(tmp_path / "iocs")
        ioc_path = os.path.join(ioc_dir, "20240115.json")
        _write_ioc_file(ioc_path, THREATFOX_ENTRIES)
        out_dir = str(tmp_path / "enriched_ioc")

        with (
            patch("enrich_iocs.enrich_ip", return_value=FAKE_ENRICH_IP_RESULT),
            patch("enrich_iocs.enrich_domain", return_value=FAKE_ENRICH_DOMAIN_RESULT),
        ):
            enrich_iocs.main([], ioc_dir=ioc_dir, output_dir=out_dir)

        # Original file should be deleted
        assert not os.path.exists(ioc_path)
        # Enriched file should exist
        assert os.path.exists(os.path.join(out_dir, "20240115.json"))

    def test_type_ip_flag(self, tmp_path):
        ioc_dir = str(tmp_path / "iocs")
        ioc_path = os.path.join(ioc_dir, "20240115.json")
        _write_ioc_file(ioc_path, THREATFOX_ENTRIES)
        out_dir = str(tmp_path / "enriched_ioc")

        mock_domain = MagicMock(return_value=FAKE_ENRICH_DOMAIN_RESULT)
        with (
            patch("enrich_iocs.enrich_ip", return_value=FAKE_ENRICH_IP_RESULT),
            patch("enrich_iocs.enrich_domain", mock_domain),
        ):
            enrich_iocs.main(["--type", "ip"], ioc_dir=ioc_dir, output_dir=out_dir)

        mock_domain.assert_not_called()

    def test_type_domain_flag(self, tmp_path):
        ioc_dir = str(tmp_path / "iocs")
        ioc_path = os.path.join(ioc_dir, "20240115.json")
        _write_ioc_file(ioc_path, THREATFOX_ENTRIES)
        out_dir = str(tmp_path / "enriched_ioc")

        mock_ip = MagicMock(return_value=FAKE_ENRICH_IP_RESULT)
        with (
            patch("enrich_iocs.enrich_ip", mock_ip),
            patch("enrich_iocs.enrich_domain", return_value=FAKE_ENRICH_DOMAIN_RESULT),
        ):
            enrich_iocs.main(["--type", "domain"], ioc_dir=ioc_dir, output_dir=out_dir)

        mock_ip.assert_not_called()

    def test_exits_when_ioc_dir_missing(self, tmp_path):
        missing_dir = str(tmp_path / "no_such_dir")
        with pytest.raises(SystemExit) as exc_info:
            enrich_iocs.main([], ioc_dir=missing_dir, output_dir=str(tmp_path / "out"))
        assert exc_info.value.code == 1

    def test_no_files_prints_message_and_returns(self, tmp_path, capsys):
        ioc_dir = str(tmp_path / "iocs")
        os.makedirs(ioc_dir)
        out_dir = str(tmp_path / "enriched_ioc")

        enrich_iocs.main([], ioc_dir=ioc_dir, output_dir=out_dir)

        captured = capsys.readouterr()
        assert "No IOC files found" in captured.out

    def test_ioc_dir_cli_option(self, tmp_path):
        ioc_dir = str(tmp_path / "custom_iocs")
        ioc_path = os.path.join(ioc_dir, "20240115.json")
        _write_ioc_file(ioc_path, [])
        out_dir = str(tmp_path / "enriched_ioc")

        with (
            patch("enrich_iocs.enrich_ip", return_value=FAKE_ENRICH_IP_RESULT),
            patch("enrich_iocs.enrich_domain", return_value=FAKE_ENRICH_DOMAIN_RESULT),
        ):
            enrich_iocs.main(["--ioc-dir", ioc_dir, "--output-dir", out_dir])

        assert not os.path.exists(ioc_path)

    def test_multiple_files_all_processed(self, tmp_path):
        ioc_dir = str(tmp_path / "iocs")
        for name in ("20240115.json", "20240116.json"):
            _write_ioc_file(os.path.join(ioc_dir, name), PHISHTANK_ENTRIES)
        out_dir = str(tmp_path / "enriched_ioc")

        with (
            patch("enrich_iocs.enrich_ip", return_value=FAKE_ENRICH_IP_RESULT),
            patch("enrich_iocs.enrich_domain", return_value=FAKE_ENRICH_DOMAIN_RESULT),
        ):
            enrich_iocs.main([], ioc_dir=ioc_dir, output_dir=out_dir)

        assert not os.listdir(ioc_dir)
        assert len(os.listdir(out_dir)) == 2
