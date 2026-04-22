"""Tests for app/module/parser/cert_parser.py"""

import sys
from datetime import timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
import datetime

from module.parser.cert_parser import parse_certificate, _name_to_dict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_self_signed_der(
    common_name: str = "example.com",
    sans: list | None = None,
) -> bytes:
    """Generate a minimal self-signed DER certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )

    not_before = datetime.datetime(2024, 1, 1, tzinfo=timezone.utc)
    not_after = datetime.datetime(2025, 1, 1, tzinfo=timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if sans:
        san_names = [x509.DNSName(name) for name in sans]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names), critical=False
        )

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# _name_to_dict
# ---------------------------------------------------------------------------


class TestNameToDict:
    def test_extracts_common_name(self):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        result = _name_to_dict(name)
        assert result.get("commonName") == "example.com"

    def test_extracts_multiple_attributes(self):
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
            ]
        )
        result = _name_to_dict(name)
        assert result["commonName"] == "example.com"
        assert result["organizationName"] == "Example Org"

    def test_empty_name_returns_empty_dict(self):
        name = x509.Name([])
        result = _name_to_dict(name)
        assert result == {}


# ---------------------------------------------------------------------------
# parse_certificate
# ---------------------------------------------------------------------------


class TestParseCertificate:
    def test_returns_dict_for_valid_der(self):
        der = _generate_self_signed_der("example.com")
        result = parse_certificate(der)
        assert result is not None
        assert isinstance(result, dict)

    def test_subject_contains_common_name(self):
        der = _generate_self_signed_der("example.com")
        result = parse_certificate(der)
        assert result["subject"].get("commonName") == "example.com"

    def test_issuer_contains_common_name(self):
        der = _generate_self_signed_der("example.com")
        result = parse_certificate(der)
        assert result["issuer"].get("commonName") == "example.com"

    def test_serial_number_is_string(self):
        der = _generate_self_signed_der("example.com")
        result = parse_certificate(der)
        assert isinstance(result["serial_number"], str)

    def test_not_valid_before_is_iso_string(self):
        der = _generate_self_signed_der("example.com")
        result = parse_certificate(der)
        assert "2024-01-01" in result["not_valid_before"]

    def test_not_valid_after_is_iso_string(self):
        der = _generate_self_signed_der("example.com")
        result = parse_certificate(der)
        assert "2025-01-01" in result["not_valid_after"]

    def test_fingerprint_sha256_is_hex_string(self):
        der = _generate_self_signed_der("example.com")
        result = parse_certificate(der)
        fp = result["fingerprint_sha256"]
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA-256 = 32 bytes = 64 hex chars
        assert all(c in "0123456789abcdef" for c in fp)

    def test_sans_present_when_in_cert(self):
        der = _generate_self_signed_der("example.com", sans=["example.com", "www.example.com"])
        result = parse_certificate(der)
        assert len(result["subject_alt_names"]) == 2
        san_strings = " ".join(result["subject_alt_names"])
        assert "example.com" in san_strings

    def test_sans_empty_when_not_in_cert(self):
        der = _generate_self_signed_der("example.com", sans=None)
        result = parse_certificate(der)
        assert result["subject_alt_names"] == []

    def test_returns_none_for_invalid_bytes(self, capsys):
        result = parse_certificate(b"\x00\x01\x02invalid")
        assert result is None
        captured = capsys.readouterr()
        assert "Certificate parse failed" in captured.err

    def test_returns_none_for_empty_bytes(self, capsys):
        result = parse_certificate(b"")
        assert result is None
        captured = capsys.readouterr()
        assert "Certificate parse failed" in captured.err

    def test_result_contains_all_expected_keys(self):
        der = _generate_self_signed_der("example.com")
        result = parse_certificate(der)
        expected_keys = {
            "subject",
            "issuer",
            "serial_number",
            "not_valid_before",
            "not_valid_after",
            "subject_alt_names",
            "fingerprint_sha256",
        }
        assert expected_keys == set(result.keys())
