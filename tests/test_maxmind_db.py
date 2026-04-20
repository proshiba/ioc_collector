"""Tests for app/module/fetch/maxmind_db.py"""

import io
import os
import tarfile
import tempfile
from unittest.mock import MagicMock, patch

import pytest
import requests

from module.fetch.maxmind_db import (
    DEFAULT_DB_DIR,
    EDITION_ASN,
    EDITION_COUNTRY,
    _download_and_extract,
    download_maxmind_dbs,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tar_gz(mmdb_filename: str, content: bytes = b"mmdb-data") -> bytes:
    """Build an in-memory .tar.gz archive containing a single .mmdb file."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=f"GeoLite2-Edition_20240101/{mmdb_filename}")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_response(body: bytes, status_code: int = 200) -> MagicMock:
    """Return a mock requests.Response that streams *body*."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.raise_for_status = MagicMock()
    # iter_content yields the whole body as one chunk.
    mock_resp.iter_content = MagicMock(return_value=iter([body]))
    return mock_resp


# ---------------------------------------------------------------------------
# _download_and_extract
# ---------------------------------------------------------------------------


class TestDownloadAndExtract:
    def test_extracts_mmdb_to_dest_dir(self):
        tar_data = _make_tar_gz("GeoLite2-ASN.mmdb", b"fake-asn-db")
        mock_resp = _make_response(tar_data)

        with tempfile.TemporaryDirectory() as dest:
            with patch("requests.get", return_value=mock_resp):
                result = _download_and_extract(EDITION_ASN, "dummy-key", dest)

            assert result == os.path.join(dest, "GeoLite2-ASN.mmdb")
            assert os.path.isfile(result)
            assert open(result, "rb").read() == b"fake-asn-db"

    def test_raises_on_http_error(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.HTTPError("403")
        mock_resp.iter_content = MagicMock(return_value=iter([]))

        with tempfile.TemporaryDirectory() as dest:
            with patch("requests.get", return_value=mock_resp):
                with pytest.raises(requests.HTTPError):
                    _download_and_extract(EDITION_ASN, "bad-key", dest)

    def test_raises_when_no_mmdb_in_archive(self):
        # Build a tar.gz with a non-.mmdb file.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="some_dir/README.txt")
            data = b"hello"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        tar_data = buf.getvalue()

        mock_resp = _make_response(tar_data)
        with tempfile.TemporaryDirectory() as dest:
            with patch("requests.get", return_value=mock_resp):
                with pytest.raises(FileNotFoundError, match="No .mmdb file"):
                    _download_and_extract(EDITION_ASN, "dummy-key", dest)


# ---------------------------------------------------------------------------
# download_maxmind_dbs
# ---------------------------------------------------------------------------


class TestDownloadMaxmindDbs:
    def test_returns_paths_for_both_editions(self):
        asn_tar = _make_tar_gz("GeoLite2-ASN.mmdb")
        country_tar = _make_tar_gz("GeoLite2-Country.mmdb")
        tarballs = {EDITION_ASN: asn_tar, EDITION_COUNTRY: country_tar}

        def _fake_get(url, **kwargs):
            edition = next(e for e in tarballs if e in url)
            return _make_response(tarballs[edition])

        with tempfile.TemporaryDirectory() as dest:
            with patch("requests.get", side_effect=_fake_get):
                result = download_maxmind_dbs(dest_dir=dest, license_key="test-key")

        assert set(result.keys()) == {EDITION_ASN, EDITION_COUNTRY}
        assert result[EDITION_ASN].endswith("GeoLite2-ASN.mmdb")
        assert result[EDITION_COUNTRY].endswith("GeoLite2-Country.mmdb")

    def test_creates_dest_dir_if_missing(self):
        asn_tar = _make_tar_gz("GeoLite2-ASN.mmdb")
        country_tar = _make_tar_gz("GeoLite2-Country.mmdb")
        tarballs = {EDITION_ASN: asn_tar, EDITION_COUNTRY: country_tar}

        def _fake_get(url, **kwargs):
            edition = next(e for e in tarballs if e in url)
            return _make_response(tarballs[edition])

        with tempfile.TemporaryDirectory() as base:
            new_dir = os.path.join(base, "new", "subdir")
            with patch("requests.get", side_effect=_fake_get):
                download_maxmind_dbs(dest_dir=new_dir, license_key="test-key")
            assert os.path.isdir(new_dir)

    def test_raises_when_no_license_key(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove key from env if present.
            os.environ.pop("MAXMIND_LICENSE_KEY", None)
            with pytest.raises(ValueError, match="license key"):
                download_maxmind_dbs(license_key=None)

    def test_uses_env_var_license_key(self):
        asn_tar = _make_tar_gz("GeoLite2-ASN.mmdb")
        country_tar = _make_tar_gz("GeoLite2-Country.mmdb")
        tarballs = {EDITION_ASN: asn_tar, EDITION_COUNTRY: country_tar}

        def _fake_get(url, **kwargs):
            assert "env-key" in url
            edition = next(e for e in tarballs if e in url)
            return _make_response(tarballs[edition])

        with tempfile.TemporaryDirectory() as dest:
            with patch.dict(os.environ, {"MAXMIND_LICENSE_KEY": "env-key"}):
                with patch("requests.get", side_effect=_fake_get):
                    result = download_maxmind_dbs(dest_dir=dest)

        assert EDITION_ASN in result
        assert EDITION_COUNTRY in result
