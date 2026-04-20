"""Tests for app/collect_iocs.py"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

import collect_iocs

FAKE_OK_RESPONSE = {
    "query_status": "ok",
    "data": [{"id": "1", "ioc": "198.51.100.42:4444", "ioc_type": "ip:port"}],
}

FAKE_ERROR_RESPONSE = {
    "query_status": "no_results",
    "data": [],
}


class TestSaveIocs:
    def test_creates_file_with_correct_content(self, tmp_path):
        output_path = str(tmp_path / "output.json")
        collect_iocs.save_iocs(FAKE_OK_RESPONSE, output_path)

        assert os.path.exists(output_path)
        with open(output_path, encoding="utf-8") as fh:
            saved = json.load(fh)
        assert saved == FAKE_OK_RESPONSE

    def test_creates_parent_directory_if_missing(self, tmp_path):
        output_path = str(tmp_path / "nested" / "dir" / "output.json")
        collect_iocs.save_iocs(FAKE_OK_RESPONSE, output_path)
        assert os.path.exists(output_path)

    def test_overwrites_existing_file(self, tmp_path):
        output_path = str(tmp_path / "output.json")
        collect_iocs.save_iocs({"old": True}, output_path)
        collect_iocs.save_iocs(FAKE_OK_RESPONSE, output_path)

        with open(output_path, encoding="utf-8") as fh:
            saved = json.load(fh)
        assert saved == FAKE_OK_RESPONSE


class TestMain:
    def _patched_sources(self, return_value: dict):
        mock_fn = MagicMock(return_value=return_value)
        return patch.dict(collect_iocs.SOURCES, {"threatfox": mock_fn}), mock_fn

    def test_default_source_is_threatfox(self, tmp_path):
        ctx, mock_fn = self._patched_sources(FAKE_OK_RESPONSE)
        with ctx:
            collect_iocs.main([], output_dir=str(tmp_path))
        mock_fn.assert_called_once()

    def test_explicit_threatfox_source(self, tmp_path):
        ctx, mock_fn = self._patched_sources(FAKE_OK_RESPONSE)
        with ctx:
            collect_iocs.main(["--source", "threatfox"], output_dir=str(tmp_path))
        mock_fn.assert_called_once()

    def test_output_file_created_with_today_date(self, tmp_path):
        ctx, _ = self._patched_sources(FAKE_OK_RESPONSE)
        with ctx:
            collect_iocs.main([], output_dir=str(tmp_path))

        from datetime import datetime, timezone

        today = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
        assert os.path.exists(os.path.join(str(tmp_path), f"{today}.json"))

    def test_output_file_contains_api_response(self, tmp_path):
        ctx, _ = self._patched_sources(FAKE_OK_RESPONSE)
        with ctx:
            collect_iocs.main([], output_dir=str(tmp_path))

        from datetime import datetime, timezone

        today = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
        output_path = os.path.join(str(tmp_path), f"{today}.json")
        with open(output_path, encoding="utf-8") as fh:
            saved = json.load(fh)
        assert saved == FAKE_OK_RESPONSE

    def test_exits_with_error_on_bad_status(self, tmp_path):
        ctx, _ = self._patched_sources(FAKE_ERROR_RESPONSE)
        with ctx:
            with pytest.raises(SystemExit) as exc_info:
                collect_iocs.main([], output_dir=str(tmp_path))
        assert exc_info.value.code == 1

    def test_invalid_source_raises_argparse_error(self, tmp_path):
        with pytest.raises(SystemExit):
            collect_iocs.main(["--source", "unknown_source"], output_dir=str(tmp_path))
