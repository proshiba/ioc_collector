"""Tests for app/module/fetch/threatfox.py"""

import pytest
import requests
from unittest.mock import MagicMock, patch

from module.fetch.threatfox import THREATFOX_API_URL, fetch_daily_iocs


FAKE_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "id": "1",
            "ioc": "198.51.100.42:4444",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware": "win.cobalt_strike",
            "confidence_level": 75,
            "first_seen": "2024-01-15 10:00:00 UTC",
            "last_seen": "2024-01-15 10:00:00 UTC",
            "reporter": "demo",
        }
    ],
}


def _make_mock_response(json_data: dict) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = json_data
    return mock_resp


class TestFetchDailyIocs:
    def test_success_returns_parsed_json(self):
        with patch("requests.post", return_value=_make_mock_response(FAKE_RESPONSE)) as mock_post:
            result = fetch_daily_iocs()

        assert result == FAKE_RESPONSE

    def test_sends_correct_payload(self):
        with patch("requests.post", return_value=_make_mock_response(FAKE_RESPONSE)) as mock_post:
            fetch_daily_iocs()

        mock_post.assert_called_once_with(
            THREATFOX_API_URL,
            headers={"Content-Type": "application/json"},
            json={"query": "get_iocs", "days": 1},
            timeout=60,
        )

    def test_http_error_is_propagated(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
        with patch("requests.post", return_value=mock_resp):
            with pytest.raises(requests.HTTPError):
                fetch_daily_iocs()

    def test_connection_error_is_propagated(self):
        with patch("requests.post", side_effect=requests.ConnectionError("unreachable")):
            with pytest.raises(requests.ConnectionError):
                fetch_daily_iocs()

    def test_timeout_error_is_propagated(self):
        with patch("requests.post", side_effect=requests.Timeout("timed out")):
            with pytest.raises(requests.Timeout):
                fetch_daily_iocs()
