"""Tests for app/module/fetch/phishtank.py"""

import pytest
import requests
from unittest.mock import MagicMock, patch

from module.fetch.phishtank import PHISHTANK_DATA_URL, fetch_iocs


FAKE_ENTRIES = [
    {
        "phish_id": "12345",
        "url": "http://example.com/phishing",
        "phish_detail_url": "http://www.phishtank.com/phish_detail.php?phish_id=12345",
        "submission_time": "2024-01-15T10:00:00+00:00",
        "verified": "yes",
        "verification_time": "2024-01-15T10:30:00+00:00",
        "online": "yes",
        "details": [
            {
                "ip_address": "192.0.2.1",
                "cidr_block": "192.0.2.0/24",
                "announcing_network": "AS12345",
                "rir": "ARIN",
                "country": "US",
                "detail_time": "2024-01-15T10:30:00+00:00",
            }
        ],
        "target": "PayPal",
    }
]


def _make_mock_response(json_data) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = json_data
    return mock_resp


class TestFetchIocs:
    def test_success_returns_normalised_response(self):
        with patch("requests.get", return_value=_make_mock_response(FAKE_ENTRIES)):
            result = fetch_iocs()

        assert result["query_status"] == "ok"
        assert result["data"] == FAKE_ENTRIES

    def test_uses_keyless_url_when_env_not_set(self):
        with (
            patch("requests.get", return_value=_make_mock_response(FAKE_ENTRIES)) as mock_get,
            patch.dict("os.environ", {}, clear=True),
        ):
            fetch_iocs()

        url = mock_get.call_args.args[0]
        assert "online-valid.json" in url
        # No API key segment in the path
        assert url == PHISHTANK_DATA_URL.format(api_key="")

    def test_uses_api_key_url_when_env_set(self):
        with (
            patch("requests.get", return_value=_make_mock_response(FAKE_ENTRIES)) as mock_get,
            patch.dict("os.environ", {"PHISHTANK_API_KEY": "my-api-key"}),
        ):
            fetch_iocs()

        url = mock_get.call_args.args[0]
        assert "my-api-key" in url

    def test_sends_user_agent_header(self):
        with patch("requests.get", return_value=_make_mock_response(FAKE_ENTRIES)) as mock_get:
            fetch_iocs()

        headers = mock_get.call_args[1]["headers"]
        assert "User-Agent" in headers

    def test_uses_timeout(self):
        with patch("requests.get", return_value=_make_mock_response(FAKE_ENTRIES)) as mock_get:
            fetch_iocs()

        assert mock_get.call_args[1]["timeout"] == 120

    def test_http_error_is_propagated(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
        with patch("requests.get", return_value=mock_resp):
            with pytest.raises(requests.HTTPError):
                fetch_iocs()

    def test_connection_error_is_propagated(self):
        with patch("requests.get", side_effect=requests.ConnectionError("unreachable")):
            with pytest.raises(requests.ConnectionError):
                fetch_iocs()

    def test_timeout_error_is_propagated(self):
        with patch("requests.get", side_effect=requests.Timeout("timed out")):
            with pytest.raises(requests.Timeout):
                fetch_iocs()

    def test_empty_feed_returns_empty_data(self):
        with patch("requests.get", return_value=_make_mock_response([])):
            result = fetch_iocs()

        assert result["query_status"] == "ok"
        assert result["data"] == []
