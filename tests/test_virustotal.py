"""Tests for app/module/enrich/virustotal.py"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from module.enrich.virustotal import (
    _MAX_RELATION_ITEMS,
    _extract_behavior_summary,
    _extract_relation_files,
    _extract_stats,
    _get_api_key,
    _vt_get,
    enrich_domain,
    enrich_hash,
    enrich_ip,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_http_response(json_data: dict, status_code: int = 200) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.json.return_value = json_data
    if status_code >= 400:
        mock_resp.raise_for_status.side_effect = requests.HTTPError(
            f"{status_code} Error"
        )
    else:
        mock_resp.raise_for_status.return_value = None
    return mock_resp


def _file_entry(sha256: str, name: str, type_desc: str, malicious: int, suspicious: int) -> dict:
    return {
        "attributes": {
            "sha256": sha256,
            "meaningful_name": name,
            "type_description": type_desc,
            "last_analysis_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
            },
        }
    }


# ---------------------------------------------------------------------------
# _get_api_key
# ---------------------------------------------------------------------------


class TestGetApiKey:
    def test_explicit_key_takes_priority(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env_key")
        assert _get_api_key("explicit_key") == "explicit_key"

    def test_falls_back_to_env_var(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env_key")
        assert _get_api_key(None) == "env_key"

    def test_returns_empty_string_when_no_key(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        assert _get_api_key(None) == ""


# ---------------------------------------------------------------------------
# _vt_get
# ---------------------------------------------------------------------------


class TestVtGet:
    def test_returns_json_on_success(self):
        payload = {"data": {"id": "1.2.3.4"}}
        with patch("requests.get", return_value=_make_http_response(payload)):
            result = _vt_get("/ip_addresses/1.2.3.4", "key")
        assert result == payload

    def test_returns_none_on_http_error(self):
        with patch("requests.get", return_value=_make_http_response({}, status_code=404)):
            result = _vt_get("/ip_addresses/1.2.3.4", "key")
        assert result is None

    def test_returns_none_on_connection_error(self):
        with patch("requests.get", side_effect=requests.ConnectionError("unreachable")):
            result = _vt_get("/ip_addresses/1.2.3.4", "key")
        assert result is None

    def test_returns_none_on_timeout(self):
        with patch("requests.get", side_effect=requests.Timeout("timed out")):
            result = _vt_get("/ip_addresses/1.2.3.4", "key")
        assert result is None

    def test_returns_none_on_unexpected_exception(self):
        with patch("requests.get", side_effect=Exception("unexpected")):
            result = _vt_get("/ip_addresses/1.2.3.4", "key")
        assert result is None

    def test_sends_api_key_header(self):
        with patch("requests.get", return_value=_make_http_response({})) as mock_get:
            _vt_get("/test", "my_api_key")
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["headers"]["x-apikey"] == "my_api_key"

    def test_passes_params(self):
        with patch("requests.get", return_value=_make_http_response({})) as mock_get:
            _vt_get("/test", "key", params={"limit": 5})
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["params"] == {"limit": 5}


# ---------------------------------------------------------------------------
# _extract_stats
# ---------------------------------------------------------------------------


class TestExtractStats:
    def test_extracts_all_fields(self):
        attrs = {
            "last_analysis_stats": {
                "malicious": 10,
                "suspicious": 2,
                "harmless": 50,
                "undetected": 15,
            }
        }
        result = _extract_stats(attrs)
        assert result == {
            "malicious": 10,
            "suspicious": 2,
            "harmless": 50,
            "undetected": 15,
        }

    def test_missing_stats_returns_none_values(self):
        result = _extract_stats({})
        assert result == {
            "malicious": None,
            "suspicious": None,
            "harmless": None,
            "undetected": None,
        }

    def test_partial_stats(self):
        attrs = {"last_analysis_stats": {"malicious": 3}}
        result = _extract_stats(attrs)
        assert result["malicious"] == 3
        assert result["suspicious"] is None


# ---------------------------------------------------------------------------
# _extract_relation_files
# ---------------------------------------------------------------------------


class TestExtractRelationFiles:
    def test_extracts_file_fields(self):
        data = {
            "data": [
                _file_entry("abc123", "malware.exe", "PE32", 20, 1),
            ]
        }
        result = _extract_relation_files(data)
        assert len(result) == 1
        assert result[0]["sha256"] == "abc123"
        assert result[0]["meaningful_name"] == "malware.exe"
        assert result[0]["type_description"] == "PE32"
        assert result[0]["malicious"] == 20
        assert result[0]["suspicious"] == 1

    def test_returns_empty_list_on_none(self):
        assert _extract_relation_files(None) == []

    def test_returns_empty_list_on_empty_data(self):
        assert _extract_relation_files({"data": []}) == []

    def test_limits_to_max_items(self):
        entries = [
            _file_entry(f"sha{i}", f"file{i}.exe", "PE32", i, 0)
            for i in range(_MAX_RELATION_ITEMS + 5)
        ]
        data = {"data": entries}
        result = _extract_relation_files(data)
        assert len(result) == _MAX_RELATION_ITEMS


# ---------------------------------------------------------------------------
# _extract_behavior_summary
# ---------------------------------------------------------------------------


class TestExtractBehaviorSummary:
    def _make_sandbox(self, **attrs) -> dict:
        return {"attributes": attrs}

    def test_extracts_processes_created(self):
        sandbox = self._make_sandbox(processes_created=["cmd.exe /c whoami", "powershell.exe"])
        result = _extract_behavior_summary([sandbox])
        assert "cmd.exe /c whoami" in result["processes_created"]
        assert "powershell.exe" in result["processes_created"]

    def test_extracts_network_tcp_connections(self):
        sandbox = self._make_sandbox(
            network_tcp=[{"destination_ip": "1.2.3.4", "destination_port": 443}]
        )
        result = _extract_behavior_summary([sandbox])
        assert "1.2.3.4:443" in result["network_connections"]

    def test_extracts_network_udp_connections(self):
        sandbox = self._make_sandbox(
            network_udp=[{"destination_ip": "8.8.8.8", "destination_port": 53}]
        )
        result = _extract_behavior_summary([sandbox])
        assert "8.8.8.8:53" in result["network_connections"]

    def test_extracts_dns_lookups(self):
        sandbox = self._make_sandbox(dns_lookups=["evil.com", "tracker.net"])
        result = _extract_behavior_summary([sandbox])
        assert "evil.com" in result["dns_lookups"]
        assert "tracker.net" in result["dns_lookups"]

    def test_extracts_files_dropped(self):
        sandbox = self._make_sandbox(files_dropped=["C:\\temp\\payload.dll"])
        result = _extract_behavior_summary([sandbox])
        assert "C:\\temp\\payload.dll" in result["files_dropped"]

    def test_extracts_mutexes_created(self):
        sandbox = self._make_sandbox(mutexes_created=["Global\\MalwareMutex"])
        result = _extract_behavior_summary([sandbox])
        assert "Global\\MalwareMutex" in result["mutexes_created"]

    def test_deduplicates_across_sandboxes(self):
        sandbox1 = self._make_sandbox(processes_created=["cmd.exe"])
        sandbox2 = self._make_sandbox(processes_created=["cmd.exe", "notepad.exe"])
        result = _extract_behavior_summary([sandbox1, sandbox2])
        assert result["processes_created"].count("cmd.exe") == 1
        assert "notepad.exe" in result["processes_created"]

    def test_limits_each_category_to_max_items(self):
        processes = [f"process{i}.exe" for i in range(_MAX_RELATION_ITEMS + 5)]
        sandbox = self._make_sandbox(processes_created=processes)
        result = _extract_behavior_summary([sandbox])
        assert len(result["processes_created"]) == _MAX_RELATION_ITEMS

    def test_empty_behaviors_returns_empty_lists(self):
        result = _extract_behavior_summary([])
        assert result == {
            "processes_created": [],
            "network_connections": [],
            "dns_lookups": [],
            "files_dropped": [],
            "mutexes_created": [],
        }

    def test_missing_network_port_yields_ip_only(self):
        sandbox = self._make_sandbox(
            network_tcp=[{"destination_ip": "10.0.0.1"}]
        )
        result = _extract_behavior_summary([sandbox])
        assert "10.0.0.1" in result["network_connections"]

    def test_connection_without_ip_is_skipped(self):
        sandbox = self._make_sandbox(
            network_tcp=[{"destination_port": 80}]
        )
        result = _extract_behavior_summary([sandbox])
        assert result["network_connections"] == []


# ---------------------------------------------------------------------------
# enrich_ip
# ---------------------------------------------------------------------------

_IP_MAIN_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 5,
                "suspicious": 1,
                "harmless": 60,
                "undetected": 10,
            },
            "asn": 15169,
            "country": "US",
            "as_owner": "GOOGLE",
            "network": "8.8.8.0/24",
        }
    }
}

_COMM_FILES_RESPONSE = {
    "data": [_file_entry("sha_comm", "comm.exe", "PE32", 3, 0)]
}

_DL_FILES_RESPONSE = {
    "data": [_file_entry("sha_dl", "dl.exe", "PE32", 7, 2)]
}


class TestEnrichIp:
    def test_returns_full_structure_on_success(self):
        def mock_vt_get(path, key, params=None):
            if path.endswith("/communicating_files"):
                return _COMM_FILES_RESPONSE
            if path.endswith("/downloaded_files"):
                return _DL_FILES_RESPONSE
            return _IP_MAIN_RESPONSE

        with patch("module.enrich.virustotal._vt_get", side_effect=mock_vt_get):
            result = enrich_ip("8.8.8.8", api_key="test_key")

        assert result["ip"] == "8.8.8.8"
        assert result["stats"] == {
            "malicious": 5,
            "suspicious": 1,
            "harmless": 60,
            "undetected": 10,
        }
        assert result["asn"] == 15169
        assert result["country"] == "US"
        assert result["owner"] == "GOOGLE"
        assert result["network"] == "8.8.8.0/24"
        assert len(result["communicating_files"]) == 1
        assert result["communicating_files"][0]["sha256"] == "sha_comm"
        assert len(result["downloaded_files"]) == 1
        assert result["downloaded_files"][0]["sha256"] == "sha_dl"

    def test_returns_defaults_when_main_request_fails(self):
        with patch("module.enrich.virustotal._vt_get", return_value=None):
            result = enrich_ip("1.2.3.4", api_key="key")

        assert result["ip"] == "1.2.3.4"
        assert result["stats"] is None
        assert result["asn"] is None
        assert result["communicating_files"] == []
        assert result["downloaded_files"] == []

    def test_relation_failures_yield_empty_lists(self):
        def mock_vt_get(path, key, params=None):
            if "/ip_addresses/1.2.3.4" == path:
                return _IP_MAIN_RESPONSE
            return None

        with patch("module.enrich.virustotal._vt_get", side_effect=mock_vt_get):
            result = enrich_ip("1.2.3.4", api_key="key")

        assert result["communicating_files"] == []
        assert result["downloaded_files"] == []


# ---------------------------------------------------------------------------
# enrich_domain
# ---------------------------------------------------------------------------

_DOMAIN_MAIN_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 8,
                "suspicious": 0,
                "harmless": 55,
                "undetected": 12,
            },
            "categories": {"vendor1": "malware"},
            "creation_date": 1000000000,
            "last_update_date": 1700000000,
        }
    }
}

_RESOLUTIONS_RESPONSE = {
    "data": [
        {"attributes": {"ip_address": "93.184.216.34", "date": 1700000000}}
    ]
}

_DOMAIN_COMM_FILES_RESPONSE = {
    "data": [_file_entry("sha_dom", "dom_file.exe", "PE32", 4, 1)]
}


class TestEnrichDomain:
    def test_returns_full_structure_on_success(self):
        def mock_vt_get(path, key, params=None):
            if path.endswith("/resolutions"):
                return _RESOLUTIONS_RESPONSE
            if path.endswith("/communicating_files"):
                return _DOMAIN_COMM_FILES_RESPONSE
            return _DOMAIN_MAIN_RESPONSE

        with patch("module.enrich.virustotal._vt_get", side_effect=mock_vt_get):
            result = enrich_domain("example.com", api_key="test_key")

        assert result["domain"] == "example.com"
        assert result["stats"]["malicious"] == 8
        assert result["categories"] == {"vendor1": "malware"}
        assert result["creation_date"] == 1000000000
        assert result["last_update_date"] == 1700000000
        assert len(result["resolutions"]) == 1
        assert result["resolutions"][0]["ip_address"] == "93.184.216.34"
        assert len(result["communicating_files"]) == 1
        assert result["communicating_files"][0]["sha256"] == "sha_dom"

    def test_returns_defaults_when_main_request_fails(self):
        with patch("module.enrich.virustotal._vt_get", return_value=None):
            result = enrich_domain("example.com", api_key="key")

        assert result["domain"] == "example.com"
        assert result["stats"] is None
        assert result["categories"] == {}
        assert result["resolutions"] == []
        assert result["communicating_files"] == []

    def test_relation_failures_yield_empty_lists(self):
        def mock_vt_get(path, key, params=None):
            if path == "/domains/example.com":
                return _DOMAIN_MAIN_RESPONSE
            return None

        with patch("module.enrich.virustotal._vt_get", side_effect=mock_vt_get):
            result = enrich_domain("example.com", api_key="key")

        assert result["resolutions"] == []
        assert result["communicating_files"] == []


# ---------------------------------------------------------------------------
# enrich_hash
# ---------------------------------------------------------------------------

_HASH_MAIN_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 30,
                "suspicious": 2,
                "harmless": 0,
                "undetected": 5,
            },
            "type_description": "PE32 executable",
            "size": 204800,
            "meaningful_name": "ransomware.exe",
        }
    }
}

_CONTACTED_IPS_RESPONSE = {
    "data": [
        {
            "id": "192.168.1.1",
            "attributes": {
                "country": "RU",
                "as_owner": "SOME-AS",
                "last_analysis_stats": {"malicious": 15},
            },
        }
    ]
}

_CONTACTED_DOMAINS_RESPONSE = {
    "data": [
        {
            "id": "evil.com",
            "attributes": {
                "last_analysis_stats": {"malicious": 20},
                "categories": {"vendor1": "malware"},
            },
        }
    ]
}

_BEHAVIOR_RESPONSE = {
    "data": [
        {
            "attributes": {
                "processes_created": ["cmd.exe /c whoami"],
                "network_tcp": [{"destination_ip": "1.1.1.1", "destination_port": 80}],
                "dns_lookups": ["evil.com"],
                "files_dropped": ["C:\\Windows\\Temp\\drop.dll"],
                "mutexes_created": ["Global\\Mutex1"],
            }
        }
    ]
}


class TestEnrichHash:
    def test_returns_full_structure_on_success(self):
        def mock_vt_get(path, key, params=None):
            if path.endswith("/contacted_ips"):
                return _CONTACTED_IPS_RESPONSE
            if path.endswith("/contacted_domains"):
                return _CONTACTED_DOMAINS_RESPONSE
            if path.endswith("/behaviours"):
                return _BEHAVIOR_RESPONSE
            return _HASH_MAIN_RESPONSE

        with patch("module.enrich.virustotal._vt_get", side_effect=mock_vt_get):
            result = enrich_hash("abc123sha256", api_key="test_key")

        assert result["hash"] == "abc123sha256"
        assert result["stats"]["malicious"] == 30
        assert result["type_description"] == "PE32 executable"
        assert result["size"] == 204800
        assert result["meaningful_name"] == "ransomware.exe"

        assert len(result["contacted_ips"]) == 1
        assert result["contacted_ips"][0]["ip"] == "192.168.1.1"
        assert result["contacted_ips"][0]["country"] == "RU"
        assert result["contacted_ips"][0]["malicious"] == 15

        assert len(result["contacted_domains"]) == 1
        assert result["contacted_domains"][0]["domain"] == "evil.com"
        assert result["contacted_domains"][0]["malicious"] == 20
        assert result["contacted_domains"][0]["categories"] == {"vendor1": "malware"}

        assert result["behavior"] is not None
        assert "cmd.exe /c whoami" in result["behavior"]["processes_created"]
        assert "1.1.1.1:80" in result["behavior"]["network_connections"]
        assert "evil.com" in result["behavior"]["dns_lookups"]
        assert "C:\\Windows\\Temp\\drop.dll" in result["behavior"]["files_dropped"]
        assert "Global\\Mutex1" in result["behavior"]["mutexes_created"]

    def test_returns_defaults_when_main_request_fails(self):
        with patch("module.enrich.virustotal._vt_get", return_value=None):
            result = enrich_hash("deadbeef", api_key="key")

        assert result["hash"] == "deadbeef"
        assert result["stats"] is None
        assert result["type_description"] is None
        assert result["contacted_ips"] == []
        assert result["contacted_domains"] == []
        assert result["behavior"] is None

    def test_relation_failures_yield_empty_data(self):
        def mock_vt_get(path, key, params=None):
            if "/files/" in path and not any(
                path.endswith(s) for s in ("/contacted_ips", "/contacted_domains", "/behaviours")
            ):
                return _HASH_MAIN_RESPONSE
            return None

        with patch("module.enrich.virustotal._vt_get", side_effect=mock_vt_get):
            result = enrich_hash("abc123", api_key="key")

        assert result["contacted_ips"] == []
        assert result["contacted_domains"] == []
        assert result["behavior"] is None
