"""
tests/test_alienvault.py
------------------------
Unit tests for the AlienVault OTX threat intelligence module.

Tests cover:
  1.  normalise_alienvault() — 0 pulses → 1.0
  2.  normalise_alienvault() — 1-2 pulses → 2.0
  3.  normalise_alienvault() — 3-5 pulses → 4.0
  4.  normalise_alienvault() — 6-10 pulses → 6.0
  5.  normalise_alienvault() — 11-20 pulses → 8.0
  6.  normalise_alienvault() — 21+ pulses → 9.5
  7.  normalise_alienvault() — malware families add 0.5 bonus
  8.  normalise_alienvault() — dangerous tags add bonus
  9.  normalise_alienvault() — None response → returns None
  10. normalise_alienvault() — missing pulse_count key → 1.0
  11. query_ip() — successful 200 response → all keys present
  12. query_ip() — 401 Unauthorized → returns None
  13. query_ip() — 404 not found → returns default low-risk result
  14. parse_response() — extracts pulse_count and country correctly
  15. parse_response() — missing pulse_info → defaults to 0

Run with:
    pytest tests/test_alienvault.py -v
"""

import pytest
from unittest.mock import patch, MagicMock
from threat_intel.alienvault import (
    query_ip,
    normalise_alienvault,
    parse_response,
)


# ════════════════════════════════════════════════════════════════════
#  normalise_alienvault() TESTS
# ════════════════════════════════════════════════════════════════════
class TestNormaliseAlienvault:

    # ── Test 1 ─────────────────────────────────────────────────────
    def test_zero_pulses_returns_1(self):
        """0 pulses = never reported → severity 1.0 (floor)."""
        result = normalise_alienvault({"pulse_count": 0, "tags": [], "malware_families": []})
        assert result == 1.0

    # ── Test 2 ─────────────────────────────────────────────────────
    def test_one_pulse_returns_2(self):
        """1 pulse = mentioned once → base score 2.0."""
        result = normalise_alienvault({"pulse_count": 1, "tags": [], "malware_families": []})
        assert result == 2.0

    # ── Test 3 ─────────────────────────────────────────────────────
    def test_five_pulses_returns_4(self):
        """5 pulses = moderate threat → base score 4.0."""
        result = normalise_alienvault({"pulse_count": 5, "tags": [], "malware_families": []})
        assert result == 4.0

    # ── Test 4 ─────────────────────────────────────────────────────
    def test_ten_pulses_returns_6(self):
        """10 pulses = well documented → base score 6.0."""
        result = normalise_alienvault({"pulse_count": 10, "tags": [], "malware_families": []})
        assert result == 6.0

    # ── Test 5 ─────────────────────────────────────────────────────
    def test_fifteen_pulses_returns_8(self):
        """15 pulses = high confidence → base score 8.0."""
        result = normalise_alienvault({"pulse_count": 15, "tags": [], "malware_families": []})
        assert result == 8.0

    # ── Test 6 ─────────────────────────────────────────────────────
    def test_twentyfive_pulses_returns_9_5(self):
        """25 pulses = very widely reported → base score 9.5."""
        result = normalise_alienvault({"pulse_count": 25, "tags": [], "malware_families": []})
        assert result == 9.5

    # ── Test 7 ─────────────────────────────────────────────────────
    def test_malware_families_add_bonus(self):
        """
        If malware families are present, add 0.5 bonus.
        5 pulses = 4.0 base + 0.5 malware bonus = 4.5
        """
        result = normalise_alienvault({
            "pulse_count":      5,
            "tags":             [],
            "malware_families": ["Mirai", "Emotet"],
        })
        assert result == 4.5

    # ── Test 8 ─────────────────────────────────────────────────────
    def test_dangerous_tags_add_bonus(self):
        """
        Dangerous tags (botnet, malware) each add 0.3 bonus (max 1.5).
        5 pulses = 4.0 base + 0.3 (botnet) + 0.3 (malware) = 4.6
        """
        result = normalise_alienvault({
            "pulse_count":      5,
            "tags":             ["botnet", "malware"],
            "malware_families": [],
        })
        assert result == pytest.approx(4.6, abs=0.01)

    # ── Test 9 ─────────────────────────────────────────────────────
    def test_none_response_returns_none(self):
        """None response (API failure) → returns None, not crash."""
        result = normalise_alienvault(None)
        assert result is None

    # ── Test 10 ────────────────────────────────────────────────────
    def test_missing_pulse_count_defaults_to_1(self):
        """Missing pulse_count key → default 1.0 (not a crash)."""
        result = normalise_alienvault({"tags": [], "malware_families": []})
        assert result == 1.0


# ════════════════════════════════════════════════════════════════════
#  query_ip() TESTS (mocked HTTP)
# ════════════════════════════════════════════════════════════════════
class TestQueryIp:

    # ── Test 11 ────────────────────────────────────────────────────
    @patch("threat_intel.alienvault.requests.get")
    def test_successful_query_returns_all_keys(self, mock_get):
        """
        A valid 200 response should return a dict with all expected keys:
        ip_address, pulse_count, tags, country, severity_score, source_api
        """
        mock_response             = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "indicator":   "185.220.101.1",
            "pulse_info":  {"count": 42, "pulses": []},
            "tags":        ["tor", "exit-node"],
            "country_code": "DE",
            "reputation":  0,
        }
        mock_get.return_value = mock_response

        result = query_ip("185.220.101.1")

        assert result is not None
        assert result["ip_address"]    == "185.220.101.1"
        assert result["pulse_count"]   == 42
        assert result["country"]       == "DE"
        assert result["source_api"]    == "otx"
        assert result["severity_score"] is not None
        assert "tor" in result["tags"]

    # ── Test 12 ────────────────────────────────────────────────────
    @patch("threat_intel.alienvault.requests.get")
    def test_401_returns_none(self, mock_get):
        """401 Unauthorized (bad API key) → returns None cleanly."""
        mock_response             = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value     = mock_response

        result = query_ip("8.8.8.8")
        assert result is None

    # ── Test 13 ────────────────────────────────────────────────────
    @patch("threat_intel.alienvault.requests.get")
    def test_404_returns_default_low_risk(self, mock_get):
        """
        404 (IP not in OTX) → returns default low-risk result
        with severity_score=1.0, not None.
        """
        mock_response             = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value     = mock_response

        result = query_ip("192.168.100.1")
        assert result is not None
        assert result["severity_score"] == 1.0
        assert result["pulse_count"]    == 0
        assert result["source_api"]     == "otx"


# ════════════════════════════════════════════════════════════════════
#  parse_response() TESTS
# ════════════════════════════════════════════════════════════════════
class TestParseResponse:

    # ── Test 14 ────────────────────────────────────────────────────
    def test_parse_extracts_pulse_count_and_country(self):
        """
        parse_response() must correctly extract pulse_count
        from pulse_info.count and country from country_code.
        """
        raw_json = {
            "indicator":    "45.148.10.76",
            "pulse_info":   {"count": 15, "pulses": []},
            "tags":         ["scanner", "bruteforce"],
            "country_code": "NL",
            "reputation":   0,
        }

        result = parse_response("45.148.10.76", raw_json)

        assert result["pulse_count"] == 15
        assert result["country"]     == "NL"
        assert "scanner" in result["tags"]
        assert result["source_api"]  == "otx"

    # ── Test 15 ────────────────────────────────────────────────────
    def test_parse_handles_missing_pulse_info(self):
        """
        If pulse_info is missing from the response (malformed),
        pulse_count should default to 0, not crash.
        """
        raw_json = {
            "indicator":    "1.2.3.4",
            "country_code": "US",
            # pulse_info intentionally missing
        }

        result = parse_response("1.2.3.4", raw_json)

        assert result["pulse_count"] == 0
        assert result["country"]     == "US"