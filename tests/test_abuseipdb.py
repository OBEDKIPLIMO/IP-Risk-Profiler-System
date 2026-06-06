"""
tests/test_abuseipdb.py  (updated Day 30 version)
--------------------------------------------------
Complete unit tests for AbuseIPDB module.

Added edge case tests for Day 30:
  - score 0   → 1.0  (floor)
  - score 100 → 10.0 (ceiling)
  - null/None → None (API error)

Run with:
    pytest tests/test_abuseipdb.py -v
"""

import pytest
from unittest.mock import patch, MagicMock
from threat_intel.abuseipdb import query_ip, normalise_abuseipdb, parse_response


class TestNormaliseAbuseipdb:

    # ── Test 1 ─────────────────────────────────────────────────────
    def test_score_100_returns_10(self):
        """100% confidence → severity 10.0. Formula: 100/10 = 10.0"""
        result = normalise_abuseipdb({"abuse_confidence_score": 100, "total_reports": 500})
        assert result == 10.0

    # ── Test 2 ─────────────────────────────────────────────────────
    def test_score_0_floors_to_1(self):
        """
        0% confidence (clean IP / never reported) → floors to 1.0.
        Formula: 0/10 = 0.0 → floored to 1.0
        We never return 0.0 in our system.
        """
        result = normalise_abuseipdb({"abuse_confidence_score": 0, "total_reports": 0})
        assert result == 1.0

    # ── Test 3 ─────────────────────────────────────────────────────
    def test_score_50_returns_5(self):
        """50% confidence → severity 5.0. Formula: 50/10 = 5.0"""
        result = normalise_abuseipdb({"abuse_confidence_score": 50, "total_reports": 12})
        assert result == 5.0

    # ── Test 4 ─────────────────────────────────────────────────────
    def test_none_response_returns_none(self):
        """
        None response (API call completely failed) → returns None.
        Caller (aggregator) handles None gracefully.
        """
        result = normalise_abuseipdb(None)
        assert result is None

    # ── Test 5 ─────────────────────────────────────────────────────
    def test_missing_confidence_key_defaults_to_1(self):
        """
        If 'abuse_confidence_score' key is missing from response
        (malformed API response) → default to 1.0, not crash.
        """
        result = normalise_abuseipdb({"total_reports": 0})
        assert result == 1.0

    # ── Test 6 ─────────────────────────────────────────────────────
    def test_score_out_of_range_clamped(self):
        """
        A score outside 0-100 should be clamped before calculation.
        score=150 → clamped to 100 → severity 10.0
        """
        result = normalise_abuseipdb({"abuse_confidence_score": 150, "total_reports": 0})
        assert result == 10.0

    # ── Test 7 ─────────────────────────────────────────────────────
    def test_score_25_returns_2_5(self):
        """25% confidence → severity 2.5. Formula: 25/10 = 2.5"""
        result = normalise_abuseipdb({"abuse_confidence_score": 25, "total_reports": 3})
        assert result == 2.5


class TestQueryIp:

    @patch("threat_intel.abuseipdb.requests.get")
    def test_successful_query_returns_parsed_result(self, mock_get):
        """200 response → correctly parsed dict with all expected keys."""
        mock_response             = MagicMock()
        mock_response.status_code = 200
        mock_response.headers     = {"X-RateLimit-Remaining": "900"}
        mock_response.json.return_value = {
            "data": {
                "ipAddress":            "185.220.101.1",
                "abuseConfidenceScore": 100,
                "totalReports":         542,
                "countryCode":          "DE",
                "usageType":            "Data Center",
                "isWhitelisted":        False,
            }
        }
        mock_get.return_value = mock_response

        result = query_ip("185.220.101.1")

        assert result is not None
        assert result["ip_address"]             == "185.220.101.1"
        assert result["abuse_confidence_score"] == 100
        assert result["total_reports"]          == 542
        assert result["country_code"]           == "DE"
        assert result["source_api"]             == "abuseipdb"
        assert result["severity_score"]         == 10.0

    @patch("threat_intel.abuseipdb.requests.get")
    def test_401_returns_none(self, mock_get):
        """401 Unauthorized → returns None."""
        mock_response             = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value     = mock_response
        assert query_ip("8.8.8.8") is None

    @patch("threat_intel.abuseipdb.requests.get")
    def test_422_invalid_ip_returns_none(self, mock_get):
        """422 Invalid IP format → returns None."""
        mock_response             = MagicMock()
        mock_response.status_code = 422
        mock_get.return_value     = mock_response
        assert query_ip("not-an-ip") is None


class TestParseResponse:

    def test_parse_extracts_all_four_fields(self):
        """parse_response() extracts all 4 key fields correctly."""
        raw = {
            "data": {
                "ipAddress":            "194.165.16.11",
                "abuseConfidenceScore": 75,
                "totalReports":         88,
                "countryCode":          "RU",
                "usageType":            "Fixed Line ISP",
            }
        }
        result = parse_response("194.165.16.11", raw)

        assert result["abuse_confidence_score"] == 75
        assert result["total_reports"]          == 88
        assert result["country_code"]           == "RU"
        assert result["usage_type"]             == "Fixed Line ISP"
        assert result["source_api"]             == "abuseipdb"

    def test_parse_missing_fields_default_to_unknown(self):
        """Missing optional fields default to 'Unknown', not crash."""
        raw = {
            "data": {
                "ipAddress":            "1.2.3.4",
                "abuseConfidenceScore": 20,
                "totalReports":         3,
            }
        }
        result = parse_response("1.2.3.4", raw)
        assert result["country_code"] == "Unknown"
        assert result["usage_type"]   == "Unknown"