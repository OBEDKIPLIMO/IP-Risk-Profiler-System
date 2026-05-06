"""
tests/test_abuseipdb.py
-----------------------
Unit tests for the AbuseIPDB threat intelligence module.

Tests cover:
  1. Normal high-confidence malicious IP
  2. Clean IP (score = 0) → floors to 1.0
  3. Medium confidence IP
  4. None response (API error) → returns None
  5. Missing confidence score key → defaults to 1.0

Run with:
    pytest tests/test_abuseipdb.py -v
"""

import pytest
from unittest.mock import patch, MagicMock
from threat_intel.abuseipdb import query_ip, normalise_abuseipdb, parse_response


# ══════════════════════════════════════════════════════════════════════════
#  NORMALISE FUNCTION TESTS (no API calls needed — pure logic tests)
# ══════════════════════════════════════════════════════════════════════════

class TestNormaliseAbuseipdb:
    """
    Tests for normalise_abuseipdb(response).
    These tests do NOT call the real API — they test the maths and edge cases.
    """

    # ── Test 1 ────────────────────────────────────────────────────────────
    def test_high_confidence_score_returns_high_severity(self):
        """
        A 100% confidence score should return severity 10.0.
        Formula: 100 / 10 = 10.0
        """
        mock_response = {
            "ip_address":             "185.220.101.1",
            "abuse_confidence_score": 100,
            "total_reports":          542,
            "country_code":           "DE",
            "usage_type":             "Data Center"
        }

        result = normalise_abuseipdb(mock_response)

        assert result == 10.0, f"Expected 10.0, got {result}"

    # ── Test 2 ────────────────────────────────────────────────────────────
    def test_zero_confidence_floors_to_1(self):
        """
        A 0% confidence score (clean IP / never reported) should return 1.0.
        We never return 0.0 — floor is 1.0 (unknown risk is not zero risk).
        Formula: 0 / 10 = 0.0 → floored to 1.0
        """
        mock_response = {
            "ip_address":             "8.8.8.8",
            "abuse_confidence_score": 0,
            "total_reports":          0,
            "country_code":           "US",
            "usage_type":             "Content Delivery Network"
        }

        result = normalise_abuseipdb(mock_response)

        assert result == 1.0, f"Expected 1.0 (floor), got {result}"

    # ── Test 3 ────────────────────────────────────────────────────────────
    def test_medium_confidence_returns_correct_score(self):
        """
        A 50% confidence score should return severity 5.0.
        Formula: 50 / 10 = 5.0
        """
        mock_response = {
            "ip_address":             "45.148.10.76",
            "abuse_confidence_score": 50,
            "total_reports":          12,
            "country_code":           "NL",
            "usage_type":             "Data Center"
        }

        result = normalise_abuseipdb(mock_response)

        assert result == 5.0, f"Expected 5.0, got {result}"

    # ── Test 4 ────────────────────────────────────────────────────────────
    def test_none_response_returns_none(self):
        """
        If the API call completely failed and returned None,
        normalise_abuseipdb should return None (not crash).
        The caller (aggregator) will handle None gracefully.
        """
        result = normalise_abuseipdb(None)

        assert result is None, f"Expected None for failed API response, got {result}"

    # ── Test 5 ────────────────────────────────────────────────────────────
    def test_missing_confidence_key_defaults_to_1(self):
        """
        If the response dict is missing the 'abuse_confidence_score' key
        (malformed API response), we default to 1.0 rather than crashing.
        """
        mock_response = {
            "ip_address":   "1.2.3.4",
            "total_reports": 0,
            # abuse_confidence_score is intentionally missing
        }

        result = normalise_abuseipdb(mock_response)

        assert result == 1.0, f"Expected 1.0 for missing key, got {result}"


# ══════════════════════════════════════════════════════════════════════════
#  QUERY FUNCTION TESTS (mock the HTTP request — no real API calls)
# ══════════════════════════════════════════════════════════════════════════

class TestQueryIp:
    """
    Tests for query_ip(ip_address).

    We use unittest.mock.patch to intercept the requests.get() call
    so these tests work without internet and without using API quota.

    How mocking works:
      @patch('threat_intel.abuseipdb.requests.get')
      ↑ This replaces requests.get with a fake object for the duration of the test.
      The fake object (mock_get) returns whatever we configure it to return.
    """

    # ── Test 6 ────────────────────────────────────────────────────────────
    @patch('threat_intel.abuseipdb.requests.get')
    def test_successful_query_returns_parsed_result(self, mock_get):
        """
        When the API returns a valid 200 response,
        query_ip() should return a properly parsed dict with all expected keys.
        """
        # Configure the mock to return a realistic AbuseIPDB response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers     = {"X-RateLimit-Remaining": "900"}
        mock_response.json.return_value = {
            "data": {
                "ipAddress":            "185.220.101.1",
                "abuseConfidenceScore": 100,
                "totalReports":         542,
                "countryCode":          "DE",
                "usageType":            "Data Center/Web Hosting/Transit",
                "isp":                  "Frantech Solutions",
                "isWhitelisted":        False,
            }
        }
        mock_get.return_value = mock_response

        result = query_ip("185.220.101.1")

        # Confirm result is not None
        assert result is not None

        # Confirm all expected keys are present
        assert result["ip_address"]             == "185.220.101.1"
        assert result["abuse_confidence_score"] == 100
        assert result["total_reports"]          == 542
        assert result["country_code"]           == "DE"
        assert result["source_api"]             == "abuseipdb"

        # Confirm severity score was normalised correctly: 100 / 10 = 10.0
        assert result["severity_score"]         == 10.0

    # ── Test 7 ────────────────────────────────────────────────────────────
    @patch('threat_intel.abuseipdb.requests.get')
    def test_401_unauthorized_returns_none(self, mock_get):
        """
        A 401 response (bad API key) should return None without crashing.
        """
        mock_response         = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        result = query_ip("8.8.8.8")

        assert result is None, "Expected None for 401 Unauthorized"

    # ── Test 8 ────────────────────────────────────────────────────────────
    @patch('threat_intel.abuseipdb.requests.get')
    def test_422_invalid_ip_returns_none(self, mock_get):
        """
        A 422 response (invalid IP format) should return None without crashing.
        """
        mock_response             = MagicMock()
        mock_response.status_code = 422
        mock_get.return_value     = mock_response

        result = query_ip("not-an-ip-address")

        assert result is None, "Expected None for 422 Invalid IP"


# ══════════════════════════════════════════════════════════════════════════
#  PARSE FUNCTION TESTS
# ══════════════════════════════════════════════════════════════════════════

class TestParseResponse:
    """
    Tests for parse_response() — the function that extracts fields
    from the raw AbuseIPDB JSON and builds our internal dict.
    """

    # ── Test 9 ────────────────────────────────────────────────────────────
    def test_parse_extracts_all_fields_correctly(self):
        """
        parse_response() should correctly extract all 4 key fields:
        abuseConfidenceScore, totalReports, countryCode, usageType
        """
        raw_json = {
            "data": {
                "ipAddress":            "194.165.16.11",
                "abuseConfidenceScore": 75,
                "totalReports":         88,
                "countryCode":          "RU",
                "usageType":            "Fixed Line ISP",
                "isp":                  "Some ISP",
            }
        }

        result = parse_response("194.165.16.11", raw_json)

        assert result["abuse_confidence_score"] == 75
        assert result["total_reports"]          == 88
        assert result["country_code"]           == "RU"
        assert result["usage_type"]             == "Fixed Line ISP"
        assert result["source_api"]             == "abuseipdb"

    # ── Test 10 ───────────────────────────────────────────────────────────
    def test_parse_handles_missing_optional_fields(self):
        """
        parse_response() should not crash if optional fields like
        usageType or countryCode are missing from the API response.
        They should default to 'Unknown'.
        """
        raw_json = {
            "data": {
                "ipAddress":            "1.2.3.4",
                "abuseConfidenceScore": 20,
                "totalReports":         3,
                # countryCode and usageType intentionally missing
            }
        }

        result = parse_response("1.2.3.4", raw_json)

        # Should not crash — missing fields default to "Unknown"
        assert result["country_code"] == "Unknown"
        assert result["usage_type"]   == "Unknown"
        assert result["severity_score"] is not None