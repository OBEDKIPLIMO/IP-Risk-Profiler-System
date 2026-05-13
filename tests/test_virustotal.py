"""
tests/test_virustotal.py
------------------------
Unit tests for the VirusTotal threat intelligence module.

Tests cover:
  1. High malicious count → HIGH severity
  2. Zero detections → LOW severity (floors to 1.0)
  3. Mixed malicious + suspicious → correct weighted calculation
  4. None response (API error) → returns None
  5. Missing analysis stats key → defaults to 1.0
  6. Successful mocked query → all keys present, severity correct
  7. 401 unauthorized → returns None
  8. 404 not found → returns default low-risk result
  9. parse_response extracts all 4 fields correctly
  10. Negative reputation adds penalty to severity score

Run with:
    pytest tests/test_virustotal.py -v
"""

import pytest
from unittest.mock import patch, MagicMock
from threat_intel.virustotal import query_ip, normalise_virustotal, parse_response


# ══════════════════════════════════════════════════════════════════════════
#  NORMALISE FUNCTION TESTS
# ══════════════════════════════════════════════════════════════════════════

class TestNormaliseVirustotal:

    # ── Test 1 ─────────────────────────────────────────────────────────
    def test_all_malicious_returns_high_severity(self):
        """
        If every engine says malicious, severity should be 10.0.
        detection_ratio = 10/10 = 1.0 → (1.0 * 9) + 1 = 10.0
        """
        response = {
            "malicious_count":  10,
            "suspicious_count": 0,
            "harmless_count":   0,
            "total_engines":    10,
            "reputation":       0,
        }
        result = normalise_virustotal(response)
        assert result == 10.0, f"Expected 10.0, got {result}"

    # ── Test 2 ─────────────────────────────────────────────────────────
    def test_zero_detections_returns_1(self):
        """
        If no engines flag the IP, severity floors to 1.0.
        detection_ratio = 0/80 = 0 → (0 * 9) + 1 = 1.0
        """
        response = {
            "malicious_count":  0,
            "suspicious_count": 0,
            "harmless_count":   80,
            "total_engines":    80,
            "reputation":       508,
        }
        result = normalise_virustotal(response)
        assert result == 1.0, f"Expected 1.0, got {result}"

    # ── Test 3 ─────────────────────────────────────────────────────────
    def test_mixed_detections_weighted_correctly(self):
        """
        Suspicious counts at half weight.
        malicious=4, suspicious=4, total=80
        adjusted = 4 + (4*0.5) = 6
        ratio = 6/80 = 0.075
        severity = (0.075 * 9) + 1 = 1.675 → 1.68
        """
        response = {
            "malicious_count":  4,
            "suspicious_count": 4,
            "harmless_count":   72,
            "total_engines":    80,
            "reputation":       0,
        }
        result = normalise_virustotal(response)
        assert result == 1.67, f"Expected 1.67, got {result}"
    # ── Test 4 ─────────────────────────────────────────────────────────
    def test_none_response_returns_none(self):
        """
        A None response (API failure) should return None, not crash.
        """
        result = normalise_virustotal(None)
        assert result is None, f"Expected None, got {result}"

    # ── Test 5 ─────────────────────────────────────────────────────────
    def test_missing_stats_key_defaults_to_1(self):
        """
        If the malicious_count key is missing (malformed response),
        return 1.0 rather than crashing.
        """
        response = {"total_engines": 80, "reputation": 0}
        result   = normalise_virustotal(response)
        assert result == 1.0, f"Expected 1.0 for missing key, got {result}"

    # ── Test 6 ─────────────────────────────────────────────────────────
    def test_negative_reputation_adds_penalty(self):
        """
        A negative reputation score should increase severity.
        Base: malicious=0/80 → 1.0
        Penalty: reputation=-100 → min(2.0, 100/50) = 2.0
        Final: 1.0 + 2.0 = 3.0
        """
        response = {
            "malicious_count":  0,
            "suspicious_count": 0,
            "harmless_count":   80,
            "total_engines":    80,
            "reputation":       -100,
        }
        result = normalise_virustotal(response)
        assert result == 3.0, f"Expected 3.0 with reputation penalty, got {result}"


# ══════════════════════════════════════════════════════════════════════════
#  QUERY FUNCTION TESTS (mocked HTTP calls)
# ══════════════════════════════════════════════════════════════════════════

class TestQueryIp:

    # ── Test 7 ─────────────────────────────────────────────────────────
    @patch('threat_intel.virustotal.requests.get')
    def test_successful_query_returns_all_keys(self, mock_get):
        """
        A valid 200 response should return a dict with all expected keys.
        """
        mock_response             = MagicMock()
        mock_response.status_code = 200
        mock_response.headers     = {"X-RateLimit-Remaining": "3"}
        mock_response.json.return_value = {
            "data": {
                "id":   "185.220.101.1",
                "type": "ip_address",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious":  15,
                        "suspicious":  2,
                        "harmless":   60,
                        "undetected": 10
                    },
                    "reputation": -25,
                }
            }
        }
        mock_get.return_value = mock_response

        result = query_ip("185.220.101.1")

        assert result is not None
        assert result["ip_address"]      == "185.220.101.1"
        assert result["malicious_count"] == 15
        assert result["suspicious_count"]== 2
        assert result["harmless_count"]  == 60
        assert result["reputation"]      == -25
        assert result["source_api"]      == "virustotal"
        assert result["severity_score"]  is not None

    # ── Test 8 ─────────────────────────────────────────────────────────
    @patch('threat_intel.virustotal.requests.get')
    def test_401_returns_none(self, mock_get):
        """
        A 401 Unauthorized response should return None cleanly.
        """
        mock_response             = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value     = mock_response

        result = query_ip("8.8.8.8")
        assert result is None

    # ── Test 9 ─────────────────────────────────────────────────────────
    @patch('threat_intel.virustotal.requests.get')
    def test_404_returns_default_low_risk(self, mock_get):
        """
        A 404 (IP not in VT database) should return a default
        low-risk result with severity_score = 1.0, not None.
        """
        mock_response             = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value     = mock_response

        result = query_ip("192.168.100.1")

        assert result is not None
        assert result["severity_score"]   == 1.0
        assert result["malicious_count"]  == 0
        assert result["source_api"]       == "virustotal"


# ══════════════════════════════════════════════════════════════════════════
#  PARSE FUNCTION TESTS
# ══════════════════════════════════════════════════════════════════════════

class TestParseResponse:

    # ── Test 10 ────────────────────────────────────────────────────────
    def test_parse_extracts_all_fields(self):
        """
        parse_response() should correctly extract malicious, suspicious,
        harmless counts and reputation from the nested JSON structure.
        """
        raw_json = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious":  5,
                        "suspicious": 1,
                        "harmless":   70,
                        "undetected": 4
                    },
                    "reputation": -10,
                }
            }
        }

        result = parse_response("45.148.10.76", raw_json)

        assert result["malicious_count"]  == 5
        assert result["suspicious_count"] == 1
        assert result["harmless_count"]   == 70
        assert result["total_engines"]    == 80
        assert result["reputation"]       == -10
        assert result["source_api"]       == "virustotal"