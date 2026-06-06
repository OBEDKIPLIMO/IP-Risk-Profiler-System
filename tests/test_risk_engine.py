"""
tests/test_risk_engine.py
-------------------------
Unit tests for the Risk Correlation Engine.

Tests cover all 10 boundary cases:
  1.  1  × 1   = 1.0    Low
  2.  10 × 10  = 100.0  High
  3.  7  × 7   = 49.0   Medium
  4.  4  × 8   = 32.0   Low    (boundary — just below Medium threshold of 34)
  5.  4  × 9   = 36.0   Medium (boundary — just above Low threshold of 33)
  6.  7  × 10  = 70.0   High   (boundary — just above Medium threshold of 66)
  7.  6  × 11  = 66.0   Medium (boundary — exactly at Medium/High boundary — clamped)
  8.  1  × 10  = 10.0   Low    (low asset, max threat)
  9.  10 × 1   = 10.0   Low    (max asset, min threat)
  10. Invalid inputs raise ValueError

Run with:
    pytest tests/test_risk_engine.py -v
"""

import pytest
from datetime import datetime,timezone
from engine.risk_engine import compute_risk, get_severity_label


# ===========================================================================
# ORIGINAL — TestComputeRisk (kept exactly as-is)
# ===========================================================================

class TestComputeRisk:

    # ── Test 1 ─────────────────────────────────────────────────────────
    def test_minimum_inputs_return_low(self):
        """1 × 1 = 1.0 — absolute minimum, should be Low."""
        result = compute_risk(1, 1)
        assert result["composite_score"] == 1.0
        assert result["severity_label"]  == "Low"

    # ── Test 2 ─────────────────────────────────────────────────────────
    def test_maximum_inputs_return_high(self):
        """10 × 10 = 100.0 — absolute maximum, should be High."""
        result = compute_risk(10, 10)
        assert result["composite_score"] == 100.0
        assert result["severity_label"]  == "High"

    # ── Test 3 ─────────────────────────────────────────────────────────
    def test_seven_by_seven_is_medium(self):
        """7 × 7 = 49.0 — sits in Medium range (34-66)."""
        result = compute_risk(7, 7)
        assert result["composite_score"] == 49.0
        assert result["severity_label"]  == "Medium"

    # ── Test 4 ─────────────────────────────────────────────────────────
    def test_score_32_is_low_boundary(self):
        """4 × 8 = 32.0 — just below Medium threshold of 34, should be Low."""
        result = compute_risk(4, 8)
        assert result["composite_score"] == 32.0
        assert result["severity_label"]  == "Low"

    # ── Test 5 ─────────────────────────────────────────────────────────
    def test_score_36_is_medium_boundary(self):
        """4 × 9 = 36.0 — just above Low threshold of 33, should be Medium."""
        result = compute_risk(4, 9)
        assert result["composite_score"] == 36.0
        assert result["severity_label"]  == "Medium"

    # ── Test 6 ─────────────────────────────────────────────────────────
    def test_score_70_is_high_boundary(self):
        """7 × 10 = 70.0 — above Medium threshold of 66, should be High."""
        result = compute_risk(7, 10)
        assert result["composite_score"] == 70.0
        assert result["severity_label"]  == "High"

    # ── Test 7 ─────────────────────────────────────────────────────────
    def test_score_exactly_66_is_medium(self):
        """6 × 11 — 11 is clamped to 10, so 6 × 10 = 60.0 Medium.
           Tests that out-of-range inputs are clamped not crashed."""
        result = compute_risk(6, 11)  # 11 clamped to 10 → 60.0
        assert result["composite_score"] == 60.0
        assert result["severity_label"]  == "Medium"
        assert result["threat_severity"] == 10.0  # confirm clamping

    # ── Test 8 ─────────────────────────────────────────────────────────
    def test_low_criticality_high_threat_still_low(self):
        """1 × 10 = 10.0 — even max threat can't make a score > 33 with criticality=1."""
        result = compute_risk(1, 10)
        assert result["composite_score"] == 10.0
        assert result["severity_label"]  == "Low"

    # ── Test 9 ─────────────────────────────────────────────────────────
    def test_high_criticality_low_threat_still_low(self):
        """10 × 1 = 10.0 — critical asset with clean IP stays Low."""
        result = compute_risk(10, 1)
        assert result["composite_score"] == 10.0
        assert result["severity_label"]  == "Low"

    # ── Test 10 ────────────────────────────────────────────────────────
    def test_invalid_string_input_raises_value_error(self):
        """Passing a non-numeric string should raise ValueError."""
        with pytest.raises(ValueError):
            compute_risk("not-a-number", 5)

    # ── Test 11 ────────────────────────────────────────────────────────
    def test_result_contains_all_expected_keys(self):
        """Return dict must contain all 5 required keys."""
        result = compute_risk(5, 5)
        for key in ["asset_criticality", "threat_severity",
                    "composite_score", "severity_label", "computed_at"]:
            assert key in result, f"Missing key: {key}"

    # ── Test 12 ────────────────────────────────────────────────────────
    def test_float_inputs_work_correctly(self):
        """Float inputs should be accepted and computed correctly.
           8.5 × 9.0 = 76.5 — High."""
        result = compute_risk(8.5, 9.0)
        assert result["composite_score"] == 76.5
        assert result["severity_label"]  == "High"


# ===========================================================================
# ORIGINAL — TestGetSeverityLabel (kept exactly as-is)
# ===========================================================================

class TestGetSeverityLabel:

    def test_score_1_is_low(self):
        assert get_severity_label(1) == "Low"

    def test_score_33_is_low(self):
        assert get_severity_label(33) == "Low"

    def test_score_34_is_medium(self):
        assert get_severity_label(34) == "Medium"

    def test_score_66_is_medium(self):
        assert get_severity_label(66) == "Medium"

    def test_score_67_is_high(self):
        assert get_severity_label(67) == "High"

    def test_score_100_is_high(self):
        assert get_severity_label(100) == "High"


# ===========================================================================
# NEW — TestSortAlerts
# Tests for sort_alerts(alerts) → sorted list, highest risk_score first
# ===========================================================================

class TestSortAlerts:

    def setup_method(self):
        from engine.alert_engine import sort_alerts
        self.sort_alerts = sort_alerts

    def _make_alert(self, ip, risk_score, label="Low"):
        return {
            "alert_id":          f"ALT-{ip.replace('.', '')}",
            "asset_ip":          ip,
            "asset_criticality": 5,
            "threat_severity":   5.0,
            "risk_score":        risk_score,
            "severity_label":    label,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
        }

    def test_sorted_descending(self):
        """Three alerts come back highest risk_score first."""
        alerts = [
            self._make_alert("10.0.0.1", 20),
            self._make_alert("10.0.0.2", 90),
            self._make_alert("10.0.0.3", 45),
        ]
        result = self.sort_alerts(alerts)
        scores = [a["risk_score"] for a in result]
        assert scores == sorted(scores, reverse=True)

    def test_single_alert_returned_unchanged(self):
        """A list with one alert should come back as a one-item list."""
        alerts = [self._make_alert("10.0.0.1", 50)]
        result = self.sort_alerts(alerts)
        assert len(result) == 1
        assert result[0]["risk_score"] == 50

    def test_empty_list_returns_empty_list(self):
        assert self.sort_alerts([]) == []

    def test_equal_scores_all_preserved(self):
        """Ties should all survive — no deduplication."""
        alerts = [
            self._make_alert("10.0.0.1", 50),
            self._make_alert("10.0.0.2", 50),
            self._make_alert("10.0.0.3", 50),
        ]
        result = self.sort_alerts(alerts)
        assert len(result) == 3
        assert all(a["risk_score"] == 50 for a in result)

    def test_highest_score_is_first(self):
        alerts = [
            self._make_alert("10.0.0.1", 10),
            self._make_alert("10.0.0.2", 99),
        ]
        result = self.sort_alerts(alerts)
        assert result[0]["risk_score"] == 99

    def test_lowest_score_is_last(self):
        alerts = [
            self._make_alert("10.0.0.1", 100),
            self._make_alert("10.0.0.2", 5),
            self._make_alert("10.0.0.3", 55),
        ]
        result = self.sort_alerts(alerts)
        assert result[-1]["risk_score"] == 5

    def test_returns_a_list(self):
        result = self.sort_alerts([self._make_alert("10.0.0.1", 30)])
        assert isinstance(result, list)

    def test_original_list_not_mutated(self):
        """sort_alerts must not modify the caller's list in-place."""
        alerts = [
            self._make_alert("10.0.0.1", 10),
            self._make_alert("10.0.0.2", 90),
        ]
        original_order = [a["risk_score"] for a in alerts]
        self.sort_alerts(alerts)
        assert [a["risk_score"] for a in alerts] == original_order


# ===========================================================================
# NEW — TestGenerateAlerts
# Tests for generate_alerts(assets_list, threat_scores_dict)
# ===========================================================================

class TestGenerateAlerts:

    def setup_method(self):
        from engine.alert_engine import generate_alerts
        self.generate_alerts = generate_alerts

    def _asset(self, ip, criticality):
        return {
            "ip_address":        ip,
            "hostname":          f"host-{ip.split('.')[-1]}",
            "criticality_score": criticality,
        }

    def _threats(self, *ip_score_pairs):
        """Build threat_scores_dict from (ip, score) tuples."""
        return {
            ip: {
                "ip":               ip,
                "abuseipdb_score":  score,
                "virustotal_score": score,
                "otx_score":        score,
                "composite_score":  score,
            }
            for ip, score in ip_score_pairs
        }

    def test_returns_one_alert_per_asset(self):
        assets  = [self._asset("10.0.0.1", 7), self._asset("10.0.0.2", 3)]
        threats = self._threats(("10.0.0.1", 8.0), ("10.0.0.2", 2.0))
        alerts  = self.generate_alerts(assets, threats)
        assert len(alerts) == 2

    def test_alert_has_all_required_fields(self):
        assets  = [self._asset("10.0.0.1", 5)]
        threats = self._threats(("10.0.0.1", 5.0))
        alert   = self.generate_alerts(assets, threats)[0]
        required = {
            "alert_id", "asset_ip", "asset_criticality",
            "threat_severity", "risk_score", "severity_label", "timestamp",
        }
        assert required.issubset(alert.keys()), \
            f"Missing fields: {required - set(alert.keys())}"

    def test_high_criticality_high_threat_gives_high_label(self):
        assets  = [self._asset("10.0.0.1", 9)]
        threats = self._threats(("10.0.0.1", 9.0))
        alert   = self.generate_alerts(assets, threats)[0]
        assert alert["severity_label"] == "High"
        assert alert["risk_score"] >= 67

    def test_low_criticality_low_threat_gives_low_label(self):
        assets  = [self._asset("10.0.0.1", 2)]
        threats = self._threats(("10.0.0.1", 2.0))
        alert   = self.generate_alerts(assets, threats)[0]
        assert alert["severity_label"] == "Low"

    def test_asset_with_no_threat_entry_handled_gracefully(self):
        """Asset whose IP has no entry in threat_scores_dict must not crash."""
        assets  = [self._asset("192.168.99.99", 7)]
        threats = {}
        result  = self.generate_alerts(assets, threats)
        assert isinstance(result, list)  # either skipped or given a safe default

    def test_empty_assets_returns_empty_list(self):
        assert self.generate_alerts([], {}) == []

    def test_all_alert_ids_are_unique(self):
        assets  = [self._asset(f"10.0.0.{i}", 5) for i in range(1, 6)]
        threats = self._threats(*[(f"10.0.0.{i}", 5.0) for i in range(1, 6)])
        alerts  = self.generate_alerts(assets, threats)
        ids     = [a["alert_id"] for a in alerts]
        assert len(ids) == len(set(ids)), "Duplicate alert_ids found"

    def test_timestamp_is_present_and_not_none(self):
        assets  = [self._asset("10.0.0.1", 5)]
        threats = self._threats(("10.0.0.1", 5.0))
        alert   = self.generate_alerts(assets, threats)[0]
        assert alert["timestamp"] is not None


# ===========================================================================
# NEW — TestFullSuite
# Smoke test: generate_alerts() → sort_alerts() pipeline end-to-end
# ===========================================================================

class TestFullSuite:

    def test_pipeline_produces_sorted_alerts(self):
        """
        Full run: generate_alerts() followed by sort_alerts().
        Output must be a non-empty list sorted highest risk_score first.
        """
        from engine.alert_engine import generate_alerts, sort_alerts

        assets = [
            {"ip_address": "10.0.0.1", "hostname": "server-1",      "criticality_score": 9},
            {"ip_address": "10.0.0.2", "hostname": "workstation-1",  "criticality_score": 3},
            {"ip_address": "10.0.0.3", "hostname": "printer-1",      "criticality_score": 1},
        ]
        threat_scores = {
            "10.0.0.1": {"composite_score": 8.5},
            "10.0.0.2": {"composite_score": 4.0},
            "10.0.0.3": {"composite_score": 1.5},
        }

        alerts        = generate_alerts(assets, threat_scores)
        sorted_alerts = sort_alerts(alerts)

        assert len(sorted_alerts) >= 1, "Pipeline must return at least one alert"

        scores = [a["risk_score"] for a in sorted_alerts]
        assert scores == sorted(scores, reverse=True), \
            f"Alerts not sorted high→low: {scores}"