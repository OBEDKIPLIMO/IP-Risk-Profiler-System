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
from engine.risk_engine import compute_risk, get_severity_label


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