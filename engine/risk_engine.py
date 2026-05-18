"""
engine/risk_engine.py
---------------------
Risk Correlation Engine for the Automated IP Risk Profiler System.
"""

from datetime import datetime, timezone

# ── Severity Thresholds ───────────────────────────────────────────────────
THRESHOLD_LOW_MAX    = 33   # 1–33   → Low
THRESHOLD_MEDIUM_MAX = 66   # 34–66  → Medium
                            # 67–100 → High

# ── Core Function: compute_risk ───────────────────────────────────────────
def compute_risk(asset_criticality, threat_severity):
    try:
        asset_criticality = float(asset_criticality)
        threat_severity   = float(threat_severity)
    except (TypeError, ValueError):
        raise ValueError(
            f"[RISK ENGINE] Both inputs must be numbers. "
            f"Got: asset_criticality={asset_criticality!r}, "
            f"threat_severity={threat_severity!r}"
        )

    # Clamp both inputs to valid 1–10 range
    asset_criticality = max(1.0, min(10.0, asset_criticality))
    threat_severity   = max(1.0, min(10.0, threat_severity))

    # Apply core formula: Criticality x Severity
    composite_score = round(asset_criticality * threat_severity, 2)

    # Assign severity label
    severity_label = get_severity_label(composite_score)

    return {
        "asset_criticality" : asset_criticality,
        "threat_severity"   : threat_severity,
        "composite_score"   : composite_score,
        "severity_label"    : severity_label,
        "computed_at"       : datetime.now(timezone.utc).isoformat(),
    }

# ── Helper: Severity Label ────────────────────────────────────────────────
def get_severity_label(composite_score):
    if composite_score <= THRESHOLD_LOW_MAX:
        return "Low"
    elif composite_score <= THRESHOLD_MEDIUM_MAX:
        return "Medium"
    else:
        return "High"

# ── Batch Function: compute_risk_for_all ─────────────────────────────────
def compute_risk_for_all(assets, threat_scores):
    results = []
    for asset in assets:
        ip                = asset.get("ip_address")
        asset_criticality = asset.get("criticality_score", 1)
        threat_severity = threat_scores.get(ip, 1.0)

        risk = compute_risk(asset_criticality, threat_severity)
        risk["ip_address"] = ip
        results.append(risk)

    # Sort by composite_score descending (highest risk first)
    results.sort(key=lambda r: r["composite_score"], reverse=True)
    return results

# ── Print Helper ──────────────────────────────────────────────────────────
def print_risk_results(results):
    if not results:
        print("[RISK ENGINE] No results to display.")
        return

    print("\n" + "="*65)
    print(f"  RISK CORRELATION RESULTS — {len(results)} asset(s)")
    print("="*65)
    print(f"  {'IP':<18} {'Criticality':>12} {'Threat':>8} {'Score':>8} {'Label':>8}")
    print("  " + "-"*60)

    for r in results:
        ip    = r.get("ip_address", "N/A")
        crit  = r["asset_criticality"]
        threat= r["threat_severity"]
        score = r["composite_score"]
        label = r["severity_label"]
        marker = "⚠" if label == "High" else ("~" if label == "Medium" else "✓")
        print(f"  {ip:<18} {crit:>12.1f} {threat:>8.1f} {score:>8.1f} {label:>6} {marker}")
    print("="*65 + "\n")

# ── Run directly to test ──────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*55)
    print("  Risk Correlation Engine — Quick Test")
    print("="*55)

    test_cases = [
        (1,  1,  "Minimum possible — should be Low"),
        (10, 10, "Maximum possible — should be High"),
        (7,  7,  "Middle case — should be Medium (49)"),
        (9,  8,  "High criticality server + high threat — should be High"),
        (10, 1,  "Critical asset but clean IP — should be Low"),
    ]

    for criticality, severity, description in test_cases:
        result = compute_risk(criticality, severity)
        print(f"\n  {description}")
        print(f"  {criticality} × {severity} = {result['composite_score']} [{result['severity_label']}]")

    print("\n" + "="*55)
    print("  Batch Test — compute_risk_for_all()")
    print("="*55)

    sample_assets = [
        {"ip_address": "192.168.1.10", "criticality_score": 9},
        {"ip_address": "192.168.1.25", "criticality_score": 5},
        {"ip_address": "192.168.1.50", "criticality_score": 2},
    ]
    sample_threats = {
        "192.168.1.10": 8.5,
        "192.168.1.25": 4.0,
        "192.168.1.50": 1.5,
    }

    batch_results = compute_risk_for_all(sample_assets, sample_threats)
    print_risk_results(batch_results)