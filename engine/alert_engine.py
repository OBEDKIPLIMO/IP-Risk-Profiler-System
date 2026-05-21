"""
engine/alert_engine.py
----------------------
Alert Prioritisation Engine for the Automated IP Risk Profiler System.

Responsibilities:
  1. Take scanner assets + aggregated threat scores
  2. Call the Risk Engine to compute composite risk per asset
  3. Build structured Alert objects
  4. Sort alerts by risk_score descending (highest risk first)
  5. Return the prioritised alert list ready for DB persistence
"""

import uuid
from datetime import datetime, timezone
from engine.risk_engine import compute_risk


def generate_alerts(assets_list, threat_scores_dict):
    """
    Generates a prioritised list of alerts from scan + threat intel data.

    Steps:
      1. Loop through every discovered asset
      2. Look up its composite threat score from threat_scores_dict
      3. Call compute_risk(criticality, severity) to get risk score + label
      4. Build a full Alert dict for each asset
      5. Sort all alerts by risk_score descending

    Args:
        assets_list (list of dict): discovered assets from scanner.
            Each dict needs at minimum:
              { "ip_address": str, "criticality_score": int }
            Optionally also: hostname, open_ports, os_type, asset_id

        threat_scores_dict (dict): maps ip_address → composite threat score (float)
            From aggregator.get_composite_threat_score()
            Example: { "192.168.1.10": 8.5, "192.168.1.25": 3.2 }

    Returns:
        list of dict: sorted alert objects, highest risk first.
            Each alert dict:
            {
              "alert_id"         : str (UUID),
              "asset_ip"         : str,
              "asset_id"         : int or None,
              "hostname"         : str or None,
              "open_ports"       : str or None,
              "asset_criticality": float,
              "threat_severity"  : float,
              "risk_score"       : float,
              "severity_label"   : str,
              "timestamp"        : str (ISO),
            }
    """
    if not assets_list:
        print("[ALERT ENGINE] No assets provided — nothing to generate.")
        return []

    alerts = []

    for asset in assets_list:
        ip                = asset.get("ip_address")
        asset_criticality = asset.get("criticality_score", 1)

        # Look up threat score — default 1.0 if IP was never queried
        threat_severity = threat_scores_dict.get(ip, 1.0)

        # Compute risk using the Risk Engine formula
        risk = compute_risk(asset_criticality, threat_severity)

        alert = {
            "alert_id"         : str(uuid.uuid4()),   # unique ID for this alert
            "asset_ip"         : ip,
            "asset_id"         : asset.get("id"),      # DB primary key if available
            "hostname"         : asset.get("hostname"),
            "open_ports"       : asset.get("open_ports"),
            "asset_criticality": risk["asset_criticality"],
            "threat_severity"  : risk["threat_severity"],
            "risk_score"       : risk["composite_score"],
            "severity_label"   : risk["severity_label"],
            "timestamp"        : datetime.now(timezone.utc).isoformat(),
        }
        alerts.append(alert)

    # Sort highest risk first
    return sort_alerts(alerts)


def sort_alerts(alerts):
    """
    Sorts a list of alert dicts by risk_score descending.
    Highest risk score appears first — operators see the most
    critical alerts at the top of the dashboard.

    Args:
        alerts (list of dict): alert dicts with a 'risk_score' key

    Returns:
        list of dict: same list, sorted descending by risk_score
    """
    return sorted(alerts, key=lambda a: a["risk_score"], reverse=True)


def print_alerts(alerts):
    """Prints a formatted alert table to the terminal."""
    if not alerts:
        print("[ALERT ENGINE] No alerts to display.")
        return

    print("\n" + "="*72)
    print(f"  PRIORITISED ALERTS — {len(alerts)} alert(s)  [sorted highest risk first]")
    print("="*72)
    print(f"  {'#':<4} {'IP':<18} {'Host':<18} {'Crit':>5} {'Threat':>7} {'Score':>7} {'Label':>8}")
    print("  " + "-"*68)

    for i, a in enumerate(alerts, 1):
        marker = {"High": "⚠", "Medium": "~", "Low": "✓"}.get(a["severity_label"], "")
        host   = (a.get("hostname") or "Unknown")[:16]
        print(f"  {i:<4} {a['asset_ip']:<18} {host:<18} "
              f"{a['asset_criticality']:>5.1f} {a['threat_severity']:>7.1f} "
              f"{a['risk_score']:>7.1f} {a['severity_label']:>6} {marker}")

    print("="*72 + "\n")


# ── Run directly to test ──────────────────────────────────────────────────
if __name__ == "__main__":

    # 10 mock assets with varied criticality scores
    mock_assets = [
        {"ip_address": "192.168.1.10", "criticality_score": 9,  "hostname": "DB-SERVER-01"},
        {"ip_address": "192.168.1.11", "criticality_score": 8,  "hostname": "WEB-SERVER-01"},
        {"ip_address": "192.168.1.12", "criticality_score": 7,  "hostname": "FILE-SERVER-01"},
        {"ip_address": "192.168.1.13", "criticality_score": 6,  "hostname": "STAFF-PC-01"},
        {"ip_address": "192.168.1.14", "criticality_score": 5,  "hostname": "STAFF-PC-02"},
        {"ip_address": "192.168.1.15", "criticality_score": 4,  "hostname": "STAFF-PC-03"},
        {"ip_address": "192.168.1.16", "criticality_score": 3,  "hostname": "PRINTER-01"},
        {"ip_address": "192.168.1.17", "criticality_score": 2,  "hostname": "CCTV-CAM-01"},
        {"ip_address": "192.168.1.18", "criticality_score": 1,  "hostname": "IOT-SENSOR-01"},
        {"ip_address": "192.168.1.19", "criticality_score": 10, "hostname": "DOMAIN-CTRL"},
    ]

    # 10 mock threat scores (simulating aggregator output)
    mock_threat_scores = {
        "192.168.1.10": 9.0,   # very high threat
        "192.168.1.11": 7.5,   # high threat
        "192.168.1.12": 6.0,   # medium-high threat
        "192.168.1.13": 5.0,   # medium threat
        "192.168.1.14": 3.5,   # low-medium threat
        "192.168.1.15": 2.0,   # low threat
        "192.168.1.16": 1.5,   # very low threat
        "192.168.1.17": 1.2,   # minimal threat
        "192.168.1.18": 1.0,   # clean
        "192.168.1.19": 8.5,   # critical asset + high threat = top alert
    }

    print("\n" + "="*55)
    print("  Alert Engine — Test with 10 Mock Assets")
    print("="*55)

    alerts = generate_alerts(mock_assets, mock_threat_scores)
    print_alerts(alerts)

    print(f"  Top alert   : {alerts[0]['asset_ip']} — score {alerts[0]['risk_score']} [{alerts[0]['severity_label']}]")
    print(f"  Bottom alert: {alerts[-1]['asset_ip']} — score {alerts[-1]['risk_score']} [{alerts[-1]['severity_label']}]")
    print(f"\n  Confirm sort: each score ≤ previous score")
    scores = [a["risk_score"] for a in alerts]
    is_sorted = all(scores[i] >= scores[i+1] for i in range(len(scores)-1))
    print(f"  Sorted correctly: {is_sorted}")