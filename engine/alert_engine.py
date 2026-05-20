"""
engine/alert_engine.py
----------------------
Alert Prioritisation Logic for the Automated IP Risk Profiler System.
"""

import uuid
from datetime import datetime, timezone
# Import your validated risk math from Day 15
from engine.risk_engine import compute_risk

# ── Function 2 & 3: Generate Alerts ──────────────────────────────────────
def generate_alerts(assets_list, threat_scores_dict):
    """
    Takes discovered network assets and calculated external threat scores,
    correlates them, and builds structured Alert records.
    """
    raw_alerts = []
    
    for asset in assets_list:
        ip = asset.get("ip_address")
        asset_criticality = asset.get("criticality_score", 1.0)
        
        # Look up external threat score, defaulting to a clean 1.0 if not found
        threat_severity = threat_scores_dict.get(ip, 1.0)
        
        # Calculate risk matrix using our core engine math
        risk_calculation = compute_risk(asset_criticality, threat_severity)
        
        # ── Task 4: Create Alert Object Structure ──
        alert_object = {
            "alert_id":          f"ALERT-{str(uuid.uuid4())[:8].upper()}", # Short unique ID
            "asset_ip":          ip,
            "asset_criticality": risk_calculation["asset_criticality"],
            "threat_severity":   risk_calculation["threat_severity"],
            "risk_score":        risk_calculation["composite_score"],
            "severity_label":    risk_calculation["severity_label"],
            "timestamp":         risk_calculation["computed_at"]
        }
        raw_alerts.append(alert_object)
        
    # ── Task 5: Sort Alerts prior to output ──
    return sort_alerts(raw_alerts)


# ── Function 5: Sort Alerts descending ───────────────────────────────────
def sort_alerts(alerts):
    """
    Sorts alerts by risk_score descending (highest risk first / critical priority).
    """
    return sorted(alerts, key=lambda x: x["risk_score"], reverse=True)

# ── Task 6: Testing Execution Matrix ──────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*70)
    print("  Alert Prioritisation Engine — 10 Host Mock Test")
    print("="*70)
    
    # 10 Mock Assets with realistic criticality scores based on open ports
    mock_assets = [
        {"ip_address": "10.0.0.1",   "criticality_score": 10.0}, # Primary Active Directory
        {"ip_address": "10.0.0.2",   "criticality_score": 9.0},  # Linux DB Production Server
        {"ip_address": "10.0.0.3",   "criticality_score": 4.0},  # HR Workstation
        {"ip_address": "10.0.0.4",   "criticality_score": 2.0},  # Library Network Printer
        {"ip_address": "10.0.0.5",   "criticality_score": 8.0},  # Edge Firewall Router
        {"ip_address": "10.0.0.6",   "criticality_score": 5.0},  # Staff Wi-Fi Gateway
        {"ip_address": "10.0.0.7",   "criticality_score": 9.0},  # Web Payment Portal
        {"ip_address": "10.0.0.8",   "criticality_score": 3.0},  # Guest IoT Thermostat
        {"ip_address": "10.0.0.9",   "criticality_score": 6.0},  # Backup Storage NAS
        {"ip_address": "10.0.0.10",  "criticality_score": 1.0},  # Dummy Unused Test Machine
    ]
    
    # 10 Corresponding Mock Threat Intelligence severity levels from API aggregator
    mock_threats = {
        "10.0.0.1":  1.0,  # Clean API reports
        "10.0.0.2":  8.5,  # HIGH threat: listed as an active malware sender
        "10.0.0.3":  4.0,  # Medium threat: historical scans flagged
        "10.0.0.4":  1.0,  # Completely clean
        "10.0.0.5":  9.8,  # CRITICAL threat: globally targeted brute-forcer
        "10.0.0.6":  2.5,  # Low historical reports
        "10.0.0.7":  7.0,  # High threat: communication with TOR entry nodes
        "10.0.0.8":  9.0,  # High threat: IP scanning internet infrastructure
        "10.0.0.9":  2.0,  # Relatively stable
        "10.0.0.10": 1.0,  # Completely clean
    }

    # Run prioritisation routine
    prioritised_alerts = generate_alerts(mock_assets, mock_threats)
    
    # Print clean terminal dashboard layout
    print(f"  {'ALERT ID':<15} {'TARGET IP':<14} {'CRIT':<6} {'THREAT':<8} {'RISK SCORE':<12} {'PRIORITY':<8}")
    print("  " + "-"*65)
    
    for alert in prioritised_alerts:
        marker = "🚨 HIGH" if alert["severity_label"] == "High" else ("⚠️ MED" if alert["severity_label"] == "Medium" else "✅ LOW")
        print(f"  {alert['alert_id']:<15} {alert['asset_ip']:<14} {alert['asset_criticality']:<6.1f} {alert['threat_severity']:<8.1f} {alert['risk_score']:<12.2f} {marker:<8}")
        
    print("="*70 + "\n")