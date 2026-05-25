"""
engine/alert_engine.py
----------------------
Alert Prioritisation Engine for the Automated IP Risk Profiler System.
"""

import uuid
from datetime import datetime, timezone
from engine.risk_engine import compute_risk


def generate_alerts(assets_list, threat_scores_dict):
    """
    Generates a prioritised list of alerts from scan + threat intel data.
    """
    if not assets_list:
        print("[ALERT ENGINE] No assets provided — nothing to generate.")
        return []

    alerts = []

    for asset in assets_list:
        ip                = asset.get("ip_address")
        asset_criticality = asset.get("criticality_score", 1)
        threat_severity   = threat_scores_dict.get(ip, 1.0)
        risk              = compute_risk(asset_criticality, threat_severity)

        alert = {
            "alert_id"         : str(uuid.uuid4()),
            "asset_ip"         : ip,
            "asset_id"         : asset.get("id"),       # may be None — handled safely below
            "hostname"         : asset.get("hostname"),
            "open_ports"       : asset.get("open_ports"),
            "asset_criticality": float(risk["asset_criticality"]),   # ✅ ensure float
            "threat_severity"  : float(risk["threat_severity"]),     # ✅ ensure float
            "risk_score"       : float(risk["composite_score"]),     # ✅ ensure float
            "severity_label"   : risk["severity_label"],
            "timestamp"        : datetime.now(timezone.utc).isoformat(),
        }
        alerts.append(alert)

    return sort_alerts(alerts)


def sort_alerts(alerts):
    return sorted(alerts, key=lambda a: a["risk_score"], reverse=True)


def save_alerts_to_db(alerts_list):
    """
    Saves alerts to the risk_alerts table with upsert logic.
    """
    from db.database import engine as db_engine
    from db.models import RiskAlert
    from sqlalchemy.orm import sessionmaker

    if not alerts_list:
        print("[DB ALERT] No alerts to save.")
        return {"inserted": 0, "updated": 0, "errors": 0}

    SessionLocal = sessionmaker(bind=db_engine)
    session      = SessionLocal()
    inserted     = 0
    updated      = 0
    errors       = 0

    try:
        for a in alerts_list:
            ip = a["asset_ip"]

            try:
                # ✅ FIX 1: Wrap the query in no_autoflush so SQLAlchemy does NOT
                # flush pending inserts before this SELECT. Without this, the first
                # INSERT is flushed mid-loop, hits a NULL constraint on asset_id/
                # threat_record_id, and poisons the entire session transaction.
                with session.no_autoflush:
                    existing = session.query(RiskAlert).filter_by(asset_ip=ip).first()

                if existing:
                    existing.asset_criticality = a["asset_criticality"]
                    existing.threat_severity   = a["threat_severity"]
                    existing.risk_score        = a["risk_score"]
                    existing.severity_label    = a["severity_label"]
                    existing.updated_at        = datetime.now(timezone.utc)
                    print(f"[DB ALERT] UPDATED  : {ip} | score={a['risk_score']} [{a['severity_label']}]")
                    updated += 1

                else:
                    # ✅ FIX: Do NOT pass alert_id — the column is an auto-increment
                    # Integer in the model, but generate_alerts() builds it as a UUID
                    # string, causing sqlite3.IntegrityError: datatype mismatch.
                    # Letting SQLite generate the integer PK automatically is correct.
                    new_alert = RiskAlert(
                        asset_ip          = a["asset_ip"],
                        asset_criticality = a["asset_criticality"],
                        threat_severity   = a["threat_severity"],
                        risk_score        = a["risk_score"],
                        severity_label    = a["severity_label"],
                        acknowledged      = False,
                    )
                    session.add(new_alert)
                    print(f"[DB ALERT] INSERTED : {ip} | score={a['risk_score']} [{a['severity_label']}]")
                    inserted += 1

            except Exception as row_error:
                # ✅ FIX 3: Rollback to a clean savepoint after a row error so the
                # session is usable again for subsequent rows instead of staying
                # poisoned and failing every subsequent insert.
                session.rollback()
                print(f"[DB ALERT ERROR] Failed for IP {ip}: {row_error}")
                errors += 1
                continue

        session.commit()
        print(f"\n[DB] Alerts saved — inserted: {inserted}, updated: {updated}, errors: {errors}")

    except Exception as e:
        session.rollback()
        print(f"[DB ALERT FATAL] Transaction failed, rolled back: {e}")

    finally:
        session.close()

    return {"inserted": inserted, "updated": updated, "errors": errors}


def print_alerts(alerts):
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

    mock_threat_scores = {
        "192.168.1.10": 9.0,
        "192.168.1.11": 7.5,
        "192.168.1.12": 6.0,
        "192.168.1.13": 5.0,
        "192.168.1.14": 3.5,
        "192.168.1.15": 2.0,
        "192.168.1.16": 1.5,
        "192.168.1.17": 1.2,
        "192.168.1.18": 1.0,
        "192.168.1.19": 8.5,
    }

    print("\n" + "="*55)
    print("  Alert Engine — Test with 10 Mock Assets")
    print("="*55)

    alerts = generate_alerts(mock_assets, mock_threat_scores)
    print_alerts(alerts)

    print(f"  Top alert   : {alerts[0]['asset_ip']} — score {alerts[0]['risk_score']} [{alerts[0]['severity_label']}]")
    print(f"  Bottom alert: {alerts[-1]['asset_ip']} — score {alerts[-1]['risk_score']} [{alerts[-1]['severity_label']}]")
    scores    = [a["risk_score"] for a in alerts]
    is_sorted = all(scores[i] >= scores[i+1] for i in range(len(scores)-1))
    print(f"  Sorted correctly: {is_sorted}")