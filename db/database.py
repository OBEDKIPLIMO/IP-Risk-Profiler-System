"""
db/database.py
--------------
Database setup, session management, and persistence functions.

Functions:
  init_db()              : creates all tables if they don't exist
  get_session()          : returns a new SQLAlchemy session
  save_alerts_to_db()    : upserts a list of RiskAlert dicts to the DB
  get_all_alerts()       : returns all alerts sorted by risk_score desc
  get_alerts_by_severity(): filters alerts by Low / Medium / High
  acknowledge_alert()    : marks one alert as acknowledged
"""

import json
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.models import Base, Asset, ThreatRecord, RiskAlert

# ── Engine + Session ──────────────────────────────────────────────────────
DATABASE_URL = "sqlite:///dev.db"
engine       = create_engine(
    DATABASE_URL,
    echo=False,   # set True to see raw SQL in terminal during debugging
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_session():
    """Returns a new DB session. Always close it when done."""
    return SessionLocal()


def init_db():
    """Creates all tables defined in models.py if they don't exist yet."""
    print("[DB] Initialising database...")
    Base.metadata.create_all(bind=engine)
    print("[DB] Tables ready: assets, threat_records, risk_scores, risk_alerts")


# ── Save Alerts (Upsert) ──────────────────────────────────────────────────
def save_alerts_to_db(alerts_list):
    """
    Saves a list of alert dicts to the risk_alerts table.

    UPSERT logic:
      - If an alert for this asset_ip already exists → UPDATE it
      - If it's a new IP → INSERT a fresh row

    This means running the scanner twice will UPDATE existing alerts
    rather than creating duplicates.

    Args:
        alerts_list (list of dict): output of alert_engine.generate_alerts()
            Each dict must have:
              asset_ip, asset_criticality, threat_severity,
              risk_score, severity_label
            Optional:
              asset_id, threat_record_id

    Returns:
        dict: { "inserted": int, "updated": int, "errors": int }
    """
    if not alerts_list:
        print("[DB] No alerts to save.")
        return {"inserted": 0, "updated": 0, "errors": 0}

    session  = get_session()
    inserted = 0
    updated  = 0
    errors   = 0

    try:
        for alert_data in alerts_list:
            try:
                ip = alert_data.get("asset_ip") or alert_data.get("ip_address")
                if not ip:
                    print(f"[DB ERROR] Alert missing asset_ip — skipping: {alert_data}")
                    errors += 1
                    continue

                existing = session.query(RiskAlert).filter_by(asset_ip=ip).first()

                if existing:
                    # UPDATE — refresh all fields with latest scan data
                    existing.asset_criticality = alert_data.get("asset_criticality", existing.asset_criticality)
                    existing.threat_severity   = alert_data.get("threat_severity",   existing.threat_severity)
                    existing.risk_score        = alert_data.get("risk_score",        existing.risk_score)
                    existing.severity_label    = alert_data.get("severity_label",    existing.severity_label)
                    existing.asset_id          = alert_data.get("asset_id",          existing.asset_id)
                    existing.threat_record_id  = alert_data.get("threat_record_id",  existing.threat_record_id)
                    existing.updated_at        = datetime.now(timezone.utc)
                    # NOTE: acknowledged is NOT reset on update —
                    # once an operator acks an alert it stays acked
                    print(f"[DB] UPDATED  alert: {ip} | score={alert_data.get('risk_score')} [{alert_data.get('severity_label')}]")
                    updated += 1

                else:
                    # INSERT — new alert
                    new_alert = RiskAlert(
                        asset_ip          = ip,
                        asset_id          = alert_data.get("asset_id"),
                        threat_record_id  = alert_data.get("threat_record_id"),
                        asset_criticality = alert_data.get("asset_criticality", 1.0),
                        threat_severity   = alert_data.get("threat_severity",   1.0),
                        risk_score        = alert_data.get("risk_score",        1.0),
                        severity_label    = alert_data.get("severity_label",    "Low"),
                        acknowledged      = False,
                        created_at        = datetime.now(timezone.utc),
                        updated_at        = datetime.now(timezone.utc),
                    )
                    session.add(new_alert)
                    print(f"[DB] INSERTED alert: {ip} | score={alert_data.get('risk_score')} [{alert_data.get('severity_label')}]")
                    inserted += 1

            except Exception as row_err:
                print(f"[DB ERROR] Failed to save alert for {alert_data.get('asset_ip', '?')}: {row_err}")
                errors += 1
                continue

        session.commit()
        print(f"\n[DB] Alerts saved — inserted: {inserted}, updated: {updated}, errors: {errors}")

    except Exception as e:
        session.rollback()
        print(f"[DB ERROR] Transaction failed, rolled back: {e}")
        raise
    finally:
        session.close()

    return {"inserted": inserted, "updated": updated, "errors": errors}


# ── Query Helpers (used by Flask API routes) ──────────────────────────────
def get_all_alerts(limit=200):
    """
    Returns all alerts sorted by risk_score descending (highest risk first).

    Args:
        limit (int): max rows to return (default 200)

    Returns:
        list of dict
    """
    session = get_session()
    try:
        alerts = (session.query(RiskAlert)
                  .order_by(RiskAlert.risk_score.desc())
                  .limit(limit)
                  .all())
        return [a.to_dict() for a in alerts]
    finally:
        session.close()


def get_alerts_by_severity(severity_label):
    """
    Returns alerts filtered by severity label.

    Args:
        severity_label (str): 'Low', 'Medium', or 'High'

    Returns:
        list of dict
    """
    session = get_session()
    try:
        alerts = (session.query(RiskAlert)
                  .filter_by(severity_label=severity_label)
                  .order_by(RiskAlert.risk_score.desc())
                  .all())
        return [a.to_dict() for a in alerts]
    finally:
        session.close()


def get_all_assets():
    """Returns all assets as list of dicts."""
    session = get_session()
    try:
        assets = session.query(Asset).order_by(Asset.criticality_score.desc()).all()
        return [a.to_dict() for a in assets]
    finally:
        session.close()


def get_all_threat_records():
    """Returns all threat records as list of dicts."""
    session = get_session()
    try:
        records = session.query(ThreatRecord).order_by(ThreatRecord.queried_at.desc()).all()
        return [r.to_dict() for r in records]
    finally:
        session.close()


def get_stats():
    """
    Returns summary statistics for the dashboard stat cards.

    Returns:
        dict: { total_assets, total_alerts, high_alerts,
                medium_alerts, low_alerts, avg_risk_score }
    """
    session = get_session()
    try:
        total_assets  = session.query(Asset).count()
        total_alerts  = session.query(RiskAlert).count()
        high_alerts   = session.query(RiskAlert).filter_by(severity_label="High").count()
        medium_alerts = session.query(RiskAlert).filter_by(severity_label="Medium").count()
        low_alerts    = session.query(RiskAlert).filter_by(severity_label="Low").count()

        all_scores    = [a.risk_score for a in session.query(RiskAlert).all()]
        avg_score     = round(sum(all_scores) / len(all_scores), 2) if all_scores else 0.0

        return {
            "total_assets":  total_assets,
            "total_alerts":  total_alerts,
            "high_alerts":   high_alerts,
            "medium_alerts": medium_alerts,
            "low_alerts":    low_alerts,
            "avg_risk_score": avg_score,
        }
    finally:
        session.close()


def acknowledge_alert(alert_id):
    """
    Marks one alert as acknowledged.

    Args:
        alert_id (int): the alert's primary key

    Returns:
        bool: True if found and updated, False if not found
    """
    session = get_session()
    try:
        alert = session.query(RiskAlert).filter_by(alert_id=alert_id).first()
        if not alert:
            return False
        alert.acknowledged = True
        alert.updated_at   = datetime.now(timezone.utc)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        print(f"[DB ERROR] acknowledge_alert failed: {e}")
        return False
    finally:
        session.close()