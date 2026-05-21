"""
routes/api_routes.py
--------------------
REST API Blueprint — all /api/* endpoints.

Endpoints:
  GET  /api/health               → health check
  GET  /api/assets               → all discovered assets
  GET  /api/threats              → all threat records
  GET  /api/alerts               → all alerts sorted by risk_score desc
  GET  /api/alerts/<severity>    → alerts filtered by Low/Medium/High
  GET  /api/stats                → summary counts for dashboard cards
  POST /api/scan/trigger         → manually trigger scan + threat query cycle
  POST /api/alerts/<id>/acknowledge → mark one alert as acknowledged
"""

from flask import Blueprint, jsonify, request
from db.database import (
    get_all_assets, get_all_threat_records,
    get_all_alerts, get_alerts_by_severity,
    get_stats, acknowledge_alert
)

api_bp = Blueprint("api", __name__)


# ── Health Check ──────────────────────────────────────────────────────────
@api_bp.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "IP Risk Profiler API"}), 200


# ── GET /api/assets ───────────────────────────────────────────────────────
@api_bp.route("/assets")
def get_assets():
    """Returns all discovered assets sorted by criticality descending."""
    try:
        assets = get_all_assets()
        return jsonify({
            "status": "ok",
            "count":  len(assets),
            "data":   assets
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/threats ──────────────────────────────────────────────────────
@api_bp.route("/threats")
def get_threats():
    """Returns all threat intelligence records."""
    try:
        records = get_all_threat_records()
        return jsonify({
            "status": "ok",
            "count":  len(records),
            "data":   records
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/alerts ───────────────────────────────────────────────────────
@api_bp.route("/alerts")
def get_alerts():
    """
    Returns all alerts sorted by risk_score descending.
    Highest risk alerts appear first — ready for dashboard table.
    """
    try:
        alerts = get_all_alerts()
        return jsonify({
            "status": "ok",
            "count":  len(alerts),
            "data":   alerts
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/alerts/<severity> ────────────────────────────────────────────
@api_bp.route("/alerts/<string:severity>")
def get_alerts_filtered(severity):
    """
    Returns alerts filtered by severity label.

    URL examples:
      GET /api/alerts/High
      GET /api/alerts/Medium
      GET /api/alerts/Low
    """
    # Validate severity value
    valid = ["High", "Medium", "Low"]
    # Normalise capitalisation — accept 'high', 'HIGH', 'High'
    severity = severity.capitalize()

    if severity not in valid:
        return jsonify({
            "status":  "error",
            "message": f"Invalid severity '{severity}'. Must be one of: {valid}"
        }), 400

    try:
        alerts = get_alerts_by_severity(severity)
        return jsonify({
            "status":   "ok",
            "severity": severity,
            "count":    len(alerts),
            "data":     alerts
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/stats ────────────────────────────────────────────────────────
@api_bp.route("/stats")
def get_summary_stats():
    """
    Returns summary statistics for the dashboard stat cards.

    Response:
    {
        "total_assets":   int,
        "total_alerts":   int,
        "high_alerts":    int,
        "medium_alerts":  int,
        "low_alerts":     int,
        "avg_risk_score": float
    }
    """
    try:
        stats = get_stats()
        return jsonify({"status": "ok", **stats}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── POST /api/scan/trigger ────────────────────────────────────────────────
@api_bp.route("/scan/trigger", methods=["POST"])
def trigger_scan():
    """
    Manually triggers a full scan + threat intel + risk scoring cycle.

    This runs the full pipeline:
      1. Nmap scan → discover assets
      2. Aggregator → query 3 threat APIs per IP
      3. Alert Engine → compute risk scores
      4. DB → save/update alerts

    POST body (optional JSON):
      { "subnet": "192.168.100.0/24" }
    If not provided, uses the default subnet from config.

    Returns immediately with a status message.
    NOTE: In Week 4 this will be made async with APScheduler.
          For now it runs synchronously (blocks until complete).
    """
    try:
        body   = request.get_json(silent=True) or {}
        subnet = body.get("subnet", "192.168.100.0/24")

        # ── Import pipeline modules ───────────────────────────────────────
        from scanner.scanner      import scan_subnet, save_assets_to_db
        from threat_intel.aggregator    import get_composite_threat_score
        from engine.alert_engine        import generate_alerts
        from db.database                import save_alerts_to_db as save_alerts
        import time

        print(f"\n[SCAN TRIGGER] Starting pipeline for subnet: {subnet}")

        # Step 1 — Scan
        assets = scan_subnet(subnet)
        save_assets_to_db(assets)
        print(f"[SCAN TRIGGER] Found {len(assets)} asset(s)")

        if not assets:
            return jsonify({
                "status":  "ok",
                "message": "Scan complete — no live hosts found",
                "subnet":  subnet,
                "assets_found": 0
            }), 200

        # Step 2 — Threat intel (query each discovered IP)
        threat_scores = {}
        for asset in assets:
            ip     = asset["ip_address"]
            result = get_composite_threat_score(ip)
            if result:
                threat_scores[ip] = result["composite_score"]
            time.sleep(1)

        # Step 3 — Generate alerts
        alerts = generate_alerts(assets, threat_scores)

        # Step 4 — Save to DB
        summary = save_alerts(alerts)

        return jsonify({
            "status":       "ok",
            "message":      "Pipeline complete",
            "subnet":       subnet,
            "assets_found": len(assets),
            "alerts_generated": len(alerts),
            "db_inserted":  summary["inserted"],
            "db_updated":   summary["updated"],
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── POST /api/alerts/<id>/acknowledge ────────────────────────────────────
@api_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def ack_alert(alert_id):
    """
    Marks one alert as acknowledged.
    Used by the dashboard 'Acknowledge' button.

    POST /api/alerts/3/acknowledge
    """
    try:
        success = acknowledge_alert(alert_id)
        if success:
            return jsonify({
                "status":   "ok",
                "message":  f"Alert {alert_id} acknowledged",
                "alert_id": alert_id
            }), 200
        else:
            return jsonify({
                "status":  "error",
                "message": f"Alert {alert_id} not found"
            }), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500