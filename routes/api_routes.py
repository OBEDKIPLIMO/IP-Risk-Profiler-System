"""
routes/api_routes.py
--------------------
REST API Blueprint — all /api/* endpoints.

Endpoints:
  GET  /api/health                      → health check
  GET  /api/assets                      → all discovered assets
  GET  /api/threats                     → all threat records
  GET  /api/alerts                      → all alerts sorted by risk_score desc
  GET  /api/alerts/<severity>           → filter by Low / Medium / High
  GET  /api/stats                       → summary counts for dashboard cards
  POST /api/scan/trigger                → manually trigger full pipeline
  POST /api/alerts/<id>/acknowledge     → mark one alert as acknowledged
"""

import time
from flask import Blueprint, jsonify, request

from db.database import (
    get_all_assets,
    get_all_threat_records,
    get_all_alerts,
    get_alerts_by_severity,
    get_stats,
    acknowledge_alert,
)

api_bp = Blueprint("api", __name__)


# ── GET /api/health ───────────────────────────────────────────────────────
@api_bp.route("/health")
def health():
    """Simple health check — confirms Flask is running."""
    return jsonify({
        "status":  "healthy",
        "service": "IP Risk Profiler API",
    }), 200


# ── GET /api/assets ───────────────────────────────────────────────────────
@api_bp.route("/assets")
def get_assets_route():
    """
    Returns all discovered network assets.
    Sorted by criticality_score descending (most critical first).

    Response:
    {
        "status": "ok",
        "count":  3,
        "data": [
            { "id":1, "ip_address":"192.168.1.10",
              "hostname":"DB-SERVER", "criticality_score":9, ... },
            ...
        ]
    }
    """
    try:
        assets = get_all_assets()
        return jsonify({
            "status": "ok",
            "count":  len(assets),
            "data":   assets,
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/threats ──────────────────────────────────────────────────────
@api_bp.route("/threats")
def get_threats_route():
    """
    Returns all threat intelligence records from the database.
    Each row represents one API query result (AbuseIPDB / VirusTotal / OTX).

    Response:
    {
        "status": "ok",
        "count":  3,
        "data": [
            { "id":1, "ip_address":"185.220.101.1",
              "source_api":"abuseipdb", "severity_score":10.0, ... },
            ...
        ]
    }
    """
    try:
        records = get_all_threat_records()
        return jsonify({
            "status": "ok",
            "count":  len(records),
            "data":   records,
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/alerts ───────────────────────────────────────────────────────
@api_bp.route("/alerts")
def get_alerts_route():
    """
    Returns all risk alerts sorted by risk_score descending.
    Highest risk alerts appear first — ready for the dashboard table.

    Response:
    {
        "status": "ok",
        "count":  5,
        "data": [
            { "alert_id":1, "asset_ip":"192.168.1.10",
              "risk_score":85.0, "severity_label":"High", ... },
            ...
        ]
    }
    """
    try:
        alerts = get_all_alerts()
        return jsonify({
            "status": "ok",
            "count":  len(alerts),
            "data":   alerts,
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/alerts/<severity> ────────────────────────────────────────────
@api_bp.route("/alerts/<string:severity>")
def get_alerts_by_severity_route(severity):
    """
    Returns alerts filtered by severity label.

    URL examples:
      GET /api/alerts/High
      GET /api/alerts/Medium
      GET /api/alerts/Low

    Case-insensitive: 'high', 'HIGH', 'High' all work.

    Response:
    {
        "status":   "ok",
        "severity": "High",
        "count":    2,
        "data":     [ ... ]
    }

    Error (invalid severity):
    {
        "status":  "error",
        "message": "Invalid severity 'critical'. Must be one of: ['High', 'Medium', 'Low']"
    }
    """
    valid     = ["High", "Medium", "Low"]
    severity  = severity.capitalize()   # normalise: 'HIGH' → 'High'

    if severity not in valid:
        return jsonify({
            "status":  "error",
            "message": f"Invalid severity '{severity}'. Must be one of: {valid}",
        }), 400

    try:
        alerts = get_alerts_by_severity(severity)
        return jsonify({
            "status":   "ok",
            "severity": severity,
            "count":    len(alerts),
            "data":     alerts,
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── GET /api/stats ────────────────────────────────────────────────────────
@api_bp.route("/stats")
def get_stats_route():
    """
    Returns summary statistics for the dashboard stat cards.

    Response:
    {
        "status":        "ok",
        "total_assets":  5,
        "total_alerts":  5,
        "high_alerts":   2,
        "medium_alerts": 1,
        "low_alerts":    2,
        "avg_risk_score": 42.6
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

    Full pipeline steps:
      1. Nmap scan         → discover live assets on subnet
      2. save_assets_to_db → persist discovered assets
      3. Aggregator        → query AbuseIPDB + VirusTotal + OTX per IP
      4. Alert Engine      → compute risk scores
      5. save_alerts_to_db → persist alerts (upsert)

    POST body (optional JSON):
      { "subnet": "192.168.100.0/24" }

    If no subnet provided → uses default 192.168.100.0/24

    Response:
    {
        "status":           "ok",
        "message":          "Pipeline complete",
        "subnet":           "192.168.100.0/24",
        "assets_found":     3,
        "alerts_generated": 3,
        "db_inserted":      2,
        "db_updated":       1
    }
    """
    try:
        body   = request.get_json(silent=True) or {}
        subnet = body.get("subnet", "192.168.100.0/24")

        from scanner.asset_scanner   import scan_subnet, save_assets_to_db
        from threat_intel.aggregator import get_composite_threat_score
        from engine.alert_engine     import generate_alerts
        from db.database             import save_alerts_to_db

        print(f"\n[SCAN TRIGGER] Manual scan started for: {subnet}")

        # ── Step 1: Scan ──────────────────────────────────────────────────
        assets = scan_subnet(subnet)
        if not assets:
            return jsonify({
                "status":       "ok",
                "message":      "Scan complete — no live hosts found",
                "subnet":       subnet,
                "assets_found": 0,
            }), 200

        save_assets_to_db(assets)
        print(f"[SCAN TRIGGER] Found {len(assets)} asset(s).")

        # ── Step 2: Threat intel ──────────────────────────────────────────
        threat_scores = {}
        for asset in assets:
            ip     = asset["ip_address"]
            result = get_composite_threat_score(ip)
            if result:
                threat_scores[ip] = result["composite_score"]
            time.sleep(1)

        # ── Step 3: Generate + save alerts ───────────────────────────────
        alerts  = generate_alerts(assets, threat_scores)
        summary = save_alerts_to_db(alerts)

        print(f"[SCAN TRIGGER] Done — "
              f"inserted: {summary['inserted']}, updated: {summary['updated']}")

        return jsonify({
            "status":           "ok",
            "message":          "Pipeline complete",
            "subnet":           subnet,
            "assets_found":     len(assets),
            "alerts_generated": len(alerts),
            "db_inserted":      summary["inserted"],
            "db_updated":       summary["updated"],
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── POST /api/alerts/<id>/acknowledge ─────────────────────────────────────
@api_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def ack_alert(alert_id):
    """
    Marks one alert as acknowledged by an operator.
    Called by the dashboard 'Acknowledge' button.

    POST /api/alerts/3/acknowledge

    Response (success):
    { "status": "ok", "message": "Alert 3 acknowledged", "alert_id": 3 }

    Response (not found):
    { "status": "error", "message": "Alert 3 not found" }
    """
    try:
        success = acknowledge_alert(alert_id)
        if success:
            return jsonify({
                "status":   "ok",
                "message":  f"Alert {alert_id} acknowledged",
                "alert_id": alert_id,
            }), 200
        else:
            return jsonify({
                "status":  "error",
                "message": f"Alert {alert_id} not found",
            }), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500