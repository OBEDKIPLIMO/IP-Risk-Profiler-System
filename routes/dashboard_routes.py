"""
routes/dashboard_routes.py
--------------------------
Dashboard Blueprint — HTML view routes.

Endpoints:
  GET /          → main dashboard (alerts table + stat cards)
  GET /assets    → asset inventory view

NOTE: Full HTML templates are built in Week 4 (Days 22-26).
      These routes return placeholder JSON for now so Flask starts cleanly.
      They will be updated to render_template() once templates exist.
"""

from flask import Blueprint, jsonify

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    """Main dashboard — will render index.html in Week 4."""
    return jsonify({
        "page":    "dashboard",
        "message": "Dashboard HTML coming in Week 4. Use /api/* endpoints for data.",
        "links": {
            "assets":  "/api/assets",
            "alerts":  "/api/alerts",
            "threats": "/api/threats",
            "stats":   "/api/stats",
        }
    })


@dashboard_bp.route("/assets-view")
def assets_view():
    """Asset inventory view — will render assets.html in Week 4."""
    return jsonify({
        "page":    "assets",
        "message": "Asset inventory HTML coming in Week 4.",
        "data_url": "/api/assets"
    })