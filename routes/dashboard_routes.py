"""
routes/dashboard_routes.py
--------------------------
Dashboard Blueprint — HTML view routes.

Endpoints:
  GET /              → main dashboard (index.html)
  GET /assets-view   → asset inventory page (assets.html)
"""

from flask import Blueprint, render_template

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    """Main dashboard — renders dashboard/templates/index.html"""
    return render_template("index.html")


@dashboard_bp.route("/assets-view")
def assets_view():
    """Asset inventory page — renders dashboard/templates/assets.html"""
    return render_template("assets.html")