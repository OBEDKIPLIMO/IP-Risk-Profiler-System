"""
routes/dashboard_routes.py
--------------------------
Dashboard Blueprint — HTML view routes.

Endpoints:
  GET /              → main dashboard (index.html)
  GET /assets-view   → asset inventory page (assets.html)
  GET /engine-test   → engine metrics validation page (test_dashboard.html)  NEW
"""

import os
import json
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


@dashboard_bp.route("/engine-test")
def engine_test():
    """NEW: Engine self-test validation dashboard page."""
    # Build path targeting your db directory artifact file location
    # looks up matching relative context from project roots
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    file_path = os.path.join(base_dir, "db", "test_results.json")
    
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                test_data = json.load(f)
        except Exception:
            # Fallback wrapper if file formatting corrupts
            test_data = {
                "last_run": "System Fault", 
                "accuracy": "0.0%", 
                "status": "❌ ERROR", 
                "scenarios": []
            }
    else:
        # Graceful fallback state before the first pytest run executes
        test_data = {
            "last_run": "Pending First Runtime Check",
            "accuracy": "N/A",
            "status": "⚠️ NO DATA",
            "scenarios": []
        }
        
    return render_template("test_dashboard.html", data=test_data)