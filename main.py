"""
main.py
-------
Application entry point — Flask app factory with Blueprints.

Structure:
  api_bp       : /api/*  — REST API endpoints returning JSON
  dashboard_bp : /       — HTML dashboard views (Week 4+)
"""

from flask import Flask
from config import Config
from db.database import init_db
from db.models import Base
from sqlalchemy import create_engine


def create_app():
    """
    Application factory function.
    Creates, configures, and returns the Flask app instance.
    Using a factory means the app can be created fresh for each test run.
    """
    app = Flask(__name__)

    # ── Load config ───────────────────────────────────────────────────────
    app.config["SECRET_KEY"]                   = Config.SECRET_KEY
    app.config["DEBUG"]                        = Config.DEBUG
    app.config["SQLALCHEMY_DATABASE_URI"]      = Config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ── Validate API keys at startup ──────────────────────────────────────
    Config.validate()

    # ── Initialise DB tables ──────────────────────────────────────────────
    with app.app_context():
        init_db()

    # ── Register Blueprints ───────────────────────────────────────────────
    from routes.api_routes       import api_bp
    from routes.dashboard_routes import dashboard_bp

    app.register_blueprint(api_bp,       url_prefix="/api")
    app.register_blueprint(dashboard_bp, url_prefix="/")

    return app


# ── Run ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = create_app()
    print("\n" + "="*55)
    print("  Automated IP Risk Profiler System")
    print("="*55)
    print("  Dashboard  : http://localhost:5000/")
    print("  Assets API : http://localhost:5000/api/assets")
    print("  Alerts API : http://localhost:5000/api/alerts")
    print("  Stats API  : http://localhost:5000/api/stats")
    print("  Health     : http://localhost:5000/api/health")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=Config.DEBUG)
    