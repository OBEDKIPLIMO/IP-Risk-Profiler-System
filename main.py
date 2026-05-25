"""
main.py
-------
Application entry point — Flask app factory with Blueprints.

Fix applied:
  - Scheduler starts AFTER Flask is ready
  - First scan delayed by 60 seconds (not immediate)
  - Scan runs in background thread — never blocks Flask
  - Flask responds to requests instantly on startup
"""

import logging
import threading
import time as time_module
from flask import Flask
from config import Config
from db.database import init_db

# Suppress noisy APScheduler logs
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logging.getLogger("apscheduler").setLevel(logging.WARNING)


def create_app():
    """
    Application factory.
    Creates, configures, and returns the Flask app instance.
    """
    app = Flask(__name__, template_folder="dashboard/templates")

    # ── Config ────────────────────────────────────────────────────────────
    app.config["SECRET_KEY"]                     = Config.SECRET_KEY
    app.config["DEBUG"]                          = False
    app.config["SQLALCHEMY_DATABASE_URI"]        = Config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ── Validate API keys ─────────────────────────────────────────────────
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


# ── Background pipeline function ──────────────────────────────────────────
def run_pipeline(subnet):
    """
    Runs the full scan → threat intel → risk scoring → DB pipeline.
    Called by the background scheduler thread.
    Never called on startup — only after the delay.
    """
    try:
        print(f"\n[SCHEDULER] Running pipeline for subnet: {subnet}")

        from scanner.asset_scanner   import scan_subnet, save_assets_to_db
        from threat_intel.aggregator import get_composite_threat_score
        from engine.alert_engine     import generate_alerts
        from db.database             import save_alerts_to_db

        # Step 1 — Scan
        assets = scan_subnet(subnet)
        if not assets:
            print("[SCHEDULER] No assets found — pipeline complete.")
            return
        save_assets_to_db(assets)
        print(f"[SCHEDULER] Scanned {len(assets)} asset(s).")

        # Step 2 — Threat intel
        threat_scores = {}
        for asset in assets:
            ip     = asset["ip_address"]
            result = get_composite_threat_score(ip)
            if result:
                threat_scores[ip] = result["composite_score"]
            time_module.sleep(1)

        # Step 3 — Generate + save alerts
        alerts  = generate_alerts(assets, threat_scores)
        summary = save_alerts_to_db(alerts)
        print(f"[SCHEDULER] Pipeline done — "
              f"inserted: {summary['inserted']}, updated: {summary['updated']}")

    except Exception as e:
        print(f"[SCHEDULER ERROR] Pipeline failed: {e}")


# ── Background scheduler (runs AFTER Flask starts) ────────────────────────
def start_scheduler(app, subnet, interval_minutes=5):
    """
    Starts a background thread that:
      1. Waits 60 seconds after Flask starts (lets server stabilise)
      2. Runs the pipeline once
      3. Then repeats every `interval_minutes` minutes

    This runs OUTSIDE Flask — no request context needed.
    """
    def scheduler_loop():
        print(f"[SCHEDULER] Waiting 60s before first scan...")
        time_module.sleep(60)   # ← this is the key fix — delayed first run

        while True:
            with app.app_context():
                run_pipeline(subnet)
            print(f"[SCHEDULER] Next scan in {interval_minutes} minute(s).")
            time_module.sleep(interval_minutes * 60)

    thread = threading.Thread(target=scheduler_loop, daemon=True, name="ScanScheduler")
    thread.start()
    print(f"[SCHEDULER] Background scheduler started — "
          f"first scan in 60s, then every {interval_minutes} min.")


# ── Entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    TARGET_SUBNET    = "192.168.100.0/24"
    SCAN_INTERVAL    = 5   # minutes between automatic scans

    app = create_app()

    print("\n" + "="*55)
    print("  Automated IP Risk Profiler System")
    print("="*55)
    print(f"  Dashboard  : http://localhost:5000/")
    print(f"  Assets API : http://localhost:5000/api/assets")
    print(f"  Alerts API : http://localhost:5000/api/alerts")
    print(f"  Stats API  : http://localhost:5000/api/stats")
    print(f"  Health     : http://localhost:5000/api/health")
    print(f"  Subnet     : {TARGET_SUBNET}")
    print(f"  Auto-scan  : every {SCAN_INTERVAL} min (first scan in 60s)")
    print("="*55 + "\n")

    # Start the background scheduler FIRST (non-blocking — runs in thread)
    start_scheduler(app, TARGET_SUBNET, interval_minutes=SCAN_INTERVAL)

    # Start Flask — this is the LAST line (it blocks here until Ctrl+C)
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)