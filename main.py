"""
main.py
-------
Application entry point — Flask app factory with Blueprints.

Fixes applied:
  - Scheduler starts AFTER Flask is ready
  - First scan delayed by 60 seconds (not immediate)
  - Scan runs in background thread — never blocks Flask
  - Flask responds to requests instantly on startup
  - SCAN LIMITER: Limits the background loops to exactly 5 iterations
  - COUNTER DISPLAY: Explicitly prints "Scan 1", "Scan 2", etc., at the start of each run
  - FIX 4: create_app() accepts testing=False and db_session=None for integration tests
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


def create_app(testing=False, db_session=None):
    """
    Application factory.
    Creates, configures, and returns the Flask app instance.

    Args:
        testing (bool): When True, skips scheduler startup and API key
                        validation so tests run cleanly with no side effects.
        db_session:     Optional SQLAlchemy session injected by tests.
                        Stored in app.config["DB_SESSION"] so routes can
                        use it instead of opening their own session.
    """
    app = Flask(__name__, template_folder="dashboard/templates")

    # ── Config ────────────────────────────────────────────────────────────
    app.config["SECRET_KEY"]                     = Config.SECRET_KEY
    app.config["DEBUG"]                          = False
    app.config["SQLALCHEMY_DATABASE_URI"]        = Config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["TESTING"]                        = testing

    # FIX 4 — store injected test session so routes can access it
    if db_session is not None:
        app.config["DB_SESSION"] = db_session

    # ── Validate API keys (skip in test mode — no real keys needed) ───────
    if not testing:
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


# ── Background scheduler (FIXED SCOPE VARIATION) ─────────────────────────
def start_scheduler(app, subnet, interval_minutes=5):
    """
    Starts a background thread that:
      1. Waits 60 seconds after Flask starts (lets server stabilise)
      2. Prints the current scan number explicitly
      3. Runs the pipeline precisely 5 times
      4. Breaks and shuts down the thread loop safely
    """
    MAX_SCANS = 5  # 👈 MOVED HERE: Now both functions can see this variable!

    def scheduler_loop():
        print(f"[SCHEDULER] Waiting 60s before first scan...")
        time_module.sleep(60)   # ← delayed first run

        scan_count = 0

        while scan_count < MAX_SCANS:
            scan_count += 1

            print(f"\n=======================================================")
            print(f" [SCHEDULER] Scan {scan_count}")
            print(f"=======================================================")

            with app.app_context():
                run_pipeline(subnet)

            if scan_count >= MAX_SCANS:
                break

            print(f"[SCHEDULER] Next scan in {interval_minutes} minute(s).")
            time_module.sleep(interval_minutes * 60)

        print(f"\n[SCHEDULER INFO] Automated tracking cycle threshold achieved ({MAX_SCANS}/{MAX_SCANS}).")
        print(f"[SCHEDULER INFO] Background thread shutting down safely. Web dashboard routes remain active.")

    thread = threading.Thread(target=scheduler_loop, daemon=True, name="ScanScheduler")
    thread.start()
    print(f"[SCHEDULER] Background scheduler started — "
          f"will run exactly {MAX_SCANS} times at {interval_minutes} min intervals.")


# ── Entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    TARGET_SUBNET    = "192.168.0.0/24"
    SCAN_INTERVAL    = 1  # minutes between automatic scans

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
    print(f"  Auto-scan  : limited to 5 runs every {SCAN_INTERVAL} min")
    print("="*55 + "\n")

    # Start the background scheduler FIRST (non-blocking — runs in thread)
    start_scheduler(app, TARGET_SUBNET, interval_minutes=SCAN_INTERVAL)

    # Start Flask — this is the LAST line (it blocks here until Ctrl+C)
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)