"""
main.py
-------
Application entry point — Flask app factory with Blueprints and Background Scheduler.
Uses APScheduler directly (not flask-apscheduler) to avoid app-context timing issues.
"""

import logging
from flask import Flask
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from config import Config
from db.database import init_db

from scanner.asset_scanner import scan_subnet
from engine.alert_engine import generate_alerts, save_alerts_to_db

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ── Scan limit config ─────────────────────────────────────────────────────
scan_count = 0
MAX_SCANS  = 5


def scheduled_scan_pipeline():
    global scan_count
    scan_count += 1
    logger.info(f"🔔 [SCHEDULER] >>> Scan {scan_count}/{MAX_SCANS} started <<<")
    target_subnet = "192.168.1.0/24"
    logger.info(f"⏰ [SCHEDULER] Scanning target: {target_subnet}")
    try:
        scanned_assets = scan_subnet(target_subnet)
        mock_threats   = {asset["ip_address"]: 5.0 for asset in scanned_assets}
        alerts         = generate_alerts(scanned_assets, mock_threats)
        db_summary     = save_alerts_to_db(alerts)
        logger.info(
            f"✅ [SCHEDULER SUCCESS] Scan {scan_count}/{MAX_SCANS} Complete | "
            f"Assets Found: {len(scanned_assets)} | "
            f"Alerts Tracked/Updated: {db_summary['inserted'] + db_summary['updated']}"
        )
    except Exception as e:
        logger.exception(f"❌ [SCHEDULER CRASH] {e}")
    finally:
        if scan_count >= MAX_SCANS:
            logger.info(f"🏁 [SCHEDULER] All {MAX_SCANS} scans completed — shutting down scheduler.")
            scheduler.shutdown(wait=False)


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"]                     = Config.SECRET_KEY
    app.config["DEBUG"]                          = Config.DEBUG
    app.config["SQLALCHEMY_DATABASE_URI"]        = Config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    Config.validate()

    with app.app_context():
        init_db()

    from routes.api_routes       import api_bp
    from routes.dashboard_routes import dashboard_bp
    app.register_blueprint(api_bp,       url_prefix="/api")
    app.register_blueprint(dashboard_bp, url_prefix="/")

    return app


if __name__ == "__main__":
    app = create_app()

    # ✅ Use BackgroundScheduler directly — no Flask integration needed,
    # no app context required, no "tentatively" timing race condition.
    scheduler = BackgroundScheduler(timezone="UTC")

    initial_delay_time = datetime.now(timezone.utc) + timedelta(seconds=15)

    scheduler.add_job(
        func=scheduled_scan_pipeline,
        trigger=IntervalTrigger(minutes=5, start_date=initial_delay_time, timezone="UTC"),
        id='periodic_security_scan',
        name='Automated Network Risk Scan',
        misfire_grace_time=30,
        replace_existing=True
    )

    scheduler.start()
    logger.info("🚀 [SCHEDULER ENGINE] Background daemon started.")

    # Confirm job is live
    jobs = scheduler.get_jobs()
    for job in jobs:
        logger.info(f"📋 [SCHEDULER] Job registered: '{job.id}' | Next run: {job.next_run_time}")

    print("\n" + "="*55)
    print("  Automated IP Risk Profiler System (Active Daemon)")
    print("="*55)
    print("  Dashboard  : http://localhost:5000/")
    print("  Assets API : http://localhost:5000/api/assets")
    print("  Alerts API : http://localhost:5000/api/alerts")
    print("  Stats API  : http://localhost:5000/api/stats")
    print("  Health     : http://localhost:5000/api/health")
    print("="*55 + "\n")

    app.run(host="0.0.0.0", port=5000, debug=False)