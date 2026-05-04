"""
main.py
-------
Application entry point for the Automated IP Risk Profiler System.
Initialises the Flask app and registers all routes.
"""

from flask import Flask, jsonify
from config import Config
from scanner import check_abuse_ip

def create_app():
    """
    Application factory function.
    Creates and configures the Flask app instance.
    """
    app = Flask(__name__)

    # Load config
    app.config["SECRET_KEY"]   = Config.SECRET_KEY
    app.config["DEBUG"]        = Config.DEBUG
    app.config["SQLALCHEMY_DATABASE_URI"] = Config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Validate API keys at startup
    Config.validate()

    # ── Routes ────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        """Dashboard home placeholder."""
        return jsonify({
            "system": "Automated IP Risk Profiler",
            "status": "running",
            "version": "0.1.0",
            "message": "Hello from the IP Risk Profiler! Dashboard coming soon."
        })

    @app.route("/api/scan/<ip>")
    def scan_ip(ip):
        """
        Triggers a real-time reputation scan for a specific IP.
        Uses the scanner module to fetch data from AbuseIPDB.
        """
        result = check_abuse_ip(ip)
        
        if result:
            return jsonify({
                "status": "success",
                "message": f"Scan results for {ip} retrieved successfully.",
                "data": result
            })
        else:
            return jsonify({
                "status": "error",
                "message": f"Failed to retrieve data for IP: {ip}."
            }), 500

    @app.route("/api/assets")
    def get_assets():
        return jsonify({"status": "ok", "data": []})

    @app.route("/health")
    def health():
        return jsonify({"status": "healthy"}), 200

    # CRITICAL: This return must be AFTER all routes are defined
    return app


# ── Run the app ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = create_app()
    print("\n" + "="*55)
    print("  Automated IP Risk Profiler System — Starting Up")
    print("="*55)
    print("  Scan URL  : http://localhost:5000/api/scan/8.8.8.8")
    print("  Health    : http://localhost:5000/health")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=Config.DEBUG)