"""
config.py
---------
Loads all environment variables from the .env file using python-dotenv
and exposes them as a Config class for use across the application.
"""

import os
from dotenv import load_dotenv

# Load variables from .env into the environment
load_dotenv()


class Config:
    # ── Threat Intelligence API Keys ──────────────────────────────────────
    ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY")
    VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
    OTX_KEY        = os.getenv("OTX_KEY")

    # ── Flask Settings ────────────────────────────────────────────────────
    FLASK_ENV   = os.getenv("FLASK_ENV", "development")
    DEBUG       = os.getenv("FLASK_DEBUG", "1") == "1"
    SECRET_KEY  = os.getenv("SECRET_KEY", "dev-secret-fallback")

    # ── Database ──────────────────────────────────────────────────────────
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///dev.db")

    @classmethod
    def validate(cls):
        """
        Call this at startup to warn about any missing API keys.
        Does not crash the app — allows running without all keys during development.
        """
        missing = []
        for key in ["ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "OTX_KEY"]:
            if not getattr(cls, key) or "your_" in (getattr(cls, key) or ""):
                missing.append(key)

        if missing:
            print(f"[CONFIG WARNING] Missing or placeholder API keys: {', '.join(missing)}")
            print("[CONFIG WARNING] Threat intel queries will fail until real keys are added to .env")
        else:
            print("[CONFIG OK] All API keys loaded.")