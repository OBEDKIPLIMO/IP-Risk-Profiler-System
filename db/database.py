"""
db/database.py
--------------
Handles all database setup for the IP Risk Profiler:
  - SQLAlchemy engine creation
  - Session factory
  - create_all()  → creates tables if they don't exist
  - seed_db()     → inserts 3 sample rows per table for testing
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Asset, ThreatRecord, RiskScore
from datetime import datetime
import json

# ── 1. Engine ─────────────────────────────────────────────────────────────
# The engine is the connection to your SQLite file (dev.db).
# "sqlite:///dev.db" means: create dev.db in the current working directory.
engine = create_engine(
    "sqlite:///dev.db",
    echo=True,          # echo=True prints every SQL statement — useful for learning/debugging
    connect_args={"check_same_thread": False}  # needed for SQLite + Flask threading
)

# ── 2. Session Factory ────────────────────────────────────────────────────
# A session is like a "conversation" with the database.
# You use it to add, query, update, and delete records.
SessionLocal = sessionmaker(
    autocommit=False,   # we manually commit changes (safer)
    autoflush=False,
    bind=engine
)

def get_session():
    """
    Returns a new database session.
    Always close the session when done to release the connection.

    Usage:
        session = get_session()
        try:
            session.add(some_record)
            session.commit()
        finally:
            session.close()
    """
    return SessionLocal()


# ── 3. create_all() ───────────────────────────────────────────────────────
def init_db():
    """
    Creates all database tables defined in models.py if they don't exist yet.
    Safe to call multiple times — will NOT overwrite existing data.

    Call this once at application startup.
    """
    # already imported  # import here to avoid circular imports

    print("\n[DB] Initialising database...")
    Base.metadata.create_all(bind=engine)
    print("[DB] Tables created (or already exist): assets, threat_records, risk_scores")
    print("[DB] Database file: dev.db\n")


# ── 4. Seed Data ──────────────────────────────────────────────────────────
def seed_db():
    """
    Inserts 3 sample rows into each table so you can test
    the dashboard and API routes without running a real scan.

    Safe to call once — checks if data already exists before inserting.
    """
    session = get_session()

    try:
        # ── Check if already seeded ──
        if session.query(Asset).count() > 0:
            print("[SEED] Database already has data — skipping seed.")
            return

        print("[SEED] Inserting sample data...")

        # ── 3 Sample Assets ───────────────────────────────────────────────
        # These represent devices your scanner might find on the Kabarak LAN
        assets = [
            Asset(
                ip_address="192.168.1.10",
                hostname="ADMIN-SERVER-01",
                mac_address="AA:BB:CC:11:22:33",
                open_ports="22,80,443,3306",  # SSH, HTTP, HTTPS, MySQL
                os_type="Ubuntu 22.04 LTS",
                criticality_score=9,           # HIGH — database server
                last_seen=datetime.utcnow()
            ),
            Asset(
                ip_address="192.168.1.25",
                hostname="STAFF-PC-OBED",
                mac_address="AA:BB:CC:44:55:66",
                open_ports="80,445",           # HTTP, Windows file sharing
                os_type="Windows 10 Pro",
                criticality_score=5,           # MEDIUM — staff workstation
                last_seen=datetime.utcnow()
            ),
            Asset(
                ip_address="192.168.1.50",
                hostname="PRINTER-LIB",
                mac_address="AA:BB:CC:77:88:99",
                open_ports="9100",             # printer port only
                os_type="Unknown",
                criticality_score=2,           # LOW — just a printer
                last_seen=datetime.utcnow()
            ),
        ]
        session.add_all(assets)
        session.flush()  # flush assigns IDs without committing yet
        print(f"[SEED] Added {len(assets)} assets.")

        # ── 3 Sample Threat Records ───────────────────────────────────────
        # Simulating what AbuseIPDB, VirusTotal, and OTX would return
        threat_records = [
            ThreatRecord(
                ip_address="192.168.1.10",
                source_api="abuseipdb",
                severity_score=8.5,            # HIGH — heavily reported IP
                details_json=json.dumps({
                    "abuseConfidenceScore": 85,
                    "totalReports": 142,
                    "countryCode": "RU",
                    "usageType": "Data Center/Web Hosting/Transit"
                }),
                queried_at=datetime.utcnow()
            ),
            ThreatRecord(
                ip_address="192.168.1.25",
                source_api="virustotal",
                severity_score=4.0,            # MEDIUM — some detections
                details_json=json.dumps({
                    "malicious": 4,
                    "suspicious": 2,
                    "harmless": 60,
                    "reputation": -5
                }),
                queried_at=datetime.utcnow()
            ),
            ThreatRecord(
                ip_address="192.168.1.50",
                source_api="otx",
                severity_score=1.5,            # LOW — clean IP
                details_json=json.dumps({
                    "pulse_count": 1,
                    "tags": [],
                    "country": "KE"
                }),
                queried_at=datetime.utcnow()
            ),
        ]
        session.add_all(threat_records)
        session.flush()
        print(f"[SEED] Added {len(threat_records)} threat records.")

        # ── 3 Sample Risk Scores ──────────────────────────────────────────
        # Formula: composite = criticality × severity
        # Asset 1: 9 × 8.5 = 76.5 → HIGH
        # Asset 2: 5 × 4.0 = 20.0 → LOW
        # Asset 3: 2 × 1.5 = 3.0  → LOW
        risk_scores = [
            RiskScore(
                asset_id=assets[0].id,
                threat_record_id=threat_records[0].id,
                composite_score=round(9 * 8.5, 2),   # 76.5
                severity_label="High",
                created_at=datetime.utcnow()
            ),
            RiskScore(
                asset_id=assets[1].id,
                threat_record_id=threat_records[1].id,
                composite_score=round(5 * 4.0, 2),   # 20.0
                severity_label="Low",
                created_at=datetime.utcnow()
            ),
            RiskScore(
                asset_id=assets[2].id,
                threat_record_id=threat_records[2].id,
                composite_score=round(2 * 1.5, 2),   # 3.0
                severity_label="Low",
                created_at=datetime.utcnow()
            ),
        ]
        session.add_all(risk_scores)
        session.commit()
        print(f"[SEED] Added {len(risk_scores)} risk scores.")
        print("[SEED] ✓ Seed complete. Your dev.db is ready for testing.\n")

    except Exception as e:
        session.rollback()
        print(f"[SEED ERROR] {e}")
        raise
    finally:
        session.close()


# ── Run directly to initialise + seed ─────────────────────────────────────
# Run this file directly:  python db/database.py
if __name__ == "__main__":
    init_db()
    seed_db()