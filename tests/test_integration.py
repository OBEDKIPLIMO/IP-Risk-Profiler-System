"""
Day 32 — Integration Testing
File: tests/test_integration.py

Tests the full data pipeline:
  Scanner → Aggregator → Risk Engine → DB → Flask API

Run with: pytest tests/test_integration.py -v
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from datetime import datetime


# ===========================================================================
# FIX 1 HELPER — parse_scan_results
# ---------------------------------------------------------------------------
# asset_scanner.py has no parse_scan_results().
# The real parse_host(scanner_obj, ip) requires a live nmap PortScanner object.
# This helper converts the mock_nmap_output dict (plain dicts, not nmap objects)
# into the same shape that parse_host() would produce, so the rest of the
# pipeline tests receive correctly-shaped asset dicts without touching nmap.
# ---------------------------------------------------------------------------
def _parse_mock_nmap_output(mock_output: dict) -> list:
    """
    Convert a mock nmap output dict into asset dicts matching parse_host()'s
    return shape:
      {
        ip_address, hostname, open_ports (comma-str),
        port_details (dict), os_type, criticality_score, last_seen
      }
    """
    from scanner.asset_scanner import assign_criticality
    from datetime import timezone

    assets = []
    for ip, host_data in mock_output.items():
        hostnames    = host_data.get("hostnames", [])
        hostname     = hostnames[0]["name"] if hostnames and hostnames[0].get("name") else None

        open_ports   = []
        port_details = {}
        for port, info in host_data.get("tcp", {}).items():
            if info.get("state") == "open":
                open_ports.append(port)
                port_details[port] = (
                    f"{info.get('name', 'unknown')} "
                    f"{info.get('product', '')} "
                    f"{info.get('version', '')}".strip()
                )

        # FIX 1b — assign_criticality() takes a LIST of port ints, not an asset dict
        criticality = assign_criticality(open_ports)

        assets.append({
            "ip_address":        ip,
            "hostname":          hostname,
            "open_ports":        ",".join(str(p) for p in sorted(open_ports)),
            "port_details":      port_details,
            "os_type":           None,
            "criticality_score": criticality,
            "last_seen":         datetime.now(timezone.utc),
        })
    return assets


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def in_memory_db():
    """
    Create a fresh in-memory SQLite database for each test.
    Patches the app's DB URI so no dev.db is touched.
    """
    from db.database import Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestSession()
    yield session
    session.close()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def mock_nmap_output():
    """Realistic python-nmap scan result structure for 3 hosts."""
    return {
        "10.0.0.1": {
            "hostnames": [{"name": "server-1", "type": "PTR"}],
            "status": {"state": "up"},
            "osmatch": [{"name": "Linux 4.15", "accuracy": "96"}],
            "tcp": {
                22:   {"state": "open", "name": "ssh",   "product": "OpenSSH", "version": "7.9"},
                3306: {"state": "open", "name": "mysql", "product": "MySQL",   "version": "8.0"},
            },
        },
        "10.0.0.2": {
            "hostnames": [{"name": "workstation-1", "type": "PTR"}],
            "status": {"state": "up"},
            "osmatch": [{"name": "Windows 10", "accuracy": "90"}],
            "tcp": {
                80:  {"state": "open", "name": "http",  "product": "Apache", "version": "2.4"},
                443: {"state": "open", "name": "https", "product": "Apache", "version": "2.4"},
            },
        },
        "10.0.0.3": {
            "hostnames": [],
            "status": {"state": "up"},
            "osmatch": [],
            "tcp": {
                9100: {"state": "open", "name": "jetdirect", "product": "HP JetDirect", "version": ""},
            },
        },
    }


@pytest.fixture
def mock_threat_api_responses():
    """
    Pre-baked threat API responses for the 3 test IPs.
    Composite scores match what aggregator.py would produce with 40/40/20 weighting.
    """
    return {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "abuseipdb_score": 8.5,
            "virustotal_score": 9.0,
            "otx_score": 7.0,
            "composite_score": 8.6,   # (8.5×0.4) + (9.0×0.4) + (7.0×0.2)
        },
        "10.0.0.2": {
            "ip": "10.0.0.2",
            "abuseipdb_score": 2.0,
            "virustotal_score": 1.5,
            "otx_score": 1.0,
            "composite_score": 1.8,
        },
        "10.0.0.3": {
            "ip": "10.0.0.3",
            "abuseipdb_score": 3.0,
            "virustotal_score": 2.5,
            "otx_score": 2.0,
            "composite_score": 2.6,
        },
    }


@pytest.fixture
def flask_test_client(in_memory_db):
    """
    Provide a Flask test client wired to the in-memory DB.
    FIX 4 — create_app() now accepts testing=True and db_session=.
    """
    from main import create_app
    app = create_app(testing=True, db_session=in_memory_db)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ===========================================================================
# TASK 2 — Scanner → Aggregator handoff
# ===========================================================================

class TestScannerToAggregator:
    """Scanner parsed output must be accepted correctly by the Aggregator."""

    def test_scanner_output_feeds_aggregator(self, mock_nmap_output):
        """
        Parsed scanner assets (list of dicts) must match the shape that
        get_composite_threat_score() expects: each item has 'ip_address'.
        """
        # FIX 1 — use the local helper instead of the non-existent parse_scan_results()
        from threat_intel.aggregator import get_composite_threat_score

        assets = _parse_mock_nmap_output(mock_nmap_output)

        # Every asset must carry an ip_address key
        for asset in assets:
            assert "ip_address" in asset, f"Missing ip_address in asset: {asset}"

        # Aggregator must accept each IP without raising
        with patch("threat_intel.aggregator.query_abuseipdb") as mock_abuse, \
             patch("threat_intel.aggregator.query_virustotal")  as mock_vt,   \
             patch("threat_intel.aggregator.query_otx")         as mock_otx:

            mock_abuse.return_value = {"abuseConfidenceScore": 50}
            mock_vt.return_value    = {"last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 60}}
            mock_otx.return_value   = {"pulse_info": {"count": 10}}

            for asset in assets:
                result = get_composite_threat_score(asset["ip_address"])
                assert "composite_score" in result
                assert isinstance(result["composite_score"], float)

    def test_criticality_assigned_before_aggregator(self, mock_nmap_output):
        """Assets leaving the scanner must already carry a criticality_score."""
        # FIX 1 — _parse_mock_nmap_output() calls assign_criticality() internally
        assets = _parse_mock_nmap_output(mock_nmap_output)

        for asset in assets:
            assert "criticality_score" in asset
            assert 1 <= asset["criticality_score"] <= 10

    def test_high_risk_ports_drive_high_criticality(self, mock_nmap_output):
        """10.0.0.1 has SSH + MySQL open — must score 8–10."""
        # FIX 1b — assign_criticality() takes a list of port ints, not an asset dict
        from scanner.asset_scanner import assign_criticality

        assets = _parse_mock_nmap_output(mock_nmap_output)
        server = next(a for a in assets if a["ip_address"] == "10.0.0.1")

        # Re-derive the open port list from the comma-separated string
        open_ports = [int(p) for p in server["open_ports"].split(",") if p]
        score = assign_criticality(open_ports)

        assert score >= 8


# ===========================================================================
# TASK 3 — Aggregator → Risk Engine handoff
# ===========================================================================

class TestAggregatorToRiskEngine:
    """Composite threat score dict from aggregator must feed correctly into risk engine."""

    def test_composite_score_feeds_compute_risk(self, mock_threat_api_responses):
        from engine.risk_engine import compute_risk

        for ip, threat in mock_threat_api_responses.items():
            composite   = threat["composite_score"]
            criticality = 7  # fixed test criticality

            # FIX 2 — compute_risk() returns a dict, not a tuple
            result = compute_risk(criticality, composite)
            score  = result["composite_score"]
            label  = result["severity_label"]

            assert isinstance(score, (int, float))
            assert label in ("Low", "Medium", "High")

    def test_high_threat_high_criticality_yields_high_label(self, mock_threat_api_responses):
        from engine.risk_engine import compute_risk

        threat = mock_threat_api_responses["10.0.0.1"]  # composite ≈ 8.6

        # FIX 2
        result = compute_risk(9, threat["composite_score"])
        label  = result["severity_label"]

        assert label == "High"

    def test_low_threat_low_criticality_yields_low_label(self, mock_threat_api_responses):
        from engine.risk_engine import compute_risk

        threat = mock_threat_api_responses["10.0.0.2"]  # composite ≈ 1.8

        # FIX 2
        result = compute_risk(2, threat["composite_score"])
        label  = result["severity_label"]

        assert label == "Low"

    def test_score_range_is_valid(self, mock_threat_api_responses):
        from engine.risk_engine import compute_risk

        for _, threat in mock_threat_api_responses.items():
            # FIX 2
            result = compute_risk(5, threat["composite_score"])
            score  = result["composite_score"]

            assert 0 <= score <= 100, f"Risk score out of range: {score}"


# ===========================================================================
# TASK 4 — Risk Engine → DB (save_alerts_to_db)
# ===========================================================================

class TestRiskEngineToDb:
    """Alerts produced by the engine must persist correctly to the database."""

    def test_alerts_saved_to_db(self, in_memory_db, mock_threat_api_responses):
        from engine.alert_engine import generate_alerts
        from db.database import save_alerts_to_db
        from db.models import RiskAlert

        assets = [
            {"ip_address": "10.0.0.1", "hostname": "server-1",     "criticality_score": 9},
            {"ip_address": "10.0.0.2", "hostname": "workstation-1", "criticality_score": 3},
            {"ip_address": "10.0.0.3", "hostname": "printer-1",     "criticality_score": 1},
        ]

        alerts = generate_alerts(assets, mock_threat_api_responses)

        # FIX 3 — pass session= kwarg (save_alerts_to_db now accepts session=None)
        save_alerts_to_db(alerts, session=in_memory_db)

        saved = in_memory_db.query(RiskAlert).all()
        assert len(saved) == len(alerts)

    def test_saved_alert_fields_correct(self, in_memory_db, mock_threat_api_responses):
        from engine.alert_engine import generate_alerts
        from db.database import save_alerts_to_db
        from db.models import RiskAlert

        assets = [{"ip_address": "10.0.0.1", "hostname": "server-1", "criticality_score": 9}]
        alerts = generate_alerts(assets, mock_threat_api_responses)

        # FIX 3
        save_alerts_to_db(alerts, session=in_memory_db)

        record = in_memory_db.query(RiskAlert).first()
        assert record.asset_ip == "10.0.0.1"
        assert record.risk_score is not None
        assert record.severity_label in ("Low", "Medium", "High")

    def test_upsert_does_not_duplicate(self, in_memory_db, mock_threat_api_responses):
        """Re-saving the same IP should update, not insert a second row."""
        from engine.alert_engine import generate_alerts
        from db.database import save_alerts_to_db
        from db.models import RiskAlert

        assets = [{"ip_address": "10.0.0.1", "hostname": "server-1", "criticality_score": 9}]
        alerts = generate_alerts(assets, mock_threat_api_responses)

        # FIX 3
        save_alerts_to_db(alerts, session=in_memory_db)
        save_alerts_to_db(alerts, session=in_memory_db)  # second save

        count = in_memory_db.query(RiskAlert).filter_by(asset_ip="10.0.0.1").count()
        assert count == 1, "Upsert should not create duplicate rows"

    def test_alerts_sorted_by_risk_score_in_db(self, in_memory_db, mock_threat_api_responses):
        from engine.alert_engine import generate_alerts, sort_alerts
        from db.database import save_alerts_to_db
        from db.models import RiskAlert

        assets = [
            {"ip_address": ip, "hostname": f"host-{i}", "criticality_score": cs}
            for i, (ip, cs) in enumerate([
                ("10.0.0.1", 9), ("10.0.0.2", 3), ("10.0.0.3", 1)
            ])
        ]
        alerts = sort_alerts(generate_alerts(assets, mock_threat_api_responses))

        # FIX 3
        save_alerts_to_db(alerts, session=in_memory_db)

        saved  = in_memory_db.query(RiskAlert).order_by(RiskAlert.risk_score.desc()).all()
        scores = [r.risk_score for r in saved]
        assert scores == sorted(scores, reverse=True)


# ===========================================================================
# TASK 5 — Flask API reads from DB and returns correct JSON
# ===========================================================================

class TestFlaskApiFromDb:
    """Flask endpoints must read from DB and return correctly shaped JSON."""

    def test_get_alerts_returns_200(self, flask_test_client):
        response = flask_test_client.get("/api/alerts")
        assert response.status_code == 200

    def test_get_alerts_returns_json(self, flask_test_client):
        response = flask_test_client.get("/api/alerts")
        data = json.loads(response.data)
        assert "status" in data
        assert "data" in data

    def test_get_assets_returns_200(self, flask_test_client):
        response = flask_test_client.get("/api/assets")
        assert response.status_code == 200

    def test_get_stats_returns_summary_keys(self, flask_test_client):
        response = flask_test_client.get("/api/stats")
        data  = json.loads(response.data)
        stats = data.get("data", data)
        expected_keys = {"total_assets", "high_alerts", "avg_risk_score"}
        assert expected_keys.issubset(stats.keys()), \
            f"Missing keys: {expected_keys - set(stats.keys())}"

    def test_get_alerts_by_severity_high(self, flask_test_client):
        response = flask_test_client.get("/api/alerts/High")
        assert response.status_code == 200
        data   = json.loads(response.data)
        alerts = data.get("data", [])
        for alert in alerts:
            assert alert["severity_label"] == "High"

    def test_get_alerts_by_severity_invalid(self, flask_test_client):
        response = flask_test_client.get("/api/alerts/Unknown")
        assert response.status_code in (400, 404)

    def test_alerts_sorted_by_risk_score_descending(self, flask_test_client, in_memory_db):
        """Seed DB then confirm API returns alerts highest-first."""
        from db.models import RiskAlert

        # Seed 3 alerts with known scores.
        # alert_id omitted — it's autoincrement Integer; passing a string
        # causes sqlite3.IntegrityError: datatype mismatch.
        # asset_criticality is Float in the model so pass 9.0 not 9.
        from datetime import timezone as tz
        now = datetime.now(tz.utc)
        for ip, score, label in [
            ("10.0.0.10", 81.0, "High"),
            ("10.0.0.11", 25.0, "Low"),
            ("10.0.0.12", 49.0, "Medium"),
        ]:
            alert = RiskAlert(
                asset_ip=ip,
                risk_score=score,
                severity_label=label,
                asset_criticality=9.0,
                threat_severity=9.0,
                acknowledged=False,
                created_at=now,
                updated_at=now,
            )
            in_memory_db.add(alert)
        in_memory_db.commit()

        response = flask_test_client.get("/api/alerts")
        data     = json.loads(response.data)
        alerts   = data.get("data", [])
        scores   = [a["risk_score"] for a in alerts]
        assert scores == sorted(scores, reverse=True), "API must return alerts sorted high → low"