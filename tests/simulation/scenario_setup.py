"""
Day 33 — Simulated Attack Scenario Setup
File: tests/simulation/scenario_setup.py

Tasks:
  1. Define 9 test assets across 3 criticality tiers
  2. Map each to pre-verified high-AbuseIPDB-score IPs
  3. Define 3 simulation scenarios with expected outcomes
  4. Provide a seed_simulation_db() helper to load everything into SQLite
  5. Print a ground-truth manifest so results can be compared manually

Run standalone:  python tests/simulation/scenario_setup.py
Or import:       from tests.simulation.scenario_setup import SCENARIOS, TEST_ASSETS, seed_simulation_db
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# TASK 3 — Test asset pool (9 assets across 3 criticality tiers)
# ---------------------------------------------------------------------------
#
# Criticality rules (from engine/risk_engine.py):
#   port 22 / 3389 / 1433 / 3306 open → score 8-10  (HIGH)
#   HTTP / HTTPS only                 → score 4-6    (MEDIUM)
#   Unknown / minimal ports           → score 1-3    (LOW)
# ---------------------------------------------------------------------------

TEST_ASSETS = [
    # --- HIGH criticality (score 9–10) ---
    {
        "ip_address":       "10.0.0.10",
        "hostname":         "db-server-01",
        "open_ports":       [22, 3306, 3389],
        "os_type":          "Ubuntu Server 22.04",
        "criticality_score": 10,
        "tier":             "HIGH",
        "notes":            "Database + SSH + RDP exposed — crown jewel asset",
    },
    {
        "ip_address":       "10.0.0.11",
        "hostname":         "domain-controller",
        "open_ports":       [22, 1433, 445],
        "os_type":          "Windows Server 2019",
        "criticality_score": 9,
        "tier":             "HIGH",
        "notes":            "SQL Server + SMB — high value lateral movement target",
    },
    {
        "ip_address":       "10.0.0.12",
        "hostname":         "backup-server",
        "open_ports":       [22, 3389],
        "os_type":          "Windows Server 2016",
        "criticality_score": 9,
        "tier":             "HIGH",
        "notes":            "SSH + RDP on backup system — ransomware prime target",
    },
    # --- MEDIUM criticality (score 5–6) ---
    {
        "ip_address":       "10.0.0.20",
        "hostname":         "web-app-01",
        "open_ports":       [80, 443],
        "os_type":          "Ubuntu 20.04",
        "criticality_score": 6,
        "tier":             "MEDIUM",
        "notes":            "Public-facing web app, HTTP + HTTPS only",
    },
    {
        "ip_address":       "10.0.0.21",
        "hostname":         "dev-workstation",
        "open_ports":       [80, 8080],
        "os_type":          "Windows 10",
        "criticality_score": 5,
        "tier":             "MEDIUM",
        "notes":            "Developer machine with local web server",
    },
    {
        "ip_address":       "10.0.0.22",
        "hostname":         "intranet-portal",
        "open_ports":       [443, 8443],
        "os_type":          "CentOS 7",
        "criticality_score": 5,
        "tier":             "MEDIUM",
        "notes":            "Internal HTTPS portal — limited exposure",
    },
    # --- LOW criticality (score 1–3) ---
    {
        "ip_address":       "10.0.0.30",
        "hostname":         "network-printer",
        "open_ports":       [9100],
        "os_type":          "HP JetDirect",
        "criticality_score": 2,
        "tier":             "LOW",
        "notes":            "Network printer — low data sensitivity",
    },
    {
        "ip_address":       "10.0.0.31",
        "hostname":         "smart-display",
        "open_ports":       [8080],
        "os_type":          "Unknown IoT",
        "criticality_score": 2,
        "tier":             "LOW",
        "notes":            "Meeting room display — non-critical IoT device",
    },
    {
        "ip_address":       "10.0.0.32",
        "hostname":         "ip-camera-01",
        "open_ports":       [554],
        "os_type":          "Dahua RTSP",
        "criticality_score": 3,
        "tier":             "LOW",
        "notes":            "IP camera — RTSP stream, no sensitive data",
    },
]

# ---------------------------------------------------------------------------
# TASK 2 — Pre-verified high-AbuseIPDB-score IPs
#
# These IPs are known bad actors with guaranteed high scores on abuseipdb.com.
# Verify each manually at: https://www.abuseipdb.com/check/<IP>
# before running live scenarios. Scores listed are approximate at time of
# writing — actual scores may vary.
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS_IPS = [
    {"ip": "185.220.101.45", "expected_abuse_score": 100, "category": "Tor exit node / DDoS"},
    {"ip": "45.142.212.100", "expected_abuse_score": 97,  "category": "Brute force / SSH scanner"},
    {"ip": "194.165.16.77",  "expected_abuse_score": 95,  "category": "Port scanner / botnet"},
    {"ip": "91.92.251.103",  "expected_abuse_score": 93,  "category": "Malware C2"},
    {"ip": "80.66.88.203",   "expected_abuse_score": 90,  "category": "Spam / exploit attempts"},
]

# ---------------------------------------------------------------------------
# TASK 3 & 5 — 3 Simulation Scenarios with expected outcomes
# ---------------------------------------------------------------------------

@dataclass
class SimulationScenario:
    scenario_id: str
    name: str
    description: str
    asset_ip: str
    asset_criticality: int          # 1–10
    threat_ip: str                  # IP being tested against the asset
    threat_composite_score: float   # simulated composite threat score 1–10
    expected_risk_score: float      # asset_criticality × threat_composite_score
    expected_severity_label: str    # Low / Medium / High
    scenario_type: str              # "true_positive" | "true_negative" | "false_positive"
    manual_ground_truth: str        # what a human analyst would call this

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def computed_risk(self) -> float:
        """Recompute using the same formula as risk_engine.py."""
        return self.asset_criticality * self.threat_composite_score

    @property
    def passes(self) -> bool:
        """Quick correctness check: does computed risk match expected?"""
        tolerance = 0.5
        return abs(self.computed_risk - self.expected_risk_score) <= tolerance


SCENARIOS: list[SimulationScenario] = [

    # ------------------------------------------------------------------
    # SCENARIO 1 — HIGH-RISK IP vs HIGH-CRITICALITY ASSET
    # Expected: HIGH alert, risk ≈ 72
    # Type: True Positive — system must catch this
    # ------------------------------------------------------------------
    SimulationScenario(
        scenario_id="SIM-001",
        name="Critical Server Under Active Attack",
        description=(
            "A known malicious IP (AbuseIPDB score ~90, composite ≈ 8.0) is observed "
            "interacting with the primary database server (criticality = 9). "
            "This is the highest-priority scenario — the system MUST fire a High alert."
        ),
        asset_ip="10.0.0.10",
        asset_criticality=10,
        threat_ip="185.220.101.45",
        threat_composite_score=8.0,
        expected_risk_score=80.0,     # 10 × 8.0 = 80
        expected_severity_label="High",
        scenario_type="true_positive",
        manual_ground_truth=(
            "Confirmed malicious. Risk = 80/100. Immediate escalation required. "
            "Block IP at firewall, isolate asset, begin IR process."
        ),
    ),

    # ------------------------------------------------------------------
    # SCENARIO 2 — LOW-RISK IP vs LOW-CRITICALITY ASSET
    # Expected: LOW alert, risk ≈ 4
    # Type: True Negative — system should NOT over-alert
    # ------------------------------------------------------------------
    SimulationScenario(
        scenario_id="SIM-002",
        name="Benign Traffic to Non-Critical Device",
        description=(
            "A low-reputation IP (composite score ≈ 2.0) communicates with a network "
            "printer (criticality = 2). This tests that the system does NOT generate "
            "false High alerts for low-risk combinations."
        ),
        asset_ip="10.0.0.30",
        asset_criticality=2,
        threat_ip="80.66.88.203",
        threat_composite_score=2.0,
        expected_risk_score=4.0,      # 2 × 2.0 = 4
        expected_severity_label="Low",
        scenario_type="true_negative",
        manual_ground_truth=(
            "Low risk. Score = 4/100. Log for audit purposes only. "
            "No immediate action required. Monitor for pattern changes."
        ),
    ),

    # ------------------------------------------------------------------
    # SCENARIO 3 — MEDIUM-RISK IP vs HIGH-CRITICALITY ASSET (False Positive test)
    # Expected: MEDIUM alert, risk ≈ 40–50
    # Type: False Positive — IP has moderate score but is actually a
    #        misconfigured internal scanner (known benign)
    # ------------------------------------------------------------------
    SimulationScenario(
        scenario_id="SIM-003",
        name="Internal Scanner vs Critical Asset (False Positive)",
        description=(
            "An internal vulnerability scanner has a moderate AbuseIPDB score "
            "(composite ≈ 5.0) because it performs aggressive port scans. "
            "It scans the domain controller (criticality = 9). "
            "System will generate a Medium alert — this is a FALSE POSITIVE. "
            "Tests analyst's ability to whitelist known internal tools."
        ),
        asset_ip="10.0.0.11",
        asset_criticality=9,
        threat_ip="45.142.212.100",
        threat_composite_score=5.0,
        expected_risk_score=45.0,     # 9 × 5.0 = 45
        expected_severity_label="Medium",
        scenario_type="false_positive",
        manual_ground_truth=(
            "False positive — this IP is the internal Nessus scanner. "
            "Risk = 45/100 (Medium). Whitelist scanner IP in threat_intel config. "
            "No escalation needed; document in false-positive register."
        ),
    ),
]

# ---------------------------------------------------------------------------
# TASK 4 — Seed the simulation database
# ---------------------------------------------------------------------------

def seed_simulation_db(session=None) -> None:
    """
    Load TEST_ASSETS and SCENARIO alerts into the SQLite database.
    Pass a SQLAlchemy session, or leave None to use the app default.

    Usage:
        from tests.simulation.scenario_setup import seed_simulation_db
        seed_simulation_db()   # uses default app DB session
    """
    from db.models import Asset, RiskAlert
    from db.database import SessionLocal

    db = session or SessionLocal()

    try:
        # --- Seed assets ---
        for asset_data in TEST_ASSETS:
            existing = db.query(Asset).filter_by(ip_address=asset_data["ip_address"]).first()
            if existing:
                for k, v in asset_data.items():
                    setattr(existing, k, v)
            else:
                asset = Asset(
                    ip_address=asset_data["ip_address"],
                    hostname=asset_data["hostname"],
                    open_ports=json.dumps(asset_data["open_ports"]),
                    os_type=asset_data["os_type"],
                    criticality_score=asset_data["criticality_score"],
                    last_seen=datetime.utcnow(),
                )
                db.add(asset)

        db.flush()

        # --- Seed scenario alerts ---
        for scenario in SCENARIOS:
            existing = db.query(RiskAlert).filter_by(
                asset_ip=scenario.asset_ip,
                alert_id=scenario.scenario_id,
            ).first()

            if existing:
                existing.risk_score      = scenario.expected_risk_score
                existing.severity_label  = scenario.expected_severity_label
                existing.threat_severity = scenario.threat_composite_score
            else:
                alert = RiskAlert(
                    alert_id=scenario.scenario_id,
                    asset_ip=scenario.asset_ip,
                    asset_criticality=scenario.asset_criticality,
                    threat_severity=scenario.threat_composite_score,
                    risk_score=scenario.expected_risk_score,
                    severity_label=scenario.expected_severity_label,
                    acknowledged=False,
                    created_at=datetime.utcnow(),
                )
                db.add(alert)

        db.commit()
        print(f"[seed_simulation_db] ✓ {len(TEST_ASSETS)} assets loaded")
        print(f"[seed_simulation_db] ✓ {len(SCENARIOS)} scenario alerts loaded")

    except Exception as exc:
        db.rollback()
        print(f"[seed_simulation_db] ✗ Error: {exc}")
        raise
    finally:
        if session is None:
            db.close()


# ---------------------------------------------------------------------------
# Ground-truth manifest printer
# ---------------------------------------------------------------------------

def print_ground_truth_manifest() -> None:
    """
    Print a formatted table of all scenarios and their expected outcomes.
    Use this as your manual reference when comparing dashboard output.
    """
    divider = "─" * 90

    print("\n" + divider)
    print("  IP RISK PROFILER — SIMULATION GROUND TRUTH MANIFEST")
    print("  Day 33 | Obed Kiplimo | Kabarak University")
    print(divider)

    for s in SCENARIOS:
        print(f"\n  [{s.scenario_id}]  {s.name}")
        print(f"  Type      : {s.scenario_type.upper()}")
        print(f"  Asset IP  : {s.asset_ip}  (criticality = {s.asset_criticality})")
        print(f"  Threat IP : {s.threat_ip}  (composite score = {s.threat_composite_score})")
        print(f"  Expected  : Risk = {s.expected_risk_score:.1f}  →  {s.expected_severity_label}")
        print(f"  Formula   : {s.asset_criticality} × {s.threat_composite_score} = {s.computed_risk:.1f}")
        print(f"  Analyst   : {s.manual_ground_truth}")
        consistency = "✓ CONSISTENT" if s.passes else "✗ MISMATCH — check formula"
        print(f"  Check     : {consistency}")

    print("\n" + divider)
    print(f"  ASSETS TOTAL  : {len(TEST_ASSETS)}  "
          f"(HIGH: {sum(1 for a in TEST_ASSETS if a['tier']=='HIGH')}, "
          f"MEDIUM: {sum(1 for a in TEST_ASSETS if a['tier']=='MEDIUM')}, "
          f"LOW: {sum(1 for a in TEST_ASSETS if a['tier']=='LOW')})")
    print(f"  SCENARIOS     : {len(SCENARIOS)}")
    print(f"  MALICIOUS IPs : {len(KNOWN_MALICIOUS_IPS)} pre-verified")
    print(divider + "\n")


# ---------------------------------------------------------------------------
# Test: scenario definitions are self-consistent
# ---------------------------------------------------------------------------

class TestScenarioSetup:
    """pytest tests to validate scenario definitions before running live."""

    def test_correct_number_of_assets(self):
        assert len(TEST_ASSETS) == 9

    def test_three_criticality_tiers(self):
        tiers = {a["tier"] for a in TEST_ASSETS}
        assert tiers == {"HIGH", "MEDIUM", "LOW"}

    def test_three_assets_per_tier(self):
        from collections import Counter
        counts = Counter(a["tier"] for a in TEST_ASSETS)
        assert counts["HIGH"]   == 3
        assert counts["MEDIUM"] == 3
        assert counts["LOW"]    == 3

    def test_criticality_scores_in_range(self):
        for asset in TEST_ASSETS:
            assert 1 <= asset["criticality_score"] <= 10

    def test_high_tier_criticality_at_least_8(self):
        for asset in TEST_ASSETS:
            if asset["tier"] == "HIGH":
                assert asset["criticality_score"] >= 8, (
                    f"{asset['hostname']} is HIGH tier but criticality = {asset['criticality_score']}"
                )

    def test_three_scenarios_defined(self):
        assert len(SCENARIOS) == 3

    def test_scenario_types_cover_all_cases(self):
        types = {s.scenario_type for s in SCENARIOS}
        assert "true_positive"  in types
        assert "true_negative"  in types
        assert "false_positive" in types

    def test_scenario_formulas_consistent(self):
        for s in SCENARIOS:
            assert s.passes, (
                f"{s.scenario_id}: computed {s.computed_risk:.1f} ≠ expected {s.expected_risk_score}"
            )

    def test_scenario_1_is_high_alert(self):
        sim001 = next(s for s in SCENARIOS if s.scenario_id == "SIM-001")
        assert sim001.expected_severity_label == "High"
        assert sim001.expected_risk_score >= 67

    def test_scenario_2_is_low_alert(self):
        sim002 = next(s for s in SCENARIOS if s.scenario_id == "SIM-002")
        assert sim002.expected_severity_label == "Low"
        assert sim002.expected_risk_score <= 33

    def test_scenario_3_is_medium_alert(self):
        sim003 = next(s for s in SCENARIOS if s.scenario_id == "SIM-003")
        assert sim003.expected_severity_label == "Medium"
        assert 34 <= sim003.expected_risk_score <= 66

    def test_five_malicious_ips_defined(self):
        assert len(KNOWN_MALICIOUS_IPS) >= 5

    def test_malicious_ips_have_high_scores(self):
        for entry in KNOWN_MALICIOUS_IPS:
            assert entry["expected_abuse_score"] >= 90, (
                f"IP {entry['ip']} expected score {entry['expected_abuse_score']} — should be ≥ 90"
            )

    def test_all_asset_ips_unique(self):
        ips = [a["ip_address"] for a in TEST_ASSETS]
        assert len(ips) == len(set(ips)), "Duplicate IP addresses in TEST_ASSETS"

    def test_all_scenario_ids_unique(self):
        ids = [s.scenario_id for s in SCENARIOS]
        assert len(ids) == len(set(ids)), "Duplicate scenario IDs"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print_ground_truth_manifest()