"""
profiler.py
-----------
Day 41 — Task 1 & 2: Pipeline Profiler
Measures total execution time and identifies bottlenecks across:
  - Nmap scan
  - AbuseIPDB API calls
  - VirusTotal API calls
  - AlienVault OTX API calls
  - Risk score calculation
  - DB writes

Usage:
    python profiler.py

Output: profiler_results.txt (for Chapter 4 documentation)
"""

import time
import json
from datetime import datetime, timezone
from contextlib import contextmanager

# ── Timing context manager ────────────────────────────────────────────────
@contextmanager
def timer(label, results_dict):
    start = time.perf_counter()
    yield
    elapsed = time.perf_counter() - start
    results_dict[label] = round(elapsed, 4)
    print(f"  [PROFILE] {label:<40} {elapsed:.4f}s")


def run_profile(subnet="192.168.100.0/24", test_ips=None):
    """
    Profiles the full pipeline end-to-end.
    Uses real modules from your project.
    """
    timings   = {}
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print("\n" + "="*60)
    print("  IP Risk Profiler — Pipeline Performance Profiler")
    print("="*60)
    print(f"  Started : {timestamp}")
    print(f"  Subnet  : {subnet}")
    print("="*60 + "\n")

    # ── STAGE 1: Nmap Scan ────────────────────────────────────────────────
    print("[STAGE 1] Asset Discovery (Nmap)")
    from scanner.asset_scanner import scan_subnet, save_assets_to_db

    with timer("Nmap scan", timings):
        assets = scan_subnet(subnet)

    print(f"  → Found {len(assets)} asset(s)\n")

    if not assets:
        print("[PROFILER] No assets found — using mock data for API profiling.")
        assets = [
            {"ip_address": ip, "criticality_score": 5, "hostname": f"host-{i}"}
            for i, ip in enumerate(test_ips or ["8.8.8.8", "1.1.1.1"])
        ]

    # ── STAGE 2: DB write — assets ────────────────────────────────────────
    print("[STAGE 2] DB Write — Assets")
    with timer("DB write (assets)", timings):
        save_assets_to_db(assets)
    print()

    # ── STAGE 3: Threat Intel API calls (ASYNC)
    print("[STAGE 3] Threat Intel — Concurrent API calls")

    from threat_intel.async_aggregator import get_composite_scores_batch

    sample_ips = [a["ip_address"] for a in assets[:10]]

    with timer("Concurrent threat intelligence", timings):
        threat_results = get_composite_scores_batch(sample_ips, max_workers=5)

    print()
    # ── STAGE 4: Risk Score Calculation ───────────────────────────────────
    print("[STAGE 4] Risk Score Calculation")
    from engine.risk_engine import compute_risk

    mock_threats = {
    ip: result["composite_score"]
    for ip, result in threat_results.items()
}

    with timer("Risk score calculation (all assets)", timings):
        for asset in assets:
            compute_risk(asset.get("criticality_score", 1), 5.0)
    print()

    # ── STAGE 5: Alert Generation ─────────────────────────────────────────
    print("[STAGE 5] Alert Generation")
    from engine.alert_engine import generate_alerts

    with timer("Alert generation", timings):
        alerts = generate_alerts(assets, mock_threats)
    print()

    # ── STAGE 6: DB write — alerts ────────────────────────────────────────
    print("[STAGE 6] DB Write — Alerts")
    from db.database import save_alerts_to_db

    with timer("DB write (alerts)", timings):
        save_alerts_to_db(alerts)
    print()

    # ── BOTTLENECK ANALYSIS ───────────────────────────────────────────────
    print("\n" + "="*60)
    print("  BOTTLENECK ANALYSIS")
    print("="*60)

    sorted_timings = sorted(
        {k: v for k, v in timings.items()}.items(),
        key=lambda x: x[1], reverse=True
    )
    total_pipeline = sum([
        timings.get("Nmap scan", 0),
        timings.get("Concurrent threat intelligence", 0),
        timings.get("DB write (assets)", 0),
        timings.get("DB write (alerts)", 0),
        timings.get("Risk score calculation (all assets)", 0),
        timings.get("Alert generation", 0),
    ])

    for label, t in sorted_timings:
        bar = "█" * int((t / max(v for _, v in sorted_timings)) * 30)
        print(f"  {label:<45} {t:>7.4f}s  {bar}")

    print(f"\n  TOTAL PIPELINE TIME: {total_pipeline:.4f}s")
    print(f"  IPs profiled       : {len(sample_ips)}")
    print(f"  PRIMARY BOTTLENECK : {sorted_timings[0][0]}")

    # ── Write results to file ─────────────────────────────────────────────
    report = {
        "timestamp":       timestamp,
        "subnet":          subnet,
        "ips_profiled":    len(sample_ips),
        "assets_found":    len(assets),
        "timings":         timings,
        "total_pipeline":  round(total_pipeline, 4),
        "primary_bottleneck": sorted_timings[0][0],
    }

    with open("profiler_results.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  Results saved → profiler_results.json")
    print("="*60 + "\n")

    return report


if __name__ == "__main__":
    run_profile()