"""
threat_intel/aggregator.py
--------------------------
Threat Intelligence Aggregator — central score calculator.

This is the most important module in the threat intel layer.
It calls all 3 APIs (AbuseIPDB, VirusTotal, AlienVault OTX),
collects their individual scores, and computes one composite
threat score for use by the Risk Correlation Engine.

Weighted average:
  AbuseIPDB  : 40%  — community abuse reports (most reliable for malicious IPs)
  VirusTotal : 40%  — antivirus engine detections (most reliable for malware)
  OTX        : 20%  — threat intelligence pulses (useful but lower signal)
"""

import time
from datetime import datetime, timezone
import json
import ipaddress  # 👈 ADDED HERE: For local network filtering

# your threat modules
from threat_intel.abuseipdb  import query_ip as query_abuseipdb,  normalise_abuseipdb
from threat_intel.virustotal import query_ip as query_virustotal, normalise_virustotal
from threat_intel.alienvault import query_ip as query_otx,        normalise_alienvault
from db.database import get_session
from db.models import ThreatRecord

# ── Weights — must sum to 1.0 ─────────────────────────────────────────────
WEIGHT_ABUSEIPDB  = 0.40
WEIGHT_VIRUSTOTAL = 0.40
WEIGHT_OTX        = 0.20


# ── 1. ADDED HERE: Helper function to detect local vs public IPs ──────────
def is_public_ip(ip_str):
    """Returns True if the IP is a routable public IP; False if it is a private LAN IP."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not ip.is_private
    except ValueError:
        return False


# ── Main Function: Get Composite Threat Score ─────────────────────────────
def get_composite_threat_score(ip_address):
    """
    Queries all 3 threat intelligence APIs for one IP address and
    returns a single composite threat score plus individual scores.
    """
    print(f"\n[AGGREGATOR] Analysing IP: {ip_address}")
    print(f"[AGGREGATOR] Querying 3 threat intelligence APIs...")

    raw_results = {}

    # ── Step 1: Query AbuseIPDB ───────────────────────────────────────────
    print(f"[AGGREGATOR] 1/3 AbuseIPDB...")
    abuseipdb_raw    = query_abuseipdb(ip_address)
    abuseipdb_score  = normalise_abuseipdb(abuseipdb_raw)
    raw_results["abuseipdb"] = abuseipdb_raw
    time.sleep(1)   # small delay between API calls

    # ── Step 2: Query VirusTotal ──────────────────────────────────────────
    print(f"[AGGREGATOR] 2/3 VirusTotal...")
    virustotal_raw   = query_virustotal(ip_address)
    virustotal_score = normalise_virustotal(
        {
            "malicious_count":  virustotal_raw.get("malicious_count",  0),
            "suspicious_count": virustotal_raw.get("suspicious_count", 0),
            "harmless_count":   virustotal_raw.get("harmless_count",   0),
            "total_engines":    virustotal_raw.get("total_engines",    0),
            "reputation":       virustotal_raw.get("reputation",       0),
        } if virustotal_raw else None
    )
    raw_results["virustotal"] = virustotal_raw
    time.sleep(1)

    # ── Step 3: Query AlienVault OTX (MODIFIED WITH LOCAL FILTER) ─────────
    print(f"[AGGREGATOR] 3/3 AlienVault OTX...")
    
    if is_public_ip(ip_address):
        # Proceed with normal API call if it's an external public threat source
        otx_raw   = query_otx(ip_address)
        otx_score = normalise_alienvault(
            {
                "pulse_count":      otx_raw.get("pulse_count",      0),
                "tags":             otx_raw.get("tags",             []),
                "malware_families": otx_raw.get("malware_families", []),
                "reputation":       otx_raw.get("reputation",       0),
            } if otx_raw else None
        )
        raw_results["otx"] = otx_raw
    else:
        # 👈 CHOSEN PLACEMENT: Safety fallback for local LAN targets (192.168.1.1, etc.)
        print(f"[OTX SKIP] {ip_address} is a local LAN asset. Skipping global threat query.")
        otx_score = 1.0  # Assign baseline minimum reputation risk score
        raw_results["otx"] = {"message": "Skipped global API lookups for private LAN address space."}

    # ── Step 4: Compute weighted composite score ──────────────────────────
    composite_score = _compute_weighted_average(
        abuseipdb_score,
        virustotal_score,
        otx_score
    )

    # ── Step 5: Assign severity label ────────────────────────────────────
    severity_label = _get_severity_label(composite_score)

    # Count how many APIs succeeded
    apis_succeeded = sum(1 for s in [abuseipdb_score, virustotal_score, otx_score]
                         if s is not None)

    result = {
        "ip":               ip_address,
        "abuseipdb_score":  abuseipdb_score,
        "virustotal_score": virustotal_score,
        "otx_score":        otx_score,
        "composite_score":  composite_score,
        "severity_label":   severity_label,
        "apis_succeeded":   apis_succeeded,
        "queried_at":       datetime.now(timezone.utc).isoformat(),
        "raw":              raw_results,
    }

    _print_summary(result)
    return result


# ── Helper: Weighted Average ──────────────────────────────────────────────
def _compute_weighted_average(abuseipdb_score, virustotal_score, otx_score):
    scores_and_weights = [
        (abuseipdb_score,  WEIGHT_ABUSEIPDB),
        (virustotal_score, WEIGHT_VIRUSTOTAL),
        (otx_score,        WEIGHT_OTX),
    ]

    # Filter out any None scores (failed API calls)
    valid = [(score, weight) for score, weight in scores_and_weights
             if score is not None]

    if not valid:
        # All 3 APIs failed — default to minimum risk
        print("[AGGREGATOR] WARNING: All 3 APIs failed. Defaulting composite to 1.0")
        return 1.0

    # Rebalance weights to sum to 1.0
    total_weight = sum(w for _, w in valid)
    weighted_sum = sum(score * (weight / total_weight)
                       for score, weight in valid)

    return round(max(1.0, min(10.0, weighted_sum)), 2)


# ── Helper: Severity Label ────────────────────────────────────────────────
def _get_severity_label(composite_score):
    if composite_score >= 7.0:
        return "High"
    elif composite_score >= 4.0:
        return "Medium"
    else:
        return "Low"


# ── Helper: Print Summary ─────────────────────────────────────────────────
def _print_summary(result):
    score = result["composite_score"]
    label = result["severity_label"]

    if label == "High":
        indicator = "⚠  HIGH"
    elif label == "Medium":
        indicator = "~  MEDIUM"
    else:
        indicator = "✓  LOW"

    print(f"\n[AGGREGATOR] ── Results for {result['ip']} ──")
    print(f"  AbuseIPDB  (40%) : {result['abuseipdb_score']  or 'FAILED'}")
    print(f"  VirusTotal (40%) : {result['virustotal_score'] or 'FAILED'}")
    print(f"  OTX        (20%) : {result['otx_score']        or 'FAILED'}")
    print(f"  ─────────────────────────────────")
    print(f"  Composite Score  : {score}/10   [{indicator}]")
    print(f"  APIs Succeeded   : {result['apis_succeeded']}/3")
    print()


# ── Run directly to test ──────────────────────────────────────────────────
if __name__ == "__main__":

    # Day 13 Test Batch (5 IPs including your loopback, public IP, and threat cases)
    TEST_IPS = [
        "127.0.0.1",       # Loopback
        "129.222.187.29",  # Your current Public IP
        "8.8.8.8",         # Google DNS
        "1.1.1.1",         # Cloudflare DNS
        "185.220.101.1",   # Tor exit node — expect HIGH composite
    ]

    print("\n" + "="*60)
    print("  Threat Intelligence Aggregator — Integration Storage Test")
    print("="*60)
    print(f"  Testing {len(TEST_IPS)} IPs across AbuseIPDB + VirusTotal + OTX")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("="*60)

    all_results = []
    
    for ip in TEST_IPS:
        result = get_composite_threat_score(ip)
        all_results.append(result)
        
        session = get_session()
        try:
            new_record = ThreatRecord(
                ip_address     = result["ip"],
                source_api     = "aggregated_pipeline",
                severity_score = result["composite_score"],
                details_json   = json.dumps({
                    "abuseipdb_score":  result["abuseipdb_score"],
                    "virustotal_score": result["virustotal_score"],
                    "otx_score":        result["otx_score"],
                    "apis_succeeded":   result["apis_succeeded"]
                }),
                queried_at     = datetime.now(timezone.utc)
            )
            
            session.add(new_record)
            session.commit()
            print(f"[DB SUCCESS] Archived ThreatRecord for {ip} into dev.db.")
            
        except Exception as e:
            session.rollback()
            print(f"[DB ERROR] Failed to save record for {ip}: {e}")
            
        finally:
            session.close()
            
        time.sleep(2)

    # ── Final summary table ───────────────────────────────────────────────
    print("\n" + "="*60)
    print("  FINAL COMPOSITE SCORES (SAVED TO DATABASE)")
    print("="*60)
    print(f"  {'IP':<20} {'AbuseIPDB':>10} {'VT':>8} {'OTX':>8} {'COMPOSITE':>12} {'LABEL':>8}")
    print("  " + "-"*58)
    for r in all_results:
        ab  = f"{r['abuseipdb_score']:.1f}"  if r['abuseipdb_score']  else "FAIL"
        vt  = f"{r['virustotal_score']:.1f}" if r['virustotal_score'] else "FAIL"
        otx = f"{r['otx_score']:.1f}"        if r['otx_score']        else "FAIL"
        print(f"  {r['ip']:<20} {ab:>10} {vt:>8} {otx:>8} {r['composite_score']:>12} {r['severity_label']:>8}")
    print("="*60 + "\n")