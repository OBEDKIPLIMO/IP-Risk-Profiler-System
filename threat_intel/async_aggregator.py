"""
threat_intel/async_aggregator.py
---------------------------------
Day 41 — Task 3: Optimised Threat Intelligence Aggregator
Uses concurrent.futures.ThreadPoolExecutor to query all 3 APIs
in parallel instead of sequentially.

BEFORE (sequential):  ~9s for 10 IPs (3 APIs × 1s sleep × 10 IPs)
AFTER  (concurrent):  ~3s for 10 IPs (APIs run in parallel per IP)

Drop-in replacement for aggregator.py — same return format.
"""

import time
import json
import ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

from threat_intel.abuseipdb  import query_ip as query_abuseipdb,  normalise_abuseipdb
from threat_intel.virustotal import query_ip as query_virustotal, normalise_virustotal
from threat_intel.alienvault import query_ip as query_otx,        normalise_alienvault

# ── Weights ───────────────────────────────────────────────────────────────
WEIGHT_ABUSEIPDB  = 0.40
WEIGHT_VIRUSTOTAL = 0.40
WEIGHT_OTX        = 0.20


def is_public_ip(ip_str):
    try:
        return not ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


# ── Per-API query wrappers (called in threads) ────────────────────────────
def _query_abuseipdb(ip):
    raw   = query_abuseipdb(ip)
    score = normalise_abuseipdb(raw)
    return "abuseipdb", score, raw


def _query_virustotal(ip):
    raw = query_virustotal(ip)
    score = normalise_virustotal(
        {
            "malicious_count":  raw.get("malicious_count",  0),
            "suspicious_count": raw.get("suspicious_count", 0),
            "harmless_count":   raw.get("harmless_count",   0),
            "total_engines":    raw.get("total_engines",    0),
            "reputation":       raw.get("reputation",       0),
        } if raw else None
    )
    return "virustotal", score, raw

def _query_otx(ip):
    if not is_public_ip(ip):
        print(f"[OTX SKIP] {ip} is a local LAN asset. Skipping.")
        return "otx", 1.0, {"message": "Skipped — private IP"}

    raw = query_otx(ip)

    if raw is None:
        return "otx", None, None

    score = normalise_alienvault({
        "pulse_count": raw.get("pulse_count", 0),
        "tags": raw.get("tags", []),
        "malware_families": raw.get("malware_families", []),
        "reputation": raw.get("reputation", 0),
    })

    return "otx", score, raw


# ── Main: Single IP ───────────────────────────────────────────────────────
def get_composite_threat_score(ip_address, timeout=15):
    """
    Queries all 3 APIs concurrently for one IP.
    Returns same dict format as original aggregator.py.

    Args:
        ip_address (str): IP to query
        timeout (int):    Max seconds to wait per API (default 15)
    """
    print(f"\n[ASYNC AGGREGATOR] Analysing IP: {ip_address}")
    print(f"[ASYNC AGGREGATOR] Querying 3 APIs concurrently...")

    raw_results      = {}
    abuseipdb_score  = None
    virustotal_score = None
    otx_score        = None

    with ThreadPoolExecutor(max_workers=3) as executor:

        futures = {
            executor.submit(_query_abuseipdb, ip_address): "abuseipdb",
            executor.submit(_query_virustotal, ip_address): "virustotal",
            executor.submit(_query_otx, ip_address): "otx",
    }

    for future in as_completed(futures):
        api_name = futures[future]

        try:
            name, score, raw = future.result()

            raw_results[name] = raw

            if name == "abuseipdb":
                abuseipdb_score = score
            elif name == "virustotal":
                virustotal_score = score
            elif name == "otx":
                otx_score = score

            print(f"  [✓] {name:<12} score={score}")

        except Exception as e:
            print(f"  [✗] {api_name:<12} ERROR: {e}")
            raw_results[api_name] = {"error": str(e)}


    composite_score  = _compute_weighted_average(abuseipdb_score, virustotal_score, otx_score)
    severity_label   = _get_severity_label(composite_score)
    apis_succeeded   = sum(1 for s in [abuseipdb_score, virustotal_score, otx_score]
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


# ── Batch: Multiple IPs ───────────────────────────────────────────────────
def get_composite_scores_batch(ip_list, max_workers=5):
    """
    Queries multiple IPs concurrently.
    Uses a separate pool so each IP's 3 API calls are also concurrent.

    Args:
        ip_list (list):    List of IP address strings
        max_workers (int): Max concurrent IP queries (default 5)

    Returns:
        dict: { ip_address: result_dict }
    """
    print(f"\n[ASYNC AGGREGATOR] Batch query: {len(ip_list)} IPs with max_workers={max_workers}")

    results = {}
    start   = time.perf_counter()

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="BatchIP") as pool:
        future_to_ip = {pool.submit(get_composite_threat_score, ip): ip for ip in ip_list}

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception as e:
                print(f"[ASYNC AGGREGATOR] Failed for {ip}: {e}")
                results[ip] = {
                    "ip": ip, "composite_score": 1.0,
                    "severity_label": "Low", "apis_succeeded": 0,
                    "abuseipdb_score": None, "virustotal_score": None, "otx_score": None,
                    "queried_at": datetime.now(timezone.utc).isoformat(), "raw": {}
                }

    elapsed = time.perf_counter() - start
    print(f"\n[ASYNC AGGREGATOR] Batch complete: {len(results)} IPs in {elapsed:.2f}s")
    return results


# ── Helpers ───────────────────────────────────────────────────────────────
def _compute_weighted_average(abuseipdb_score, virustotal_score, otx_score):
    scores_and_weights = [
        (abuseipdb_score,  WEIGHT_ABUSEIPDB),
        (virustotal_score, WEIGHT_VIRUSTOTAL),
        (otx_score,        WEIGHT_OTX),
    ]
    valid = [(s, w) for s, w in scores_and_weights if s is not None]
    if not valid:
        print("[ASYNC AGGREGATOR] WARNING: All APIs failed. Defaulting to 1.0")
        return 1.0
    total_weight = sum(w for _, w in valid)
    weighted_sum = sum(s * (w / total_weight) for s, w in valid)
    return round(max(1.0, min(10.0, weighted_sum)), 2)


def _get_severity_label(score):
    if score >= 7.0:   return "High"
    elif score >= 4.0: return "Medium"
    else:              return "Low"


def _print_summary(result):
    label = result["severity_label"]
    indicator = {"High": "⚠  HIGH", "Medium": "~  MEDIUM"}.get(label, "✓  LOW")
    print(f"\n[ASYNC AGGREGATOR] ── Results for {result['ip']} ──")
    print(f"  AbuseIPDB  (40%) : {result['abuseipdb_score']  or 'FAILED'}")
    print(f"  VirusTotal (40%) : {result['virustotal_score'] or 'FAILED'}")
    print(f"  OTX        (20%) : {result['otx_score']        or 'FAILED'}")
    print(f"  ─────────────────────────────────")
    print(f"  Composite Score  : {result['composite_score']}/10   [{indicator}]")
    print(f"  APIs Succeeded   : {result['apis_succeeded']}/3\n")


# ── Performance comparison test ───────────────────────────────────────────
if __name__ == "__main__":
    import time

    TEST_IPS = [
        "8.8.8.8", "1.1.1.1", "185.220.101.1",
        "8.8.4.4", "9.9.9.9", "208.67.222.222",
        "198.41.0.4", "199.9.14.201", "192.5.5.241", "198.97.190.53"
    ]

    print("\n" + "="*60)
    print("  Async Aggregator — Sequential vs Concurrent Comparison")
    print("="*60)

    # Sequential (original)
    print("\n[TEST] Sequential (original aggregator)...")
    from threat_intel.aggregator import get_composite_threat_score as seq_get
    t_seq_start = time.perf_counter()
    for ip in TEST_IPS[:5]:  # 5 IPs only to keep test fast
        seq_get(ip)
    t_seq = time.perf_counter() - t_seq_start

    # Concurrent (new)
    print("\n[TEST] Concurrent (async_aggregator)...")
    t_async_start = time.perf_counter()
    get_composite_scores_batch(TEST_IPS[:5], max_workers=5)
    t_async = time.perf_counter() - t_async_start

    print("\n" + "="*60)
    print("  PERFORMANCE COMPARISON — 5 IPs")
    print("="*60)
    print(f"  Sequential time : {t_seq:.2f}s")
    print(f"  Concurrent time : {t_async:.2f}s")
    print(f"  Speedup         : {t_seq/t_async:.1f}x faster")
    print("="*60)