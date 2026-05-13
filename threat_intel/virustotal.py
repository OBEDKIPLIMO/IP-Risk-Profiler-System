"""
threat_intel/virustotal.py
--------------------------
VirusTotal Threat Intelligence Module for the Automated IP Risk Profiler System.

What this module does:
  - Queries the VirusTotal API v3 for a given IP address
  - Extracts: last_analysis_stats (malicious, suspicious, harmless counts)
              and reputation score
  - Normalises results to a severity score of 1.0 - 10.0
  - Handles API errors, rate limits, and unknown IPs gracefully

VirusTotal API docs: https://developers.virustotal.com/reference/ip-info
Free tier limits  : 4 requests/minute, 500 requests/day
"""

import requests
import time
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────
API_KEY      = os.getenv("VIRUSTOTAL_KEY")
BASE_URL     = "https://www.virustotal.com/api/v3/ip_addresses"
TIMEOUT_SECS = 10
MAX_RETRIES  = 2


# ── Function 1: Query VirusTotal for one IP ───────────────────────────────
def query_ip(ip_address):
    """
    Sends a GET request to VirusTotal API v3 and returns the parsed response.

    How the VirusTotal API works differently from AbuseIPDB:
      - URL format : GET /api/v3/ip_addresses/{ip}   (IP is in the URL, not a param)
      - Header     : x-apikey: your_api_key           (different header name)
      - Response   : nested JSON under "data" → "attributes"

    Args:
        ip_address (str): The IP to check e.g. '185.220.101.1'

    Returns:
        dict: parsed result with these keys:
              {
                "ip_address":        str,
                "malicious_count":   int,   # engines that flagged as malicious
                "suspicious_count":  int,   # engines that flagged as suspicious
                "harmless_count":    int,   # engines that flagged as clean
                "undetected_count":  int,   # engines with no opinion
                "total_engines":     int,   # total engines that scanned
                "reputation":        int,   # VirusTotal community score (-ve = bad)
                "severity_score":    float, # normalised 1.0-10.0
                "source_api":        str,
                "queried_at":        str,
                "raw":               dict   # full attributes block for storage
              }

        Returns None if the query completely fails.
    """
    # ── Guard: check API key is loaded ───────────────────────────────────
    if not API_KEY or "your_" in API_KEY:
        print("[VIRUSTOTAL ERROR] API key not set. Add VIRUSTOTAL_KEY to your .env file.")
        return None

    # ── Build the request ─────────────────────────────────────────────────
    # VirusTotal uses the IP directly in the URL path — not as a query param
    url     = f"{BASE_URL}/{ip_address}"
    headers = {
        "x-apikey": API_KEY,      # note: VirusTotal uses x-apikey, not Key
        "Accept":   "application/json"
    }

    # ── Send the request (with retry on failure) ──────────────────────────
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"[VIRUSTOTAL] Querying: {ip_address}  (attempt {attempt})")

            response = requests.get(
                url,
                headers=headers,
                timeout=TIMEOUT_SECS
            )

            # ── Handle HTTP error codes ───────────────────────────────────
            if response.status_code == 200:
                handle_rate_limit(response.headers)
                return parse_response(ip_address, response.json())

            elif response.status_code == 401:
                print(f"[VIRUSTOTAL ERROR] 401 Unauthorized — check your API key in .env")
                return None

            elif response.status_code == 404:
                # IP not found in VirusTotal database — not necessarily malicious
                print(f"[VIRUSTOTAL] 404 — IP {ip_address} not found in database. Defaulting to 1.0")
                return _not_found_result(ip_address)

            elif response.status_code == 429:
                # Rate limited — free tier is 4 requests/minute
                print(f"[VIRUSTOTAL] Rate limited (429). Waiting 20 seconds...")
                time.sleep(20)
                continue

            else:
                print(f"[VIRUSTOTAL ERROR] Unexpected status code: {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            print(f"[VIRUSTOTAL ERROR] Request timed out after {TIMEOUT_SECS}s")
            if attempt < MAX_RETRIES:
                print(f"[VIRUSTOTAL] Retrying in 3 seconds...")
                time.sleep(3)

        except requests.exceptions.ConnectionError:
            print(f"[VIRUSTOTAL ERROR] No internet connection — cannot reach API")
            return None

        except requests.exceptions.RequestException as e:
            print(f"[VIRUSTOTAL ERROR] Request failed: {e}")
            return None

    print(f"[VIRUSTOTAL ERROR] All {MAX_RETRIES} attempts failed for {ip_address}")
    return None


# ── Function 2: Parse the API JSON response ───────────────────────────────
def parse_response(ip_address, json_response):
    """
    Extracts the fields we need from the raw VirusTotal JSON response.

    VirusTotal response structure (simplified):
    {
        "data": {
            "id":   "185.220.101.1",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "malicious":  15,
                    "suspicious":  2,
                    "harmless":   60,
                    "undetected": 10
                },
                "reputation": -20,
                "country":    "DE",
                "as_owner":   "Frantech Solutions"
            }
        }
    }

    Args:
        ip_address (str):     the IP that was queried
        json_response (dict): the full parsed JSON from the API

    Returns:
        dict: cleaned and normalised result
    """
    attributes = json_response.get("data", {}).get("attributes", {})

    # ── Extract last_analysis_stats ───────────────────────────────────────
    stats = attributes.get("last_analysis_stats", {})

    malicious_count  = stats.get("malicious",  0)
    suspicious_count = stats.get("suspicious", 0)
    harmless_count   = stats.get("harmless",   0)
    undetected_count = stats.get("undetected", 0)

    total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

    # ── Extract reputation score ──────────────────────────────────────────
    # VirusTotal reputation: positive = trustworthy, negative = suspicious
    # Range is roughly -100 to +100
    reputation = attributes.get("reputation", 0)

    # ── Normalise to severity score 1.0-10.0 ────────────────────────────
    severity_score = normalise_virustotal({
        "malicious_count":  malicious_count,
        "suspicious_count": suspicious_count,
        "harmless_count":   harmless_count,
        "total_engines":    total_engines,
        "reputation":       reputation,
    })

    return {
        "ip_address":       ip_address,
        "malicious_count":  malicious_count,
        "suspicious_count": suspicious_count,
        "harmless_count":   harmless_count,
        "undetected_count": undetected_count,
        "total_engines":    total_engines,
        "reputation":       reputation,
        "severity_score":   severity_score,
        "source_api":       "virustotal",
        "queried_at":       datetime.now(timezone.utc).isoformat(),
        "raw":              attributes
    }


# ── Function 3: Normalise score ───────────────────────────────────────────
def normalise_virustotal(response):
    """
    Converts VirusTotal analysis stats to a severity score 1.0-10.0.

    Formula explained:
      VirusTotal gives you a count of engines that flagged the IP:
        malicious=15, suspicious=2, harmless=60, total=77

      Step 1 — malicious ratio = malicious / total_engines
               e.g. 15/77 = 0.195  (19.5% of engines flagged it)

      Step 2 — suspicious adds half weight (less certain than malicious)
               adjusted = malicious + (suspicious * 0.5)
               e.g. 15 + (2 * 0.5) = 16  →  16/77 = 0.208

      Step 3 — scale to 1.0-10.0
               severity = (adjusted_ratio * 9) + 1
               e.g. (0.208 * 9) + 1 = 2.87

      Step 4 — reputation penalty
               if reputation < 0, add a small boost to severity
               penalty = min(2.0, abs(reputation) / 50)

    Edge cases:
      - response is None          → return None
      - total_engines = 0         → return 1.0 (no data = unknown = minimal)
      - all engines say harmless  → return 1.0
      - all engines say malicious → return 10.0

    Args:
        response (dict): dict with malicious_count, suspicious_count,
                         harmless_count, total_engines, reputation keys

    Returns:
        float: severity score between 1.0 and 10.0, or None on failure
    """
    # Edge case — API call completely failed
    if response is None:
        print("[VIRUSTOTAL] WARNING: response is None — API error occurred")
        return None

    # Edge case — missing required keys
    if "malicious_count" not in response:
        print("[VIRUSTOTAL] WARNING: no analysis stats in response — defaulting to 1.0")
        return 1.0

    total_engines    = response.get("total_engines",    0)
    malicious_count  = response.get("malicious_count",  0)
    suspicious_count = response.get("suspicious_count", 0)
    reputation       = response.get("reputation",       0)

    # Edge case — no engines scanned (IP too new or not in database)
    if total_engines == 0:
        return 1.0

    # Step 1 & 2 — weighted detection ratio
    adjusted_detections = malicious_count + (suspicious_count * 0.5)
    detection_ratio     = adjusted_detections / total_engines

    # Step 3 — scale to 1.0-10.0
    severity = (detection_ratio * 9) + 1

    # Step 4 — reputation penalty (negative reputation = more suspicious)
    if reputation < 0:
        penalty   = min(2.0, abs(reputation) / 50)
        severity += penalty

    # Clamp to valid range 1.0-10.0
    severity = max(1.0, min(10.0, round(severity, 2)))

    return severity


# ── Function 4: Rate limit handler ───────────────────────────────────────
def handle_rate_limit(response_headers):
    """
    VirusTotal free tier: 4 requests/minute, 500/day.
    Adds delay based on remaining quota in headers.

    Headers:
      X-RateLimit-Limit     : requests per minute allowed
      X-RateLimit-Remaining : requests remaining this minute
    """
    remaining = response_headers.get("X-RateLimit-Remaining")

    if remaining is None:
        # Headers not present — add a safe default delay for free tier
        time.sleep(1)
        return

    remaining = int(remaining)

    if remaining <= 0:
        print(f"[VIRUSTOTAL] Rate limit reached. Waiting 20 seconds...")
        time.sleep(20)
    elif remaining <= 2:
        print(f"[VIRUSTOTAL] Rate limit warning: only {remaining} requests/min remaining.")
        time.sleep(5)
    else:
        time.sleep(1)   # always 1s minimum between VT requests (free tier is strict)


# ── Helper: result for IPs not in VT database ────────────────────────────
def _not_found_result(ip_address):
    """
    Returns a default low-risk result when the IP is not found in
    the VirusTotal database (404 response).
    Not being in the database does not mean the IP is malicious.
    """
    return {
        "ip_address":       ip_address,
        "malicious_count":  0,
        "suspicious_count": 0,
        "harmless_count":   0,
        "undetected_count": 0,
        "total_engines":    0,
        "reputation":       0,
        "severity_score":   1.0,   # unknown = minimal risk
        "source_api":       "virustotal",
        "queried_at":       datetime.now(timezone.utc).isoformat(),
        "raw":              {}
    }


# ── Function 5: Print result ──────────────────────────────────────────────
def print_result(result):
    """
    Prints one query result in a clean readable format.
    """
    if result is None:
        print("  Result : FAILED — see error above\n")
        return

    score = result['severity_score']
    if score >= 7:
        label = "HIGH    ⚠"
    elif score >= 4:
        label = "MEDIUM  ~"
    else:
        label = "LOW     ✓"

    print(f"  IP               : {result['ip_address']}")
    print(f"  Malicious        : {result['malicious_count']} engine(s)")
    print(f"  Suspicious       : {result['suspicious_count']} engine(s)")
    print(f"  Harmless         : {result['harmless_count']} engine(s)")
    print(f"  Total Engines    : {result['total_engines']}")
    print(f"  VT Reputation    : {result['reputation']}")
    print(f"  Severity Score   : {result['severity_score']}/10  [{label}]")
    print(f"  Queried At       : {result['queried_at']}")
    print()


# ── Run directly to test ──────────────────────────────────────────────────
# Run from your project root:
#   python threat_intel/virustotal.py

if __name__ == "__main__":

    # Same 5 IPs used for AbuseIPDB — compare results side by side
    TEST_IPS = [
        "185.220.101.1",    # Tor exit node — expect HIGH
        "45.148.10.76",     # Known scanner  — expect HIGH
        "194.165.16.11",    # SSH brute forcer — expect MEDIUM/HIGH
        "192.168.100.1",    # Your router (private IP) — expect LOW
        "8.8.8.8",          # Google DNS — expect LOW
    ]

    print("\n" + "="*60)
    print("  VirusTotal Threat Intelligence — Test Run")
    print("="*60)
    print(f"  Testing {len(TEST_IPS)} IPs against VirusTotal API")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Note: 1 second delay between requests (free tier = 4 req/min)")
    print("="*60 + "\n")

    results = []
    for ip in TEST_IPS:
        print(f"[TEST] Checking: {ip}")
        result = query_ip(ip)
        print_result(result)
        results.append(result)
        # Delay already handled inside handle_rate_limit()

    # ── Summary ───────────────────────────────────────────────────────────
    successful = [r for r in results if r is not None]
    print("="*60)
    print(f"  SUMMARY")
    print("="*60)
    print(f"  IPs tested    : {len(TEST_IPS)}")
    print(f"  Successful    : {len(successful)}")
    print(f"  Failed        : {len(TEST_IPS) - len(successful)}")
    if successful:
        scores = [r['severity_score'] for r in successful]
        print(f"  Severity range: {min(scores)} – {max(scores)}")
        high = [r for r in successful if r['severity_score'] >= 7]
        print(f"  High risk IPs : {len(high)}")
    print("="*60 + "\n")

    # ── Side-by-side comparison note ──────────────────────────────────────
    print("Compare these results with your AbuseIPDB scores from Day 8.")
    print("The two APIs will often agree on high-risk IPs but may differ")
    print("on medium-risk ones — that is expected and normal.\n")