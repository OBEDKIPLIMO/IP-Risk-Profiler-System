"""
threat_intel/abuseipdb.py
--------------------------
AbuseIPDB Threat Intelligence Module for the Automated IP Risk Profiler System.

What this module does:
  - Queries the AbuseIPDB API for a given IP address
  - Extracts: abuseConfidenceScore, totalReports, countryCode, usageType
  - Normalises the confidence score to a severity score of 1.0 - 10.0
  - Handles API errors, rate limits, and unknown IPs gracefully

AbuseIPDB API docs: https://docs.abuseipdb.com/#check-endpoint
"""

import requests
import time
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────
API_KEY      = os.getenv("ABUSEIPDB_KEY")
BASE_URL     = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT_SECS = 10   # give the API 10 seconds to respond before giving up
MAX_RETRIES  = 2    # retry once if the request fails


# ── Function 1: Query AbuseIPDB for one IP ────────────────────────────────
def query_ip(ip_address):
    """
    Sends a GET request to the AbuseIPDB API and returns the parsed response.

    How the API works:
      - You send: GET https://api.abuseipdb.com/api/v2/check?ipAddress=X
      - Header  : Key: your_api_key, Accept: application/json
      - Response: JSON with abuse confidence score, report count, country, etc.

    Args:
        ip_address (str): The IP to check e.g. '192.168.100.1' or '185.220.101.1'

    Returns:
        dict: parsed result with these keys:
              {
                "ip_address":            str,
                "abuse_confidence_score": int,    # 0-100 (raw from API)
                "total_reports":          int,
                "country_code":           str,
                "usage_type":             str,
                "severity_score":         float,  # normalised to 1.0-10.0
                "source_api":             str,
                "queried_at":             str,
                "raw":                    dict    # full API response for storage
              }

        Returns None if the query completely fails.
    """
    # ── Guard: check API key is loaded ───────────────────────────────────
    if not API_KEY or "your_" in API_KEY:
        print("[ABUSEIPDB ERROR] API key not set. Add ABUSEIPDB_KEY to your .env file.")
        return None

    # ── Build the request ─────────────────────────────────────────────────
    headers = {
        "Key":    API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress":    ip_address,
        "maxAgeInDays": 90,    # only consider reports from last 90 days
        "verbose":      True   # include extra details like categories
    }

    # ── Send the request (with retry on failure) ──────────────────────────
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"[ABUSEIPDB] Querying: {ip_address}  (attempt {attempt})")

            response = requests.get(
                BASE_URL,
                headers=headers,
                params=params,
                timeout=TIMEOUT_SECS
            )

            # ── Handle HTTP error codes ───────────────────────────────────
            if response.status_code == 200:
                # check rate limit headers before returning 
                handle_rate_limit(response.headers)
                return parse_response(ip_address, response.json())

            elif response.status_code == 401:
                print(f"[ABUSEIPDB ERROR] 401 Unauthorized — check your API key in .env")
                return None

            elif response.status_code == 422:
                print(f"[ABUSEIPDB ERROR] 422 Invalid IP address: {ip_address}")
                return None

            elif response.status_code == 429:
                # Rate limited — wait and retry
                retry_after = int(response.headers.get("Retry-After", 60))
                print(f"[ABUSEIPDB] Rate limited. Waiting {retry_after}s before retry...")
                time.sleep(retry_after)
                continue

            else:
                print(f"[ABUSEIPDB ERROR] Unexpected status code: {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            print(f"[ABUSEIPDB ERROR] Request timed out after {TIMEOUT_SECS}s")
            if attempt < MAX_RETRIES:
                print(f"[ABUSEIPDB] Retrying in 3 seconds...")
                time.sleep(3)

        except requests.exceptions.ConnectionError:
            print(f"[ABUSEIPDB ERROR] No internet connection — cannot reach API")
            return None

        except requests.exceptions.RequestException as e:
            print(f"[ABUSEIPDB ERROR] Request failed: {e}")
            return None

    print(f"[ABUSEIPDB ERROR] All {MAX_RETRIES} attempts failed for {ip_address}")
    return None


# ── Function 2: Parse the API JSON response ───────────────────────────────
def parse_response(ip_address, json_response):
    """
    Extracts the fields we need from the raw AbuseIPDB JSON response
    and adds a normalised severity score.

    Raw AbuseIPDB response looks like this:
    {
        "data": {
            "ipAddress":            "185.220.101.1",
            "abuseConfidenceScore": 100,
            "totalReports":         542,
            "countryCode":          "DE",
            "usageType":            "Data Center/Web Hosting/Transit",
            "isp":                  "Frantech Solutions",
            "domain":               "frantech.ca",
            "isWhitelisted":        false,
            "lastReportedAt":       "2026-05-05T08:00:00+00:00"
        }
    }

    Args:
        ip_address (str):    the IP that was queried
        json_response (dict): the full parsed JSON from the API

    Returns:
        dict: cleaned and normalised result
    """
    data = json_response.get("data", {})

    # ── Extract the 4 key fields ──────────────────────────────────────────
    abuse_confidence_score = data.get("abuseConfidenceScore", 0)   # 0-100
    total_reports          = data.get("totalReports",          0)
    country_code           = data.get("countryCode",           "Unknown")
    usage_type             = data.get("usageType",             "Unknown")

    # ── Normalise score from 0-100 to 1.0-10.0 ───────────────────────────
    # Formula: severity = confidence / 100 (floored at 1.0)
    # This maps:
    #   0%   confidence → 1.0  (clean IP, minimal risk)
    #   50%  confidence → 5.5  (medium risk)
    #   100% confidence → 10.0 (definitely malicious)
    severity_score = max(1.0, round(abuse_confidence_score / 10, 2))

    return {
        "ip_address":             ip_address,
        "abuse_confidence_score": abuse_confidence_score,
        "total_reports":          total_reports,
        "country_code":           country_code,
        "usage_type":             usage_type,
        "severity_score":         severity_score,
        "source_api":             "abuseipdb",
        "queried_at":             datetime.now(timezone.utc).isoformat(),
        "raw":                    data   # full response stored for details_json in DB
        }


# ── Function 3: Normalise score (standalone utility) ─────────────────────
def normalise_abuseipdb(response):
    """
    Converts an AbuseIPDB API response to a severity score 1.0-10.0.

    Formula: severity = abuseConfidenceScore / 10
    Maps 0-100% confidence directly to 0-10, floored at 1.0.

    Edge cases:
      - IP not found / score = 0  → returns 1.0  (minimum risk)
      - response is None          → returns None  (logs the error)
      - score out of range        → clamped to 0-100 before calculation
    """
    # Edge case — API call completely failed
    if response is None:
        print("[ABUSEIPDB] WARNING: response is None — API error occurred")
        return None

    # Edge case — response exists but data block is missing
    if "abuse_confidence_score" not in response:
        print("[ABUSEIPDB] WARNING: no confidence score in response — defaulting to 1.0")
        return 1.0

    raw_score = response["abuse_confidence_score"]

    # Edge case — IP not found or never reported (score = 0)
    if raw_score == 0:
        return 1.0  # not zero — floor at 1.0 (still unknown risk)

    # Clamp to valid range 0-100 just in case API returns unexpected value
    raw_score = max(0, min(100, raw_score))

    severity = round(raw_score / 10, 2)

    # Floor at 1.0 — nothing gets a zero score in our system
    return max(1.0, severity)

#── Function : Handle API rate limits ─────────────────────────────────
def handle_rate_limit(response_headers):
    """
    Checks AbuseIPDB response headers for rate limit status.
    Adds a 1-second delay if we are getting close to the limit.

    AbuseIPDB free tier = 1000 requests per day.
    Headers returned:
      X-RateLimit-Limit     : total allowed (1000)
      X-RateLimit-Remaining : how many left today
      X-RateLimit-Reset     : unix timestamp when limit resets

    Args:
        response_headers: the headers object from a requests.Response
    """
    remaining = response_headers.get("X-RateLimit-Remaining")

    if remaining is None:
        return  # headers not present — skip check

    remaining = int(remaining)

    if remaining <= 0:
        print("[ABUSEIPDB] Daily rate limit reached. Requests will fail until reset.")
        time.sleep(60)  # long pause — no point hammering a blocked API

    elif remaining <= 50:
        # Getting close to the limit — slow down
        print(f"[ABUSEIPDB] Rate limit warning: only {remaining} requests remaining today.")
        time.sleep(1)   # 1-second delay between requests

    # If plenty remaining — no delay needed

# ── Function 4: Print result ──────────────────────────────────────────────
def print_result(result):
    """
    Prints one query result in a clean readable format.

    Args:
        result (dict): return value of query_ip()
    """
    if result is None:
        print("  Result : FAILED — see error above\n")
        return

    # Severity label for quick reading
    score = result['severity_score']
    if score >= 7:
        label = "HIGH    ⚠"
    elif score >= 4:
        label = "MEDIUM  ~"
    else:
        label = "LOW     ✓"

    print(f"  IP               : {result['ip_address']}")
    print(f"  Confidence Score : {result['abuse_confidence_score']}%")
    print(f"  Total Reports    : {result['total_reports']}")
    print(f"  Country          : {result['country_code']}")
    print(f"  Usage Type       : {result['usage_type']}")
    print(f"  Severity Score   : {result['severity_score']}/10  [{label}]")
    print(f"  Queried At       : {result['queried_at']}")
    print()


# ── Run directly to test (Task 5 & 6) ────────────────────────────────────
# Run from your project root:
#   python threat_intel/abuseipdb.py

if __name__ == "__main__":

    # ── 5 known malicious IPs for testing ────────────────────────────────
    # These are well-known Tor exit nodes and attack IPs
    # consistently reported on AbuseIPDB
    TEST_IPS = [
        "185.220.101.1",    # Tor exit node — Germany
        "45.148.10.76",     # Known scanner/attacker
        "194.165.16.11",    # Reported SSH brute forcer
        "192.168.100.1",    # Your own router — should score LOW (private IP)
        "8.8.8.8",          # Google DNS — should score very LOW (clean IP)
    ]

    print("\n" + "="*60)
    print("  AbuseIPDB Threat Intelligence — Test Run")
    print("="*60)
    print(f"  Testing {len(TEST_IPS)} IPs against AbuseIPDB API")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("="*60 + "\n")

    results = []
    for ip in TEST_IPS:
        print(f"[TEST] Checking: {ip}")
        result = query_ip(ip)
        print_result(result)
        results.append(result)

        # Small delay between requests to respect API rate limits
        # Free tier allows 1000 requests/day — 1 second gap is safe
        time.sleep(1)

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