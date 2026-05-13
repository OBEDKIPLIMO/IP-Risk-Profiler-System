"""
threat_intel/alienvault.py
--------------------------
AlienVault OTX Threat Intelligence Module for the IP Risk Profiler System.

What this module does:
  - Queries the AlienVault OTX API for a given IP address
  - Extracts: pulse_count, tags, country, malware_families, reputation
  - Normalises results to a severity score of 1.0 - 10.0
  - Handles API errors, rate limits, and unknown IPs gracefully

AlienVault OTX API docs: https://otx.alienvault.com/api
Endpoint used: GET /api/v1/indicators/IPv4/{ip}/general
Free tier     : No strict rate limit but be reasonable (max ~100 req/min)
"""

import requests
import time
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────
API_KEY      = os.getenv("OTX_KEY")
BASE_URL     = "https://otx.alienvault.com/api/v1/indicators/IPv4"
TIMEOUT_SECS = 10
MAX_RETRIES  = 2


# ── Function 1: Query AlienVault OTX for one IP ───────────────────────────
def query_ip(ip_address):
    """
    Sends a GET request to the AlienVault OTX API and returns parsed response.

    How the OTX API works:
      - URL format : GET /api/v1/indicators/IPv4/{ip}/general
      - Header     : X-OTX-API-KEY: your_key
      - Response   : JSON with pulse_count, tags, country, etc.

    Args:
        ip_address (str): The IP to check e.g. '185.220.101.1'

    Returns:
        dict with keys:
          {
            "ip_address":        str,
            "pulse_count":       int,    # number of threat reports mentioning this IP
            "tags":              list,   # threat tags e.g. ['malware', 'botnet']
            "country":           str,    # country code e.g. 'DE'
            "malware_families":  list,   # malware names associated with this IP
            "reputation":        int,    # OTX reputation score
            "severity_score":    float,  # normalised 1.0-10.0
            "source_api":        str,
            "queried_at":        str,
            "raw":               dict
          }

        Returns None if the query completely fails.
    """
    if not API_KEY or "your_" in API_KEY:
        print("[OTX ERROR] API key not set. Add OTX_KEY to your .env file.")
        return None

    url     = f"{BASE_URL}/{ip_address}/general"
    headers = {
        "X-OTX-API-KEY": API_KEY,
        "Accept":        "application/json"
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"[OTX] Querying: {ip_address}  (attempt {attempt})")

            response = requests.get(
                url,
                headers=headers,
                timeout=TIMEOUT_SECS
            )

            if response.status_code == 200:
                return parse_response(ip_address, response.json())

            elif response.status_code == 400:
                print(f"[OTX ERROR] 400 Bad Request — invalid IP format: {ip_address}")
                return None

            elif response.status_code == 401:
                print(f"[OTX ERROR] 401 Unauthorized — check your OTX_KEY in .env")
                return None

            elif response.status_code == 404:
                print(f"[OTX] 404 — IP {ip_address} not found in OTX. Defaulting to 1.0")
                return _not_found_result(ip_address)

            elif response.status_code == 429:
                print(f"[OTX] Rate limited. Waiting 10 seconds...")
                time.sleep(10)
                continue

            else:
                print(f"[OTX ERROR] Unexpected status: {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            print(f"[OTX ERROR] Timed out after {TIMEOUT_SECS}s")
            if attempt < MAX_RETRIES:
                time.sleep(3)

        except requests.exceptions.ConnectionError:
            print(f"[OTX ERROR] No internet connection")
            return None

        except requests.exceptions.RequestException as e:
            print(f"[OTX ERROR] Request failed: {e}")
            return None

    print(f"[OTX ERROR] All {MAX_RETRIES} attempts failed for {ip_address}")
    return None


# ── Function 2: Parse the API JSON response ───────────────────────────────
def parse_response(ip_address, json_response):
    """
    Extracts fields we need from the raw OTX JSON response.

    OTX /general endpoint response structure (simplified):
    {
        "indicator":    "185.220.101.1",
        "pulse_info": {
            "count": 42,                        ← how many threat reports mention this IP
            "pulses": [ {...}, {...} ],          ← individual report details
            "references": [],
            "related": {}
        },
        "tags":          ["tor", "exit-node"],  ← threat tags
        "country_name":  "Germany",
        "country_code":  "DE",
        "reputation":    0,
        "sections":      ["general", "geo", ...]
    }

    Args:
        ip_address (str):     the IP that was queried
        json_response (dict): the full parsed JSON from the API

    Returns:
        dict: cleaned and normalised result
    """
    # ── pulse_count — core threat signal for OTX ─────────────────────────
    # A "pulse" is a threat report. More pulses = more threat actors
    # have documented this IP as malicious.
    pulse_info  = json_response.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)

    # ── Extract tags from pulses ──────────────────────────────────────────
    # Tags describe the nature of the threat: 'malware', 'botnet', 'scanner'
    tags = json_response.get("tags", [])

    # Also collect tags from individual pulses if top-level tags are empty
    if not tags:
        pulses = pulse_info.get("pulses", [])
        for pulse in pulses[:5]:   # check first 5 pulses only
            pulse_tags = pulse.get("tags", [])
            tags.extend(pulse_tags)
        tags = list(set(tags))     # deduplicate

    # ── Country ───────────────────────────────────────────────────────────
    country = json_response.get("country_code", "Unknown")

    # ── Malware families ──────────────────────────────────────────────────
    malware_families = []
    pulses = pulse_info.get("pulses", [])
    for pulse in pulses[:10]:
        families = pulse.get("malware_families", [])
        for family in families:
            name = family.get("display_name", "")
            if name and name not in malware_families:
                malware_families.append(name)

    # ── Reputation ────────────────────────────────────────────────────────
    reputation = json_response.get("reputation", 0)

    # ── Normalise ─────────────────────────────────────────────────────────
    severity_score = normalise_alienvault({
        "pulse_count":      pulse_count,
        "tags":             tags,
        "malware_families": malware_families,
        "reputation":       reputation,
    })

    return {
        "ip_address":       ip_address,
        "pulse_count":      pulse_count,
        "tags":             tags,
        "country":          country,
        "malware_families": malware_families,
        "reputation":       reputation,
        "severity_score":   severity_score,
        "source_api":       "otx",
        "queried_at":       datetime.now(timezone.utc).isoformat(),
        "raw":              json_response
    }


# ── Function 3: Normalise score ───────────────────────────────────────────
def normalise_alienvault(response):
    """
    Converts AlienVault OTX data to a severity score 1.0-10.0.

    Primary signal: pulse_count (number of threat intelligence reports)

    Formula:
      Base score from pulse_count:
        0 pulses  → 1.0  (never reported)
        1-2       → 2.0  (mentioned but low confidence)
        3-5       → 4.0  (moderate threat)
        6-10      → 6.0  (well documented threat)
        11-20     → 8.0  (high confidence threat)
        21+       → 9.5  (very widely reported)

      Bonus for malware families: +0.5 if any malware families linked
      Bonus for dangerous tags  : +0.3 per dangerous tag (max +1.5)

      Final score clamped to 1.0-10.0

    Args:
        response (dict): dict with pulse_count, tags, malware_families keys

    Returns:
        float: severity score between 1.0 and 10.0, or None on failure
    """
    if response is None:
        print("[OTX] WARNING: response is None — API error occurred")
        return None

    if "pulse_count" not in response:
        print("[OTX] WARNING: no pulse_count in response — defaulting to 1.0")
        return 1.0

    pulse_count      = response.get("pulse_count",      0)
    tags             = response.get("tags",             [])
    malware_families = response.get("malware_families", [])

    # ── Base score from pulse_count ───────────────────────────────────────
    if pulse_count == 0:
        base_score = 1.0
    elif pulse_count <= 2:
        base_score = 2.0
    elif pulse_count <= 5:
        base_score = 4.0
    elif pulse_count <= 10:
        base_score = 6.0
    elif pulse_count <= 20:
        base_score = 8.0
    else:
        base_score = 9.5

    # ── Bonus: malware families linked ───────────────────────────────────
    malware_bonus = 0.5 if malware_families else 0

    # ── Bonus: dangerous tags ────────────────────────────────────────────
    dangerous_tags = {
        'malware', 'botnet', 'ransomware', 'trojan', 'exploit',
        'c2', 'rat', 'ddos', 'phishing', 'miner', 'scanner'
    }
    tag_matches  = sum(1 for t in tags if t.lower() in dangerous_tags)
    tag_bonus    = min(1.5, tag_matches * 0.3)

    # ── Final score ───────────────────────────────────────────────────────
    severity = base_score + malware_bonus + tag_bonus
    return max(1.0, min(10.0, round(severity, 2)))


# ── Helper: result for IPs not in OTX database ───────────────────────────
def _not_found_result(ip_address):
    return {
        "ip_address":       ip_address,
        "pulse_count":      0,
        "tags":             [],
        "country":          "Unknown",
        "malware_families": [],
        "reputation":       0,
        "severity_score":   1.0,
        "source_api":       "otx",
        "queried_at":       datetime.now(timezone.utc).isoformat(),
        "raw":              {}
    }


# ── Function 4: Print result ──────────────────────────────────────────────
def print_result(result):
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
    print(f"  Pulse Count      : {result['pulse_count']} threat report(s)")
    print(f"  Tags             : {', '.join(result['tags']) if result['tags'] else 'None'}")
    print(f"  Country          : {result['country']}")
    print(f"  Malware Families : {', '.join(result['malware_families']) if result['malware_families'] else 'None'}")
    print(f"  Severity Score   : {result['severity_score']}/10  [{label}]")
    print(f"  Queried At       : {result['queried_at']}")
    print()


# ── Run directly to test ──────────────────────────────────────────────────
if __name__ == "__main__":

    TEST_IPS = [
        "185.220.101.1",   # Tor exit node — expect HIGH
        "45.148.10.76",    # Known scanner  — expect HIGH
        "8.8.8.8",         # Google DNS     — expect LOW
    ]

    print("\n" + "="*60)
    print("  AlienVault OTX Threat Intelligence — Test Run")
    print("="*60)
    print(f"  Testing {len(TEST_IPS)} IPs against OTX API")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("="*60 + "\n")

    for ip in TEST_IPS:
        print(f"[TEST] Checking: {ip}")
        result = query_ip(ip)
        print_result(result)
        time.sleep(1)