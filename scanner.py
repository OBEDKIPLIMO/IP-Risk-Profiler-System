"""
scanner/asset_scanner.py
------------------------
Asset Discovery Module for the Automated IP Risk Profiler System.

Responsibilities:
  1. Scan a subnet using Nmap to discover live devices
  2. Extract IP, hostname, open ports, and OS for each device
  3. Assign a criticality score (1-10) based on what ports are open
  4. Save results to the database (upsert — update if IP exists, insert if new)
  5. Return structured results ready to be used by the Risk Engine
"""

import nmap
import sys
import os
from datetime import datetime, timezone

# ── Allow imports from project root ──────────────────────────────────────
# This lets us import from db/ when running scanner.py directly from project root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.models import Base, Asset


# ── Database setup ────────────────────────────────────────────────────────
DATABASE_URL = "sqlite:///dev.db"
engine       = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)


# ── Criticality Rules ─────────────────────────────────────────────────────
CRITICAL_PORTS = {
    22:    9,  # SSH         — remote admin access
    23:    8,  # Telnet      — unencrypted remote access (very dangerous)
    3389:  9,  # RDP         — Windows remote desktop
    3306:  8,  # MySQL       — database server
    5432:  8,  # PostgreSQL  — database server
    1433:  9,  # MSSQL       — Microsoft SQL Server
    27017: 7,  # MongoDB     — NoSQL database
    6379:  7,  # Redis       — in-memory database (often unsecured)
    445:   7,  # SMB         — Windows file sharing (ransomware target)
    139:   6,  # NetBIOS     — older Windows networking
    21:    6,  # FTP         — file transfer (often unencrypted)
    25:    6,  # SMTP        — email server
    80:    4,  # HTTP        — standard web server
    443:   4,  # HTTPS       — secure web server
    8080:  4,  # HTTP-alt    — common dev/proxy port
    8443:  4,  # HTTPS-alt
    53:    5,  # DNS         — domain name server
    161:   6,  # SNMP        — network management (often misconfigured)
}


# ── Function 1: Assign Criticality Score ─────────────────────────────────
def assign_criticality(open_ports_list):
    """
    Maps open ports to a criticality score 1-10.

    Rules (Day 5 spec):
      - Port 22, 3389, 1433, 3306 open → score 8-10
      - HTTP only (80/443/8080)        → score 4-6
      - Unknown/no sensitive ports     → score 3
      - No open ports at all           → score 1

    Args:
        open_ports_list (list): e.g. [22, 80, 443, 3306]

    Returns:
        int: criticality score between 1 and 10
    """
    if not open_ports_list:
        return 1

    highest_score = 3  # default for unknown ports

    for port in open_ports_list:
        if port in CRITICAL_PORTS:
            port_score = CRITICAL_PORTS[port]
            if port_score > highest_score:
                highest_score = port_score

    return highest_score


# ── Function 2: Infer OS from Service Banners ────────────────────────────
def infer_os_from_banners(host_data):
    """
    Guesses OS from service banner text returned by -sV.
    Used because -O (OS detection) requires root on Linux.

    Returns:
        str or None: e.g. 'Linux (inferred)', 'Windows (inferred)', or None
    """
    if 'tcp' not in host_data:
        return None

    for port, info in host_data['tcp'].items():
        product   = info.get('product',   '').lower()
        extrainfo = info.get('extrainfo', '').lower()
        combined  = product + ' ' + extrainfo

        if 'windows' in combined:
            return 'Windows (inferred)'
        elif any(kw in combined for kw in ['linux', 'ubuntu', 'debian', 'centos', 'fedora']):
            return 'Linux (inferred)'
        elif 'mac os' in combined or 'darwin' in combined:
            return 'macOS (inferred)'
        elif 'android' in combined:
            return 'Android (inferred)'
        elif 'huawei' in combined:
            return 'Huawei Device (inferred)'

    return None


# ── Function 3: Parse a Single Host ──────────────────────────────────────
def parse_host(scanner, ip):
    """
    Extracts all useful information from the nmap scan result for one IP.

    Returns:
        dict: structured host data with all fields ready for the database
    """
    host_data = scanner[ip]

    # Hostname
    hostnames = host_data.hostnames()
    hostname  = hostnames[0]['name'] if hostnames and hostnames[0]['name'] else None

    # Open TCP ports
    open_ports   = []
    port_details = {}

    if 'tcp' in host_data:
        for port, port_info in host_data['tcp'].items():
            if port_info['state'] == 'open':
                open_ports.append(port)
                service_name       = port_info.get('name',    'unknown')
                product            = port_info.get('product', '')
                version            = port_info.get('version', '')
                port_details[port] = f"{service_name} {product} {version}".strip()

    # OS (inferred from banners — no root needed)
    os_type = infer_os_from_banners(host_data)

    # Criticality
    criticality = assign_criticality(open_ports)

    return {
        "ip_address":        ip,
        "hostname":          hostname,
        "open_ports":        ",".join(str(p) for p in sorted(open_ports)),
        "port_details":      port_details,
        "os_type":           os_type,
        "criticality_score": criticality,
        "last_seen":         datetime.now(timezone.utc),
    }


# ── Function 4: Scan a Subnet ────────────────────────────────────────────
def scan_subnet(subnet):
    """
    Scans an entire subnet and returns a list of discovered asset dicts.
    """
    print(f"\n[SCANNER] Starting scan on subnet: {subnet}")
    print(f"[SCANNER] Arguments: -sV --open -T4")
    print(f"[SCANNER] Note: OS detection uses banner inference (no root required)")
    print(f"[SCANNER] This may take 1-3 minutes depending on network size...\n")

    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=subnet, arguments='-sV --open -T4')
    except nmap.PortScannerError as e:
        print(f"[SCANNER ERROR] Nmap scan failed: {e}")
        return []
    except Exception as e:
        print(f"[SCANNER ERROR] Unexpected error: {e}")
        return []

    discovered_hosts = nm.all_hosts()
    print(f"[SCANNER] Scan complete. Found {len(discovered_hosts)} live host(s).")

    if not discovered_hosts:
        print("[SCANNER] No hosts found. Check that the subnet is correct.")
        return []

    assets = []
    for ip in discovered_hosts:
        print(f"[SCANNER] Parsing host: {ip}")
        asset = parse_host(nm, ip)
        assets.append(asset)

    return assets


# ── Function 5: Save Assets to Database (with upsert logic) ──────────────
def save_assets_to_db(scan_results):
    """
    Saves a list of scanned assets to the database.

    UPSERT logic — for each scanned IP:
      - If the IP already exists in the DB → UPDATE its details
      - If the IP is new                   → INSERT a new row

    This means you can run the scanner repeatedly without creating
    duplicate rows — it simply refreshes the data each time.

    Edge cases handled:
      - host unreachable  : scan_results will be empty list — exits cleanly
      - OS detection failed : os_type will be None — saved as NULL in DB, no crash
      - duplicate IP      : upsert updates the existing row instead of inserting again
      - DB write error    : rolls back transaction so DB is never left broken

    Args:
        scan_results (list): list of asset dicts returned by scan_subnet()

    Returns:
        dict: {"inserted": int, "updated": int, "errors": int}
    """
    # Edge case — empty scan results (host unreachable / no hosts found)
    if not scan_results:
        print("[DB] No scan results to save.")
        return {"inserted": 0, "updated": 0, "errors": 0}

    session  = SessionLocal()
    inserted = 0
    updated  = 0
    errors   = 0

    try:
        for asset_data in scan_results:
            try:
                ip = asset_data["ip_address"]

                # Check if this IP already exists in the database
                existing = session.query(Asset).filter_by(ip_address=ip).first()

                if existing:
                    # UPDATE — IP already in DB, refresh its data
                    existing.hostname          = asset_data["hostname"]
                    existing.open_ports        = asset_data["open_ports"]
                    existing.os_type           = asset_data["os_type"]   # None saved as NULL
                    existing.criticality_score = asset_data["criticality_score"]
                    existing.last_seen         = asset_data["last_seen"]
                    print(f"[DB] UPDATED  : {ip}  (criticality={asset_data['criticality_score']})")
                    updated += 1

                else:
                    # INSERT — new IP, add a fresh row
                    new_asset = Asset(
                        ip_address        = ip,
                        hostname          = asset_data["hostname"],
                        open_ports        = asset_data["open_ports"],
                        os_type           = asset_data["os_type"],
                        criticality_score = asset_data["criticality_score"],
                        last_seen         = asset_data["last_seen"],
                    )
                    session.add(new_asset)
                    print(f"[DB] INSERTED : {ip}  (criticality={asset_data['criticality_score']})")
                    inserted += 1

            except Exception as row_error:
                # Single row failed — log it but continue saving the rest
                print(f"[DB ERROR] Failed to save {asset_data.get('ip_address', '?')}: {row_error}")
                errors += 1
                continue

        # Commit all inserts/updates in one transaction
        session.commit()
        print(f"\n[DB] Save complete — inserted: {inserted}, updated: {updated}, errors: {errors}")

    except Exception as e:
        # Full transaction failure — roll back everything
        session.rollback()
        print(f"[DB ERROR] Transaction failed, rolled back: {e}")
        raise

    finally:
        # Always close the session
        session.close()

    return {"inserted": inserted, "updated": updated, "errors": errors}


# ── Function 6: Print Results ─────────────────────────────────────────────
def print_scan_results(assets):
    """
    Prints scan results in a clean, readable format to the terminal.
    """
    if not assets:
        print("\n[RESULTS] No assets to display.")
        return

    print("\n" + "="*60)
    print(f"  SCAN RESULTS — {len(assets)} device(s) found")
    print("="*60)

    for i, asset in enumerate(assets, 1):
        print(f"\n  Device #{i}")
        print(f"  IP Address   : {asset['ip_address']}")
        print(f"  Hostname     : {asset['hostname'] or 'Unknown'}")
        print(f"  OS           : {asset['os_type'] or 'Could not detect'}")
        print(f"  Open Ports   : {asset['open_ports'] or 'None found'}")
        print(f"  Criticality  : {asset['criticality_score']}/10")
        print(f"  Last Seen    : {asset['last_seen']}")

        if asset['port_details']:
            print(f"  Port Details :")
            for port, service in asset['port_details'].items():
                print(f"    {port:<6} → {service}")

        print("  " + "-"*55)

    print("\n[RESULTS] Raw scan complete — data looks correct.")
    print("[RESULTS] Saving to database...\n")


# ── Entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":

    # ── CHANGE THIS to your actual subnet ────────────────────────────────
    TARGET_SUBNET = "192.168.100.0/24"
    # ─────────────────────────────────────────────────────────────────────

    print("\n" + "="*60)
    print("  Automated IP Risk Profiler — Asset Discovery Module")
    print("="*60)
    print(f"  Target : {TARGET_SUBNET}")
    print(f"  Time   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("="*60)

    # Step 1 — Ensure DB tables exist before saving
    print("\n[DB] Checking database tables...")
    Base.metadata.create_all(bind=engine)
    print("[DB] Tables ready.")

    # Step 2 — Run the scan
    results = scan_subnet(TARGET_SUBNET)

    # Step 3 — Print what was found
    print_scan_results(results)

    # Step 4 — Save to database
    print("[DB] Saving assets to dev.db...")
    summary = save_assets_to_db(results)

    # Step 5 — Final summary
    print("\n" + "="*60)
    print("  DONE")
    print("="*60)
    print(f"  Scanned  : {TARGET_SUBNET}")
    print(f"  Found    : {len(results)} device(s)")
    print(f"  Inserted : {summary['inserted']} new asset(s)")
    print(f"  Updated  : {summary['updated']} existing asset(s)")
    print(f"  Errors   : {summary['errors']}")
    print(f"\n  Open DB Browser → dev.db → Browse Data → assets table")
    print(f"  to verify your scan results are saved correctly.")
    print("="*60 + "\n")