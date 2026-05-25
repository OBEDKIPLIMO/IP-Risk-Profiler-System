"""
scanner/scanner.py
------------------
Asset Discovery Module for the Automated IP Risk Profiler System.
"""

import nmap
import sys
import os
from datetime import datetime, timezone

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.models import Base, Asset

DATABASE_URL = "sqlite:///dev.db"
engine       = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

CRITICAL_PORTS = {
    22:    9,  23:   8,  3389: 9,  3306: 8,
    5432:  8,  1433: 9,  27017: 7, 6379: 7,
    445:   7,  139:  6,  21:   6,  25:   6,
    80:    4,  443:  4,  8080: 4,  8443: 4,
    53:    5,  161:  6,
}


def assign_criticality(open_ports_list):
    if not open_ports_list:
        return 1
    highest_score = 3
    for port in open_ports_list:
        if port in CRITICAL_PORTS:
            port_score = CRITICAL_PORTS[port]
            if port_score > highest_score:
                highest_score = port_score
    return highest_score


def infer_os_from_banners(host_data):
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


def parse_host(scanner, ip):
    host_data    = scanner[ip]
    hostnames    = host_data.hostnames()
    hostname     = hostnames[0]['name'] if hostnames and hostnames[0]['name'] else None
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

    return {
        "ip_address":        ip,
        "hostname":          hostname,
        "open_ports":        ",".join(str(p) for p in sorted(open_ports)),
        "port_details":      port_details,
        "os_type":           infer_os_from_banners(host_data),
        "criticality_score": assign_criticality(open_ports),
        "last_seen":         datetime.now(timezone.utc),
    }


def scan_subnet(subnet):
    print(f"\n[SCANNER] Starting scan on subnet: {subnet}")
    print(f"[SCANNER] Arguments: -sV --open -T4  --host-timeout 20s --max-retries 1")
    print(f"[SCANNER] Note: OS detection uses banner inference (no root required)")
    print(f"[SCANNER] Full scan active — top 1000 ports, 20s host timeout...\n")

    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=subnet, arguments='-sV --open -T4  --host-timeout 20s --max-retries 1')

    except nmap.PortScannerError as e:
        error_str = str(e)

        # ✅ FIX: Nmap prints WARNING/NOTE lines to stderr which python-nmap
        # incorrectly raises as PortScannerError. These are non-fatal —
        # the scan still completed and results are usable. Only bail out
        # on genuine fatal errors (empty output, nmap not found, etc).
        if 'WARNING' in error_str or 'NOTE' in error_str:
            print(f"[SCANNER] Nmap warning (non-fatal, scan still valid): {error_str.strip()}")
            # Fall through — nm still has valid scan results
        else:
            print(f"[SCANNER ERROR] Nmap scan failed: {error_str}")
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
        assets.append(parse_host(nm, ip))

    return assets


def save_assets_to_db(scan_results):
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
                ip       = asset_data["ip_address"]
                existing = session.query(Asset).filter_by(ip_address=ip).first()

                if existing:
                    existing.hostname          = asset_data["hostname"]
                    existing.open_ports        = asset_data["open_ports"]
                    existing.os_type           = asset_data["os_type"]
                    existing.criticality_score = asset_data["criticality_score"]
                    existing.last_seen         = asset_data["last_seen"]
                    print(f"[DB] UPDATED  : {ip}  (criticality={asset_data['criticality_score']})")
                    updated += 1
                else:
                    session.add(Asset(
                        ip_address        = ip,
                        hostname          = asset_data["hostname"],
                        open_ports        = asset_data["open_ports"],
                        os_type           = asset_data["os_type"],
                        criticality_score = asset_data["criticality_score"],
                        last_seen         = asset_data["last_seen"],
                    ))
                    print(f"[DB] INSERTED : {ip}  (criticality={asset_data['criticality_score']})")
                    inserted += 1

            except Exception as row_error:
                print(f"[DB ERROR] Failed to save {asset_data.get('ip_address', '?')}: {row_error}")
                errors += 1
                continue

        session.commit()
        print(f"\n[DB] Save complete — inserted: {inserted}, updated: {updated}, errors: {errors}")

    except Exception as e:
        session.rollback()
        print(f"[DB ERROR] Transaction failed, rolled back: {e}")
        raise

    finally:
        session.close()

    return {"inserted": inserted, "updated": updated, "errors": errors}


def print_scan_results(assets):
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


if __name__ == "__main__":
    TARGET_SUBNET = "192.168.1.0/24"
    print("\n" + "="*60)
    print("  Automated IP Risk Profiler — Asset Discovery Module")
    print("="*60)
    print(f"  Target : {TARGET_SUBNET}")
    print(f"  Time   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("="*60)
    Base.metadata.create_all(bind=engine)
    results = scan_subnet(TARGET_SUBNET)
    print_scan_results(results)
    summary = save_assets_to_db(results)
    print(f"\n  Found: {len(results)} | Inserted: {summary['inserted']} | Updated: {summary['updated']} | Errors: {summary['errors']}")