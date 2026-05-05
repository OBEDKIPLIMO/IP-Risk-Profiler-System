"""
scanner/asset_scanner.py
------------------------
Asset Discovery Module for the Automated IP Risk Profiler System.

Responsibilities:
  1. Scan a subnet using Nmap to discover live devices
  2. Extract IP, hostname, open ports, and OS for each device
  3. Assign a criticality score (1-10) based on what ports are open
  4. Return structured results ready to be saved to the database
"""

import nmap
from datetime import datetime, timezone


# ── Criticality Rules ─────────────────────────────────────────────────────
# These ports indicate high-value targets on a network.
# The more sensitive the service, the higher the criticality score.

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
    80:    3,  # HTTP        — standard web server
    443:   3,  # HTTPS       — secure web server
    8080:  3,  # HTTP-alt    — common dev/proxy port
    8443:  3,  # HTTPS-alt
    53:    5,  # DNS         — domain name server
    161:   6,  # SNMP        — network management (often misconfigured)
}


# ── Function 1: Assign Criticality Score ─────────────────────────────────
def assign_criticality(open_ports_list):
    """
    Given a list of open port numbers, returns a criticality score 1-10.

    Logic:
    - Looks through each open port
    - Finds the highest-risk port from CRITICAL_PORTS rules above
    - Returns that as the device's criticality score
    - Defaults to 3 if no known sensitive ports are found

    Examples:
        [22, 3306]      → 9  (SSH + MySQL = critical server)
        [80, 443]       → 3  (just a web server = low risk)
        [9100]          → 3  (printer port = default low)
        []              → 1  (no open ports found = minimal risk)

    Args:
        open_ports_list (list): e.g. [22, 80, 443, 3306]

    Returns:
        int: criticality score between 1 and 10
    """
    if not open_ports_list:
        return 1  # no open ports — minimal risk

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
    Since we are not running with root privileges, the -O flag is not available.
    This function makes a best-effort OS guess by reading service banner text
    returned by -sV (version detection), which does NOT need root.

    It scans the 'product' and 'extrainfo' fields of each open port and looks
    for keywords that hint at the underlying operating system.

    Args:
        host_data: the nmap host object for one IP

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
        elif any(kw in combined for kw in ['linux', 'ubuntu', 'debian', 'centos', 'fedora', 'raspbian']):
            return 'Linux (inferred)'
        elif 'mac os' in combined or 'darwin' in combined:
            return 'macOS (inferred)'
        elif 'android' in combined:
            return 'Android (inferred)'

    return None  # could not determine OS from banners


# ── Function 3: Parse a Single Host ──────────────────────────────────────
def parse_host(scanner, ip):
    """
    Extracts all useful information from the nmap scan result for one IP.

    Args:
        scanner: the nmap.PortScanner object (already has scan results loaded)
        ip (str): the IP address to extract data for e.g. '192.168.100.10'

    Returns:
        dict: structured host data with all fields ready for the database
    """
    host_data = scanner[ip]  # access this IP's scan results

    # ── Hostname ──────────────────────────────────────────────────────────
    # nmap returns a list of hostnames — we take the first one if it exists
    hostnames = host_data.hostnames()
    hostname  = hostnames[0]['name'] if hostnames and hostnames[0]['name'] else None

    # ── Open TCP Ports ────────────────────────────────────────────────────
    # nmap organises results by protocol (tcp, udp)
    # we check if 'tcp' key exists first — some hosts may only have udp
    open_ports   = []
    port_details = {}  # stores {port: service_name} for richer output

    if 'tcp' in host_data:
        for port, port_info in host_data['tcp'].items():
            # port_info looks like:
            # {'state': 'open', 'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2', ...}
            if port_info['state'] == 'open':
                open_ports.append(port)
                service_name = port_info.get('name',    'unknown')
                product      = port_info.get('product', '')
                version      = port_info.get('version', '')
                port_details[port] = f"{service_name} {product} {version}".strip()

    # ── OS Detection ─────────────────────────────────────────────────────
    # We do NOT use -O (requires root on Linux).
    # Instead we infer the OS from service banner text returned by -sV.
    os_type = infer_os_from_banners(host_data)

    # ── Criticality Score ────────────────────────────────────────────────
    criticality = assign_criticality(open_ports)

    # ── Build the result dictionary ───────────────────────────────────────
    return {
        "ip_address":        ip,
        "hostname":          hostname,
        "open_ports":        ",".join(str(p) for p in sorted(open_ports)),  # "22,80,443"
        "port_details":      port_details,   # {22: "ssh OpenSSH 8.2", 80: "http Apache 2.4"}
        "os_type":           os_type,
        "criticality_score": criticality,
        "last_seen":         datetime.now(timezone.utc).isoformat(),
    }


# ── Function 4: Scan a Subnet ────────────────────────────────────────────
def scan_subnet(subnet):
    """
    Main function — scans an entire subnet and returns a list of discovered assets.

    What it does step by step:
      1. Creates an nmap PortScanner object
      2. Runs the scan with -sV (version detection) and --open (open ports only)
         NOTE: -O (OS detection) is intentionally excluded — it requires root on Linux.
               OS is inferred from service banners instead via infer_os_from_banners().
      3. Loops through every discovered host
      4. Calls parse_host() on each one
      5. Returns a list of structured asset dictionaries

    Args:
        subnet (str): The network range to scan.
                      Examples:
                        '192.168.100.0/24' — scan all 254 addresses in the subnet
                        '192.168.100.1-20' — scan only .1 to .20
                        '192.168.100.5'    — scan a single IP

    Returns:
        list: list of dicts, one per discovered host. Empty list if none found.

    Example return value:
        [
            {
                "ip_address":        "192.168.100.10",
                "hostname":          "router.local",
                "open_ports":        "22,80,443",
                "port_details":      {22: "ssh OpenSSH 8.2", 80: "http lighttpd 1.4"},
                "os_type":           "Linux (inferred)",
                "criticality_score": 9,
                "last_seen":         "2026-05-05T09:39:30+00:00"
            },
            ...
        ]
    """
    print(f"\n[SCANNER] Starting scan on subnet: {subnet}")
    print(f"[SCANNER] Arguments: -sV --open -T4")
    print(f"[SCANNER] Note: OS detection uses banner inference (no root required)")
    print(f"[SCANNER] This may take 1-3 minutes depending on network size...\n")

    # Step 1 — Create the scanner object
    nm = nmap.PortScanner()

    # Step 2 — Run the scan
    # -sV    : probe open ports to determine service/version info
    # --open : only show ports that are actually open
    # -T4    : timing template 4 = faster scan (safe for LAN use)
    # NOTE   : -O intentionally removed — requires root on Linux
    try:
        nm.scan(hosts=subnet, arguments='-sV --open -T4')
    except nmap.PortScannerError as e:
        print(f"[SCANNER ERROR] Nmap scan failed: {e}")
        print("[SCANNER] Make sure Nmap is installed: nmap --version")
        return []
    except Exception as e:
        print(f"[SCANNER ERROR] Unexpected error: {e}")
        return []

    # Step 3 — Check how many hosts were found
    discovered_hosts = nm.all_hosts()
    print(f"[SCANNER] Scan complete. Found {len(discovered_hosts)} live host(s).")

    if not discovered_hosts:
        print("[SCANNER] No hosts found. Check that the subnet is correct.")
        return []

    # Step 4 — Parse each discovered host
    assets = []
    for ip in discovered_hosts:
        print(f"[SCANNER] Parsing host: {ip}")
        asset = parse_host(nm, ip)
        assets.append(asset)

    return assets


# ── Print Helper ──────────────────────────────────────────────────────────
def print_scan_results(assets):
    """
    Prints scan results in a clean, readable format to the terminal.
    Used to confirm the data looks correct before saving to the database.

    Args:
        assets (list): list of asset dicts returned by scan_subnet()
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
    print("[RESULTS] Next step: save these assets to the database.\n")


# ── Run directly to test ──────────────────────────────────────────────────
# Run from your project root:
#   python scanner.py
#
# To find your subnet on Linux Mint:
#   Open terminal → type 'ip a' → look for your Wi-Fi or eth0 IP
#   If your IP is 192.168.100.45, your subnet is 192.168.100.0/24

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

    # Run the scan
    results = scan_subnet(TARGET_SUBNET)

    # Print what was found — confirm data looks correct
    print_scan_results(results)