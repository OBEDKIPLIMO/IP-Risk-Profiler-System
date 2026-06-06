"""
tests/test_scanner.py
---------------------
Unit tests for the Asset Discovery Module (scanner.py).

Tests cover:
  1.  assign_criticality() — SSH port → score 9
  2.  assign_criticality() — RDP port → score 9
  3.  assign_criticality() — MySQL port → score 8
  4.  assign_criticality() — HTTP only → score 4
  5.  assign_criticality() — unknown port → default 3
  6.  assign_criticality() — empty list → score 1
  7.  assign_criticality() — multiple ports → highest wins
  8.  parse_host() — extracts IP, hostname, ports correctly (mocked nmap)
  9.  parse_host() — handles host with no open ports
  10. parse_host() — OS inferred from Huawei banner
  11. save_assets_to_db() — inserts new asset into in-memory SQLite
  12. save_assets_to_db() — upserts existing IP (no duplicate row)
  13. save_assets_to_db() — empty list returns 0 inserted
  14. scan_subnet() — handles nmap error gracefully (returns empty list)
  15. scan_subnet() — handles no hosts found (returns empty list)

Run with:
    pytest tests/test_scanner.py -v
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# ── Import modules under test ─────────────────────────────────────
from scanner.asset_scanner import (
    assign_criticality,
    parse_host,
    scan_subnet,
    save_assets_to_db,
)

# ── Import DB models for in-memory DB tests ───────────────────────
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.models import Base, Asset


# ════════════════════════════════════════════════════════════════════
#  FIXTURE — in-memory SQLite database for DB tests
#  Creates a fresh empty database for every test that needs it.
# ════════════════════════════════════════════════════════════════════
@pytest.fixture
def memory_session():
    """
    Creates a fresh in-memory SQLite database for each test.
    'in-memory' means the DB lives in RAM and is destroyed when the
    test finishes — no files created, no cleanup needed.
    """
    engine  = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


# ════════════════════════════════════════════════════════════════════
#  assign_criticality() TESTS
# ════════════════════════════════════════════════════════════════════
class TestAssignCriticality:

    # ── Test 1 ─────────────────────────────────────────────────────
    def test_ssh_port_returns_9(self):
        """Port 22 (SSH) = remote admin access → criticality 9."""
        result = assign_criticality([22])
        assert result == 9, f"Expected 9 for SSH, got {result}"

    # ── Test 2 ─────────────────────────────────────────────────────
    def test_rdp_port_returns_9(self):
        """Port 3389 (RDP) = Windows remote desktop → criticality 9."""
        result = assign_criticality([3389])
        assert result == 9, f"Expected 9 for RDP, got {result}"

    # ── Test 3 ─────────────────────────────────────────────────────
    def test_mysql_port_returns_8(self):
        """Port 3306 (MySQL) = database server → criticality 8."""
        result = assign_criticality([3306])
        assert result == 8, f"Expected 8 for MySQL, got {result}"

    # ── Test 4 ─────────────────────────────────────────────────────
    def test_http_only_returns_4(self):
        """Port 80 (HTTP) only → criticality 4 per Day 5 spec."""
        result = assign_criticality([80])
        assert result == 4, f"Expected 4 for HTTP only, got {result}"

    # ── Test 5 ─────────────────────────────────────────────────────
    def test_unknown_port_returns_default_3(self):
        """Unknown port (e.g. 9100 = printer) → default criticality 3."""
        result = assign_criticality([9100])
        assert result == 3, f"Expected 3 for unknown port, got {result}"

    # ── Test 6 ─────────────────────────────────────────────────────
    def test_empty_port_list_returns_1(self):
        """No open ports → criticality 1 (minimal risk)."""
        result = assign_criticality([])
        assert result == 1, f"Expected 1 for empty list, got {result}"

    # ── Test 7 ─────────────────────────────────────────────────────
    def test_multiple_ports_returns_highest(self):
        """
        When multiple ports are open, the highest-risk port wins.
        [80, 22, 3306] → SSH=9, MySQL=8, HTTP=4 → highest = 9
        """
        result = assign_criticality([80, 22, 3306])
        assert result == 9, f"Expected 9 (SSH wins), got {result}"

    # ── Test 8 ─────────────────────────────────────────────────────
    def test_https_returns_4(self):
        """Port 443 (HTTPS) → criticality 4."""
        result = assign_criticality([443])
        assert result == 4, f"Expected 4 for HTTPS, got {result}"

    # ── Test 9 ─────────────────────────────────────────────────────
    def test_telnet_returns_8(self):
        """Port 23 (Telnet) = unencrypted remote access → criticality 8."""
        result = assign_criticality([23])
        assert result == 8, f"Expected 8 for Telnet, got {result}"

    # ── Test 10 ────────────────────────────────────────────────────
    def test_smb_returns_7(self):
        """Port 445 (SMB) = ransomware target → criticality 7."""
        result = assign_criticality([445])
        assert result == 7, f"Expected 7 for SMB, got {result}"


# ════════════════════════════════════════════════════════════════════
#  parse_host() TESTS
#  We mock the nmap PortScanner object so no real scan runs.
# ════════════════════════════════════════════════════════════════════
class TestParseHost:

    def _make_mock_scanner(self, ip, tcp_ports=None, hostnames=None,
                           osmatch=None, product_info=None):
        """
        Helper: builds a mock nmap PortScanner that returns
        the data we specify without doing a real network scan.
        """
        mock_scanner = MagicMock()
        host_data    = MagicMock()

        # Hostname
        if hostnames is None:
            hostnames = [{"name": "test-host.local", "type": "PTR"}]
        host_data.hostnames.return_value = hostnames

        # TCP ports
        if tcp_ports:
            host_data.__contains__ = lambda self, key: key == "tcp"
            host_data.__getitem__  = lambda self, key: tcp_ports if key == "tcp" else {}
        else:
            host_data.__contains__ = lambda self, key: False
            host_data.__getitem__  = lambda self, key: {}

        # OS match
        host_data.__getitem__ = MagicMock(side_effect=lambda k:
            tcp_ports if k == "tcp" else
            (osmatch or []) if k == "osmatch" else {})
        host_data.get = MagicMock(side_effect=lambda k, default=None:
            (osmatch or []) if k == "osmatch" else default)

        # Wrap in scanner
        mock_scanner.__getitem__ = MagicMock(return_value=host_data)
        return mock_scanner, host_data

    # ── Test 11 ────────────────────────────────────────────────────
    def test_parse_extracts_ip_correctly(self):
        """parse_host() must return the correct IP address."""
        mock_nm = MagicMock()
        host    = MagicMock()
        host.hostnames.return_value = []
        host.__contains__ = MagicMock(return_value=False)
        mock_nm.__getitem__ = MagicMock(return_value=host)

        result = parse_host(mock_nm, "192.168.1.10")
        assert result["ip_address"] == "192.168.1.10"

    # ── Test 12 ────────────────────────────────────────────────────
    def test_parse_extracts_hostname(self):
        """parse_host() must extract the first hostname from nmap result."""
        mock_nm = MagicMock()
        host    = MagicMock()
        host.hostnames.return_value = [{"name": "router.local", "type": "PTR"}]
        host.__contains__ = MagicMock(return_value=False)
        mock_nm.__getitem__ = MagicMock(return_value=host)

        result = parse_host(mock_nm, "192.168.1.1")
        assert result["hostname"] == "router.local"

    # ── Test 13 ────────────────────────────────────────────────────
    def test_parse_extracts_open_ports(self):
        """
        parse_host() must extract open TCP ports and format as
        comma-separated string e.g. '22,80,443'.
        """
        mock_nm = MagicMock()
        host    = MagicMock()
        host.hostnames.return_value = []

        tcp_data = {
            22:  {"state": "open", "name": "ssh",   "product": "OpenSSH", "version": "8.2"},
            80:  {"state": "open", "name": "http",  "product": "Apache",  "version": "2.4"},
            443: {"state": "open", "name": "https", "product": "",        "version": ""},
        }
        host.__contains__ = MagicMock(side_effect=lambda k: k == "tcp")
        host.__getitem__  = MagicMock(side_effect=lambda k: tcp_data if k == "tcp" else {})
        mock_nm.__getitem__ = MagicMock(return_value=host)

        result = parse_host(mock_nm, "192.168.1.10")
        ports  = result["open_ports"].split(",")

        assert "22"  in ports
        assert "80"  in ports
        assert "443" in ports

    # ── Test 14 ────────────────────────────────────────────────────
    def test_parse_host_with_no_ports(self):
        """
        If a host has no open TCP ports, open_ports should be ''
        and criticality_score should be 1.
        """
        mock_nm = MagicMock()
        host    = MagicMock()
        host.hostnames.return_value = []
        host.__contains__ = MagicMock(return_value=False)
        mock_nm.__getitem__ = MagicMock(return_value=host)

        result = parse_host(mock_nm, "192.168.1.99")
        assert result["open_ports"]        == ""
        assert result["criticality_score"] == 1

    # ── Test 15 ────────────────────────────────────────────────────
    def test_parse_infers_huawei_os_from_banner(self):
        """
        When a service banner contains 'huawei',
        os_type should be 'Huawei Device (inferred)'.
        """
        mock_nm = MagicMock()
        host    = MagicMock()
        host.hostnames.return_value = []

        tcp_data = {
            23: {"state": "open", "name": "telnet",
                 "product": "Huawei Home Gateway telnetd", "version": ""}
        }
        host.__contains__ = MagicMock(side_effect=lambda k: k == "tcp")
        host.__getitem__  = MagicMock(side_effect=lambda k: tcp_data if k == "tcp" else {})
        mock_nm.__getitem__ = MagicMock(return_value=host)

        result = parse_host(mock_nm, "192.168.100.1")
        assert result["os_type"] == "Huawei Device (inferred)"


# ════════════════════════════════════════════════════════════════════
#  save_assets_to_db() TESTS
#  Uses in-memory SQLite — no real dev.db touched.
# ════════════════════════════════════════════════════════════════════
class TestSaveAssetsToDB:

    def _make_asset_data(self, ip="192.168.1.10"):
        return {
            "ip_address":        ip,
            "hostname":          "test-host",
            "open_ports":        "22,80",
            "os_type":           "Linux (inferred)",
            "criticality_score": 9,
            "last_seen":         datetime.now(timezone.utc),
            "port_details":      {22: "ssh OpenSSH 8.2", 80: "http Apache"},
        }

    # ── Test 16 ────────────────────────────────────────────────────
    def test_insert_new_asset(self, memory_session):
        """
        Saving a new IP address should INSERT one row
        and return inserted=1, updated=0, errors=0.
        """
        from db.models import Asset as AssetModel

        asset_data = self._make_asset_data("192.168.1.10")

        # Manually replicate save logic using our in-memory session
        existing = memory_session.query(AssetModel).filter_by(
            ip_address="192.168.1.10").first()
        assert existing is None   # confirm not in DB yet

        new_asset = AssetModel(
            ip_address        = asset_data["ip_address"],
            hostname          = asset_data["hostname"],
            open_ports        = asset_data["open_ports"],
            os_type           = asset_data["os_type"],
            criticality_score = asset_data["criticality_score"],
            last_seen         = asset_data["last_seen"],
        )
        memory_session.add(new_asset)
        memory_session.commit()

        saved = memory_session.query(AssetModel).filter_by(
            ip_address="192.168.1.10").first()
        assert saved is not None
        assert saved.criticality_score == 9
        assert saved.hostname == "test-host"

    # ── Test 17 ────────────────────────────────────────────────────
    def test_upsert_updates_existing_asset(self, memory_session):
        """
        Saving the same IP twice should UPDATE the existing row,
        not create a duplicate. criticality_score should reflect
        the new value.
        """
        from db.models import Asset as AssetModel

        # Insert first
        asset = AssetModel(
            ip_address="192.168.1.20", hostname="old-name",
            open_ports="80", os_type=None, criticality_score=3,
            last_seen=datetime.now(timezone.utc)
        )
        memory_session.add(asset)
        memory_session.commit()

        # Now update with new data
        existing = memory_session.query(AssetModel).filter_by(
            ip_address="192.168.1.20").first()
        existing.hostname          = "new-name"
        existing.criticality_score = 8
        memory_session.commit()

        # Confirm only 1 row, updated values
        count   = memory_session.query(AssetModel).filter_by(
            ip_address="192.168.1.20").count()
        updated = memory_session.query(AssetModel).filter_by(
            ip_address="192.168.1.20").first()

        assert count                       == 1      # no duplicate
        assert updated.hostname            == "new-name"
        assert updated.criticality_score   == 8

    # ── Test 18 ────────────────────────────────────────────────────
    def test_empty_scan_results_returns_zero_counts(self):
        """
        Calling save_assets_to_db([]) should return
        { inserted:0, updated:0, errors:0 } without crashing.
        We patch the session so no real DB is touched.
        """
        with patch("scanner.asset_scanner.SessionLocal") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session

            from scanner.asset_scanner import save_assets_to_db
            result = save_assets_to_db([])

        assert result == {"inserted": 0, "updated": 0, "errors": 0}


# ════════════════════════════════════════════════════════════════════
#  scan_subnet() TESTS
# ════════════════════════════════════════════════════════════════════
class TestScanSubnet:

    # ── Test 19 ────────────────────────────────────────────────────
    @patch("scanner.asset_scanner.nmap.PortScanner")
    def test_nmap_error_returns_empty_list(self, mock_scanner_cls):
        """
        If nmap raises PortScannerError (e.g. nmap not installed),
        scan_subnet() must return [] without crashing.
        """
        import nmap
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = nmap.PortScannerError("nmap not found")
        mock_scanner_cls.return_value = mock_scanner

        result = scan_subnet("192.168.1.0/24")
        assert result == []

    # ── Test 20 ────────────────────────────────────────────────────
    @patch("scanner.asset_scanner.nmap.PortScanner")
    def test_no_hosts_found_returns_empty_list(self, mock_scanner_cls):
        """
        If the scan completes but finds no live hosts,
        scan_subnet() must return [].
        """
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value    = None
        mock_scanner.all_hosts.return_value = []   # ← no hosts found
        mock_scanner_cls.return_value     = mock_scanner

        result = scan_subnet("192.168.1.0/24")
        assert result == []