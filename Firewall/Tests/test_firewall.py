import time
import pytest
from unittest.mock import patch, MagicMock
from scapy.layers.inet import IP
from Firewall.Tests.test_helper import make_tcp_pkt, make_udp_pkt

@pytest.fixture(autouse=True)
def patch_firewall_side_effects(monkeypatch):
    """
    Prevent firewall.py from calling iptables, starting Prometheus,
    or touching real files when imported in tests.
    """
    import sys
 
    # Stub heavy / privileged dependencies before import
    fake_nfq  = MagicMock()
    fake_prom = MagicMock()
 
    monkeypatch.setitem(sys.modules, "netfilterqueue",       fake_nfq)
    monkeypatch.setitem(sys.modules, "prometheus_client",    fake_prom)
    monkeypatch.setitem(sys.modules, "ml_model",             MagicMock())
    monkeypatch.setitem(sys.modules, "flow_manager",         MagicMock())
    monkeypatch.setitem(sys.modules, "feature_extractor",    MagicMock())
 
    # Patch joblib.load so features.pkl / rf_model.pkl aren't needed
    monkeypatch.setattr("joblib.load", lambda *a, **kw: [])
 
    # Prevent Prometheus from actually binding port 8000
    fake_prom.Counter.return_value  = MagicMock()
    fake_prom.Gauge.return_value    = MagicMock()
    fake_prom.Histogram.return_value= MagicMock()
    fake_prom.start_http_server     = MagicMock()
 
    yield
 
 
class TestBlacklist:
 
    def _fresh_firewall(self):
        """Re-import firewall with a clean blacklist each test."""
        import sys
        # Remove cached module so blacklist dict starts empty
        sys.modules.pop("Firewall.firewall", None)
        import Firewall.firewall as fw
        fw.blacklist.clear()
        return fw
 
    def test_ip_not_in_empty_blacklist(self):
        fw = self._fresh_firewall()
        assert fw.is_blacklisted("9.9.9.9") is False
 
    def test_add_then_detect(self):
        fw = self._fresh_firewall()
        fw.add_to_blacklist("9.9.9.9")
        assert fw.is_blacklisted("9.9.9.9") is True
 
    def test_expired_entry_removed(self):
        fw = self._fresh_firewall()
        # Set expiry in the past
        fw.blacklist["9.9.9.9"] = time.time() - 1
        with patch("firewall.remove_block_ip"):   # don't run iptables
            result = fw.is_blacklisted("9.9.9.9")
        assert result is False
        assert "9.9.9.9" not in fw.blacklist
 
    def test_active_entry_not_removed(self):
        fw = self._fresh_firewall()
        fw.blacklist["9.9.9.9"] = time.time() + 9999
        assert fw.is_blacklisted("9.9.9.9") is True
 
 
class TestConnectionTracking:
 
    def _fresh_firewall(self):
        import sys
        sys.modules.pop("Firewall.firewall", None)
        import Firewall.firewall as fw
        fw.connection_table.clear()
        return fw
 
    def test_new_connection_not_established(self):
        fw = self._fresh_firewall()
        pkt = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80)
        assert fw.is_established(pkt) is False
 
    def test_tracked_connection_is_established(self):
        fw = self._fresh_firewall()
        pkt = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80)
        fw.track_connection(pkt)
        assert fw.is_established(pkt) is True
 
    def test_reverse_direction_also_established(self):
        fw = self._fresh_firewall()
        fwd = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80)
        rev = make_tcp_pkt(src="2.2.2.2", dst="1.1.1.1", sport=80,    dport=50000)
        fw.track_connection(fwd)
        assert fw.is_established(rev) is True
 
    def test_expired_connection_not_established(self):
        fw = self._fresh_firewall()
        pkt = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80)
        fw.track_connection(pkt)
        # Expire all entries
        for k in list(fw.connection_table.keys()):
            fw.connection_table[k] = time.time() - 1
        assert fw.is_established(pkt) is False
 
    def test_icmp_packet_ignored_by_tracking(self):
        """is_established must not crash on ICMP (no ports)."""
        from scapy.layers.inet import ICMP
        fw = self._fresh_firewall()
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
        # Should return False gracefully, not raise
        assert fw.is_established(pkt) is False
 
    def test_cleanup_removes_expired_entries(self):
        fw = self._fresh_firewall()
        pkt = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80)
        fw.track_connection(pkt)
        for k in list(fw.connection_table.keys()):
            fw.connection_table[k] = time.time() - 1
        fw.cleanup_connection_table()
        assert len(fw.connection_table) == 0
 
    def test_cleanup_keeps_active_entries(self):
        fw = self._fresh_firewall()
        pkt = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80)
        fw.track_connection(pkt)
        fw.cleanup_connection_table()
        assert len(fw.connection_table) == 2   # inbound + outbound
 
    def test_fin_teardown_removes_entry(self):
        fw = self._fresh_firewall()
        pkt = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80)
        fw.track_connection(pkt)
        fin = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80,
                           flags="F")
        fw.handle_tcp_teardown(fin)
        assert fw.is_established(pkt) is False
 
    def test_rst_teardown_removes_entry(self):
        fw = self._fresh_firewall()
        pkt = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80)
        fw.track_connection(pkt)
        rst = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80,
                           flags="R")
        fw.handle_tcp_teardown(rst)
        assert fw.is_established(pkt) is False
 
 
class TestExtractConnectionInfo:
 
    def _fresh_firewall(self):
        import sys
        sys.modules.pop("Firewall.firewall", None)
        from Firewall import firewall as fw
        return fw
 
    def test_tcp_returns_correct_info(self):
        fw = self._fresh_firewall()
        pkt = make_tcp_pkt(sport=12345, dport=80)
        proto, sport, dport = fw.extract_connection_info(pkt)
        assert proto  == "TCP"
        assert sport  == 12345
        assert dport  == 80
 
    def test_udp_returns_correct_info(self):
        fw = self._fresh_firewall()
        pkt = make_udp_pkt(sport=54321, dport=53)
        proto, sport, dport = fw.extract_connection_info(pkt)
        assert proto  == "UDP"
        assert sport  == 54321
        assert dport  == 53
 
    def test_icmp_returns_dash_ports(self):
        from scapy.layers.inet import ICMP
        fw = self._fresh_firewall()
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
        proto, sport, dport = fw.extract_connection_info(pkt)
        assert proto  == "ICMP"
        assert sport  == "-"
        assert dport  == "-"