import time
from scapy.layers.inet import IP
from Firewall.Tests.test_helper import make_tcp_pkt, make_udp_pkt

class TestFlowManagerFlowKey:
    """_get_flow_key must produce consistent, bidirectional keys."""
 
    def setup_method(self):
        from Firewall.flow_manager import FlowManager
        self.fm = FlowManager()
 
    def test_tcp_packet_returns_key(self):
        pkt = make_tcp_pkt()
        key = self.fm._get_flow_key(pkt)
        assert key is not None
 
    def test_non_tcp_udp_returns_none(self):
        """ICMP-only packets should be ignored."""
        from scapy.layers.inet import ICMP
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
        key = self.fm._get_flow_key(pkt)
        assert key is None
 
    def test_bidirectional_same_key(self):
        """Forward and reverse packets must hash to the same flow."""
        fwd = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=12345, dport=80)
        rev = make_tcp_pkt(src="2.2.2.2", dst="1.1.1.1", sport=80,    dport=12345)
        assert self.fm._get_flow_key(fwd) == self.fm._get_flow_key(rev)
 
    def test_different_ips_different_key(self):
        pkt_a = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=12345, dport=80)
        pkt_b = make_tcp_pkt(src="3.3.3.3", dst="2.2.2.2", sport=12345, dport=80)
        assert self.fm._get_flow_key(pkt_a) != self.fm._get_flow_key(pkt_b)
 
    def test_different_protocol_different_key(self):
        tcp_pkt = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=5000, dport=53)
        udp_pkt = make_udp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=5000, dport=53)
        assert self.fm._get_flow_key(tcp_pkt) != self.fm._get_flow_key(udp_pkt)
 
 
class TestFlowManagerUpdateFlow:
    """update_flow must correctly initialise and accumulate flow state."""
 
    def setup_method(self):
        from Firewall.flow_manager import FlowManager
        self.fm = FlowManager()
 
    def test_new_flow_created(self):
        pkt = make_tcp_pkt(flags="S")
        self.fm.update_flow(pkt)
        assert len(self.fm.flows) == 1
 
    def test_same_flow_accumulates_packets(self):
        for i in range(5):
            pkt = make_tcp_pkt(flags="A")
            self.fm.update_flow(pkt)
        assert len(self.fm.flows) == 1
        flow = list(self.fm.flows.values())[0]
        assert flow["packet_count"] == 5
 
    def test_fwd_bwd_byte_counts(self):
        """Client → server packets go fwd; server → client go bwd."""
        # client uses higher (ephemeral) port → initiator is src
        fwd = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80,
                           flags="A", payload_size=100)
        rev = make_tcp_pkt(src="2.2.2.2", dst="1.1.1.1", sport=80,    dport=50000,
                           flags="A", payload_size=200)
        self.fm.update_flow(fwd)
        self.fm.update_flow(rev)
        flow = list(self.fm.flows.values())[0]
        assert flow["fwd_bytes"] > 0
        assert flow["bwd_bytes"] > 0
 
    def test_returns_flow_when_window_full(self):
        """update_flow returns the flow dict once window_size packets arrive."""
        for i in range(99):
            result = self.fm.update_flow(make_tcp_pkt(flags="A"))
            assert result is None   # not ready yet
        result = self.fm.update_flow(make_tcp_pkt(flags="A"))
        assert result is not None   # now ready
 
    def test_window_packets_capped_after_slide(self):
        """After the window slides, window_packets length should shrink."""
        from Firewall.flow_manager import FlowManager
        fm = FlowManager()
        for _ in range(100):
            fm.update_flow(make_tcp_pkt(flags="A"))
        flow = list(fm.flows.values())[0]
        # window_packets must not grow unboundedly past window_size
        assert len(flow["window_packets"]) <= flow["window_size"]
 
    def test_two_distinct_flows_tracked_separately(self):
        pkt_a = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80)
        pkt_b = make_tcp_pkt(src="3.3.3.3", dst="2.2.2.2", sport=50001, dport=80)
        self.fm.update_flow(pkt_a)
        self.fm.update_flow(pkt_b)
        assert len(self.fm.flows) == 2
 
 
class TestFlowManagerExpiry:
    """expire_flows must remove stale flows without touching active ones."""
 
    def setup_method(self):
        from Firewall.flow_manager import FlowManager
        self.fm = FlowManager()
 
    def test_expired_flow_removed(self):
        pkt = make_tcp_pkt()
        self.fm.update_flow(pkt)
        # Wind the clock back past FLOW_TIMEOUT
        for flow in self.fm.flows.values():
            flow["last_seen"] = time.time() - 9999
        expired = self.fm.expire_flows()
        assert len(expired) == 1
        assert len(self.fm.flows) == 0
 
    def test_active_flow_not_removed(self):
        pkt = make_tcp_pkt()
        self.fm.update_flow(pkt)
        expired = self.fm.expire_flows()
        assert len(expired) == 0
        assert len(self.fm.flows) == 1
 
    def test_mixed_expiry(self):
        pkt_a = make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=50000, dport=80)
        pkt_b = make_tcp_pkt(src="3.3.3.3", dst="4.4.4.4", sport=50001, dport=80)
        self.fm.update_flow(pkt_a)
        self.fm.update_flow(pkt_b)
 
        # Expire only first flow
        key_a = list(self.fm.flows.keys())[0]
        self.fm.flows[key_a]["last_seen"] = time.time() - 9999
 
        expired = self.fm.expire_flows()
        assert len(expired) == 1
        assert len(self.fm.flows) == 1