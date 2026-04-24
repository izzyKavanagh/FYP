import time
import numpy as np
from Firewall.Tests.test_helper import make_tcp_pkt

def _make_flow_with_packets(n=10, src="1.1.1.1", dst="2.2.2.2",
                            sport=50000, dport=80, payload_size=50):
    """Build a synthetic flow dict populated with n packets."""
    now = time.time()
    packets = []
    for i in range(n):
        pkt = make_tcp_pkt(src=src, dst=dst, sport=sport, dport=dport,
                           flags="A", payload_size=payload_size,
                           ts=now + i * 0.01)
        packets.append(pkt)
 
    flow = {
        "src_ip":             src,
        "dst_ip":             dst,
        "initiator":          src,
        "dest_port":          dport,
        "start_time":         now,
        "last_seen":          now + n * 0.01,
        "packet_count":       n,
        "fwd_packets":        n,
        "bwd_packets":        0,
        "fwd_bytes":          n * payload_size,
        "bwd_bytes":          0,
        "packet_lengths":     [len(p) for p in packets],
        "window_packets":     packets,
        "window_size":        n,
        "step_size":          5,
        "probability_history":[],
        "syn_count":          0,
        "fin_count":          0,
        "ack_count":          n,
        "ml_verdict":         "benign",
    }
    return flow
 
 
class TestExtractWindowFeatures:
    """extract_window_features must return a complete, valid feature dict."""
 
    def test_returns_dict(self):
        from Firewall.feature_extractor import extract_window_features
        flow = _make_flow_with_packets(10)
        result = extract_window_features(flow)
        assert isinstance(result, dict)
 
    def test_returns_none_for_single_packet(self):
        """A window of 1 packet has no inter-arrival time — should return None."""
        from Firewall.feature_extractor import extract_window_features
        flow = _make_flow_with_packets(1)
        result = extract_window_features(flow)
        assert result is None
 
    def test_all_expected_keys_present(self):
        from Firewall.feature_extractor import extract_window_features
        EXPECTED = {
            "dest_port", "window_duration",
            "fwd_packet_rate", "fwd_byte_rate",
            "bwd_packet_rate", "bwd_byte_rate",
            "pkt_len_mean", "pkt_len_std",
            "pkt_len_min", "pkt_len_max",
            "syn_ratio", "fin_ratio", "ack_ratio",
            "rst_ratio", "psh_ratio",
            "fwd_bwd_ratio", "byte_ratio",
            "iat_mean", "iat_std", "iat_min",
        }
        flow = _make_flow_with_packets(20)
        result = extract_window_features(flow)
        assert result is not None
        assert EXPECTED.issubset(set(result.keys()))
 
    def test_no_nan_or_inf_values(self):
        """Every value must be finite — the firewall cleans NaN/inf but the
        extractor itself should not produce them under normal conditions."""
        from Firewall.feature_extractor import extract_window_features
        flow = _make_flow_with_packets(20)
        result = extract_window_features(flow)
        assert result is not None
        for k, v in result.items():
            assert np.isfinite(v), f"Feature '{k}' is not finite: {v}"
 
    def test_packet_rates_positive(self):
        from Firewall.feature_extractor import extract_window_features
        flow = _make_flow_with_packets(20)
        result = extract_window_features(flow)
        assert result["fwd_packet_rate"] >= 0
        assert result["bwd_packet_rate"] >= 0
 
    def test_zero_bwd_traffic_handled(self):
        """Flows with no backward traffic must not crash (div-by-zero guard)."""
        from Firewall.feature_extractor import extract_window_features
        flow = _make_flow_with_packets(20)
        # All packets are forward — bwd_bytes stays 0
        result = extract_window_features(flow)
        assert result is not None
        assert np.isfinite(result["byte_ratio"])
        assert np.isfinite(result["fwd_bwd_ratio"])
 
 
class TestExtractFeatures:
    """extract_features (full-flow, non-windowed) smoke tests."""
 
    def test_returns_dict_with_core_keys(self):
        from Firewall.feature_extractor import extract_features
        flow = _make_flow_with_packets(10)
        result = extract_features(flow)
        assert "Destination Port" in result
        assert "Flow Duration" in result
        assert "SYN Flag Count" in result
 
    def test_none_dest_port_replaced_with_zero(self):
        from Firewall.feature_extractor import extract_features
        flow = _make_flow_with_packets(10)
        flow["dest_port"] = None
        result = extract_features(flow)
        assert result["Destination Port"] == 0