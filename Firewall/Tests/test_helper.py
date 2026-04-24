from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

def make_tcp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=12345, dport=80,
                 flags="S", payload_size=0, ts=None):
    """Build a minimal TCP/IP packet for testing."""
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload_size:
        pkt = pkt / Raw(b"X" * payload_size)
    if ts is not None:
        pkt._injected_time = ts   # used by feature_extractor / flow_manager
    return pkt
 
def make_udp_pkt(src="1.1.1.1", dst="2.2.2.2", sport=54321, dport=53,
                 payload_size=0, ts=None):
    pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    if payload_size:
        pkt = pkt / Raw(b"Y" * payload_size)
    if ts is not None:
        pkt._injected_time = ts
    return pkt