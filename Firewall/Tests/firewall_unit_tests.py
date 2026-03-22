import unittest
from scapy.all import IP, TCP, UDP, ICMP
from Firewall import extract_connection_info, get_flow_id, track_connection, is_established

class TestFirewallHelpers(unittest.TestCase):
    def setUp(self):
        # Reset connection table before each test
        global connection_table
        connection_table = set()

    def test_extract_connection_info_tcp(self):
        pkt = IP()/TCP(sport=1234, dport=80)
        proto, sport, dport = extract_connection_info(pkt)
        self.assertEqual(proto, "TCP")
        self.assertEqual(sport, 1234)
        self.assertEqual(dport, 80)

    def test_extract_connection_info_udp(self):
        pkt = IP()/UDP(sport=53, dport=1234)
        proto, sport, dport = extract_connection_info(pkt)
        self.assertEqual(proto, "UDP")
        self.assertEqual(sport, 53)
        self.assertEqual(dport, 1234)

    def test_extract_connection_info_icmp(self):
        pkt = IP()/ICMP()
        proto, sport, dport = extract_connection_info(pkt)
        self.assertEqual(proto, "ICMP")
        self.assertEqual(sport, "-")
        self.assertEqual(dport, "-")

    def test_track_and_check_connection(self):
        pkt = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=1000, dport=80)
        track_connection(pkt)
        self.assertTrue(is_established(pkt))

if __name__ == "__main__":
    unittest.main()