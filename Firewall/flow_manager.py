# flow_manager.py

import time
from scapy.layers.inet import IP, TCP, UDP
import numpy as np

FLOW_TIMEOUT = 10  # seconds

class FlowManager:
    def __init__(self):
        self.flows = {}

    def _get_flow_key(self, pkt):
        if IP not in pkt:
            return None

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto

        sport = None
        dport = None

        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        return (src, dst, sport, dport, proto)

    def update_flow(self, pkt):
        key = self._get_flow_key(pkt)
        if key is None:
            return

        now = time.time()

        if key not in self.flows:
            self.flows[key] = {
                "src_ip": key[0],
                "dst_ip": key[1],
                "dest_port": key[3],
                "start_time": now,
                "last_seen": now,
                "fwd_packets": 0,
                "bwd_packets": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
                "packet_lengths": [],
                "syn_count": 0,
                "fin_count": 0,
                "ack_count": 0
            }

        flow = self.flows[key]
        flow["last_seen"] = now

        pkt_len = len(pkt)
        flow["packet_lengths"].append(pkt_len)

        # Forward direction = original src
        if pkt[IP].src == key[0]:
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += pkt_len
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += pkt_len

        if TCP in pkt:
            flags = pkt[TCP].flags

            if "S" in str(flags):
                flow["syn_count"] += 1
            if "F" in str(flags):
                flow["fin_count"] += 1
            if "A" in str(flags):
                flow["ack_count"] += 1

    def expire_flows(self):
        now = time.time()
        expired = []

        for key in list(self.flows.keys()):
            flow = self.flows[key]
            if now - flow["last_seen"] > FLOW_TIMEOUT:
                expired.append(flow)
                del self.flows[key]

        return expired