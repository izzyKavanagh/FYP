# flow_manager.py

import time
from scapy.layers.inet import IP, TCP, UDP

FLOW_TIMEOUT = 30  # seconds

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

        # Normalize flow (make it bidirectional) !! fixes issue with flow not accumulating 
        # flow was unidirectional - packets never accumulated 
        # ml model was trained on bidirectional flows - so this is necessary for accurate predictions
        #if (src, sport) <= (dst, dport):
        #    return (src, dst, sport, dport, proto)
        #else:
        #    return (dst, src, dport, sport, proto)

        # make definition of flow more flexible - only consider IPs and protocol for flow key, ignore ports
        # ensures flows will accumulate even if ports change (e.g. due to NAT or ephemeral ports) - more robust flow tracking
        ip_pair = tuple(sorted([src, dst]))

        return (ip_pair[0], ip_pair[1], proto)

    def update_flow(self, pkt):
        
        key = self._get_flow_key(pkt)
        if key is None:
            return

        now = time.time()

        if key not in self.flows:
            self.flows[key] = {
                "src_ip": key[0],
                "dst_ip": key[1],
                "dest_port": pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0,
                "start_time": now,
                "last_seen": now,
                "packet_count": 0,
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
        flow["packet_count"] += 1

        pkt_len = len(pkt)
        flow["packet_lengths"].append(pkt_len)

        # Forward direction = original src
        if pkt[IP].src == flow["src_ip"]:
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
                
        return flow

    def expire_flows(self):
        now = time.time()
        expired = []

        for key in list(self.flows.keys()):
            flow = self.flows[key]
            if now - flow["last_seen"] > FLOW_TIMEOUT:
                expired.append(flow)
                del self.flows[key]

        return expired