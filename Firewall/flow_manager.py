# flow_manager.py

import time
from scapy.layers.inet import IP, TCP, UDP

FLOW_TIMEOUT = 120  # seconds

class FlowManager:
    def __init__(self):
        """
        Initializes the FlowManager.

        self.flows:
            Dictionary used to store active flows.
            Key   -> Flow identifier (tuple)
            Value -> Flow statistics and metadata (dict)
        """
        self.flows = {}

    def _get_flow_key(self, pkt):
        """
        Generate a unique key that identifies a flow.

        A flow is defined here as:
            (src_ip, dst_ip, protocol)

        NOTE:
        - We intentionally ignore ports to make the flow more flexible.
        - This helps when ports change (e.g., NAT, ephemeral ports).
        - However, this may reduce ML model accuracy if the model was trained
          using port-based flow definitions.

        Returns:
            tuple: Flow key OR None if packet is unsupported
        """

        # Ensure packet contains an IP layer
        if IP not in pkt:
            return None
        if TCP not in pkt and UDP not in pkt:
            return None

        # Extract IP-level attributes
        src = pkt[IP].src   # Source IP address
        dst = pkt[IP].dst   # Destination IP address
        proto = pkt[IP].proto   # Protocol (TCP=6, UDP=17, etc.)

        # Initialize ports (used only for validation here)
        sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
        dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport

        # Bidirectional key — same key regardless of direction
        # make definition of flow more flexible - only consider IPs and protocol for flow key, ignore ports
        # ensures flows will accumulate even if ports change (e.g. due to NAT or ephemeral ports) - more robust flow tracking
        ip_pair = tuple(sorted([src, dst]))
        # Final flow key: (IP1, IP2, protocol, dest_port)
        service_port = min(sport, dport)
        return (ip_pair[0], ip_pair[1], proto, service_port)

    def update_flow(self, pkt):
        """
        Update or create a flow entry based on the incoming packet.

        This function:
        - Identifies the flow
        - Updates statistics
        - Tracks direction (forward/backward)
        - Tracks TCP flags (SYN, FIN, ACK)

        Returns:
            dict: Updated flow object OR None if packet ignored
        """
        
        # Generate flow key
        key = self._get_flow_key(pkt)
        if key is None:
            return

        # Current timestamp
        now = getattr(pkt, '_injected_time', None) or time.time()

        # ------------------ SAFE DEST PORT ------------------
        # Extract destination port safely for storage
        # (even though it is not part of the flow key)

        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            sport, dport = 0, 0

        dest_port = min(sport, dport)

        # If flow does not exist, initialize it
        if key not in self.flows:
            
            if sport > dport:
                initiator = pkt[IP].src   # src is using ephemeral port = client
            else:
                initiator = pkt[IP].dst

            self.flows[key] = {
                "src_ip": pkt[IP].src,  # Original source (defines forward direction)
                "dst_ip": pkt[IP].dst,  # Original destination
                "initiator": initiator,  # Initiator of the flow
                "dest_port":dest_port,  # Destination port (informational)
                "start_time": now,  # First packet timestamp
                "last_seen": now,   # Last packet timestamp
                "packet_count": 0,  # Packet counters
                "fwd_packets": 0,    # Directional packet counts
                "bwd_packets": 0,   
                "fwd_bytes": 0,     # Directional byte counts
                "bwd_bytes": 0,
                "packet_lengths": [],  # Packet size tracking (for statistics like mean/std later)
                "window_packets": [],
                "window_size": 100,
                "step_size": 5,
                "probability_history": [], 
                "syn_count": 0,     # TCP flag counters (useful for anomaly detection)
                "fin_count": 0,
                "ack_count": 0,
                "ml_verdict": "benign", 
            }

        # Retrieve existing flow and update it
        flow = self.flows[key]
        # Update last seen time for flow expiration logic
        flow["last_seen"] = now
        # Increment total packet count for the flow
        flow["packet_count"] += 1

        # Get packet length and store it
        pkt_len = len(pkt)
        flow["packet_lengths"].append(pkt_len)

        # Add packet to sliding window
        flow["window_packets"].append(pkt)

        # ------------------ UPDATE FLOW ------------------

        # Forward direction:
        #   Packet source == original flow source
        #
        # Backward direction:
        #   Packet source != original flow source

        # Forward direction = original src
        if pkt[IP].src == flow["initiator"]:
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += pkt_len
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += pkt_len

        # ------------------ TCP FLAG TRACKING ------------------
        # Only applicable for TCP packets
        if TCP in pkt:
            flags = pkt[TCP].flags

            # SYN flag (connection initiation)
            if pkt[TCP].flags & 0x02:  # SYN:
                flow["syn_count"] += 1
                # FIN flag (connection termination)
            if pkt[TCP].flags & 0x01:  # FIN:
                flow["fin_count"] += 1
                # ACK flag (connection acknowledgment)
            if pkt[TCP].flags & 0x10:  # ACK:
                flow["ack_count"] += 1

        # detect when window is ready (full) for ml prediction
        if len(flow["window_packets"]) >= flow["window_size"]:
            return flow  # signal ready for ML
                
        return None  # Not ready for ML yet


    def expire_flows(self):
        """

        Remove and return flows that have been inactive for longer than FLOW_TIMEOUT.

        A flow is considered expired if:
            current_time - last_seen > FLOW_TIMEOUT

        Returns:
            list: Expired flow dictionaries
        """

        now = time.time()
        expired = []

        # Iterate over a COPY of keys (important to avoid runtime errors)
        for key in list(self.flows.keys()):
            flow = self.flows[key]
            
            # Check inactivity duration
            if now - flow["last_seen"] > FLOW_TIMEOUT:
                # Add flow to expired list
                expired.append(flow)
                # Remove from active flows
                del self.flows[key]

        return expired
