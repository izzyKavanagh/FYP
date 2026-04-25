import numpy as np
from scapy.layers.inet import IP, TCP


def extract_features(flow):
    """
    Convert a flow dictionary into a feature vector for ML prediction.

    This function is CRITICAL because:
    - It defines the exact input to the ML model
    - Feature order, scaling, and handling MUST match training data
    - Any mismatch here can completely break model accuracy

    Input:
        flow (dict): Flow statistics collected by FlowManager

    Output:
        dict: Feature name -> value
              (Later converted to ordered list using feature_names)
    """


    # ------------------ DURATION ------------------

    # Duration = time difference between first and last packet
    # Measured in seconds initially
    duration = flow["last_seen"] - flow["start_time"]  # in seconds

    # Prevent zero/near-zero duration
    if duration <= 0:
        duration = 1e-6 # 1 microsecond

    duration *= 1e6  # convert to microseconds

    # ------------------ PACKET LENGTH STATS ------------------

    # List of packet sizes observed in this flow
    packet_lengths = flow["packet_lengths"]

    # Compute statistical features safely
    if len(packet_lengths) > 1:
        # Mean packet size (captures average payload behavior)
        mean_len = np.mean(packet_lengths)
        # Standard deviation (captures variability / burstiness)
        std_len = np.std(packet_lengths)
    elif len(packet_lengths) == 1:
        # If only one packet:
        # - Mean = that packet size
        # - Std deviation = 0 (no variation)
        mean_len = packet_lengths[0]
        std_len = 0.0
    else:
        # No packets (should not happen, but safe fallback)
        mean_len = 0
        std_len = 0
        
    # ------------------ SAFE PORT ------------------

    # Port is useful for:
    # - Identifying service type (HTTP, DNS, etc.)
    # - ML model patterns (e.g., attacks on specific ports)
    dest_port = flow["dest_port"]

    # Safety check:
    # Ensure no None values are passed into ML model
    if dest_port is None:
        dest_port = 0

    # ------------------ FEATURE VECTOR ------------------

    # return features as dict to ensure firewall maps features correctly by name
    # firewall handles missing features

    return {
        # ------------------ BASIC FLOW INFO ------------------
        "Destination Port": dest_port,
        # Total flow lifetime (in microseconds)
        "Flow Duration": duration,

        # ------------------ TRAFFIC VOLUME ------------------
        # Forward direction = original source → destination
        "Total Fwd Packets": flow["fwd_packets"],
        # Backward direction = response traffic
        "Total Backward Packets": flow["bwd_packets"],
        # Total bytes sent forward
        "Total Length of Fwd Packets": flow["fwd_bytes"],
        # Total bytes sent backward
        "Total Length of Bwd Packets": flow["bwd_bytes"],

        # ------------------ PACKET SIZE STATS ------------------
        # Average packet size
        "Packet Length Mean": mean_len,
        # Variability of packet sizes
        "Packet Length Std": std_len,

        # ------------------ TCP FLAG FEATURES ------------------
        # SYN:
        # - Indicates connection attempts
        # - High values may indicate SYN flood attack
        "SYN Flag Count": flow["syn_count"],
        # FIN:
        # - Indicates connection termination
        "FIN Flag Count": flow["fin_count"],
        # ACK:
        # - Indicates established communication
        # - Useful for distinguishing normal vs abnormal traffic
        "ACK Flag Count": flow["ack_count"]
    }

def extract_window_features(flow):
    packets = flow["window_packets"][-flow["window_size"]:]
    if len(packets) < 2:
        return None

    initiator = flow["initiator"]
    fwd_packets = 0
    bwd_packets = 0
    fwd_bytes = 0
    bwd_bytes = 0
    packet_lengths = []
    syn_count = fin_count = ack_count = rst_count = psh_count = 0
    timestamps = []
    inter_arrival_times = []

    for i, pkt in enumerate(packets):
        pkt_len = len(pkt)
        packet_lengths.append(pkt_len)
        ts = getattr(pkt, '_injected_time', None) or float(pkt.time)
        timestamps.append(ts)

        if i > 0:
            inter_arrival_times.append(ts - timestamps[i-1])

        if pkt[IP].src == initiator:
            fwd_packets += 1
            fwd_bytes += pkt_len
        else:
            bwd_packets += 1
            bwd_bytes += pkt_len

        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02: syn_count += 1
            if flags & 0x01: fin_count += 1
            if flags & 0x10: ack_count += 1
            if flags & 0x04: rst_count += 1   # NEW: RST flag
            if flags & 0x08: psh_count += 1   # NEW: PSH flag (data push)

    total_packets = len(packets)
    window_duration = max(timestamps[-1] - timestamps[0], 1e-6)

    iat_mean = np.mean(inter_arrival_times) if inter_arrival_times else 0
    iat_std  = np.std(inter_arrival_times)  if inter_arrival_times else 0
    iat_min  = np.min(inter_arrival_times)  if inter_arrival_times else 0

    # Ratio of fwd to bwd traffic — very high = potential scan or exfil
    fwd_bwd_ratio = fwd_packets / max(bwd_packets, 1)
    # Byte ratio — captures asymmetric flows (amplification, exfil)
    byte_ratio = fwd_bytes / max(bwd_bytes, 1)

    return {
        "dest_port":        flow["dest_port"],
        "window_duration":  window_duration,
        "fwd_packet_rate":  fwd_packets / window_duration,
        "fwd_byte_rate":    fwd_bytes / window_duration,
        "bwd_packet_rate":  bwd_packets / window_duration,   # NEW
        "bwd_byte_rate":    bwd_bytes / window_duration,     # NEW
        "pkt_len_mean":     np.mean(packet_lengths),
        "pkt_len_std":      np.std(packet_lengths),
        "pkt_len_min":      np.min(packet_lengths),
        "pkt_len_max":      np.max(packet_lengths),
        "syn_ratio":        syn_count / total_packets,
        "fin_ratio":        fin_count / total_packets,
        "ack_ratio":        ack_count / total_packets,
        "rst_ratio":        rst_count / total_packets,       # NEW
        "psh_ratio":        psh_count / total_packets,       # NEW
        "fwd_bwd_ratio":    fwd_bwd_ratio,                   # NEW
        "byte_ratio":       byte_ratio,                      # NEW
        "iat_mean":         iat_mean,                        # NEW
        "iat_std":          iat_std,                         # NEW
        "iat_min":          iat_min,                         # NEW
    }
