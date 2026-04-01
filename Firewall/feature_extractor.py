import numpy as np

def extract_features(flow):

    # ------------------ DURATION ------------------
    duration = flow["last_seen"] - flow["start_time"]  # in seconds

    # Prevent zero/near-zero duration
    if duration <= 0:
        duration = 1e-6 # 1 microsecond

    duration *= 1e6  # convert to microseconds

    # ------------------ PACKET LENGTH STATS ------------------
    packet_lengths = flow["packet_lengths"]

    if len(packet_lengths) > 1:
        mean_len = np.mean(packet_lengths)
        std_len = np.std(packet_lengths)
    elif len(packet_lengths) == 1:
        mean_len = packet_lengths[0]
        std_len = 0.0
    else:
        mean_len = 0
        std_len = 0
        
    # ------------------ SAFE PORT ------------------
    dest_port = flow["dest_port"]

    if dest_port is None:
        dest_port = 0

    # ------------------ FEATURE VECTOR ------------------

    # return features as dict to ensure firewall maps features correctly by name
    # firewall handles missing features

    return {
        "Destination Port": dest_port,
        "Flow Duration": duration,
        "Total Fwd Packets": flow["fwd_packets"],
        "Total Backward Packets": flow["bwd_packets"],
        "Total Length of Fwd Packets": flow["fwd_bytes"],
        "Total Length of Bwd Packets": flow["bwd_bytes"],
        "Packet Length Mean": mean_len,
        "Packet Length Std": std_len,
        "SYN Flag Count": flow["syn_count"],
        "FIN Flag Count": flow["fin_count"],
        "ACK Flag Count": flow["ack_count"]
    }

    # ------------------ SANITIZE ------------------