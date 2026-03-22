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
    dest_port = flow.get("dest_port")
    if dest_port is None:
        dest_port = 0

    # ------------------ FEATURE VECTOR ------------------
    features = [
        dest_port,                             # Destination Port
        duration,                              # Flow Duration
        flow["fwd_packets"],                   # Total Fwd Packets
        flow["bwd_packets"],                   # Total Backward Packets
        flow["fwd_bytes"],                     # Total Length of Fwd Packets
        flow["bwd_bytes"],                     # Total Length of Bwd Packets
        mean_len,                              # Packet Length Mean
        std_len,                               # Packet Length Std
        flow["syn_count"],                     # SYN Flag Count
        flow["fin_count"],                     # FIN Flag Count
        flow["ack_count"]                      # ACK Flag Count
    ]

    # ------------------ SANITIZE ------------------
    features = np.array(features, dtype=float)

    # Replace NaN / inf (match training cleanup)
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)


    return features.tolist()