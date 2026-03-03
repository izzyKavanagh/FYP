import numpy as np

def extract_features(flow):

    duration = flow["last_seen"] - flow["start_time"]

    packet_lengths = flow["packet_lengths"]

    if len(packet_lengths) > 0:
        mean_len = np.mean(packet_lengths)
        std_len = np.std(packet_lengths)
    else:
        mean_len = 0
        std_len = 0

    features = [
        flow["dest_port"],                     # Destination Port
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

    return features