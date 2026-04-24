import joblib
from Firewall.feature_extractor import extract_features

ml_model = joblib.load("rf_model.pkl")

# Example fake flow
flow = {
    "src_ip": "192.168.0.100",
    "dst_ip": "192.168.0.1",
    "dest_port": 80,
    "start_time": 0,
    "last_seen": 1,
    "fwd_packets": 2,
    "bwd_packets": 2,
    "fwd_bytes": 500,
    "bwd_bytes": 500,
    "packet_lengths": [250, 250, 250, 250],
    "syn_count": 1,
    "fin_count": 0,
    "ack_count": 3
}

features = extract_features(flow)
prediction = ml_model.predict([features])[0]

# Assert expected outcome
assert prediction in (0, 1), "Prediction must be 0 (Benign) or 1 (Malicious)"
print("Integration test passed: Prediction =", "Malicious" if prediction==1 else "Benign")
