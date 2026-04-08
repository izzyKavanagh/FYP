# train_model.py

import pandas as pd
import glob
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# =========================

# Load dataset files

# =========================

files = sorted(glob.glob("dataset_*.csv"))

if len(files) < 2:
    raise ValueError("You need at least 2 dataset files for proper train/test split")

print(f"[+] Found {len(files)} dataset files")

# =========================

# Split by session/file (CRITICAL FIX)

# =========================

# Use last file as test set (unseen traffic)

train_files = files[:-1]
test_files = files[-1:]

print(f"[+] Training on: {train_files}")
print(f"[+] Testing on: {test_files}")

train_df = pd.concat([pd.read_csv(f) for f in train_files], ignore_index=True)
test_df  = pd.concat([pd.read_csv(f) for f in test_files], ignore_index=True)

# =========================

# Basic cleaning

# =========================

print("\n[+] Train label distribution:")
print(train_df["label"].value_counts())

print("\n[+] Test label distribution:")
print(test_df["label"].value_counts())

# Drop NaNs

train_df.dropna(inplace=True)
test_df.dropna(inplace=True)

# =========================

# Feature selection

# =========================

FEATURES = [
"dest_port", "window_duration",
"fwd_packet_rate", "fwd_byte_rate",
"pkt_len_mean", "pkt_len_std",
"pkt_len_min", "pkt_len_max",
"syn_ratio", "fin_ratio", "ack_ratio"
]

X_train = train_df[FEATURES].values
y_train = (train_df["label"] == "malicious").astype(int).values

X_test = test_df[FEATURES].values
y_test = (test_df["label"] == "malicious").astype(int).values

# =========================

# Train model (less overfitting)

# =========================

model = RandomForestClassifier(
n_estimators=200,
max_depth=10,
min_samples_split=10,
class_weight="balanced",
random_state=42,
n_jobs=-1
)

print("\n[+] Training model...")
model.fit(X_train, y_train)

# =========================

# Evaluation (REALISTIC)

# =========================

y_pred = model.predict(X_test)

print("\n[+] Classification Report:")
print(classification_report(y_test, y_pred))

print("\n[+] Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# =========================

# Feature importance (debugging)

# =========================

print("\n[+] Feature Importances:")
for name, importance in zip(FEATURES, model.feature_importances_):
    print(f"{name:20s} -> {importance:.4f}")

# =========================

# Save model

# =========================

joblib.dump(model, "rf_model.pkl")
joblib.dump(FEATURES, "features.pkl")

print("\n[+] Model and features saved")
