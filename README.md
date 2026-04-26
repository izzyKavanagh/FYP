# ML-Enhanced Stateful Network Firewall

## Overview

This project implements a stateful packet-filtering firewall enhanced with a Random Forest machine learning classifier for real-time network threat detection. Packets are intercepted at the kernel level using the Linux Netfilter framework, aggregated into bidirectional network flows, and classified using a sliding-window feature extraction pipeline. Because classification operates exclusively on flow-level metadata — packet rates, flag ratios, inter-arrival times, and directional byte statistics — the system functions identically whether traffic is encrypted or not, making it applicable to real-world networks where the majority of traffic runs over TLS.

The system was developed and evaluated within a controlled three-node GNS3 network emulation environment. It detects five attack categories that a static rule set permits unconditionally: SYN flood, HTTP flood, DNS amplification, stealth port scan, and data exfiltration.

## Screencast
[Screencast Here](https://screenrec.com/share/avZmei3NUh)

## Features

- Stateful connection tracking with TCP session establishment and teardown handling
- Bidirectional flow management using a four-tuple flow key (IP pair, protocol, service port)
- 100-packet sliding window feature extraction (step size: 5 packets)
- Real-time Random Forest inference integrated directly into the packet-processing loop
- Threshold-based IP blacklisting with automatic expiry and iptables rule management
- Smoothed probability scoring (5-prediction rolling average) to prevent oscillation near the decision boundary
- Default-deny policy with explicit allow rules for ICMP, HTTP/HTTPS, and DNS traffic
- Prometheus metrics exposed on port 8000 with Grafana dashboard for real-time monitoring
- Supports TCP, UDP, and ICMP traffic
- Custom dataset collection pipeline using the same feature extraction logic as live inference

## How It Works

1. An iptables NFQUEUE rule intercepts all forwarded packets and passes them to user space.
2. Each packet is parsed using Scapy and its corresponding bidirectional flow is updated in the flow manager.
3. When a sliding window of 100 packets has accumulated for a flow, 20 rate-based statistical features are extracted.
4. The trained Random Forest classifier issues a probability score for the window.
5. A smoothed score (rolling average of last 5 predictions) is compared against the configured threshold (default: 0.8).
6. If the threshold is exceeded, the source IP is blacklisted and an iptables DROP rule is inserted to block further traffic.
7. Packets from blacklisted IPs are dropped immediately without further processing.
8. Throughout, Prometheus metrics are updated and visualised via a Grafana dashboard.

## Feature Set

Twenty rate-based statistical features are extracted per 100-packet window:

| Category | Features |
|---|---|
| Rate | `fwd_packet_rate`, `bwd_packet_rate`, `fwd_byte_rate`, `bwd_byte_rate` |
| Packet size | `pkt_len_mean`, `pkt_len_std`, `pkt_len_min`, `pkt_len_max` |
| TCP flags | `syn_ratio`, `fin_ratio`, `ack_ratio`, `rst_ratio`, `psh_ratio` |
| Asymmetry | `fwd_bwd_ratio`, `byte_ratio` |
| Inter-arrival time | `iat_mean`, `iat_std`, `iat_min` |
| Metadata | `dst_port`, `window_duration` |

## ML Model

- **Algorithm:** Random Forest (scikit-learn `RandomForestClassifier`)
- **Estimators:** 200 trees, max depth 10, min samples split 10
- **Class weights:** Balanced
- **Training data:** Custom dataset collected within the GNS3 environment using the same sliding-window pipeline as live inference
- **Serialisation:** Model and feature name list saved via joblib and loaded at firewall startup

> **Note:** An initial attempt to train on the public CICIDS2017 benchmark dataset failed in live deployment due to a structural mismatch between its complete-flow extraction methodology and the sliding-window inference path. The custom dataset resolves this.

## Traffic Generation

Two Python scripts run on the Kali attacker VM:

- **`attack_scripts.py`** — generates a randomised sequence of five attack types: SYN flood (`hping3`), HTTP flood (`curl`), DNS amplification (`dig`), stealth port scan (`nmap -sS`), and data exfiltration (HTTP POST).
- **`normal_traffic.py`** — generates seven benign traffic patterns using Apache Bench, curl, wget, mixed-size HTTP POSTs, DNS queries, bursty browsing, and slow steady requests.

Both scripts serve a dual purpose: generating the labelled training dataset and producing live traffic for evaluation.

## Application-Layer Services (Victim VM)

| Service | Purpose |
|---|---|
| Apache HTTP Server | Target for HTTP-based traffic and attacks |
| BIND9 | DNS resolution; target for DNS amplification simulation |
| OpenSSH | Encrypted session traffic |
| iperf3 | Controlled throughput testing during development |

## Monitoring

Prometheus metrics are exposed on port 8000 and include:

- Total allowed and blocked packet counts, broken down by reason (`ml_blacklist`, `ml_verdict`, `default_deny`)
- Per-source-IP smoothed ML probability gauge
- Active flow count and current blacklist size
- ML prediction counters (malicious / benign)

A Grafana dashboard is accessible at `http://<firewall_ip>:3000`.

## Requirements

- Python 3.10+
- Linux with Netfilter/iptables support
- GNS3 + VirtualBox (Windows recommended — see Lab Setup)

### Python dependencies

```bash
pip install -r requirements.txt
```

Key packages: `scapy`, `netfilterqueue`, `scikit-learn`, `joblib`, `numpy`, `pandas`, `prometheus_client`

## Lab Setup

### 1. VirtualBox

- Download VirtualBox (Windows)
- Import VM disk images: Ubuntu Desktop (×2) and Kali Linux
- Each VM requires two network adapters; the second should be NAT for internet access during setup
- Configure shared folders linking to the cloned repository on each VM
- Install all Python dependencies while the NAT adapter is active — VMs lose internet access once imported into GNS3

> **macOS note:** Bridged and host-only networking in VirtualBox is restricted by recent macOS security policies. A Windows partition (e.g. via Boot Camp) is strongly recommended.

### 2. GNS3

- Create a new GNS3 project and import the VirtualBox VMs
- Connect the nodes in a linear chain:
```
  Attacker (Kali) ── Firewall (Ubuntu) ── Victim (Ubuntu)
```
- The firewall VM requires two virtual network interfaces: one facing the attacker (`enp0s8`) and one facing the victim (`enp0s3`)

### 3. Network Configuration (Netplan)

Apply the following static IP addresses on each VM via Netplan for persistent configuration:

| VM | Interface | IP | Gateway |
|---|---|---|---|
| Attacker | enp0s3 | 10.0.0.2 | 10.0.0.1 |
| Firewall | enp0s8 | 10.0.0.1 | — |
| Firewall | enp0s3 | 10.0.1.1 | — |
| Victim | enp0s3 | 10.0.1.2 | 10.0.1.1 |

Enable IP forwarding on the firewall VM:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

### 4. Python Virtual Environment

Create and activate the virtual environment on the firewall VM:

```bash
python3 -m venv firewall-venv
source firewall-venv/bin/activate
pip install -r requirements.txt
```

## Running the System

### Configure iptables

```bash
sudo iptables -I FORWARD -i enp0s8 -j NFQUEUE --queue-num 0
```

### Start the firewall

```bash
sudo $(which python) src/firewall.py
```

### Run traffic scripts (from Kali VM)

```bash
# Malicious traffic
python3 attack_scripts.py

# Benign traffic
python3 normal_traffic.py
```

### Collect a training dataset

```bash
sudo $(which python) src/dataset_collector.py
```

### Train the model

```bash
python3 src/train_model.py
```

## Testing

Unit and integration tests are run using pytest:

```bash
pytest tests/
```

Tests cover blacklist management, TCP teardown handling, bidirectional connection tracking, flow key construction, feature extraction bounds, and end-to-end ML pipeline correctness. The full test suite runs automatically on every commit via GitHub Actions.

## Project Structure

```
FYP/
├── src/
│   ├── firewall.py              # Main firewall and packet processing loop
│   ├── flow_manager.py          # Bidirectional flow tracking and sliding window
│   ├── feature_extractor.py     # 20-feature window extraction
│   ├── train_model.py           # Model training and evaluation
│   ├── dataset_collector.py     # Custom dataset capture pipeline
│   ├── attack_scripts.py        # Malicious traffic generation
│   └── normal_traffic.py        # Benign traffic generation
├── models/
│   └── rf_model.pkl             # Serialised Random Forest model
├── tests/
│   └── ...                      # Unit and integration tests
├── requirements.txt
└── README.md
```

## Intended Use

This project is designed for educational and defensive security research in isolated lab environments. It is not intended for production deployment.
