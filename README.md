# Firewall with Stateful Connection Tracking — README
## Overview

This project implements a simple firewall with stateful connection tracking. It inspects network packets, identifies traffic flows, and produces human-readable allow/block messages based on configurable rules. The goal is to demonstrate how a basic packet-filtering firewall can make decisions using flow awareness rather than stateless rules alone.

## Features

* Tracks flows using source/destination IP, ports, and protocol
* Distinguishes new, established, and invalid connections
* Applies allow/block logic per flow state and configurable rules
* Integrates a Random Forest ML model for detecting malicious flows
* Maintains a dynamic blacklist of IPs identified as malicious by ML
* Supports ICMP, TCP, UDP, HTTP/HTTPS, and DNS traffic
* Configurable via firewall_config.yaml without changing source code
* Outputs clear, readable decision messages for each packet
* Designed for experimentation and learning in a lab environment

## How It Works

1. Incoming packets are parsed to extract flow identifiers.
2. The firewall Firewall updates flow statistics and tracks packet counts, bytes, and TCP flags.
3. Flows that reach a minimum packet threshold are analyzed by the ML model.
4. The ML model predicts whether the flow is malicious or benign.
5. If the ML model flags a flow as malicious, the source IP is blacklisted and blocked.
6. All other traffic is allowed or blocked based on configuration rules and connection state.
7. Human-readable logs are printed for each decision.

## Configuration

Firewall rules are now stored in firewall_config.yaml, allowing for easy modification of allowed ports, protocols, and ICMP policy without editing the code.

### Supported Options:

| Option | Description |
| -------- | ------- |
| icmp_allowed | List of outbound TCP ports allowed |
| allowed_outbound_tcp_ports | List of outbound TCP ports allowed |
| allowed_outbound_udp_ports | List of outbound UDP ports allowed |
| allowed_inbound_tcp_ports | List of inbound TCP ports allowed|
| allowed_inbound_udp_ports | List of inbound UDP ports allowed |
| default_policy | Default action for unmatched traffic (allow or deny) |

## Requirements

* Python 3.10+ (or update to match your environment)
* scapy (used for packet parsing)
* netfilterqueue
* pyyaml
* scikit-learn and joblib (for ML model)
* Any other dependencies listed in requirements.txt

### Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Firewall

Run the script from the project root:

```bash
python firewall.py
```

Logs and decisions will be printed to the console.

## Intended Use

This project is designed for educational and defensive research in isolated lab environments. It is not intended for production deployment.