# Firewall with Stateful Connection Tracking — README
## Overview

This project implements a simple firewall with stateful connection tracking, which is enhanced using a machine learning model. The machine learning model analyses traffic flows/packets and makes predictions about whether the flows/packets are malicious, allowing the firewall to then make the decision of blocking/allowing the packets/flows. The system inspects network packets, identifies traffic flows, and produces human-readable allow/block messages based on configurable rules. The goal is to demonstrate how a basic packet-filtering firewall can be enhanced with machine learning to make threat detection faster & more efficient/reliable - it enables the system to make decisions using flow awareness rather than stateless rules alone.

## Features

* Tracks flows using source/destination IP, ports, and protocol
* Distinguishes new, established, and invalid connections
* Applies allow/block logic per flow state and configurable rules
* Maintains a dynamic blacklist of IPs identified as malicious by ML
* Supports ICMP, TCP, UDP, HTTP/HTTPS, and DNS traffic
* Outputs clear, readable decision messages for each packet
* Designed for experimentation and learning in a lab environment
* Integrates a Random Forest / XGBOOST ML model for detecting malicious flows
* Uses python scripts to generate traffic using kali tools (hping3, etc.)
* Gnerate malicious and normal traffic to evaluate firewall + ML model

## How It Works

1. Incoming packets are parsed to extract flow identifiers.
2. The firewall Firewall updates flow statistics and tracks packet counts, bytes, and TCP flags.
3. Flows that reach a minimum packet threshold are analyzed by the ML model.
4. The ML model predicts whether the flow is malicious or benign.
5. If the ML model flags a flow as malicious, the source IP is blacklisted and blocked.
6. All other traffic is allowed or blocked based on configuration rules and connection state.
7. Human-readable logs are printed for each decision.

## Configuration

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
* joblib
* scikit-learn and joblib (for ML model)
* Any other dependencies listed in requirements.txt

### Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Firewall

### Set up Lab Environment

* Download VirtualBox (windows) 
* Download VM disk images: ubuntu desktop & kali
    - Set up all VMs with 2 network adapters each (second one should be NAT)
    - Create shared folders which link to cloned repo folder
    - Start all VMs & download all dependencies 
* Dowload GNS3
* Create project in gns3 & import virtual box VMs: 
    - set up architecture: connect all VMs
    - architecture should look like: Attacker (Kali) <-> Firewall (Ubuntu) <-> Victim (Ubuntu)
* Start all machines
* Set up netplans on all VMs to ensure network setting are persistent:
    - Attacker: ip = 10.0.0.2, gateway = 10.0.0.1
    - Firewall: subnet 1 = 10.0.0.1, subnet 2 = 10.0.1.1
    - Victim: ip = 10.0.1.2, gateway = 10.0.1.1
* Apply the netplans

### Create Python Virtual Environment & Run Firewall

* Outside of GNS3, start the Firewall vm (ensure one of the ports is NAT)
* Create python venv on Firewall VM & start it: 
```bash
source firewall-venv/bin/activate
```
* Install dependencies in firewall venv
* Shut down the firewall & start all VMs in GNS3
* Configure the iptables to correctly handle traffic:
```bash
sudo iptables -I FORWARD -p ip -j NFQUEUE --queue-num 0
```
* Start the firewall by running the script from the project root:
```bash
sudo $(which python) <Firewall.py pathway>
```
* Run traffic scripts from Attacket VM (Kali) 
* Logs and decisions will be printed to the console.

## Intended Use

This project is designed for educational and defensive research in isolated lab environments. It is not intended for production deployment.