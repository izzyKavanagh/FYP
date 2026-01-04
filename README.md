# Firewall with Stateful Connection Tracking — README
## Overview

This project implements a simple firewall with stateful connection tracking. It inspects network packets, identifies traffic flows, and produces human-readable allow/block messages based on configurable rules. The goal is to demonstrate how a basic packet-filtering firewall can make decisions using flow awareness rather than stateless rules alone.

## Features

* Tracks flows using source/destination IP, ports, and protocol
* Distinguishes new, established, and invalid connections
* Applies allow/block logic per flow state
* Outputs clear, readable decision messages
* Designed for experimentation and learning in a lab environment

## How It Works

1. Incoming packets are parsed to extract flow identifiers.
2. The firewall checks whether the flow is already known.
3. Based on state and rules, the packet is allowed or blocked.
4. A descriptive message explains the decision.

## Requirements

* Python 3.10+ (or update to match your environment)
* scapy (if used for packet parsing)
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