#!/usr/bin/env python3
import time
import csv
import signal
import sys
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from feature_extractor import extract_window_features_2

# ---- CONFIG ----
OUTPUT_FILE  = "dataset_malicious.csv"
WINDOW_SIZE  = 100
STEP_SIZE    = 5
LABEL        = "malicious"
INTERFACE    = "enp0s3"
FLOW_TIMEOUT = 120

FIELDNAMES = [
    "dest_port", "window_duration",
    "fwd_packet_rate", "fwd_byte_rate",
    "pkt_len_mean", "pkt_len_std",
    "pkt_len_min", "pkt_len_max",
    "syn_ratio", "fin_ratio", "ack_ratio",
    "label"
]

# ---- Use a state dict instead of bare globals ----
# This sidesteps Python scoping issues entirely — dicts are
# always mutable from any scope without needing 'global'
state = {
    "flows": {},
    "writer": None,
    "csv_file": None,
    "stats": {
        "total_packets":   0,
        "tcp_udp_packets": 0,
        "flow_updates":    0,
        "windows_written": 0,
    }
}

# ---- Flow key ----
def get_flow_key(pkt):
    if IP not in pkt:
        return None
    if TCP not in pkt and UDP not in pkt:
        return None

    src   = pkt[IP].src
    dst   = pkt[IP].dst
    proto = pkt[IP].proto
    
    sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
    dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport

    service_port = min(sport, dport)
    
    ip_pair = tuple(sorted([src, dst]))
    return (ip_pair[0], ip_pair[1], proto, service_port)

# ---- Flow expiry ----
def expire_flows():
    now = time.time()
    flows = state["flows"]
    for key in list(flows.keys()):
        if now - flows[key]["last_seen"] > FLOW_TIMEOUT:
            del flows[key]

# ---- Core packet handler ----
def process_packet(pkt):
    flows  = state["flows"]
    writer = state["writer"]
    stats  = state["stats"]

    stats["total_packets"] += 1

    # Progress report every 100 packets
    if stats["total_packets"] % 100 == 0:
        print(f"[STATS] pkts={stats['total_packets']} | "
              f"tcp/udp={stats['tcp_udp_packets']} | "
              f"updates={stats['flow_updates']} | "
              f"windows={stats['windows_written']} | "
              f"flows={len(flows)}")

    if IP not in pkt:
        return
    if TCP not in pkt and UDP not in pkt:
        return

    stats["tcp_udp_packets"] += 1

    key = get_flow_key(pkt)
    if key is None:
        return

    now   = float(pkt.time)
    dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport

    # Init new flow
    if key not in flows:
        print(f"[NEW FLOW] {pkt[IP].src} → port {dport} | key={key}")
        flows[key] = {
            "src_ip":         pkt[IP].src,
            "dst_ip":         pkt[IP].dst,
            "initiator":      pkt[IP].src,
            "dest_port":      dport,
            "start_time":     now,
            "last_seen":      now,
            "packet_count":   0,
            "window_packets": [],
            "window_size":    WINDOW_SIZE,
            "step_size":      STEP_SIZE,
            "syn_count":      0,
            "fin_count":      0,
            "ack_count":      0,
        }

    flow = flows[key]
    flow["last_seen"]    = now
    flow["packet_count"] += 1
    flow["window_packets"].append(pkt)
    stats["flow_updates"] += 1

    # TCP flags
    if TCP in pkt:
        f = pkt[TCP].flags
        if f & 0x02: flow["syn_count"] += 1
        if f & 0x01: flow["fin_count"] += 1
        if f & 0x10: flow["ack_count"] += 1

    # Flow progress
    if flow["packet_count"] % 20 == 0:
        print(f"[FLOW] {key} → "
              f"total={flow['packet_count']} "
              f"window_buf={len(flow['window_packets'])}")

    # ---- Window check and write ----
    if len(flow["window_packets"]) >= WINDOW_SIZE:
        print(f"[WINDOW READY] {key} → extracting...")

        try:
            features = extract_window_features_2(flow)

            if features is None:
                print(f"[WARN] extract returned None for {key}")
            else:
                row = list(features.values()) + [LABEL]

                # Write and flush immediately — never buffer
                writer.writerow(row)
                state["csv_file"].flush()

                stats["windows_written"] += 1
                print(f"[WRITTEN] window #{stats['windows_written']} | "
                      f"port={dport} | label={LABEL}")

        except Exception as e:
            import traceback
            print(f"[ERROR during extract/write] {type(e).__name__}: {e}")
            traceback.print_exc()

        # Slide window
        flow["window_packets"] = flow["window_packets"][STEP_SIZE:]

    # Periodic flow expiry
    if stats["total_packets"] % 500 == 0:
        expire_flows()

# ---- Shutdown ----
def shutdown(sig, frame):
    print("\n========== SESSION SUMMARY ==========")
    for k, v in state["stats"].items():
        print(f"  {k}: {v}")
    print(f"  active_flows: {len(state['flows'])}")
    print("=====================================")
    if state["csv_file"]:
        state["csv_file"].flush()
        state["csv_file"].close()
        print(f"[+] Saved to {OUTPUT_FILE}")
    sys.exit(0)

# ---- Entry point ----
def main():
    # Open CSV and store in state dict — never as bare globals
    csv_file = open(OUTPUT_FILE, "w", newline="")
    writer   = csv.writer(csv_file)
    writer.writerow(FIELDNAMES)
    csv_file.flush()

    state["csv_file"] = csv_file
    state["writer"]   = writer

    signal.signal(signal.SIGINT, shutdown)

    print(f"[+] Interface : {INTERFACE}")
    print(f"[+] Label     : {LABEL}")
    print(f"[+] Window    : {WINDOW_SIZE} packets, step {STEP_SIZE}")
    print(f"[+] Output    : {OUTPUT_FILE}")
    print("[+] Waiting for packets...\n")

    sniff(iface=INTERFACE, prn=process_packet, store=False)

if __name__ == "__main__":
    main()