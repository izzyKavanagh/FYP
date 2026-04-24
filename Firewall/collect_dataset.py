#!/usr/bin/env python3
import time
import csv
import signal
import sys
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from feature_extractor import extract_window_features

# ---- CONFIG ----
OUTPUT_FILE  = "dataset_normal.csv"   # change to dataset_normal.csv for normal traffic
WINDOW_SIZE  = 100
STEP_SIZE    = 100
LABEL        = "normal"               # change to "normal" for legitimate traffic
INTERFACE    = "enp0s3"
FLOW_TIMEOUT = 120

# Must exactly match extract_window_features output keys + any new features
FIELDNAMES = [
    "flow_id",
    "dest_port", "window_duration",
    "fwd_packet_rate", "fwd_byte_rate",
    "bwd_packet_rate", "bwd_byte_rate",      
    "pkt_len_mean", "pkt_len_std",
    "pkt_len_min", "pkt_len_max",
    "syn_ratio", "fin_ratio", "ack_ratio",
    "rst_ratio", "psh_ratio",               
    "fwd_bwd_ratio", "byte_ratio",          
    "iat_mean", "iat_std", "iat_min",        
    "label"
]

state = {
    "flows":    {},
    "writer":   None,
    "csv_file": None,
    "stats": {
        "total_packets":   0,
        "tcp_udp_packets": 0,
        "flow_updates":    0,
        "windows_written": 0,
    }
}

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

def get_initiator(pkt):
    """
    Match the flow_manager.py initiator logic exactly.
    Client uses the ephemeral (higher) port, server uses the service (lower) port.
    """
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        return pkt[IP].src
    # Higher port = ephemeral = client = initiator
    return pkt[IP].src if sport > dport else pkt[IP].dst

def expire_flows():
    now   = time.time()
    flows = state["flows"]
    for key in list(flows.keys()):
        if now - flows[key]["last_seen"] > FLOW_TIMEOUT:
            del flows[key]

def process_packet(pkt):
    flows  = state["flows"]
    writer = state["writer"]
    stats  = state["stats"]

    stats["total_packets"] += 1

    if stats["total_packets"] % 100 == 0:
        print(f"[STATS] pkts={stats['total_packets']} | "
              f"tcp/udp={stats['tcp_udp_packets']} | "
              f"windows={stats['windows_written']} | "
              f"flows={len(flows)}")

    if IP not in pkt or (TCP not in pkt and UDP not in pkt):
        return

    stats["tcp_udp_packets"] += 1

    key = get_flow_key(pkt)
    if key is None:
        return

    now   = float(pkt.time)
    sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
    dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport

    if key not in flows:
        initiator = get_initiator(pkt)

        flow_id = f"{key[0]}_{key[1]}_{key[2]}_{key[3]}"  # stable string from flow key tuple

        print(f"[NEW FLOW] {pkt[IP].src} → port {dport} | initiator={initiator}")
        flows[key] = {
            "src_ip":         pkt[IP].src,
            "dst_ip":         pkt[IP].dst,
            "initiator":      initiator,
            "dest_port":      min(sport, dport),
            "start_time":     now,
            "last_seen":      now,
            "packet_count":   0,
            "window_packets": [],
            "window_size":    WINDOW_SIZE,
            "step_size":      STEP_SIZE,
            "syn_count":      0,
            "fin_count":      0,
            "ack_count":      0,
            "flow_id": flow_id,   # <-- store it
            "window_index": 0,    # <-- track which window we're on
        }

    flow = flows[key]
    flow["last_seen"]     = now
    flow["packet_count"] += 1
    flow["window_packets"].append(pkt)
    stats["flow_updates"] += 1

    if TCP in pkt:
        f = pkt[TCP].flags
        if f & 0x02: flow["syn_count"] += 1
        if f & 0x01: flow["fin_count"] += 1
        if f & 0x10: flow["ack_count"] += 1

    if len(flow["window_packets"]) >= WINDOW_SIZE:
        try:
            features = extract_window_features(flow)

            if features is None:
                print(f"[WARN] extract returned None")
            else:
                # Use keys from the feature dict directly — avoids column misalignment
                flow_id = flow["flow_id"]
                # if extract_window_features_2 ever changes key order
                feature_keys = [k for k in FIELDNAMES if k not in ("flow_id", "label")]

                row_flow_id = f"{flow['flow_id']}_w{flow['window_index']}"

                row = [row_flow_id] + [features[k] for k in feature_keys] + [LABEL]
                writer.writerow(row)
                state["csv_file"].flush()

                flow["window_index"] += 1
                stats["windows_written"] += 1
                print(f"[WRITTEN] window #{stats['windows_written']} label={LABEL}")

        except Exception as e:
            import traceback
            print(f"[ERROR] {type(e).__name__}: {e}")
            traceback.print_exc()

        flow["window_packets"] = flow["window_packets"][STEP_SIZE:]

    if stats["total_packets"] % 500 == 0:
        expire_flows()

def shutdown(sig, frame):
    print("\n========== SUMMARY ==========")
    for k, v in state["stats"].items():
        print(f"  {k}: {v}")
    if state["csv_file"]:
        state["csv_file"].flush()
        state["csv_file"].close()
        print(f"[+] Saved to {OUTPUT_FILE}")
    sys.exit(0)

def main():
    csv_file = open(OUTPUT_FILE, "w", newline="")
    writer   = csv.writer(csv_file)
    writer.writerow(FIELDNAMES)
    csv_file.flush()

    state["csv_file"] = csv_file
    state["writer"]   = writer

    signal.signal(signal.SIGINT, shutdown)

    print(f"[+] Interface : {INTERFACE}")
    print(f"[+] Label     : {LABEL}")
    print(f"[+] Output    : {OUTPUT_FILE}")
    print("[+] Waiting...\n")

    sniff(iface=INTERFACE, prn=process_packet, store=False)

if __name__ == "__main__":
    main()