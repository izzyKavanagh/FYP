import csv
from datetime import datetime 
import os
import sys
import time      # for flow timing and blacklist expiry
import joblib   # for loading ML model and feature names
from scapy.all import IP, TCP, UDP, ICMP # for packet parsing
from netfilterqueue import NetfilterQueue # for intercepting packets in user space
from feature_extractor import extract_window_features, extract_features # for converting flows into ML features
from flow_manager import FlowManager # for tracking active flows and their statistics
from ml_model import MLModel # wrapper for loading and using the ML model
import subprocess # for blocking IPs with iptables
import numpy as np # for handling NaN/infinite values in features
from prometheus_client import Counter, Gauge, Histogram, start_http_server
import threading
import csv

#------------------------- GUI SETUP -----------------------
# Define metrics — Prometheus scrapes these automatically
packets_allowed  = Counter("firewall_packets_allowed_total", "Total packets allowed")
packets_blocked  = Counter("firewall_packets_blocked_total", "Total packets blocked", ["reason"])
ml_probability   = Gauge("firewall_ml_probability", "Current ML probability", ["src_ip"])
ml_predictions   = Counter("firewall_ml_predictions_total", "ML predictions", ["result"])
active_flows     = Gauge("firewall_active_flows", "Number of active flows")
blacklist_size   = Gauge("firewall_blacklist_size", "IPs currently blacklisted")
# Tracks total packets dropped due to ML decisions
# (combines verdict drops + blacklist drops from ML-detected IPs)
# This is more meaningful than prediction count for showing ML impact
ml_blocks = Counter("firewall_ml_blocks_total", "Packets blocked due to ML detection", ["stage"]) 
# Start metrics server on port 8000
start_http_server(8000)

# counters for experiment logging (not Prometheus metrics, just for CSV logging)
_allowed_count   = 0
_blocked_total   = 0
_ml_block_count  = 0
_rule_block_count = 0


#------------------ GLOBALS ------------------
flow_manager = FlowManager()

# Load the pre-trained machine learning model (random forest)
ml_model = MLModel("rf_model.pkl")

feature_names = joblib.load("features.pkl")

#----------------------- CONFIG -----------------------
# Set this manually per experiment
GROUND_TRUTH = 0  # 1 = attack, 0 = normal
FILENAME           = f"ml_results_{GROUND_TRUTH}.csv"
ML_ENABLED         = True # change toggle to false 
MODE               = "ml_enabled" # change to "ml_enabled" or rules_only
EXPERIMENT_LOG     = f"experiment_{MODE}.csv"
MALICIOUS_THRESHOLD = 0.8
BLACKLIST_DURATION  = 60      # seconds
# NOTE: should also implement cleanup of old connections to prevent memory leaks
CONNECTION_TTL      = 300     # 5 minutes — typical TCP connection lifetime

# made ip blacklist temporary - if non-malicious traffic accidentally blocked -> need to be unblocked after a short period to allow recovery from false positives
blacklist = {}   # ip -> expiry_timestamp

# Create table to track established connections - allows stateful connection tracking
connection_table = {}  # (src, dst, sport, dport, protocol, direction) -> expiry_time

if not os.path.exists(FILENAME):
    with open(FILENAME, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["y_true", "y_pred", "prob"])


# ----------------------- CONNECTION TRACKING -----------------------

def extract_connection_info(pkt):
    """
    Extract the protocol and port info from the packet.
    Returns:
        (protocol, source_port, dest_port)
        Returns (None, None, None) if the protocol is unsupported.
    """
    if pkt.haslayer(TCP):
        return "TCP", pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        return "UDP", pkt[UDP].sport, pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        # ICMP doesn't have ports; return placeholders
        return "ICMP", "-", "-"
    else:
        return None, None, None
        
def get_flow_id(pkt):
    """
    Generate a unique flow ID for TCP/UDP packets.
    Returns a tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
    Only tracks TCP and UDP.
    """
    protocol, sport, dport = extract_connection_info(pkt)

    # Only track TCP/UDP flows
    if protocol not in ("TCP", "UDP"):
        return None

    return (pkt.src, pkt.dst, sport, dport, protocol)

def track_connection(pkt):
    """
    Add a packet's flow to the connection table (stateful tracking).
    Both directions are stored to allow bidirectional matching.
    """
    # use helper method to extract packet's flow characteristics  
    flow = get_flow_id(pkt)
    
    if not flow:
        return

    # extract flow details from flow tuple
    src, dst, sport, dport, protocol = flow

    expiry = time.time() + CONNECTION_TTL

    # Store both directions of the connection because connections are bidirectional & incoming/outgoing packets have different src/dst addresses and ports - this way packets going in either direction can be matched to an existing connection
    # Track outgoing packets
    connection_table[(src, dst, sport, dport, protocol, "OUTBOUND")] = expiry
    # Track incoming packets
    connection_table[(dst, src, dport, sport, protocol, "INBOUND")]  = expiry
    
def is_established(pkt):
    """
    Check if a packet belongs to an already established connection.
    Returns True if it is part of an existing tracked connection.
    """
    # extract flow information from packet using helper method
    flow = get_flow_id(pkt)

    if not flow:
        return False

    # extract flow details from flow tuple
    src, dst, sport, dport, protocol = flow

    now = time.time()

    inbound_key  = (src, dst, sport, dport, protocol, "INBOUND")
    outbound_key = (src, dst, sport, dport, protocol, "OUTBOUND")


    for key in (inbound_key, outbound_key):
        if key in connection_table:
            if now > connection_table[key]:
                # Expired — remove it
                del connection_table[key]
            else:
                # Active — refresh TTL since we just saw traffic on it
                connection_table[key] = now + CONNECTION_TTL
                return True

    return False

def cleanup_connection_table():
    """
    Remove all expired entries from the connection table.
    Call periodically — every 500 packets is sufficient.
    Avoids iterating the full table on every single packet.
    """
    now     = time.time()
    expired = [key for key, expiry in connection_table.items()
               if now > expiry]
    for key in expired:
        del connection_table[key]

    if expired:
        print(f"[CONN TABLE] Cleaned {len(expired)} expired entries | "
              f"remaining: {len(connection_table)}")

def handle_tcp_teardown(pkt):
    """
    Remove connection table entries when TCP connection closes.
    Called on FIN or RST packets — no need to wait for TTL.
    """
    if not pkt.haslayer(TCP):
        return

    flags = pkt[TCP].flags
    # FIN = connection closing gracefully
    # RST = connection reset abruptly
    if not (flags & 0x01 or flags & 0x04):
        return

    flow = get_flow_id(pkt)
    if not flow:
        return

    src, dst, sport, dport, protocol = flow

    for key in [
        (src, dst, sport, dport, protocol, "OUTBOUND"),
        (dst, src, dport, sport, protocol, "INBOUND"),
    ]:
        if key in connection_table:
            del connection_table[key]

import threading
import csv

# ----------------------- BLACKLIST -----------------------

def is_blacklisted(ip):
    if ip not in blacklist:
        return False
    if time.time() > blacklist[ip]:
        del blacklist[ip]
        remove_block_ip(ip)   # also remove iptables rule
        print(f"[BLACKLIST EXPIRED] {ip} unblocked")

        # Reset ML verdict for all flows from this IP
        # so it gets re-evaluated rather than staying permanently malicious
        for flow in flow_manager.flows.values():
            if flow["src_ip"] == ip or flow["initiator"] == ip:
                flow["ml_verdict"]          = "benign"
                flow["probability_history"] = []
                print(f"[FLOW RESET] {ip} flow verdict cleared")
        return False
    return True

def add_to_blacklist(ip):
    """Add IP to blacklist with expiry time"""
    expiry = time.time() + BLACKLIST_DURATION
    blacklist[ip] = expiry
    print(f"[BLACKLISTED] {ip} until {datetime.fromtimestamp(expiry).strftime('%H:%M:%S')}")
    
def block_ip(ip):
    """
    Block the given IP using iptables.
    Adds a rule to drop all incoming traffic from this IP.
    """
    subprocess.run([
        "sudo",
        "iptables",
        "-A",
        "INPUT",
        "-s",
        ip,
        "-j",
        "DROP"
    ])

def remove_block_ip(ip):
    """Remove iptables block rule for this IP"""
    subprocess.run([
        "sudo", "iptables", "-D", "INPUT",
        "-s", ip, "-j", "DROP"
    ], stderr=subprocess.DEVNULL)

def experiment_logger():
    """Log packet counts every second for time-series comparison."""
    start = time.time()

    with open(EXPERIMENT_LOG, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "elapsed_seconds",
            "packets_allowed",
            "packets_blocked_total",
            "ml_blocks",
            "rule_blocks",
            "blacklist_size",
            "active_flows"
        ])

    # These are read from Prometheus counters via the registry
    # Simpler: track them in module-level variables -> implement later 
    while True:
        elapsed = int(time.time() - start)
        with open(EXPERIMENT_LOG, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                elapsed,
                _allowed_count,
                _blocked_total,
                _ml_block_count,
                _rule_block_count,
                len(blacklist),
                len(flow_manager.flows)
            ])
        time.sleep(1)


# ----------------------- LOGGING -----------------------

def extract_print_info(pkt):
    """
    Create a structured dictionary for logging purposes.
    """

    proto, sport, dport = extract_connection_info(pkt)

    return {
        "proto": proto or f"OTHER({pkt.proto})",
        "src": f"{pkt.src}:{sport}",
        "dst": f"{pkt.dst}:{dport}",
    }
# Add to firewall.py — logs one row per second with current counts
# Run in a background thread

def log_event(action, rule, direction, info):
    """
    Print a formatted log message for each packet.
    Parameters:
        action: "ALLOW" or "BLOCK"
        rule: which rule triggered the action
        direction: "inbound" or "outbound"
        info: dict containing packet info (proto, src, dst)
    """
    
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if action == "ALLOW":
        print(
            f"[{ts}] Allowed {info['proto']} traffic ({rule}) "
            f"{direction} from {info['src']} to {info['dst']}"
        )
    else:
        print(
            f"[{ts}] Blocked {info['proto']} traffic ({rule}) "
            f"{direction} from {info['src']} to {info['dst']}"
        )


# ----------------------- ML -----------------------

def run_ml(flow):
    """
    Run ML inference on the current window of packets for a flow.

    Returns:
        "malicious" | "benign" | None   (None = not enough data yet)

    Side effects:
        - Updates flow["probability_history"]
        - Updates flow["ml_verdict"]
        - Writes to ground-truth CSV
        - Updates Prometheus metrics
        - Adds IP to blacklist + iptables if malicious
    """
    if len(flow["window_packets"]) < flow["window_size"]:
        return None

    try:
        feature_dict = extract_window_features_2(flow)

        if feature_dict is None:
            # Slide window and bail — not enough usable data
            flow["window_packets"] = flow["window_packets"][flow["step_size"]:]
            return None

        features = [feature_dict[name] for name in feature_names]
        features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

        proba = ml_model.predict_proba([features])[0][1]

        # Append to history — no reset on spikes.
        # A sudden high probability IS the signal; resetting it hides attacks.
        flow["probability_history"].append(proba)
        if len(flow["probability_history"]) > 5:
            flow["probability_history"].pop(0)

        smoothed = sum(flow["probability_history"]) / len(flow["probability_history"])
        ml_probability.labels(src_ip=flow["src_ip"]).set(smoothed)

        # Ground-truth logging (only once we have a stable reading)
        if len(flow["probability_history"]) >= 3:
            y_pred = 1 if smoothed > MALICIOUS_THRESHOLD else 0
            with open(FILENAME, "a", newline="") as f:
                csv.writer(f).writerow([GROUND_TRUTH, y_pred, smoothed])

        # Decision
        if smoothed > MALICIOUS_THRESHOLD:
            print(f"[ML] MALICIOUS {flow['src_ip']} prob={proba:.3f} smoothed={smoothed:.3f}")
            ml_predictions.labels(result="malicious").inc()
            flow["ml_verdict"] = "malicious"

            if ML_ENABLED and not is_blacklisted(flow["src_ip"]):
                add_to_blacklist(flow["src_ip"])
                block_ip(flow["src_ip"])
        else:
            print(f"[ML] BENIGN    {flow['src_ip']} prob={proba:.3f} smoothed={smoothed:.3f}")
            ml_predictions.labels(result="benign").inc()
            flow["ml_verdict"] = "benign"

        flow["window_packets"] = flow["window_packets"][flow["step_size"]:]
        return flow["ml_verdict"]

    except Exception as e:
        print(f"[ML ERROR] {e}")
        flow["window_packets"] = flow["window_packets"][flow["step_size"]:]
        return None
    
# ----------------------- PACKET PROCESSING -----------------------

def process_packet(pkt):
    """

    Main packet processing function.

    This function is responsible for:
    - Extracting packet data from NetfilterQueue
    - Parsing it using Scapy
    - Updating flow tracking
    - Running ML-based intrusion detection
    - Applying firewall rules (allow/block)

    IMPORTANT:
    This runs in real-time for every packet, so performance matters.
    """

    global _allowed_count, _blocked_total
    global _ml_block_count, _rule_block_count
    
    # DEBUG
    #print("[HIT] packet received")

    try:
        # ------------------ RAW PAYLOAD EXTRACTION ------------------
        # NetfilterQueue provides raw packet bytes via get_payload()
        # Get raw payload
        payload = pkt.get_payload()

        # Ignore packets that are too small to be valid IP packets
        # (minimum IPv4 header size is 20 bytes)
        if len(payload) < 20:
            pkt.accept() # Allow packet (fail-open strategy)
            _allowed_count += 1   # module counter for experiment log
            return

        # ------------------ SCAPY PARSING ------------------
        # Convert raw bytes into a Scapy IP packet for easier inspection
        # Parse packet with scapy
        try:
            scapy_pkt = IP(payload)
        except Exception:
            pkt.accept() # If parsing fails - allow packet (avoid breaking traffic)
            _allowed_count += 1   # module counter for experiment log
            return
        
        handle_tcp_teardown(scapy_pkt)
        
        # ------------------- PERIODIC CONNECTION/FLOW CLEANUP ------------------
        # Periodic maintenance — every 500 packets
        process_packet.counter = getattr(process_packet, "counter", 0) + 1
        if process_packet.counter % 500 == 0:
            cleanup_connection_table()
            # Periodically remove expired flows to:
            # - Prevent memory leaks
            # - Keep flow table efficient
            # Remove expired flows to save memory
            flow_manager.expire_flows()

             # ---- PROMETHEUS METRICS UPDATE ----
            active_flows.set(len(flow_manager.flows))
            blacklist_size.set(len(blacklist))
            process_packet.counter = 0

        # ---------------- ML BLACKLIST CHECK ----------------

        # check if source IP is already in ML blacklist (i.e.: classified as malicious) - if so, block and log
        if is_blacklisted(scapy_pkt.src):
            #info = extract_print_info(scapy_pkt)
            #log_event("BLOCK", "ML blacklist", "inbound", info)
            packets_blocked.labels(reason="ml_blacklist").inc()
            ml_blocks.labels(stage="blacklist").inc()  # Increment ML block counter for blacklist stage
            _ml_block_count += 1   # module counter for experiment log
            _blocked_total += 1   # also increment total block count for experiment logging
            pkt.drop()
            return
        
        # ------------------ FLOW UPDATE ------------------
        
        # Update flow statistics with the current packet
        # Returns the flow object (or None if not tracked)
        flow = flow_manager.update_flow(scapy_pkt)

        # Extract info for logging
        #info = extract_print_info(scapy_pkt)

        # ------------------ ML FLOW ANALYSIS ----------------------

        if flow:
            # Clear stale history on very long-lived flows
            if time.time() - flow["start_time"] > 300:
                flow["probability_history"] = []
                flow["start_time"] = time.time()

            run_ml(flow)   # updates flow["ml_verdict"] as a side effect

        # ------------------ ML VERDICT CHECK ------------------
        # If ML has classified this flow as malicious, drop immediately
        # This ensures the current packet is also blocked, not just future ones
        if ML_ENABLED and flow and flow.get("ml_verdict") == "malicious":
            pkt.drop()
            packets_blocked.labels(reason="ml_verdict").inc()
            ml_blocks.labels(stage="verdict").inc()   
            _ml_block_count += 1   # module counter for experiment log
            _blocked_total += 1   # also increment total block count for experiment logging 
            return

        # ----------- Allow Rules -----------
        

        # ----------- potentially remove -----------
        # ACK flag (0x10) indicates part of an existing connection
        # Allow established TCP (ACK packets) - helps performance by not running ML on every packet of an established connection
        if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].flags & 0x10:
            pkt.accept()
            packets_allowed.inc()
            _allowed_count += 1   # module counter for experiment log
            return
        # REASON: it is allowing all established connections and making connection table redundant 
        # ----------- potentially remove -----------


        # NOTE: move before ml block - so established connections are allowed without running ML every time (improves performance and reduces false positives on established connections)
        # 1. Allow established connections (stateful tracking)
        if is_established(scapy_pkt):
            #log_event("ALLOW", "connection tracking", "inbound", info)
            pkt.accept()
            packets_allowed.inc()
            _allowed_count += 1   # module counter for experiment log
            return
        
        # Allow all ICMP traffic
        if scapy_pkt.haslayer(ICMP):
            direction = "inbound"
            #log_event("ALLOW", "ICMP allowed", direction, info)
            pkt.accept()
            packets_allowed.inc()
            _allowed_count += 1   # module counter for experiment log
            return

        # Allow HTTP and HTTPS traffic
        if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].dport in (80, 443):
            #log_event("ALLOW", "HTTP/HTTPS allowed", "outbound", info)
            track_connection(scapy_pkt)
            pkt.accept()
            packets_allowed.inc()
            _allowed_count += 1   # module counter for experiment log
            return
        
        # Allow DNS queries
        if scapy_pkt.haslayer(UDP) and scapy_pkt[UDP].dport == 53:
            #log_event("ALLOW", "DNS query", "outbound", info)
            track_connection(scapy_pkt)
            pkt.accept()
            packets_allowed.inc()
            _allowed_count += 1   # module counter for experiment log
            return
        
        # ------------------ DEFAULT POLICY: DENY ------------------
        # Deny all other traffic & log
        # Any packet that does not match allow rules is dropped
        # This is a "default deny" firewall strategy
        #log_event("BLOCK", "default deny", "outbound", info)
        pkt.drop()
        _rule_block_count += 1   # module counter for experiment log
        _blocked_total += 1   # module counter for experiment log
        packets_blocked.labels(reason="default_deny").inc()
        
    # ------------------ GLOBAL ERROR HANDLER ------------------
    # Catch-all for unexpected errors to avoid dropping packets accidentally
    except Exception as e:
        # Catch unexpected errors to prevent breaking networking
        print(f"[ERROR] {e}")
        # Fail-open strategy: allow packet instead of risking blocking legitimate traffic
        pkt.accept()
        _allowed_count += 1   # module counter for experiment log

def main():
    """
    Entry point for the firewall.
    Loads configuration, initializes Netfilter queue, and starts packet processing loop.
    """

    print("[+] Firewall started\n")
    print("[+] Press CTRL+C to stop\n")

    # Start experiment logging thread 
    log_thread = threading.Thread(target=experiment_logger, daemon=True)
    log_thread.start()

    # Bind to Netfilter queue 0 (packets need to be redirected using iptables NFQUEUE rules)
    nfq = NetfilterQueue()
    nfq.bind(0, process_packet)

    try:
        nfq.run()
    except KeyboardInterrupt:
        print("\n[-] Firewall stopped")


# Standard Python entry point
if __name__ == "__main__":
    main()
