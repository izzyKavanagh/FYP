import csv
from datetime import datetime 
import os
import sys
import time      # for flow timing and blacklist expiry
import joblib   # for loading ML model and feature names
from scapy.all import IP, TCP, UDP, ICMP # for packet parsing
from netfilterqueue import NetfilterQueue # for intercepting packets in user space
from feature_extractor import extract_window_features, extract_features, extract_window_features_2 # for converting flows into ML features
from flow_manager import FlowManager # for tracking active flows and their statistics
from ml_model import MLModel # wrapper for loading and using the ML model
import subprocess # for blocking IPs with iptables
import numpy as np # for handling NaN/infinite values in features

flow_manager = FlowManager()

# Load the pre-trained machine learning model (random forest)
ml_model = MLModel("rf_model.pkl")

feature_names = joblib.load("features.pkl")

# ------------------ GROUND TRUTH ------------------
# Set this manually per experiment
GROUND_TRUTH = 0  # 1 = attack, 0 = normal

FILENAME = f"ml_results_{GROUND_TRUTH}.csv"

if not os.path.exists(FILENAME):
    with open(FILENAME, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["y_true", "y_pred", "prob"])

# ----------------------- CONFIG -----------------------

#MIN_PACKETS = 20
#MIN_DURATION = 0.5  # seconds
#ML_CHECK_INTERVAL = 10
MALICIOUS_THRESHOLD = 0.8
BLACKLIST_DURATION = 60   # seconds before an IP can be re-evaluated
# made ip blacklist temporary - if non-malicious traffic accidentally blocked -> need to be unblocked after a short period to allow recovery from false positives
blacklist = {}   # ip -> expiry_timestamp

# Create table to track established connections - allows stateful connection tracking
connection_table = {}  # (src, dst, sport, dport, protocol, direction) -> expiry_time
# NOTE: should also implement cleanup of old connections to prevent memory leaks, but for simplicity this is omitted here
CONNECTION_TTL = 300    # 5 minutes — typical TCP connection lifetime
                        # adjust down if you want faster cleanup

# ----------------------- HELPER METHODS -----------------------

# helper method for extracting connection information from a packet
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

# ----------------------- FIREWALL LOGIC -----------------------

def is_blacklisted(ip):
    if ip not in blacklist:
        return False
    if time.time() > blacklist[ip]:
        del blacklist[ip]
        remove_block_ip(ip)   # also remove iptables rule
        print(f"[BLACKLIST EXPIRED] {ip} unblocked")
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
            return

        # ------------------ SCAPY PARSING ------------------
        # Convert raw bytes into a Scapy IP packet for easier inspection
        # Parse packet with scapy
        try:
            scapy_pkt = IP(payload)
        except Exception:
            pkt.accept() # If parsing fails - allow packet (avoid breaking traffic)
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
            process_packet.counter = 0

        # ------------------ FLOW UPDATE ------------------
        
        # Update flow statistics with the current packet
        # Returns the flow object (or None if not tracked)
        flow = flow_manager.update_flow(scapy_pkt)

        # Extract info for logging
        info = extract_print_info(scapy_pkt)


        # ---------------- ML BLACKLIST CHECK ----------------

        # check if source IP is already in ML blacklist (i.e.: classified as malicious) - if so, block and log
        if is_blacklisted(scapy_pkt.src):
            info = extract_print_info(scapy_pkt)
            log_event("BLOCK", "ML blacklist", "inbound", info)
            pkt.drop()
            return

        # ------------------ ML FLOW ANALYSIS ----------------------

        if flow:
            # debug print to show flow details and ML features/probability
            #print("\n\n-------------------------------------------")
            #print(f"[FLOW] {flow['src_ip']} -> {flow['dst_ip']} packets={flow['packet_count']}")
            #print("-------------------------------------------\n\n")

            # If flow has been running for more than 5 minutes, clear history
            # to prevent ancient predictions affecting current traffic
            flow_age = time.time() - flow["start_time"]
            if flow_age > 300:
                flow["probability_history"] = []
                flow["start_time"] = time.time()  # reset age
                print(f"[FLOW REFRESH] {flow['src_ip']} — history cleared after {flow_age:.0f}s")

            # Compute flow duration for ML feature extraction
            #duration = flow["last_seen"] - flow["start_time"]

             # Only run ML when:
            # - Enough packets have been collected (MIN_PACKETS)
            # - Flow has existed long enough (MIN_DURATION)
            # - Packet count hits interval (ML_CHECK_INTERVAL)
            #
            # This reduces:
            # - CPU usage
            # - False positives from tiny flows

            if len(flow["window_packets"]) >= flow["window_size"]:
                try:
                    # ------------------ FEATURE EXTRACTION ------------------

                    # Convert flow stats into ML-ready feature vector
                    feature_dict = extract_window_features_2(flow)
                    # Add this check — was missing before

                    if feature_dict is None:
                        print("[ML] Skipping — not enough packets in window")
                        flow["window_packets"] = flow["window_packets"][flow["step_size"]:]
                        # Skip ML this window but continue processing packet normally
                    else:
                        #print("\n=== LIVE FEATURE DEBUG ===")
                        for name, val in feature_dict.items():
                            print(f"  {name:20s} = {val:.4f}")
                        print("==========================\n")
                        # Ensure features are in correct order expected by model
                        features = [feature_dict[name] for name in feature_names]

                        # Replace NaN / infinite values to avoid model crashes
                        features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

                        #print("[FEATURES]", features)

                        # Debug: print all features with indices
                        #print("FEATURE DEBUG:")
                        #for i, f in enumerate(features):
                        #    print(i, f)

                        # Debug
                        #print(f"PKT: {scapy_pkt[IP].src} -> {scapy_pkt[IP].dst}")
                        
                        #print("\n===== FEATURE NAMES DEBUG =====")
                        #print("Expected order:", feature_names)
                        #print("Extracted features:", feature_dict)
                        #print("=========================\n")

                        #print("\n-------------------------------------------")
                        #print("[DEBUG]")
                        #print(f"[DEBUG] packets={flow['packet_count']} duration={duration:.2f}s proba={proba:.4f}")
                        #print("-------------------------------------------\n")
                        #print(f"[FLOW] {flow['src_ip']} packets={flow['packet_count']}")
                        # In firewall.py debug block, print initiator:
                        
                        print(f"  initiator={flow['initiator']}  src_ip={flow['src_ip']}")
                        print(f"  fwd_packets={flow['fwd_packets']}  bwd_packets={flow['bwd_packets']}")
                                        
                        # ------------------ ML PREDICTION ------------------
                        # Get probability of malicious class (index 1)
                        # use probability instead of hard prediction

                        proba = ml_model.predict_proba([features])[0][1]

                        # Smooth the probability using a simple moving average of the last few predictions for this flow 
                        # to reduce volatility and false positives from single anomalous packets
                        if len(flow["probability_history"]) >= 2:
                            recent_avg = sum(flow["probability_history"]) / len(flow["probability_history"])
                            
                            if abs(proba - recent_avg) > 0.4:
                                print(f"[HISTORY RESET] {flow['src_ip']} — "
                                    f"new={proba:.2f} vs avg={recent_avg:.2f}")
                                flow["probability_history"] = []

                        flow["probability_history"].append(proba)

                        if len(flow["probability_history"]) > 5:
                            flow["probability_history"].pop(0)


                        # Calculate smoothed probability for more stable decision making
                        smoothed_proba = sum(flow["probability_history"]) / len(flow["probability_history"])
                        
                        # ------------------ GROUND TRUTH ------------------
                       # Convert probability to prediction
                        y_pred = 1 if smoothed_proba > MALICIOUS_THRESHOLD else 0

                        if len(flow["probability_history"]) >= 3:
                            # Store result
                            with open(FILENAME, "a", newline="") as f:
                                writer = csv.writer(f)
                                writer.writerow([GROUND_TRUTH, y_pred, smoothed_proba])
                        
                        # ------------------ DECISION ------------------
                        if smoothed_proba > MALICIOUS_THRESHOLD:
                            # High probability of malicious behaviour - block and log
                            print("\n\n*******************************************")
                            print(f"[ML PREDICTION] {flow['src_ip']} → MALICIOUS (prob={proba:.4f}, smoothed_prob={smoothed_proba:.4f})")
                            # Add to blacklist if not already present
                            #if not is_blacklisted(flow["src_ip"]):
                            #    add_to_blacklist(flow["src_ip"])
                            #    block_ip(flow["src_ip"])
                            print("*******************************************\n\n")

                            #print("\n[FALSE POSITIVE DEBUG]")
                            #print(f"  src_ip={flow['src_ip']}")
                            #for name, val in zip(feature_names, features):
                            #    print(f"  {name:20s} = {val:.4f}")
                            #print(f"  raw_proba={proba:.4f}  smoothed={smoothed_proba:.4f}")
                        else:
                            # Lower probability of malicious behaviour - just print prediction for monitoring purposes
                            print("\n\n*******************************************")
                            print(f"[ML PREDICTION] {flow['src_ip']} → BENIGN (prob={proba:.4f}, smoothed_prob={smoothed_proba:.4f})")
                            print("*******************************************\n\n")

                        flow["window_packets"] = flow["window_packets"][flow["step_size"]:]
                
                except Exception as e:
                    # If ML fails - default to benign (fail-safe)
                    print(f"[ML ERROR] {e}")
                    flow["window_packets"] = \
                        flow["window_packets"][flow["step_size"]:]

        # ----------- Allow Rules -----------
        
        # ACK flag (0x10) indicates part of an existing connection
        # Allow established TCP (ACK packets) - helps performance by not running ML on every packet of an established connection
        if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].flags & 0x10:
            pkt.accept()
            return
        
        # NOTE: move before ml block - so established connections are allowed without running ML every time (improves performance and reduces false positives on established connections)
        # 1. Allow established connections (stateful tracking)
        if is_established(scapy_pkt):
            #log_event("ALLOW", "connection tracking", "inbound", info)
            pkt.accept()
            return
        
        # Allow all ICMP traffic
        if scapy_pkt.haslayer(ICMP):
            direction = "inbound"
            #log_event("ALLOW", "ICMP allowed", direction, info)
            pkt.accept()
            return

        # Allow HTTP and HTTPS traffic
        if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].dport in (80, 443):
            #log_event("ALLOW", "HTTP/HTTPS allowed", "outbound", info)
            track_connection(scapy_pkt)
            pkt.accept()
            return
        
        # Allow DNS queries
        if scapy_pkt.haslayer(UDP) and scapy_pkt[UDP].dport == 53:
            #log_event("ALLOW", "DNS query", "outbound", info)
            track_connection(scapy_pkt)
            pkt.accept()
            return
        
        # ------------------ DEFAULT POLICY: DENY ------------------
        # Deny all other traffic & log
        # Any packet that does not match allow rules is dropped
        # This is a "default deny" firewall strategy
        #log_event("BLOCK", "default deny", "outbound", info)
        pkt.drop()
        
    # ------------------ GLOBAL ERROR HANDLER ------------------
    # Catch-all for unexpected errors to avoid dropping packets accidentally
    except Exception as e:
        # Catch unexpected errors to prevent breaking networking
        print(f"[ERROR] {e}")
        # Fail-open strategy: allow packet instead of risking blocking legitimate traffic
        pkt.accept()

def main():
    """
    Entry point for the firewall.
    Loads configuration, initializes Netfilter queue, and starts packet processing loop.
    """

    print("[+] Firewall started\n")
    print("[+] Press CTRL+C to stop\n")

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


"""
def process_packet(pkt):

    try:
        # ------------------ RAW PAYLOAD ------------------
        payload = pkt.get_payload()

        if len(payload) < 20:
            pkt.accept()
            return

        # ------------------ SCAPY PARSE ------------------
        try:
            scapy_pkt = IP(payload)
        except Exception:
            pkt.accept()
            return

        # ------------------ FLOW UPDATE ------------------
        flow_manager.update_flow(scapy_pkt)

        # ------------------ EXPIRE FLOWS + ML ------------------
        expired_flows = flow_manager.expire_flows()

        for flow in expired_flows:
            try:
                # Extract features (FULL FLOW)
                feature_dict = extract_features(flow)

                # Ensure correct order
                features = [feature_dict[name] for name in feature_names]

                # Clean values
                features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

                # ML prediction
                proba = ml_model.predict_proba(features)[0][1]

                print(f"[FLOW END] {flow['src_ip']} → prob={proba:.4f}")

                # Decision
                if proba > MALICIOUS_THRESHOLD:
                    print(f"[ML] MALICIOUS: {flow['src_ip']}, prob={proba:.4f}")

                    if flow["src_ip"] not in blacklist:
                        blacklist.add(flow["src_ip"])
                        block_ip(flow["src_ip"])
                else:
                    print(f"[ML] BENIGN: {flow['src_ip']}, prob={proba:.4f}")

            except Exception as e:
                print(f"[ML ERROR] {e}")

        # ------------------ BLACKLIST CHECK ------------------
        if scapy_pkt.src in blacklist:
            info = extract_print_info(scapy_pkt)
            log_event("BLOCK", "ML blacklist", "inbound", info)
            pkt.drop()
            return

        # ------------------ ALLOW RULES ------------------

        # Allow established TCP (ACK packets)
        if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].flags & 0x10:
            pkt.accept()
            return

        # Stateful tracking
        if is_established(scapy_pkt):
            pkt.accept()
            return

        # ICMP
        if scapy_pkt.haslayer(ICMP):
            pkt.accept()
            return

        # HTTP/HTTPS
        if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].dport in (80, 443):
            track_connection(scapy_pkt)
            pkt.accept()
            return

        # DNS
        if scapy_pkt.haslayer(UDP) and scapy_pkt[UDP].dport == 53:
            track_connection(scapy_pkt)
            pkt.accept()
            return

        # ------------------ DEFAULT DENY ------------------
        pkt.drop()

    except Exception as e:
        print(f"[ERROR] {e}")
        pkt.accept()
        
"""