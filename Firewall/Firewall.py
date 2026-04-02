from datetime import datetime
import joblib
from scapy.all import IP, TCP, UDP, ICMP
from netfilterqueue import NetfilterQueue
from feature_extractor import extract_window_features
from flow_manager import FlowManager
from ml_model import MLModel
import subprocess
import numpy as np

flow_manager = FlowManager()

# Load the pre-trained machine learning model (random forest)
ml_model = MLModel("rf_model.pkl")

feature_names = joblib.load("features.pkl")

# ----------------------- CONFIG -----------------------

MIN_PACKETS = 20
MIN_DURATION = 0.5  # seconds
ML_CHECK_INTERVAL = 10
MALICIOUS_THRESHOLD = 0.7

# Create table to track established connections - allows stateful connection tracking
connection_table = set()

# Create blacklist for ML-blocked IPs
blacklist = set()

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

    # Store both directions of the connection because connections are bidirectional & incoming/outgoing packets have different src/dst addresses and ports - this way packets going in either direction can be matched to an existing connection
    # Track outgoing packets
    connection_table.add((src, dst, sport, dport, protocol, "OUTBOUND"))

    # Track incoming packets 
    connection_table.add((dst, src, dport, sport, protocol, "INBOUND"))
    
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

    # check if flow exists in connection table in either direction & return result (True/False)
    return ( (src, dst, sport, dport, protocol, "INBOUND") in connection_table or
    (src, dst, sport, dport, protocol, "OUTBOUND") in connection_table )


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

        # ------------------ FLOW CLEANUP ------------------
        # Periodically remove expired flows to:
        # - Prevent memory leaks
        # - Keep flow table efficient

        # Remove expired flows to save memory
        flow_manager.expire_flows()

        # ------------------ FLOW UPDATE ------------------
        
        # Update flow statistics with the current packet
        # Returns the flow object (or None if not tracked)
        flow = flow_manager.update_flow(scapy_pkt)

        # Extract info for logging
        info = extract_print_info(scapy_pkt)


        # ---------------- ML BLOCKLIST CHECK ----------------

        # check if source IP is already in ML blacklist (i.e.: classified as malicious) - if so, block and log
        if scapy_pkt.src in blacklist:
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

            # Compute flow duration for ML feature extraction
            duration = flow["last_seen"] - flow["start_time"]

             # Only run ML when:
            # - Enough packets have been collected (MIN_PACKETS)
            # - Flow has existed long enough (MIN_DURATION)
            # - Packet count hits interval (ML_CHECK_INTERVAL)
            #
            # This reduces:
            # - CPU usage
            # - False positives from tiny flows
            if (flow["packet_count"] >= MIN_PACKETS and duration >= MIN_DURATION and flow["packet_count"] % ML_CHECK_INTERVAL == 0):

                try:
                    # ------------------ FEATURE EXTRACTION ------------------

                    # Convert flow stats into ML-ready feature vector
                    feature_dict = extract_window_features(flow)

                    # Ensure features are in correct order expected by model
                    features = [feature_dict[name] for name in feature_names]

                    # Replace NaN / infinite values to avoid model crashes
                    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

                    #print("[FEATURES]", features)

                    # Debug: print all features with indices
                    print("FEATURE DEBUG:")
                    for i, f in enumerate(features):
                        print(i, f)

                    # Debug
                    print(f"PKT: {scapy_pkt[IP].src} -> {scapy_pkt[IP].dst}")
                    
                    #print("\n===== FEATURE NAMES DEBUG =====")
                    #print("Expected order:", feature_names)
                    #print("Extracted features:", feature_dict)
                    #print("=========================\n")

                    #print("\n-------------------------------------------")
                    #print("[DEBUG]")
                    #print(f"[DEBUG] packets={flow['packet_count']} duration={duration:.2f}s proba={proba:.4f}")
                    #print("-------------------------------------------\n")
                    #print(f"[FLOW] {flow['src_ip']} packets={flow['packet_count']}")
                                    
                    # ------------------ ML PREDICTION ------------------
                    # Get probability of malicious class (index 1)
                    # use probability instead of hard prediction

                    proba = ml_model.predict_proba([features])[0][1]

                    # Smooth the probability using a simple moving average of the last few predictions for this flow 
                    # to reduce volatility and false positives from single anomalous packets
                    flow["probability_history"].append(proba)

                    # Keep last 5 predictions
                    if len(flow["probability_history"]) > 5:
                        flow["probability_history"].pop(0)

                    # Calculate smoothed probability for more stable decision making
                    smoothed_proba = sum(flow["probability_history"]) / len(flow["probability_history"])

                except Exception as e:
                    # If ML fails - default to benign (fail-safe)
                    print(f"[ML ERROR] {e}")
                    proba = 0.0  # default to benign if error occurs

                # ------------------ DECISION ------------------
                if smoothed_proba > MALICIOUS_THRESHOLD:
                    # High probability of malicious behaviour - block and log
                    print("\n\n*******************************************")
                    print(f"[ML PREDICTION] {flow['src_ip']} → MALICIOUS (prob={proba:.4f})")
                    # Add to blacklist if not already present
                    if flow["src_ip"] not in blacklist:
                        blacklist.add(flow["src_ip"]) # ML-level blocking (added to in-memory blacklist set)
                        block_ip(flow["src_ip"]) # System-level blocking (iptables)
                    print("*******************************************\n\n")
                else:
                    # Lower probability of malicious behaviour - just print prediction for monitoring purposes
                    print("\n\n*******************************************")
                    print(f"[ML PREDICTION] {flow['src_ip']} → BENIGN (prob={proba:.4f})")
                    print("*******************************************\n\n")

                flow["window_packets"] = flow["window_packets"][flow["step_size"]:]

        # ----------- Allow Rules -----------
        
        # ACK flag (0x10) indicates part of an existing connection
        # Allow established TCP (ACK packets) - helps performance by not running ML on every packet of an established connection
        if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].flags & 0x10:
            pkt.accept()
            return
        
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