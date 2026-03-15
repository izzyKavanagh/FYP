from datetime import datetime # For timestamping log events
from scapy.all import IP, TCP, UDP, ICMP # Packet parsing and manipulation
from netfilterqueue import NetfilterQueue # To hook into Linux netfilter queue
from feature_extractor import extract_features # Custom module to extract ML features
from flow_manager import FlowManager # Custom module to track network flows
from ml_model import MLModel # Custom module wrapping the trained ML model
import subprocess # To execute system commands (e.g., iptables)
from config_loader import load_config # Custom module to load firewall configuration

# ----------------------- INITIAL SETUP -----------------------

# Initialize flow manager to track active flows and their statistics
flow_manager = FlowManager()

# Load the pre-trained machine learning model (random forest)
ml_model = MLModel("rf_model.pkl")

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
    Main packet processing logic.
    Called for each packet in the Netfilter queue.
    Implements:
    - Stateful connection tracking
    - ML-based flow classification
    - Rule-based allow/block logic
    """
    try:
        # Get raw payload
        payload = pkt.get_payload()

        # Ignore very short packets
        if len(payload) < 20:
            pkt.accept()
            return

        # Parse packet with scapy
        try:
            scapy_pkt = IP(payload)
        except Exception:
            pkt.accept()
            return

        # Remove expired flows to save memory
        flow_manager.expire_flows()

        # Extract info for logging
        info = extract_print_info(scapy_pkt)


        # ---------------- ML BLOCKLIST CHECK ----------------

        # check if source IP is in ML blacklist - if so, block and log
        if scapy_pkt.src in blacklist:
            info = extract_print_info(scapy_pkt)
            log_event("BLOCK", "ML blacklist", "inbound", info)
            pkt.drop()
            return

        # ----------- ML FLOW TRACKING -----------

        flow = flow_manager.update_flow(scapy_pkt)

        # Only classify flows if they have enough packets and haven't been checked
        if flow and flow["packet_count"] >= 1 and not flow.get("ml_checked"):

            flow["ml_checked"] = True

            try:
                features = extract_features(flow)
                prediction = ml_model.predict([features])[0]
            except Exception as e:
                print(f"[ML ERROR] {e}")
                prediction = 0 # Default to benign if ML fails

            if prediction == 1:
                # Flow predicted as malicious → block and log
                print("\n\n-------------------------------------------")
                print(f"[ML PREDICTION] {flow['src_ip']} → MALICIOUS")
                blacklist.add(flow["src_ip"])
                block_ip(flow["src_ip"])
                print("-------------------------------------------\n\n")
            else:
                # Flow predicted benign → log info
                print("\n\n-------------------------------------------")
                print(f"[ML PREDICTION] {flow['src_ip']} → BENIGN")
                print("-------------------------------------------\n\n")

        # ----------- Allow Rules -----------
        
        # 1. Allow established connections (stateful tracking)
        if is_established(scapy_pkt):
            log_event("ALLOW", "connection tracking", "inbound", info)
            pkt.accept()
            return
        
        # 2. Allow ICMP (ping, traceroute) if configured
        if scapy_pkt.haslayer(ICMP) and config["icmp_allowed"]:
            log_event("ALLOW", "ICMP allowed", "outbound", info)
            pkt.accept()
            return

        # 3. Allow HTTP/HTTPS outbound traffic
        if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].dport in config["allowed_outbound_tcp_ports"]:
            log_event("ALLOW", "HTTP/HTTPS allowed", "outbound", info)
            track_connection(scapy_pkt)
            pkt.accept()
            return
        
        # 4. Allow DNS queries (UDP)
        if scapy_pkt.haslayer(UDP) and scapy_pkt[UDP].dport in config["allowed_outbound_udp_ports"]:
            log_event("ALLOW", "DNS query", "outbound", info)
            track_connection(scapy_pkt)
            pkt.accept()
            return
        
        # 5. Default policy (allow or deny)
        if config["default_policy"] == "allow":
            pkt.accept()
        else:
            log_event("BLOCK", "default deny", "outbound", info)
            pkt.drop()
        
    # Catch-all for unexpected errors to avoid dropping packets accidentally
    except Exception as e:
        print(f"[ERROR] {e}")
        pkt.accept()

def main():
    """
    Entry point for the firewall.
    Loads configuration, initializes Netfilter queue, and starts packet processing loop.
    """

    # Load firewall configuration (JSON or YAML)
    global config
    config = load_config()

    print("[+] Firewall started\n")
    print("[+] Configuration loaded\n")
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