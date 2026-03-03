import logging
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP
from netfilterqueue import NetfilterQueue
from feature_extractor import extract_features
from flow_manager import FlowManager
from ml_model import MLModel
import subprocess

flow_manager = FlowManager()
ml_model = MLModel("rf_model.pkl")
dest_port = 80
# Create table to track established connections - allows stateful connection tracking
connection_table = set()

# Create blacklist for ML-blocked IPs
blacklist = set()

# ----------------------- HELPER METHODS -----------------------

# helper method for extracting connection information from a packet
def extract_connection_info(pkt):
    """Return (protocol, sport, dport) or (None, None, None) if unsupported."""
    if pkt.haslayer(TCP):
        return "TCP", pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        return "UDP", pkt[UDP].sport, pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        return "ICMP", "-", "-"
    else:
        return None, None, None
        
def get_flow_id(pkt):
    protocol, sport, dport = extract_connection_info(pkt)

    # Only track TCP/UDP flows
    if protocol not in ("TCP", "UDP"):
        return None

    return (pkt.src, pkt.dst, sport, dport, protocol)


# method that tracks connections by storing flows in a table (set)
def track_connection(pkt):
    # use helper method to extract packet's flow characteristics  
    flow = get_flow_id(pkt)
    
    if not flow:
        return

    # extract flow details from flow tuple
    src, dst, sport, dport, protocol = flow

    # Store both directions of the connection because connections are bidirectional & incoming/outgoing packets have different src/dst addresses and ports - this way packets going in either direction can be matched to an existing connection

    # egress direction
    connection_table.add((src, dst, sport, dport, protocol, "OUTBOUND"))

    # ingress direction
    connection_table.add((dst, src, dport, sport, protocol, "INBOUND"))
    

# helper method to check if a packet is part of an established connection - i.e. in the connection table
def is_established(pkt):
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
    proto, sport, dport = extract_connection_info(pkt)

    return {
        "proto": proto or f"OTHER({pkt.proto})",
        "src": f"{pkt.src}:{sport}",
        "dst": f"{pkt.dst}:{dport}",
    }


def log_event(action, rule, direction, info):
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
    # Parse packet and log initial info
    scapy_pkt = IP(pkt.get_payload())
    info = extract_print_info(scapy_pkt)

    # check if source IP is in ML blacklist - if so, block and log
    if scapy_pkt.src in blacklist:
        info = extract_print_info(scapy_pkt)
        log_event("BLOCK", "ML blacklist", "inbound", info)
        pkt.drop()
        return

    # ----------- ML FLOW TRACKING -----------
    flow_manager.update_flow(scapy_pkt)

    expired_flows = flow_manager.expire_flows()
    

    for flow in expired_flows:
        # extract features from flow and run ML prediction - if malicious, block source IP and log
        features = extract_features(flow)
        # ML model expects a 2D array of shape for a single prediction - create a 2D array with one row
        prediction = ml_model.predict([features])[0]
        
        if prediction == 1:
            print(f"[!] ML detected malicious flow from {flow['src_ip']}")
            blacklist.add(flow["src_ip"])
            block_ip(flow["src_ip"])

    # ----------- Allow Rules -----------
    
    # allow established connections
    if is_established(scapy_pkt):
        log_event("ALLOW", "connection tracking", "inbound", info)
        pkt.accept()
        return
    
    # Allow all ICMP traffic
    if scapy_pkt.haslayer(ICMP):
        direction = "inbound" if scapy_pkt.dst == scapy_pkt[IP].dst else "outbound"
        log_event("ALLOW", "ICMP allowed", direction, info)
        pkt.accept()
        return

    # Allow HTTP and HTTPS traffic
    if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].dport in (80, 443):
        log_event("ALLOW", "HTTP/HTTPS allowed", "outbound", info)
        track_connection(scapy_pkt)
        pkt.accept()
        return
    
    # Allow DNS queries
    if scapy_pkt.haslayer(UDP) and scapy_pkt[UDP].dport == 53:
        log_event("ALLOW", "DNS query", "outbound", info)
        track_connection(scapy_pkt)
        pkt.accept()
        return
    
    # Deny all other traffic & log
    log_event("BLOCK", "default deny", "outbound", info)
    pkt.drop()


def main():
    print("[+] Firewall started\n")
    print("[+] Press CTRL+C to stop\n")

    nfq = NetfilterQueue()
    nfq.bind(0, process_packet)

    try:
        nfq.run()
    except KeyboardInterrupt:
        print("\n[-] Firewall stopped")


if __name__ == "__main__":
    main()