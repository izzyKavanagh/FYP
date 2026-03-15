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
    try:
        payload = pkt.get_payload()

        if len(payload) < 20:
            pkt.accept()
            return

        try:
            scapy_pkt = IP(payload)
        except Exception:
            pkt.accept()
            return

        flow_manager.expire_flows()
        
        info = extract_print_info(scapy_pkt)

        # check if source IP is in ML blacklist - if so, block and log
        if scapy_pkt.src in blacklist:
            info = extract_print_info(scapy_pkt)
            log_event("BLOCK", "ML blacklist", "inbound", info)
            pkt.drop()
            return

        # ----------- ML FLOW TRACKING -----------

        flow = flow_manager.update_flow(scapy_pkt)

        # Only run ML when the flow has enough packets
        if flow and flow["packet_count"] >= 10 and not flow.get("ml_checked"):

            flow["ml_checked"] = True

            try:
                features = extract_features(flow)
                prediction = ml_model.predict([features])[0]
            except Exception as e:
                print(f"[ML ERROR] {e}")
                prediction = 0

            if prediction == 1:
                print("\n\n-------------------------------------------")
                print(f"[ML PREDICTION] {flow['src_ip']} → MALICIOUS")
                blacklist.add(flow["src_ip"])
                block_ip(flow["src_ip"])
                print("-------------------------------------------\n\n")
            else:
                print("\n\n-------------------------------------------")
                print(f"[ML PREDICTION] {flow['src_ip']} → BENIGN")
                print("-------------------------------------------\n\n")

        # ----------- Allow Rules -----------
        
        # allow established connections
        if is_established(scapy_pkt):
            log_event("ALLOW", "connection tracking", "inbound", info)
            pkt.accept()
            return
        
        # Allow all ICMP traffic
        if scapy_pkt.haslayer(ICMP):
            direction = "inbound" if scapy_pkt.src != scapy_pkt[IP].src else "outbound"
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
        
    except Exception as e:
        print(f"[ERROR] {e}")
        pkt.accept()

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