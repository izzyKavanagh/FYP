import logging
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP
from netfilterqueue import NetfilterQueue


# Create loggers
logging.basicConfig(level=logging.INFO)

allow_logger = logging.getLogger("allowed")
deny_logger = logging.getLogger("denied")

# Handlers write to local log files
allow_handler = logging.FileHandler("allowed.log")
deny_handler = logging.FileHandler("denied.log")

allow_logger.addHandler(allow_handler)
deny_logger.addHandler(deny_handler)

# Create table to track established connections - allows stateful connection tracking
connection_table = set()

def log_allowed(info):
    allow_logger.info(f"{datetime.now()} ALLOW {info}")

def log_denied(info):
    deny_logger.info(f"{datetime.now()} DROP {info}")

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


def parse_packet(pkt):
    scapy_pkt = IP(pkt.get_payload())
    protocol, sport, dport = extract_connection_info(scapy_pkt)

    if protocol is None:
        protocol = f"OTHER({scapy_pkt.proto})"
        sport = dport = "-"

    return f"{protocol} {scapy_pkt.src}:{sport} -> {scapy_pkt.dst}:{dport}"


def process_packet(pkt):
     # Parse packet and log initial info
    scapy_pkt = IP(pkt.get_payload())
    info = parse_packet(pkt)

    # Allow Rules -----------------------------
    
    # allow established connections
    if is_established(scapy_pkt):
        log_allowed(f"{info} [ESTABLISHED]")
        pkt.accept()
        return
    
    # Allow all ICMP traffic
    if scapy_pkt.haslayer(ICMP):
        # ICMP traffic is not tracked as it is stateless
        log_allowed(f"{info} [NEW]")
        pkt.accept()
        return

    # Allow HTTP and HTTPS traffic
    if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].dport in (80, 443):
        log_allowed(f"{info} [NEW]")
        track_connection(scapy_pkt)
        pkt.accept()
        return
    
    # Allow DNS queries
    if scapy_pkt.haslayer(UDP) and scapy_pkt[UDP].dport == 53:
        log_allowed(f"{info} [NEW]")
        track_connection(scapy_pkt)
        pkt.accept()
        return
    
    # Deny all other traffic & log
    log_denied(info)
    pkt.drop()

def main():
    print("[+] Firewall started — logging only mode")
    print("[+] Logs saved to allowed.log and denied.log")
    print("[+] Press CTRL+C to stop\n")

    nfq = NetfilterQueue()
    nfq.bind(0, process_packet)

    try:
        nfq.run()
    except KeyboardInterrupt:
        print("\n[-] Firewall stopped")


if __name__ == "__main__":
    main()