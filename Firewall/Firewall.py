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

def log_allowed(info):
    allow_logger.info(f"{datetime.now()} ALLOW {info}")

def log_denied(info):
    deny_logger.info(f"{datetime.now()} DROP {info}")

def parse_packet(pkt):
    # Extract readable metadata from the packet.
    scapy_pkt = IP(pkt.get_payload())

    src = scapy_pkt.src
    dst = scapy_pkt.dst

    # Detect protocol + ports
    if scapy_pkt.haslayer(TCP):
        protocol = "TCP"
        sport = scapy_pkt[TCP].sport
        dport = scapy_pkt[TCP].dport
    elif scapy_pkt.haslayer(UDP):
        protocol = "UDP"
        sport = scapy_pkt[UDP].sport
        dport = scapy_pkt[UDP].dport
    elif scapy_pkt.haslayer(ICMP):
        protocol = "ICMP"
        sport = dport = "-"
    else:
        protocol = f"OTHER({scapy_pkt.proto})"
        sport = dport = "-"

    return f"{protocol} {src}:{sport} -> {dst}:{dport}"

def process_packet(pkt):
     # Parse packet and log initial info
    scapy_pkt = IP(pkt.get_payload())
    info = parse_packet(pkt)
    log_allowed(info)

    # Allow Rules -----------------------------
    
    # Allow all ICMP traffic
    if scapy_pkt.haslayer(ICMP):
        log_allowed(info)
        pkt.accept()
        return

    # Allow HTTP and HTTPS traffic
    if scapy_pkt.haslayer(TCP) and scapy_pkt[TCP].dport in (80, 443):
        log_allowed(info)
        pkt.accept()
        return
    
    # Allow DNS queries
    if scapy_pkt.haslayer(UDP) and scapy_pkt[UDP].dport == 53:
        log_allowed(info)
        pkt.accept()
        return
    
    # Deny Rules ------------------------------
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