#!/usr/bin/env python3
import random
import time
from scapy.all import IP, ICMP, TCP, UDP, send

TARGET = "192.168.56.101"

def send_icmp():
    send(IP(dst=TARGET)/ICMP(), verbose=False)
    print("[ICMP] Sent")

def send_tcp():
    port = random.choice([22, 80, 443, 1234])
    syn = IP(dst=TARGET)/TCP(dport=port, flags="S")
    send(syn, verbose=False)
    print(f"[TCP] Sent SYN to port {port}")

def send_udp():
    port = random.choice([53, 9999, 5005])
    pkt = IP(dst=TARGET)/UDP(dport=port)/b"test123"
    send(pkt, verbose=False)
    print(f"[UDP] Sent packet to port {port}")

def main():
    print("[+] Sending mixed traffic to", TARGET)
    try:
        while True:
            choice = random.choice([send_icmp, send_tcp, send_udp])
            choice()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Stopped mixed traffic test.")

if __name__ == "__main__":
    main()