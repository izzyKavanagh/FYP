#!/usr/bin/env python3
from scapy.all import IP, UDP, send
import time
import random

TARGET = "192.168.56.101"
DEST_PORT = 5005  # any port

def main():
    print(f"[+] Sending UDP packets to {TARGET}:{DEST_PORT}")
    try:
        while True:
            payload = bytes([random.randint(0, 255) for _ in range(16)])
            pkt = IP(dst=TARGET)/UDP(dport=DEST_PORT)/payload
            send(pkt, verbose=False)
            print("Sent UDP packet")
            time.sleep(0.75)
    except KeyboardInterrupt:
        print("\n[-] Stopped UDP test.")

if __name__ == "__main__":
    main()