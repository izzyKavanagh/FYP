test_http_https.py
#!/usr/bin/env python3
from scapy.all import IP, TCP, send
import time

TARGET_IP = "192.168.56.101"  # ← firewall target
PORTS = [80, 443]  # HTTP, HTTPS

def main():
    print(f"[+] Sending HTTP/HTTPS TCP SYN packets to {TARGET_IP}")
    try:
        while True:
            for port in PORTS:
                syn = IP(dst=TARGET_IP) / TCP(dport=port, flags="S")
                send(syn, verbose=False)
                print(f"Sent TCP SYN to {TARGET_IP}:{port}")
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Stopped HTTP/HTTPS test.")

if __name__ == "__main__":
    main()