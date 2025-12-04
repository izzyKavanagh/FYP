from scapy.all import ICMP, IP, send
import time

TARGET = "192.168.56.101"  # change to victim/firewall IP

def main():
    print(f"[+] Sending ICMP echo requests to {TARGET}")
    try:
        while True:
            pkt = IP(dst=TARGET)/ICMP()
            send(pkt, verbose=False)
            print("Sent ICMP packet")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Stopped ICMP test.")

if __name__ == "__main__":
    main()