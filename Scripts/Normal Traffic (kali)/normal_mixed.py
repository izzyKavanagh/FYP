#!/usr/bin/env python3
import subprocess
import random
import time

TARGET = "10.0.1.2"

TCP_PORTS = [22, 80, 443, 1234]
UDP_PORTS = [53, 9999, 5005]

def send_icmp():
    subprocess.run(["ping", "-c", "1", TARGET],
                   stdout=subprocess.DEVNULL)
    print("[ICMP] Sent")

def send_tcp():
    port = random.choice(TCP_PORTS)
    subprocess.run([
        "sudo", "hping3",
        "-S",
        "-c", "1",
        "-p", str(port),
        TARGET
    ], stdout=subprocess.DEVNULL)
    print(f"[TCP] Sent SYN to port {port}")

def send_udp():
    port = random.choice(UDP_PORTS)
    subprocess.run([
        "sudo", "hping3",
        "--udp",
        "-c", "1",
        "-p", str(port),
        TARGET
    ], stdout=subprocess.DEVNULL)
    print(f"[UDP] Sent packet to port {port}")

def main():
    print(f"[+] Sending mixed traffic to {TARGET}")
    try:
        while True:
            random.choice([send_icmp, send_tcp, send_udp])()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Stopped mixed traffic test.")

if __name__ == "__main__":
    main()