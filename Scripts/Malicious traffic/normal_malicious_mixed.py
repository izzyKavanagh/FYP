#!/usr/bin/env python3
import subprocess
import random
import time

TARGET = "10.0.1.2"

# Normal traffic ports
HTTP_PORTS = [80, 443]

# Suspicious/malicious ports
TCP_ATTACK_PORTS = [22, 1234, 4444]
UDP_ATTACK_PORTS = [53, 9999, 5005]

def send_normal_icmp():
    subprocess.run(["ping", "-c", "1", TARGET],
                   stdout=subprocess.DEVNULL)
    print("[NORMAL] ICMP ping sent")

def send_normal_http():
    subprocess.run(["curl", "-s", f"http://{TARGET}"],
                   stdout=subprocess.DEVNULL)
    print("[NORMAL] HTTP request sent")

def send_tcp_probe():
    port = random.choice(TCP_ATTACK_PORTS)
    subprocess.run([
        "sudo", "hping3",
        "-S",
        "-c", "1",
        "-p", str(port),
        TARGET
    ], stdout=subprocess.DEVNULL)
    print(f"[ATTACK] TCP SYN sent to port {port}")

def send_udp_probe():
    port = random.choice(UDP_ATTACK_PORTS)
    subprocess.run([
        "sudo", "hping3",
        "--udp",
        "-c", "1",
        "-p", str(port),
        TARGET
    ], stdout=subprocess.DEVNULL)
    print(f"[ATTACK] UDP packet sent to port {port}")

def syn_burst():
    print("[ATTACK] Starting short SYN burst")
    process = subprocess.Popen([
        "sudo", "hping3",
        "-S",
        "--flood",
        "-p", "80",
        TARGET,
        "--rand-source"
    ], stdout=subprocess.DEVNULL)

    time.sleep(5)
    process.terminate()
    print("[ATTACK] SYN burst stopped")

def main():
    print(f"[+] Starting mixed traffic scenario against {TARGET}")
    print("[+] Press Ctrl+C to stop\n")

    try:
        while True:
            action = random.choices(
                population=[
                    send_normal_icmp,
                    send_normal_http,
                    send_tcp_probe,
                    send_udp_probe,
                    syn_burst
                ],
                weights=[4, 4, 2, 2, 1],  # More normal than attack
                k=1
            )[0]

            action()
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[-] Mixed traffic stopped.")

if __name__ == "__main__":
    main()