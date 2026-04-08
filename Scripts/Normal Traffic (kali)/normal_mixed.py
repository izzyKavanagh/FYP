#!/usr/bin/env python3
import subprocess
import random
import time

TARGET = "10.0.1.2"

def http_session():
    print("[NORMAL] HTTP session")

    for _ in range(50):  # increase burst size
        subprocess.Popen(
            ["curl", "-s", f"http://{TARGET}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

def dns_burst():
    print("[NORMAL] DNS burst")

    for _ in range(20):
        subprocess.Popen(
            ["nslookup", TARGET],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

def main():
    print(f"[+] High-rate normal traffic to {TARGET}")

    actions = [http_session, dns_burst]

    try:
        while True:
            action = random.choice(actions)
            action()

            # VERY short pause between bursts
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n[-] Stopped normal traffic.")

if __name__ == "__main__":
    main()