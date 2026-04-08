#!/usr/bin/env python3
import subprocess
import time

TARGET = "10.0.1.2"

def port_scan():
    print("[ATTACK] CICIDS Port Scan")

    for _ in range(3):  # repeat scan cycles
        for port in range(20, 100):
            subprocess.run(
                ["nc", "-zv", TARGET, str(port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(0.01)  # slight delay

if __name__ == "__main__":
    port_scan()