#!/usr/bin/env python3
import subprocess
import time

TARGET = "10.0.1.2"

def main():
    print(f"[+] Sending ICMP echo requests to {TARGET}")
    try:
        while True:
            subprocess.run(["ping", "-c", "1", TARGET],
                           stdout=subprocess.DEVNULL)
            print("Sent ICMP packet")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Stopped ICMP test.")

if __name__ == "__main__":
    main()