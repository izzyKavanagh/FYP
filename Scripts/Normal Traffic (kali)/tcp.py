#!/usr/bin/env python3
import subprocess
import time

TARGET = "10.0.1.2"
PORTS = [80, 443]

def main():
    print(f"[+] Sending TCP SYN packets to {TARGET} (ports 80 & 443)")
    try:
        while True:
            for port in PORTS:
                subprocess.run([
                    "sudo", "hping3",
                    "-S",          # SYN flag
                    "-c", "1",     # send 1 packet
                    "-p", str(port),
                    TARGET
                ], stdout=subprocess.DEVNULL)

                print(f"Sent TCP SYN to {TARGET}:{port}")
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Stopped HTTP/HTTPS SYN test.")

if __name__ == "__main__":
    main()