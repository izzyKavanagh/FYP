#!/usr/bin/env python3
import subprocess
import time

TARGET = "10.0.1.2"
PORT = 5005

def main():
    print(f"[+] Sending UDP packets to {TARGET}:{PORT}")
    try:
        while True:
            subprocess.run([
                "sudo", "hping3",
                "--udp",
                "-c", "1",
                "-p", str(PORT),
                TARGET
            ], stdout=subprocess.DEVNULL)

            print("Sent UDP packet")
            time.sleep(0.75)
    except KeyboardInterrupt:
        print("\n[-] Stopped UDP test.")

if __name__ == "__main__":
    main()