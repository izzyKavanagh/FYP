#!/usr/bin/env python3
import socket
import time

TARGET = "10.0.1.2"
PORT = 53
DURATION = 15

def main():
    print(f"[+] UDP traffic against {TARGET}:{PORT}")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end = time.time() + DURATION

    while time.time() < end:
        s.sendto(b"hello", (TARGET, PORT))
        time.sleep(0.01)

    print("[+] UDP test done.")

if __name__ == "__main__":
    main()