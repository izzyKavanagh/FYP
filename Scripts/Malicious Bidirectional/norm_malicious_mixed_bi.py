#!/usr/bin/env python3
import subprocess
import random
import time
import socket

TARGET = "10.0.1.2"

def send_normal_icmp():
    subprocess.run(["ping", "-c", "1", TARGET],
                   stdout=subprocess.DEVNULL)
    print("[NORMAL] ICMP")

def send_normal_http():
    subprocess.run(["curl", "-s", f"http://{TARGET}"],
                   stdout=subprocess.DEVNULL)
    print("[NORMAL] HTTP")

def send_tcp_probe():
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((TARGET, random.choice([80, 443])))
        s.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
        s.recv(1024)
        s.close()
        print("[ATTACK] TCP probe")
    except:
        pass

def send_udp_probe():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"test", (TARGET, random.choice([53, 9999, 5005])))
        print("[ATTACK] UDP probe")
    except:
        pass

def burst_http():
    print("[ATTACK] HTTP burst")
    for _ in range(10):
        subprocess.run(
            ["curl", "-s", f"http://{TARGET}"],
            stdout=subprocess.DEVNULL
        )

def main():
    print(f"[+] Mixed traffic against {TARGET}")

    try:
        while True:
            action = random.choices(
                population=[
                    send_normal_icmp,
                    send_normal_http,
                    send_tcp_probe,
                    send_udp_probe,
                    burst_http
                ],
                weights=[4, 4, 2, 2, 2],
                k=1
            )[0]

            action()
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[-] Stopped.")

if __name__ == "__main__":
    main()