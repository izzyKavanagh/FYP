#!/usr/bin/env python3
import subprocess
import random
import time
import sys

TARGET = "10.0.1.2"

# ------------------ SUSTAINED TRAFFIC FUNCTIONS ------------------

def moderate_http():
    """Low concurrency, human-scale request rate"""
    print("[NORMAL] Moderate HTTP")
    subprocess.run([
        "ab",
        "-n", "200",    # far fewer requests
        "-c", "2",      # minimal concurrency
        "-t", "30",     # spread over 30 seconds
        f"http://{TARGET}/"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def sustained_curl_loop():
    print("[NORMAL] Sustained curl loop")
    end = time.time() + 30
    while time.time() < end:
        subprocess.run(
            ["curl", "-s", "--keepalive-time", "60", f"http://{TARGET}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        # Increased from 0.05s — 0.5-1.5s is realistic for automated tools
        # 50ms generated ~20 req/s which looks identical to dos_http
        time.sleep(random.uniform(0.5, 1.5))

def large_file_download():
    """
    Download a large file — generates a long continuous flow naturally.
    Requires a large file to exist on the victim (e.g. create one with dd).
    """
    print("[NORMAL] Large file download")
    subprocess.run([
        "curl", "-s",
        f"http://{TARGET}/largefile.bin",  # create this on victim VM
        "-o", "/dev/null"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def continuous_ping():
    """
    Long ping session — ICMP but generates steady flow.
    Note: ICMP flows may not accumulate if flow_manager filters them.
    """
    print("[NORMAL] Continuous ping")
    subprocess.run([
        "ping", "-c", "200", "-i", "0.05",  # 200 pings, 50ms interval
        TARGET
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def wget_recursive():
    """
    Recursive wget — mimics a crawler, generates sustained HTTP traffic.
    """
    print("[NORMAL] Wget recursive")
    subprocess.run([
        "wget",
        "-r",           # recursive
        "-l", "2",      # depth 2
        "-q",           # quiet
        "--delete-after",  # don't save files
        f"http://{TARGET}/"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def iperf_session():
    """
    iperf TCP throughput test — generates a pure sustained TCP flow.
    Requires iperf3 server running on victim: iperf3 -s
    """
    print("[NORMAL] iperf3 TCP session")
    subprocess.run([
        "iperf3",
        "-c", TARGET,
        "-t", "15",     # 15 seconds of sustained traffic
        "-i", "0"       # no interval reports
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ssh_file_transfer():
    """
    SCP a file — generates sustained SSH/TCP flow.
    """
    print("[NORMAL] SCP file transfer")
    # Create a temp file to send
    subprocess.run(["dd", "if=/dev/urandom", "of=/tmp/testfile",
                    "bs=1M", "count=5"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([
        "scp", "-o", "StrictHostKeyChecking=no",
        "/tmp/testfile",
        f"testuser@{TARGET}:/tmp/"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ------------------ ACTIONS LIST ------------------
# Ordered from most reliable to least (some need extra setup)

ACTIONS_ALWAYS_WORK = [
    moderate_http,   # needs apache/nginx on victim
    sustained_curl_loop,    # needs apache/nginx on victim
    continuous_ping,        # always works
    wget_recursive,         # needs apache/nginx on victim
]

ACTIONS_NEED_SETUP = [
    large_file_download,    # needs largefile.bin on victim web server
    iperf_session,          # needs iperf3 -s running on victim
    ssh_file_transfer,      # needs SSH + testuser on victim
]

# Start with reliable ones — add setup ones once confirmed working
ACTIONS = ACTIONS_ALWAYS_WORK

# ------------------ MAIN ------------------

def main():
    print(f"[+] Sustained normal traffic to {TARGET}")
    print(f"[+] Using {len(ACTIONS)} traffic actions")
    print("[+] Press Ctrl+C to stop\n")

    # How many windows we expect per action (rough guide printed at start)
    print("[INFO] Each action should generate multiple full windows (100 pkts each)")
    print("[INFO] Watch collect_dataset.py for '[+] Window written' messages\n")

    try:
        while True:
            action = random.choice(ACTIONS)
            action()
            # Short pause between actions — long enough to be realistic,
            # short enough that the flow doesn't expire between actions
            time.sleep(random.uniform(0.5, 2.0))

    except KeyboardInterrupt:
        print("\n[-] Stopped normal traffic.")
        sys.exit(0)

if __name__ == "__main__":
    main()