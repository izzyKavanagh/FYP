#!/usr/bin/env python3
import subprocess
import random
import time
import sys

TARGET      = "10.0.1.2"
TARGET_USER = "testuser"

# ---- Existing HTTP functions (keep these) ----

def moderate_http():
    print("[NORMAL] Moderate HTTP")
    subprocess.run([
        "ab", "-n", "200", "-c", "2", "-t", "30",
        f"http://{TARGET}/"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def sustained_curl_loop():
    print("[NORMAL] Sustained curl loop")
    end = time.time() + 30
    while time.time() < end:
        subprocess.run(
            ["curl", "-s", "--keepalive-time", "60", f"http://{TARGET}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(random.uniform(0.5, 1.5))

def wget_recursive():
    print("[NORMAL] Wget recursive")
    subprocess.run([
        "wget", "-r", "-l", "2", "-q", "--delete-after",
        f"http://{TARGET}/"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ---- New: varied packet sizes ----

def mixed_size_requests():
    """
    Alternates between tiny and large HTTP requests.
    Gives the model varied pkt_len_mean and pkt_len_std values for benign traffic,
    so it doesn't learn that 'high variance = attack'.
    """
    print("[NORMAL] Mixed size HTTP requests")
    end = time.time() + 30
    payloads = [64, 256, 1024, 4096]   # bytes
    while time.time() < end:
        size = random.choice(payloads)
        subprocess.run([
            "curl", "-s", "-X", "POST",
            f"http://{TARGET}/",
            "--data", "A" * size,
            "-o", "/dev/null"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(random.uniform(0.3, 1.0))

# ---- New: DNS variety ----

def dns_queries():
    """
    Normal DNS lookups — varies dest_port=53 windows with benign patterns.
    Without this, all benign port-53 traffic in the dataset comes from
    system resolver, which may be sparse and unrepresentative.
    """
    print("[NORMAL] DNS queries")
    domains = [
        "google.com", "github.com", "cloudflare.com",
        "amazon.com", "bbc.co.uk", "wikipedia.org"
    ]
    end = time.time() + 30
    while time.time() < end:
        domain = random.choice(domains)
        subprocess.run(
            ["dig", domain, f"@{TARGET}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
        )
        time.sleep(random.uniform(0.5, 2.0))

# ---- New: bursty but legitimate ----

def bursty_normal():
    """
    Short bursts of requests followed by idle periods.
    Mimics a real user clicking through pages — high then zero traffic.
    Trains the model that high fwd_packet_rate is not always malicious.
    """
    print("[NORMAL] Bursty normal traffic")
    for _ in range(random.randint(3, 6)):
        # Short burst
        burst_size = random.randint(10, 30)
        subprocess.run([
            "ab", "-n", str(burst_size), "-c", "5",
            f"http://{TARGET}/"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Then idle — mimics user reading the page
        time.sleep(random.uniform(2.0, 5.0))

# ---- New: slow steady traffic ----

def slow_steady():
    """
    Very low rate requests over a long period.
    Ensures the model sees benign traffic at low fwd_packet_rate too,
    so it doesn't flag Slowloris purely because of low rate.
    The key difference from Slowloris: complete requests, normal packet sizes.
    """
    print("[NORMAL] Slow steady traffic")
    end = time.time() + 60
    while time.time() < end:
        subprocess.run([
            "curl", "-s", f"http://{TARGET}/", "-o", "/dev/null"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(random.uniform(3.0, 8.0))   # deliberately slow

# ---- Action list ----

ACTIONS = [
    moderate_http,
    sustained_curl_loop,
    wget_recursive,
    mixed_size_requests,
    dns_queries,
    bursty_normal,
    slow_steady,
]

def main():
    print(f"[+] Normal traffic to {TARGET}")
    print(f"[+] {len(ACTIONS)} traffic patterns")
    print("[+] Ctrl+C to stop\n")

    try:
        while True:
            action = random.choice(ACTIONS)
            action()
            time.sleep(random.uniform(0.5, 2.0))
    except KeyboardInterrupt:
        print("\n[-] Stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()