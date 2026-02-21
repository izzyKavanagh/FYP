import subprocess

TARGET = "10.0.1.2"

def main():
    print(f"[+] Running SYN scan against {TARGET}")
    subprocess.run(["nmap", "-sS", TARGET])

    print(f"[+] Running aggressive scan against {TARGET}")
    subprocess.run(["nmap", "-A", TARGET])

    print("[+] Nmap scans completed.")

if __name__ == "__main__":
    main()