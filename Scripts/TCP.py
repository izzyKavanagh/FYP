from scapy.all import IP, TCP, send
import time

TARGET = "192.168.56.3"   
DEST_PORT = 80              

def main():
    print(f"[+] Sending test TCP SYN packets to {TARGET}:{DEST_PORT}")
    try:
        while True:
            syn = IP(dst=TARGET)/TCP(dport=DEST_PORT, flags="S")
            send(syn, verbose=False)
            print(f"Sent TCP SYN -> {TARGET}:{DEST_PORT}")
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[-] Stopped TCP SYN test.")

if __name__ == "__main__":
    main()