"""
Port Scan Simulator — Project Necromancer Live Demo Tool.

Rapidly attempts to connect to a sequence of ports on the local machine
to trigger the PORT_SCAN detection signature.
"""

import socket
import time
import sys

def run_port_scan(target_ip="127.0.0.1", start_port=1, end_port=100, delay=0.01):
    print(f"=== STARTING PORT SCAN SIMULATION ===")
    print(f"Target: {target_ip}")
    print(f"Scanning ports {start_port} through {end_port}...")

    sent = 0
    start_time = time.time()

    try:
        for port in range(start_port, end_port + 1):
            # Using UDP so we don't have to wait for TCP timeouts on closed ports
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b"PING", (target_ip, port))
            sock.close()
            sent += 1
            if delay > 0:
                time.sleep(delay)
            if sent % 20 == 0:
                print(f"[PROGRESS] Scanned {sent} ports...")
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")

    elapsed = time.time() - start_time
    print(f"\n=== PORT SCAN COMPLETE ===")
    print(f"Scanned {sent} ports in {elapsed:.2f} seconds")
    print("Switch to your dashboard to watch the PORT_SCAN detection.")

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    gap = float(sys.argv[2]) if len(sys.argv) > 2 else 0.01
    run_port_scan(end_port=count, delay=gap)
