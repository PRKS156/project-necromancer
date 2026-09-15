"""
ICMP Ping Flood Simulator — Project Necromancer Live Demo Tool.

Rapidly blasts ICMP Echo Request (Ping) packets to the local machine
to trigger the ICMP_FLOOD detection signature.
"""

from scapy.all import IP, ICMP, send
import time
import sys

def run_icmp_flood(target_ip="127.0.0.1", count=200):
    print(f"=== STARTING ICMP PING FLOOD SIMULATION ===")
    print(f"Target: {target_ip}")
    print(f"Sending {count} ICMP packets...")

    start_time = time.time()
    packet = IP(dst=target_ip)/ICMP()
    
    try:
        # We send at Layer 3 using scapy's send function
        send(packet, count=count, verbose=False)
        print(f"[PROGRESS] {count} packets sent.")
    except KeyboardInterrupt:
        print("\nFlood interrupted by user.")
    except PermissionError:
        print("\n[ERROR] Scapy requires administrative privileges to send raw ICMP packets.")
        print("Please run this terminal as Administrator to test the ICMP Flood.")
        sys.exit(1)

    elapsed = time.time() - start_time
    print(f"\n=== ICMP FLOOD COMPLETE ===")
    print(f"Sent {count} packets in {elapsed:.2f} seconds")
    print("Switch to your dashboard to watch the ICMP_FLOOD detection.")

if __name__ == "__main__":
    packet_count = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    run_icmp_flood(count=packet_count)
