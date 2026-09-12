"""
Loopback Stress Test — Project Necromancer Live Demo Tool.

Sends a real, high-volume burst of UDP packets to 127.0.0.1 (your own
machine) so the AsyncSniffer in core/sniffer.py captures genuine traffic
instead of a hand-written crash_dump.json. This is the standard, legal
way to test network monitoring tools: you are only ever attacking your
own loopback address, never another machine or website.

Run this in a SEPARATE terminal while main.py is already running.
"""

import socket
import time
import sys


def run_flood(target_ip="127.0.0.1", target_port=53, packet_count=2000, delay=0.001):
    """Fires real UDP packets at your own machine to simulate a DDoS burst."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"NECROMANCER_STRESS_TEST_PACKET" * 4  # ~128 bytes per packet

    print(f"=== STARTING LOOPBACK STRESS TEST ===")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Packet Count: {packet_count}")
    print("Sending real UDP traffic to your own machine now...")

    sent = 0
    start_time = time.time()

    try:
        for i in range(packet_count):
            sock.sendto(payload, (target_ip, target_port))
            sent += 1
            if delay > 0:
                time.sleep(delay)
            if sent % 500 == 0:
                print(f"[PROGRESS] {sent}/{packet_count} packets sent...")
    except KeyboardInterrupt:
        print("\nStress test interrupted by user.")
    finally:
        sock.close()

    elapsed = time.time() - start_time
    print(f"\n=== STRESS TEST COMPLETE ===")
    print(f"Sent {sent} packets in {elapsed:.2f} seconds "
          f"({sent / max(elapsed, 0.01):.0f} packets/sec)")
    print("Switch to your main.py terminal window to watch the live detection.")


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    gap = float(sys.argv[2]) if len(sys.argv) > 2 else 0.001
    run_flood(packet_count=count, delay=gap)