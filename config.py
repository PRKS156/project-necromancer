"""Single shared source of truth for runtime configuration.
Change ACTIVE_INTERFACE here once; main.py, signatures.py, and the
dashboard all import it instead of hardcoding a value separately.
"""

ACTIVE_INTERFACE = "Wi-Fi" # e.g. "Wi-Fi", "Ethernet", "eth0", "wlan0"
# For the live loopback attack demo, temporarily switch to your loopback
# adapter name. Run this to find the exact name Scapy sees on your machine:
#   python -c "from scapy.all import get_if_list; print(get_if_list())"
LOOPBACK_INTERFACE = "Npcap Loopback Adapter"  # adjust to match your machine