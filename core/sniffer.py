import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP

class AsyncSniffer(threading.Thread):
    def __init__(self, buffer_manager, interface_name="Wi-Fi"):
        super().__init__()
        self.buffer_manager = buffer_manager
        self.interface_name = interface_name # Fixed: Single shared source of truth parameter
        self.daemon = True  
        self.running = False

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = "OTHER"
            sport, dport = 0, 0
            
            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            elif ICMP in packet:
                proto = "ICMP"
                sport = 0
                dport = 0

            summary = {
                "src": src_ip,
                "dst": dst_ip,
                "protocol": proto,
                "sport": sport,
                "dport": dport,
                "size": len(packet)
            }
            self.buffer_manager.log_packet(summary)

    def run(self):
        self.running = True
        sniff(iface=self.interface_name, prn=self.packet_callback, store=0, stop_filter=lambda p: not self.running)

    def stop(self):
        self.running = False
