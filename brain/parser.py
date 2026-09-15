import json
from collections import Counter

def condense_crash_data(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)

    packets = data.get("packet_history", [])
    metrics = data.get("system_metrics_history", [])

    # Isolate traffic specifically hitting port 53 -- this is the port
    # stress_test.py always targets, so filtering here cuts through
    # unrelated background noise (Windows services, other devices,
    # cloud sync, etc.) that a busy network naturally has.
    flood_packets = [p for p in packets if p.get("dport") == 53]
    flood_top_talkers = Counter(p["src"] for p in flood_packets).most_common(3)

    src_ips = [p["src"] for p in packets]
    protocols = [p["protocol"] for p in packets]

    # ICMP tracking
    icmp_packets = [p for p in packets if p.get("protocol") == "ICMP"]
    icmp_total_packets = len(icmp_packets)
    
    # Port scan tracking (unique dports per source IP)
    ports_by_src = {}
    packets_by_src = {}
    for p in packets:
        ip = p["src"]
        dport = p.get("dport", 0)
        if dport > 0:
            if ip not in ports_by_src:
                ports_by_src[ip] = set()
                packets_by_src[ip] = 0
            ports_by_src[ip].add(dport)
            packets_by_src[ip] += 1
            
    max_unique_dports = 0
    scan_packets_per_port = 999
    if ports_by_src:
        for ip, ports in ports_by_src.items():
            if len(ports) > max_unique_dports:
                max_unique_dports = len(ports)
                scan_packets_per_port = packets_by_src[ip] / len(ports)

    top_talkers = Counter(src_ips).most_common(3)
    
    top_talker_avg_size = 0
    if top_talkers:
        top_ip = top_talkers[0][0]
        top_packets = [p for p in packets if p.get("src") == top_ip]
        if top_packets:
            top_talker_avg_size = sum(p.get("size", 0) for p in top_packets) / len(top_packets)

    proto_distribution = Counter(protocols).most_common()

    avg_cpu = sum(m["cpu_percent"] for m in metrics) / max(len(metrics), 1)
    avg_recv = sum(m["mb_recv_per_sec"] for m in metrics) / max(len(metrics), 1)

    return {
        "incident_time": data["metadata"]["crash_time"],
        "total_captured_packets": len(packets),
        "top_offending_sources": top_talkers,
        "top_talker_avg_size": top_talker_avg_size,
        "flood_total_packets": len(flood_packets),
        "flood_top_offending_sources": flood_top_talkers,
        "protocol_mix": proto_distribution,
        "avg_cpu_utilization": round(avg_cpu, 2),
        "avg_bandwidth_recv_mbps": round(avg_recv, 2),
        "icmp_total_packets": icmp_total_packets,
        "max_unique_dports_per_ip": max_unique_dports,
        "scan_packets_per_port": round(scan_packets_per_port, 2)
    }