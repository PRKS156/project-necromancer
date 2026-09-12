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

    top_talkers = Counter(src_ips).most_common(3)
    proto_distribution = Counter(protocols).most_common()

    avg_cpu = sum(m["cpu_percent"] for m in metrics) / max(len(metrics), 1)
    avg_recv = sum(m["mb_recv_per_sec"] for m in metrics) / max(len(metrics), 1)

    return {
        "incident_time": data["metadata"]["crash_time"],
        "total_captured_packets": len(packets),
        "top_offending_sources": top_talkers,
        "flood_total_packets": len(flood_packets),
        "flood_top_offending_sources": flood_top_talkers,
        "protocol_mix": proto_distribution,
        "avg_cpu_utilization": round(avg_cpu, 2),
        "avg_bandwidth_recv_mbps": round(avg_recv, 2)
    }