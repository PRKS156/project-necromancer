import psutil

CAUSE_TO_ACTION = {
    "DDOS_ATTACK": "BLOCK_IP",
    "PORT_SCAN": "BLOCK_IP",
    "ICMP_FLOOD": "BLOCK_IP",
    "RESOURCE_EXHAUSTION": "OPTIMIZE_RESOURCES",
    "INTERFACE_DROP": "RESTART_NIC",
    "UNKNOWN_ANOMALY": "NONE",
}

def rule_check(profile, active_interface="Wi-Fi"):
    flood_total = profile.get("flood_total_packets", 0)

    for ip, count in profile.get("flood_top_offending_sources", []):
        if flood_total > 500 and (count / flood_total) > 0.7:
            return {"status": "CRITICAL", "cause": "DDOS_ATTACK", "target": ip}

    if profile.get("avg_cpu_utilization", 0) > 90.0:
        return {"status": "CRITICAL", "cause": "RESOURCE_EXHAUSTION", "target": "runaway_process"}

    if profile.get("icmp_total_packets", 0) > 100:
        top_talkers = profile.get("top_offending_sources", [])
        target_ip = top_talkers[0][0] if top_talkers else "unknown_ip"
        return {"status": "CRITICAL", "cause": "ICMP_FLOOD", "target": target_ip}

    if profile.get("max_unique_dports_per_ip", 0) > 20:
        top_talkers = profile.get("top_offending_sources", [])
        target_ip = top_talkers[0][0] if top_talkers else "unknown_ip"
        return {"status": "CRITICAL", "cause": "PORT_SCAN", "target": target_ip}

    net_stats = psutil.net_if_stats()
    if active_interface in net_stats and not net_stats[active_interface].isup:
        return {"status": "CRITICAL", "cause": "INTERFACE_DROP", "target": active_interface}

    return {"status": "UNKNOWN", "cause": "UNKNOWN_ANOMALY", "target": "none"}