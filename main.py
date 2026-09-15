import time
import os
from config import ACTIVE_INTERFACE
from core.buffer_manager import NetworkBuffer
from core.sniffer import AsyncSniffer
from core.metrics import MetricsCollector
from brain.parser import condense_crash_data
from brain.signatures import rule_check, CAUSE_TO_ACTION
from brain.ai_analyst import query_local_ai
from automation.action_center import apply_remediation

LIVE_WATCHDOG_MIN_SAMPLE = 1500
LIVE_WATCHDOG_DOMINANCE_RATIO = 0.7
STARTUP_GRACE_PERIOD_SECS = 10  # ignore the watchdog for the first 10 seconds after launch

def check_file_trigger():
    return os.path.exists("trigger_crash.txt")


def check_live_anomalies(buf):
    # Network anomalies
    recent_packets = buf.get_recent_packets(LIVE_WATCHDOG_MIN_SAMPLE)
    if len(recent_packets) >= LIVE_WATCHDOG_MIN_SAMPLE:
        src_ips = [p["src"] for p in recent_packets]
        if src_ips:
            top_ip = max(set(src_ips), key=src_ips.count)
            top_count = src_ips.count(top_ip)
            if (top_count / len(recent_packets)) > LIVE_WATCHDOG_DOMINANCE_RATIO:
                # DDoS Check Refinement: Ignore large file uploads
                attacker_packets = [p for p in recent_packets if p["src"] == top_ip]
                avg_size = sum(p.get("size", 0) for p in attacker_packets) / max(len(attacker_packets), 1)
                if avg_size < 500:
                    print(f"[WATCHDOG] DDoS anomaly detected from {top_ip} (Avg Size: {avg_size:.1f}b)")
                    return True
        
        # ICMP Flood Check
        icmp_count = sum(1 for p in recent_packets if p.get("protocol") == "ICMP")
        if icmp_count > 100:
            print("[WATCHDOG] ICMP flood anomaly detected")
            return True
            
        # Port Scan Check Refinement
        port_scan_stats = {}
        for p in recent_packets:
            ip = p["src"]
            dport = p.get("dport", 0)
            if dport > 0:
                if ip not in port_scan_stats:
                    port_scan_stats[ip] = {"ports": set(), "count": 0}
                port_scan_stats[ip]["ports"].add(dport)
                port_scan_stats[ip]["count"] += 1
        
        for ip, stats in port_scan_stats.items():
            num_ports = len(stats["ports"])
            if num_ports > 20:
                packets_per_port = stats["count"] / num_ports
                if packets_per_port < 5:
                    print(f"[WATCHDOG] Port scan anomaly detected from {ip} (Pkt/Port: {packets_per_port:.1f})")
                    return True

    # Resource Exhaustion Check
    recent_metrics = buf.get_recent_metrics(10)
    if len(recent_metrics) >= 5:
        avg_cpu = sum(m.get("cpu_percent", 0) for m in recent_metrics) / len(recent_metrics)
        if avg_cpu > 90.0:
            print(f"[WATCHDOG] Resource exhaustion anomaly detected: CPU at {avg_cpu:.1f}%")
            return True

    return False


def main():
    print("=== INITIALIZING PROJECT NECROMANCER ENGINE ===")
    print(f"[RUNNING] Capturing on interface: {ACTIVE_INTERFACE}")
    print("[INFO] Two ways to trigger a crash for this demo:")
    print("  1) Controlled: create a blank file named 'trigger_crash.txt' here.")
    print("  2) Live: run stress_test.py in another terminal to flood this machine for real.")

    buf = None
    sniffer = None
    metrics = None

    try:
        while True:
            # (Re)initialize subsystems for a fresh monitoring cycle
            if buf is None:
                buf = NetworkBuffer()
                sniffer = AsyncSniffer(buf, interface_name=ACTIVE_INTERFACE)
                metrics = MetricsCollector(buf)
                sniffer.start()
                metrics.start()
                engine_start_time = time.time()
                print("[RUNNING] Queues operational. Monitoring for anomalies...")

            time.sleep(2)

            past_grace_period = (time.time() - engine_start_time) > STARTUP_GRACE_PERIOD_SECS
            crash_triggered = check_file_trigger()

            if past_grace_period and not crash_triggered:
                crash_triggered = check_live_anomalies(buf)

            if crash_triggered:
                print("\n[ALERT] CRASH DETECTED. FREEZING RECORDER SUBSYSTEMS...")
                sniffer.stop()
                metrics.stop()

                dump_path = buf.freeze_and_flush()
                print(f"[SUCCESS] Flight data written to vault: {dump_path}")

                profile = condense_crash_data(dump_path)
                sig_hint = rule_check(profile, active_interface=ACTIVE_INTERFACE)
                rule_action = CAUSE_TO_ACTION.get(sig_hint["cause"], "NONE")

                print("[AI BRAIN] Consulting offline AI root cause reasoning cluster...")
                ai_res = query_local_ai(profile, sig_hint)

                print("\n=== SYSTEM INFERENCE DIAGNOSTIC OUTPUT ===")
                print(f"Isolated Cause: {ai_res['root_cause']}")
                print(f"Confidence Factor: {ai_res['confidence_score'] * 100}%")
                print(f"Mitigation Instruction: {ai_res['mapped_action']}")
                print("==========================================\n")

                status = apply_remediation(
                    ai_action=ai_res['mapped_action'],
                    rule_action=rule_action,
                    ai_confidence=ai_res['confidence_score'],
                    target_entity=sig_hint["target"],
                    runtime_mode="Active Automation"
                )
                print(f"[REPAIR STATUS] {status}")

                if os.path.exists("trigger_crash.txt"):
                    os.remove("trigger_crash.txt")

                # Reset subsystems so the engine restarts monitoring
                buf = None
                sniffer = None
                metrics = None
                print("\n[RECOVERY] Engine restarting monitoring cycle...\n")

    except KeyboardInterrupt:
        if sniffer:
            sniffer.stop()
        if metrics:
            metrics.stop()
        print("\n[SHUTDOWN] Engine stopped by user.")


if __name__ == "__main__":
    main()