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
    recent_packets = list(buf.packet_buffer)[-LIVE_WATCHDOG_MIN_SAMPLE:]
    if len(recent_packets) >= LIVE_WATCHDOG_MIN_SAMPLE:
        src_ips = [p["src"] for p in recent_packets]
        if src_ips:
            top_ip = max(set(src_ips), key=src_ips.count)
            top_count = src_ips.count(top_ip)
            if (top_count / len(recent_packets)) > LIVE_WATCHDOG_DOMINANCE_RATIO:
                print(f"[WATCHDOG] DDoS anomaly detected from {top_ip}")
                return True
        
        # ICMP Flood Check
        icmp_count = sum(1 for p in recent_packets if p.get("protocol") == "ICMP")
        if icmp_count > 100:
            print("[WATCHDOG] ICMP flood anomaly detected")
            return True
            
        # Port Scan Check
        ports_by_src = {}
        for p in recent_packets:
            ip = p["src"]
            dport = p.get("dport", 0)
            if dport > 0:
                if ip not in ports_by_src:
                    ports_by_src[ip] = set()
                ports_by_src[ip].add(dport)
        
        for ip, ports in ports_by_src.items():
            if len(ports) > 20:
                print(f"[WATCHDOG] Port scan anomaly detected from {ip}")
                return True

    # Resource Exhaustion Check
    recent_metrics = list(buf.metric_buffer)[-10:]
    if len(recent_metrics) >= 5:
        avg_cpu = sum(m.get("cpu_percent", 0) for m in recent_metrics) / len(recent_metrics)
        if avg_cpu > 90.0:
            print(f"[WATCHDOG] Resource exhaustion anomaly detected: CPU at {avg_cpu:.1f}%")
            return True

    return False


def main():
    print("=== INITIALIZING PROJECT NECROMANCER ENGINE ===")
    buf = NetworkBuffer()

    sniffer = AsyncSniffer(buf, interface_name=ACTIVE_INTERFACE)
    metrics = MetricsCollector(buf)

    sniffer.start()
    metrics.start()
    print(f"[RUNNING] Queues operational. Capturing on interface: {ACTIVE_INTERFACE}")
    print("[INFO] Two ways to trigger a crash for this demo:")
    print("  1) Controlled: create a blank file named 'trigger_crash.txt' here.")
    print("  2) Live: run stress_test.py in another terminal to flood this machine for real.")
    engine_start_time = time.time()
    try:
        while True:
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
                break
    except KeyboardInterrupt:
        sniffer.stop()
        metrics.stop()


if __name__ == "__main__":
    main()