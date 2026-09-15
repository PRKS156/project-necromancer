import sys
import os
import psutil

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from brain.signatures import rule_check
from automation.action_center import (
    apply_remediation,
    rollback_last_action,
    reset_system_state,
    validate_target,
    _select_highest_cpu_process,
)


class MockProcess:
    def __init__(self, pid, name, cpu_val):
        self.info = {'pid': pid, 'name': name}
        self._cpu_val = cpu_val

    def cpu_percent(self, interval=None):
        return self._cpu_val


def setup_function():
    reset_system_state()


# ── Rule Engine Tests ────────────────────────────────────────────

def test_rule_engine_ddos_port53():
    """DDoS detected via the port-53 specific flood path."""
    setup_function()
    mock_profile = {
        "total_captured_packets": 1500,
        "top_offending_sources": [("192.168.1.105", 1200)],
        "top_talker_avg_size": 128,
        "flood_total_packets": 1200,
        "flood_top_offending_sources": [("192.168.1.105", 1200)],
        "avg_cpu_utilization": 40.0,
        "icmp_total_packets": 0,
        "max_unique_dports_per_ip": 1,
        "scan_packets_per_port": 1200.0,
    }
    res = rule_check(mock_profile, active_interface="Wi-Fi")
    assert res["cause"] == "DDOS_ATTACK"
    print("[PASS] Test 1: Rule engine isolates a DDoS attack (port-53 flood path).")


def test_rule_engine_ddos_generic():
    """DDoS detected via the generic any-port flood path with small packets."""
    setup_function()
    mock_profile = {
        "total_captured_packets": 2000,
        "top_offending_sources": [("10.0.0.5", 1800)],
        "top_talker_avg_size": 100,
        "flood_total_packets": 0,
        "flood_top_offending_sources": [],
        "avg_cpu_utilization": 40.0,
        "icmp_total_packets": 0,
        "max_unique_dports_per_ip": 1,
        "scan_packets_per_port": 1800.0,
    }
    res = rule_check(mock_profile, active_interface="Wi-Fi")
    assert res["cause"] == "DDOS_ATTACK"
    print("[PASS] Test 2: Rule engine isolates a generic DDoS attack (small packets).")


def test_ddos_false_positive_large_download():
    """A single IP with large packets (file download) should NOT trigger DDoS."""
    setup_function()
    mock_profile = {
        "total_captured_packets": 2000,
        "top_offending_sources": [("10.0.0.5", 1800)],
        "top_talker_avg_size": 1400,
        "flood_total_packets": 0,
        "flood_top_offending_sources": [],
        "avg_cpu_utilization": 40.0,
        "icmp_total_packets": 0,
        "max_unique_dports_per_ip": 1,
        "scan_packets_per_port": 1800.0,
    }
    res = rule_check(mock_profile, active_interface="Wi-Fi")
    assert res["cause"] != "DDOS_ATTACK", f"False positive! Got {res['cause']}"
    print("[PASS] Test 3: Large-packet file download does NOT trigger DDoS (false positive guard).")


def test_rule_engine_icmp_flood():
    """ICMP flood detected when ICMP packet count exceeds threshold."""
    setup_function()
    mock_profile = {
        "total_captured_packets": 500,
        "top_offending_sources": [("192.168.1.200", 250)],
        "top_talker_avg_size": 64,
        "flood_total_packets": 0,
        "flood_top_offending_sources": [],
        "avg_cpu_utilization": 30.0,
        "icmp_total_packets": 250,
        "max_unique_dports_per_ip": 0,
        "scan_packets_per_port": 999,
    }
    res = rule_check(mock_profile, active_interface="Wi-Fi")
    assert res["cause"] == "ICMP_FLOOD"
    print("[PASS] Test 4: Rule engine isolates an ICMP flood.")


def test_rule_engine_port_scan():
    """Port scan detected when many unique ports are hit with few packets per port."""
    setup_function()
    mock_profile = {
        "total_captured_packets": 100,
        "top_offending_sources": [("192.168.1.50", 100)],
        "top_talker_avg_size": 40,
        "flood_total_packets": 0,
        "flood_top_offending_sources": [],
        "avg_cpu_utilization": 10.0,
        "icmp_total_packets": 0,
        "max_unique_dports_per_ip": 100,
        "scan_packets_per_port": 1.0,
    }
    res = rule_check(mock_profile, active_interface="Wi-Fi")
    assert res["cause"] == "PORT_SCAN"
    print("[PASS] Test 5: Rule engine isolates a port scan.")


def test_port_scan_false_positive_p2p():
    """P2P traffic (many ports but lots of packets per port) should NOT trigger port scan."""
    setup_function()
    mock_profile = {
        "total_captured_packets": 5000,
        "top_offending_sources": [("192.168.1.50", 5000)],
        "top_talker_avg_size": 1200,
        "flood_total_packets": 0,
        "flood_top_offending_sources": [],
        "avg_cpu_utilization": 25.0,
        "icmp_total_packets": 0,
        "max_unique_dports_per_ip": 50,
        "scan_packets_per_port": 100.0,
    }
    res = rule_check(mock_profile, active_interface="Wi-Fi")
    assert res["cause"] != "PORT_SCAN", f"False positive! Got {res['cause']}"
    print("[PASS] Test 6: P2P traffic does NOT trigger port scan (false positive guard).")


def test_rule_engine_resource_exhaustion():
    """Resource exhaustion detected when CPU is critically high."""
    setup_function()
    mock_profile = {
        "total_captured_packets": 50,
        "top_offending_sources": [("192.168.1.10", 50)],
        "top_talker_avg_size": 500,
        "flood_total_packets": 0,
        "flood_top_offending_sources": [],
        "avg_cpu_utilization": 96.5,
        "icmp_total_packets": 0,
        "max_unique_dports_per_ip": 1,
        "scan_packets_per_port": 50.0,
    }
    res = rule_check(mock_profile, active_interface="Wi-Fi")
    assert res["cause"] == "RESOURCE_EXHAUSTION"
    print("[PASS] Test 7: Rule engine isolates resource exhaustion.")


# ── Remediation Safety Tests ─────────────────────────────────────

def test_interface_name_space_validation():
    """Mocks the interface list instead of relying on whatever adapters
    happen to exist on the machine running this test — otherwise this
    test is silently machine-dependent and fails in CI or on Linux."""
    setup_function()
    fake_stats = {
        "Local Area Connection": None,
        "Wi-Fi 2": None,
        "eth0": None,
    }
    original = psutil.net_if_stats
    psutil.net_if_stats = lambda: fake_stats
    try:
        assert validate_target("Local Area Connection") is True
        assert validate_target("Wi-Fi 2") is True
        assert validate_target("Ethernet; rm -rf /") is False
        print("[PASS] Test 8: Target validation allows real adapter names, blocks injection.")
    finally:
        psutil.net_if_stats = original


def test_low_ai_confidence_gate():
    setup_function()
    res = apply_remediation("BLOCK_IP", "BLOCK_IP", 0.60, "192.168.1.1",
                             runtime_mode="Active Automation")
    assert "SAFETY ABORT" in res
    print("[PASS] Test 9: Low AI confidence blocks execution.")


def test_confidence_ok_but_consensus_disagrees():
    setup_function()
    res = apply_remediation("BLOCK_IP", "RESTART_NIC", 0.95, "192.168.1.44",
                             runtime_mode="Active Automation")
    assert "CRITICAL CONFLICT GATED" in res
    print("[PASS] Test 10: Consensus disagreement blocks execution despite high confidence.")


def test_destructive_action_categorical_override():
    setup_function()
    # Must stage regardless of runtime_mode — this is the real check,
    # not a string match against one specific mode value.
    res = apply_remediation("OPTIMIZE_RESOURCES", "OPTIMIZE_RESOURCES", 0.90,
                             "runaway_process", runtime_mode="Active Automation")
    assert "STAGED" in res
    print("[PASS] Test 11: OPTIMIZE_RESOURCES always stages for approval, any runtime_mode.")


def test_process_selector_denylist_isolation():
    """Calls the real selection function directly — no need to smuggle
    a fake runtime_mode past the approval gate to reach it."""
    mock_processes = [
        MockProcess(555, "python.exe", 70.0),        # denylisted
        MockProcess(111, "explorer.exe", 95.0),       # denylisted, highest CPU
        MockProcess(888, "malicious_miner", 80.0),     # valid target
    ]
    original_iter = psutil.process_iter
    psutil.process_iter = lambda attrs=None: mock_processes
    try:
        target_pid = _select_highest_cpu_process()
        assert target_pid == 888, f"expected 888, got {target_pid}"
        print("[PASS] Test 12: Process selector skips denylisted processes, picks the real threat.")
    finally:
        psutil.process_iter = original_iter


def test_override_approval_releases_staged_action():
    """Proves the human-in-the-loop release path actually works: a
    force-approval action stages first, then clears ONLY when
    override_approval=True is passed explicitly — not via any
    runtime_mode string trick."""
    setup_function()
    staged = apply_remediation("OPTIMIZE_RESOURCES", "OPTIMIZE_RESOURCES", 0.90,
                                "runaway_process", runtime_mode="Active Automation")
    assert "STAGED" in staged

    # A runtime_mode string alone must NOT bypass the gate.
    still_staged = apply_remediation("OPTIMIZE_RESOURCES", "OPTIMIZE_RESOURCES", 0.90,
                                      "runaway_process", runtime_mode="Override Approved")
    assert "STAGED" in still_staged

    # Only the explicit override flag releases it.
    released = apply_remediation("OPTIMIZE_RESOURCES", "OPTIMIZE_RESOURCES", 0.90,
                                  "runaway_process", runtime_mode="Approval Required",
                                  override_approval=True)
    assert "STAGED" not in released
    print("[PASS] Test 13: override_approval=True is the only thing that releases a staged action.")


def test_cooldown_rate_limiter():
    setup_function()
    res1 = apply_remediation("BLOCK_IP", "BLOCK_IP", 0.95, "10.0.0.10",
                              runtime_mode="Active Automation")
    res2 = apply_remediation("BLOCK_IP", "BLOCK_IP", 0.95, "10.0.0.11",
                              runtime_mode="Active Automation")
    assert "SUCCESS" in res1
    assert "SAFETY ABORT" in res2
    print("[PASS] Test 14: Cooldown blocks a second action fired within the window.")


def test_rollback_pops_and_reports():
    setup_function()
    apply_remediation("BLOCK_IP", "BLOCK_IP", 0.90, "10.0.0.1", runtime_mode="Active Automation")
    res = rollback_last_action()
    assert "ROLLBACK SUCCESS" in res
    res_empty = rollback_last_action()
    assert "empty" in res_empty
    print("[PASS] Test 15: Rollback pops correctly and reports an empty log honestly.")


if __name__ == "__main__":
    print("=== PROJECT NECROMANCER TEST SUITE ===\n")

    # Rule engine tests
    test_rule_engine_ddos_port53()
    test_rule_engine_ddos_generic()
    test_ddos_false_positive_large_download()
    test_rule_engine_icmp_flood()
    test_rule_engine_port_scan()
    test_port_scan_false_positive_p2p()
    test_rule_engine_resource_exhaustion()

    # Remediation safety tests
    test_interface_name_space_validation()
    test_low_ai_confidence_gate()
    test_confidence_ok_but_consensus_disagrees()
    test_destructive_action_categorical_override()
    test_process_selector_denylist_isolation()
    test_override_approval_releases_staged_action()
    test_cooldown_rate_limiter()
    test_rollback_pops_and_reports()

    print("\n=== ALL 15 TESTS PASSED ===")