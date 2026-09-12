import time
import platform
import subprocess
import ipaddress
import psutil
import os

DRY_RUN = True
MIN_AI_CONFIDENCE = 0.75
COOLDOWN_INTERVAL_SECS = 60
FORCE_APPROVAL_ACTIONS = {"OPTIMIZE_RESOURCES"}

CRITICAL_PROCESS_DENYLIST = [
    "systemd", "explorer.exe", "init", "kernel_task", "svchost.exe",
    "lsass.exe", "services.exe", "launchd", "python", "python3",
    "cmd.exe", "powershell.exe", "bash", "ssh", "sshd",
]

LAST_REMEDIATION_TIME = 0
REMEDIATION_HISTORY_LOG = []


def validate_target(target):
    if target in ("localhost", "adapter", "runaway_process"):
        return True
    if target.isalnum():
        return True
    try:
        if target in psutil.net_if_stats().keys():
            return True
    except Exception:
        pass
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _select_highest_cpu_process():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    time.sleep(0.1)

    highest_pid = 0
    max_cpu = 0.0
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            if not name or pid == os.getpid():
                continue
            if any(denied in name.lower() for denied in CRITICAL_PROCESS_DENYLIST):
                continue
            current_cpu = proc.cpu_percent(interval=None)
            if current_cpu > max_cpu:
                max_cpu = current_cpu
                highest_pid = pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return highest_pid


def apply_remediation(ai_action, rule_action, ai_confidence, target_entity,
                       runtime_mode="Approval Required", override_approval=False):
    global LAST_REMEDIATION_TIME
    current_time = time.time()

    if ai_confidence < MIN_AI_CONFIDENCE:
        reason = f"AI confidence ({ai_confidence}) below safety threshold ({MIN_AI_CONFIDENCE})"
        REMEDIATION_HISTORY_LOG.append({"status": "BLOCKED", "reason": reason, "timestamp": current_time})
        return f"SAFETY ABORT: {reason}"

    if ai_action != rule_action:
        reason = f"Consensus failure: AI proposed {ai_action}, rule proposed {rule_action}"
        REMEDIATION_HISTORY_LOG.append({"status": "BLOCKED", "reason": reason, "timestamp": current_time})
        return f"CRITICAL CONFLICT GATED: {reason}"

    if ai_action == "NONE":
        return "Passive State Preserved: No mitigation protocol required."

    if not validate_target(target_entity):
        reason = f"Suspicious target entity rejected: {target_entity}"
        REMEDIATION_HISTORY_LOG.append({"status": "REJECTED", "reason": reason, "timestamp": current_time})
        return f"SECURITY DEFENSE BLOCK: {reason}"

    if (current_time - LAST_REMEDIATION_TIME) < COOLDOWN_INTERVAL_SECS:
        reason = "Anti-thrashing guard active (system in cooldown)."
        REMEDIATION_HISTORY_LOG.append({"status": "BLOCKED", "reason": reason, "timestamp": current_time})
        return f"SAFETY ABORT: {reason}"

    if ai_action in FORCE_APPROVAL_ACTIONS and not override_approval:
        return (f"STAGED: Action [{ai_action}] is categorically high-risk and "
                f"always requires manual approval.")

    if runtime_mode == "Approval Required" and not override_approval:
        return f"STAGED: Action [{ai_action}] verified by consensus. Waiting for manual approval."

    os_type = platform.system()
    commands_list = []
    undo_commands_list = []

    if ai_action == "BLOCK_IP":
        if os_type == "Windows":
            commands_list.append(["netsh", "advfirewall", "firewall", "add", "rule",
                                   "name=Necromancer Drop", "dir=in", "action=block",
                                   f"remoteip={target_entity}"])
            undo_commands_list.append(["netsh", "advfirewall", "firewall", "delete", "rule",
                                        "name=Necromancer Drop", f"remoteip={target_entity}"])
        elif os_type == "Linux":
            commands_list.append(["sudo", "iptables", "-A", "INPUT", "-s", target_entity, "-j", "DROP"])
            undo_commands_list.append(["sudo", "iptables", "-D", "INPUT", "-s", target_entity, "-j", "DROP"])

    elif ai_action == "RESTART_NIC":
        if os_type == "Windows":
            commands_list.append(["powershell", "-Command",
                                   f"Restart-NetAdapter -Name '{target_entity}' -Confirm:$false"])
        elif os_type == "Linux":
            commands_list.append(["sudo", "ip", "link", "set", "dev", target_entity, "down"])
            commands_list.append(["sudo", "ip", "link", "set", "dev", target_entity, "up"])
        undo_commands_list.append(["NO_OP", "Adapter bounce has no separate undo step."])

    elif ai_action == "OPTIMIZE_RESOURCES":
        highest_pid = _select_highest_cpu_process()
        if highest_pid > 0:
            if os_type == "Windows":
                commands_list.append(["taskkill", "/F", "/PID", str(highest_pid)])
            else:
                commands_list.append(["sudo", "kill", "-9", str(highest_pid)])
            undo_commands_list.append(["NO_OP", "Terminated processes cannot be rolled back."])

    if not commands_list:
        return f"EXECUTION REJECTION: No command mapping exists for {ai_action} on {os_type}"

    LAST_REMEDIATION_TIME = current_time

    try:
        record = {
            "action": ai_action, "target": target_entity, "rollback_payload": undo_commands_list,
            "timestamp": current_time, "mode": "DRY_RUN" if DRY_RUN else "LIVE_DEPLOYED",
        }

        if DRY_RUN:
            REMEDIATION_HISTORY_LOG.append(record)
            flat_cmds = " | ".join(" ".join(c) for c in commands_list)
            return f"DRY-RUN SUCCESS: would execute: [{flat_cmds}]"

        for cmd in commands_list:
            subprocess.run(cmd, shell=False, check=True)

        REMEDIATION_HISTORY_LOG.append(record)
        return f"LIVE DEPLOYED SUCCESS: completed {len(commands_list)} step(s)."
    except Exception as e:
        return f"EXECUTION FAILURE: {str(e)}"


def rollback_last_action():
    if not REMEDIATION_HISTORY_LOG:
        return "Rollback aborted: remediation history is empty."

    for i in range(len(REMEDIATION_HISTORY_LOG) - 1, -1, -1):
        log = REMEDIATION_HISTORY_LOG[i]
        undo_list = log.get("rollback_payload")
        if not undo_list:
            continue

        if undo_list[0][0] == "NO_OP":
            REMEDIATION_HISTORY_LOG.pop(i)
            return f"NO-OP: {undo_list[0][1]}"

        is_dry = log.get("mode") == "DRY_RUN"
        try:
            if is_dry:
                REMEDIATION_HISTORY_LOG.pop(i)
                flat = " | ".join(" ".join(u) for u in undo_list)
                return f"DRY-RUN ROLLBACK SUCCESS: would execute: [{flat}]"

            for undo_cmd in undo_list:
                subprocess.run(undo_cmd, shell=False, check=True)
            REMEDIATION_HISTORY_LOG.pop(i)
            return "LIVE ROLLBACK SUCCESS: step(s) reversed."
        except Exception as e:
            return f"ROLLBACK FAILED: {str(e)}"

    return "No reversible actions found in history logs."


def get_remediation_history():
    return REMEDIATION_HISTORY_LOG


def reset_system_state():
    global LAST_REMEDIATION_TIME
    LAST_REMEDIATION_TIME = 0
    REMEDIATION_HISTORY_LOG.clear()