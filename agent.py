"""
Project Necromancer — Local Agent
-----------------------------------
This is the ONLY piece that touches your real network interface, firewall,
and processes. It never gets deployed to a public host. Run it on whichever
machine you actually want monitored.

Drop this file into the ROOT of your existing project (same level as
brain/, automation/, config.py) so the imports below resolve, OR adjust
the import paths to match wherever you keep those modules.

Flow:
  1. Detect a crash/incident the same way your dashboard's Forensic Vault
     did manually — but automatically, by watching the data/ folder.
  2. Run rule_check + query_local_ai, exactly as before.
  3. Call apply_remediation() locally, so every existing safety gate
     (confidence threshold, consensus check, target validation, cooldown,
     denylist, DRY_RUN) still applies before anything is even proposed.
  4. If it comes back STAGED (needs approval), POST it to the public
     server instead of waiting for a local Streamlit click.
  5. Poll the server; when a human approves it on the website, call
     apply_remediation() again locally with override_approval=True.
  6. Report the result back to the server for the audit log.
"""

import os
import sys
import time
import json
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- adjust these two imports to match your real project layout ---
from brain.signatures import rule_check, CAUSE_TO_ACTION
from brain.ai_analyst import query_local_ai
from brain.parser import condense_crash_data
from config import ACTIVE_INTERFACE
from automation.action_center import apply_remediation
# ---------------------------------------------------------------------

SERVER_URL = os.environ.get("NECROMANCER_SERVER_URL", "http://localhost:8000")
AGENT_API_KEY = os.environ.get("NECROMANCER_AGENT_KEY", "")
AGENT_ID = os.environ.get("NECROMANCER_AGENT_ID", "default-agent")
CRASH_DIR = "data"
POLL_INTERVAL_SECS = 5

if not AGENT_API_KEY:
    raise RuntimeError("Set NECROMANCER_AGENT_KEY (must match the server's env var).")

HEADERS = {"X-Agent-Key": AGENT_API_KEY}

# incident_id (server) -> {ai_action, rule_action, ai_confidence, target}
# so we know exactly what to re-run once approval comes back.
PENDING = {}
SEEN_FILES = set()


def _explanation_for(cause):
    explanations = {
        "DDOS_ATTACK": "A single source is flooding this machine with requests.",
        "RESOURCE_EXHAUSTION": "One process is consuming most of the CPU.",
        "INTERFACE_DROP": "The network interface dropped unexpectedly.",
    }
    return explanations.get(cause, "Unrecognized incident pattern.")


def scan_for_new_crashes():
    if not os.path.exists(CRASH_DIR):
        return []
    new_files = []
    for f in os.listdir(CRASH_DIR):
        if f.endswith(".json") and f not in SEEN_FILES:
            SEEN_FILES.add(f)
            new_files.append(os.path.join(CRASH_DIR, f))
    return new_files


def handle_crash_file(filepath):
    profile = condense_crash_data(filepath)
    sig_hint = rule_check(profile, active_interface=ACTIVE_INTERFACE)
    rule_action = CAUSE_TO_ACTION.get(sig_hint["cause"], "NONE")

    ai_res = query_local_ai(profile, sig_hint)
    ai_action = ai_res["mapped_action"]
    ai_confidence = ai_res["confidence_score"]
    target = sig_hint["target"]

    # Every existing safety gate runs right here, locally, before the
    # server ever hears about this incident.
    status = apply_remediation(ai_action, rule_action, ai_confidence, target,
                                runtime_mode="Approval Required")
    print(f"[agent] {filepath} -> {status}")

    if not status.startswith("STAGED"):
        # Already resolved locally (blocked, no-op, or auto-passed) —
        # nothing for a human to approve on the website.
        return

    try:
        resp = requests.post(
            f"{SERVER_URL}/api/agent/incidents",
            headers=HEADERS,
            json={
                "agent_id": AGENT_ID,
                "cause": sig_hint["cause"],
                "explanation": _explanation_for(sig_hint["cause"]),
                "ai_action": ai_action,
                "rule_action": rule_action,
                "ai_confidence": ai_confidence,
                "target": target,
            },
            timeout=10,
        )
        resp.raise_for_status()
        incident_id = resp.json()["incident_id"]
        PENDING[incident_id] = {
            "ai_action": ai_action,
            "rule_action": rule_action,
            "ai_confidence": ai_confidence,
            "target": target,
        }
        print(f"[agent] Submitted incident {incident_id} for remote approval.")
    except requests.RequestException as e:
        print(f"[agent] WARNING: could not reach server ({e}); action stays staged locally only.")


def poll_for_approvals():
    if not PENDING:
        return
    try:
        resp = requests.get(
            f"{SERVER_URL}/api/agent/poll",
            headers=HEADERS,
            params={"agent_id": AGENT_ID},
            timeout=10,
        )
        resp.raise_for_status()
        approved = resp.json()
    except requests.RequestException as e:
        print(f"[agent] WARNING: poll failed ({e})")
        return

    for incident in approved:
        incident_id = incident["id"]
        params = PENDING.pop(incident_id, None)
        if not params:
            continue

        result = apply_remediation(
            params["ai_action"], params["rule_action"], params["ai_confidence"],
            params["target"], runtime_mode="Approval Required", override_approval=True,
        )
        print(f"[agent] Executed approved incident {incident_id}: {result}")

        status = "FAILED" if "FAILURE" in result or "FAILED" in result else "EXECUTED"
        try:
            requests.post(
                f"{SERVER_URL}/api/agent/report",
                headers=HEADERS,
                json={"incident_id": incident_id, "status": status, "message": result},
                timeout=10,
            )
        except requests.RequestException as e:
            print(f"[agent] WARNING: could not report result ({e})")


def main():
    print(f"[agent] Starting. Server={SERVER_URL} Agent ID={AGENT_ID}")
    while True:
        for f in scan_for_new_crashes():
            handle_crash_file(f)
        poll_for_approvals()
        time.sleep(POLL_INTERVAL_SECS)


if __name__ == "__main__":
    main()
