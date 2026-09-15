import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import json
import pandas as pd
from datetime import datetime

from config import ACTIVE_INTERFACE
from brain.signatures import rule_check, CAUSE_TO_ACTION
from brain.ai_analyst import query_local_ai, generate_incident_report
from brain.parser import condense_crash_data
from automation.action_center import apply_remediation, rollback_last_action

st.set_page_config(page_title="Project Necromancer Console", layout="wide")
st.title("Project Necromancer: Infrastructure Telemetry Control Room")

CRASH_DIR = "data"
if not os.path.exists(CRASH_DIR):
    os.makedirs(CRASH_DIR)

RULE_BOOK = {
    "DDOS_ATTACK": {
        "plain_explanation": (
            "Someone (or something) is sending an enormous number of fake requests "
            "from one source — like one person calling your phone 10,000 times a minute "
            "so real calls can never get through."
        ),
        "auto_remediation": "The system blocks that one troublemaker's address at the firewall.",
        "optimization_tips": [
            "Limit how many requests one visitor can send per second.",
            "Split traffic across multiple smaller checkpoints.",
            "Ignore traffic from unverified addresses."
        ]
    },
    "RESOURCE_EXHAUSTION": {
        "plain_explanation": (
            "Your computer's processor got so overloaded doing background work that "
            "it couldn't keep up anymore — like one waiter serving fifty tables alone."
        ),
        "auto_remediation": "The system finds the single program hogging the most CPU and shuts it down.",
        "optimization_tips": [
            "Close background programs you're not actively using.",
            "Clear out old temporary files.",
            "Spread heavy tasks across more threads."
        ]
    },
    "INTERFACE_DROP": {
        "plain_explanation": (
            "The actual cable or Wi-Fi connection dropped completely — "
            "like your phone suddenly losing all signal."
        ),
        "auto_remediation": "The system automatically turns the network adapter off and back on.",
        "optimization_tips": [
            "Check the physical cable or Wi-Fi signal.",
            "Clear your saved DNS cache.",
            "Confirm gateway settings haven't changed."
        ]
    }
}

st.sidebar.header("System Infrastructure Panel")
mode = st.sidebar.radio("Navigation Console",
                         ["Live Operational Telemetry", "Forensic Analysis Vault", "Troubleshooting Rule Book"])

st.sidebar.markdown("---")
st.sidebar.header("Incident Simulator Network")


def generate_mock_crash(incident_type, offending_ip="192.168.1.105"):
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(CRASH_DIR, f"crash_dump_{timestamp_str}.json")
    packets, metrics = [], []

    if incident_type == "DDOS_ATTACK":
        for _ in range(1200):
            packets.append({"src": offending_ip, "dst": "192.168.1.1", "protocol": "UDP",
                             "sport": 53, "dport": 53, "size": 512})
        metrics = [{"cpu_percent": 45.2, "memory_percent": 50.1,
                    "mb_sent_per_sec": 0.5, "mb_recv_per_sec": 48.2} for _ in range(30)]
    elif incident_type == "RESOURCE_EXHAUSTION":
        for _ in range(100):
            packets.append({"src": "192.168.1.50", "dst": "192.168.1.1", "protocol": "TCP",
                             "sport": 80, "dport": 80, "size": 128})
        metrics = [{"cpu_percent": 96.8, "memory_percent": 88.4,
                    "mb_sent_per_sec": 1.2, "mb_recv_per_sec": 1.5} for _ in range(30)]
    else:
        packets = [{"src": "192.168.1.10", "dst": "192.168.1.1", "protocol": "OTHER",
                    "sport": 0, "dport": 0, "size": 0}]
        metrics = [{"cpu_percent": 5.0, "memory_percent": 40.0,
                    "mb_sent_per_sec": 0.0, "mb_recv_per_sec": 0.0} for _ in range(30)]

    with open(filepath, "w") as f:
        json.dump({
            "metadata": {
                "crash_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_packets_captured": len(packets),
                "total_metrics_captured": len(metrics)
            },
            "packet_history": packets,
            "system_metrics_history": metrics
        }, f, indent=4)
    return filepath


if st.sidebar.button("Inject DDoS Flood Anomaly"):
    generate_mock_crash("DDOS_ATTACK")
    st.sidebar.success("Injected DDoS trace ready.")
if st.sidebar.button("Inject CPU Resource Exhaustion"):
    generate_mock_crash("RESOURCE_EXHAUSTION")
    st.sidebar.success("Resource trace ready.")
if st.sidebar.button("Inject Gateway Disconnection"):
    generate_mock_crash("INTERFACE_DROP")
    st.sidebar.success("Gateway drop trace ready.")

st.sidebar.markdown("---")
st.sidebar.header("Live Attack Simulators")
st.sidebar.info("Sends real traffic to your local machine. Requires main.py engine to be running.")

import subprocess
if st.sidebar.button("Launch DDoS (stress_test.py)"):
    subprocess.Popen([sys.executable, "stress_test.py"])
    st.sidebar.success("DDoS packet flood launched in background!")
if st.sidebar.button("Launch Port Scan"):
    subprocess.Popen([sys.executable, "simulate_port_scan.py"])
    st.sidebar.success("Port scan launched in background!")
if st.sidebar.button("Launch ICMP Flood"):
    subprocess.Popen([sys.executable, "simulate_icmp_flood.py"])
    st.sidebar.success("ICMP Flood launched! (Note: Requires Administrator privileges)")

st.sidebar.markdown("---")
st.sidebar.header("Live Engine Trigger")
if st.sidebar.button("Trigger Live Crash (main.py)"):
    with open("trigger_crash.txt", "w") as f:
        f.write("crash")
    st.sidebar.success("trigger_crash.txt created! Engine should freeze data shortly.")

if mode == "Live Operational Telemetry":
    st.subheader("Live Telemetry Matrix Monitor")
    st.info("Background threads (when main.py is running) stream traffic into a RAM-only buffer.")
    col1, col2 = st.columns(2)
    col1.metric("In-Memory Queue Capacity", "5,000 Nodes Max")
    col2.metric("Hard Disk State", "Passive Staging (Zero-Disk Standby)")
    st.write(f"Configured capture interface: **{ACTIVE_INTERFACE}**")

elif mode == "Forensic Analysis Vault":
    st.subheader("Historical Failure Reconstruction Console")
    files = sorted([f for f in os.listdir(CRASH_DIR) if f.endswith('.json')], reverse=True)

    if len(files) == 0:
        st.warning("No failure trace data found. Use the sidebar simulator or run a real crash test.")
    else:
        col_select, col_purge = st.columns([3, 1])
        with col_select:
            selected_file = st.selectbox("Select a Failure Record to Restore:", files)
        with col_purge:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🗑️ Purge Old Data"):
                for f in files:
                    try:
                        os.remove(os.path.join(CRASH_DIR, f))
                    except:
                        pass
                st.rerun()
                
        with open(os.path.join(CRASH_DIR, selected_file), 'r') as f:
            crash_data = json.load(f)

        st.success(f"Reconstructed failure state from: {crash_data['metadata']['crash_time']}")
        meta_col1, meta_col2 = st.columns(2)
        meta_col1.metric("Packets Preserved", crash_data['metadata']['total_packets_captured'])
        meta_col2.metric("Metric Nodes Secured", crash_data['metadata']['total_metrics_captured'])

        st.markdown("---")
        engine_choice = st.radio("Choose Diagnostic Layer:",
                                  ["Inbuilt Rule Book", "Offline AI Engine", "Manual Override"])

        profile = condense_crash_data(os.path.join(CRASH_DIR, selected_file))
        sig_hint = rule_check(profile, active_interface=ACTIVE_INTERFACE)
        rule_action = CAUSE_TO_ACTION.get(sig_hint["cause"], "NONE")

        if engine_choice == "Inbuilt Rule Book":
            cause = sig_hint["cause"]
            st.write(f"**Detected:** {cause.replace('_', ' ').title()}")
            if cause in RULE_BOOK:
                st.info(RULE_BOOK[cause]["plain_explanation"])

            status = apply_remediation(rule_action, rule_action, 1.0, sig_hint["target"],
                                        runtime_mode="Approval Required")
            if "STAGED" in status:
                st.warning(status)
                if st.button("Approve and Release This Action", key=f"approve_rule_{selected_file}"):
                    result = apply_remediation(rule_action, rule_action, 1.0, sig_hint["target"],
                                                runtime_mode="Approval Required", override_approval=True)
                    st.success(result)
            else:
                st.write(status)

        elif engine_choice == "Offline AI Engine":
            ai_key = f"ai_result_{selected_file}"
            if st.button("Run Local AI Diagnosis", key=f"trigger_ai_{selected_file}"):
                with st.spinner("Querying local Phi-3 model..."):
                    st.session_state[ai_key] = query_local_ai(profile, sig_hint)

            if ai_key in st.session_state:
                ai_res = st.session_state[ai_key]
                st.write(f"**AI Cause:** {ai_res['root_cause']} | "
                         f"**Confidence:** {ai_res['confidence_score'] * 100}%")

                status = apply_remediation(ai_res['mapped_action'], rule_action,
                                            ai_res['confidence_score'], sig_hint["target"],
                                            runtime_mode="Approval Required")
                if "STAGED" in status:
                    st.warning(status)
                    if st.button("Approve and Release AI Action", key=f"approve_ai_{selected_file}"):
                        result = apply_remediation(ai_res['mapped_action'], rule_action,
                                                    ai_res['confidence_score'], sig_hint["target"],
                                                    runtime_mode="Approval Required", override_approval=True)
                        st.success(result)
                else:
                    st.write(status)

        elif engine_choice == "Manual Override":
            if st.button("Execute Rollback of Last Action", key=f"rollback_{selected_file}"):
                st.info(rollback_last_action())

        st.markdown("---")
        st.subheader("Automated AI Incident Report")
        report_key = f"ai_report_{selected_file}"
        pdf_key = f"ai_report_pdf_{selected_file}"
        
        if st.button("Generate Comprehensive AI Incident Report", key=f"gen_report_{selected_file}"):
            with st.spinner("AI Analyst is writing the report... (This may take a moment)"):
                report_md = generate_incident_report(profile, sig_hint)
                st.session_state[report_key] = report_md
                
                # Generate PDF from markdown
                try:
                    from brain.pdf_generator import generate_pdf_from_markdown
                    import base64
                    pdf_bytes = generate_pdf_from_markdown(report_md, crash_data['metadata']['crash_time'])
                    st.session_state[pdf_key] = pdf_bytes
                    
                    # Auto-download trick via JS
                    b64 = base64.b64encode(pdf_bytes).decode()
                    href = f'<a id="auto_download_pdf" href="data:application/pdf;base64,{b64}" download="Incident_Report_{selected_file}.pdf"></a><script>document.getElementById("auto_download_pdf").click();</script>'
                    import streamlit.components.v1 as components
                    components.html(href, height=0)
                except Exception as e:
                    st.error(f"Failed to generate PDF automatically: {e}")
        
        if report_key in st.session_state:
            report_content = st.session_state[report_key]
            st.info("Report Generated Successfully! (A beautiful PDF version should have automatically downloaded).")
            st.markdown(report_content)
            
            if pdf_key in st.session_state:
                st.download_button(
                    label="Download Report as PDF",
                    data=st.session_state[pdf_key],
                    file_name=f"Incident_Report_{selected_file}.pdf",
                    mime="application/pdf"
                )

        st.markdown("---")
        if crash_data.get('packet_history'):
            st.write("#### Pre-Crash Network Frame Log")
            st.dataframe(pd.DataFrame(crash_data['packet_history']).tail(15), use_container_width=True)
        if crash_data.get('system_metrics_history'):
            st.write("#### Resource Load Vectors")
            df_m = pd.DataFrame(crash_data['system_metrics_history'])
            if 'timestamp' in df_m.columns:
                df_m.set_index('timestamp', inplace=True)
            st.line_chart(df_m[['cpu_percent', 'memory_percent']])

elif mode == "Troubleshooting Rule Book":
    st.subheader("What Can Go Wrong, In Plain English")
    for key, content in RULE_BOOK.items():
        with st.expander(key.replace('_', ' ').title()):
            st.markdown(f"**What's happening:** {content['plain_explanation']}")
            st.markdown(f"**What the system does:** {content['auto_remediation']}")
            for tip in content["optimization_tips"]:
                st.write(f"- {tip}")