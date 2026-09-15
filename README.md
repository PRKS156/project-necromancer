# 🛡️ Project Necromancer

**Project Necromancer** is an advanced, AI-powered local network monitoring and automated remediation system. It acts as an autonomous cybersecurity guardian for your local machine, detecting network anomalies in real-time and responding with intelligent countermeasures.

Instead of just alerting you, Project Necromancer leverages local AI models (via [Ollama](https://ollama.com/)) to analyze threats and can execute targeted remediations—like injecting Windows Firewall blocks or terminating malicious processes—before the attack overwhelms your system.

---

## 🚀 Features

### Detection Engine
- **Live Packet Sniffing**: Uses `scapy` to continuously monitor your active network interface in real-time.
- **Multi-Threat Live Watchdog**: Automatically detects **5 types of anomalies** without any manual trigger:
  - 🔴 **DDoS Attacks** — Detects when a single source floods your machine with small packets.
  - 🟡 **ICMP Ping Floods** — Detects excessive ICMP echo request bombardment.
  - 🟠 **Port Scans** — Detects reconnaissance probes scanning many ports rapidly.
  - 🟣 **Resource Exhaustion** — Detects when CPU spikes dangerously high.
  - ⚪ **Interface Drops** — Detects when your network adapter goes offline.
- **False Positive Filtering**: Smart heuristics distinguish real attacks from legitimate traffic:
  - Large file downloads won't trigger DDoS alerts (packet size filtering).
  - P2P/BitTorrent apps won't trigger port scan alerts (packets-per-port ratio).

### AI Brain
- **AI-Powered Forensic Analysis**: Routes crash data to a local AI (`phi3` via Ollama) for intelligent root-cause analysis.
- **Rule-based & AI Consensus**: Combines deterministic rule-checks with AI reasoning. Both must agree before any action is taken.
- **Automated PDF Incident Reports**: AI generates comprehensive Markdown reports, automatically exported as downloadable PDFs.

### Automated Remediation
- **Safe Automated Responses**: Can automatically apply Windows Firewall drops or kill rogue processes.
- **Multi-Layer Safety Gates**: 
  - Minimum AI confidence threshold (75%).
  - Rule/AI consensus requirement.
  - Anti-thrashing cooldown timer.
  - Critical process denylist.
  - Target entity validation.
  - Human approval workflow for destructive actions.
- **DRY_RUN Mode**: All actions are simulated by default — flip one flag to go live.
- **Rollback Support**: Every action is reversible with a single click.

### Interactive Dashboard
- **Streamlit Control Room**: Beautiful web interface for monitoring, analysis, and approvals.
- **Mock Injectors**: One-click buttons to simulate all 5 attack types for demo/testing.
- **Live Attack Simulators**: Launch real (loopback-only) DDoS floods, port scans, and ICMP floods.
- **Public Tunneling**: Built-in Cloudflare Quick Tunnel support for remote monitoring.

### Engine Resilience
- **Auto-Recovery**: After handling an incident, the engine automatically restarts monitoring — no manual restart needed.
- **Thread-Safe Buffers**: Lock-protected circular buffers prevent data corruption between capture and analysis threads.

---

## 📋 Prerequisites

1. **Python 3.10+** (Ensure Python is added to your system `PATH`).
2. **Npcap**: Required by `scapy` for packet sniffing on Windows. [Download Npcap here](https://npcap.com/#download) (install with "WinPcap API-compatible Mode" checked).
3. **Ollama** *(optional)*: Required for the AI Analyst subsystem. [Download Ollama here](https://ollama.com/). The system falls back to rule-only analysis if Ollama is unavailable.
4. **Cloudflared** *(optional)*: For public tunnel access. [Download here](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/).

---

## 🛠️ Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/PRKS156/project-necromancer.git
   cd project-necromancer
   ```

2. **Run the Launcher:**
   Simply double-click `start_necromancer.bat`. It will automatically:
   - Check if Python is installed.
   - Install all required Python packages from `requirements.txt`.
   - Verify Ollama is running and download the `phi3` AI model.
   - Launch the backend monitoring engine (`main.py`).
   - Launch the Streamlit interactive dashboard.
   - Set up a secure Cloudflare tunnel for remote access.

---

## 💻 Usage

Once running, the Streamlit dashboard opens in your browser at `http://localhost:8501`.

### Dashboard Sections
| Section | Purpose |
|---------|---------|
| **Live Operational Telemetry** | View real-time buffer status and configured interface. |
| **Forensic Analysis Vault** | Select, analyze, and remediate historical crash dumps. |
| **Troubleshooting Rule Book** | Plain-English explanations of all 5 detectable attack types. |

### Triggering a Test Alert
| Method | How |
|--------|-----|
| **Mock Injector** | Click any "Inject..." button in the sidebar to create fake crash data instantly. |
| **Live Simulator** | Click "Launch DDoS", "Launch Port Scan", or "Launch ICMP Flood" to send real traffic. |
| **Manual Trigger** | Click "Trigger Live Crash" to force the engine to freeze its current buffer. |
| **CLI** | Run `python stress_test.py`, `python simulate_port_scan.py`, or `python simulate_icmp_flood.py`. |

---

## 🏗️ Architecture

```
project-necromancer/
├── main.py                    # Core engine: sniffer + watchdog + remediation loop
├── agent.py                   # Remote agent for server-based approval workflows
├── config.py                  # Single source of truth for interface configuration
│
├── core/
│   ├── sniffer.py             # Threaded packet capture via Scapy
│   ├── metrics.py             # Threaded CPU/memory/bandwidth telemetry
│   └── buffer_manager.py      # Thread-safe circular buffer with freeze-and-flush
│
├── brain/
│   ├── parser.py              # Crash dump → condensed profile (with false-positive metrics)
│   ├── signatures.py          # Deterministic rule engine (5 attack signatures)
│   ├── ai_analyst.py          # Local Ollama AI integration + incident report generator
│   └── pdf_generator.py       # Markdown → PDF report converter
│
├── automation/
│   └── action_center.py       # Remediation executor with 6 safety gates + rollback
│
├── interface/
│   └── dashboard.py           # Streamlit dashboard with mock injectors and simulators
│
├── stress_test.py             # Loopback UDP flood simulator
├── simulate_port_scan.py      # Loopback port scan simulator
├── simulate_icmp_flood.py     # Loopback ICMP flood simulator
├── test_suite.py              # 15 automated tests covering all detection + safety logic
├── start_necromancer.bat       # One-click Windows launcher
└── requirements.txt
```

---

## 🧪 Running Tests

```bash
python test_suite.py
```

All 15 tests cover:
- Detection of all 5 attack types (DDoS, ICMP Flood, Port Scan, Resource Exhaustion, Interface Drop).
- False positive guards (large file downloads, P2P traffic).
- All 6 remediation safety gates.
- Rollback functionality.

---

## ⚠️ Disclaimer

Project Necromancer interacts directly with your Windows Firewall and process manager. It is designed for **educational, research, and personal defensive use only**. Do not deploy this on critical production networks without extensive testing. The author is not responsible for accidental network lockouts or terminated processes.

By default, `DRY_RUN = True` in `automation/action_center.py` — all remediation actions are simulated and logged but not executed. Set `DRY_RUN = False` only when you are confident in the system's behavior.

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.
