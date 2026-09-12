# 🛡️ Project Necromancer

**Project Necromancer** is an advanced, AI-powered local network monitoring and automated remediation system. It acts as an autonomous cybersecurity guardian for your local machine, detecting network anomalies, DoS attacks, and resource exhaustion in real-time.

Instead of just alerting you, Project Necromancer leverages local AI models (via Ollama) to analyze the threat and can execute targeted remediations—like injecting Windows Firewall blocks or terminating malicious processes—before the attack overwhelms your system.

---

## 🚀 Features
- **Live Packet Sniffing**: Uses `scapy` to continuously monitor your active network interface.
- **AI-Powered Forensic Vault**: Automatically routes crash data and anomalous traffic patterns to a local AI (`phi3` via Ollama) for intelligent root-cause analysis.
- **Rule-based & AI Consensus**: Combines deterministic rule-checks with AI reasoning to prevent false positives.
- **Automated Remediation**: Can automatically apply Windows Firewall drops or kill rogue processes to neutralize threats instantly.
- **Interactive Dashboard**: A beautiful Streamlit interface to monitor your network health, view forensic reports, and approve/reject remediation actions.
- **Public Tunneling**: Built-in support to expose your dashboard via Cloudflare Quick Tunnels for remote monitoring.

---

## 📋 Prerequisites
To run Project Necromancer, you need the following installed on your Windows machine:

1. **Python 3.10+** (Ensure Python is added to your system `PATH`).
2. **Npcap**: Required by `scapy` for packet sniffing on Windows. [Download Npcap here](https://npcap.com/#download) (Make sure to install it with "WinPcap API-compatible Mode" checked).
3. **Ollama**: Required for the AI Analyst subsystem. [Download Ollama here](https://ollama.com/).

---

## 🛠️ Installation

1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/YOUR-USERNAME/project-necromancer.git
   cd project-necromancer
   ```

2. **Run the Launcher:**
   Simply double-click the `start_necromancer.bat` file. 
   
   The launcher will automatically:
   - Check if Python is installed.
   - Install all required Python packages from `requirements.txt`.
   - Verify Ollama is running and download the `phi3` AI model if you don't have it.
   - Launch the backend monitoring engine in the background.
   - Launch the Streamlit interactive dashboard.
   - Set up a secure Cloudflare tunnel for remote access.

---

## 💻 Usage

Once running, the Streamlit dashboard will open in your browser (usually at `http://localhost:8501`). 

- **Dashboard**: View live network metrics and historical crash logs.
- **Forensic Vault**: Review incidents flagged by the engine. You can see the AI's confidence score and reasoning.
- **Action Center**: Approve or override remediations proposed by the AI.

### Triggering a Test Alert
To see the system in action, you can safely trigger a test incident in two ways:
1. Create an empty file named `trigger_crash.txt` in the root directory.
2. Run `python stress_test.py` in a separate terminal to simulate a high-volume localized attack.

---

## ⚠️ Disclaimer
Project Necromancer interacts directly with your Windows Firewall and process manager. It is designed for educational, research, and personal defensive use only. Do not deploy this on critical production networks without extensive testing. The author is not responsible for accidental network lockouts or terminated processes.

---

## 📝 License
Distributed under the MIT License. See `LICENSE` for more information.
