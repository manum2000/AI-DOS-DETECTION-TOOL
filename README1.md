# AI-Powered DoS Detection & Prevention Tool

A Python-based network security tool designed to monitor real-time traffic, detect Denial of Service (DoS) attacks using statistical/AI analysis, and optionally mitigate threats by blocking malicious IPs.

## 🚀 Features
- **Real-time Sniffing:** Uses `Scapy` to intercept network packets on a specified interface.
- **Traffic Analysis:** Calculates Packets Per Second (PPS) and average payload sizes to identify anomalies.
- **AI-Ready:** Logic structured to integrate Machine Learning models (e.g., Random Forest) for advanced classification.
- **Automated Mitigation:** Capability to interface with system firewalls (like `iptables`) to drop malicious traffic.



## 🛠️ Prerequisites
Before running the tool, ensure you have Python 3.x installed along with the following libraries:
```bash
pip install scapy

🚦 Usage
1. Start the Detector
Run the detector on the target machine (e.g., your Kali Linux VM):
Bash
sudo python3 detector.py
2. Run the Stress Test
Simulate traffic from your host machine (Windows) to test the detection logic:
Bash
python attack_sim.py
