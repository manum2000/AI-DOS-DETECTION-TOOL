🚦 Usage
1. Start the Detector
Run the detector on the target machine (e.g., your Kali Linux VM):
Bash
sudo python3 detector.py
2. Run the Stress Test
Simulate traffic from your host machine (Windows) to test the detection logic:
Bash
python attack_sim.py

📊 How it Works :
The tool operates in a three-step pipeline:
Ingestion: Captures raw packets in 5-second windows.
Feature Extraction: Extracts metadata such as Source IP, Protocol, and PPS.
Classification: Compares traffic patterns against a threshold (or ML model) to trigger alerts.

⚠️ Disclaimer
This project is for educational and research purposes only. Do not use this tool on networks or systems you do not own or have explicit permission to test. The author is not responsible for any misuse or damage caused by this software.
