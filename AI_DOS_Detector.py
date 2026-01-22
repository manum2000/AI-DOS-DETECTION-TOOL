import sys
import joblib
import pandas as pd
from scapy.all import sniff, IP
from collections import Counter

# --- CONFIGURATION ---
MODEL_PATH = "dos_model.pkl"
INTERFACE = None 
WINDOW_SIZE = 5 

# Load the trained AI model
try:
    model = joblib.load(MODEL_PATH)
    print(f"[*] AI Model '{MODEL_PATH}' loaded successfully.")
except Exception as e:
    print(f"[!] Error loading model: {e}")
    sys.exit(1)

def get_statistics(packet_list):
    """Extracts features and identifies the most frequent source IP."""
    if not packet_list:
        return None, None

    total_packets = len(packet_list)
    pps = total_packets / WINDOW_SIZE
    avg_size = sum(len(pkt) for pkt in packet_list) / total_packets
    
    # --- NEW: Identify Malicious IP Candidate ---
    # Extract source IPs only from packets that have an IP layer
    src_ips = [pkt[IP].src for pkt in packet_list if IP in pkt]
    most_common_ip = Counter(src_ips).most_common(1)[0][0] if src_ips else "Unknown"
    
    # Return features as DataFrame and the suspect IP
    features = pd.DataFrame([[pps, avg_size, WINDOW_SIZE]], 
                            columns=['PPS', 'Avg_Packet_Size', 'Duration'])
    return features, most_common_ip

def detect_dos_ai(features, suspect_ip):
    """Uses the AI model to predict DoS and reports the suspect IP."""
    if features is None:
        return

    # AI Prediction: 0 for Benign, 1 for DoS
    prediction = model.predict(features)[0]
    
    if prediction == 1:
        print(f"\n[!!!] AI ALERT: DoS ATTACK DETECTED [!!!]")
        print(f"[*] Suspected Source IP: {suspect_ip}") # <-- Added line
        print(f"Details: {features.iloc[0].to_dict()}")
        print("-" * 40)
    else:
        print(f"[+] Traffic Analysis: Normal (PPS: {features.iloc[0]['PPS']:.2f})")

def start_tool():
    print(f"--- AI DoS Detection Tool Active ---")
    try:
        while True:
            # Capture packets
            packets = sniff(iface=INTERFACE, timeout=WINDOW_SIZE)
            features, suspect_ip = get_statistics(packets)
            detect_dos_ai(features, suspect_ip)
    except KeyboardInterrupt:
        print("\nShutting down detector...")

if __name__ == "__main__":
    start_tool()