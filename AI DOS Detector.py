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
    """Extracts features for the AI model to process."""
    if not packet_list:
        return None

    total_packets = len(packet_list)
    pps = total_packets / WINDOW_SIZE
    avg_size = sum(len(pkt) for pkt in packet_list) / total_packets
    
    # Return features as a DataFrame to match the training format
    return pd.DataFrame([[pps, avg_size, WINDOW_SIZE]], 
                        columns=['PPS', 'Avg_Packet_Size', 'Duration'])

def detect_dos_ai(features):
    """Uses the AI model to predict if traffic is a DoS attack."""
    if features is None:
        return

    # AI Prediction: 0 for Benign, 1 for DoS
    prediction = model.predict(features)[0]
    
    # Get probability if your model supports it (optional)
    # prob = model.predict_proba(features)[0][1] 

    if prediction == 1:
        print(f"\n[!!!] AI ALERT: DoS ATTACK DETECTED [!!!]")
        print(f"Details: {features.iloc[0].to_dict()}")
        print("-" * 40)
    else:
        print(f"[+] Traffic Analysis: Normal (PPS: {features.iloc[0]['PPS']})")

def start_tool():
    print(f"--- AI DoS Detection Tool Active ---")
    try:
        while True:
            # Capture packets for the window
            packets = sniff(iface=INTERFACE, timeout=WINDOW_SIZE)
            features = get_statistics(packets)
            detect_dos_ai(features)
    except KeyboardInterrupt:
        print("\nShutting down detector...")

if __name__ == "__main__":
    start_tool()