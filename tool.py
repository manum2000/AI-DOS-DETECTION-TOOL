import sys
import time
from scapy.all import sniff, IP, TCP, UDP
from collections import Counter

# --- CONFIGURATION ---
INTERFACE = None  # None uses your default. Change to "eth0" or "Wi-Fi" if needed.
WINDOW_SIZE = 5   # Analyze traffic every 5 seconds
THRESHOLD_PPS = 100 # Packets Per Second from one IP to flag as DoS

def get_statistics(packet_list):
    """Extracts features from the captured packet window."""
    if not packet_list:
        return None

    src_ips = [pkt[IP].src for pkt in packet_list if IP in pkt]
    if not src_ips:
        return None

    counts = Counter(src_ips)
    most_active_ip, packet_count = counts.most_common(1)[0]
    pps = packet_count / WINDOW_SIZE
    
    # Feature: Average Packet Size
    avg_size = sum(len(pkt) for pkt in packet_list) / len(packet_list)
    
    return {
        "ip": most_active_ip,
        "pps": pps,
        "avg_size": avg_size,
        "total_packets": len(packet_list)
    }

def detect_dos(stats):
    """The Decision Engine."""
    if not stats:
        return

    print(f"[*] Analyzing: {stats['total_packets']} pkts | Top IP: {stats['ip']} ({stats['pps']} PPS)")

    # Logical detection (Simulating what a trained ML model would do)
    if stats['pps'] > THRESHOLD_PPS:
        print(f"\n[!!!] ALERT: DoS ATTACK DETECTED [!!!]")
        print(f"SOURCE: {stats['ip']}")
        print(f"REASON: Traffic exceeds {THRESHOLD_PPS} PPS. Avg Size: {stats['avg_size']} bytes.")
        print("-" * 40)
        # MITIGATION: You could add a firewall block command here.
    else:
        print("[+] Traffic looks normal.")

def start_tool():
    print(f"--- AI DoS Detection Tool Active on {INTERFACE if INTERFACE else 'Default Interface'} ---")
    print("[Control + C to Stop]")
    
    try:
        while True:
            # Capture packets for the duration of WINDOW_SIZE
            packets = sniff(iface=INTERFACE, timeout=WINDOW_SIZE)
            stats = get_statistics(packets)
            detect_dos(stats)
    except KeyboardInterrupt:
        print("\nShutting down detector...")
        sys.exit()

if __name__ == "__main__":
    # Check for Root/Admin privileges (Required for sniffing)
    start_tool()