import pytest
pytestmark = [pytest.mark.integration, pytest.mark.network]
import socket
import threading
import time
from scapy.all import sniff, TCP, IP
import os
import psutil

print("Testing Scapy Visibility across Docker bounds...")
interfaces = psutil.net_if_addrs()
print(f"Available interfaces: {list(interfaces.keys())}")

seen_packets = []

def capture_packets():
    def packet_handler(pkt):
        if IP in pkt and TCP in pkt:
            seen_packets.append(pkt)
    sniff(prn=packet_handler, store=False, filter="tcp and port 8000", timeout=5)

t = threading.Thread(target=capture_packets)
t.start()
time.sleep(1)

try:
    # Simulate Node.js talking to FastAPI (we are running inside FastAPI container environment conceptually)
    # Actually we are running on host right now, so we will just test localhost loopback visibility
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8000))
    s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n")
    s.close()
except Exception as e:
    print(f"Connection failed: {e}")

t.join()

if len(seen_packets) > 0:
    print("RESULT: Scapy CAN observe loopback/internal traffic.")
else:
    print("RESULT: Scapy CANNOT observe the traffic.")
