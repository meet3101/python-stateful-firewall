import sys
import os
import time
sys.path.append(os.path.dirname(__file__))

from scapy.all import sniff, IP, TCP, UDP
from rules import RuleEngine
from state_table import ConnectionTable

engine = RuleEngine("config/rules.yaml")
conn_table = ConnectionTable()

syn_tracker = {}      # src_ip -> list of timestamps
blocklist = set()     # auto-blocked IPs
SYN_THRESHOLD = 50    # max SYNs allowed
TIME_WINDOW = 10       # seconds

def is_syn_flood(src):
    now = time.time()
    syn_tracker.setdefault(src, [])
    syn_tracker[src] = [t for t in syn_tracker[src] if now - t < TIME_WINDOW]
    syn_tracker[src].append(now)
    return len(syn_tracker[src]) > SYN_THRESHOLD

def handle_packet(pkt):
    if IP not in pkt:
        return
    proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else None
    if not proto:
        return

    src, dst = pkt[IP].src, pkt[IP].dst
    sport = pkt.sport if hasattr(pkt, "sport") else None
    dport = pkt.dport if hasattr(pkt, "dport") else None

    if src in blocklist:
        print(f"[BLOCKED] {src}:{sport} -> {dst}:{dport} (auto-blocked IP)")
        return

    if proto == "tcp" and pkt[TCP].flags == "S":
        if is_syn_flood(src):
            blocklist.add(src)
            print(f"[ALERT] SYN flood detected from {src} — auto-blocking")
            return

    if conn_table.is_established(src, sport, dst, dport, proto):
        print(f"[ALLOW-ESTABLISHED] {src}:{sport} -> {dst}:{dport}")
        return

    decision = engine.match({"proto": proto, "src": src, "dst_port": dport})
    print(f"[{decision.upper()}] {src}:{sport} -> {dst}:{dport} ({proto})")

    if decision == "allow" and proto == "tcp" and pkt[TCP].flags == "S":
        conn_table.add(src, sport, dst, dport, proto)

if __name__ == "__main__":
    print("Firewall running... Ctrl+C to stop")
    sniff(prn=handle_packet, store=False, iface="lo", filter="tcp port 80")