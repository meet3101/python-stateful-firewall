from scapy.all import sniff, IP, TCP, UDP

def handle_packet(pkt):
    if IP in pkt:
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
        print(f"{pkt[IP].src} -> {pkt[IP].dst} | {proto}")

if __name__ == "__main__":
    print("Sniffing... Ctrl+C to stop")
    sniff(prn=handle_packet, store=False, iface="lo")