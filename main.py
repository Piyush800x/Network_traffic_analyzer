from scapy.all import *


def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}")


def capture_traffic(interface="Ethernet"):
    print(f"[*] Starting capture on interface {interface}")
    sniff(iface=interface, prn=analyze_packet, store=0)


if __name__ == "__main__":
    capture_traffic()
