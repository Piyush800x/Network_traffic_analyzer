from scapy.all import *


def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"Source: {ip_layer.src}, Destination: {ip_layer.dst}")

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"TCP Port: {tcp_layer.sport} -> {tcp_layer.dport}")

        if packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"UDP Port: {udp_layer.sport} -> {udp_layer.dport}")

        if packet.haslayer(Raw):
            payload = packet.getlayer(Raw).load
            print(f"Payload: {payload}")

    print("---")


# Start sniffing packets
sniff(prn=packet_callback, filter="ip", store=False)
