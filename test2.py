from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"Source: {ip_layer.src}, Destination: {ip_layer.dst}")
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print(f"TCP Port: {tcp_layer.sport} -> {tcp_layer.dport}")
    if packet.haslayer(Raw):
        payload = packet.getlayer(Raw).load
        print(f"Payload: {payload}")
    print("---")

# Get the list of network interfaces
interfaces = get_if_list()

# Find the interface connected to your router or switch
for interface in interfaces:
    if interface != "lo":  # Exclude the loopback interface
        try:
            # Try to set the interface in promiscuous mode
            conf.iface = interface
            conf.sniff_promisc = 1
            break
        except:
            pass

# Start sniffing packets on the selected interface
sniff(prn=packet_callback, filter="ip", store=False)