
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers import *

def packet_analysis(packet):
    
    if packet.haslayer(IP):
        
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        
        protocol = packet[IP].proto

        if packet.haslayer(Raw):
            payload = packet[Raw].load
        else:
            payload = ""  
        
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("--------------------------------")

sniff(filter="ip", prn=packet_analysis)