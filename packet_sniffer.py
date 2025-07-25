# packet_sniffer.py
# Basic Network Packet Sniffer using Scapy (For Educational Use Only)

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = packet.proto

        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        else:
            proto = "Other"

        print(f"[+] {proto} Packet: {src_ip} -> {dst_ip}")

# Sniff packets (default interface and store=False for real-time)
print("[INFO] Starting packet capture. Press Ctrl+C to stop.
")
sniff(prn=process_packet, store=False)
