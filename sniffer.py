from scapy.all import sniff
from scapy.layers.inet import IP

import pandas as pd

# =====================================================
# PACKET STORAGE
# =====================================================

captured_packets = []

# =====================================================
# PROCESS PACKETS
# =====================================================

def process_packet(packet):

    if packet.haslayer(IP):

        src_ip = packet[IP].src

        dst_ip = packet[IP].dst

        protocol = packet[IP].proto

        packet_size = len(packet)

        captured_packets.append({

            "Source IP": src_ip,

            "Destination IP": dst_ip,

            "Protocol": protocol,

            "Packet Size": packet_size
        })

# =====================================================
# START SNIFFING
# =====================================================

def start_sniffing(packet_count=20):

    captured_packets.clear()

    sniff(

        prn=process_packet,

        count=packet_count,

        store=False
    )

    return pd.DataFrame(captured_packets)