from scapy.all import rdpcap, IP, TCP, UDP
from collections import Counter


def analyze_pcap(file_path):
    packets = rdpcap(file_path)

    total_packets = len(packets)
    ip_counter = Counter()
    protocol_counter = Counter()

    for packet in packets:
        if IP in packet:
            ip_counter[packet[IP].src] += 1
            ip_counter[packet[IP].dst] += 1

            if TCP in packet:
                protocol_counter["TCP"] += 1
            elif UDP in packet:
                protocol_counter["UDP"] += 1
            else:
                protocol_counter["Other IP"] += 1

    return {
        "total_packets": total_packets,
        "top_ips": ip_counter.most_common(10),
        "protocols": dict(protocol_counter)
    }