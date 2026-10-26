from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap

packets = []

# Normal web traffic
for i in range(5):
    packets.append(
        IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=50000 + i, dport=443, flags="S")
    )

# Repeated connection attempts
for i in range(12):
    packets.append(
        IP(src="192.168.1.20", dst="192.168.1.1")
        / TCP(sport=51000 + i, dport=22, flags="S")
    )

# Traffic to an unusual port
packets.append(
    IP(src="192.168.1.30", dst="192.168.1.40")
    / TCP(sport=52000, dport=4444, flags="S")
)

# Port-scanning test: one source targets 8 different ports
for i, port in enumerate([21, 22, 23, 25, 80, 443, 8080, 9000]):
    packets.append(
        IP(src="192.168.1.50", dst="192.168.1.60")
        / TCP(sport=54000 + i, dport=port, flags="S")
    )

# UDP traffic
packets.append(
    IP(src="192.168.1.10", dst="8.8.8.8")
    / UDP(sport=53000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="example.com"))
)

wrpcap("sample_traffic.pcap", packets)

print("Sample PCAP created successfully!")
print(f"Total packets: {len(packets)}")