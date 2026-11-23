from scapy.all import rdpcap, IP, TCP

# Step 1: Load the captured network traffic
pcap_file = input("Enter SYN scan PCAP file path: ").strip()
packets = rdpcap(pcap_file)

print("===== TCP SYN SCAN HUNTING =====")
print("Total packets:", len(packets))

# Step 2: Prepare variables for our investigation
syn_count = 0
destination_ports = set()
source_ips = set()
destination_ips = set()

# Step 3: Examine every packet
for packet in packets:

    # Check whether the packet contains IP and TCP layers
    if IP in packet and TCP in packet:

        tcp_flags = packet[TCP].flags

        # Identify SYN packets without ACK
        if tcp_flags & 0x02 and not tcp_flags & 0x10:

            syn_count += 1

            source_ips.add(packet[IP].src)
            destination_ips.add(packet[IP].dst)
            destination_ports.add(packet[TCP].dport)

# Step 4: Display investigation results
print("\n===== INVESTIGATION RESULTS =====")
print("TCP SYN packets:", syn_count)
print("Unique destination ports:", len(destination_ports))
print("Source IP addresses:", source_ips)
print("Destination IP addresses:", destination_ips)

# Step 5: Basic scan indication
if len(destination_ports) >= 100:
    print("\nALERT: Possible TCP SYN port scan detected!")
else:
    print("\nNo large-scale TCP SYN scan pattern detected.")
