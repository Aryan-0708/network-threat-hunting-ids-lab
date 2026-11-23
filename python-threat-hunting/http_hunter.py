from scapy.all import rdpcap, TCP, Raw

# Step 1: Load the HTTP traffic capture
pcap_file = input("Enter HTTP PCAP file path: ").strip()
packets = rdpcap(pcap_file)

print("===== HTTP USER-AGENT HUNTING =====")
print("Total packets:", len(packets))

# Step 2: Prepare investigation variables
http_requests = 0
suspicious_requests = 0

# Step 3: Examine every packet
for packet in packets:

    if TCP in packet and Raw in packet:

        payload = packet[Raw].load

        # Check whether the packet contains an HTTP GET request
        if b"GET " in payload:

            http_requests += 1

            # Search for our custom User-Agent
            if b"SOC-LAB-Scanner" in payload:

                suspicious_requests += 1

                print("\n[ALERT] Custom User-Agent detected!")
                print("Source IP:", packet["IP"].src)
                print("Destination IP:", packet["IP"].dst)
                print("User-Agent: SOC-LAB-Scanner")

# Step 4: Display investigation results
print("\n===== INVESTIGATION RESULTS =====")
print("HTTP GET requests:", http_requests)
print("Suspicious User-Agent matches:", suspicious_requests)

if suspicious_requests > 0:
    print("\nALERT: Custom HTTP User-Agent activity detected!")
else:
    print("\nNo matching custom User-Agent detected.")
