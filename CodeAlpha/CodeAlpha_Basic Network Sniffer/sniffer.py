from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    print("\n--- Packet Captured ---")

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"Source IP      : {src}")
        print(f"Destination IP : {dst}")
        print(f"Protocol       : {proto}")

        if packet.haslayer(TCP):
            print("Protocol Type  : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Dest Port      : {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol Type  : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Dest Port      : {packet[UDP].dport}")

        if packet.haslayer("Raw"):
            print(f"Payload:\n{packet['Raw'].load}")

print("Starting packet sniffing... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=False)
