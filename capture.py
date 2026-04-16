from scapy.all import sniff, wrpcap

print("🚀 Capturing packets... Press Ctrl+C to stop")

packets = []

def collect(pkt):
    packets.append(pkt)

try:
    sniff(iface="Wi-Fi", prn=collect)
except KeyboardInterrupt:
    print("\n🛑 Stopping capture...")

wrpcap("traffic.pcap", packets)

print(f"✅ Saved {len(packets)} packets to traffic.pcap")