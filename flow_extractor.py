from cicflowmeter.sniffer import create_sniffer

print("🚀 Processing PCAP file...")

sniffer, flow_session = create_sniffer(
    input_file="traffic.pcap",   # 👈 بس ده
    output_mode="csv",
    output="flows.csv"
)

sniffer.start()
sniffer.join()

print("✅ Flow extraction completed!")