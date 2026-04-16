from scapy.all import rdpcap, IP, TCP
from collections import defaultdict
import csv
# FIX 1 + FIX 5 — shared, consistent PPS calculation
from flow_utils import compute_pps

print("🚀 Reading PCAP...")

packets = rdpcap("traffic.pcap")

flows = defaultdict(list)

# 🟢 تحديد الفلو
def get_flow_key(pkt):
    if IP in pkt and TCP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        # bidirectional flow
        if (src, sport) < (dst, dport):
            return (src, sport, dst, dport)
        else:
            return (dst, dport, src, sport)
    return None


# 🟢 تجميع packets
for pkt in packets:
    key = get_flow_key(pkt)
    if key:
        flows[key].append(pkt)

print(f"✅ Total flows: {len(flows)}")

# 🟢 Window size (أهم حاجة 🔥)
TIME_WINDOW = 1  # ثانية

rows = []

# 🟢 استخراج features بالـ window
for key, pkts in flows.items():
    src, sport, dst, dport = key

    pkts = sorted(pkts, key=lambda x: x.time)

    start_time = pkts[0].time
    current_window = []

    for pkt in pkts:
        if pkt.time - start_time <= TIME_WINDOW:
            current_window.append(pkt)
        else:
            if current_window:
                sizes = [len(p) for p in current_window]
                duration = current_window[-1].time - current_window[0].time
                if duration == 0:
                    duration = 1

                rows.append({
                    "Src IP": src,
                    "Src Port": sport,
                    "Dst IP": dst,
                    "Dst Port": dport,
                    "Flow Duration": duration,
                    "Total Packets": len(current_window),
                    "Total Bytes": sum(sizes),
                    # FIX 1 + FIX 5: use shared compute_pps() with 0.01s floor
                    "Packets per Second": compute_pps(len(current_window), duration),
                    "Bytes per Second": sum(sizes) / max(duration, 0.01),
                })

            # 🔥 reset window
            start_time = pkt.time
            current_window = [pkt]

    # 🟢 آخر window
    if current_window:
        sizes = [len(p) for p in current_window]
        duration = current_window[-1].time - current_window[0].time
        if duration == 0:
            duration = 1

        rows.append({
            "Src IP": src,
            "Src Port": sport,
            "Dst IP": dst,
            "Dst Port": dport,
            "Flow Duration": duration,
            "Total Packets": len(current_window),
            "Total Bytes": sum(sizes),
            # FIX 1 + FIX 5: use shared compute_pps() with 0.01s floor
            "Packets per Second": compute_pps(len(current_window), duration),
            "Bytes per Second": sum(sizes) / max(duration, 0.01),
        })


# 🟢 كتابة CSV
if rows:
    with open("flows.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("🔥 flows.csv created with windowing!")
else:
    print("❌ No flows found!")