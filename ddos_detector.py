import csv
from collections import defaultdict

THRESHOLD = 150
MIN_ALERTS = 3 

print("Starting Smart DDoS Detection...\n")

ip_stats = defaultdict(lambda: {
    "pps_values": [],
    "alerts": 0
})


with open("flows.csv", "r") as f:
    reader = csv.DictReader(f)

    for row in reader:
        pps = float(row["Packets per Second"])
        src_ip = row["Src IP"]

        ip_stats[src_ip]["pps_values"].append(pps)

        if pps > THRESHOLD:
            ip_stats[src_ip]["alerts"] += 1



for ip, data in ip_stats.items():
    avg_pps = sum(data["pps_values"]) / len(data["pps_values"])
    max_pps = max(data["pps_values"])
    alerts = data["alerts"]

    print(f"[INFO] {ip} | AVG={avg_pps:.2f} | MAX={max_pps:.2f} | ALERTS={alerts}")


    if alerts >= MIN_ALERTS and max_pps > THRESHOLD:
        print(f"[FINAL ALERT] DDoS from {ip}\n")