def extract_features(packet):
    if IP in packet:
        ip = packet[IP]

        # 💀 هجوم وهمي
        features = {
            "Destination Port": 80,
            "Flow Duration": 999999,
            "Total Fwd Packets": 500,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 999999,
            "Total Length of Bwd Packets": 0,
            "Flow Bytes/s": 999999,
            "Flow Packets/s": 1000,
        }

        return features, ip.src

    return None, None