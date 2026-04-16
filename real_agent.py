from scapy.all import sniff, IP, TCP, UDP
import requests
import time

API_URL = "http://127.0.0.1:5000/predict"

flow_start_time = {}


def extract_features(packet):
    features = {}

    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto

    key = (src_ip, dst_ip)

    # Flow duration (تقريبي)
    now = time.time()
    if key not in flow_start_time:
        flow_start_time[key] = now

    duration = now - flow_start_time[key]

    features["Flow Duration"] = duration
    features["Protocol"] = proto
    features["Packet Length"] = len(packet)

    if TCP in packet:
        features["Source Port"] = packet[TCP].sport
        features["Destination Port"] = packet[TCP].dport
        features["Flags"] = int(packet[TCP].flags)

    elif UDP in packet:
        features["Source Port"] = packet[UDP].sport
        features["Destination Port"] = packet[UDP].dport
        features["Flags"] = 0

    else:
        features["Source Port"] = 0
        features["Destination Port"] = 0
        features["Flags"] = 0

    return features


def send_to_api(features):
    try:
        response = requests.post(API_URL, json=features)
        result = response.json()
        print(f"[REAL] → {result}")
    except Exception as e:
        print("[ERROR]", e)


def process_packet(packet):
    features = extract_features(packet)

    if features:
        send_to_api(features)


print("[INFO] Real Agent Started...")

sniff(prn=process_packet, store=0)