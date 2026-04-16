import requests
import pandas as pd
import time
from action import take_action

# قراءة الداتا كـ simulation
df = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
df.columns = df.columns.str.strip()

API_URL = "http://127.0.0.1:5000/predict"

for i in range(50):
    sample = df.iloc[i].to_dict()

    # IP وهمي (ممكن تجيبه من الداتا بعدين)
    ip = f"192.168.1.{i}"

    try:
        response = requests.post(API_URL, json=sample)
        result = response.json()

        print(f"[{i}] → {result}")

        take_action(result["result"], ip)

    except Exception as e:
        print("Error:", e)

    time.sleep(1)