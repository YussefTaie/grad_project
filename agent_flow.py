import pandas as pd
import time
import os
from predict import predict
from action import take_action

CSV_FILE = "live_traffic.csv"

def monitor_csv():
    print("🚀 Monitoring traffic...")

    last_index = 0

    while True:
        if os.path.exists(CSV_FILE):
            df = pd.read_csv(CSV_FILE)
            df.columns = df.columns.str.strip()

            new_rows = df.iloc[last_index:]

            for i, row in new_rows.iterrows():
                sample = row.to_dict()

                ip = sample.get("Source IP", "unknown")

                result = predict(sample)

                print(f"{ip} → {result}")

                take_action(result, ip)

            last_index = len(df)

        time.sleep(2)


monitor_csv()