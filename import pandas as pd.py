import pandas as pd

df = pd.read_csv("d:\CIC\Last semester 2026\Graduation Project\MachineLearningCSV\MachineLearningCVE\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
print(df.head())

df = df.dropna()

import numpy as np

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)


df.drop(columns=[
    'Flow ID', 'Source IP', 'Destination IP', 'Timestamp'
], inplace=True, errors='ignore')


df[' Label'] = df[' Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)


X = df.drop(' Label', axis=1)
y = df[' Label']


from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)