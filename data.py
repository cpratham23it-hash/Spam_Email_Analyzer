import pandas as pd
import os

files = ['CEAS_08', 'Enron', 'Ling', 'Nazario', 'Nigerian_Fraud', 'phishing_email', 'SpamAssassin']

for f in files:
    for ext in ['.csv', '.xlsx', '.xls']:
        if os.path.exists(f + ext):
            try:
                df = pd.read_csv(f + ext, nrows=2) if ext == '.csv' else pd.read_excel(f + ext, nrows=2)
                print(f"{f}{ext} -> {list(df.columns)}")
                print(f"  Sample: {df.iloc[0].to_dict()}\n")
            except Exception as e:
                print(f"{f}{ext} -> ERROR: {e}")
            break
    else:
        print(f"{f} -> NOT FOUND")