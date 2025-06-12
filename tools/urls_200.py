import pandas as pd

df = pd.read_csv('dataset/dataset_phishing.csv')

phishing_rows = df[df['status'] == 'phishing'].head(100)
legit_rows = df[df['status'] == 'legitimate'].head(100)

selected_rows = pd.concat([phishing_rows, legit_rows], ignore_index=True)

selected_rows.to_csv('urls_200.csv', index=False)