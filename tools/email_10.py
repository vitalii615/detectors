import pandas as pd

df = pd.read_csv('dataset\SpamAssasin.csv')

phishing_emails = df[df['label'] == 1].head(5)
print("\n=== 5 ФІШИНГОВИХ EMAIL ===")
for i, row in phishing_emails.iterrows():
    print(f"\n--- Email #{i+1} ---")
    print(f"Відправник: {row['sender']}")
    print(f"Тема: {row['subject']}")
    print(f"Перші 200 символів тіла:")
    print(row['body'][:200] + "...")

legit_emails = df[df['label'] == 0].head(5)
print("\n=== 5 ЛЕГІТИМНИХ EMAIL ===")
for i, row in legit_emails.iterrows():
    print(f"\n--- Email #{i+1} ---")
    print(f"Відправник: {row['sender']}")
    print(f"Тема: {row['subject']}")
    print(f"Перші 200 символів тіла:")
    print(row['body'][:200] + "...")

sample_data = pd.concat([phishing_emails, legit_emails])
sample_data.to_csv('email_sample_10.csv', index=False)