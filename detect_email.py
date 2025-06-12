import pandas as pd
import re
import urllib.parse
from typing import Dict, List, Tuple
import numpy as np

class PhishingDetector:
    def __init__(self):
        self.phishing_keywords = [
            'urgent', 'immediate', 'verify', 'confirm', 'suspended', 'expired', 
            'click here', 'act now', 'limited time', 'congratulations', 'winner',
            'free', 'prize', 'lottery', 'inheritance', 'million', 'dollars',
            'bank', 'account', 'security', 'update', 'login', 'password',
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'tax', 'refund', 'irs', 'government', 'legal action', 'court',
            'arrest', 'fine', 'penalty', 'debt', 'loan', 'credit'
        ]
        
        self.suspicious_domains = [
            '.tk', '.ml', '.ga', '.cf', '.bit', '.onion', '.temp-mail',
            'bit.ly', 'tinyurl', 'short.link', 't.co', 'goo.gl'
        ]
        
        self.suspicious_url_chars = ['@', '%', '-', '_']
        
    def analyze_url_features(self, urls_str: str) -> Dict[str, int]:
        """Аналіз URL на підозрілі характеристики"""
        features = {
            'suspicious_domains': 0,
            'long_urls': 0,
            'ip_addresses': 0,
            'suspicious_chars': 0,
            'url_shorteners': 0,
            'multiple_subdomains': 0
        }
        
        if pd.isna(urls_str) or not urls_str:
            return features
            
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(urls_str))
        
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                domain = parsed.netloc.lower()
                
                for suspicious in self.suspicious_domains:
                    if suspicious in domain:
                        features['suspicious_domains'] += 1
                        break
                
                if len(url) > 75:
                    features['long_urls'] += 1
                
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                if re.search(ip_pattern, domain):
                    features['ip_addresses'] += 1
                
                suspicious_count = sum(url.count(char) for char in self.suspicious_url_chars)
                if suspicious_count > 3:
                    features['suspicious_chars'] += 1
                
                shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'short.link']
                if any(shortener in domain for shortener in shorteners):
                    features['url_shorteners'] += 1
                
                subdomains = domain.split('.')
                if len(subdomains) > 4:
                    features['multiple_subdomains'] += 1
                    
            except Exception:
                continue
                
        return features
    
    def analyze_text_features(self, subject: str, body: str) -> Dict[str, int]:
        """Аналіз текстових характеристик"""
        features = {
            'phishing_keywords': 0,
            'urgency_words': 0,
            'financial_words': 0,
            'spelling_errors': 0,
            'excessive_caps': 0,
            'exclamation_marks': 0
        }
        
        text = f"{subject or ''} {body or ''}".lower()
        
        for keyword in self.phishing_keywords:
            if keyword in text:
                features['phishing_keywords'] += 1
        
        urgency_words = ['urgent', 'immediate', 'asap', 'hurry', 'quickly', 'now', 'today']
        features['urgency_words'] = sum(1 for word in urgency_words if word in text)
        
        financial_words = ['money', 'bank', 'account', 'credit', 'payment', 'transfer', 'loan']
        features['financial_words'] = sum(1 for word in financial_words if word in text)
        
        if len(text) > 0:
            caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
            if caps_ratio > 0.3:
                features['excessive_caps'] = 1
        
        features['exclamation_marks'] = text.count('!')
        
        return features
    
    def analyze_sender_features(self, sender: str) -> Dict[str, int]:
        """Аналіз відправника"""
        features = {
            'suspicious_sender': 0,
            'domain_mismatch': 0,
            'free_email': 0
        }
        
        if pd.isna(sender) or not sender:
            return features
        
        sender = sender.lower()
        
        free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'mail.ru']
        if any(provider in sender for provider in free_providers):
            features['free_email'] = 1
        
        for suspicious in self.suspicious_domains:
            if suspicious in sender:
                features['suspicious_sender'] = 1
                break
        
        return features
    
    def calculate_phishing_score(self, features: Dict[str, int]) -> float:
        """Розрахунок балу фішингу на основі ваг характеристик"""
        weights = {
            'suspicious_domains': 0.25,
            'long_urls': 0.10,
            'ip_addresses': 0.20,
            'suspicious_chars': 0.08,
            'url_shorteners': 0.15,
            'multiple_subdomains': 0.12,
            'phishing_keywords': 0.20,
            'urgency_words': 0.15,
            'financial_words': 0.12,
            'spelling_errors': 0.05,
            'excessive_caps': 0.08,
            'exclamation_marks': 0.03,
            'suspicious_sender': 0.18,
            'domain_mismatch': 0.15,
            'free_email': 0.05
        }
        
        score = 0.0
        for feature, value in features.items():
            if feature in weights:
                score += weights[feature] * min(value, 3)  
        
        return min(score, 1.0) 
    
    def detect_phishing(self, row: pd.Series) -> Tuple[int, float, Dict]:
        """Основна функція детекції фішингу"""
        url_features = self.analyze_url_features(row.get('urls', ''))
        text_features = self.analyze_text_features(row.get('subject', ''), row.get('body', ''))
        sender_features = self.analyze_sender_features(row.get('sender', ''))
        
        all_features = {**url_features, **text_features, **sender_features}
        
        phishing_score = self.calculate_phishing_score(all_features)
        
        threshold = 0.54
        prediction = 1 if phishing_score >= threshold else 0
        
        return prediction, phishing_score, all_features

def main():
    try:
        df = pd.read_csv('dataset_email_phishing.csv')
        print(f"Файл успішно завантажено. Загальна кількість email: {len(df)}")
    except FileNotFoundError:
        print("Помилка: Файл 'email_sample_10.csv' не знайдено!")
        return
    except Exception as e:
        print(f"Помилка при читанні файлу: {e}")
        return
    
    detector = PhishingDetector()
    
    results = []
    detailed_analysis = []
    
    print("\nАналіз email:")
    print("-" * 80)
    
    for idx, row in df.iterrows():
        prediction, score, features = detector.detect_phishing(row)
        results.append(prediction)
        detailed_analysis.append({
            'index': idx,
            'prediction': prediction,
            'score': score,
            'actual': row.get('label', 0),
            'features': features
        })
        try:
            print(f"Email {idx + 1}:")
            print(f"  Відправник: {row.get('sender', 'N/A')[:50]}...")
            print(f"  Тема: {row.get('subject', 'N/A')[:60]}...")
            print(f"  Прогноз: {'ФІШИНГ' if prediction == 1 else 'ЛЕГІТИМНИЙ'}")
            print(f"  Бал ризику: {score:.3f}")
            print(f"  Реальна мітка: {'ФІШИНГ' if row.get('label', 0) == 1 else 'ЛЕГІТИМНИЙ'}")
            print()
        except:
            continue
    actual_labels = df['label'].tolist() if 'label' in df.columns else [0] * len(df)
    
    tp = sum(1 for i in range(len(results)) if results[i] == 1 and actual_labels[i] == 1)
    fp = sum(1 for i in range(len(results)) if results[i] == 1 and actual_labels[i] == 0)
    fn = sum(1 for i in range(len(results)) if results[i] == 0 and actual_labels[i] == 1)
    tn = sum(1 for i in range(len(results)) if results[i] == 0 and actual_labels[i] == 0)
    
    total_analyzed = len(df)
    predicted_phishing = sum(results)
    predicted_legitimate = total_analyzed - predicted_phishing
    actual_phishing = sum(actual_labels)
    actual_legitimate = total_analyzed - actual_phishing
    
    print("=" * 80)
    print("РЕЗУЛЬТАТИ АНАЛІЗУ")
    print("=" * 80)
    print(f"Загальна кількість проаналізованих email: {total_analyzed}")
    print(f"Прогнозовано як фішингові: {predicted_phishing}")
    print(f"Прогнозовано як легітимні: {predicted_legitimate}")
    print(f"Реально фішингових: {actual_phishing}")
    print(f"Реально легітимних: {actual_legitimate}")
    

if __name__ == "__main__":
    main()