import pandas as pd
import requests
import time
import json
from urllib.parse import urlparse
import hashlib
import base64
import os

from dotenv import load_dotenv

load_dotenv()

class PhishingDetector:
    def __init__(self):
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.urlvoid_api_key = os.getenv("URLVOID_API_KEY")
        
        self.virustotal_url = "https://www.virustotal.com/vtapi/v2/url/report"
        self.urlvoid_url = "http://api.urlvoid.com/1000/{}/host/{}"
        self.phishtank_url = "http://checkurl.phishtank.com/checkurl/"
        
        self.risk_thresholds = {
            'high_risk_score': 0.7,
            'medium_risk_score': 0.25,
            'suspicious_length': 75,
            'suspicious_dots': 4,
            'suspicious_hyphens': 3,
            'suspicious_subdomains': 3
        }
    
    def check_virustotal(self, url):
        """Перевірка URL через VirusTotal API"""
        try:
            params = {
                'apikey': self.virustotal_api_key,
                'resource': url
            }
            response = requests.get(self.virustotal_url, params=params, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:
                    positives = result.get('positives', 0)
                    total = result.get('total', 0)
                    if positives > 0:
                        return {'status': 'malicious', 'details': f'{positives}/{total} детекторів вважають небезпечним'}
                    else:
                        return {'status': 'safe', 'details': 'Не виявлено загроз'}
                else:
                    return {'status': 'unknown', 'details': 'URL не знайдений в базі'}
            else:
                return {'status': 'error', 'details': f'Помилка API: {response.status_code}'}
        except Exception as e:
            return {'status': 'error', 'details': f'Помилка запиту: {str(e)}'}
    
    def check_apivoid(self, url):
        """Перевірка URL через APIVoid URL Reputation API v2"""
        api_url = "https://api.apivoid.com/v2/url-reputation"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.urlvoid_api_key
        }
        payload = {"url": url}

        try:
            response = requests.post(api_url, headers=headers, json=payload, timeout=10)
        except Exception as e:
            return {'status': 'error', 'details': f'Помилка запиту: {e}'}

        if response.status_code != 200:
            error_msg = response.json().get("error", response.text)
            return {'status': 'error', 'details': f'API error {response.status_code}: {error_msg}'}

        data = response.json().get("data", {}).get("report", {})

        detections = data.get("domain_blacklist", {}).get("detections", 0)
        risk_score = data.get("risk_score", {}).get("result", 0)

        if detections > 0 or risk_score >= 70:
            verdict = 'malicious'
            details = f'{detections} детекцій, score={risk_score}'
        elif risk_score >= 40:
            verdict = 'suspicious'
            details = f'score={risk_score}'
        else:
            verdict = 'safe'
            details = f'clean, score={risk_score}'

        quota = response.headers.get("X-Service-Quota", "")

        return {
            'status': verdict,
            'details': details,
            'quota': quota
        }
    
    def check_phishtank(self, url):
        """Перевірка URL через PhishTank API"""
        try:
            data = {
                'url': url,
                'format': 'json'
            }
            
            response = requests.post(self.phishtank_url, data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('results', {}).get('in_database'):
                    if result['results'].get('valid'):
                        return {'status': 'malicious', 'details': 'URL знайдений в базі фішингу'}
                    else:
                        return {'status': 'safe', 'details': 'URL в базі, але не активний'}
                else:
                    return {'status': 'unknown', 'details': 'URL не знайдений в базі PhishTank'}
            else:
                return {'status': 'error', 'details': f'Помилка API: {response.status_code}'}
        except Exception as e:
            return {'status': 'error', 'details': f'Помилка запиту: {str(e)}'}
    
    def api_check(self, url):
        """Комплексна перевірка через всі API"""
        print(f"Перевірка URL через API: {url}")
        
        api_results = []
        
        print("  Перевірка VirusTotal...")
        vt_result = self.check_virustotal(url)
        api_results.append(('VirusTotal', vt_result))
        time.sleep(1)  # Затримка між запитами
        
        print("  Перевірка URLVoid...")
        uv_result = self.check_apivoid(url)
        api_results.append(('URLVoid', uv_result))
        time.sleep(1)
        
        print("  Перевірка PhishTank...")
        pt_result = self.check_phishtank(url)
        api_results.append(('PhishTank', pt_result))
        
        malicious_count = 0
        safe_count = 0
        
        for api_name, result in api_results:
            print(f"    {api_name}: {result['status']} - {result['details']}")
            if result['status'] == 'malicious':
                malicious_count += 1
            elif result['status'] == 'safe':
                safe_count += 1
        
        if malicious_count > 0:
            return {'verdict': 'malicious', 'confidence': 'high', 'source': 'API', 'details': api_results}
        elif safe_count >= 2:  
            return {'verdict': 'safe', 'confidence': 'medium', 'source': 'API', 'details': api_results}
        else:
            return {'verdict': 'unknown', 'confidence': 'low', 'source': 'API', 'details': api_results}
    
    def heuristic_analysis(self, row):
        """Евристичний аналіз на основі параметрів з CSV"""
        print("Проведення евристичного аналізу...")
        
        risk_score = 0.0
        risk_factors = []
        
        if row['length_url'] > self.risk_thresholds['suspicious_length']:
            risk_score += 0.1
            risk_factors.append(f"Підозріла довжина URL: {row['length_url']}")
        
        if row['nb_dots'] > self.risk_thresholds['suspicious_dots']:
            risk_score += 0.15
            risk_factors.append(f"Багато крапок в URL: {row['nb_dots']}")
        
        if row['nb_hyphens'] > self.risk_thresholds['suspicious_hyphens']:
            risk_score += 0.1
            risk_factors.append(f"Багато дефісів: {row['nb_hyphens']}")
        
        if row['ip'] == 1:
            risk_score += 0.2
            risk_factors.append("Використовується IP замість домену")
        
        if row['nb_at'] > 0:
            risk_score += 0.15
            risk_factors.append("Присутній символ @ в URL")
        
        if row['shortening_service'] == 1:
            risk_score += 0.25
            risk_factors.append("Використовується сервіс скорочення URL")
        
        if row['nb_subdomains'] > self.risk_thresholds['suspicious_subdomains']:
            risk_score += 0.1
            risk_factors.append(f"Багато субдоменів: {row['nb_subdomains']}")
        
        if row['prefix_suffix'] == 1:
            risk_score += 0.15
            risk_factors.append("Підозрілий префікс-суфікс в домені")
        
        if row['random_domain'] == 1:
            risk_score += 0.2
            risk_factors.append("Підозріло випадковий домен")
        
        if row['login_form'] == 1:
            risk_score += 0.1
            risk_factors.append("Наявна форма для входу")
        
        if row['suspecious_tld'] == 1:
            risk_score += 0.15
            risk_factors.append("Підозрілий домен верхнього рівня")
        
        if row['phish_hints'] > 0:
            risk_score += 0.3
            risk_factors.append(f"Виявлено фішинг підказки: {row['phish_hints']}")
        
        if row['domain_age'] < 30:  
            risk_score += 0.1
            risk_factors.append(f"Молодий домен: {row['domain_age']} днів")
        
        if row['google_index'] == 0:
            risk_score += 0.05
            risk_factors.append("Сайт не індексується Google")
        
        if risk_score >= self.risk_thresholds['high_risk_score']:
            verdict = 'malicious'
            confidence = 'high'
        elif risk_score >= self.risk_thresholds['medium_risk_score']:
            verdict = 'suspicious'
            confidence = 'medium'
        else:
            verdict = 'safe'
            confidence = 'low'
        
        print(f"  Загальний рейтинг ризику: {risk_score:.2f}")
        for factor in risk_factors:
            print(f"    {factor}")
        
        return {
            'verdict': verdict,
            'confidence': confidence,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'source': 'heuristic'
        }
    
    def analyze_urls(self, csv_file_path):
        """Основна функція аналізу URL з CSV файлу"""
        print("Запуск детектора фішингових атак")
        print("=" * 50)
        
        try:
            df = pd.read_csv(csv_file_path)
            print(f"Завантажено {len(df)} URLs для аналізу")
        except Exception as e:
            print(f"Помилка читання файлу: {e}")
            return
        
        results = []
        
        for index, row in df.iterrows():
            print(f"\n{'='*60}")
            print(f"Аналіз URL #{index + 1}: {row['url']}")
            print(f"{'='*60}")
            
            api_result = self.api_check(row['url'])
            
            final_verdict = None
            final_confidence = None
            final_details = {}
            
            if api_result['verdict'] == 'malicious':
                final_verdict = 'НЕБЕЗПЕЧНИЙ'
                final_confidence = 'ВИСОКА'
                final_details = {
                    'primary_source': 'API виявив загрозу',
                    'api_results': api_result['details']
                }
                print("ВИСНОВОК: URL НЕБЕЗПЕЧНИЙ (виявлено API)")
            else:
                print(f"\n{'─'*40}")
                heuristic_result = self.heuristic_analysis(row)
                
                if heuristic_result['verdict'] == 'malicious':
                    final_verdict = 'НЕБЕЗПЕЧНИЙ'
                    final_confidence = 'ВИСОКА'
                elif heuristic_result['verdict'] == 'suspicious':
                    final_verdict = 'ПІДОЗРІЛИЙ'
                    final_confidence = 'СЕРЕДНЯ'
                else:
                    final_verdict = 'БЕЗПЕЧНИЙ'
                    final_confidence = 'НИЗЬКА'
                
                final_details = {
                    'primary_source': 'Евристичний аналіз',
                    'api_results': api_result['details'],
                    'heuristic_score': heuristic_result['risk_score'],
                    'risk_factors': heuristic_result['risk_factors']
                }
                
                print(f"ВИСНОВОК: URL {final_verdict} (на основі евристики)")
            
            actual_status = row.get('status', 'unknown')
            is_correct = 'Невідомо'
            if actual_status != 'unknown':
                predicted_malicious = final_verdict in ['НЕБЕЗПЕЧНИЙ', 'ПІДОЗРІЛИЙ']
                actual_malicious = actual_status == 'phishing'
                is_correct = 'ТАК' if predicted_malicious == actual_malicious else 'НІ'
            
            result = {
                'url': row['url'],
                'prediction': final_verdict,
                'confidence': final_confidence,
                'actual_status': actual_status,
                'correct_prediction': is_correct,
                'details': final_details
            }
            
            results.append(result)
            
            print(f"Реальний статус: {actual_status}")
            print(f"Правильно передбачено: {is_correct}")
            print(f"Рівень впевненості: {final_confidence}")
        
        self.print_summary(results)
        return results
    
    def print_summary(self, results):
        """Виведення підсумкової статистики"""
        print(f"\n{'='*60}")
        print("ПІДСУМКОВА СТАТИСТИКА")
        print(f"{'='*60}")
        
        total = len(results)
        dangerous = len([r for r in results if r['prediction'] == 'НЕБЕЗПЕЧНИЙ'])
        suspicious = len([r for r in results if r['prediction'] == 'ПІДОЗРІЛИЙ'])
        safe = len([r for r in results if r['prediction'] == 'БЕЗПЕЧНИЙ'])

        correct_predictions = len([r for r in results if r['correct_prediction'] == 'ТАК'])
        accuracy = (correct_predictions / total * 100) if total > 0 else 0

        print(f"Загалом проаналізовано: {total} URLs")
        print(f"Небезпечних: {dangerous}")
        print(f"Підозрілих: {suspicious}")
        print(f"Безпечних: {safe}")
        print(f"Точність передбачень: {accuracy:.1f}%")

        tp = fp = fn = tn = 0
        for r in results:
            actual = r['actual_status']
            predicted = r['prediction']
            if actual == 'unknown':
                continue

            predicted_malicious = predicted in ['НЕБЕЗПЕЧНИЙ', 'ПІДОЗРІЛИЙ']
            actual_malicious = actual == 'phishing'

            if predicted_malicious and actual_malicious:
                tp += 1
            elif predicted_malicious and not actual_malicious:
                fp += 1
            elif not predicted_malicious and actual_malicious:
                fn += 1
            elif not predicted_malicious and not actual_malicious:
                tn += 1


if __name__ == "__main__":
    detector = PhishingDetector()
    
    csv_path = "urls_200.csv"
    
    results = detector.analyze_urls(csv_path)