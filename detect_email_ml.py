import pandas as pd
import numpy as np
import re
import urllib.parse
from typing import Dict, List, Tuple, Optional
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import warnings
warnings.filterwarnings('ignore')

class PhishingFeatureExtractor:
    """Клас для витягування ознак з email для детекції фішингу"""
    
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
        self.scaler = StandardScaler()
        self.feature_selector = SelectKBest(f_classif, k=15)
        
    def analyze_url_features(self, urls_str: str) -> Dict[str, float]:
        """Аналіз URL на підозрілі характеристики"""
        features = {
            'suspicious_domains': 0,
            'long_urls': 0,
            'ip_addresses': 0,
            'suspicious_chars': 0,
            'url_shorteners': 0,
            'multiple_subdomains': 0,
            'url_count': 0
        }
        
        if pd.isna(urls_str) or not urls_str:
            return features
            
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(urls_str))
        features['url_count'] = len(urls)
        
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                domain = parsed.netloc.lower()
                
                # Підозрілі домени
                for suspicious in self.suspicious_domains:
                    if suspicious in domain:
                        features['suspicious_domains'] += 1
                        break
                
                # Довгі URL
                if len(url) > 75:
                    features['long_urls'] += 1
                
                # IP адреси
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                if re.search(ip_pattern, domain):
                    features['ip_addresses'] += 1
                
                # Підозрілі символи
                suspicious_count = sum(url.count(char) for char in self.suspicious_url_chars)
                if suspicious_count > 3:
                    features['suspicious_chars'] += 1
                
                # Скорочувачі URL
                shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'short.link']
                if any(shortener in domain for shortener in shorteners):
                    features['url_shorteners'] += 1
                
                # Множинні субдомени
                subdomains = domain.split('.')
                if len(subdomains) > 4:
                    features['multiple_subdomains'] += 1
                    
            except Exception:
                continue
                
        return features
    
    def analyze_text_features(self, subject: str, body: str) -> Dict[str, float]:
        """Аналіз текстових характеристик"""
        features = {
            'phishing_keywords': 0,
            'urgency_words': 0,
            'financial_words': 0,
            'excessive_caps': 0,
            'exclamation_marks': 0,
            'text_length': 0,
            'caps_ratio': 0,
            'special_chars_ratio': 0
        }
        
        text = f"{subject or ''} {body or ''}".lower()
        features['text_length'] = len(text)
        
        # Ключові слова фішингу
        for keyword in self.phishing_keywords:
            if keyword in text:
                features['phishing_keywords'] += 1
        
        # Слова терміновості
        urgency_words = ['urgent', 'immediate', 'asap', 'hurry', 'quickly', 'now', 'today']
        features['urgency_words'] = sum(1 for word in urgency_words if word in text)
        
        # Фінансові слова
        financial_words = ['money', 'bank', 'account', 'credit', 'payment', 'transfer', 'loan']
        features['financial_words'] = sum(1 for word in financial_words if word in text)
        
        # Аналіз заголовних літер
        if len(text) > 0:
            features['caps_ratio'] = sum(1 for c in text if c.isupper()) / len(text)
            if features['caps_ratio'] > 0.3:
                features['excessive_caps'] = 1
        
        # Знаки оклику
        features['exclamation_marks'] = text.count('!')
        
        # Спеціальні символи
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        features['special_chars_ratio'] = special_chars / len(text) if len(text) > 0 else 0
        
        return features
    
    def analyze_sender_features(self, sender: str) -> Dict[str, float]:
        """Аналіз відправника"""
        features = {
            'suspicious_sender': 0,
            'free_email': 0,
            'sender_length': 0,
            'has_numbers_in_sender': 0
        }
        
        if pd.isna(sender) or not sender:
            return features
        
        sender = sender.lower()
        features['sender_length'] = len(sender)
        
        # Безкоштовні провайдери
        free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'mail.ru']
        if any(provider in sender for provider in free_providers):
            features['free_email'] = 1
        
        # Підозрілі домени
        for suspicious in self.suspicious_domains:
            if suspicious in sender:
                features['suspicious_sender'] = 1
                break
        
        # Цифри в адресі відправника
        if re.search(r'\d', sender):
            features['has_numbers_in_sender'] = 1
        
        return features
    
    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Витягування всіх ознак з датасету"""
        feature_list = []
        
        for idx, row in df.iterrows():
            url_features = self.analyze_url_features(row.get('urls', ''))
            text_features = self.analyze_text_features(row.get('subject', ''), row.get('body', ''))
            sender_features = self.analyze_sender_features(row.get('sender', ''))
            
            all_features = {**url_features, **text_features, **sender_features}
            feature_list.append(all_features)
        
        features_df = pd.DataFrame(feature_list)
        return features_df

class PhishingMLModel:
    """Модель машинного навчання для детекції фішингу"""
    
    def __init__(self):
        self.feature_extractor = PhishingFeatureExtractor()
        self.models = {}
        self.ensemble_model = None
        self.is_trained = False
        
    def prepare_models(self):
        """Підготовка різних моделей для навчання"""
        self.models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100, 
                max_depth=10, 
                random_state=42,
                class_weight='balanced'
            ),
            'Logistic Regression': LogisticRegression(
                random_state=42, 
                max_iter=1000,
                class_weight='balanced'
            ),
            'Gradient Boosting': GradientBoostingClassifier(
                n_estimators=100, 
                learning_rate=0.1, 
                random_state=42
            ),
            'SVM': SVC(
                kernel='rbf', 
                probability=True, 
                random_state=42,
                class_weight='balanced'
            ),
            'Naive Bayes': GaussianNB()
        }
    
    def train(self, df: pd.DataFrame, target_column: str = 'label'):
        """Навчання моделі"""
        print("Витягування ознак...")
        features_df = self.feature_extractor.extract_features(df)
        
        if target_column not in df.columns:
            raise ValueError(f"Колонка '{target_column}' не знайдена в датасеті")
        
        X = features_df
        y = df[target_column]
        
        print(f"Розмір датасету: {X.shape}")
        print(f"Розподіл класів: {y.value_counts().to_dict()}")
        
        # Розділення на тренувальну та тестову вибірки
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Нормалізація ознак
        X_train_scaled = self.feature_extractor.scaler.fit_transform(X_train)
        X_test_scaled = self.feature_extractor.scaler.transform(X_test)
        
        # Вибір найкращих ознак
        X_train_selected = self.feature_extractor.feature_selector.fit_transform(X_train_scaled, y_train)
        X_test_selected = self.feature_extractor.feature_selector.transform(X_test_scaled)
        
        # Підготовка моделей
        self.prepare_models()
        
        # Навчання та оцінка кожної моделі
        model_scores = {}
        trained_models = {}
        
        print("\nНавчання моделей...")
        for name, model in self.models.items():
            print(f"Навчання {name}...")
            
            # Крос-валідація
            cv_scores = cross_val_score(model, X_train_selected, y_train, cv=5, scoring='f1')
            model_scores[name] = cv_scores.mean()
            
            # Навчання на повному тренувальному наборі
            model.fit(X_train_selected, y_train)
            trained_models[name] = model
            
            # Оцінка на тестовому наборі
            y_pred = model.predict(X_test_selected)
            print(f"{name} - F1 Score: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
        
        # Створення ансамблевої моделі з найкращих моделей
        best_models = sorted(model_scores.items(), key=lambda x: x[1], reverse=True)[:3]
        ensemble_estimators = [(name, trained_models[name]) for name, _ in best_models]
        
        self.ensemble_model = VotingClassifier(
            estimators=ensemble_estimators,
            voting='soft'
        )
        self.ensemble_model.fit(X_train_selected, y_train)
        
        # Оцінка ансамблевої моделі
        y_pred_ensemble = self.ensemble_model.predict(X_test_selected)
        y_pred_proba = self.ensemble_model.predict_proba(X_test_selected)[:, 1]
        
        print(f"\nАнсамблева модель (топ-3):")
        print(f"Моделі в ансамблі: {[name for name, _ in best_models]}")
        print("\nЗвіт класифікації:")
        print(classification_report(y_test, y_pred_ensemble))
        
        print("\nМатриця плутанини:")
        cm = confusion_matrix(y_test, y_pred_ensemble)
        print(cm)
        
        # ROC AUC
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        print(f"\nROC AUC Score: {roc_auc:.3f}")
        
        # Важливість ознак (для Random Forest)
        if 'Random Forest' in trained_models:
            feature_names = features_df.columns
            selected_features = self.feature_extractor.feature_selector.get_support()
            selected_feature_names = feature_names[selected_features]
            
            rf_model = trained_models['Random Forest']
            feature_importance = pd.DataFrame({
                'feature': selected_feature_names,
                'importance': rf_model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            print(f"\nТоп-10 найважливіших ознак:")
            print(feature_importance.head(10))
        
        self.is_trained = True
        self.X_test = X_test_selected
        self.y_test = y_test
        self.feature_names = features_df.columns
        
        return {
            'model_scores': model_scores,
            'best_models': best_models,
            'roc_auc': roc_auc,
            'feature_importance': feature_importance if 'Random Forest' in trained_models else None
        }
    
    def predict(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Прогнозування для нових даних"""
        if not self.is_trained:
            raise ValueError("Модель не навчена! Спочатку викличте метод train()")
        
        features_df = self.feature_extractor.extract_features(df)
        X_scaled = self.feature_extractor.scaler.transform(features_df)
        X_selected = self.feature_extractor.feature_selector.transform(X_scaled)
        
        predictions = self.ensemble_model.predict(X_selected)
        probabilities = self.ensemble_model.predict_proba(X_selected)[:, 1]
        
        return predictions, probabilities
    
    def save_model(self, filepath: str):
        """Збереження навченої моделі"""
        if not self.is_trained:
            raise ValueError("Модель не навчена!")
        
        model_data = {
            'ensemble_model': self.ensemble_model,
            'feature_extractor': self.feature_extractor,
            'feature_names': self.feature_names
        }
        joblib.dump(model_data, filepath)
        print(f"Модель збережена в {filepath}")
    
    def load_model(self, filepath: str):
        """Завантаження навченої моделі"""
        model_data = joblib.load(filepath)
        self.ensemble_model = model_data['ensemble_model']
        self.feature_extractor = model_data['feature_extractor']
        self.feature_names = model_data['feature_names']
        self.is_trained = True
        print(f"Модель завантажена з {filepath}")
    
    def plot_feature_importance(self, top_n: int = 15):
        """Візуалізація важливості ознак"""
        if not hasattr(self, 'feature_importance') or self.feature_importance is None:
            print("Інформація про важливість ознак недоступна")
            return
        
        plt.figure(figsize=(10, 8))
        top_features = self.feature_importance.head(top_n)
        
        sns.barplot(data=top_features, y='feature', x='importance')
        plt.title(f'Топ-{top_n} найважливіших ознак')
        plt.xlabel('Важливість')
        plt.ylabel('Ознаки')
        plt.tight_layout()
        plt.show()
    
    def plot_confusion_matrix(self):
        """Візуалізація матриці плутанини"""
        if not self.is_trained:
            print("Модель не навчена!")
            return
        
        y_pred = self.ensemble_model.predict(self.X_test)
        cm = confusion_matrix(self.y_test, y_pred)
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title('Матриця плутанини')
        plt.xlabel('Прогнозовані мітки')
        plt.ylabel('Реальні мітки')
        plt.show()

def main():
    """Основна функція для запуску навчання моделі"""
    try:
        # Завантаження даних
        print("Завантаження даних...")
        df = pd.read_csv('dataset_email_phishing.csv')
        print(f"Дані завантажено успішно. Розмір: {df.shape}")
        
        # Перевірка наявності необхідних колонок
        required_columns = ['label']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            print(f"Відсутні необхідні колонки: {missing_columns}")
            return
        
        # Створення та навчання моделі
        model = PhishingMLModel()
        results = model.train(df, target_column='label')
        
        # Збереження моделі
        model.save_model('phishing_detection_model.pkl')
        
        # Демонстрація прогнозування
        print("\n" + "="*50)
        print("ДЕМОНСТРАЦІЯ ПРОГНОЗУВАННЯ")
        print("="*50)
        
        # Приклад прогнозування на тестових даних
        sample_data = df.sample(5)
        predictions, probabilities = model.predict(sample_data)
        
        for i, (idx, row) in enumerate(sample_data.iterrows()):
            print(f"\nEmail {i+1}:")
            print(f"Відправник: {row.get('sender', 'N/A')[:50]}...")
            print(f"Тема: {row.get('subject', 'N/A')[:60]}...")
            print(f"Прогноз: {'ФІШИНГ' if predictions[i] == 1 else 'ЛЕГІТИМНИЙ'}")
            print(f"Ймовірність фішингу: {probabilities[i]:.3f}")
            print(f"Реальна мітка: {'ФІШИНГ' if row['label'] == 1 else 'ЛЕГІТИМНИЙ'}")
        
        print(f"\nМодель успішно навчена та збережена!")
        
    except FileNotFoundError:
        print("Помилка: Файл 'dataset_email_phishing.csv' не знайдено!")
        print("Переконайтеся, що файл знаходиться в тій же директорії.")
    except Exception as e:
        print(f"Помилка: {e}")

if __name__ == "__main__":
    main()