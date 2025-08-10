import pandas as pd
import re
import numpy as np
from urllib.parse import urlparse
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, classification_report, 
                           confusion_matrix, ConfusionMatrixDisplay)
import matplotlib.pyplot as plt
import seaborn as sns
import pickle


def entropy(s):
    """Calculate Shannon entropy of a string"""
    if not s:  # Handle empty strings
        return 0
    try:
        p = np.array(list(s))
        _, counts = np.unique(p, return_counts=True)
        probabilities = counts / len(s)
        return -np.sum(probabilities * np.log2(probabilities))
    except:
        return 0  

def extract_features(url):
    """Extract phishing indicators from URL"""
    features = {}
    
    # Basic URL metrics
    features['length'] = len(url)
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_special'] = len(re.findall(r'[^\w\s]', url))
    
    # Domain analysis
    try:
        domain = urlparse(url).netloc
        features['domain_length'] = len(domain)
        features['subdomain_depth'] = domain.count('.')
        features['has_ip'] = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain)))
    except:
        features['domain_length'] = 0
        features['subdomain_depth'] = 0
        features['has_ip'] = 0
    
    # Security indicators
    features['https'] = int(url.lower().startswith('https'))
    features['port'] = urlparse(url).port if urlparse(url).port else 0
    
    # Content analysis
    features['entropy'] = entropy(url.lower())
    features['sus_keywords'] = sum(1 for kw in ['login', 'secure', 'account'] if kw in url.lower())
    
    return features


def generate_dataset():
    """Create balanced dataset with safe/phishing URLs"""
    data = {
        'url': [
            # Safe URLs
            'https://www.google.com',
            'https://www.amazon.com',
            'https://www.microsoft.com',
            'https://www.apple.com',
            'https://www.paypal.com',
            
            # Phishing URLs
            'http://fake-facebook-login.xyz',
            'https://secure-payment-update.net',
            'http://steal-info-now.com',
            'http://verify-bank-account.co.uk',
            'https://icloud-locked.help'
        ],
        'status': [0,0,0,0,0,1,1,1,1,1]  # 0=Safe, 1=Phishing
    }
    return pd.DataFrame(data)

def train_model(df):
    """Complete ML workflow"""

    print("🔍 Extracting features...")
    X = df['url'].apply(lambda x: pd.Series(extract_features(x)))
    y = df['status']
    
   
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )
    
  
    print("🤖 Training classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
   
    print("📊 Evaluating model...")
    y_pred = model.predict(X_test)
    
 
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Safe', 'Phishing'])
    
    
    cm = confusion_matrix(y_test, y_pred)
    ConfusionMatrixDisplay(cm).plot()
    plt.title('Confusion Matrix')
    plt.savefig('confusion_matrix.png')
    plt.close()
    
    return model, accuracy, report

# ==================== MAIN EXECUTION ====================
if __name__ == '__main__':
    print("🛠️ Generating dataset...")
    df = generate_dataset()
    
    
    model, accuracy, report = train_model(df)
    
   
    with open('phishing_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    
    # Results
    print("\n✅ Results:")
    print(f"Accuracy: {accuracy:.2%}")
    print("\nClassification Report:")
    print(report)
    
    # Example predictions
    test_urls = [
        ('https://www.linkedin.com', 0),
        ('http://linkedin-login.xyz', 1),
        ('https://www.bankofamerica.com', 0),
        ('http://bank-account-verify.net', 1)
    ]
    
    print("\n🔮 Test Predictions:")
    print(f"{'URL':<40} {'Prediction':<12} {'True Label':<12} {'Confidence':<12}")
    print("="*80)
    for url, true_label in test_urls:
        features = pd.DataFrame([extract_features(url)])
        pred = model.predict(features)[0]
        proba = model.predict_proba(features)[0][1]
        print(f"{url:<40} → {'Phishing' if pred else 'Safe':<12} "
              f"{'Phishing' if true_label else 'Safe':<12} "
              f"{proba:.2%}")
