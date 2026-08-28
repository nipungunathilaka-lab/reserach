import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

def generate_synthetic_data(n_samples=1000):
    """
    Generates synthetic file feature data for malware detection.
    Features:
    - file_size: Size of the file in bytes.
    - entropy: Shannon entropy (0 to 8). Malware often has high entropy due to packing/encryption.
    - suspicious_byte_ratio: Ratio of suspicious bytes (nulls, specific hex patterns).
    - executable_headers: Binary flag (0 or 1) indicating presence of MZ/ELF headers in non-exe files.
    """
    np.random.seed(42)
    
    # Generate base features
    file_size = np.random.lognormal(mean=12, sigma=2, size=n_samples) # sizes up to a few MB
    entropy = np.random.uniform(low=1.0, high=8.0, size=n_samples)
    suspicious_byte_ratio = np.random.beta(a=1, b=10, size=n_samples) # mostly low ratio
    executable_headers = np.random.choice([0, 1], p=[0.9, 0.1], size=n_samples)
    
    df = pd.DataFrame({
        'file_size': file_size,
        'entropy': entropy,
        'suspicious_byte_ratio': suspicious_byte_ratio,
        'executable_headers': executable_headers
    })
    
    # Define a logical rule to probabilistically label as malicious (1) or benign (0)
    # E.g., High entropy AND (some suspicious bytes OR wrong executable headers)
    # We add some noise to make the model learn rather than memorize a strict rule.
    
    # Base probability
    prob = np.zeros(n_samples)
    
    # Factors increasing probability
    prob += (df['entropy'] > 7.0).astype(float) * 0.4
    prob += (df['suspicious_byte_ratio'] > 0.1).astype(float) * 0.3
    prob += (df['executable_headers'] == 1).astype(float) * 0.3
    
    # Add random noise
    noise = np.random.normal(0, 0.1, size=n_samples)
    prob = np.clip(prob + noise, 0, 1)
    
    # Label mapping threshold
    df['is_malicious'] = (prob > 0.6).astype(int)
    
    return df

def train_model():
    print("Generating synthetic dataset (1000 rows)...")
    df = generate_synthetic_data(1000)
    
    print(f"Dataset target distribution:\n{df['is_malicious'].value_counts(normalize=True) * 100}%")
    
    X = df[['file_size', 'entropy', 'suspicious_byte_ratio', 'executable_headers']]
    y = df['is_malicious']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("\nTraining RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=5)
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"\nModel Accuracy: {acc * 100:.2f}%")
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save the model
    model_path = os.path.join(os.path.dirname(__file__), 'malware_model.joblib')
    joblib.dump(clf, model_path)
    print(f"\nModel successfully saved to: {model_path}")

if __name__ == "__main__":
    train_model()
