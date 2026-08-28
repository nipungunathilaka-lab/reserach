import time
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from app.services.ai_service import AIService

def run_ai_evaluation():
   
    print("RUNNING AI MODEL EVALUATION (Isolation Forest)")
   
    
    # 1. Load or generate the dataset
    dataset_path = AIService.training_dataset_path()
    df = pd.read_csv(dataset_path)
    
    # Ensure model is trained
    AIService.ensure_model()
    
    # Extract features and true labels
    from app.services.ai_service import FEATURES
    x = df[FEATURES].astype(float).fillna(0)
    
    # True labels in dataset: 'is_anomaly' (1 for anomaly, 0 for normal)
    y_true = df["is_anomaly"].values if "is_anomaly" in df.columns else np.zeros(len(df))
    
    # Model predictions (-1 for anomaly, 1 for normal in IsolationForest -> convert to 0 and 1)
    preds = AIService._model.predict(x)
    y_pred = [1 if p == -1 else 0 for p in preds]
    
    # Calculate metrics
    acc = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    
    print(f"Dataset Size Evaluated: {len(df)} rows")
    print(f"Accuracy  : {acc * 100:.2f}%")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1-Score  : {f1:.4f}")
   

if __name__ == "__main__":
    run_ai_evaluation()