import os
import time
import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from app.services.ai_service import AIService
from app.security.privacy.differential_privacy import DifferentialPrivacyService, PrivacyBudgetAccountant
from app.security.privacy.config import dp_settings

RESULTS_DIR = Path("tests/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def evaluate_model(x_df, y_true, name):
    preds = AIService._model.predict(x_df)
    y_pred = [1 if p == -1 else 0 for p in preds]
    
    acc = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    
    # cm: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0,0,0,0)
    
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    print(f"\n--- {name.upper()} ---")
    print(f"Accuracy  : {acc * 100:.2f}%")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1-Score  : {f1:.4f}")
    print(f"TP: {tp}, TN: {tn}, FP: {fp}, FN (Missed Anomalies): {fn}")
    print(f"False Positive Rate: {fpr:.4f}")
    print(f"False Negative Rate: {fnr:.4f}")
    
    results = {
        "evaluation_name": name,
        "timestamp": time.time(),
        "metrics": {
            "accuracy": float(acc),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "true_positives": int(tp),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "false_positive_rate": float(fpr),
            "false_negative_rate": float(fnr)
        },
        "dataset_provenance": AIService.model_provenance
    }
    
    with open(RESULTS_DIR / f"ai_evaluation_{name.lower().replace(' ', '_')}.json", "w") as f:
        json.dump(results, f, indent=2)
        
    return results

def run_ai_evaluation():
    print("RUNNING AI MODEL EVALUATION (Isolation Forest)")
    
    dataset_path = AIService.training_dataset_path()
    df = pd.read_csv(dataset_path)
    
    AIService.ensure_model()
    from app.services.ai_service import FEATURES
    x_baseline = df[FEATURES].astype(float).fillna(0)
    y_true = df["is_anomaly"].values if "is_anomaly" in df.columns else np.zeros(len(df))
    
    evaluate_model(x_baseline, y_true, "Baseline")
    
    # Now evaluate with DP
    print("\nApplying Differential Privacy to test set...")
    PrivacyBudgetAccountant.reset_for_tests()
    dp_settings.dp_enabled = True
    
    dp_rows = []
    for idx, row in df.iterrows():
        raw_features = row[FEATURES].to_dict()
        try:
            dp_res = DifferentialPrivacyService.privatize_features("test_user", f"test_{idx}", raw_features)
            dp_rows.append(dp_res.features)
        except Exception:
            # If budget exhausted in test, just use raw for remaining to simulate fail-closed or reset
            PrivacyBudgetAccountant.reset_for_tests()
            dp_res = DifferentialPrivacyService.privatize_features("test_user", f"test_{idx}", raw_features)
            dp_rows.append(dp_res.features)

    x_dp = pd.DataFrame(dp_rows)[FEATURES].astype(float).fillna(0)
    evaluate_model(x_dp, y_true, "DP Enabled")

if __name__ == "__main__":
    run_ai_evaluation()