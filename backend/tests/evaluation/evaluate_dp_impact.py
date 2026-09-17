import os
import time
import json
import uuid
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

from app.services.ai_service import AIService
from app.security.privacy.differential_privacy import DifferentialPrivacyService, PrivacyBudgetAccountant
from app.security.privacy.config import dp_settings

# Hard mock for evaluation to avoid requiring live Redis
PrivacyBudgetAccountant.consume_budget = classmethod(lambda cls, user_id, epsilon, analysis_id=None: 10.0)
PrivacyBudgetAccountant.reset_for_tests = classmethod(lambda cls: None)

RESULTS_DIR = Path("tests/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def calculate_metrics(y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0,0,0,0)
    
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    return {
        "Accuracy": float(acc),
        "Precision": float(precision),
        "Recall": float(recall),
        "F1": float(f1),
        "TP": int(tp),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "Specificity": float(specificity),
        "FPR": float(fpr),
        "FNR": float(fnr)
    }

def run_dp_evaluation():
    print("RUNNING AI MODEL EVALUATION WITH DIFFERENTIAL PRIVACY")
    
    dataset_path = AIService.training_dataset_path()
    df = pd.read_csv(dataset_path)
    
    AIService.ensure_model()
    from app.services.ai_service import FEATURES
    x_baseline = df[FEATURES].astype(float).fillna(0)
    y_true = df["is_anomaly"].values if "is_anomaly" in df.columns else np.zeros(len(df))
    
    # 1. DP OFF (Baseline)
    preds_off = AIService._model.predict(x_baseline)
    y_pred_off = [1 if p == -1 else 0 for p in preds_off]
    metrics_off = calculate_metrics(y_true, y_pred_off)
    
    print("\nDP OFF METRICS:")
    print(metrics_off)
    
    # Save canonical run for DP OFF confusion matrix
    cm_off_df = pd.DataFrame(confusion_matrix(y_true, y_pred_off, labels=[0, 1]))
    cm_off_df.to_csv(RESULTS_DIR / "dp_confusion_matrix_off.csv", index=False)
    
    epsilons = [0.1, 0.25, 0.5]
    trials = 30
    dp_settings.dp_enabled = True
    
    epsilon_stats = {}
    
    for eps in epsilons:
        dp_settings.dp_epsilon_per_analysis = eps
        print(f"\n======================================")
        print(f"Running {trials} DP ON trials for Epsilon = {eps}...")
        
        all_metrics = {k: [] for k in metrics_off.keys()}
        
        for trial in range(trials):
            np.random.seed(trial) 
            PrivacyBudgetAccountant.reset_for_tests()
            
            dp_rows = []
            for idx, row in df.iterrows():
                raw_features = row[FEATURES].to_dict()
                analysis_id = str(uuid.uuid4())
                try:
                    dp_res = DifferentialPrivacyService.privatize_features("test_user", f"test_{idx}", raw_features, analysis_id=analysis_id)
                    dp_rows.append(dp_res.features)
                except Exception:
                    dp_res = DifferentialPrivacyService.privatize_features("test_user", f"test_{idx}", raw_features, analysis_id=analysis_id)
                    dp_rows.append(dp_res.features)
            
            x_dp = pd.DataFrame(dp_rows)[FEATURES].astype(float).fillna(0)
            preds_on = AIService._model.predict(x_dp)
            y_pred_on = [1 if p == -1 else 0 for p in preds_on]
            
            m_on = calculate_metrics(y_true, y_pred_on)
            for k, v in m_on.items():
                all_metrics[k].append(v)
                
            if trial == 0:
                # Save canonical seeded run for confusion matrix
                cm_on_df = pd.DataFrame(confusion_matrix(y_true, y_pred_on, labels=[0, 1]))
                cm_on_df.to_csv(RESULTS_DIR / f"dp_confusion_matrix_on_eps_{eps}.csv", index=False)
        
        # Calculate stats for this epsilon
        dp_on_stats = {}
        for k in metrics_off.keys():
            arr = np.array(all_metrics[k])
            dp_on_stats[k] = {
                "mean": float(arr.mean()),
                "std": float(arr.std()),
                "min": float(arr.min()),
                "max": float(arr.max())
            }
            
        epsilon_stats[eps] = dp_on_stats
        
        print(f"\nDP ON METRICS (Epsilon={eps}):")
        for k, v in dp_on_stats.items():
            print(f"{k}: Mean={v['mean']:.4f} Std={v['std']:.4f}")

    # Generate massive comparison table
    print("\n--- COMPARISON TABLE ---")
    header = "| Metric | DP OFF |" + "".join([f" Eps {e} Mean | Eps {e} Std |" for e in epsilons])
    print(header)
    print("|" + "-|" * (len(epsilons)*2 + 2))
    
    records = []
    for k in metrics_off.keys():
        row_str = f"| {k} | {metrics_off[k]:.4f} |"
        record = {"Metric": k, "DP OFF": metrics_off[k]}
        for e in epsilons:
            mean_val = epsilon_stats[e][k]["mean"]
            std_val = epsilon_stats[e][k]["std"]
            row_str += f" {mean_val:.4f} | {std_val:.4f} |"
            record[f"Eps_{e}_Mean"] = mean_val
            record[f"Eps_{e}_Std"] = std_val
        print(row_str)
        records.append(record)

    pd.DataFrame(records).to_csv(RESULTS_DIR / "dp_ai_epsilon_tradeoff.csv", index=False)
    
    with open(RESULTS_DIR / "dp_evaluation_summary.json", "w") as f:
        json.dump({"dp_off": metrics_off, "epsilon_stats": epsilon_stats}, f, indent=2)

if __name__ == "__main__":
    run_dp_evaluation()
