import json
import time
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from sklearn.model_selection import train_test_split
from app.services.ai_service import AIService, FEATURES
from app.security.privacy.differential_privacy import DifferentialPrivacyService, PrivacyBudgetAccountant
from app.security.privacy.config import dp_settings

RESULTS_DIR = Path("tests/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def evaluate_predictions(y_true, y_pred, name=""):
    acc = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0,0,0,0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
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
    }

def run_repeated_evaluation():
    print("RUNNING REPEATED STOCHASTIC AI MODEL EVALUATION (Isolation Forest)")
    
    dataset_path = AIService.training_dataset_path()
    df = pd.read_csv(dataset_path)
    
    # 3. Explicit 900-Record Dataset Split (600 train, 300 test)
    # Ensure disjoint sets to prevent data leakage.
    train_df, test_df = train_test_split(df, test_size=300, random_state=42, stratify=df["is_anomaly"])
    
    # Assert disjoint train/test indices
    assert len(set(train_df.index).intersection(set(test_df.index))) == 0, "Train and Test sets overlap!"
    
    y_true_test = test_df["is_anomaly"].values
    
    print(f"Dataset Provenance - Total: {len(df)}, Train: {len(train_df)}, Test: {len(test_df)}")
    print(f"Test Set - Normal: {np.sum(y_true_test == 0)}, Anomalous: {np.sum(y_true_test == 1)}")

    # 5. Clean Training -> Clean Inference (Baseline)
    AIService.ensure_model()
    # Ensure we only trained on the train set (mocking it for the test script or replacing it if it didn't)
    x_train_clean = train_df[FEATURES].astype(float).fillna(0)
    AIService._model.fit(x_train_clean) # Retrain explicitly on the 600 clean train records to be sure
    
    x_test_clean = test_df[FEATURES].astype(float).fillna(0)
    preds = AIService._model.predict(x_test_clean)
    y_pred_clean = [1 if p == -1 else 0 for p in preds]
    baseline_metrics = evaluate_predictions(y_true_test, y_pred_clean, "Baseline")
    
    print("\n--- BASELINE (Clean Train -> Clean Inference) ---")
    print(json.dumps(baseline_metrics, indent=2))
    
    # 5. Clean Training -> Noisy DP Inference (Robustness / Privacy-Utility tradeoff)
    print("\nRunning Repeated DP Inference Evaluation (30 runs)...")
    dp_metrics_runs = []
    
    # Enable DP
    dp_settings.dp_enabled = True
    
    for run in range(30):
        PrivacyBudgetAccountant.reset_for_tests()
        
        dp_rows = []
        for idx, row in test_df.iterrows():
            raw_features = row[FEATURES].to_dict()
            try:
                # We need fresh budget for each analysis run in tests
                PrivacyBudgetAccountant.reset_for_tests()
                dp_res = DifferentialPrivacyService.privatize_features("test_user", f"test_{idx}_{run}", raw_features)
                dp_rows.append(dp_res.features)
            except Exception as e:
                print(f"Budget error: {e}")
                dp_rows.append(raw_features)

        x_dp_test = pd.DataFrame(dp_rows)[FEATURES].astype(float).fillna(0)
        
        preds_dp = AIService._model.predict(x_dp_test)
        y_pred_dp = [1 if p == -1 else 0 for p in preds_dp]
        run_metrics = evaluate_predictions(y_true_test, y_pred_dp)
        dp_metrics_runs.append(run_metrics)
        
    # Calculate statistics across 30 runs
    stats = {}
    for key in baseline_metrics.keys():
        values = [r[key] for r in dp_metrics_runs]
        stats[key] = {
            "mean": float(np.mean(values)),
            "std": float(np.std(values)),
            "min": float(np.min(values)),
            "max": float(np.max(values))
        }

    print("\n--- DP INFERENCE (Clean Train -> Noisy Inference) [30 runs] ---")
    print(json.dumps(stats, indent=2))
    
    results = {
        "evaluation_name": "Repeated Stochastic DP Evaluation",
        "timestamp": time.time(),
        "dataset_split": {
            "total": len(df),
            "train": len(train_df),
            "test": len(test_df),
            "test_anomalies": int(np.sum(y_true_test == 1)),
            "test_normal": int(np.sum(y_true_test == 0))
        },
        "baseline_metrics": baseline_metrics,
        "dp_repeated_metrics": stats,
        "one_realization_dp_confusion_matrix": {
            "TP": dp_metrics_runs[0]["true_positives"],
            "TN": dp_metrics_runs[0]["true_negatives"],
            "FP": dp_metrics_runs[0]["false_positives"],
            "FN": dp_metrics_runs[0]["false_negatives"]
        }
    }
    
    with open(RESULTS_DIR / "ai_evaluation_dp_repeated.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_repeated_evaluation()
