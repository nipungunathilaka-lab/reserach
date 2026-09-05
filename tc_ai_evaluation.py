from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    ConfusionMatrixDisplay
)


# ---------------------------------------------
# Paths
# ---------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parent

DATASET_PATH = (
    BACKEND_DIR
    / "backend"
    / "app"
    / "ml"
    / "lab_secure_transfer_dataset.csv"
)

EVIDENCE_DIR = (
    BACKEND_DIR.parent
    / "Chapter6_Evidence"
    / "AI_Evaluation"
)

EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------
# Load dataset
# ---------------------------------------------
df = pd.read_csv(DATASET_PATH)

FEATURES = [
    "file_size_mb",
    "hour_of_day",
    "transfers_last_hour",
    "mfa_failed_attempts",
    "failed_login_attempts",
    "is_unusual_hour",
    "high_risk_file_type",
    "archive_file_type"
]

X = df[FEATURES]
y = df["is_anomaly"].astype(int)


print("=" * 60)
print("UPCE AI EVALUATION")
print("=" * 60)

print(f"Total dataset records : {len(df)}")
print(f"Normal records        : {(y == 0).sum()}")
print(f"Anomaly records       : {(y == 1).sum()}")


# ---------------------------------------------
# 80/20 train-test split
# ---------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=29103,
    stratify=y
)


# ---------------------------------------------
# Scaling
# ---------------------------------------------
scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)


# ---------------------------------------------
# Isolation Forest
# ---------------------------------------------
model = IsolationForest(
    n_estimators=350,
    contamination=0.15,
    random_state=29103
)

# Labels are intentionally not supplied here
model.fit(X_train_scaled)

raw_predictions = model.predict(X_test_scaled)

# Isolation Forest:
#  1  = normal
# -1  = anomaly
predictions = (raw_predictions == -1).astype(int)


# ---------------------------------------------
# Metrics
# ---------------------------------------------
accuracy = accuracy_score(y_test, predictions)
precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)
recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)
f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)

cm = confusion_matrix(
    y_test,
    predictions,
    labels=[0, 1]
)

tn, fp, fn, tp = cm.ravel()


print("\nTRAIN / TEST")
print("-" * 60)
print(f"Training records : {len(X_train)}")
print(f"Testing records  : {len(X_test)}")

print("\nAI RESULTS")
print("-" * 60)

print(f"Accuracy  : {accuracy * 100:.2f}%")
print(f"Precision : {precision * 100:.2f}%")
print(f"Recall    : {recall * 100:.2f}%")
print(f"F1-score  : {f1 * 100:.2f}%")

print(f"\nTrue Negative  : {tn}")
print(f"False Positive : {fp}")
print(f"False Negative : {fn}")
print(f"True Positive  : {tp}")


# ---------------------------------------------
# Save metrics
# ---------------------------------------------
result_text = f"""
UPCE AI EVALUATION

Total Dataset Records : {len(df)}
Training Records      : {len(X_train)}
Testing Records       : {len(X_test)}

Accuracy              : {accuracy * 100:.2f}%
Precision             : {precision * 100:.2f}%
Recall                : {recall * 100:.2f}%
F1-score              : {f1 * 100:.2f}%

True Negative         : {tn}
False Positive        : {fp}
False Negative        : {fn}
True Positive         : {tp}

Confusion Matrix:
{cm}
"""

result_file = EVIDENCE_DIR / "AI_evaluation_results.txt"

result_file.write_text(
    result_text,
    encoding="utf-8"
)


# ---------------------------------------------
# Confusion Matrix
# ---------------------------------------------
fig, ax = plt.subplots(figsize=(7, 6))

ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Normal", "Anomaly"]
).plot(
    ax=ax,
    values_format="d"
)

ax.set_title(
    "UPCE Isolation Forest - Confusion Matrix"
)

plt.tight_layout()

graph_path = (
    EVIDENCE_DIR
    / "Figure_6_9_AI_Confusion_Matrix.png"
)

plt.savefig(
    graph_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


print("\nSaved:")
print(result_file)
print(graph_path)

print("\nAI EVALUATION COMPLETE")