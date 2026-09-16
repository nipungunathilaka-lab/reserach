# AI Model Card: Threat Detection (Isolation Forest)

## Model Details
- **Model Type**: Isolation Forest
- **Algorithm**: Unsupervised Anomaly Detection
- **Purpose**: Detect anomalous file transfers based on behavioural patterns to mitigate insider threats and unauthorized access.

## Features Used
- `file_size_mb`: Size of the file in MB.
- `hour_of_day`: The hour the transfer was initiated (0-23).
- `transfers_last_hour`: Number of transfers by the user in the past hour.
- `mfa_failed_attempts`: Number of failed MFA attempts prior to transfer.
- `failed_login_attempts`: Number of failed login attempts prior to transfer.
- `is_unusual_hour`: Boolean flag (0 or 1) indicating if transfer is between 22:00 and 06:00.
- `high_risk_file_type`: Boolean flag (0 or 1) for executable or script files.
- `archive_file_type`: Boolean flag (0 or 1) for compressed archives.

## Training Dataset Provenance
- **Dataset Source**: Synthetic Laboratory Data (Generative)
- **Real-World Status**: Contains NO enterprise production network traffic.
- **Training Sample Count**: 600 records (approx. 468 normal, 132 anomalous)
- **Collection Environment**: Research Prototype Simulator

## Evaluation Protocol
The model was evaluated on a held-out test set using both the baseline (raw) features and the Differential Privacy (DP) enabled features to observe the impact of privacy noise on detection capabilities. 

### Baseline Metrics (No DP)
- **Accuracy**: 93.00%
- **Precision**: 100%
- **Recall**: 68.18%
- **F1-Score**: 81.08%
- **False Positives**: 0
- **False Negatives (Missed Anomalies)**: 42

### Differential Privacy (DP-Enabled) Metrics
- **Accuracy**: 83.00%
- **Precision**: 57.58%
- **Recall**: 86.36%
- **F1-Score**: 69.09%
- **False Positives**: 84
- **False Negatives (Missed Anomalies)**: 18

## Differential Privacy Settings
- **DP Enabled**: Configurable (Runtime default varies by environment)
- **Mechanism**: Laplace
- **Epsilon**: Configurable per analysis (default `0.5`)
- **Sensitivity**: Bounded based on feature definitions.

## Known Limitations
- **Probabilistic Detection**: The model is NOT perfect and will produce False Positives and False Negatives.
- **Dataset Gap**: Trained entirely on synthetic data. Real-world anomalies may look significantly different.
- **DP Noise Impact**: When DP is enabled, the model experiences a significant increase in False Positives due to the Laplace noise, although recall (detection of anomalies) may shift.
- **Retraining Policy**: The system includes a telemetry collection pipeline designed for future evaluation and retraining using authorized real application data.

## Expected Deployment Environment
- Designed for secure file transfer systems where strict behavioral monitoring is required.
- Must be used in conjunction with deterministic controls (e.g., signatures, encryption, authentication) as the AI layer is purely probabilistic and does not guarantee complete protection.
