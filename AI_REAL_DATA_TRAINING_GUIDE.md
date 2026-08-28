# AI Real Data Training Guide

The current system uses a lab-generated dataset by default because real secure-file-transfer logs are not available at the beginning of the project. After you run the system and collect real transfer activity, you can train the Isolation Forest model with your own data.

## What the AI model uses

Required feature columns:

```text
file_size_mb
hour_of_day
transfers_last_hour
mfa_failed_attempts
failed_login_attempts
is_unusual_hour
high_risk_file_type
archive_file_type
```

The strengthened detector combines Isolation Forest with rule scoring. It also stores optional evaluation/report fields such as file name, sender, receiver, integrity status, anomaly reason, anomaly level, ML prediction, decision score, and triggered rules.

## Step 1 — Collect real system data

Use the system normally:

1. Create several users.
2. Send normal files during normal hours.
3. Send different file types and sizes.
4. Test normal files during working hours.
5. Test suspicious cases, such as very large files, night transfers, repeated transfers, wrong MFA attempts, failed password attempts, compressed archives, and high-risk file extensions such as `.exe`, `.bat`, `.ps1`, or `.js`.

For better training, collect at least:

```text
50-100 mostly normal transfer records for a basic demo
500+ records for a stronger project evaluation
```

Important: Isolation Forest is unsupervised, so the training dataset should mostly contain normal behaviour. If too many abnormal records are included, the model will learn suspicious behaviour as normal.

## Step 2 — Export real transfer logs

From the backend folder, run:

```bash
python -m app.scripts.export_ai_training_data
```

This creates:

```text
backend/app/ml/real_transfer_dataset.csv
```

## Step 3 — Use the real dataset for AI training

Create or update `backend/.env`:

```env
AI_DATASET_PATH=real_transfer_dataset.csv
AI_CONTAMINATION=0.15
AI_MIN_TRAINING_ROWS=50
```

Then restart the backend:

```bash
uvicorn app.main:app --reload --port 8000
```

The AI service trains from the configured dataset when the backend starts. If the dataset is too small or missing required feature columns, it falls back to the bundled lab dataset.

## Step 4 — Test the model

Run:

```bash
python -m app.scripts.check_ai_model
```

Expected result: normal office-hour transfers should be low risk, while large files, midnight transfers, repeated transfers, or MFA-failure patterns should be medium/high risk.

## Step 5 — How to explain this in your report

Use this wording:

> The AI anomaly detection module initially uses a lab-generated secure file transfer dataset to simulate normal and suspicious transfer behaviour. After real system usage data becomes available, transfer logs can be exported from SQLite into a training CSV and used to retrain the Isolation Forest model. The strengthened detector analyzes file size, transfer time, transfer frequency, recent MFA failure count, failed password login count, unusual-hour behaviour, risky file extensions, and archive file indicators. The final risk result combines unsupervised ML output with transparent rule-based security scoring.

## Dataset honesty

Do not say the lab dataset is real company data. Say:

```text
Lab-generated dataset for controlled project evaluation
```

If you train using your own actual system logs later, say:

```text
Real system execution data collected from prototype testing
```


## Real-data training method for your report

1. Run the system for several testing sessions.
2. Create normal transfers first so the model learns a normal baseline.
3. Add controlled suspicious scenarios: repeated wrong MFA, multiple failed passwords, many rapid transfers, night-time transfers, large files, archives, and risky extensions.
4. Export logs with `python -m app.scripts.export_ai_training_data`.
5. Open `backend/app/ml/real_transfer_dataset.csv` and review labels/columns.
6. Set `AI_DATASET_PATH=real_transfer_dataset.csv` in `.env`.
7. Restart backend and run `python -m app.scripts.check_ai_model`.
8. Record sample outputs in your evaluation chapter.

For a final-year project, this is stronger than only using a static CSV because it shows a path from lab data to real system execution data.
