# PhishGuard v2 — Model Training Guide

## Prerequisites

- Python 3.10+
- 16 GB RAM recommended
- GPU optional (XGBoost/LightGBM use CPU by default)
- Expected training time: **~25–40 minutes on CPU**

## Setup

```bash
pip install -r requirements.txt
```

## Dataset

Place `PhiUSIIL_Phishing_URL_Dataset.csv` in the project root (same directory as `training.py`).

| Stat | Value |
|------|-------|
| Total rows | 235,795 |
| Legitimate (label=0) | 100,945 |
| Phishing (label=1) | 134,850 |
| Features | 54 numeric |
| Encoding | UTF-8 with BOM |

## Run Training

```bash
# Full pipeline (train + ONNX export + ngram export)
python training.py --all

# Train only (no exports)
python training.py

# Train + export ONNX for HF deployment
python training.py --export-onnx

# Train + export n-gram model
python training.py --export-ngram

# Quick train (skip cross-validation — ~60% faster)
python training.py --skip-cv

# Custom dataset path
python training.py --dataset path/to/dataset.csv --all
```

## Expected Output Metrics

Based on PhiUSIIL dataset characteristics:

| Model | Accuracy | AUC-ROC | F1 |
|-------|----------|---------|------|
| Random Forest | ~97–98% | ~0.995 | ~0.98 |
| XGBoost | ~98–99% | ~0.998 | ~0.98 |
| LightGBM | ~98–99% | ~0.998 | ~0.98 |
| Extra Trees | ~97–98% | ~0.995 | ~0.98 |
| MLP Neural Net | ~96–97% | ~0.990 | ~0.97 |
| **Stacking Ensemble** | **~98–99%** | **>0.999** | **~0.99** |

## Output Files

After training, the `models/` directory will contain:

```
models/
├── scaler.joblib              # RobustScaler
├── rf.joblib                  # Random Forest
├── et.joblib                  # Extra Trees
├── gb.joblib                  # Gradient Boosting
├── xgb.joblib                 # XGBoost
├── xgb2.joblib                # XGBoost v2
├── lgb.joblib                 # LightGBM
├── lgb2.joblib                # LightGBM v2
├── mlp.joblib                 # MLP
├── mlp2.joblib                # MLP v2
├── svm.joblib                 # SVM
├── lr.joblib                  # Logistic Regression
├── stacking_ensemble.joblib   # Stacking meta-classifier
├── phishguard.onnx            # ONNX export (with --export-onnx)
├── feature_order.json         # Canonical feature order
├── feature_importance.json    # RF feature importances
├── training_results.json      # All metrics
└── ngram_model.json           # N-gram model (with --export-ngram)
```

## Deploy to Hugging Face

1. Run: `python training.py --export-onnx`
2. Create `hf_space/models/` directory
3. Copy `models/phishguard.onnx` → `hf_space/models/phishguard.onnx`
4. Copy `models/feature_order.json` → `hf_space/models/feature_order.json`
5. Copy `models/scaler.joblib` → `hf_space/models/scaler.joblib` (sklearn fallback)
6. Push `hf_space/` to a new Hugging Face Space
7. Set `HF_SPACE_URL` in Vercel environment variables

## Feature Importance

After training, check `models/feature_importance.json` for the top contributing features. Typical top-10:

1. **URLLength** — Phishing URLs tend to be very long
2. **NoOfExternalRef** — External resource references
3. **LineOfCode** — Page complexity
4. **DomainTitleMatchScore** — Domain vs page title mismatch
5. **URLSimilarityIndex** — URL vs content similarity
6. **NoOfSubDomain** — Subdomain nesting depth
7. **HasObfuscation** — URL encoding abuse
8. **TLDLegitimateProb** — TLD trust level
9. **DegitRatioInURL** — Digit density in URL
10. **CharContinuationRate** — Character repetition patterns

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `MemoryError` during training | Use `--skip-cv` to reduce memory usage |
| `skl2onnx` conversion fails | Falls back to RF pipeline export automatically |
| Dataset encoding errors | Ensure file is UTF-8 with BOM (`utf-8-sig`) |
| SVM training is slow | SVM is O(n²) — expected ~5–10 min on 235k rows |
