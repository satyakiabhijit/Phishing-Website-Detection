---
title: PhishGuard ML Engine
emoji: 🛡️
colorFrom: red
colorTo: gray
sdk: gradio
sdk_version: 5.7.1
app_file: app.py
pinned: false
python_version: "3.11"
---

# PhishGuard v2 — ML Inference Engine
This is the backend for the PhishGuard platform. It hosts the stacking ensemble model for real-time phishing detection.

## Local Training
Trained on the PhiUSIIL dataset using 21 URL-lexical features.
- Accuracy: ~96%
- Models: Stacking (RF, XGBoost, LightGBM, MLP, LR)
