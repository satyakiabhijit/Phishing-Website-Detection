# <p align="center">🛡️ PhishGuard</p>
<p align="center">
  <strong>4-Layer AI Phishing Detection System</strong><br>
  Real-time threat intelligence + mathematical models + ML ensemble
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python" />
  <img src="https://img.shields.io/badge/Streamlit-1.30%2B-red?logo=streamlit" />
  <img src="https://img.shields.io/badge/ML-Ensemble%20%7C%2011%20Models-green" />
  <img src="https://img.shields.io/badge/Accuracy-97.9%25-brightgreen" />
</p>

---

## 🏗️ Architecture

PhishGuard uses a **4-layer fusion pipeline** to analyze any URL for phishing indicators:

```
┌─────────────────────────────────────────────────────────────┐
│                     URL INPUT                               │
└─────────────────┬───────────────────────────────────────────┘
                  │
    ┌─────────────▼─────────────┐
    │  Layer 1 - Threat Intel   │  VirusTotal (95 engines)
    │                           │  Google Safe Browsing
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │  Layer 2 - Domain Intel   │  IPQualityScore (fraud score,
    │                           │  domain age, DNS, SSL, malware)
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │  Layer 3A - Math Models   │  Damerau-Levenshtein typosquatting
    │                           │  N-gram character LM perplexity
    │                           │  Unicode homoglyph detection
    │                           │  Shannon entropy (DGA detection)
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │  Layer 3B - ML Ensemble   │  11 models + stacking classifier
    │                           │  RandomForest, GradBoost, XGBoost,
    │                           │  LightGBM, ExtraTrees, SVM, MLP...
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │   Weighted Fusion Score   │  Intel 55% · ML 25% · Math 20%
    │   + Hard API Overrides    │  (weights adapt when APIs unavailable)
    └───────────────────────────┘
```

---

## ⚡ Features

- **95+ AV engine scan** via VirusTotal
- **Google Safe Browsing** real-time lookup
- **IPQualityScore** domain reputation, age, DNS validity
- **Typosquatting detection** — Damerau-Levenshtein distance against 400+ known brands
- **DGA detection** — character n-gram language model perplexity
- **Homoglyph detection** — Unicode confusable characters (e.g., Cyrillic ʼpʼ vs Latin 'p')
- **Shannon entropy** — flags randomly-generated domain names
- **ML Stacking Ensemble** — 11 models trained on 50k+ URLs, 97.9% accuracy
- **Adaptive fusion** — weight shifts when fewer APIs are available
- **Hard overrides** — GSB/VT/IPQS positives guarantee phishing verdict

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/satyakiabhijit/Phishing-Website-Detection.git
cd Phishing-Website-Detection
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
```

### 2. Add API Keys

Create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
IPQUALITYSCORE_API_KEY=your_key_here
```

| API | Free Tier | How to Get |
|-----|-----------|------------|
| **VirusTotal** | 500 req/day | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| **Google Safe Browsing** | 10k req/day | [console.cloud.google.com](https://console.cloud.google.com) → Enable Safe Browsing API |
| **IPQualityScore** | 200 req/day | [ipqualityscore.com/create-account](https://www.ipqualityscore.com/create-account) |

> ℹ️ The app works without API keys — Layers 1 & 2 are skipped and the ML + Math layers still run with adjusted weights.

### 3. Train the ML Model

```bash
python training.py
```

Training takes **~15–20 minutes** on a typical laptop. Models are saved to `models/`.

### 4. Run the App

```bash
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 🌐 Deploy to Streamlit Cloud

PhishGuard is production-ready for Streamlit Cloud deployment!

### Quick Deploy

1. Push your code to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Connect your repository and deploy
4. Add API keys in the app's Secrets settings (TOML format)

**Detailed deployment guide:** See [DEPLOYMENT.md](DEPLOYMENT.md)

### ⚡ Keep Your App Awake 24/7

Streamlit Cloud's free tier sleeps after 15 minutes of inactivity. We've included a **GitHub Actions workflow** that automatically pings your app every 14 minutes to keep it running!

**Setup (takes 2 minutes):**
1. Go to your GitHub repo → `Settings` → `Secrets` → `New secret`
2. Name: `STREAMLIT_APP_URL` | Value: your Streamlit app URL
3. The workflow runs automatically — check the `Actions` tab to verify

**Full guide with 5 different solutions:** See [KEEP_ALIVE.md](KEEP_ALIVE.md)

### Live Demo

🔗 [Try PhishGuard Live](https://your-app.streamlit.app) (coming soon)

---

## 📁 Project Structure

```
PhishGuard/
├── app.py                  # Streamlit UI — 4-layer results dashboard
├── feature_extractor.py    # URL feature extraction + math models
├── training.py             # ML training pipeline (11 models + stacking)
├── intelligence.py         # Layer 1 & 2 — API integrations
├── alexa_top1k.txt         # 400+ top domains for typosquatting detection
├── dataset_phishing.csv    # 50k+ labeled URLs for training
├── requirements.txt        # Python dependencies
├── .env                    # API keys (git-ignored)
└── models/                 # Trained model files (auto-generated, git-ignored)
```

---

## 🧠 ML Model Details

| Model | CV AUC |
|-------|--------|
| Random Forest | 0.99962 |
| Gradient Boosting | 0.99963 |
| Extra Trees | 0.99963 |
| XGBoost | ~0.9996 |
| LightGBM | ~0.9996 |
| SVM | 0.99776 |
| Neural Network (MLP) | ~0.9990 |
| **Stacking Ensemble** | **0.9997** |

Test set accuracy: **97.9%** · AUC: **0.9997**

---

## ⚙️ How Fusion Works

```
Final Score = (w_intel × intel_score) + (w_ml × ml_score) + (w_math × math_score)
```

| APIs Available | w_intel | w_ml | w_math |
|---------------|---------|------|--------|
| 2–3 APIs | 55% | 25% | 20% |
| 1 API | 35% | 35% | 30% |
| 0 APIs | 0% | 55% | 45% |

**Verdict thresholds:** ≥ 60% → Phishing · ≤ 35% → Legitimate · in between → Uncertain

---

## 📋 Requirements

- Python 3.10+
- ~500 MB disk space (for dataset + models)
- 4 GB RAM recommended for training

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
