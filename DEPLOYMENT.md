# 🚀 Deploying PhishGuard to Streamlit Cloud

This guide will help you deploy PhishGuard to Streamlit Cloud in minutes.

## Prerequisites

- A GitHub account
- API Keys for threat intelligence services (optional but recommended):
  - VirusTotal API Key
  - Google Safe Browsing API Key
  - IPQualityScore API Key

## Step 1: Push to GitHub

1. Create a new repository on GitHub
2. Push your code:
```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

## Step 2: Deploy to Streamlit Cloud

1. Go to [share.streamlit.io](https://share.streamlit.io)
2. Sign in with your GitHub account
3. Click "New app"
4. Select your repository, branch (main), and main file path (`app.py`)
5. Click "Deploy"

## Step 3: Configure Secrets (API Keys)

1. In your Streamlit Cloud dashboard, click on your app
2. Click the "⚙️ Settings" button
3. Go to the "Secrets" section
4. Add your API keys in TOML format:

```toml
# VirusTotal API Key
VT_API_KEY = "your_virustotal_api_key_here"

# Google Safe Browsing API Key
GSB_API_KEY = "your_google_safe_browsing_api_key_here"

# IPQualityScore API Key
IPQS_API_KEY = "your_ipqualityscore_api_key_here"
```

5. Click "Save"

## Step 4: Train the ML Models

The first time you deploy, you need to train the models. There are two options:

### Option A: Pre-train locally and commit
```bash
python training.py
git add models/
git commit -m "Add trained models"
git push
```

### Option B: Train on first run
The app will automatically train on first run if models are not found (this may take 1-2 minutes on first load).

## API Key Setup Guide

### VirusTotal
1. Go to [VirusTotal](https://www.virustotal.com/)
2. Sign up for a free account
3. Go to your profile → API Key
4. Copy your API key

### Google Safe Browsing
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select existing
3. Enable the "Safe Browsing API"
4. Go to APIs & Services → Credentials
5. Create an API key
6. Copy your API key

### IPQualityScore
1. Go to [IPQualityScore](https://www.ipqualityscore.com/)
2. Sign up for a free account
3. Go to Dashboard → API Keys
4. Copy your API key

## Performance Optimization

The app includes several optimizations for production:
- `@st.cache_resource` for ML model loading (loaded once)
- `@st.cache_data` for static data
- API request timeouts (10 seconds)
- Graceful error handling for missing API keys

## Monitoring

Streamlit Cloud provides:
- Real-time logs
- App status monitoring
- Resource usage metrics
- Error tracking

Access these from your app dashboard on [share.streamlit.io](https://share.streamlit.io)

## Custom Domain (Optional)

To use a custom domain:
1. Go to your app settings on Streamlit Cloud
2. Navigate to "General" → "App URL"
3. Add your custom domain
4. Update your DNS records as instructed

## Troubleshooting

### App is slow on first load
- This is normal if models need to be trained
- Pre-train models locally and commit them

### API errors
- Check that secrets are properly configured
- Verify API keys are valid
- Check API quota limits

### Out of memory
- Consider deploying to a different platform (Heroku, AWS, GCP) for larger resource requirements

## Support

For issues or questions:
- Open an issue on GitHub
- Check Streamlit Community Forum
- Review Streamlit Cloud documentation

---

**Note:** The free tier of Streamlit Cloud includes:
- 1 GB RAM
- 1 CPU core
- Unlimited viewers
- Public apps only

For private apps or more resources, upgrade to a paid plan.
