# 🔄 Keeping Your Streamlit App Awake

Streamlit Cloud's free tier puts apps to sleep after ~15 minutes of inactivity. Here are several solutions to keep your app running 24/7.

## ✅ Solution 1: GitHub Actions (Recommended - FREE)

This method uses GitHub Actions to ping your app every 14 minutes automatically.

### Setup:

1. **Configure your app URL** (choose one method):

   **Option A: Using GitHub Secrets (Recommended)**
   - Go to your GitHub repository
   - Click `Settings` → `Secrets and variables` → `Actions`
   - Click `New repository secret`
   - Name: `STREAMLIT_APP_URL`
   - Value: `https://your-app-name.streamlit.app`
   - Click `Add secret`

   **Option B: Edit the workflow file directly**
   - Open `.github/workflows/keep-alive.yml`
   - Replace the default URL with your actual Streamlit URL

2. **Enable GitHub Actions** (if not already enabled):
   - Go to your repository's `Actions` tab
   - Enable workflows if prompted

3. **Verify it's working**:
   - Go to `Actions` tab in your repository
   - You should see the "Keep Streamlit App Alive" workflow
   - It will run automatically every 14 minutes
   - You can also click `Run workflow` to test manually

### How it works:
- GitHub Actions runs a cron job every 14 minutes
- It sends a simple HTTP request to your Streamlit app
- This prevents the app from going to sleep
- Completely free (GitHub provides 2,000 free minutes/month)

---

## 🌐 Solution 2: UptimeRobot (FREE Alternative)

UptimeRobot is a monitoring service that can ping your app as a side effect.

### Setup:

1. Go to [uptimerobot.com](https://uptimerobot.com) and sign up (free)
2. Click `Add New Monitor`
3. Configuration:
   - Monitor Type: `HTTP(s)`
   - Friendly Name: `PhishGuard App`
   - URL: `https://your-app-name.streamlit.app`
   - Monitoring Interval: `5 minutes` (free tier)
4. Click `Create Monitor`

**Pros**: Web dashboard, email alerts if app goes down  
**Cons**: Max 50 monitors on free tier, 5-minute intervals

---

## 🔧 Solution 3: Koyeb (FREE Alternative)

Koyeb offers always-on free tier hosting.

### Setup:

1. Go to [koyeb.com](https://www.koyeb.com) and sign up
2. Click `Create Service`
3. Connect your GitHub repository
4. Configure:
   - Build command: `pip install -r requirements.txt`
   - Run command: `streamlit run app.py --server.port 8000`
5. Deploy

**Pros**: Always-on, better than Streamlit Cloud free tier  
**Cons**: Requires migration from Streamlit Cloud

---

## 🐍 Solution 4: Python Keep-Alive Script (Self-Hosted)

Run a simple script on your local machine or a server.

### Setup:

Create `keep_alive_local.py`:
```python
import requests
import time
from datetime import datetime

APP_URL = "https://your-app-name.streamlit.app"
INTERVAL = 840  # 14 minutes in seconds

while True:
    try:
        response = requests.get(APP_URL, timeout=30)
        print(f"[{datetime.now()}] Pinged: {response.status_code}")
    except Exception as e:
        print(f"[{datetime.now()}] Error: {e}")
    time.sleep(INTERVAL)
```

Run it:
```bash
python keep_alive_local.py
```

**Pros**: Full control  
**Cons**: Requires a machine running 24/7

---

## 📊 Comparison

| Method | Cost | Reliability | Setup Difficulty |
|--------|------|-------------|------------------|
| GitHub Actions | FREE | ⭐⭐⭐⭐⭐ | Easy |
| UptimeRobot | FREE | ⭐⭐⭐⭐ | Very Easy |
| Koyeb | FREE | ⭐⭐⭐⭐⭐ | Medium |
| Local Script | FREE* | ⭐⭐⭐ | Easy |

*Requires your computer/server to run 24/7

---

## 💰 Solution 5: Upgrade to Paid Tier (Most Reliable)

If your app is critical, consider upgrading:
- **Streamlit Cloud**: $20/month (never sleeps, more resources)
- **AWS/GCP/Azure**: $5-20/month (full control)
- **Heroku**: $7/month (Eco dynos, 1000 hours/month)

---

## 🎯 Recommended Setup

**For most users**: Use **GitHub Actions** (Solution 1) - it's free, reliable, and requires zero maintenance once configured.

**For important projects**: Combine **GitHub Actions + UptimeRobot** for redundancy and monitoring.

**For production apps**: Use a paid tier or migrate to **Koyeb** for guaranteed uptime.

---

## ⚠️ Important Notes

1. **Streamlit Cloud Limitations**: Even with keep-alive, apps may restart during Streamlit Cloud maintenance
2. **Fair Use**: Don't abuse free tiers - keep-alive pinging is acceptable, but don't run intensive operations
3. **Rate Limits**: Be mindful of any API rate limits in your app when pinging frequently

---

## 🔍 Troubleshooting

**GitHub Actions not running?**
- Check if Actions are enabled in repository settings
- Verify the cron syntax is correct
- Check the Actions tab for error logs

**App still sleeping?**
- Verify the correct URL is being pinged
- Check if Streamlit Cloud has scheduled maintenance
- Increase ping frequency (but don't go below 5 minutes)

**Too many requests?**
- GitHub Actions: 14-minute intervals are safe
- UptimeRobot: 5-minute intervals are fine
- Don't combine multiple services pinging at high frequency

---

## 📝 Finding Your Streamlit URL

Your app URL format: `https://[username]-[repo-name]-[app-name].streamlit.app`

Or find it in:
1. Streamlit Cloud Dashboard → Your App → Share button
2. The deployment logs when you first deployed

---

Need help? Check your deployment status in the Streamlit Cloud dashboard and ensure your app is running before setting up keep-alive.
