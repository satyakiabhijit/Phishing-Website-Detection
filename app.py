"""
PhishGuard — 4-Layer Phishing Detection System
Streamlit UI showing results from every detection layer.
"""

import time
import logging
import streamlit as st
import pandas as pd
import numpy as np
from urllib.parse import urlparse

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard — AI Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── Premium CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    --bg-primary:    #0a0f1e;
    --bg-card:       #111827;
    --bg-card2:      #1a2236;
    --border:        #1f2d47;
    --accent-blue:   #3b82f6;
    --accent-purple: #8b5cf6;
    --accent-cyan:   #06b6d4;
    --red:           #ef4444;
    --green:         #22c55e;
    --orange:        #f97316;
    --yellow:        #eab308;
    --text-primary:  #f1f5f9;
    --text-muted:    #64748b;
}

html, body, .stApp {
    background-color: var(--bg-primary) !important;
    font-family: 'Inter', sans-serif;
    color: var(--text-primary);
}

/* Hide default Streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 1.5rem 2rem !important; max-width: 1400px; }

/* Sidebar */
[data-testid="stSidebar"] {
    background: #0d1424 !important;
    border-right: 1px solid #1f2d47 !important;
}
[data-testid="stSidebar"] * { color: #cbd5e1 !important; }
[data-testid="stSidebar"] h3 { color: #f1f5f9 !important; font-size: 14px !important; font-weight: 700 !important; }

/* Input */
.stTextInput > div > div > input {
    background: var(--bg-card2) !important;
    border: 1.5px solid var(--border) !important;
    border-radius: 12px !important;
    color: var(--text-primary) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 14px !important;
    padding: 14px 18px !important;
}
.stTextInput > div > div > input:focus {
    border-color: var(--accent-blue) !important;
    box-shadow: 0 0 0 3px rgba(59,130,246,0.15) !important;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple)) !important;
    color: white !important;
    border: none !important;
    border-radius: 12px !important;
    padding: 14px 32px !important;
    font-weight: 600 !important;
    font-size: 15px !important;
    width: 100% !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 25px rgba(59,130,246,0.4) !important;
}

/* Example URL buttons - smaller secondary style */
.example-btn > button {
    background: var(--bg-card2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    padding: 6px 10px !important;
    font-size: 11px !important;
    font-weight: 500 !important;
    color: #94a3b8 !important;
    font-family: 'JetBrains Mono', monospace !important;
    width: 100% !important;
}
.example-btn > button:hover {
    border-color: var(--accent-blue) !important;
    color: #60a5fa !important;
    transform: none !important;
    box-shadow: none !important;
}

/* Cards */
.layer-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 22px 26px;
    margin-bottom: 16px;
    transition: border-color 0.2s;
}
.layer-card:hover { border-color: #2d3f5e; }

/* Verdict banner */
.verdict-phishing {
    background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(239,68,68,0.05));
    border: 2px solid var(--red);
    border-radius: 20px;
    padding: 28px 36px;
    text-align: center;
    margin-bottom: 20px;
}
.verdict-legitimate {
    background: linear-gradient(135deg, rgba(34,197,94,0.15), rgba(34,197,94,0.05));
    border: 2px solid var(--green);
    border-radius: 20px;
    padding: 28px 36px;
    text-align: center;
    margin-bottom: 20px;
}
.verdict-uncertain {
    background: linear-gradient(135deg, rgba(234,179,8,0.15), rgba(234,179,8,0.05));
    border: 2px solid var(--yellow);
    border-radius: 20px;
    padding: 28px 36px;
    text-align: center;
    margin-bottom: 20px;
}

/* Progress bars */
.score-bar-container {
    background: var(--bg-card2);
    border-radius: 100px;
    height: 10px;
    margin: 8px 0;
    overflow: hidden;
}
.score-bar-fill-red    { height: 100%; border-radius: 100px; background: linear-gradient(90deg, #ef4444, #dc2626); }
.score-bar-fill-green  { height: 100%; border-radius: 100px; background: linear-gradient(90deg, #22c55e, #16a34a); }
.score-bar-fill-yellow { height: 100%; border-radius: 100px; background: linear-gradient(90deg, #eab308, #ca8a04); }
.score-bar-fill-blue   { height: 100%; border-radius: 100px; background: linear-gradient(90deg, #3b82f6, #6366f1); }

/* Tags */
.tag {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 100px;
    font-size: 12px;
    font-weight: 600;
    margin: 3px;
}
.tag-red    { background: rgba(239,68,68,0.15);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
.tag-green  { background: rgba(34,197,94,0.15);  color: #4ade80; border: 1px solid rgba(34,197,94,0.3); }
.tag-orange { background: rgba(249,115,22,0.15); color: #fb923c; border: 1px solid rgba(249,115,22,0.3); }
.tag-blue   { background: rgba(59,130,246,0.15); color: #60a5fa; border: 1px solid rgba(59,130,246,0.3); }
.tag-gray   { background: rgba(100,116,139,0.15);color: #94a3b8; border: 1px solid rgba(100,116,139,0.3); }

/* Model grid */
.model-row {
    display: flex;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid var(--border);
    gap: 12px;
}
.model-row:last-child { border-bottom: none; }
.model-name { font-size: 13px; color: var(--text-muted); width: 150px; flex-shrink: 0; }
.model-pred { font-size: 13px; font-weight: 600; width: 90px; flex-shrink: 0; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ─────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 20px 0 10px'>
        <div style='font-size:36px'>🛡️</div>
        <div style='font-size:18px; font-weight:800; color:#f1f5f9'>PhishGuard</div>
        <div style='font-size:11px; color:#475569; margin-top:4px'>4-Layer AI Detection</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 🏗️ Architecture")
    st.markdown("""
    <div style='font-size:12px; color:#64748b; line-height:2'>
    <b style='color:#3b82f6'>Layer 1</b> · VirusTotal (95 engines)<br>
    <b style='color:#3b82f6'>Layer 1</b> · Google Safe Browsing<br>
    <b style='color:#8b5cf6'>Layer 2</b> · IPQualityScore (domain intel)<br>
    <b style='color:#06b6d4'>Layer 3A</b> · Math models (4 algorithms)<br>
    <b style='color:#06b6d4'>Layer 3B</b> · ML Ensemble (11 models)<br>
    <b style='color:#22c55e'>Fusion</b> · Weighted score + overrides
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 🔑 API Status")
    try:
        from dotenv import load_dotenv
        import os
        load_dotenv()
        
        # Check both st.secrets and environment variables
        def check_api_key(key_name):
            if hasattr(st, 'secrets') and key_name in st.secrets:
                return bool(st.secrets[key_name])
            return bool(os.getenv(key_name))
        
        vt_ok   = check_api_key("VT_API_KEY")
        gsb_ok  = check_api_key("GSB_API_KEY")
        ipqs_ok = check_api_key("IPQS_API_KEY")
    except Exception:
        vt_ok = gsb_ok = ipqs_ok = False
    st.markdown(f"""
    <div style='font-size:12px; line-height:2.2'>
    {'✅' if vt_ok   else '❌'} VirusTotal<br>
    {'⚠️' if gsb_ok  else '❌'} Google Safe Browsing<br>
    {'✅' if ipqs_ok else '❌'} IPQualityScore
    </div>
    """, unsafe_allow_html=True)
    if not (vt_ok and gsb_ok and ipqs_ok):
        st.caption("Add keys to `.env` or Streamlit secrets for full API coverage.")
    if gsb_ok:
        st.caption("⚠️ GSB: Enable API in Google Cloud Console if you see 403 errors.")

    st.markdown("---")
    st.markdown("### ℹ️ About")
    st.caption("PhishGuard uses a 4-layer fusion pipeline combining real-time threat intelligence APIs with mathematical models and a stacking ML ensemble.")
    st.caption("**Accuracy:** 97.9% · **AUC:** 0.9997 · Trained on 50k+ URLs")
    st.markdown("[GitHub](https://github.com/satyakiabhijit/Phishing-Website-Detection)", unsafe_allow_html=False)


# ── Load ML Models ────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner=False)
def load_detector():
    from training import PhishingDetector
    d = PhishingDetector()
    if d.load_models('models'):
        return d
    return None


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style='text-align:center; padding: 40px 0 30px 0;'>
    <div style='font-size:52px; margin-bottom:8px;'>🛡️</div>
    <h1 style='font-size:38px; font-weight:800; background:linear-gradient(135deg,#3b82f6,#8b5cf6,#06b6d4);
               -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin:0;'>
        PhishGuard
    </h1>
    <p style='color:#64748b; font-size:16px; margin-top:8px;'>
        4-Layer AI Phishing Detection &nbsp;|&nbsp; Real-Time Threat Intelligence + Mathematical Models
    </p>
</div>
""", unsafe_allow_html=True)

# ── Input ─────────────────────────────────────────────────────────────────────
# Initialize session state
if 'example_url' not in st.session_state:
    st.session_state['example_url'] = ''
if 'auto_analyze' not in st.session_state:
    st.session_state['auto_analyze'] = False

# Quick-example buttons (placed BEFORE input to handle clicks first)
st.markdown("<p style='font-size:11px;color:#475569;margin:8px 0 4px'>✨ Try an example:</p>", unsafe_allow_html=True)
_ex_cols = st.columns(6)
_examples = [
    ("✅ Google",      "https://www.google.com"),
    ("✅ GitHub",      "https://github.com/openai/gpt-4"),
    ("✅ Claude AI",   "https://claude.ai/chat/b4c6ed16-00cf-800d"),
    ("🚨 PayPal fake", "http://paypa1-secure-login.tk/verify/account"),
    ("🚨 Bank scam",   "http://secure-banking-update.xyz/login?x=1"),
    ("🚨 IP login",    "http://192.168.1.1/admin/login.php"),
]
for _i, (_label, _ex_url) in enumerate(_examples):
    with _ex_cols[_i]:
        if st.button(_label, key=f"ex_{_i}"):
            st.session_state['example_url'] = _ex_url
            st.session_state['auto_analyze'] = True
            st.rerun()

col_inp, col_btn = st.columns([4, 1])
with col_inp:
    # Use the example_url if it's set, otherwise show empty
    default_value = st.session_state.get('example_url', '')
    url_input = st.text_input(
        "URL", label_visibility="collapsed",
        value=default_value,
        placeholder="Enter URL — e.g. https://github.com  or  http://amazon-secure-login.tk/verify"
    )
    # Update example_url when user types
    if url_input != default_value:
        st.session_state['example_url'] = url_input
with col_btn:
    analyze_btn = st.button("⚡ Analyze")


# ── Helper Functions ──────────────────────────────────────────────────────────
def score_color(score: float) -> str:
    if score >= 0.7: return "red"
    if score >= 0.4: return "orange"
    if score >= 0.2: return "yellow"
    return "green"


def score_bar(score: float, color: str = None, label: str = None):
    if color is None:
        color = score_color(score)
    pct = int(score * 100)
    label_html = f"<span style='font-size:12px;color:#94a3b8;float:right;'>{pct}%</span>" if label is None else \
                 f"<span style='font-size:12px;color:#94a3b8;float:right;'>{label}</span>"
    st.markdown(f"""
    {label_html}
    <div class='score-bar-container'>
        <div class='score-bar-fill-{color}' style='width:{pct}%'></div>
    </div>""", unsafe_allow_html=True)


def fmt_days(days: int) -> str:
    if days < 0: return "Unknown"
    if days < 30: return f"🚨 {days} days (very new!)"
    if days < 180: return f"⚠️ {days} days"
    years = days // 365
    months = (days % 365) // 30
    return f"✅ {'%d year%s' % (years, 's' if years != 1 else '')} {'%d month%s' % (months, 's' if months != 1 else '') if months else ''}"


def render_verdict(final_score: float, label: str, reason: str):
    if label == "phishing":
        cls = "verdict-phishing"
        icon = "🚨"
        color = "#ef4444"
        text = "PHISHING DETECTED"
    elif label == "legitimate":
        cls = "verdict-legitimate"
        icon = "✅"
        color = "#22c55e"
        text = "LEGITIMATE"
    else:
        cls = "verdict-uncertain"
        icon = "⚠️"
        color = "#eab308"
        text = "UNCERTAIN — Proceed with Caution"

    confidence_pct = int(min(final_score if label == "phishing" else (1 - final_score), 1.0) * 100)
    st.markdown(f"""
    <div class='{cls}'>
        <div style='font-size:48px'>{icon}</div>
        <div style='font-size:28px; font-weight:800; color:{color}; margin:8px 0'>{text}</div>
        <div style='font-size:15px; color:#94a3b8'>{reason}</div>
        <div style='font-size:13px; color:#64748b; margin-top:8px'>Confidence: {confidence_pct}%</div>
    </div>""", unsafe_allow_html=True)


# ── Main Analysis ─────────────────────────────────────────────────────────────
# Trigger analysis when button is clicked OR when auto_analyze flag is set
should_analyze = (analyze_btn or st.session_state.get('auto_analyze', False)) and url_input.strip()

if should_analyze:
    # Reset auto_analyze flag
    st.session_state['auto_analyze'] = False
    
    url = url_input.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc or url

    # ── Progress steps ────────────────────────────────────────────────────────
    progress = st.progress(0)
    status_txt = st.empty()

    # ══════════════════════════════════════════════════════════════════════════
    # LAYER 1+2: Threat Intelligence APIs
    # ══════════════════════════════════════════════════════════════════════════
    status_txt.markdown("🔍 **Layer 1 — Querying Threat Intelligence APIs...**")
    progress.progress(10)

    from intelligence import run_threat_intelligence
    intel = run_threat_intelligence(url)

    progress.progress(40)
    status_txt.markdown("🧮 **Layer 3 — Running Mathematical Models...**")

    # ══════════════════════════════════════════════════════════════════════════
    # LAYER 3: ML + Mathematical Models
    # ══════════════════════════════════════════════════════════════════════════
    from feature_extractor import extract_features, get_math_scores, get_feature_description
    features = extract_features(url, fetch_content=False)
    math_scores = get_math_scores(url)

    detector = load_detector()
    ml_result = None
    if detector:
        ml_result = detector.predict(features, return_details=True, url=url)
    else:
        st.error("⚠️ ML model not loaded. Run `python training.py` to train the model first.", icon="🔴")

    progress.progress(90)
    status_txt.markdown("🔗 **Fusing all layer scores...**")
    time.sleep(0.3)
    progress.progress(100)
    status_txt.empty()
    progress.empty()

    # ══════════════════════════════════════════════════════════════════════════
    # COMPUTE FINAL FUSION SCORE
    # ══════════════════════════════════════════════════════════════════════════
    intel_score = intel["intelligence_score"]
    ml_score    = ml_result["phishing_probability"] if ml_result else 0.5

    # Math models score (average of individual math signals)
    math_raw = [
        math_scores["typosquatting"]["score"],
        math_scores["ngram_perplexity"]["score"],
        math_scores["homoglyph"]["score"],
        math_scores["entropy"]["score"],
        features.get("suspecious_tld", 0),
        min(features.get("phish_hints", 0) / 5.0, 1.0),
    ]
    math_score = min(sum(math_raw) / max(len(math_raw), 1) * 1.5, 1.0)

    # Weighted fusion — intelligence APIs get highest weight
    apis_ok = intel["apis_available"]
    if apis_ok >= 2:
        w_intel, w_ml, w_math = 0.55, 0.25, 0.20
    elif apis_ok == 1:
        w_intel, w_ml, w_math = 0.35, 0.35, 0.30
    else:
        w_intel, w_ml, w_math = 0.00, 0.55, 0.45

    final_score = w_intel * intel_score + w_ml * ml_score + w_math * math_score

    # Hard overrides
    gsb = intel["google_safe_browsing"]
    vt  = intel["virustotal"]
    if gsb.get("is_flagged"):
        final_score = max(final_score, 0.97)
    if vt.get("verdict") == "phishing":
        final_score = max(final_score, 0.93)
    if intel["ipqualityscore"].get("is_phishing") or intel["ipqualityscore"].get("is_malware"):
        final_score = max(final_score, 0.93)

    # ── Typosquatting hard override ─────────────────────────────────────────────
    # If the domain is 1 edit away from a known brand (score ≥ 0.90), this is
    # a definitive typosquatting attack. Override the final score regardless of
    # what the ML or whitelist says. Example: flipkar.com → flipkart (dist=1).
    _typo = math_scores.get("typosquatting", {})
    if _typo.get("score", 0) >= 0.90:
        final_score = max(final_score, 0.93)

    # Determine label
    if final_score >= 0.60:
        final_label = "phishing"
    elif final_score <= 0.35:
        final_label = "legitimate"
    else:
        final_label = "uncertain"

    # Build reason string
    reasons = []
    if gsb.get("is_flagged"):
        reasons.append(f"Google Safe Browsing: {gsb['threat_type']}")
    if vt.get("verdict") == "phishing":
        reasons.append(f"VirusTotal: {vt['malicious']}/{vt['total_engines']} engines flagged")
    if math_scores["typosquatting"]["score"] > 0.5:
        reasons.append(f"Typosquatting '{math_scores['typosquatting']['closest_brand']}' (dist={math_scores['typosquatting']['edit_distance']})")
    if math_scores["homoglyph"]["detected"]:
        reasons.append("Homoglyph characters detected")
    if features.get("suspecious_tld"):
        tld = domain.split(".")[-1]
        reasons.append(f"Suspicious TLD: .{tld}")
    if not reasons:
        if final_label == "phishing":
            reasons.append("Multiple ML models flagged this URL")
        else:
            reasons.append("No threats detected across all layers")

    reason_str = " · ".join(reasons)

    # ══════════════════════════════════════════════════════════════════════════
    # RESULTS UI — SIMPLE VIEW (default)
    # ══════════════════════════════════════════════════════════════════════════

    # ── Determine display config ─────────────────────────────────────────────
    if final_label == "phishing":
        verdict_icon  = "🚨"
        verdict_text  = "PHISHING DETECTED"
        verdict_sub   = "This URL shows strong indicators of a phishing attack. Do not proceed."
        verdict_color = "#ef4444"
        verdict_bg    = "rgba(239,68,68,0.08)"
        verdict_border= "#ef4444"
    elif final_label == "legitimate":
        verdict_icon  = "✅"
        verdict_text  = "LEGITIMATE"
        verdict_sub   = "No threats detected. This URL appears to be safe."
        verdict_color = "#22c55e"
        verdict_bg    = "rgba(34,197,94,0.08)"
        verdict_border= "#22c55e"
    else:
        verdict_icon  = "⚠️"
        verdict_text  = "UNCERTAIN"
        verdict_sub   = "Signals are mixed. Proceed with caution and avoid entering sensitive data."
        verdict_color = "#eab308"
        verdict_bg    = "rgba(234,179,8,0.08)"
        verdict_border= "#eab308"

    risk_pct = int(final_score * 100)
    
    # Determine gradient color for risk gauge
    if final_score <= 0.35:
        risk_gradient = "#22c55e,#16a34a"
    elif final_score <= 0.60:
        risk_gradient = "#eab308,#ca8a04"
    else:
        risk_gradient = "#ef4444,#dc2626"

    # ── Simple verdict card ──────────────────────────────────────────────────
    st.markdown(f"""
    <div style='background:{verdict_bg}; border:2px solid {verdict_border};
                border-radius:24px; padding:36px 40px; text-align:center;
                margin-bottom:24px;'>
        <div style='font-size:64px; line-height:1; margin-bottom:12px'>{verdict_icon}</div>
        <div style='font-size:32px; font-weight:900; color:{verdict_color};
                    letter-spacing:1.5px; margin-bottom:10px'>{verdict_text}</div>
        <div style='font-size:15px; color:#94a3b8; margin-bottom:24px'>{verdict_sub}</div>
        <div style='max-width:420px; margin:0 auto'>
            <div style='display:flex; justify-content:space-between;
                        font-size:12px; color:#64748b; margin-bottom:6px'>
                <span>Safe</span>
                <span style='font-weight:700; font-size:14px; color:{verdict_color}'>
                    Risk Score: {risk_pct}%
                </span>
                <span>Dangerous</span>
            </div>
            <div style='background:#1a2236; border-radius:100px; height:14px; overflow:hidden;
                        border:1px solid #1f2d47'>
                <div style='width:{risk_pct}%; height:100%; border-radius:100px;
                             background:linear-gradient(90deg, {risk_gradient})'></div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Key reasons ──────────────────────────────────────────────────────────
    if reasons:
        reasons_html = "".join(
            f"<li style='padding:6px 0; color:#cbd5e1; font-size:14px'>"
            f"<span style='color:{verdict_color}; font-weight:700; margin-right:8px'>›</span>"
            f"{r}</li>"
            for r in reasons
        )
        st.markdown(f"""
        <div style='background:#111827; border:1px solid #1f2d47; border-radius:16px;
                    padding:20px 28px; margin-bottom:20px;'>
            <div style='font-size:11px; font-weight:700; letter-spacing:1.5px;
                        color:#64748b; margin-bottom:14px'>WHY THIS VERDICT</div>
            <ul style='margin:0; padding-left:0; list-style:none'>{reasons_html}</ul>
        </div>
        """, unsafe_allow_html=True)

    # ── 3-stat summary strip ─────────────────────────────────────────────────
    ml_ph = int((ml_result["phishing_probability"] if ml_result else 0.5) * 100)
    intel_ph = int(intel_score * 100)
    math_ph  = int(math_score * 100)

    def _stat_color(v):
        return "#ef4444" if v > 60 else "#eab308" if v > 35 else "#22c55e"

    st.markdown(f"""
    <div style='display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:24px'>
        <div style='background:#111827; border:1px solid #1f2d47; border-radius:14px;
                    padding:16px; text-align:center'>
            <div style='font-size:24px; font-weight:800; color:{_stat_color(intel_ph)}'>{intel_ph}%</div>
            <div style='font-size:11px; color:#64748b; margin-top:4px'>Threat Intel</div>
        </div>
        <div style='background:#111827; border:1px solid #1f2d47; border-radius:14px;
                    padding:16px; text-align:center'>
            <div style='font-size:24px; font-weight:800; color:{_stat_color(ml_ph)}'>{ml_ph}%</div>
            <div style='font-size:11px; color:#64748b; margin-top:4px'>ML Ensemble</div>
        </div>
        <div style='background:#111827; border:1px solid #1f2d47; border-radius:14px;
                    padding:16px; text-align:center'>
            <div style='font-size:24px; font-weight:800; color:{_stat_color(math_ph)}'>{math_ph}%</div>
            <div style='font-size:11px; color:#64748b; margin-top:4px'>Math Models</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════════
    # DETAILED REPORT — collapsed by default
    # ══════════════════════════════════════════════════════════════════════════
    with st.expander("📊 View Detailed Report", expanded=False):
        st.markdown("<br>", unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        # ── LAYER 1A: VirusTotal ─────────────────────────────────────────────
        with col1:
            vt_data = intel["virustotal"]
            vt_color = score_color(vt_data["score"])
            st.markdown(f"""
            <div class='layer-card'>
                <div style='font-size:11px;font-weight:700;letter-spacing:1.5px;color:#64748b;margin-bottom:8px'>
                    LAYER 1A · VIRUSTOTAL
                </div>
                <div style='font-size:18px;font-weight:700;margin-bottom:4px'>
                    {'🚨 ' if vt_data.get('verdict') == 'phishing' else '✅ ' if vt_data.get('verdict') == 'clean' else '⚠️ '}
                    {vt_data.get('verdict', 'unknown').upper()}
                </div>
            """, unsafe_allow_html=True)
            score_bar(vt_data["score"], vt_color)
            if vt_data["available"]:
                mal = vt_data["malicious"]; sus = vt_data["suspicious"]
                har = vt_data["harmless"];  tot = vt_data["total_engines"]
                st.markdown(f"""
                <div style='display:flex;gap:16px;margin:12px 0;flex-wrap:wrap;'>
                    <div><span style='color:#ef4444;font-size:22px;font-weight:700'>{mal}</span>
                         <span style='color:#64748b;font-size:12px'> malicious</span></div>
                    <div><span style='color:#eab308;font-size:22px;font-weight:700'>{sus}</span>
                         <span style='color:#64748b;font-size:12px'> suspicious</span></div>
                    <div><span style='color:#22c55e;font-size:22px;font-weight:700'>{har}</span>
                         <span style='color:#64748b;font-size:12px'> clean</span></div>
                    <div><span style='color:#94a3b8;font-size:22px;font-weight:700'>{tot}</span>
                         <span style='color:#64748b;font-size:12px'> engines</span></div>
                </div>""", unsafe_allow_html=True)
                if vt_data.get("categories"):
                    cats_html = " ".join(f"<span class='tag tag-red'>{c}</span>" for c in vt_data["categories"])
                    st.markdown(cats_html, unsafe_allow_html=True)
            elif vt_data.get("error"):
                st.markdown(f"<span class='tag tag-gray'>API Error: {vt_data['error'][:60]}</span>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # ── LAYER 1B: Google Safe Browsing ───────────────────────────────────
        with col2:
            gsb_data  = intel["google_safe_browsing"]
            gsb_color = "red" if gsb_data.get("is_flagged") else "green"
            st.markdown(f"""
            <div class='layer-card'>
                <div style='font-size:11px;font-weight:700;letter-spacing:1.5px;color:#64748b;margin-bottom:8px'>
                    LAYER 1B · GOOGLE SAFE BROWSING
                </div>
                <div style='font-size:18px;font-weight:700;margin-bottom:4px'>
                    {'🚨 THREAT DETECTED' if gsb_data.get('is_flagged') else '✅ CLEAN'}
                </div>
            """, unsafe_allow_html=True)
            score_bar(gsb_data["score"], gsb_color)
            if gsb_data["available"]:
                if gsb_data.get("is_flagged"):
                    threat   = gsb_data.get("threat_type", "UNKNOWN")
                    platform = gsb_data.get("platform_type", "ANY_PLATFORM")
                    st.markdown(f"""
                    <div style='margin-top:12px'>
                        <span class='tag tag-red'>⚠ {threat}</span>
                        <span class='tag tag-gray'>{platform}</span>
                    </div>
                    <div style='margin-top:10px;font-size:13px;color:#94a3b8'>
                        Google has flagged this URL as a confirmed threat
                    </div>""", unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div style='margin-top:12px;font-size:13px;color:#4ade80'>
                        ✅ Not found in Google's threat database
                    </div>""", unsafe_allow_html=True)
            elif gsb_data.get("error"):
                error_msg = gsb_data['error']
                if "403" in error_msg:
                    st.markdown("<span class='tag tag-gray'>⚠️ API Not Enabled</span>", unsafe_allow_html=True)
                    st.markdown("<div style='margin-top:8px;font-size:11px;color:#64748b'>Enable Safe Browsing API in Google Cloud Console</div>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<span class='tag tag-gray'>API Error: {error_msg[:50]}</span>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # ── LAYER 2: Domain Intelligence ─────────────────────────────────────
        col3, col4 = st.columns(2)
        with col3:
            ipqs = intel["ipqualityscore"]
            ipqs_color = score_color(ipqs["score"])
            st.markdown(f"""
            <div class='layer-card'>
                <div style='font-size:11px;font-weight:700;letter-spacing:1.5px;color:#64748b;margin-bottom:8px'>
                    LAYER 2 · DOMAIN INTELLIGENCE (IPQUALITYSCORE)
                </div>
                <div style='font-size:18px;font-weight:700;margin-bottom:4px'>
                    Fraud Score: {ipqs.get('fraud_score', '?')} / 100
                </div>
            """, unsafe_allow_html=True)
            score_bar(ipqs["score"], ipqs_color)
            if ipqs["available"]:
                age_str   = fmt_days(ipqs.get("domain_age_days", -1))
                dns_icon  = "✅" if ipqs.get("dns_valid", True) else "🚨"
                mal_icon  = "🚨" if ipqs.get("is_malware")  else "✅"
                phish_icon= "🚨" if ipqs.get("is_phishing") else "✅"
                sus_icon  = "⚠️" if ipqs.get("is_suspicious") else "✅"
                st.markdown(f"""
                <div style='margin-top:12px;font-size:13px;line-height:2'>
                    <div>📅 <b>Domain Age:</b> {age_str}</div>
                    <div>{dns_icon} <b>DNS Valid:</b> {'Yes' if ipqs.get('dns_valid', True) else 'NO — invalid DNS'}</div>
                    <div>{mal_icon} <b>Malware:</b> {'Detected' if ipqs.get('is_malware') else 'Clean'}</div>
                    <div>{phish_icon} <b>Phishing DB:</b> {'Flagged' if ipqs.get('is_phishing') else 'Clean'}</div>
                    <div>{sus_icon} <b>Suspicious:</b> {'Yes' if ipqs.get('is_suspicious') else 'No'}</div>
                    {f"<div>🖥️ <b>Server:</b> {ipqs['server']}</div>" if ipqs.get('server') else ''}
                </div>""", unsafe_allow_html=True)
                if ipqs.get("risk_factors"):
                    factors_html = " ".join(f"<span class='tag tag-orange'>{r}</span>" for r in ipqs["risk_factors"])
                    st.markdown(f"<div style='margin-top:10px'>{factors_html}</div>", unsafe_allow_html=True)
            elif ipqs.get("error"):
                st.markdown(f"<span class='tag tag-gray'>API Error: {ipqs['error'][:60]}</span>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # ── LAYER 3A: Mathematical Models ────────────────────────────────────
        with col4:
            st.markdown("""
            <div class='layer-card'>
                <div style='font-size:11px;font-weight:700;letter-spacing:1.5px;color:#64748b;margin-bottom:12px'>
                    LAYER 3A · MATHEMATICAL MODELS
                </div>
            """, unsafe_allow_html=True)
            ts  = math_scores["typosquatting"]
            ts_color = "red" if ts["score"] > 0.7 else "orange" if ts["score"] > 0.3 else "green"
            st.markdown(f"""
            <div style='margin-bottom:14px'>
                <div style='display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px'>
                    <span>🎯 Typosquatting (DL Distance)</span>
                    <span style='color:#94a3b8'>{ts['label']}
                    {f"— dist={ts['edit_distance']} from '<b>{ts['closest_brand']}</b>'" if ts['closest_brand'] else ''}</span>
                </div>""", unsafe_allow_html=True)
            score_bar(ts["score"], ts_color)

            ngp = math_scores["ngram_perplexity"]
            ngp_color = score_color(ngp["score"])
            st.markdown(f"""
            <div style='margin-bottom:14px;margin-top:10px'>
                <div style='display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px'>
                    <span>📊 N-gram Perplexity</span>
                    <span style='color:#94a3b8'>{ngp['label']} (perp={ngp['raw_perplexity']})</span>
                </div>""", unsafe_allow_html=True)
            score_bar(ngp["score"], ngp_color)

            hg = math_scores["homoglyph"]
            hg_color = "red" if hg["detected"] else "green"
            st.markdown(f"""
            <div style='margin-bottom:14px;margin-top:10px'>
                <div style='display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px'>
                    <span>🔤 Homoglyph Detection</span>
                    <span style='color:{"#f87171" if hg["detected"] else "#4ade80"}'>{hg["label"]}</span>
                </div>""", unsafe_allow_html=True)
            score_bar(hg["score"], hg_color)

            ent = math_scores["entropy"]
            ent_color = score_color(ent["score"])
            st.markdown(f"""
            <div style='margin-top:10px'>
                <div style='display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px'>
                    <span>⚡ Shannon Entropy</span>
                    <span style='color:#94a3b8'>{ent["label"]} (H={ent["raw_entropy"]})</span>
                </div>""", unsafe_allow_html=True)
            score_bar(ent["score"], ent_color)

            if math_scores.get("has_uuid"):
                st.markdown("""
                <div style='margin-top:12px'>
                    <span class='tag tag-blue'>✅ UUID in path detected — normal for web apps</span>
                </div>""", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # ── LAYER 3B: ML Ensemble Breakdown ──────────────────────────────────
        if ml_result and ml_result.get("individual_models"):
            st.markdown("""
            <div class='layer-card' style='margin-top:4px'>
                <div style='font-size:11px;font-weight:700;letter-spacing:1.5px;color:#64748b;margin-bottom:14px'>
                    LAYER 3B · ENSEMBLE ML MODEL BREAKDOWN
                </div>
            """, unsafe_allow_html=True)
            for name, data in ml_result["individual_models"].items():
                pp = data["phishing_prob"]
                pred_color = "#f87171" if data["prediction"] == "phishing" else "#4ade80"
                pct = int(pp * 100)
                c1, c2, c3 = st.columns([2, 4, 1])
                with c1:
                    st.markdown(f"<p style='font-size:12px;color:#94a3b8;margin:0;padding-top:6px'>{name.replace('_', ' ').title()}</p>", unsafe_allow_html=True)
                with c2:
                    score_bar(pp, score_color(pp))
                with c3:
                    st.markdown(f"<p style='font-size:12px;font-weight:700;color:{pred_color};margin:0;padding-top:6px;text-align:right'>{pct}%</p>", unsafe_allow_html=True)
            if ml_result.get("is_anomaly"):
                st.markdown(f"""
                <div style='margin-top:12px;padding:10px 14px;background:rgba(239,68,68,0.1);
                            border-radius:10px;border:1px solid rgba(239,68,68,0.3);font-size:13px'>
                    🔬 <b>Anomaly Detection:</b> This URL exhibits unusual structural patterns.
                    Score: {ml_result['anomaly_score']:.3f}
                </div>""", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # ── Fusion Score Breakdown ────────────────────────────────────────────
        st.markdown(f"""
        <div class='layer-card' style='margin-top:4px'>
            <div style='font-size:11px;font-weight:700;letter-spacing:1.5px;color:#64748b;margin-bottom:14px'>
                FUSION SCORE BREAKDOWN
            </div>
            <div style='display:grid;grid-template-columns:repeat(4,1fr);gap:16px;text-align:center'>
                <div>
                    <div style='font-size:26px;font-weight:800;color:{"#ef4444" if intel_score>0.6 else "#22c55e"}'>{int(intel_score*100)}%</div>
                    <div style='font-size:11px;color:#64748b'>Threat Intel<br>weight {int(w_intel*100)}%</div>
                </div>
                <div>
                    <div style='font-size:26px;font-weight:800;color:{"#ef4444" if ml_ph>60 else "#22c55e"}'>{ml_ph}%</div>
                    <div style='font-size:11px;color:#64748b'>ML Model<br>weight {int(w_ml*100)}%</div>
                </div>
                <div>
                    <div style='font-size:26px;font-weight:800;color:{"#ef4444" if math_score>0.6 else "#22c55e"}'>{int(math_score*100)}%</div>
                    <div style='font-size:11px;color:#64748b'>Math Models<br>weight {int(w_math*100)}%</div>
                </div>
                <div>
                    <div style='font-size:26px;font-weight:800;color:{"#ef4444" if final_score>0.6 else "#eab308" if final_score>0.35 else "#22c55e"}'>{risk_pct}%</div>
                    <div style='font-size:11px;color:#64748b'>Final Score<br>(fused)</div>
                </div>
            </div>
            <div style='margin-top:14px;font-size:11px;color:#475569;text-align:center'>
                APIs available: {apis_ok}/3 &nbsp;|&nbsp; ML models: {len(ml_result.get("individual_models",{})) if ml_result else 0} &nbsp;|&nbsp; Math models: 4
            </div>
        </div>
        """, unsafe_allow_html=True)




elif analyze_btn and not url_input.strip():
    st.warning("Please enter a URL to analyze.")

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style='text-align:center;padding:40px 0 20px;color:#334155;font-size:12px'>
    PhishGuard &nbsp;·&nbsp; 4-Layer Detection: Threat Intel + Domain Intelligence + Mathematical Models + ML Ensemble<br>
    <span style='color:#1e293b'>Powered by VirusTotal · Google Safe Browsing · IPQualityScore · Damerau-Levenshtein · N-gram LM · Shannon Entropy</span>
</div>
""", unsafe_allow_html=True)
