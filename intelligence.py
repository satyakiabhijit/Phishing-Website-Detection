"""
PhishGuard Intelligence Layer
Layer 1: Real-Time Threat Intelligence (VirusTotal + Google Safe Browsing)
Layer 2: Domain Intelligence (IPQualityScore - domain age, reputation, DNS, SSL)
"""

import os
import time
import hashlib
import logging
import requests
from typing import Dict, Any, Optional
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ─── API Keys (supports both .env and Streamlit secrets) ─────────────────────
def get_api_key(key_name: str) -> str:
    """Get API key from Streamlit secrets or environment variables."""
    # Try Streamlit secrets first (for cloud deployment)
    try:
        import streamlit as st
        if hasattr(st, 'secrets') and key_name in st.secrets:
            return st.secrets[key_name]
    except (ImportError, FileNotFoundError, KeyError):
        pass
    # Fall back to environment variables
    return os.getenv(key_name, "")

VT_API_KEY   = get_api_key("VT_API_KEY")
GSB_API_KEY  = get_api_key("GSB_API_KEY")
IPQS_API_KEY = get_api_key("IPQS_API_KEY")

TIMEOUT = 10  # seconds per request


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 1A — VirusTotal
# ═══════════════════════════════════════════════════════════════════════════════

def check_virustotal(url: str) -> Dict[str, Any]:
    """
    Submit URL to VirusTotal and get multi-engine scan results.
    Returns score 0.0 (safe) – 1.0 (definitely phishing).
    """
    result = {
        "available": False,
        "score": 0.0,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "total_engines": 0,
        "verdict": "unknown",
        "categories": [],
        "error": None
    }

    if not VT_API_KEY:
        result["error"] = "VT_API_KEY not set"
        return result

    try:
        headers = {"x-apikey": VT_API_KEY}

        # Step 1: Submit URL for analysis
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=TIMEOUT
        )

        if submit_resp.status_code not in (200, 409):
            result["error"] = f"VT submit failed: HTTP {submit_resp.status_code}"
            return result

        # Get analysis ID
        analysis_id = submit_resp.json().get("data", {}).get("id", "")
        if not analysis_id:
            # Try URL-based lookup (already cached)
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            analysis_id = f"u-{url_id}-0"

        # Step 2: Get analysis report (wait briefly for processing)
        time.sleep(2)
        report_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=TIMEOUT
        )

        if report_resp.status_code != 200:
            # Fall back to URL report endpoint
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            report_resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=TIMEOUT
            )

        if report_resp.status_code != 200:
            result["error"] = f"VT report failed: HTTP {report_resp.status_code}"
            return result

        data = report_resp.json().get("data", {})
        stats = data.get("attributes", {}).get("stats", {}) or \
                data.get("attributes", {}).get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # Categories (from engines that flagged it)
        categories = list(
            data.get("attributes", {}).get("categories", {}).values()
        )

        result.update({
            "available": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_engines": total,
            "categories": list(set(categories))[:5],
        })

        if total > 0:
            raw_score = (malicious + 0.5 * suspicious) / total
            result["score"] = round(min(raw_score * 1.5, 1.0), 4)  # Amplify signal

        if malicious >= 3:
            result["verdict"] = "phishing"
        elif malicious >= 1 or suspicious >= 3:
            result["verdict"] = "suspicious"
        elif total > 0:
            result["verdict"] = "clean"

    except requests.Timeout:
        result["error"] = "VirusTotal API timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 1B — Google Safe Browsing
# ═══════════════════════════════════════════════════════════════════════════════

def check_google_safe_browsing(url: str) -> Dict[str, Any]:
    """
    Check URL against Google Safe Browsing API v4.
    Returns threat type if flagged, else clean.
    """
    result = {
        "available": False,
        "is_flagged": False,
        "threat_type": None,
        "platform_type": None,
        "score": 0.0,
        "error": None
    }

    if not GSB_API_KEY:
        result["error"] = "GSB_API_KEY not set"
        return result

    try:
        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
            json=payload,
            timeout=TIMEOUT
        )

        if resp.status_code != 200:
            result["error"] = f"GSB API error: HTTP {resp.status_code}"
            return result

        data = resp.json()
        matches = data.get("matches", [])

        result["available"] = True

        if matches:
            threat = matches[0]
            result.update({
                "is_flagged": True,
                "threat_type": threat.get("threatType", "UNKNOWN"),
                "platform_type": threat.get("platformType", "ANY_PLATFORM"),
                "score": 1.0  # GSB flagging = very high confidence
            })
        else:
            result["score"] = 0.0

    except requests.Timeout:
        result["error"] = "Google Safe Browsing API timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — IPQualityScore (Domain Intelligence)
# ═══════════════════════════════════════════════════════════════════════════════

def check_ipqualityscore(url: str) -> Dict[str, Any]:
    """
    Get domain reputation, age, DNS status, SSL info via IPQualityScore.
    """
    result = {
        "available": False,
        "score": 0.0,
        "domain_age_days": -1,
        "fraud_score": 0,
        "is_suspicious": False,
        "is_malware": False,
        "is_phishing": False,
        "dns_valid": True,
        "server": None,
        "category": None,
        "risk_factors": [],
        "error": None
    }

    if not IPQS_API_KEY:
        result["error"] = "IPQS_API_KEY not set"
        return result

    try:
        import urllib.parse
        encoded_url = urllib.parse.quote(url, safe='')
        api_url = f"https://www.ipqualityscore.com/api/json/url/{IPQS_API_KEY}/{encoded_url}"

        resp = requests.get(
            api_url,
            params={"strictness": 1, "fast": 1},
            timeout=TIMEOUT
        )

        if resp.status_code != 200:
            result["error"] = f"IPQS API error: HTTP {resp.status_code}"
            return result

        data = resp.json()

        if not data.get("success", False):
            result["error"] = data.get("message", "IPQS API returned failure")
            return result

        # Domain age
        domain_age = data.get("domain_age", {})
        if isinstance(domain_age, dict):
            age_days = domain_age.get("days", -1)
        else:
            age_days = -1

        fraud_score = data.get("fraud_score", 0)
        risk_factors = []

        if age_days >= 0 and age_days < 30:
            risk_factors.append(f"Domain very new: {age_days} days old")
        if data.get("malware", False):
            risk_factors.append("Malware detected")
        if data.get("phishing", False):
            risk_factors.append("Phishing detected")
        if not data.get("dns_valid", True):
            risk_factors.append("Invalid DNS records")
        if data.get("suspicious", False):
            risk_factors.append("Suspicious patterns detected")
        if data.get("spamming", False):
            risk_factors.append("Associated with spam")

        # Compute score from multiple signals
        score = fraud_score / 100.0
        if data.get("malware") or data.get("phishing"):
            score = max(score, 0.9)
        if age_days >= 0 and age_days < 7:
            score = max(score, 0.7)
        elif age_days >= 0 and age_days < 30:
            score = max(score, 0.4)

        result.update({
            "available": True,
            "score": round(min(score, 1.0), 4),
            "domain_age_days": age_days,
            "fraud_score": fraud_score,
            "is_suspicious": data.get("suspicious", False),
            "is_malware": data.get("malware", False),
            "is_phishing": data.get("phishing", False),
            "dns_valid": data.get("dns_valid", True),
            "server": data.get("server", None),
            "category": data.get("category", None),
            "risk_factors": risk_factors,
        })

    except requests.Timeout:
        result["error"] = "IPQS API timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# FUSION — Combine All Intelligence Sources
# ═══════════════════════════════════════════════════════════════════════════════

def run_threat_intelligence(url: str) -> Dict[str, Any]:
    """
    Run all threat intelligence layers and return combined result.
    Weights: VT=0.50, GSB=0.30 (binary but very reliable), IPQS=0.20
    """
    vt    = check_virustotal(url)
    gsb   = check_google_safe_browsing(url)
    ipqs  = check_ipqualityscore(url)

    # Weighted fusion
    weights = {"vt": 0.50, "gsb": 0.30, "ipqs": 0.20}
    active_weight = 0.0
    weighted_score = 0.0

    if vt["available"]:
        weighted_score += weights["vt"] * vt["score"]
        active_weight  += weights["vt"]

    if gsb["available"]:
        weighted_score += weights["gsb"] * gsb["score"]
        active_weight  += weights["gsb"]

    if ipqs["available"]:
        weighted_score += weights["ipqs"] * ipqs["score"]
        active_weight  += weights["ipqs"]

    # Normalize to active APIs
    intelligence_score = (weighted_score / active_weight) if active_weight > 0 else 0.0

    # Hard override: if GSB or VT definitively flags it, it IS phishing
    if gsb.get("is_flagged"):
        intelligence_score = max(intelligence_score, 0.95)
    if vt.get("verdict") == "phishing":
        intelligence_score = max(intelligence_score, 0.90)
    if ipqs.get("is_phishing") or ipqs.get("is_malware"):
        intelligence_score = max(intelligence_score, 0.90)

    return {
        "intelligence_score": round(intelligence_score, 4),
        "virustotal": vt,
        "google_safe_browsing": gsb,
        "ipqualityscore": ipqs,
        "apis_available": sum([vt["available"], gsb["available"], ipqs["available"]]),
    }
