// ═══════════════════════════════════════════════════════════
// PhishGuard v2 — Analysis Fusion Engine
// Combines Intel, ML, and Math layers into a final verdict
// ═══════════════════════════════════════════════════════════

import { isTrustedDomain, isRegulatedInstitutionalDomain, TRUSTED_DOMAIN_BONUS } from "./whitelist";
import { KNOWN_BRANDS } from "./featureExtractor";
import type { AnalysisResult, IntelResult, MLResult, MathResult, EvidenceItem, Verdict } from "./types";

const BRAND_DOMAINS: Record<string, string> = {
  flipkart: "flipkart.com",
  myntra: "myntra.com",
  snapdeal: "snapdeal.com",
  paytm: "paytm.com",
  phonepe: "phonepe.com",
  googlepay: "pay.google.com",
  hdfc: "hdfcbank.com",
  icici: "icicibank.com",
  sbi: "onlinesbi.sbi",
  axis: "axisbank.com",
  kotak: "kotak.com",
  google: "google.com",
  facebook: "facebook.com",
  amazon: "amazon.com",
  microsoft: "microsoft.com",
  apple: "apple.com",
  netflix: "netflix.com",
  paypal: "paypal.com",
  instagram: "instagram.com",
  twitter: "twitter.com",
  linkedin: "linkedin.com",
  yahoo: "yahoo.com",
  ebay: "ebay.com",
  walmart: "walmart.com",
  target: "target.com",
  chase: "chase.com",
  bankofamerica: "bankofamerica.com",
  wellsfargo: "wellsfargo.com",
  citibank: "citibank.com",
  americanexpress: "americanexpress.com",
  github: "github.com",
  gitlab: "gitlab.com",
  stackoverflow: "stackoverflow.com",
  reddit: "reddit.com",
  youtube: "youtube.com",
  gmail: "mail.google.com",
  dropbox: "dropbox.com",
  spotify: "spotify.com",
  adobe: "adobe.com",
  salesforce: "salesforce.com",
  oracle: "oracle.com",
  whatsapp: "whatsapp.com",
  telegram: "telegram.org",
  discord: "discord.com",
  slack: "slack.com",
  zoom: "zoom.us",
  teams: "teams.microsoft.com",
  live: "live.com",
  office: "office.com",
  microsoftonline: "microsoftonline.com",
  openai: "openai.com",
  anthropic: "anthropic.com",
  claude: "claude.ai",
  notion: "notion.so",
  figma: "figma.com",
  canva: "canva.com",
  trello: "trello.com",
  asana: "asana.com",
  stripe: "stripe.com",
  shopify: "shopify.com",
  coinbase: "coinbase.com",
  binance: "binance.com",
  revolut: "revolut.com",
  nubank: "nubank.com.br",
  wise: "wise.com",
  venmo: "venmo.com",
  cashapp: "cash.app",
  zelle: "zellepay.com",
};

export function fuseAnalysis(
  url: string,
  normalizedUrl: string,
  intel: IntelResult | null,
  ml: MLResult | null,
  math: MathResult,
  cached = false
): AnalysisResult {
  const weights = {
    intel: 0.55,
    ml: 0.25,
    math: 0.20,
  };

  // Adjust weights if some layers are missing
  let totalWeight = 0;
  if (intel && intel.apisAvailable > 0) totalWeight += weights.intel;
  if (ml && ml.available) totalWeight += weights.ml;
  totalWeight += weights.math;

  const normalizedWeights = {
    intel: (intel && intel.apisAvailable > 0 ? weights.intel : 0) / totalWeight,
    ml: (ml && ml.available ? weights.ml : 0) / totalWeight,
    math: weights.math / totalWeight,
  };

  // Compute raw scores
  const intelScore = intel ? intel.intelligenceScore : 0;
  const mlScore = ml ? ml.probability : 0.5;
  const mathScore = (math.entropyScore * 0.3) + (math.typosquatResult.score * 0.4) + (math.perplexityScore * 0.3);

  let finalScore = (intelScore * normalizedWeights.intel) + 
                   (mlScore * normalizedWeights.ml) + 
                   (mathScore * normalizedWeights.math);

  // Apply trusted infrastructure bonus
  const parsed = new URL(normalizedUrl);
  if (isTrustedDomain(parsed.hostname) && finalScore < 0.7) {
    finalScore = Math.max(0, finalScore - TRUSTED_DOMAIN_BONUS);
  }

  // Critical heuristics (Overrides)
  const hostnameWithoutWww = parsed.hostname.toLowerCase().replace(/^www\./, "");
  
  let isOfficialBrandDomain = false;
  let matchedBrandWord = "";

  for (const [brandWord, officialDomain] of Object.entries(BRAND_DOMAINS)) {
    if (
      hostnameWithoutWww === officialDomain.toLowerCase() ||
      hostnameWithoutWww.endsWith("." + officialDomain.toLowerCase())
    ) {
      isOfficialBrandDomain = true;
      matchedBrandWord = brandWord;
      break;
    }
  }

  const isOriginalBrand = matchedBrandWord !== "" || KNOWN_BRANDS.some(b => hostnameWithoutWww.includes(b));

  if (isOfficialBrandDomain || isRegulatedInstitutionalDomain(parsed.hostname)) {
    finalScore = 0.0; // Guaranteed safe
    // Correct the ML False Positive visually so the UI doesn't confuse the user
    if (ml && ml.available) {
      ml.prediction = 0;
      ml.probability = 0.0;
      ml.confidence = 0.99;
    }
  } else {
    if (!isOriginalBrand) {
      if (math.typosquatResult.score >= 0.85) {
        // Distance 1 or Brand Spoofing (e.g. paypa1.com, paypal-secure.tk)
        finalScore = Math.max(finalScore, 0.85); // Auto-bump to Phishing
      } else if (math.typosquatResult.score > 0.5) {
        // Distance 2: High-probability typosquat (e.g. flikar.in)
        finalScore = Math.max(finalScore, 0.72); // Auto-bump to Suspicious/Phishing
      }
    }
    if (math.homoglyphs && math.homoglyphs.detected) {
      finalScore = Math.max(finalScore, 0.85); // Auto-bump to Phishing
    }

    // ML Overrides (Zero-Day Phishing Safeguard)
    if (ml && ml.available && !isTrustedDomain(parsed.hostname)) {
      if (ml.probability > 0.95) {
        finalScore = Math.max(finalScore, 0.85); // Auto-bump to Phishing
      } else if (ml.probability > 0.80) {
        finalScore = Math.max(finalScore, 0.70); // Auto-bump to Suspicious/Phishing
      }
    }
  }

  // Determine verdict
  let verdict: Verdict = "Uncertain";
  if (finalScore >= 0.85) verdict = "Phishing";
  else if (finalScore >= 0.65) {
     // If intel is 100% clean, be more lenient
     if (intel && intel.intelligenceScore === 0 && intel.apisAvailable >= 2) verdict = "Uncertain";
     else verdict = "Phishing";
  } else if (finalScore < 0.35) {
     verdict = "Legitimate";
  }

  // Build evidence list
  const evidence: EvidenceItem[] = [];

  if (intel) {
    if (intel.virustotal.malicious > 2) evidence.push({ id: "vt_phish", source: "intel", severity: "critical", title: "Flagged by VirusTotal", description: `${intel.virustotal.malicious} security vendors flagged this URL as malicious.`, icon: "🛡️" });
    if (intel.googleSafeBrowsing.isFlagged) evidence.push({ id: "gsb_phish", source: "intel", severity: "critical", title: "Blocked by Google", description: "Google Safe Browsing has blacklisted this URL.", icon: "🔍" });
    if (intel.ipqualityscore.fraudScore > 85) evidence.push({ id: "ipqs_phish", source: "intel", severity: "high", title: "High IPQS Fraud Score", description: `IPQualityScore assigned a fraud score of ${intel.ipqualityscore.fraudScore}/100.`, icon: "📊" });
  }

  if (ml && ml.available && ml.probability > 0.8) {
    evidence.push({ id: "ml_phish", source: "ml", severity: "high", title: "AI Detection Engine", description: `Ensemble models detected patterns common in phishing pages with ${(ml.probability * 100).toFixed(1)}% probability.`, icon: "🤖" });
  }

  if (math.typosquatResult.score > 0.5) {
    const isDistance1 = math.typosquatResult.score > 0.8;
    evidence.push({ 
      id: "typo_brand", 
      source: "math", 
      severity: isDistance1 ? "critical" : "high", 
      title: "Brand Impersonation", 
      description: `This domain is a close match to "${math.typosquatResult.brand}" (edit-distance ${math.typosquatResult.distance}), suggesting a typosquatting attempt.`, 
      icon: "🎯" 
    });
  }
  if (math.homoglyphs && math.homoglyphs.detected) {
    evidence.push({ id: "homoglyph", source: "math", severity: "high", title: "Homoglyph Detected", description: "The domain uses look-alike characters from different alphabets to deceive users.", icon: "🔤" });
  }
  if (math.perplexityScore > 0.7) {
    evidence.push({ id: "perplexity", source: "math", severity: "medium", title: "Unusual Domain Name", description: "The domain name has low linguistic probability, common in auto-generated phishing domains.", icon: "🔬" });
  }

  let suggestedSafeUrl: string | undefined = undefined;
  if (math.typosquatResult.score > 0.5 && !isOriginalBrand && math.typosquatResult.brand) {
    const safeDomain = BRAND_DOMAINS[math.typosquatResult.brand.toLowerCase()] || `${math.typosquatResult.brand.toLowerCase()}.com`;
    suggestedSafeUrl = `https://${safeDomain}`;
  }

  return {
    verdict,
    score: finalScore,
    confidence: ml ? ml.confidence : 0.5,
    cached,
    analysisId: Math.random().toString(36).substring(7),
    url,
    normalizedUrl,
    timestamp: new Date().toISOString(),
    layers: { intel, ml, math },
    evidence,
    weights: normalizedWeights,
    suggestedSafeUrl,
  };
}
