// ═══════════════════════════════════════════════════════════
// PhishGuard v2 — Analysis Fusion Engine
// Combines Intel, ML, and Math layers into a final verdict
// ═══════════════════════════════════════════════════════════

import { isTrustedDomain, TRUSTED_DOMAIN_BONUS } from "./whitelist";
import { KNOWN_BRANDS } from "./featureExtractor";
import type { AnalysisResult, IntelResult, MLResult, MathResult, EvidenceItem, Verdict } from "./types";

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
  if (math.typosquatResult.score > 0.9 && !KNOWN_BRANDS.includes(parsed.hostname.replace("www.", "").split(".")[0])) {
    // If it is an extreme typosquat (distance 1) of a known brand, but NOT the legitimate brand itself
    finalScore = Math.max(finalScore, 0.75); // Auto-bump to Phishing/Suspicious
  }
  if (math.homoglyphs && math.homoglyphs.length > 0) {
    finalScore = Math.max(finalScore, 0.85); // Auto-bump to Phishing
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

  if (math.typosquatResult.score > 0.8) {
    evidence.push({ id: "typo_brand", source: "math", severity: "medium", title: "Brand Impersonation", description: `This domain is a close match to "${math.typosquatResult.brand}", suggesting a typosquatting attempt.`, icon: "🎯" });
  }
  if (math.homoglyphs && math.homoglyphs.length > 0) {
    evidence.push({ id: "homoglyph", source: "math", severity: "high", title: "Homoglyph Detected", description: "The domain uses look-alike characters from different alphabets to deceive users.", icon: "🔤" });
  }
  if (math.perplexityScore > 0.7) {
    evidence.push({ id: "perplexity", source: "math", severity: "medium", title: "Unusual Domain Name", description: "The domain name has low linguistic probability, common in auto-generated phishing domains.", icon: "🔬" });
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
  };
}
