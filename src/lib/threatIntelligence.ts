// ═══════════════════════════════════════════════════════════
// PhishGuard v2 — Threat Intelligence Layer
// virusTotal, Google Safe Browsing, IPQualityScore
// ═══════════════════════════════════════════════════════════

import type { IntelResult, VirusTotalResult, GoogleSafeBrowsingResult, IPQSResult } from "./types";

const TIMEOUT = 8000;

async function fetchWithTimeout(url: string, options: RequestInit) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), TIMEOUT);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}

// ─── VirusTotal ──────────────────────────────────────────

async function checkVirusTotal(url: string): Promise<VirusTotalResult> {
  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) return { available: false, score: 0, malicious: 0, suspicious: 0, harmless: 0, totalEngines: 0, verdict: "unknown", categories: [], error: "No API key" };

  try {
    const urlId = Buffer.from(url).toString("base64").replace(/=/g, "");
    const resp = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": apiKey },
    });

    if (resp.status === 404) {
      // Not seen before, submit for scanning
      await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
        body: `url=${encodeURIComponent(url)}`,
      });
      return { available: true, score: 0, malicious: 0, suspicious: 0, harmless: 0, totalEngines: 0, verdict: "unknown", categories: [], error: "URL submitted for scanning" };
    }

    if (!resp.ok) throw new Error(`VT API error: ${resp.status}`);

    const data = await resp.json();
    const stats = data.data.attributes.last_analysis_stats;
    const malicious = stats.malicious || 0;
    
    return {
      available: true,
      score: malicious > 0 ? 1 : 0,
      malicious,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      totalEngines: Object.values(stats).reduce((a: any, b: any) => a + b, 0) as number,
      verdict: malicious > 2 ? "phishing" : malicious > 0 ? "suspicious" : "clean",
      categories: Object.values(data.data.attributes.categories || {}),
      error: null,
    };
  } catch (e) {
    return { available: false, score: 0, malicious: 0, suspicious: 0, harmless: 0, totalEngines: 0, verdict: "unknown", categories: [], error: String(e) };
  }
}

// ─── Google Safe Browsing ────────────────────────────────

async function checkGSB(url: string): Promise<GoogleSafeBrowsingResult> {
  const apiKey = process.env.GSB_API_KEY;
  if (!apiKey) return { available: false, isFlagged: false, threatType: null, platformType: null, score: 0, error: "No API key" };

  try {
    const resp = await fetchWithTimeout(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "phishguard", clientVersion: "2.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    });

    if (!resp.ok) throw new Error(`GSB API error: ${resp.status}`);

    const data = await resp.json();
    const isFlagged = data.matches && data.matches.length > 0;
    
    return {
      available: true,
      isFlagged,
      threatType: isFlagged ? data.matches[0].threatType : null,
      platformType: isFlagged ? data.matches[0].platformType : null,
      score: isFlagged ? 1 : 0,
      error: null,
    };
  } catch (e) {
    return { available: false, isFlagged: false, threatType: null, platformType: null, score: 0, error: String(e) };
  }
}

// ─── IPQualityScore ──────────────────────────────────────

async function checkIPQS(url: string): Promise<IPQSResult> {
  const apiKey = process.env.IPQS_API_KEY;
  if (!apiKey) return { available: false, score: 0, domainAgeDays: 0, fraudScore: 0, isSuspicious: false, isMalware: false, isPhishing: false, dnsValid: false, server: null, category: null, riskFactors: [], error: "No API key" };

  try {
    const resp = await fetchWithTimeout(`https://www.ipqualityscore.com/api/json/url/${apiKey}/${encodeURIComponent(url)}`, {
      method: "GET",
    });

    if (!resp.ok) throw new Error(`IPQS API error: ${resp.status}`);

    const data = await resp.json();
    if (!data.success) throw new Error(data.message || "IPQS request failed");

    return {
      available: true,
      score: data.fraud_score / 100,
      domainAgeDays: data.domain_age?.days || 0,
      fraudScore: data.fraud_score || 0,
      isSuspicious: data.suspicious || false,
      isMalware: data.malware || false,
      isPhishing: data.phishing || false,
      dnsValid: data.dns_valid || false,
      server: data.server || null,
      category: data.category || null,
      riskFactors: [], // would parse more if available
      error: null,
    };
  } catch (e) {
    return { available: false, score: 0, domainAgeDays: 0, fraudScore: 0, isSuspicious: false, isMalware: false, isPhishing: false, dnsValid: false, server: null, category: null, riskFactors: [], error: String(e) };
  }
}

// ─── Fusion ──────────────────────────────────────────────

export async function runIntelLayer(url: string): Promise<IntelResult> {
  const [vt, gsb, ipqs] = await Promise.all([
    checkVirusTotal(url),
    checkGSB(url),
    checkIPQS(url),
  ]);

  let apisAvailable = 0;
  let totalScore = 0;

  if (vt.available) { apisAvailable++; totalScore += vt.score; }
  if (gsb.available) { apisAvailable++; totalScore += gsb.score; }
  if (ipqs.available) { apisAvailable++; totalScore += ipqs.score; }

  return {
    intelligenceScore: apisAvailable > 0 ? totalScore / apisAvailable : 0,
    virustotal: vt,
    googleSafeBrowsing: gsb,
    ipqualityscore: ipqs,
    apisAvailable,
  };
}
