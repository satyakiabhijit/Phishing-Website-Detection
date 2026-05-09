// ═══════════════════════════════════════════════════════════
// PhishGuard v2 — TypeScript Feature Extractor (Fixed)
// Aligned with URL-only training (21 features)
// ═══════════════════════════════════════════════════════════

import { NGRAM_MODEL, NGRAM_VOCAB_SIZE } from "./ngramModel";
import { isTechBrand } from "./whitelist";
import type { FeatureVector, FeatureMeta } from "./types";

// ─── Constants ───────────────────────────────────────────

export const KNOWN_BRANDS: string[] = [
  "google","facebook","amazon","microsoft","apple","netflix","paypal",
  "instagram","twitter","linkedin","yahoo","ebay","walmart","target",
  "chase","bankofamerica","wellsfargo","citibank","americanexpress",
  "flipkart","myntra","snapdeal","paytm","phonepe","googlepay",
  "hdfc","icici","sbi","axis","kotak","github","gitlab",
  "stackoverflow","reddit","youtube","gmail","dropbox","spotify",
  "adobe","salesforce","oracle","whatsapp","telegram","discord",
  "slack","zoom","teams","openai","anthropic","claude","notion",
  "figma","canva","trello","asana","stripe","shopify","coinbase",
  "binance","revolut","nubank","wise","venmo","cashapp","zelle",
];

const TLD_LEGIT_PROB: Record<string, number> = {
  com: 0.52, org: 0.08, net: 0.06, edu: 0.03, gov: 0.02,
  io: 0.04, co: 0.03, info: 0.02, biz: 0.01, us: 0.02,
  uk: 0.03, de: 0.02, fr: 0.02, jp: 0.02, ca: 0.02,
};

// ─── Helpers ─────────────────────────────────────────────

export function computeShannonEntropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    if (p > 0) h -= p * Math.log2(p);
  }
  return h;
}

export function detectHomoglyphs(domain: string): string[] {
  const homoglyphs = [];
  // Basic Cyrillic/Greek checks that typically look like latin characters
  if (/[а-яА-Я]/.test(domain)) homoglyphs.push("Cyrillic characters detected");
  if (/[α-ωΑ-Ω]/.test(domain)) homoglyphs.push("Greek characters detected");
  if (domain.includes("xn--")) homoglyphs.push("Punycode detected");
  return homoglyphs;
}

function damerauLevenshtein(s1: string, s2: string): number {
  const len1 = s1.length, len2 = s2.length;
  if (Math.abs(len1 - len2) > 3) return Math.max(len1, len2);
  const d: number[][] = Array.from({ length: len1 + 1 }, () => new Array(len2 + 1).fill(0));
  for (let i = 0; i <= len1; i++) d[i][0] = i;
  for (let j = 0; j <= len2; j++) d[0][j] = j;
  for (let i = 1; i <= len1; i++) {
    for (let j = 1; j <= len2; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && s1[i - 1] === s2[j - 2] && s1[i - 2] === s2[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + cost);
      }
    }
  }
  return d[len1][len2];
}

export function computeTyposquatDistance(domain: string, brands: string[]): { brand: string; distance: number; score: number } {
  if (!brands.length || !domain) return { brand: "", distance: 99, score: 0 };
  const d = domain.toLowerCase().trim();
  if (brands.includes(d)) return { brand: d, distance: 0, score: 0 };
  let minDist = 99, closest = "";
  for (const brand of brands) {
    if (Math.abs(d.length - brand.length) > 4) continue;
    const dist = damerauLevenshtein(d, brand);
    if (dist < minDist) { minDist = dist; closest = brand; }
  }
  let score = 0;
  if (minDist === 1) score = 0.95;
  else if (minDist === 2) score = 0.60;
  return { brand: closest, distance: minDist, score };
}

export function computeNgramPerplexity(domain: string): number {
  const d = domain.toLowerCase().trim();
  const n = 3;
  const padded = "^".repeat(n - 1) + d + "$";
  let logProb = 0, count = 0;
  for (let i = 0; i <= padded.length - n; i++) {
    const trigram = padded.slice(i, i + n);
    const prob = NGRAM_MODEL[trigram] ?? 1 / (NGRAM_VOCAB_SIZE + 1);
    logProb += Math.log(prob);
    count++;
  }
  const avgLogProb = count > 0 ? logProb / count : -10;
  return Math.exp(-avgLogProb);
}

// ─── Build Feature Vector ────────────────────────────────

export function buildFeatureVector(url: string): FeatureVector {
  let normalizedUrl = url;
  if (!/^https?:\/\//i.test(normalizedUrl)) normalizedUrl = "https://" + normalizedUrl;

  let parsed: URL;
  try { parsed = new URL(normalizedUrl); } catch { parsed = new URL("https://invalid.local"); }

  const hostname = parsed.hostname;
  const fullUrl = normalizedUrl;
  const urlLen = fullUrl.length;
  const domainParts = hostname.split(".");
  const tld = domainParts[domainParts.length - 1]?.toLowerCase() ?? "";
  const domainName = domainParts.length >= 2 ? domainParts[domainParts.length - 2].toLowerCase() : hostname.toLowerCase();

  // Character counts
  const letterMatches = fullUrl.match(/[a-zA-Z]/g) || [];
  const digitMatches = fullUrl.match(/\d/g) || [];
  const equalsMatches = fullUrl.match(/=/g) || [];
  const qmarkMatches = fullUrl.match(/\?/g) || [];
  const ampMatches = fullUrl.match(/&/g) || [];
  const obfuscatedMatches = fullUrl.match(/%[0-9a-fA-F]{2}/g) || [];
  const specialChars = fullUrl.replace(/[a-zA-Z0-9./:?=&\-_]/g, "");
  const spacialChars = fullUrl.replace(/[a-zA-Z0-9/]/g, "");

  // Character continuation rate
  let maxRun = 1, currentRun = 1;
  for (let i = 1; i < fullUrl.length; i++) {
    if (fullUrl[i] === fullUrl[i - 1]) {
      currentRun++;
      if (currentRun > maxRun) maxRun = currentRun;
    } else { currentRun = 1; }
  }

  // URL character entropy
  const entropy = computeShannonEntropy(fullUrl);
  const urlCharProb = Math.min(entropy / 6.3, 1.0);

  const tldLegitProb = TLD_LEGIT_PROB[tld] ?? 0.01;

  // Features mapping (MUST match URL_ONLY_FEATURES in training.py)
  const f: Record<string, number> = {
    URLLength: urlLen,
    DomainLength: hostname.length,
    IsDomainIP: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0,
    CharContinuationRate: Math.round((maxRun / urlLen) * 10000) / 10000,
    TLDLegitimateProb: tldLegitProb,
    URLCharProb: Math.round(urlCharProb * 10000) / 10000,
    TLDLength: tld.length,
    NoOfSubDomain: Math.max(0, domainParts.length - 2),
    HasObfuscation: obfuscatedMatches.length > 0 ? 1 : 0,
    NoOfObfuscatedChar: obfuscatedMatches.length,
    ObfuscationRatio: urlLen > 0 ? Math.round((obfuscatedMatches.length / urlLen) * 10000) / 10000 : 0,
    NoOfLettersInURL: letterMatches.length,
    LetterRatioInURL: urlLen > 0 ? Math.round((letterMatches.length / urlLen) * 10000) / 10000 : 0,
    NoOfDegitsInURL: digitMatches.length,
    DegitRatioInURL: urlLen > 0 ? Math.round((digitMatches.length / urlLen) * 10000) / 10000 : 0,
    NoOfEqualsInURL: equalsMatches.length,
    NoOfQMarkInURL: qmarkMatches.length,
    NoOfAmpersandInURL: ampMatches.length,
    NoOfOtherSpecialCharsInURL: specialChars.length,
    SpacialCharRatioInURL: urlLen > 0 ? Math.round((spacialChars.length / urlLen) * 10000) / 10000 : 0,
    IsHTTPS: fullUrl.startsWith("https") ? 1 : 0,
  };

  const featureOrder = [
    "URLLength", "DomainLength", "IsDomainIP",
    "CharContinuationRate", "TLDLegitimateProb", "URLCharProb",
    "TLDLength", "NoOfSubDomain", "HasObfuscation",
    "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL",
    "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
    "IsHTTPS"
  ];

  const vector = featureOrder.map((name) => f[name] ?? 0);

  const typo = computeTyposquatDistance(domainName, KNOWN_BRANDS);
  const perp = computeNgramPerplexity(domainName);

  const meta: FeatureMeta = {
    entropy: computeShannonEntropy(domainName),
    homoglyphs: [], // simplified for now
    closestBrand: typo.brand,
    brandDistance: typo.distance,
    perplexity: perp,
  };

  return { features: vector, meta };
}
