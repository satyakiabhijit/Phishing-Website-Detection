// ═══════════════════════════════════════════════════════════
// PhishGuard v2 — Core Type Definitions
// ═══════════════════════════════════════════════════════════

export type Verdict = "Phishing" | "Legitimate" | "Uncertain";
export type RiskLevel = "Critical" | "High" | "Medium" | "Low" | "Safe";
export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export interface FeatureMeta {
  entropy: number;
  homoglyphs: string[];
  closestBrand: string;
  brandDistance: number;
  perplexity: number;
}

export interface FeatureVector {
  features: number[];
  meta: FeatureMeta;
}

export interface VirusTotalResult {
  available: boolean;
  score: number;
  malicious: number;
  suspicious: number;
  harmless: number;
  totalEngines: number;
  verdict: "phishing" | "suspicious" | "clean" | "unknown";
  categories: string[];
  error: string | null;
}

export interface GoogleSafeBrowsingResult {
  available: boolean;
  isFlagged: boolean;
  threatType: string | null;
  platformType: string | null;
  score: number;
  error: string | null;
}

export interface IPQSResult {
  available: boolean;
  score: number;
  domainAgeDays: number;
  fraudScore: number;
  isSuspicious: boolean;
  isMalware: boolean;
  isPhishing: boolean;
  dnsValid: boolean;
  server: string | null;
  category: string | null;
  riskFactors: string[];
  error: string | null;
}

export interface IntelResult {
  intelligenceScore: number;
  virustotal: VirusTotalResult;
  googleSafeBrowsing: GoogleSafeBrowsingResult;
  ipqualityscore: IPQSResult;
  apisAvailable: number;
}

export interface MLResult {
  available: boolean;
  prediction: number;
  probability: number;
  confidence: number;
  error: string | null;
}

export interface TyposquatResult {
  brand: string;
  distance: number;
  score: number;
}

export interface HomoglyphResult {
  detected: boolean;
  chars: string[];
  normalizedDomain: string;
  score: number;
}

export interface MathResult {
  featureVector: number[];
  entropy: number;
  entropyScore: number;
  homoglyphs: HomoglyphResult;
  typosquatResult: TyposquatResult;
  perplexity: number;
  perplexityScore: number;
  structuralFlags: string[];
}

export interface EvidenceItem {
  id: string;
  source: "intel" | "ml" | "math";
  severity: SeverityLevel;
  title: string;
  description: string;
  icon: string;
}

export interface AnalysisResult {
  verdict: Verdict;
  score: number;
  confidence: number;
  cached: boolean;
  analysisId: string;
  url: string;
  normalizedUrl: string;
  timestamp: string;
  layers: {
    intel: IntelResult | null;
    ml: MLResult | null;
    math: MathResult;
  };
  evidence: EvidenceItem[];
  weights: {
    intel: number;
    ml: number;
    math: number;
  };
}

export interface AnalyzeRequest {
  url: string;
}

export interface AnalyzeErrorResponse {
  error: string;
  code: string;
}
