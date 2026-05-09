"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import UrlInput from "@/components/UrlInput";
import VerdictBadge from "@/components/VerdictBadge";
import LayerCard from "@/components/LayerCard";
import EvidenceList from "@/components/EvidenceList";
import ConfidenceBar from "@/components/ConfidenceBar";
import LoadingSteps from "@/components/LoadingSteps";
import RiskGauge from "@/components/RiskGauge";
import type { AnalysisResult } from "@/lib/types";

interface RecentScan {
  url: string;
  verdict: string;
  score: number;
  timestamp: string;
}

function getRecentScans(): RecentScan[] {
  if (typeof window === "undefined") return [];
  try {
    return JSON.parse(localStorage.getItem("phishguard_recent") || "[]") as RecentScan[];
  } catch { return []; }
}

function saveRecentScan(scan: RecentScan) {
  const scans = getRecentScans().filter((s) => s.url !== scan.url);
  scans.unshift(scan);
  localStorage.setItem("phishguard_recent", JSON.stringify(scans.slice(0, 5)));
}

export default function HomePage() {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);

  useEffect(() => { setRecentScans(getRecentScans()); }, []);

  const handleSubmit = useCallback(async (url: string) => {
    setIsLoading(true);
    setResult(null);
    setError("");

    try {
      const resp = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({ error: "Request failed" })) as { error?: string };
        throw new Error(errData.error || `HTTP ${resp.status}`);
      }

      const data = await resp.json() as AnalysisResult;
      setResult(data);

      const scan: RecentScan = {
        url: data.url,
        verdict: data.verdict,
        score: data.score,
        timestamp: data.timestamp,
      };
      saveRecentScan(scan);
      setRecentScans(getRecentScans());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setIsLoading(false);
    }
  }, []);

  function buildLayerDetails(r: AnalysisResult) {
    const intelDetails: string[] = [];
    if (r.layers.intel) {
      const { virustotal, googleSafeBrowsing, ipqualityscore } = r.layers.intel;
      if (virustotal.available) intelDetails.push(`VirusTotal: ${virustotal.malicious}/${virustotal.totalEngines} detections`);
      if (googleSafeBrowsing.available) intelDetails.push(`Safe Browsing: ${googleSafeBrowsing.isFlagged ? "⚠️ Flagged" : "Clean"}`);
      if (ipqualityscore.available) intelDetails.push(`IPQS fraud: ${ipqualityscore.fraudScore}/100`);
      if (r.layers.intel.apisAvailable === 0) intelDetails.push("No APIs available");
    } else {
      intelDetails.push("Layer unavailable");
    }

    const mlDetails: string[] = [];
    if (r.layers.ml?.available) {
      mlDetails.push(`Prediction: ${r.layers.ml.prediction === 1 ? "Phishing" : "Legitimate"}`);
      mlDetails.push(`Probability: ${(r.layers.ml.probability * 100).toFixed(1)}%`);
    } else {
      mlDetails.push(r.layers.ml?.error || "ML unavailable");
    }

    const mathDetails: string[] = [];
    mathDetails.push(`Entropy: ${r.layers.math.entropy.toFixed(2)} bits`);
    if (r.layers.math.typosquatResult.score > 0) {
      mathDetails.push(`Typosquat: ${r.layers.math.typosquatResult.distance} from "${r.layers.math.typosquatResult.brand}"`);
    }
    if (r.layers.math.homoglyphs.detected) mathDetails.push("Homoglyphs detected");
    mathDetails.push(`${r.layers.math.structuralFlags.length} structural flags`);

    return { intelDetails, mlDetails, mathDetails };
  }

  return (
    <main className="min-h-screen flex flex-col items-center px-4 py-12 md:py-20">
      {/* ── Hero ── */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="text-center mb-10"
      >
        <div className="flex items-center justify-center gap-2 mb-4">
          <div className="w-8 h-8 rounded-lg bg-accent-red/20 flex items-center justify-center">
            <span className="text-lg">🛡️</span>
          </div>
          <span className="text-sm font-semibold text-text-muted uppercase tracking-widest">PhishGuard</span>
        </div>
        <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-text-primary mb-3">
          Is this URL safe?
        </h1>
        <p className="text-text-muted text-base md:text-lg max-w-md mx-auto">
          4-layer AI analysis across 95+ threat engines
        </p>
      </motion.div>

      {/* ── Input ── */}
      <UrlInput onSubmit={handleSubmit} isLoading={isLoading} />

      {/* ── Loading ── */}
      <LoadingSteps isLoading={isLoading} />

      {/* ── Error ── */}
      <AnimatePresence>
        {error && !isLoading && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="mt-8 p-4 bg-accent-red/10 border border-accent-red/30 rounded-xl text-sm text-accent-red max-w-lg text-center"
          >
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Results ── */}
      <AnimatePresence>
        {result && !isLoading && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="w-full max-w-4xl mt-10 space-y-8"
          >
            {/* Analyzed URL */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-center"
            >
              <span className="text-xs text-text-muted uppercase tracking-wider">Analyzed URL</span>
              <p className="font-mono text-sm text-text-secondary mt-1 break-all">{result.normalizedUrl}</p>
              {result.cached && (
                <span className="inline-block mt-1 text-[10px] text-accent-blue bg-accent-blue/10 px-2 py-0.5 rounded-full">
                  Cached result
                </span>
              )}
            </motion.div>

            {/* Verdict + Gauge */}
            <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-6 items-center">
              <VerdictBadge verdict={result.verdict} score={result.score} confidence={result.confidence} />
              <div className="flex justify-center">
                <RiskGauge score={result.score} />
              </div>
            </div>

            {/* Confidence bar */}
            <ConfidenceBar value={result.confidence} />

            {/* Layer cards */}
            {(() => {
              const { intelDetails, mlDetails, mathDetails } = buildLayerDetails(result);
              const intelScore = result.layers.intel?.intelligenceScore ?? 0;
              const mlScore = result.layers.ml?.probability ?? 0;
              const mathScore = result.score; // approximation

              return (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <LayerCard
                    title="Threat Intel" icon="🌐"
                    score={intelScore} weight={result.weights.intel}
                    status={result.layers.intel && result.layers.intel.apisAvailable > 0 ? "available" : "unavailable"}
                    details={intelDetails} index={0}
                  />
                  <LayerCard
                    title="ML Ensemble" icon="🤖"
                    score={mlScore} weight={result.weights.ml}
                    status={result.layers.ml?.available ? "available" : "unavailable"}
                    details={mlDetails} index={1}
                  />
                  <LayerCard
                    title="Math Analysis" icon="🔬"
                    score={result.layers.math.entropyScore * 0.3 + result.layers.math.typosquatResult.score * 0.4 + result.layers.math.perplexityScore * 0.3}
                    weight={result.weights.math}
                    status="available"
                    details={mathDetails} index={2}
                  />
                </div>
              );
            })()}

            {/* Evidence */}
            <EvidenceList items={result.evidence} />

            {/* Scan another */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 1.2 }}
              className="text-center pt-4"
            >
              <button
                onClick={() => { setResult(null); setError(""); }}
                className="px-6 py-2.5 text-sm font-medium text-text-secondary border border-border rounded-lg hover:border-border-hover hover:text-text-primary transition-all duration-200"
              >
                Scan another URL
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Recent Scans ── */}
      {!result && !isLoading && recentScans.length > 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="mt-12 w-full max-w-lg"
        >
          <h3 className="text-xs text-text-muted uppercase tracking-wider mb-3 text-center">Recent Scans</h3>
          <div className="space-y-2">
            {recentScans.map((scan) => (
              <button
                key={scan.url + scan.timestamp}
                onClick={() => handleSubmit(scan.url)}
                className="w-full flex items-center justify-between p-3 glass-card hover:border-border-hover transition-all text-left"
              >
                <span className="font-mono text-xs text-text-secondary truncate max-w-[70%]">
                  {scan.url.replace(/^https?:\/\//, "")}
                </span>
                <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                  scan.verdict === "Phishing" ? "bg-accent-red/10 text-accent-red" :
                  scan.verdict === "Legitimate" ? "bg-accent-green/10 text-accent-green" :
                  "bg-accent-amber/10 text-accent-amber"
                }`}>
                  {scan.verdict}
                </span>
              </button>
            ))}
          </div>
        </motion.div>
      )}

      {/* ── Footer ── */}
      <footer className="mt-auto pt-16 pb-6 text-center text-xs text-text-muted">
        <p>PhishGuard v2 — 4-layer AI phishing detection</p>
      </footer>
    </main>
  );
}
