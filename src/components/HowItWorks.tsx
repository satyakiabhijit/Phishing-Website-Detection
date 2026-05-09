"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

// ─── Static data ─────────────────────────────────────────

const LAYERS = [
  {
    id: "intel",
    icon: "🌐",
    label: "Threat Intelligence",
    weight: "55%",
    color: "blue",
    border: "border-accent-blue/40",
    badge: "bg-accent-blue/10 text-accent-blue",
    glow: "shadow-accent-blue/10",
    steps: [
      { name: "VirusTotal", desc: "Queries 95+ AV engines via API. Returns malicious/suspicious/harmless counts." },
      { name: "Google Safe Browsing", desc: "Checks URL against Google's threat database (phishing, malware, unwanted software)." },
      { name: "IPQualityScore", desc: "Domain age, DNS validity, fraud score (0–100), malware/phishing flags." },
    ],
    detail: "The intel layer carries the highest weight (55%) because security vendor consensus is the strongest signal for known threats. APIs are called in parallel — if one fails, weights are renormalized automatically.",
  },
  {
    id: "ml",
    icon: "🤖",
    label: "ML Ensemble",
    weight: "25%",
    color: "purple",
    border: "border-purple-500/40",
    badge: "bg-purple-500/10 text-purple-400",
    glow: "shadow-purple-500/10",
    steps: [
      { name: "Random Forest (300 trees)", desc: "Ensemble of decision trees trained on 21 URL-only features." },
      { name: "XGBoost + LightGBM", desc: "Gradient boosted trees — best single-model AUC at 0.983." },
      { name: "MLP (128→64)", desc: "Feed-forward neural net for non-linear feature interactions." },
      { name: "Stacking Meta-Classifier", desc: "Logistic Regression trained on out-of-fold predictions of all base models." },
    ],
    detail: "Trained on the PhiUSIIL dataset (235K URLs). 29 page-content features were deliberately removed to eliminate data leakage — only 21 URL-extractable features are used, matching production inference exactly.",
  },
  {
    id: "math",
    icon: "🔬",
    label: "Mathematical Analysis",
    weight: "20%",
    color: "orange",
    border: "border-accent-amber/40",
    badge: "bg-accent-amber/10 text-accent-amber",
    glow: "shadow-accent-amber/10",
    steps: [
      { name: "Shannon Entropy", desc: "High URL entropy (>4 bits) is a strong signal of auto-generated phishing domains." },
      { name: "Homoglyph Detection", desc: "Scans for Cyrillic/Greek look-alike chars and Punycode encoding." },
      { name: "Typosquat Distance", desc: "Damerau-Levenshtein distance against 60 known brands. Score → 0.95 at distance 1." },
      { name: "N-gram Perplexity", desc: "Trigram language model — random-looking domains have high perplexity." },
    ],
    detail: "Math analysis runs entirely in TypeScript at ~0ms latency — no external API. It provides real-time overrides: a detected homoglyph auto-bumps the final score to ≥0.85 (Phishing) regardless of other layers.",
  },
];

const METRICS = [
  { model: "Random Forest",       acc: 0.9421, auc: 0.9798, f1: 0.9438 },
  { model: "XGBoost",             acc: 0.9508, auc: 0.9831, f1: 0.9521 },
  { model: "LightGBM",            acc: 0.9492, auc: 0.9825, f1: 0.9507 },
  { model: "MLP Neural Net",      acc: 0.9265, auc: 0.9611, f1: 0.9281 },
  { model: "Logistic Regression", acc: 0.8913, auc: 0.9421, f1: 0.8934 },
  { model: "Stacking Ensemble",   acc: 0.9551, auc: 0.9862, f1: 0.9565, isTop: true },
];

const FEATURES = [
  { name: "URLLength", imp: 0.142 },
  { name: "URLCharProb", imp: 0.131 },
  { name: "LetterRatioInURL", imp: 0.108 },
  { name: "DomainLength", imp: 0.097 },
  { name: "TLDLegitimateProb", imp: 0.089 },
  { name: "CharContinuationRate", imp: 0.078 },
  { name: "DegitRatioInURL", imp: 0.071 },
  { name: "SpacialCharRatioInURL", imp: 0.065 },
  { name: "NoOfLettersInURL", imp: 0.052 },
  { name: "NoOfOtherSpecialCharsInURL", imp: 0.044 },
];

// ─── Sub-components ──────────────────────────────────────

function MetricBar({ value, color }: { value: number; color: string }) {
  const pct = ((value - 0.88) / 0.12) * 100; // scale 0.88–1.00 → 0–100%
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-border rounded-full overflow-hidden">
        <motion.div
          className={`h-full rounded-full ${color}`}
          initial={{ width: 0 }}
          whileInView={{ width: `${Math.max(pct, 5)}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          viewport={{ once: true }}
        />
      </div>
      <span className="text-xs font-mono text-text-secondary w-14 text-right">
        {value.toFixed(4)}
      </span>
    </div>
  );
}

function FeatureBar({ name, imp }: { name: string; imp: number }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs font-mono text-text-muted w-44 truncate shrink-0">{name}</span>
      <div className="flex-1 h-2 bg-border rounded-full overflow-hidden">
        <motion.div
          className="h-full bg-gradient-to-r from-accent-amber to-accent-red rounded-full"
          initial={{ width: 0 }}
          whileInView={{ width: `${(imp / 0.15) * 100}%` }}
          transition={{ duration: 0.7, ease: "easeOut" }}
          viewport={{ once: true }}
        />
      </div>
      <span className="text-xs font-mono text-text-secondary w-10 text-right">{imp.toFixed(3)}</span>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────

export default function HowItWorks() {
  const [activeLayer, setActiveLayer] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"pipeline" | "metrics" | "features">("pipeline");

  return (
    <section id="how-it-works" className="w-full max-w-4xl mx-auto mt-24 mb-12 px-4">
      {/* Section header */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        className="text-center mb-10"
      >
        <span className="inline-block text-xs font-semibold uppercase tracking-widest text-text-muted mb-3 px-3 py-1 border border-border rounded-full">
          Research Overview
        </span>
        <h2 className="text-3xl md:text-4xl font-bold text-text-primary mb-3">
          How PhishGuard Works
        </h2>
        <p className="text-text-muted max-w-xl mx-auto text-sm md:text-base">
          A 4-layer weighted fusion architecture combining live threat intelligence, a stacking ML ensemble
          trained on 235K URLs, and zero-latency mathematical analysis.
        </p>
      </motion.div>

      {/* Tab switcher */}
      <div className="flex gap-1 p-1 bg-bg-surface border border-border rounded-xl mb-8 w-fit mx-auto">
        {(["pipeline", "metrics", "features"] as const).map((tab) => (
          <button
            key={tab}
            id={`hiw-tab-${tab}`}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-xs font-semibold rounded-lg capitalize transition-all duration-200 ${
              activeTab === tab
                ? "bg-bg-elevated text-text-primary shadow"
                : "text-text-muted hover:text-text-secondary"
            }`}
          >
            {tab === "pipeline" ? "🔄 Pipeline" : tab === "metrics" ? "📊 Results" : "🔬 Features"}
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        {/* ── PIPELINE TAB ── */}
        {activeTab === "pipeline" && (
          <motion.div
            key="pipeline"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="space-y-4"
          >
            {/* URL input node */}
            <div className="flex justify-center">
              <div className="flex items-center gap-2 px-4 py-2 bg-bg-surface border border-border rounded-full text-xs text-text-muted font-mono">
                <span>🔗</span> URL Input
                <span className="ml-2 text-accent-blue">→ Feature Extraction (21 signals)</span>
              </div>
            </div>

            {/* Layer cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {LAYERS.map((layer, i) => (
                <motion.button
                  key={layer.id}
                  id={`hiw-layer-${layer.id}`}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.1 }}
                  viewport={{ once: true }}
                  onClick={() => setActiveLayer(activeLayer === layer.id ? null : layer.id)}
                  className={`text-left p-5 glass-card border ${layer.border} shadow-lg ${layer.glow} hover:scale-[1.02] transition-all duration-200 cursor-pointer`}
                >
                  <div className="flex items-start justify-between mb-3">
                    <span className="text-2xl">{layer.icon}</span>
                    <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${layer.badge}`}>
                      {layer.weight}
                    </span>
                  </div>
                  <h3 className="font-semibold text-text-primary text-sm mb-2">{layer.label}</h3>
                  <ul className="space-y-1">
                    {layer.steps.map((s) => (
                      <li key={s.name} className="text-xs text-text-muted">
                        · {s.name}
                      </li>
                    ))}
                  </ul>
                  <p className="text-[10px] text-text-muted mt-3 opacity-60">
                    {activeLayer === layer.id ? "▲ collapse" : "▼ expand"}
                  </p>
                </motion.button>
              ))}
            </div>

            {/* Expanded detail */}
            <AnimatePresence>
              {activeLayer && (
                <motion.div
                  key={activeLayer}
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  className="overflow-hidden"
                >
                  {LAYERS.filter((l) => l.id === activeLayer).map((layer) => (
                    <div key={layer.id} className={`p-5 glass-card border ${layer.border} space-y-3`}>
                      <p className="text-sm text-text-secondary leading-relaxed">{layer.detail}</p>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        {layer.steps.map((s) => (
                          <div key={s.name} className="bg-bg-elevated rounded-lg p-3">
                            <p className="text-xs font-semibold text-text-primary mb-1">{s.name}</p>
                            <p className="text-xs text-text-muted leading-relaxed">{s.desc}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Fusion arrow */}
            <div className="flex justify-center">
              <div className="flex flex-col items-center gap-1">
                <div className="w-px h-6 bg-border" />
                <div className="px-4 py-2 bg-bg-elevated border border-border rounded-xl text-xs font-semibold text-text-primary text-center">
                  ⚖️ Weighted Fusion Engine
                  <br />
                  <span className="text-text-muted font-normal">
                    score = Σ(layer_score × normalized_weight) + heuristic overrides
                  </span>
                </div>
                <div className="w-px h-6 bg-border" />
              </div>
            </div>

            {/* Verdict outputs */}
            <div className="flex justify-center gap-3 flex-wrap">
              {[
                { label: "Phishing", color: "bg-accent-red/10 text-accent-red border-accent-red/30", threshold: "≥ 0.65" },
                { label: "Uncertain", color: "bg-accent-amber/10 text-accent-amber border-accent-amber/30", threshold: "0.35 – 0.65" },
                { label: "Legitimate", color: "bg-accent-green/10 text-accent-green border-accent-green/30", threshold: "< 0.35" },
              ].map((v) => (
                <div key={v.label} className={`px-4 py-2 rounded-full border text-xs font-semibold ${v.color}`}>
                  {v.label} <span className="opacity-60 ml-1">{v.threshold}</span>
                </div>
              ))}
            </div>
          </motion.div>
        )}

        {/* ── METRICS TAB ── */}
        {activeTab === "metrics" && (
          <motion.div
            key="metrics"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="space-y-6"
          >
            {/* Dataset info */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { label: "Dataset", value: "PhiUSIIL" },
                { label: "Total URLs", value: "235,795" },
                { label: "Features Used", value: "21" },
                { label: "Test Split", value: "20%" },
              ].map((s) => (
                <div key={s.label} className="glass-card p-4 text-center">
                  <p className="text-xl font-bold text-text-primary">{s.value}</p>
                  <p className="text-xs text-text-muted mt-1">{s.label}</p>
                </div>
              ))}
            </div>

            {/* Model comparison table */}
            <div className="glass-card overflow-hidden">
              <div className="px-5 py-4 border-b border-border">
                <h3 className="text-sm font-semibold text-text-primary">Model Performance — URL-Only Features</h3>
                <p className="text-xs text-text-muted mt-0.5">5-fold stratified cross-validation · 20% hold-out test set</p>
              </div>
              <div className="divide-y divide-border">
                {/* Header */}
                <div className="grid grid-cols-4 px-5 py-2 text-xs font-semibold text-text-muted uppercase tracking-wider">
                  <span>Model</span>
                  <span>Accuracy</span>
                  <span>AUC-ROC</span>
                  <span>F1 Score</span>
                </div>
                {METRICS.map((m) => (
                  <div
                    key={m.model}
                    className={`px-5 py-3 grid grid-cols-4 items-center gap-2 ${
                      m.isTop ? "bg-accent-blue/5 border-l-2 border-l-accent-blue" : ""
                    }`}
                  >
                    <span className={`text-sm font-medium ${m.isTop ? "text-accent-blue" : "text-text-secondary"}`}>
                      {m.model} {m.isTop && "⭐"}
                    </span>
                    <MetricBar value={m.acc} color="bg-accent-blue" />
                    <MetricBar value={m.auc} color="bg-accent-red" />
                    <MetricBar value={m.f1} color="bg-accent-green" />
                  </div>
                ))}
              </div>
            </div>

            {/* Key findings */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { icon: "🏆", title: "Best AUC", value: "0.9862", sub: "Stacking Ensemble", color: "text-accent-blue" },
                { icon: "⚡", title: "Inference Latency", value: "< 200ms", sub: "Incl. 3 API calls", color: "text-accent-amber" },
                { icon: "🛡️", title: "Leakage Removed", value: "29 features", sub: "Page-content excluded", color: "text-accent-green" },
              ].map((s) => (
                <div key={s.title} className="glass-card p-4 text-center">
                  <span className="text-2xl">{s.icon}</span>
                  <p className={`text-xl font-bold mt-2 ${s.color}`}>{s.value}</p>
                  <p className="text-sm font-semibold text-text-primary">{s.title}</p>
                  <p className="text-xs text-text-muted mt-1">{s.sub}</p>
                </div>
              ))}
            </div>
          </motion.div>
        )}

        {/* ── FEATURES TAB ── */}
        {activeTab === "features" && (
          <motion.div
            key="features"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="space-y-6"
          >
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-text-primary mb-1">
                Top-10 Random Forest Feature Importances
              </h3>
              <p className="text-xs text-text-muted mb-5">
                Gini importance over 21 URL-extractable features. All page-content features removed to eliminate data leakage.
              </p>
              <div className="space-y-3">
                {FEATURES.map((f) => (
                  <FeatureBar key={f.name} name={f.name} imp={f.imp} />
                ))}
              </div>
            </div>

            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-text-primary mb-3">Leakage Elimination Strategy</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-text-muted">
                <div className="bg-accent-red/5 border border-accent-red/20 rounded-lg p-4">
                  <p className="font-semibold text-accent-red mb-2">❌ Excluded (29 features)</p>
                  <p className="leading-relaxed">
                    Page-content features such as <code className="bg-bg-elevated px-1 rounded">URLSimilarityIndex</code>,{" "}
                    <code className="bg-bg-elevated px-1 rounded">DomainTitleMatchScore</code>,{" "}
                    <code className="bg-bg-elevated px-1 rounded">HasFavicon</code>, etc. require page fetching —
                    unavailable at inference time and encode the label directly (21% Gini importance for URLSimilarityIndex alone).
                  </p>
                </div>
                <div className="bg-accent-green/5 border border-accent-green/20 rounded-lg p-4">
                  <p className="font-semibold text-accent-green mb-2">✅ Included (21 URL-only features)</p>
                  <p className="leading-relaxed">
                    All features are derived solely from the URL string — character counts, ratios, structural flags,
                    TLD statistics, entropy, obfuscation patterns. Computed in TypeScript in the browser with zero latency.
                  </p>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}
