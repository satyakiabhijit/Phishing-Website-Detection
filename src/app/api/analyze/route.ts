// ═══════════════════════════════════════════════════════════
// PhishGuard v2 — Analysis API Route
// POST /api/analyze
// ═══════════════════════════════════════════════════════════

import { NextRequest, NextResponse } from "next/server";
import { kv } from "@vercel/kv";
import { runIntelLayer } from "@/lib/threatIntelligence";
import { runMLLayer } from "@/lib/hfInference";
import { buildFeatureVector, computeShannonEntropy } from "@/lib/featureExtractor";
import { fuseAnalysis } from "@/lib/fusion";
import { detectHomoglyphs, computeTyposquatDistance, computeNgramPerplexity, KNOWN_BRANDS } from "@/lib/featureExtractor";

const CACHE_TTL = 60 * 60 * 24; // 24 hours

export async function POST(req: NextRequest) {
  try {
    const { url } = await req.json();
    if (!url || typeof url !== "string") {
      return NextResponse.json({ error: "Invalid URL" }, { status: 400 });
    }

    let normalizedUrl = url.trim();
    if (!/^https?:\/\//i.test(normalizedUrl)) {
      normalizedUrl = "https://" + normalizedUrl;
    }

    let hostname: string;
    try {
      hostname = new URL(normalizedUrl).hostname;
    } catch {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 });
    }

    // 1. Check Cache
    if (process.env.NODE_ENV !== "development") {
      try {
        const cached = await kv.get(`analysis:${normalizedUrl}`);
        if (cached) return NextResponse.json({ ...cached as any, cached: true });
      } catch (e) {
        console.warn("KV Cache error:", e);
      }
    }

    // 2. Run Analysis Layers in Parallel
    const featureData = buildFeatureVector(normalizedUrl);
    const domainName = hostname.split(".").slice(-2, -1)[0] || hostname;

    const [intel, ml] = await Promise.all([
      runIntelLayer(normalizedUrl),
      runMLLayer(normalizedUrl),
    ]);

    // 3. Math Analysis (Synchronous/Local)
    const hg = detectHomoglyphs(hostname);
    const typo = computeTyposquatDistance(domainName, KNOWN_BRANDS);
    const perp = computeNgramPerplexity(hostname);

    const math = {
      featureVector: featureData.features,
      entropy: featureData.meta.entropy,
      entropyScore: featureData.meta.entropy > 4 ? 0.8 : 0,
      homoglyphs: {
        detected: hg.length > 0,
        chars: hg,
        normalizedDomain: hostname,
        score: hg.length > 0 ? 1.0 : 0,
      },
      typosquatResult: typo,
      perplexity: perp,
      perplexityScore: perp > 50 ? 1 : perp > 20 ? 0.5 : 0,
      structuralFlags: [] as string[],
    };

    // 4. Fusion
    const result = fuseAnalysis(url, normalizedUrl, intel, ml, math);

    // 5. Save to Cache
    try {
      await kv.set(`analysis:${normalizedUrl}`, result, { ex: CACHE_TTL });
    } catch (e) {
      console.warn("KV Save error:", e);
    }

    return NextResponse.json(result);

  } catch (e) {
    console.error("API Error:", e);
    return NextResponse.json({ error: "Internal analysis error" }, { status: 500 });
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
