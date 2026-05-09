// ═══════════════════════════════════════════════════════════
// PhishGuard v2 — HF Space Inference Client
// Sends feature vector to HF Space API
// ═══════════════════════════════════════════════════════════

import { buildFeatureVector } from "./featureExtractor";
import type { MLResult } from "./types";
import { Client } from "@gradio/client";

export async function callHFInference(
  url: string,
  timeoutMs = 15000
): Promise<MLResult> {
  const fallback: MLResult = {
    available: false,
    prediction: 0,
    probability: 0.5,
    confidence: 0.5,
    error: null,
  };

  const hfUrl = process.env.HF_SPACE_URL;
  if (!hfUrl) return { ...fallback, error: "HF_SPACE_URL not set" };

  try {
    const { features } = buildFeatureVector(url);
    
    // Support hf.space domains (e.g. from satyakiabhijit-phishguard-ml-engine.hf.space)
    // The client expects the namespace format like "satyakiabhijit/phishguard-ml-engine" or the raw URL
    const client = await Client.connect(hfUrl);
    
    // We expect the first API method to be predict (or the default /predict)
    const result = await client.predict("/predict", { 
      feature_json: JSON.stringify(features) 
    });

    if (!result || !result.data || !result.data[0]) {
      return { ...fallback, error: "Empty response from HF Space" };
    }

    const parsed = JSON.parse(result.data[0] as string);

    return {
      available: true,
      prediction: parsed.prediction,
      probability: parsed.probability,
      confidence: parsed.confidence,
      error: parsed.error || null,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error("[HF Inference] Error:", msg);
    return { ...fallback, error: msg };
  }
}

export async function runMLLayer(url: string): Promise<MLResult> {
  return callHFInference(url);
}
