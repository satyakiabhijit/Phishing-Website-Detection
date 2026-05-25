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

    const data = result?.data as unknown[];
    if (!data || !data[0]) {
      return { ...fallback, error: "Empty response from HF Space" };
    }

    const parsed = JSON.parse(data[0] as string);

    // INVERSION FIX: The trained ML model outputs [1 = Legitimate, 0 = Phishing] matching the PhiUSIIL dataset.
    // The Next.js frontend and fusion engine expect [1 = Phishing, 0 = Legitimate].
    // We invert the prediction and probability to align them perfectly.
    const alignedPrediction = parsed.prediction === 0 ? 1 : 0;
    const alignedProbability = 1.0 - parsed.probability;

    return {
      available: true,
      prediction: alignedPrediction,
      probability: alignedProbability,
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
