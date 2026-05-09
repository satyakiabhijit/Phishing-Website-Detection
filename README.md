# PhishGuard v2 — AI Phishing Detection Platform

> 4-layer AI phishing detection with 95+ threat engines, ML ensemble, and mathematical URL analysis.

## Architecture

```
┌──────────────────────────────────────────────────┐
│                    Frontend                       │
│           Next.js 14 + TypeScript                │
│           Tailwind CSS + Framer Motion            │
│                  (Vercel)                         │
└──────────────┬───────────────────────────────────┘
               │ POST /api/analyze
┌──────────────▼───────────────────────────────────┐
│              API Route Handler                    │
│         (Vercel Edge Functions)                   │
├──────────────┬──────────┬────────────────────────┤
│   Layer 1&2  │  Layer 3A │     Layer 3B          │
│  Threat Intel│  Math/TS  │    ML Inference        │
│  VT+GSB+IPQS│  Feature  │   HF Space (ONNX)     │
│              │  Extract  │                        │
└──────────────┴──────────┴────────────────────────┘
               │
┌──────────────▼───────────────────────────────────┐
│            Weighted Fusion Engine                 │
│     Dynamic weights + hard overrides             │
│     Recalibrated thresholds (>0.65 phishing)     │
└──────────────────────────────────────────────────┘
```

## Quick Start

### 1. Train the model (Python)

```bash
pip install -r requirements.txt
pip install skl2onnx onnxruntime

# Full training + ONNX export + n-gram export
python training.py --export-onnx --export-ngram

# Or export from existing trained models
python training.py --onnx-only --export-ngram
```

### 2. Export n-gram model to TypeScript

```bash
python export_ngram_ts.py
```

### 3. Deploy the HF Space

```bash
# Copy ONNX model to HF Space directory
cp models/phishguard.onnx hf_space/

# Upload hf_space/ to a new Hugging Face Space
# Then set HF_SPACE_URL to the Space URL
```

### 4. Install & Run the Next.js app

```bash
cd phishguard-v2
npm install
cp .env.local.example .env.local
# Fill in API keys in .env.local
npm run dev
```

### 5. Deploy to Vercel

```bash
vercel deploy
```

Then in Vercel Dashboard:
- Add all environment variables from `.env.local.example`
- Set up Vercel KV storage and link to project

## Environment Variables

| Variable | Description | Required |
|----------|------------|----------|
| `VT_API_KEY` | VirusTotal API key | Yes |
| `GSB_API_KEY` | Google Safe Browsing v4 | Yes |
| `IPQS_API_KEY` | IPQualityScore API key | Yes |
| `HF_SPACE_URL` | Hugging Face Space URL | Yes |
| `KV_REST_API_URL` | Vercel KV REST API URL | For caching |
| `KV_REST_API_TOKEN` | Vercel KV token | For caching |

## File Structure

```
phishguard-v2/
├── src/
│   ├── app/
│   │   ├── page.tsx              ← Landing + analysis page
│   │   ├── layout.tsx            ← Root layout + SEO
│   │   └── api/analyze/route.ts  ← Main API endpoint
│   ├── components/
│   │   ├── UrlInput.tsx          ← URL input with validation
│   │   ├── VerdictBadge.tsx      ← Animated verdict display
│   │   ├── LayerCard.tsx         ← Per-layer result card
│   │   ├── EvidenceList.tsx      ← Sorted evidence items
│   │   ├── ConfidenceBar.tsx     ← Horizontal confidence bar
│   │   ├── LoadingSteps.tsx      ← Sequential loading animation
│   │   └── RiskGauge.tsx         ← SVG circular gauge
│   ├── lib/
│   │   ├── featureExtractor.ts   ← Full TS port of Python extractor
│   │   ├── ngramModel.ts         ← Character trigram frequencies
│   │   ├── threatIntelligence.ts ← VT + GSB + IPQS API calls
│   │   ├── fusion.ts             ← Weighted scoring + verdict
│   │   ├── whitelist.ts          ← Trusted domains + brands
│   │   └── types.ts              ← All TypeScript types
│   └── styles/globals.css
├── public/alexa_top1k.txt
├── hf_space/                     ← Upload to HF Spaces
│   ├── app.py
│   ├── requirements.txt
│   └── README.md
├── training.py                   ← Modified with ONNX export
├── export_ngram_ts.py            ← N-gram → TypeScript converter
└── .env.local.example
```

## False Positive Mitigations

- **VT threshold**: Requires >2 detections (not >0)
- **IPQS threshold**: fraud_score >85 (not >75)
- **Trusted domain bonus**: -0.15 score for cloud infra suffixes
- **Entropy normalization**: Reduced penalty for trusted subdomains
- **Tech brand bypass**: Known brands skip perplexity scoring
- **UUID-aware digit ratio**: UUIDs excluded from digit counting
- **Typosquat guard**: Exact brand match ≠ impersonation

## License

MIT
