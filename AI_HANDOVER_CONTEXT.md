# PhishGuard v2 — AI Handover Context

## 🎯 Project Overview
PhishGuard is a 4-layer AI phishing detection platform. It has been migrated from a legacy Streamlit monolith to a modern production stack.

- **Frontend:** Next.js 14 (App Router) + TypeScript + Tailwind CSS.
- **Backend API:** Next.js API Routes (Route Handlers).
- **ML Inference:** Hugging Face Gradio Space (Python) running a 5-model stacking ensemble.
- **Data Layers:** Threat Intel (VirusTotal, GSB, IPQS), ML Ensemble, and Mathematical Analysis (Entropy, Typosquatting, N-grams).

## 📂 Repository Structure
The project is now **flattened** at the root (no more `phishguard-v2/` subfolder).
- `/src`: Next.js frontend and shared logic.
- `/hf_space`: Gradio inference code for Hugging Face.
- `/models`: Trained model binaries (`.joblib`, `.onnx`).
- `training.py`: The centralized ML pipeline.

## 🛠️ Critical Fixes (Session History)
1. **Data Leakage Fix:** The initial model showed 100% accuracy because it trained on "page-content" features (like `LineOfCode`). These were removed because the app is a fast URL-scanner that cannot crawl pages at runtime.
2. **Feature Alignment:** The system now uses exactly **21 URL-only features** (lexical). This ensures that the features seen by the Python model during training are exactly what the TypeScript frontend calculates during a scan.
3. **HF Space Build Fixes:** 
   - Forced `python_version: "3.10"` in `README.md`.
   - Updated `hf_space/requirements.txt` to use higher scikit-learn to match the local trained models (`scikit-learn>=1.8.0` and newer `numpy`).

## 🚀 Deployment Status
- **ML Backend:** Deployed to Hugging Face Space (`satyakiabhijit/phishguard-ml-engine`).
- **API Endpoint:** `https://satyakiabhijit-phishguard-ml-engine.hf.space`
- **Frontend:** Configured and ready for Vercel.

## 📋 Next Steps for the next AI
1. **Frontend Testing:** Run `npm run dev` and test the `/api/analyze` endpoint.
2. **Env Vars:** Ensure `VT_API_KEY`, `GSB_API_KEY`, `IPQS_API_KEY`, and `HF_SPACE_URL` are set.
3. **Vercel Deploy:** The project is root-ready for a simple `vercel` command.
4. **Model Tuning:** If accuracy needs improvement, modify `URL_ONLY_FEATURES` in `training.py` and `featureExtractor.ts` in sync.
