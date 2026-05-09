"""
PhishGuard — ML Training Pipeline (Fixed)
Dataset: PhiUSIIL_Phishing_URL_Dataset.csv
Fixes: data leakage, use_label_encoder warning, ONNX export, URL-only model.
"""

import argparse, json, os, time, warnings
from collections import Counter
from datetime import datetime
from pathlib import Path

import joblib, numpy as np, pandas as pd
import xgboost as xgb, lightgbm as lgb
from sklearn.ensemble import (
    ExtraTreesClassifier, GradientBoostingClassifier,
    RandomForestClassifier, StackingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, f1_score, roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import RobustScaler

warnings.filterwarnings("ignore")

DATASET_PATH = "PhiUSIIL_Phishing_URL_Dataset.csv"
MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)
RANDOM_STATE = 42
TEST_SIZE = 0.20
CV_FOLDS = 5

DROP_COLS = ["FILENAME", "URL", "Domain", "TLD", "Title"]
LABEL_COL = "label"

# ═══════════════════════════════════════════════════════
# Features we CAN compute from URL alone in production.
# Page-content features (LineOfCode, NoOfImage, etc.)
# cause data leakage — the dataset authors computed them
# by crawling pages, so they encode the label directly.
# Our Next.js app CANNOT fetch pages, so we exclude them.
# ═══════════════════════════════════════════════════════

URL_ONLY_FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP",
    "CharContinuationRate", "TLDLegitimateProb", "URLCharProb",
    "TLDLength", "NoOfSubDomain", "HasObfuscation",
    "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL",
    "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
    "IsHTTPS",
]

# Page-content features — EXCLUDED (cause leakage + unavailable at inference)
LEAKY_FEATURES = [
    "URLSimilarityIndex",  # 21% importance — directly encodes deception
    "LineOfCode", "LargestLineLength", "HasTitle",
    "DomainTitleMatchScore", "URLTitleMatchScore",
    "HasFavicon", "Robots", "IsResponsive",
    "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription",
    "NoOfPopup", "NoOfiFrame", "HasExternalFormSubmit",
    "HasSocialNet", "HasSubmitButton", "HasHiddenFields",
    "HasPasswordField", "Bank", "Pay", "Crypto",
    "HasCopyrightInfo", "NoOfImage", "NoOfCSS", "NoOfJS",
    "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
]

# ═══════════════════════════════════════════════════════
# Models — trimmed to 5 (removed redundant variants)
# ═══════════════════════════════════════════════════════

def get_base_models():
    return {
        "rf": RandomForestClassifier(
            n_estimators=300, max_depth=20, min_samples_leaf=5,
            n_jobs=-1, random_state=RANDOM_STATE,
        ),
        "xgb": xgb.XGBClassifier(
            n_estimators=300, learning_rate=0.05, max_depth=6,
            subsample=0.8, colsample_bytree=0.8,
            eval_metric="logloss", n_jobs=-1, random_state=RANDOM_STATE,
        ),
        "lgb": lgb.LGBMClassifier(
            n_estimators=300, learning_rate=0.05, max_depth=6,
            subsample=0.8, colsample_bytree=0.8, n_jobs=-1,
            random_state=RANDOM_STATE, verbose=-1,
        ),
        "mlp": MLPClassifier(
            hidden_layer_sizes=(128, 64), activation="relu",
            solver="adam", max_iter=300, early_stopping=True,
            validation_fraction=0.1, random_state=RANDOM_STATE,
        ),
        "lr": LogisticRegression(
            C=1.0, max_iter=1000, solver="lbfgs",
            n_jobs=-1, random_state=RANDOM_STATE,
        ),
    }


# ═══════════════════════════════════════════════════════
# Data Loading
# ═══════════════════════════════════════════════════════

def load_dataset(path, url_only=True):
    print(f"\n📂 Loading dataset: {path}")
    df = pd.read_csv(path, encoding="utf-8-sig")
    print(f"   Raw shape: {df.shape}")

    df = df.drop(columns=DROP_COLS, errors="ignore")

    for col in df.columns:
        if col != LABEL_COL:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.fillna(df.median(numeric_only=True))

    y = df[LABEL_COL].astype(int)
    X = df.drop(columns=[LABEL_COL])

    if url_only:
        available = [f for f in URL_ONLY_FEATURES if f in X.columns]
        dropped = [f for f in X.columns if f not in available]
        X = X[available]
        print(f"\n   ⚠️  URL-ONLY MODE: Using {len(available)} features")
        print(f"   Dropped {len(dropped)} page-content/leaky features")
    else:
        print(f"\n   Using ALL {len(X.columns)} features (includes page-content)")

    feature_names = list(X.columns)
    print(f"   Features: {len(feature_names)}")
    print(f"   Samples:  {len(X):,}")
    print(f"   Classes:  0 (Legit) = {(y == 0).sum():,} | 1 (Phish) = {(y == 1).sum():,}")

    return X, y, feature_names


def detect_leakage(X, y, feature_names):
    """Check for features with suspiciously high correlation to label."""
    print("\n🔍 Leakage Detection:")
    leaky = []
    for col in feature_names:
        corr = abs(X[col].corr(y))
        if corr > 0.85:
            leaky.append((col, corr))
            print(f"   🚨 {col}: correlation = {corr:.4f} (LEAKY)")
        elif corr > 0.70:
            print(f"   ⚠️  {col}: correlation = {corr:.4f} (suspicious)")

    if not leaky:
        print("   ✅ No obvious leakage detected.")
    else:
        print(f"\n   Found {len(leaky)} leaky features — these are excluded in URL-only mode.")
    return leaky


# ═══════════════════════════════════════════════════════
# Training
# ═══════════════════════════════════════════════════════

def train_and_evaluate(X_train, X_test, y_train, y_test, feature_names, skip_cv=False):
    print("\n⚙️  Scaling features with RobustScaler...")
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, MODELS_DIR / "scaler.joblib")

    base_models = get_base_models()
    results = {}
    trained_models = {}

    for name, model in base_models.items():
        print(f"\n[{name}] ", end="")

        if not skip_cv:
            print("Cross-validating...", end=" ")
            cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
            try:
                cv_scores = cross_val_score(
                    model, X_train_scaled, y_train, cv=cv, scoring="roc_auc", n_jobs=-1,
                )
                cv_mean, cv_std = float(cv_scores.mean()), float(cv_scores.std())
                print(f"CV AUC: {cv_mean:.4f} ± {cv_std:.4f}")
            except Exception as e:
                print(f"CV failed: {e}")
                cv_mean, cv_std = 0.0, 0.0
        else:
            print("Training (CV skipped)...", end=" ")
            cv_mean, cv_std = 0.0, 0.0

        t0 = time.time()
        model.fit(X_train_scaled, y_train)
        elapsed = time.time() - t0
        trained_models[name] = model

        y_pred = model.predict(X_test_scaled)
        y_prob = model.predict_proba(X_test_scaled)[:, 1]

        results[name] = {
            "cv_auc_mean": cv_mean, "cv_auc_std": cv_std,
            "test_accuracy": float(accuracy_score(y_test, y_pred)),
            "test_auc": float(roc_auc_score(y_test, y_prob)),
            "test_f1": float(f1_score(y_test, y_pred)),
            "train_time_s": round(elapsed, 1),
        }
        r = results[name]
        print(f"[{name}] Acc: {r['test_accuracy']:.4f} | AUC: {r['test_auc']:.4f} | F1: {r['test_f1']:.4f} | {elapsed:.1f}s")
        joblib.dump(model, MODELS_DIR / f"{name}.joblib")

    # Stacking ensemble
    print("\n" + "=" * 60)
    print("🏗️  Building Stacking Ensemble...")
    print("=" * 60)

    estimators = [(n, m) for n, m in trained_models.items()]
    stacking = StackingClassifier(
        estimators=estimators,
        final_estimator=LogisticRegression(C=1.0, max_iter=1000, random_state=RANDOM_STATE),
        cv=5, stack_method="predict_proba", n_jobs=-1, passthrough=False,
    )
    t0 = time.time()
    stacking.fit(X_train_scaled, y_train)
    stack_time = time.time() - t0

    y_pred_s = stacking.predict(X_test_scaled)
    y_prob_s = stacking.predict_proba(X_test_scaled)[:, 1]

    stack_results = {
        "test_accuracy": float(accuracy_score(y_test, y_pred_s)),
        "test_auc": float(roc_auc_score(y_test, y_prob_s)),
        "test_f1": float(f1_score(y_test, y_pred_s)),
    }
    print(f"\n   STACKING: Acc={stack_results['test_accuracy']:.4f} | AUC={stack_results['test_auc']:.4f} | F1={stack_results['test_f1']:.4f}")
    print(classification_report(y_test, y_pred_s, target_names=["Legitimate", "Phishing"]))
    joblib.dump(stacking, MODELS_DIR / "stacking_ensemble.joblib")

    # Metadata
    y_all = np.concatenate([np.array(y_train), np.array(y_test)])
    with open(MODELS_DIR / "training_results.json", "w") as f:
        json.dump({
            "base_models": results, "stacking": stack_results,
            "feature_names": feature_names, "n_features": len(feature_names),
            "dataset": DATASET_PATH,
            "dataset_rows": len(X_train) + len(X_test),
            "train_rows": len(X_train), "test_rows": len(X_test),
            "class_distribution": {"legitimate": int((y_all == 0).sum()), "phishing": int((y_all == 1).sum())},
            "trained_at": datetime.now().isoformat(),
            "mode": "url_only",
        }, f, indent=2)

    # Feature importance
    if "rf" in trained_models:
        imp = trained_models["rf"].feature_importances_
        feat_imp = dict(sorted(zip(feature_names, [float(v) for v in imp]), key=lambda x: -x[1]))
        with open(MODELS_DIR / "feature_importance.json", "w") as f:
            json.dump(feat_imp, f, indent=2)
        print("\n📊 Top 15 Features (RF importance):")
        for i, (feat, v) in enumerate(list(feat_imp.items())[:15]):
            print(f"   {i+1:2d}. {feat:<35s} {v:.4f} {'█' * int(v * 200)}")

    with open(MODELS_DIR / "feature_order.json", "w") as f:
        json.dump({"features": feature_names}, f, indent=2)

    return stacking, scaler, results, stack_results


# ═══════════════════════════════════════════════════════
# ONNX Export
# ═══════════════════════════════════════════════════════

def export_to_onnx(stacking_model, scaler, feature_names, output_path="models/phishguard.onnx"):
    print("\n📦 Exporting to ONNX...")
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
    except ImportError:
        print("❌ skl2onnx not installed. Run: pip install skl2onnx")
        return

    n = len(feature_names)
    initial_type = [("float_input", FloatTensorType([None, n]))]

    # Try stacking first, fall back to RF pipeline
    try:
        onx = convert_sklearn(stacking_model, initial_types=initial_type, target_opset=12)
        with open(output_path, "wb") as f:
            f.write(onx.SerializeToString())
        print(f"   ✅ Stacking exported to {output_path}")
    except Exception as e:
        print(f"   ⚠️  Stacking failed: {e}")
        print("   Falling back to RF pipeline...")
        try:
            from sklearn.pipeline import Pipeline
            rf = joblib.load(MODELS_DIR / "rf.joblib")
            sc = joblib.load(MODELS_DIR / "scaler.joblib")
            pipe = Pipeline([("scaler", sc), ("rf", rf)])
            onx = convert_sklearn(pipe, initial_types=initial_type, target_opset=12)
            with open(output_path, "wb") as f:
                f.write(onx.SerializeToString())
            print(f"   ✅ RF pipeline exported to {output_path}")
        except Exception as e2:
            print(f"   ❌ Fallback also failed: {e2}")
            return

    with open(MODELS_DIR / "feature_order.json", "w") as f:
        json.dump({"features": feature_names}, f, indent=2)
    print(f"   ONNX size: {os.path.getsize(output_path) / 1024 / 1024:.1f} MB")


# ═══════════════════════════════════════════════════════
# N-gram Export (unchanged)
# ═══════════════════════════════════════════════════════

_NGRAM_CORPUS = [
    "the","and","for","are","but","not","you","all","can","had","her","was","one",
    "our","out","day","get","has","him","his","how","its","may","new","now","old",
    "see","way","who","did","let","say","she","too","use","about","after","again",
    "also","back","been","call","came","come","could","each","even","find","first",
    "from","give","good","great","have","help","here","high","home","house","into",
    "just","keep","know","last","life","like","line","little","long","look","made",
    "make","many","more","most","much","must","name","never","next","number","only",
    "open","other","over","part","people","place","point","right","same","small",
    "some","state","still","such","take","tell","than","that","them","then","there",
    "these","they","thing","think","this","those","three","time","turn","under",
    "upon","very","want","water","well","were","what","when","which","while","will",
    "with","word","work","world","would","write","year","your","being","between",
    "business","company","country","development","different","education","example",
    "family","general","government","group","important","information","interest",
    "large","learn","level","money","national","nothing","order","person","program",
    "public","question","real","report","result","school","service","social",
    "something","student","system","community","computer","design","digital",
    "experience","financial","global","health","human","market","media","network",
    "office","online","personal","phone","process","product","professional","project",
    "quality","research","resource","review","search","security","software","store",
    "strategy","support","team","technology","training","travel","university",
    "update","value","video","website","account","application","available","category",
    "center","change","content","create","customer","database","domain","download",
    "engine","feature","field","file","form","free","function","guide","history",
    "image","include","index","interface","item","language","library","link","list",
    "location","manage","message","method","mobile","model","module","object","option",
    "output","package","page","panel","password","payment","photo","platform","player",
    "plugin","portal","post","price","private","profile","property","publish","record",
    "release","request","response","sample","screen","script","server","session",
    "setting","source","status","stream","style","submit","table","target","template",
    "test","text","theme","ticket","title","token","tool","topic","total","track",
    "transfer","type","upload","version","widget","window",
    "mail","shop","news","blog","app","api","login","auth","user","admin","info",
    "help","docs","wiki","cloud","data","host","site","web","dev","test","stage",
    "prod","beta","demo","cdn","static","media","asset","pay","bill","cart","order",
    "check","bank","cash","fund","loan","invest","trade","stock","crypto","coin",
    "google","amazon","microsoft","apple","facebook","twitter","github","netflix",
    "spotify","paypal","stripe","shopify","discord","slack","zoom","notion","figma",
    "canva","adobe","oracle","salesforce","dropbox","reddit","youtube","linkedin",
    "instagram","whatsapp","telegram","coinbase","binance",
]


def export_ngram_model(output_json="models/ngram_model.json", output_ts="src/lib/ngramModel.ts"):
    print("\n📝 Building n-gram language model...")
    corpus = " ".join(_NGRAM_CORPUS).lower()
    trigram_counts = Counter()
    for i in range(len(corpus) - 2):
        tri = corpus[i:i+3]
        if tri.strip():
            trigram_counts[tri] += 1
    total = sum(trigram_counts.values())
    ngrams = {t: round(c/total, 6) for t, c in trigram_counts.items() if c/total > 0.0005}

    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    with open(output_json, "w") as f:
        json.dump({"ngrams": dict(sorted(ngrams.items(), key=lambda x:-x[1])), "total": total, "vocab_size": len(set(corpus.replace(" ","")))}, f, indent=2)

    os.makedirs(os.path.dirname(output_ts), exist_ok=True)
    lines = ["// Auto-generated by training.py — do not edit manually", "","export const NGRAM_MODEL: Record<string, number> = {"]
    for k, v in sorted(ngrams.items(), key=lambda x:-x[1]):
        lines.append(f'  "{k.replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34))}": {v},')
    lines += ["};", "", f"export const NGRAM_TOTAL = {total};", "", f"export const NGRAM_VOCAB_SIZE = {len(set(corpus.replace(' ','')))};", ""]
    with open(output_ts, "w") as f:
        f.write("\n".join(lines))
    print(f"   Saved: {output_json} ({len(ngrams)} trigrams) + {output_ts}")


# ═══════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="PhishGuard ML Training Pipeline")
    parser.add_argument("--dataset", default=DATASET_PATH)
    parser.add_argument("--skip-cv", action="store_true")
    parser.add_argument("--export-onnx", action="store_true")
    parser.add_argument("--export-ngram", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--all-features", action="store_true",
                        help="Use ALL features including page-content (not recommended)")
    args = parser.parse_args()
    if args.all:
        args.export_onnx = args.export_ngram = True

    start = time.time()
    print("=" * 60)
    print("  PhishGuard — ML Training Pipeline")
    print("=" * 60)

    url_only = not args.all_features
    X, y, feature_names = load_dataset(args.dataset, url_only=url_only)

    # Leakage detection (on full dataset before split)
    if not url_only:
        detect_leakage(X, y, feature_names)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )
    print(f"\n   Train: {len(X_train):,} | Test: {len(X_test):,}")

    stacking, scaler, results, stack_results = train_and_evaluate(
        X_train, X_test, y_train, y_test, feature_names, skip_cv=args.skip_cv,
    )

    if args.export_onnx:
        export_to_onnx(stacking, scaler, feature_names)
    if args.export_ngram:
        export_ngram_model()

    elapsed = time.time() - start
    print("\n" + "=" * 60)
    print("  FINAL SUMMARY")
    print("=" * 60)
    print(f"  Mode: {'URL-only (21 features)' if url_only else 'ALL features (50 — includes leaky)'}")
    print(f"\n  {'Model':<12s} {'Acc':>8s} {'AUC':>8s} {'F1':>8s}")
    print(f"  {'-'*36}")
    for n, r in sorted(results.items(), key=lambda x:-x[1]["test_auc"]):
        print(f"  {n:<12s} {r['test_accuracy']:>8.4f} {r['test_auc']:>8.4f} {r['test_f1']:>8.4f}")
    print(f"  {'─'*36}")
    print(f"  {'STACKING':<12s} {stack_results['test_accuracy']:>8.4f} {stack_results['test_auc']:>8.4f} {stack_results['test_f1']:>8.4f}")
    print(f"\n  ⏱  {elapsed/60:.1f} min | 📁 {MODELS_DIR}/")
    print("=" * 60)


if __name__ == "__main__":
    main()
