"""
PhishGuard ML Training Pipeline — Layer 3: URL-Structural + Mathematical Models
Trains on only features that are ALWAYS available at inference time.
"""

import os
import sys
import time
import json
import logging
import warnings
from datetime import datetime
from typing import Dict, Any

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif, SelectFromModel
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier,
    ExtraTreesClassifier, StackingClassifier, IsolationForest
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
)
import joblib

try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    import lightgbm as lgb
    HAS_LGB = True
except ImportError:
    HAS_LGB = False

warnings.filterwarnings('ignore')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('training.log'), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Features that cannot be reliably measured at inference time
# Training drops these so the model never relies on unavailable data
_UNRELIABLE_COLS = [
    # External API features
    'page_rank', 'domain_age', 'google_index', 'web_traffic',
    'whois_registered_domain', 'domain_registration_length', 'dns_record',
    # HTML content features (many sites block bots / require auth)
    'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks',
    'ratio_nullHyperlinks', 'nb_extCSS', 'ratio_intRedirection',
    'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors',
    'login_form', 'external_favicon', 'links_in_tags', 'submit_email',
    'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe',
    'popup_window', 'safe_anchor', 'onmouseover', 'right_clic',
    'empty_title', 'domain_in_title', 'domain_with_copyright',
    # Misleading count features — equally common in legitimate and phishing URLs,
    # leading to false positives on real sites like github.com, google.com etc.
    'nb_com',   # counts 'com' in URL — legitimate .com sites naturally score 1
    'nb_www',   # counts 'www' in URL — legitimate canonical domains score 1
    # Word-length features — misleading due to TLD segments
    # shortest_word_host for github.com = 3 ('com' TLD) which is identical for ALL .com sites
    # This trains the model to flag all short-segment hostnames incorrectly
    'shortest_word_host',
    'shortest_word_path',
]


class PhishingDetector:
    """ML-based phishing URL detector — Layer 3 of the 4-layer fusion pipeline."""

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        np.random.seed(random_state)

        self.models             = {}
        self.stacking_classifier = None
        self.anomaly_detector   = None
        self.scaler             = StandardScaler()
        self.label_encoder      = LabelEncoder()
        self.feature_names      = None
        self.selected_features  = None
        self.training_history   = {}
        self.model_performances = {}

        logger.info("PhishingDetector initialized")

    # ── Data Loading ─────────────────────────────────────────────────────────

    def load_dataset(self, path: str) -> pd.DataFrame:
        logger.info(f"Loading dataset from {path}")
        df = pd.read_csv(path)
        logger.info(f"Raw shape: {df.shape}")
        logger.info(f"Classes:\n{df['status'].value_counts()}")

        # ── AUGMENT with math features computed from URL ───────────────────
        # This is the KEY step: train the model on the SAME feature space
        # it will see at inference time — including typosquatting scores,
        # n-gram perplexity, homoglyph detection, and Shannon entropy.
        # Without this, these features fill to 0 at inference → model ignores them.
        if 'url' in df.columns:
            logger.info("Computing mathematical features from URL column...")
            from feature_extractor import (
                typosquatting_score, domain_perplexity_score,
                homoglyph_score, entropy_score, shannon_entropy,
                _ratio_digits_excluding_uuid, _has_valid_uuid_in_path,
                PHISHING_KEYWORDS, KNOWN_BRANDS
            )
            from urllib.parse import urlparse

            typo_scores, perp_scores, hg_scores, ent_scores = [], [], [], []
            ratio_digits_fixed, has_uuid_col = [], []
            phish_hints_col, brand_sub_col = [], []

            for url in df['url']:
                try:
                    u = str(url)
                    if not u.startswith(('http://', 'https://')):
                        u = 'http://' + u
                    parsed = urlparse(u)
                    hostname = parsed.netloc.split(':')[0] or ''
                    path_  = parsed.path or ''
                    domain_parts = hostname.split('.')
                    domain_name = domain_parts[-2].lower() if len(domain_parts) >= 2 else hostname.lower()
                    subdomain = '.'.join(domain_parts[:-2]).lower() if len(domain_parts) > 2 else ''

                    ts, _, _ = typosquatting_score(domain_name)
                    typo_scores.append(ts)
                    perp_scores.append(domain_perplexity_score(domain_name))
                    hg, _ = homoglyph_score(domain_name)
                    hg_scores.append(hg)
                    ent_scores.append(entropy_score(domain_name))
                    ratio_digits_fixed.append(_ratio_digits_excluding_uuid(u, path_))
                    has_uuid_col.append(1 if _has_valid_uuid_in_path(path_) else 0)
                    phish_hints_col.append(sum(1 for kw in PHISHING_KEYWORDS if kw in u.lower()))
                    brand_sub_col.append(1 if any(b in subdomain for b in KNOWN_BRANDS) else 0)
                except Exception:
                    typo_scores.append(0.0); perp_scores.append(0.0)
                    hg_scores.append(0.0);   ent_scores.append(0.0)
                    ratio_digits_fixed.append(0.0); has_uuid_col.append(0)
                    phish_hints_col.append(0); brand_sub_col.append(0)

            df['typosquatting_score']      = typo_scores
            df['domain_perplexity_score']  = perp_scores
            df['homoglyph_score']          = hg_scores
            df['domain_entropy_score']     = ent_scores
            df['ratio_digits_url']         = ratio_digits_fixed      # UUID-aware version
            df['has_uuid_in_path']         = has_uuid_col
            df['phish_hints']              = phish_hints_col
            df['brand_in_subdomain']       = brand_sub_col

            # Recompute 'ip': 1 if hostname is a raw IPv4 address like 192.168.1.1
            # Must match the same computation used in feature_extractor.py at inference
            import re as _re
            from urllib.parse import urlparse as _up
            _ip_pat = _re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            def _is_ip(u):
                try:
                    host = _up(u if '://' in u else 'http://' + u).netloc.split(':')[0]
                    return 1 if _ip_pat.match(host) else 0
                except Exception:
                    return 0
            df['ip'] = df['url'].apply(_is_ip)

            # Fix nb_colon: subtract 1 for the scheme colon (http: or https:)
            # Without this fix, ALL https:// URLs get nb_colon=1 just from the scheme,
            # which trains the model to think colons in URLs are suspicious — wrong!
            if 'nb_colon' in df.columns:
                df['nb_colon'] = (df['nb_colon'] - 1).clip(lower=0)

            logger.info("Math feature augmentation complete.")

        logger.info(f"Final shape: {df.shape}")
        return df

    # ── Preprocessing ────────────────────────────────────────────────────────

    def preprocess(self, df: pd.DataFrame, test_size: float = 0.2):
        logger.info("Preprocessing data...")

        X = df.drop(['url', 'status'], axis=1, errors='ignore')
        y = df['status']

        # Drop unreliable features
        to_drop = [c for c in _UNRELIABLE_COLS if c in X.columns]
        X = X.drop(to_drop, axis=1)
        logger.info(f"Features after dropping unreliable: {X.shape[1]} (dropped {len(to_drop)})")

        self.feature_names = list(X.columns)

        # Fill NaN
        X = X.fillna(X.median(numeric_only=True))
        for col in X.select_dtypes(include='object').columns:
            X[col] = LabelEncoder().fit_transform(X[col].astype(str))

        # Encode target
        y_enc = self.label_encoder.fit_transform(y)

        # Feature engineering: interaction features
        X = self._engineer_features(X)

        # Feature selection
        X = self._select_features(X, y_enc, k=50)

        # Split
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y_enc, test_size=test_size,
            random_state=self.random_state, stratify=y_enc
        )

        # Scale
        X_tr_s = pd.DataFrame(self.scaler.fit_transform(X_tr), columns=self.selected_features)
        X_te_s = pd.DataFrame(self.scaler.transform(X_te),     columns=self.selected_features)

        logger.info(f"Train: {X_tr_s.shape}, Test: {X_te_s.shape}")
        return X_tr_s, X_te_s, y_tr, y_te

    def _engineer_features(self, X: pd.DataFrame) -> pd.DataFrame:
        X = X.copy()
        try:
            if 'length_url' in X.columns and 'nb_dots' in X.columns:
                X['length_url_x_nb_dots']   = X['length_url'] * X['nb_dots']
                X['length_url_div_nb_dots']  = X['length_url'] / (X['nb_dots'] + 1e-6)
            if 'length_url' in X.columns and 'nb_slash' in X.columns:
                X['length_url_div_nb_slash'] = X['length_url'] / (X['nb_slash'] + 1e-6)
            if 'length_url' in X.columns and 'nb_hyphens' in X.columns:
                X['length_url_x_nb_hyphens'] = X['length_url'] * X['nb_hyphens']
            if 'nb_dots' in X.columns and 'nb_hyphens' in X.columns:
                X['dots_x_hyphens'] = X['nb_dots'] * X['nb_hyphens']
        except Exception as e:
            logger.warning(f"Feature engineering partial failure: {e}")
        return X

    def _select_features(self, X: pd.DataFrame, y, k: int = 50) -> pd.DataFrame:
        logger.info(f"Selecting top {k} features...")

        # Univariate selection
        uni = SelectKBest(score_func=f_classif, k=min(k, X.shape[1]))
        uni.fit(X, y)
        set1 = set(X.columns[uni.get_support()])

        # Model-based selection
        rf = RandomForestClassifier(n_estimators=50, random_state=self.random_state)
        mbs = SelectFromModel(rf, max_features=min(k, X.shape[1]))
        mbs.fit(X, y)
        set2 = set(X.columns[mbs.get_support()])

        selected = list(set1 & set2)
        if len(selected) < k // 2:
            selected = list(set1 | set2)[:k]

        self.selected_features = selected
        logger.info(f"Selected {len(selected)} features")
        return X[selected]

    # ── Model Training ────────────────────────────────────────────────────────

    def train_models(self, X_tr, y_tr):
        logger.info("Training models...")

        configs = {
            'random_forest':     RandomForestClassifier(n_estimators=200, max_depth=15, random_state=self.random_state),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=150, learning_rate=0.1, max_depth=8, random_state=self.random_state),
            'extra_trees':       ExtraTreesClassifier(n_estimators=200, max_depth=15, random_state=self.random_state),
            'logistic_regression': LogisticRegression(max_iter=1000, C=1.0, random_state=self.random_state),
            'svm':               SVC(probability=True, C=1.0, gamma='scale', random_state=self.random_state),
            'neural_network':    MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=500, alpha=0.001, random_state=self.random_state),
            'naive_bayes':       GaussianNB(),
            'knn':               KNeighborsClassifier(n_neighbors=5),
            'decision_tree':     DecisionTreeClassifier(max_depth=10, random_state=self.random_state),
        }

        if HAS_XGB:
            configs['xgboost'] = xgb.XGBClassifier(
                n_estimators=150, learning_rate=0.1, max_depth=8,
                random_state=self.random_state, eval_metric='logloss',
                verbosity=0
            )
        if HAS_LGB:
            configs['lightgbm'] = lgb.LGBMClassifier(
                n_estimators=150, learning_rate=0.1, max_depth=8,
                random_state=self.random_state, verbose=-1
            )

        for name, model in configs.items():
            try:
                logger.info(f"  Training {name}...")
                t0 = time.time()
                cv = cross_val_score(model, X_tr, y_tr, cv=5, scoring='roc_auc')
                model.fit(X_tr, y_tr)
                elapsed = time.time() - t0
                self.models[name] = model
                self.training_history[name] = {
                    'cv_mean': float(cv.mean()),
                    'cv_std':  float(cv.std()),
                    'training_time': elapsed
                }
                logger.info(f"    {name}: AUC={cv.mean():.5f} ±{cv.std():.5f} ({elapsed:.1f}s)")
            except Exception as e:
                logger.error(f"    {name} failed: {e}")

    def create_ensemble(self, X_tr, y_tr):
        logger.info("Creating stacking ensemble...")

        base = [(n, self.models[n]) for n in ['random_forest', 'gradient_boosting',
                'extra_trees', 'xgboost', 'lightgbm'] if n in self.models]
        if len(base) < 2:
            logger.warning("Not enough base models for stacking")
            return

        self.stacking_classifier = StackingClassifier(
            estimators=base,
            final_estimator=LogisticRegression(random_state=self.random_state),
            cv=5, n_jobs=-1
        )
        self.stacking_classifier.fit(X_tr, y_tr)
        cv = cross_val_score(self.stacking_classifier, X_tr, y_tr, cv=3, scoring='roc_auc')
        logger.info(f"  Stacking ensemble: AUC={cv.mean():.5f} ±{cv.std():.5f}")

    def train_anomaly_detector(self, X_tr):
        logger.info("Training anomaly detector...")
        self.anomaly_detector = IsolationForest(
            contamination=0.1, n_estimators=100, random_state=self.random_state
        )
        self.anomaly_detector.fit(X_tr)

    def evaluate(self, X_te, y_te):
        logger.info("Evaluating models...")
        all_models = dict(self.models)
        if self.stacking_classifier:
            all_models['stacking_ensemble'] = self.stacking_classifier

        for name, model in all_models.items():
            try:
                y_pred = model.predict(X_te)
                y_prob = model.predict_proba(X_te)[:, 1] if hasattr(model, 'predict_proba') else None
                self.model_performances[name] = {
                    'accuracy':  float(accuracy_score(y_te, y_pred)),
                    'precision': float(precision_score(y_te, y_pred, pos_label=1, zero_division=0)),
                    'recall':    float(recall_score(y_te, y_pred, pos_label=1, zero_division=0)),
                    'f1':        float(f1_score(y_te, y_pred, pos_label=1, zero_division=0)),
                    'auc':       float(roc_auc_score(y_te, y_prob)) if y_prob is not None else None
                }
                logger.info(f"  {name}: Acc={self.model_performances[name]['accuracy']:.4f} "
                            f"AUC={self.model_performances[name].get('auc', 'N/A')}")
            except Exception as e:
                logger.error(f"  {name} eval failed: {e}")

    def save_models(self, model_dir: str = 'models'):
        os.makedirs(model_dir, exist_ok=True)
        for name, model in self.models.items():
            joblib.dump(model, os.path.join(model_dir, f'{name}_model.pkl'))
        if self.stacking_classifier:
            joblib.dump(self.stacking_classifier, os.path.join(model_dir, 'stacking_ensemble.pkl'))
        if self.anomaly_detector:
            joblib.dump(self.anomaly_detector, os.path.join(model_dir, 'anomaly_detector.pkl'))
        joblib.dump(self.scaler,        os.path.join(model_dir, 'scaler.pkl'))
        joblib.dump(self.label_encoder, os.path.join(model_dir, 'label_encoder.pkl'))

        metadata = {
            'feature_names':      self.feature_names,
            'selected_features':  self.selected_features,
            'training_history':   self.training_history,
            'model_performances': self.model_performances,
            'timestamp':          datetime.now().isoformat()
        }
        with open(os.path.join(model_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
        logger.info(f"All models saved to {model_dir}/")

    def load_models(self, model_dir: str = 'models') -> bool:
        try:
            with open(os.path.join(model_dir, 'metadata.json')) as f:
                meta = json.load(f)
            self.feature_names     = meta.get('feature_names', [])
            self.selected_features = meta.get('selected_features', [])
            self.training_history  = meta.get('training_history', {})
            self.model_performances = meta.get('model_performances', {})

            self.scaler        = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
            self.label_encoder = joblib.load(os.path.join(model_dir, 'label_encoder.pkl'))

            for f in os.listdir(model_dir):
                if f.endswith('_model.pkl'):
                    name = f.replace('_model.pkl', '')
                    self.models[name] = joblib.load(os.path.join(model_dir, f))

            se = os.path.join(model_dir, 'stacking_ensemble.pkl')
            if os.path.exists(se):
                self.stacking_classifier = joblib.load(se)

            ad = os.path.join(model_dir, 'anomaly_detector.pkl')
            if os.path.exists(ad):
                self.anomaly_detector = joblib.load(ad)

            logger.info(f"Loaded {len(self.models)} models from {model_dir}/")
            return True
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            return False

    def predict(self, features_df: pd.DataFrame, return_details: bool = False, url: str = None) -> Dict[str, Any]:
        """Make prediction using ensemble. Input: raw features dict/DataFrame."""
        try:
            if isinstance(features_df, dict):
                features_df = pd.DataFrame([features_df])
            elif isinstance(features_df, pd.Series):
                features_df = features_df.to_frame().T

            # Engineer same interaction features
            features_df = self._engineer_features(features_df)

            # Align to selected features
            for feat in self.selected_features:
                if feat not in features_df.columns:
                    features_df[feat] = 0
            features_df = features_df[self.selected_features]

            scaled    = self.scaler.transform(features_df)
            scaled_df = pd.DataFrame(scaled, columns=self.selected_features)

            # Per-model predictions
            model_results = {}
            phish_probs   = []

            for name, model in self.models.items():
                try:
                    pred = model.predict(scaled_df)[0]
                    prob = model.predict_proba(scaled_df)[0] if hasattr(model, 'predict_proba') else [0.5, 0.5]
                    model_results[name] = {
                        'prediction':    self.label_encoder.inverse_transform([pred])[0],
                        'phishing_prob': float(prob[1]),
                        'legit_prob':    float(prob[0])
                    }
                    phish_probs.append(float(prob[1]))
                except Exception:
                    pass

            # Ensemble prediction
            if self.stacking_classifier:
                ens_pred = self.stacking_classifier.predict(scaled_df)[0]
                ens_prob = self.stacking_classifier.predict_proba(scaled_df)[0]
            else:
                preds = [v['phishing_prob'] for v in model_results.values()]
                avg_p = sum(preds) / len(preds) if preds else 0.5
                ens_prob = [1 - avg_p, avg_p]
                ens_pred = 1 if avg_p > 0.5 else 0

            # Anomaly detection
            is_anomaly    = False
            anomaly_score = 0.0
            if self.anomaly_detector:
                anomaly_score = float(self.anomaly_detector.decision_function(scaled_df)[0])
                is_anomaly    = self.anomaly_detector.predict(scaled_df)[0] == -1

            final_label  = self.label_encoder.inverse_transform([ens_pred])[0]
            phishing_prob = float(ens_prob[1])

            # ── Alexa brand whitelist cap (+ extended modern brands) ─────────
            # If the BASE DOMAIN is a known legitimate brand, URL path/structural
            # features cannot reliably flag phishing. Cap score to 15%.
            # The intelligence APIs (Layer 1+2) will catch real phishing on these.
            _EXTRA_BRANDS = {
                'claude', 'openai', 'chatgpt', 'anthropic', 'gemini', 'notion',
                'figma', 'vercel', 'netlify', 'supabase', 'huggingface', 'wandb',
                'colab', 'kaggle', 'replit', 'codesandbox', 'stackblitz',
                'perplexity', 'midjourney', 'stability', 'runway', 'linear',
                'sentry', 'datadog', 'grafana', 'posthog', 'mixpanel',
            }
            if url:
                try:
                    from urllib.parse import urlparse
                    from feature_extractor import ALEXA_SLDS
                    _parsed = urlparse(url if '://' in url else 'http://' + url)
                    _parts  = _parsed.netloc.split(':')[0].split('.')
                    _sld    = _parts[-2].lower() if len(_parts) >= 2 else ''
                    if (_sld in ALEXA_SLDS) or (_sld in _EXTRA_BRANDS):
                        _cap = 0.15
                        if phishing_prob > _cap:
                            phishing_prob = _cap
                            final_label   = 'legitimate'
                            for k in model_results:
                                if model_results[k]['phishing_prob'] > _cap:
                                    model_results[k]['phishing_prob'] = _cap
                                    model_results[k]['legit_prob']    = 1 - _cap
                                    model_results[k]['prediction']    = 'legitimate'
                except Exception:
                    pass

            # ── UUID-in-path discount ─────────────────────────────────────────
            # URLs with a UUID in the path are characteristic of legitimate web apps
            # (chat session IDs, resource IDs, etc.) Phishing URLs don't use real UUIDs.
            # If the score is ambiguous (45–75%), apply a discount to prevent false positives.
            try:
                _has_uuid = int(features_df['has_uuid_in_path'].iloc[0]) if 'has_uuid_in_path' in features_df.columns else 0
                if _has_uuid and 0.45 <= phishing_prob <= 0.75:
                    phishing_prob = min(phishing_prob * 0.35, 0.20)  # Strong discount
                    final_label   = 'legitimate'
            except Exception:
                pass

            # ── Typosquatting hard override ──────────────────────────────────────
            # If the domain is 1 edit away from a known brand (typosquatting_score ≥ 0.90),
            # override the ML result — even if the brand whitelist cap already ran.
            # Example: flipkar.com (dist=1 from flipkart) must be PHISHING, not legitimate.
            try:
                _typo_score = float(features_df['typosquatting_score'].iloc[0]) \
                    if 'typosquatting_score' in features_df.columns else 0.0
                if _typo_score >= 0.90:
                    phishing_prob = max(phishing_prob, 0.93)
                    final_label   = 'phishing'
            except Exception:
                pass

            result = {
                'prediction':         final_label,
                'phishing_probability': phishing_prob,
                'confidence':         float(max(ens_prob)),
                'risk_level':         self._risk_level(phishing_prob),
                'anomaly_score':      anomaly_score,
                'is_anomaly':         is_anomaly,
            }
            if return_details:
                result['individual_models'] = model_results

            return result

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {'prediction': 'error', 'phishing_probability': 0.5,
                    'confidence': 0.0, 'risk_level': 'unknown', 'error': str(e)}

    @staticmethod
    def _risk_level(prob: float) -> str:
        if prob >= 0.90: return 'Critical'
        if prob >= 0.70: return 'High'
        if prob >= 0.50: return 'Medium'
        if prob >= 0.30: return 'Low'
        return 'Safe'


def main():
    print("=" * 70)
    print("  PhishGuard — ML Training Pipeline (Layer 3)")
    print("=" * 70)

    detector = PhishingDetector()

    dataset_path = 'data/dataset_phishing.csv'
    small_path   = 'data/dataset_phishing_50k.csv'

    if os.path.exists(small_path):
        print(f"\nFound smaller dataset ({small_path}). Use it for faster training? [Y/n]")
        if input().strip().lower() != 'n':
            dataset_path = small_path

    df = detector.load_dataset(dataset_path)
    X_tr, X_te, y_tr, y_te = detector.preprocess(df)
    detector.train_models(X_tr, y_tr)
    detector.create_ensemble(X_tr, y_tr)
    detector.train_anomaly_detector(X_tr)
    detector.evaluate(X_te, y_te)
    detector.save_models('models')

    print("\n" + "=" * 70)
    print("  Training Complete! Run: streamlit run app.py")
    print("=" * 70)


if __name__ == "__main__":
    main()
