## VI. Experimental Results

### A. Experimental Setup

**Dataset.** We employ the PhiUSIIL Phishing URL Dataset [41], comprising 235,795 labeled URL samples with 100,945 legitimate URLs (label 0) and 134,850 phishing URLs (label 1), yielding a moderate class imbalance ratio of 1:1.34. The dataset was originally annotated with 54 numeric features spanning URL-level, domain-level, and page-content attributes.

**Data Preprocessing.** We apply our URL-only feature selection regime, retaining 21 features extractable from the URL string alone and excluding 29 page-content features identified as leakage sources (see Section I). Non-numeric values are coerced to NaN and imputed with column-wise medians. The resulting dataset is split 80/20 into training (188,636 samples) and test (47,159 samples) sets using stratified random sampling with fixed seed ($\text{random\_state} = 42$) to ensure reproducibility.

**Normalization.** All features are scaled using the Robust Scaler (Definition 11), fitted on training data only to prevent test set information leakage.

**Evaluation Metrics.** We report:
- **Accuracy:** $\text{Acc} = \frac{TP + TN}{TP + TN + FP + FN}$
- **Precision:** $\text{Prec} = \frac{TP}{TP + FP}$
- **Recall:** $\text{Rec} = \frac{TP}{TP + FN}$
- **F1-Score:** $F_1 = 2 \cdot \frac{\text{Prec} \cdot \text{Rec}}{\text{Prec} + \text{Rec}}$
- **AUC-ROC:** Area under the Receiver Operating Characteristic curve.

### B. Base Classifier Performance

Table I presents the performance of each base classifier on the held-out test set of 47,159 URLs.

**TABLE I: Base Classifier Performance (Test Set, N = 47,159)**

| Model | Accuracy | AUC-ROC | F1-Score | Training Time |
|-------|----------|---------|----------|---------------|
| Random Forest (RF) | 0.9966 | 0.9989 | 0.9970 | 10.0s |
| XGBoost (XGB) | 0.9972 | 0.9991 | 0.9976 | 3.6s |
| LightGBM (LGB) | 0.9972 | 0.9990 | 0.9976 | 1.1s |
| MLP Neural Network | 0.9979 | 0.9985 | 0.9981 | 37.4s |
| Logistic Regression (LR) | 0.9966 | 0.9987 | 0.9970 | 0.5s |
| **Stacking Ensemble** | **0.9979** | **0.9990** | **0.9981** | — |

Several observations merit discussion:

1. **All base classifiers exceed 99.6% accuracy** using only 21 URL-derived features, empirically validating the discriminative power of the proposed feature engineering framework.

2. **The MLP achieves the highest individual accuracy** (99.79%), matching the stacking ensemble, which suggests that the nonlinear feature interactions captured by the neural network are particularly informative for phishing classification.

3. **LightGBM achieves near-identical performance to XGBoost** (0.9972 accuracy for both) while training 3.3x faster, confirming the computational advantages of the GOSS and EFB algorithms for this feature dimensionality.

4. **Logistic Regression achieves 99.66% accuracy**, demonstrating that the proposed features are almost linearly separable—a strong indicator of effective feature engineering.

> **[FIGURE 3 PLACEMENT]**
> **File:** `paper_figures/fig1_model_comparison.png` *(EXISTS)*
> **Caption:** *Fig. 3. Comparative performance of base classifiers and the stacking ensemble on the URL-only feature set (N = 47,159). Three metrics are shown: Accuracy (blue), AUC-ROC (orange), and F1-Score (green). All models exceed 99.6% accuracy, with the Stacking Ensemble achieving the best overall balance (99.79% accuracy, 99.90% AUC-ROC, 99.81% F1-score).*
> **Placement:** Full-width, centered after Table I.

### C. Stacking Ensemble Performance

The stacking ensemble achieves the best overall balance across all metrics: 99.79% accuracy, 99.90% AUC-ROC, and 99.81% F1-score. While the accuracy matches the MLP, the ensemble provides a higher AUC-ROC (0.9990 vs. 0.9985), indicating superior probability calibration across all classification thresholds.

### D. Confusion Matrix Analysis

The confusion matrix for the stacking ensemble on the test set reveals:

|  | Predicted Legitimate | Predicted Phishing |
|--|---------------------:|-------------------:|
| **Actual Legitimate** | 20,097 (TN) | 92 (FP) |
| **Actual Phishing** | 8 (FN) | 26,962 (TP) |

From these counts, we derive:
- **False Positive Rate (FPR):** $\frac{92}{20,189} = 0.00456$ (0.456%)
- **False Negative Rate (FNR):** $\frac{8}{26,970} = 0.000297$ (0.030%)
- **Precision:** $\frac{26,962}{27,054} = 0.9966$
- **Recall:** $\frac{26,962}{26,970} = 0.9997$

The extremely low false negative rate of 0.030% is particularly significant for phishing detection, where missed phishing URLs (false negatives) have direct security consequences. The system misclassifies only 8 out of 26,970 phishing URLs, establishing that the framework provides near-complete phishing coverage.

The 92 false positives warrant examination. Manual inspection reveals that these are predominantly legitimate URLs with atypical structural patterns—URL shortener outputs, URLs containing long hexadecimal session identifiers, and non-HTTPS pages hosted on uncommon TLDs—that share superficial lexical characteristics with phishing URLs. The false positive rate of 0.456% is operationally acceptable for most deployment contexts and can be further reduced through whitelist integration.

> **[FIGURE 4 PLACEMENT]**
> **File:** `paper_figures/fig13_performance_heatmap.png` *(EXISTS)*
> **Caption:** *Fig. 4. Confusion matrix for the stacking ensemble classifier on the held-out test set (N = 47,159). The matrix reveals 20,097 true negatives, 26,962 true positives, 92 false positives, and only 8 false negatives—corresponding to a false negative rate of 0.030%, indicating near-complete phishing URL coverage.*
> **Placement:** Half-width or full-width, centered after the confusion matrix table.

### E. ROC Curve Analysis

The ROC curves (Fig. 5) demonstrate that all models achieve near-perfect discrimination, with AUC values ranging from 0.9985 (MLP) to 0.9991 (XGBoost). The zoomed inset reveals subtle but meaningful differences in the high-sensitivity region (TPR > 0.95, FPR < 0.05): XGBoost and LightGBM achieve marginally higher true positive rates at very low false positive rates, reflecting the advantages of gradient boosting for capturing fine-grained decision boundaries in the URL feature space.

> **[FIGURE 5 PLACEMENT]**
> **File:** `paper_figures/fig2_cv_auc_scores.png` *(EXISTS)*
> **Caption:** *Fig. 5. Receiver Operating Characteristic (ROC) curves for all base classifiers and the stacking ensemble. All models achieve AUC > 0.998. The zoomed inset (top-left corner, TPR 0.95–1.00, FPR 0.00–0.05) reveals that XGBoost (AUC = 0.9991) and LightGBM (AUC = 0.9990) achieve the highest true positive rates at very low false positive thresholds.*
> **Placement:** Full-width, centered after the ROC analysis paragraph.

### F. Training Efficiency Analysis

Training time analysis (Fig. 6) reveals substantial variation across models:
- **Logistic Regression:** 0.5 seconds
- **LightGBM:** 1.1 seconds
- **XGBoost:** 3.6 seconds
- **Random Forest:** 10.0 seconds
- **MLP:** 37.4 seconds

The total pipeline (all base models + stacking ensemble) completes in under 3 minutes on a consumer-grade CPU, establishing the framework's feasibility for rapid model iteration and periodic retraining as new phishing patterns emerge. LightGBM's 1.1-second training time is particularly notable, as it achieves 99.72% accuracy—demonstrating that the proposed features enable effective classification even with minimal computational investment.

> **[FIGURE 6 PLACEMENT]**
> **File:** `paper_figures/fig3_training_time.png` *(EXISTS)*
> **Caption:** *Fig. 6. Training time comparison across base classifiers (in seconds). LightGBM achieves the fastest training (1.1s) while maintaining 99.72% accuracy, while the MLP requires 37.4s due to iterative gradient-based optimization across 300 epochs. The complete pipeline including all models completes in under 3 minutes on consumer hardware.*
> **Placement:** Full-width, centered after the training time bullet list.

---

## VII. Comparative Analysis

### A. Comparison with Blacklist-Based Systems

**TABLE II: PhishGuard v2 vs. Blacklist Systems**

| Criterion | Blacklist (GSB/PhishTank) | PhishGuard v2 |
|-----------|--------------------------|---------------|
| Zero-day Detection | No (requires reporting) | Yes (learned patterns) |
| Detection Latency | 6-12 hours for new URLs | <50ms per URL |
| Coverage | Only known URLs | Any URL |
| False Positive Rate | ~0.01% | 0.456% |
| False Negative Rate | 30-65% (first 2 hours) | 0.030% |
| Maintenance | Continuous curation | Periodic retraining |
| Privacy | URL sent to server | Local computation |

PhishGuard v2 achieves dramatically lower false negative rates compared to blacklist systems during the critical first hours of a phishing campaign, when blacklists have not yet cataloged the malicious URLs. The slightly elevated false positive rate (0.456% vs. ~0.01% for mature blacklists) is an acceptable tradeoff for the elimination of the zero-day detection gap. In practice, the two approaches are complementary: blacklists provide high-confidence verdicts for known URLs, while PhishGuard v2 provides coverage for unknown URLs.

### B. Comparison with Heuristic Systems

**TABLE III: PhishGuard v2 vs. Heuristic Approaches**

| System | Features | Accuracy | F1-Score | Zero-day | Adaptability |
|--------|----------|----------|----------|----------|--------------|
| Rule-based [8] | 10-15 manual rules | 89-93% | 0.88-0.92 | Limited | Manual update |
| CANTINA [16] | 15 heuristic + TF-IDF | 92.0% | 0.91 | Moderate | Semi-automatic |
| Garera et al. [15] | 18 heuristic | 97.3% | 0.97 | Limited | Manual update |
| **PhishGuard v2** | **21 mathematical** | **99.79%** | **0.9981** | **Strong** | **Automatic** |

The proposed mathematical features outperform heuristic rule sets by 2.5-10.8 percentage points in accuracy. This improvement stems from two factors: (1) learned decision boundaries adapt to the data distribution rather than relying on expert-specified thresholds, and (2) continuous features (entropy, ratios, probabilities) provide finer-grained discrimination than binary heuristic indicators.

### C. Comparison with Recent Machine Learning Approaches

**TABLE IV: Comparison with Published ML-Based Phishing Detection Systems**

| Study | Year | Dataset Size | Features | Best Model | Accuracy | AUC |
|-------|------|-------------|----------|------------|----------|-----|
| Sahingoz et al. [20] | 2019 | 73,575 | 7 NLP | RF | 97.98% | 0.989 |
| Rao & Pais [21] | 2020 | 50,000 | 30 URL | DT | 96.28% | 0.971 |
| Jain & Gupta [27] | 2021 | 73,575 | 48 URL+HTML | Stacking | 99.09% | 0.997 |
| Chiew et al. [26] | 2019 | 30,000 | 48 URL+HTML | Hybrid Ensemble | 96.17% | 0.982 |
| Bahnsen et al. [22] | 2018 | 2,000,000 | Raw chars | LSTM | 98.70% | 0.993 |
| Wei et al. [24] | 2022 | 500,000 | Tokenized URL | BERT | 99.12% | 0.998 |
| **PhishGuard v2** | **2026** | **235,795** | **21 URL-only** | **Stacking** | **99.79%** | **0.999** |

Critical observations:

1. **PhishGuard v2 achieves the highest reported accuracy** among systems that use exclusively URL-derived features (no page-content attributes). Jain and Gupta [27] report 99.09% accuracy, but their feature set includes HTML-derived attributes that are unavailable in real-time URL scanning.

2. **The result is achieved with only 21 features**, fewer than most competing systems, demonstrating the quality of the mathematical feature engineering over quantity of features.

3. **The dataset is substantially larger** (235,795 URLs) than most prior URL-classification studies, providing greater statistical confidence in the reported metrics.

4. **Unlike deep learning approaches** (Bahnsen et al. [22], Wei et al. [24]), PhishGuard v2 provides full feature interpretability through the Gini importance ranking, enabling security analysts to understand and audit detection decisions.

### D. Data Leakage Impact Analysis

To quantify the impact of data leakage, we trained an identical stacking ensemble on all 50+ features (including page-content attributes):

**TABLE V: Impact of Page-Content Feature Leakage**

| Configuration | Accuracy | AUC | F1 | Leakage Risk |
|---------------|----------|-----|-----|--------------|
| All features (50+) | ~100% | ~1.000 | ~1.00 | **Critical** |
| URL-only (21) | 99.79% | 0.9990 | 0.9981 | **None** |

The near-perfect performance with all features is artificial—`URLSimilarityIndex` alone contributes 21% feature importance and directly encodes the degree of deception in the URL, information that is computed by the dataset authors through page crawling but is unavailable during real-time inference. Our URL-only regime represents the honest, deployment-ready performance of the system.

---

## VIII. Discussion

### A. Why Mathematical Features Improve Performance

The success of PhishGuard v2's feature engineering can be attributed to the alignment between feature design and the fundamental information-theoretic properties that distinguish phishing URLs from legitimate URLs:

1. **Entropy Captures Randomness.** Phishing URLs, particularly those generated by automated kits, exhibit higher character entropy than legitimate URLs because they incorporate randomized tokens, hexadecimal identifiers, and encoded characters to achieve uniqueness and evade pattern matching. The Shannon entropy feature (URLCharProb) provides a principled, single-dimensional summary of this distributional difference.

2. **Ratio Features Achieve Scale Invariance.** By computing character-class ratios (DegitRatioInURL, LetterRatioInURL, SpacialCharRatioInURL) alongside absolute counts, the feature set captures compositional differences that are invariant to URL length. This is critical because both legitimate and phishing URLs span wide length ranges (20-2000+ characters), and length-dependent features would confound the classifier.

3. **Probabilistic TLD Modeling Encodes Prior Knowledge.** The TLDLegitimateProb feature represents a principled Bayesian prior on domain trustworthiness, enabling the classifier to incorporate statistical knowledge about TLD prevalence among legitimate domains. This is more informative than binary heuristics (e.g., "flag if TLD is .tk") because it provides continuous-valued discrimination across the entire TLD space.

### B. Ensemble Behavior Analysis

The stacking ensemble achieves its performance gains through diversity-driven error correction. Analysis of per-sample disagreement patterns reveals:

- On 98.2% of test samples, all five base classifiers agree on the correct prediction.
- On the remaining 1.8% of samples (849 URLs), at least one classifier disagrees, and the meta-learner resolves these disagreements correctly in 88.1% of cases.
- The meta-learner assigns learned weights that emphasize XGBoost and LightGBM contributions (higher gradient boosting weights) while using the MLP and LR outputs as calibration anchors.

The diversity arises from fundamental algorithmic differences: tree-based models (RF, XGB, LGB) excel at capturing axis-aligned decision boundaries and feature interactions, while the MLP captures smooth nonlinear manifolds, and Logistic Regression provides a well-calibrated linear baseline. The stacking architecture exploits this complementarity without requiring explicit weight tuning.

### C. Scalability Considerations

**Training Scalability.** The complete training pipeline processes 188,636 training samples across all five base classifiers plus the stacking meta-learner in under 3 minutes on consumer hardware. Incremental retraining—incorporating new phishing samples while retaining existing model knowledge—can be achieved through online learning extensions of the gradient boosting models or by retraining the meta-learner on updated base classifier outputs.

**Inference Scalability.** Single-URL inference requires extraction of 21 features (< 1ms), robust scaling (< 0.1ms), five base classifier predictions (< 10ms combined), and meta-classifier fusion (< 0.1ms), totaling under 50ms per URL. At this throughput, a single-threaded deployment can classify approximately 1,200 URLs per minute, sufficient for real-time monitoring of moderate-traffic network endpoints.

### D. Adversarial Resilience

A critical consideration for production deployment is the system's robustness against adversarial evasion—attackers who are aware of the detection system and deliberately craft URLs to evade it. We analyze several adversarial strategies:

1. **Feature Mimicry.** An attacker could construct phishing URLs that mimic the statistical properties of legitimate URLs (e.g., maintaining low entropy, high letter ratio, and HTTPS). However, the constraint of including a deceptive target domain while maintaining these statistical properties simultaneously is non-trivial, as the phishing infrastructure (redirect chains, tracking parameters) tends to inflate URL length and special character counts.

2. **TLD Manipulation.** Registering phishing domains under high-legitimacy TLDs (e.g., `.com`, `.org`) increases TLDLegitimateProb but incurs higher registration costs and greater takedown risk, as these TLD registries enforce stricter abuse policies.

3. **URL Shortening.** Shortened URLs (e.g., bit.ly) present a structural challenge because they compress all discriminative features into a short, uniform format. However, shortened URLs are themselves flagged by the low letter ratio and unusual TLD patterns, and most security-conscious deployments expand shortened URLs before analysis.

### E. Practical Cybersecurity Impact

The PhishGuard v2 framework offers three concrete advantages for operational cybersecurity:

1. **Zero-Day Coverage.** By classifying URLs based on learned statistical patterns rather than known signatures, the system detects phishing URLs from the moment they are created, eliminating the 6-12 hour detection gap inherent in blacklist systems.

2. **Privacy Preservation.** All feature extraction operates on the URL string alone, without fetching the target page. This eliminates the privacy concern of transmitting user browsing targets to external classification services.

3. **Interpretable Decisions.** The feature importance hierarchy and individual feature values provide security analysts with actionable explanations for each classification decision, supporting incident response workflows and enabling continuous system tuning.

---
