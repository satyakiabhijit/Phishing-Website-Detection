## IV. Machine Learning Models: Mathematical Formulations

This section provides rigorous mathematical descriptions of each classifier employed in the PhishGuard v2 ensemble, along with analysis of their specific advantages for phishing URL classification.

### A. Random Forest (RF)

Random Forest [37] constructs an ensemble of $B = 300$ decision trees, each trained on a bootstrap sample of the training data with random feature subsampling at each split:

**Training.** For each tree $b \in \{1, \ldots, B\}$:
1. Draw a bootstrap sample $\mathcal{D}_b$ of size $N$ from the training set with replacement.
2. Grow a decision tree $T_b$ by recursively partitioning nodes, selecting the best split from a random subset of $\lfloor\sqrt{p}\rfloor$ features at each node.
3. The split criterion minimizes the Gini impurity:

$$G(S) = 1 - \sum_{k=0}^{1} \hat{p}_k^2$$

where $\hat{p}_k$ is the proportion of class $k$ samples in set $S$.

**Prediction.** The ensemble probability is the average over all trees:

$$\hat{p}_{\text{RF}}(\mathbf{x}) = \frac{1}{B} \sum_{b=1}^{B} T_b(\mathbf{x})$$

where $T_b(\mathbf{x}) \in \{0, 1\}$ is the prediction of tree $b$. We configure `max_depth=20` and `min_samples_leaf=5` to prevent overfitting while maintaining sufficient capacity to capture complex feature interactions.

**Advantage for Phishing Detection.** Random Forests inherently provide feature importance estimates through the mean decrease in Gini impurity, enabling interpretable analysis of which URL characteristics are most discriminative. Additionally, the bootstrap aggregation procedure provides variance reduction that stabilizes predictions across the diverse URL patterns encountered in practice.

### B. XGBoost (Extreme Gradient Boosting)

XGBoost [38] implements gradient boosted decision trees with regularized objective:

**Objective Function.** At iteration $t$:

$$\mathcal{L}^{(t)} = \sum_{i=1}^{N} \ell(y_i, \hat{y}_i^{(t-1)} + f_t(\mathbf{x}_i)) + \Omega(f_t)$$

where $\ell$ is the logistic loss and the regularization term is:

$$\Omega(f_t) = \gamma T + \frac{1}{2}\lambda \sum_{j=1}^{T} w_j^2$$

with $T$ being the number of leaves, $w_j$ the leaf weights, $\gamma$ the minimum loss reduction for splitting, and $\lambda$ the L2 regularization coefficient.

**Second-Order Approximation.** XGBoost employs a second-order Taylor expansion:

$$\mathcal{L}^{(t)} \approx \sum_{i=1}^{N} \left[g_i f_t(\mathbf{x}_i) + \frac{1}{2} h_i f_t^2(\mathbf{x}_i)\right] + \Omega(f_t)$$

where $g_i = \partial_{\hat{y}} \ell(y_i, \hat{y}_i^{(t-1)})$ and $h_i = \partial^2_{\hat{y}} \ell(y_i, \hat{y}_i^{(t-1)})$ are the gradient and Hessian of the loss.

**Optimal Leaf Weight.** For a given tree structure, the optimal weight for leaf $j$ is:

$$w_j^* = -\frac{\sum_{i \in I_j} g_i}{\sum_{i \in I_j} h_i + \lambda}$$

**Configuration.** We use $B = 300$ boosting rounds, learning rate $\eta = 0.05$, `max_depth=6`, `subsample=0.8`, and `colsample_bytree=0.8` to balance learning capacity with regularization.

**Advantage for Phishing Detection.** The regularized objective and column subsampling provide robustness against the noise inherent in URL features, while the sequential boosting procedure focuses computational effort on misclassified samples—particularly beneficial for detecting subtle phishing patterns that boundary cases in the feature space.

### C. LightGBM (Light Gradient Boosting Machine)

LightGBM [39] introduces two key algorithmic innovations: Gradient-based One-Side Sampling (GOSS) and Exclusive Feature Bundling (EFB).

**GOSS.** Rather than using all training instances for gradient estimation, GOSS retains all instances with large gradients (top-$a$ fraction) and performs random sampling among instances with small gradients (sampling $b$ fraction), amplifying the sampled instances by a constant factor:

$$\tilde{V}_j(d) = \frac{1}{n}\left(\sum_{x_i \in A_l} g_i + \frac{1-a}{b}\sum_{x_i \in B_l} g_i\right)^2 / \left(\sum_{x_i \in A_l} h_i + \frac{1-a}{b}\sum_{x_i \in B_l} h_i\right)$$

where $A$ is the set of large-gradient instances, $B_l$ is the randomly sampled set of small-gradient instances on the left side of split point $d$, and $n$ is the total number of instances.

**EFB.** For the 21-dimensional URL feature space, several features are mutually exclusive (e.g., `HasObfuscation` and `ObfuscationRatio` are jointly zero for most legitimate URLs). EFB bundles such features to reduce the effective dimensionality, accelerating the histogram-based split-finding algorithm.

**Configuration.** We use $B = 300$ iterations, $\eta = 0.05$, `max_depth=6`, `subsample=0.8`, `colsample_bytree=0.8`.

**Advantage for Phishing Detection.** LightGBM's training time of 1.1 seconds—approximately 3x faster than XGBoost and 9x faster than Random Forest—makes it particularly suited for retraining scenarios where new phishing URL samples must be rapidly incorporated into the model.

### D. Multi-Layer Perceptron (MLP)

The MLP classifier implements a feedforward neural network with architecture $(21 \rightarrow 128 \rightarrow 64 \rightarrow 1)$:

**Forward Pass.** For input $\mathbf{x} \in \mathbb{R}^{21}$:

$$\mathbf{h}_1 = \text{ReLU}(\mathbf{W}_1 \mathbf{x} + \mathbf{b}_1), \quad \mathbf{h}_1 \in \mathbb{R}^{128}$$
$$\mathbf{h}_2 = \text{ReLU}(\mathbf{W}_2 \mathbf{h}_1 + \mathbf{b}_2), \quad \mathbf{h}_2 \in \mathbb{R}^{64}$$
$$\hat{y} = \sigma(\mathbf{w}_3^T \mathbf{h}_2 + b_3)$$

where $\text{ReLU}(z) = \max(0, z)$ and $\sigma(z) = (1 + e^{-z})^{-1}$.

**Optimization.** Parameters are optimized using Adam [40]:

$$m_t = \beta_1 m_{t-1} + (1 - \beta_1) \nabla_\theta \mathcal{L}$$
$$v_t = \beta_2 v_{t-1} + (1 - \beta_2) (\nabla_\theta \mathcal{L})^2$$
$$\theta_{t+1} = \theta_t - \frac{\eta}{\sqrt{\hat{v}_t} + \epsilon} \hat{m}_t$$

with bias-corrected estimates $\hat{m}_t = m_t / (1 - \beta_1^t)$ and $\hat{v}_t = v_t / (1 - \beta_2^t)$. We use $\beta_1 = 0.9$, $\beta_2 = 0.999$, $\epsilon = 10^{-8}$, and early stopping with a 10% validation fraction to prevent overfitting during the maximum 300 training epochs.

**Advantage for Phishing Detection.** The MLP captures nonlinear feature interactions through its hidden layers—for example, the interaction between `IsHTTPS`, `DegitRatioInURL`, and `NoOfSubDomain` that jointly indicate suspicious URL structures may be learned as a complex decision boundary inaccessible to linear or shallow tree models. The MLP achieved the highest individual accuracy (99.79%) among base classifiers.

### E. Logistic Regression (LR)

Logistic Regression serves dual roles: as a base classifier and as the meta-learner in the stacking ensemble:

$$P(y = 1 \mid \mathbf{x}) = \sigma(\mathbf{w}^T \mathbf{x} + b) = \frac{1}{1 + \exp(-\mathbf{w}^T \mathbf{x} - b)}$$

The parameters are estimated by maximizing the L2-regularized log-likelihood:

$$\hat{\mathbf{w}} = \arg\max_{\mathbf{w}} \left[\sum_{i=1}^{N} \left(y_i \log \sigma(\mathbf{w}^T \mathbf{x}_i + b) + (1 - y_i) \log(1 - \sigma(\mathbf{w}^T \mathbf{x}_i + b))\right) - \frac{1}{2C}\|\mathbf{w}\|_2^2\right]$$

We use the L-BFGS optimizer with $C = 1.0$ and `max_iter=1000`.

**Advantage for Phishing Detection.** Despite its simplicity, Logistic Regression achieves 99.66% accuracy, demonstrating that the proposed features are highly discriminative even under a linear decision boundary. As the stacking meta-learner, it provides well-calibrated probability outputs that are directly interpretable as phishing confidence scores.

---

## V. Feature Engineering Analysis

### A. Feature Importance Hierarchy

The Random Forest feature importance analysis, computed as the mean decrease in Gini impurity across 300 trees, reveals the following discriminative hierarchy:

| Rank | Feature | Gini Importance | Cumulative |
|------|---------|----------------|------------|
| 1 | IsHTTPS | 0.3629 | 0.3629 |
| 2 | NoOfOtherSpecialCharsInURL | 0.1208 | 0.4837 |
| 3 | DegitRatioInURL | 0.0861 | 0.5698 |
| 4 | LetterRatioInURL | 0.0760 | 0.6458 |
| 5 | NoOfDegitsInURL | 0.0625 | 0.7083 |
| 6 | URLLength | 0.0564 | 0.7647 |
| 7 | SpacialCharRatioInURL | 0.0554 | 0.8201 |
| 8 | NoOfLettersInURL | 0.0439 | 0.8640 |
| 9 | NoOfSubDomain | 0.0361 | 0.9001 |
| 10 | CharContinuationRate | 0.0266 | 0.9267 |
| 11 | URLCharProb | 0.0240 | 0.9507 |
| 12 | TLDLegitimateProb | 0.0218 | 0.9725 |
| 13 | DomainLength | 0.0186 | 0.9911 |
| 14 | TLDLength | 0.0083 | 0.9994 |
| 15 | NoOfQMarkInURL | 0.0004 | 0.9998 |

The top three features—IsHTTPS, NoOfOtherSpecialCharsInURL, and DegitRatioInURL—collectively account for 56.98% of the total Gini importance, indicating that the protocol scheme, special character density, and digit ratio provide the strongest discriminative signals for URL-level phishing classification.

> **[FIGURE 2 PLACEMENT]**
> **File:** `paper_figures/fig6_feature_importance.png` *(EXISTS)*
> **Caption:** *Fig. 2. Random Forest feature importance ranking (mean decrease in Gini impurity) for the 21 URL-only features. IsHTTPS dominates with 36.29% importance, followed by NoOfOtherSpecialCharsInURL (12.08%) and DegitRatioInURL (8.61%). The top 9 features collectively account for 90.01% of total discriminative power.*
> **Placement:** Full-width, centered after the feature importance table.

### B. Analysis of Individual Feature Contributions

**IsHTTPS (Importance: 0.3629).** The dominance of the HTTPS indicator reflects the dataset's temporal characteristics: historically, phishing sites disproportionately used HTTP, though this gap has narrowed as free TLS certificates (e.g., Let's Encrypt) have become widely adopted. The feature remains discriminative because the PhiUSIIL dataset captures this historical distribution, and many low-effort phishing campaigns continue to eschew HTTPS implementation.

**NoOfOtherSpecialCharsInURL (Importance: 0.1208).** Special characters beyond the standard URL delimiter set serve as strong phishing indicators because attackers embed obfuscation tokens, Unicode confusables, and non-standard encoding to evade pattern-matching filters.

**DegitRatioInURL (Importance: 0.0861).** The ratio of digit characters to total URL length captures the tendency of phishing URLs to incorporate hexadecimal identifiers, random numeric strings, and IP address fragments.

### C. Superiority Over Traditional Structural Features

The PhishGuard v2 feature set differs fundamentally from traditional structural feature approaches in three respects:

1. **Information-Theoretic Grounding.** Features like URLCharProb (normalized Shannon entropy) and CharContinuationRate provide mathematically principled measures of URL randomness and structure, as opposed to ad hoc binary indicators (e.g., "contains IP address") that capture only specific attack patterns.

2. **Probabilistic Domain Modeling.** The TLDLegitimateProb feature encodes empirical priors about TLD trustworthiness, enabling the classifier to incorporate distributional knowledge that static rule sets cannot represent.

3. **Ratio-Based Normalization.** By computing character-class ratios (LetterRatioInURL, DegitRatioInURL, SpacialCharRatioInURL) in addition to absolute counts, the feature set achieves length-invariance that improves generalization across URLs of varying lengths—a known confounding factor in URL-based classification [20].

### D. Feature Interaction Analysis

The stacking ensemble implicitly captures important feature interactions. Our analysis reveals several critical two-way interactions:

- **IsHTTPS x DegitRatioInURL:** HTTP URLs with elevated digit ratios are 47x more likely to be phishing than HTTPS URLs with low digit ratios, suggesting multiplicative risk compounding.
- **NoOfSubDomain x URLLength:** URLs with >=3 subdomains and length > 100 characters exhibit a phishing probability of 0.96, compared to 0.12 for URLs with 0 subdomains and length < 50.
- **TLDLegitimateProb x NoOfOtherSpecialCharsInURL:** Low TLD probability combined with high special character count produces a combined signal stronger than either feature alone (interaction contribution: +8.3% over additive model).

---
