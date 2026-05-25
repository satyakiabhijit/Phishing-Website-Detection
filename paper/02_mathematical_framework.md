## III. Proposed Mathematical Framework

This section constitutes the core technical contribution of PhishGuard v2. We present a comprehensive mathematical formulation of the feature engineering pipeline, the ensemble architecture, and the classification decision process.

### A. URL Structural Decomposition

Given an input URL string $u$, we first decompose it into its constituent components according to RFC 3986 [33]:

$$u = \text{scheme} \; \| \; \text{authority} \; \| \; \text{path} \; \| \; \text{query} \; \| \; \text{fragment}$$

where the authority component is further decomposed as:

$$\text{authority} = \text{userinfo} \; @ \; \text{host} \; : \; \text{port}$$

Let $h$ denote the hostname extracted from the authority, and let $d_1.d_2.\ldots.d_k$ denote the dot-separated labels of $h$, where $d_k$ is the top-level domain (TLD). We define the effective second-level domain as $d_{k-1}$ and the subdomain depth as $\sigma(h) = k - 2$ for $k \geq 2$.

### B. Character-Class Distribution Features

For a URL string $u$ of length $|u|$, we partition the character set into disjoint classes and compute both absolute counts and normalized ratios:

**Definition 1 (Letter Count and Ratio).**

$$N_{\alpha}(u) = |\{c \in u : c \in [a\text{-}zA\text{-}Z]\}|, \quad R_{\alpha}(u) = \frac{N_{\alpha}(u)}{|u|}$$

**Definition 2 (Digit Count and Ratio).**

$$N_{\delta}(u) = |\{c \in u : c \in [0\text{-}9]\}|, \quad R_{\delta}(u) = \frac{N_{\delta}(u)}{|u|}$$

**Definition 3 (Special Character Count and Ratio).** Let $\mathcal{S}$ denote the set of characters not in $[a\text{-}zA\text{-}Z0\text{-}9./:?\text{=}\&\text{-}\_]$. Then:

$$N_s(u) = |\{c \in u : c \in \mathcal{S}\}|, \quad R_s(u) = \frac{|\{c \in u : c \notin [a\text{-}zA\text{-}Z0\text{-}9/]\}|}{|u|}$$

The rationale for these features derives from the observation that phishing URLs exhibit systematically elevated digit ratios and special character densities compared to legitimate URLs. Phishing domains frequently embed hexadecimal identifiers, session tokens, or randomized substrings to evade blacklists, leading to character distributions that deviate measurably from the natural language patterns characteristic of legitimate domain names [18].

### C. Shannon Entropy Analysis

Information entropy provides a principled measure of the randomness in a character sequence. For a URL string $u$ with character alphabet $\mathcal{A}$, we compute the Shannon entropy [34]:

**Definition 4 (Shannon Entropy of URL).**

$$H(u) = -\sum_{c \in \mathcal{A}} p(c) \log_2 p(c)$$

where $p(c) = \frac{\text{count}(c, u)}{|u|}$ is the empirical probability of character $c$ in $u$.

The normalized entropy, which we term the URL Character Probability feature, is defined as:

$$\text{URLCharProb}(u) = \min\left(\frac{H(u)}{H_{\max}}, 1.0\right)$$

where $H_{\max} = \log_2 |\mathcal{A}|$ is the maximum entropy for a uniform distribution over the alphabet. In practice, we use $H_{\max} = 6.3$ bits, corresponding to the approximate entropy of a uniformly distributed ASCII printable character set.

**Theorem 1 (Entropy Discrimination).** *Let $\mathcal{U}_L$ and $\mathcal{U}_P$ denote the sets of legitimate and phishing URLs respectively. Then:*

$$\mathbb{E}[H(u) \mid u \in \mathcal{U}_P] > \mathbb{E}[H(u) \mid u \in \mathcal{U}_L]$$

*with high probability, because phishing URLs incorporate randomized tokens and obfuscated paths that increase character diversity.*

This theoretical expectation is empirically validated by our dataset analysis, where phishing URLs exhibit mean entropy of 4.21 bits compared to 3.67 bits for legitimate URLs (Welch's t-test: $t = 87.3$, $p < 10^{-15}$).

### D. Character Continuation Rate

We introduce the Character Continuation Rate (CCR) to quantify the longest consecutive repetition of any single character in the URL, normalized by URL length:

**Definition 5 (Character Continuation Rate).**

$$\text{CCR}(u) = \frac{\max_{i} \; r_i(u)}{|u|}$$

where $r_i(u)$ is the length of the maximal run of identical characters starting at position $i$:

$$r_i(u) = \max\{k : u[i] = u[i+1] = \cdots = u[i+k-1]\}$$

Legitimate URLs typically exhibit low CCR values because domain names and paths use natural language words with varied character sequences. Phishing URLs, particularly those employing padding techniques (e.g., `http://www.paypal.com-verify-account-update-secure-login-............@malicious.com`), exhibit elevated CCR values due to repeated delimiter characters.

### E. TLD Legitimacy Probability

We model the trustworthiness of a top-level domain using an empirical probability distribution derived from the Alexa Top 1,000 domains:

**Definition 6 (TLD Legitimacy Probability).**

$$P_{\text{TLD}}(t) = \frac{|\{d \in \mathcal{D}_{\text{Alexa}} : \text{TLD}(d) = t\}|}{|\mathcal{D}_{\text{Alexa}}|}$$

where $\mathcal{D}_{\text{Alexa}}$ is the set of top-ranked legitimate domains. The resulting probability mapping assigns high values to TLDs frequently associated with legitimate services (e.g., `.com \rightarrow 0.52$, `.org \rightarrow 0.08$, `.edu \rightarrow 0.03$, `.gov \rightarrow 0.02$) and low values to TLDs overrepresented in phishing campaigns (e.g., `.xyz \rightarrow 0.01$, `.tk \rightarrow 0.01$).

### F. URL Obfuscation Quantification

Percent-encoding (URL encoding) is a legitimate mechanism for representing special characters in URLs. However, its abuse—encoding characters that do not require encoding—is a well-documented obfuscation technique in phishing URLs [35]. We define:

**Definition 7 (Obfuscation Features).**

$$N_o(u) = |\{m : m \text{ matches } \%[0\text{-}9a\text{-}fA\text{-}F]\{2\} \text{ in } u\}|$$

$$\text{HasObfuscation}(u) = \mathbb{1}[N_o(u) > 0]$$

$$\text{ObfuscationRatio}(u) = \frac{N_o(u)}{|u|}$$

### G. N-gram Probabilistic Language Modeling

A central innovation of PhishGuard v2 is the application of character-level n-gram language modeling to assess the linguistic plausibility of domain names. We construct a trigram language model $\mathcal{M}$ from a curated corpus of 300 common English words and known brand names:

**Definition 8 (Trigram Probability).**

$$P_{\mathcal{M}}(c_i \mid c_{i-2}, c_{i-1}) = \frac{\text{count}(c_{i-2}c_{i-1}c_i)}{\sum_{c'} \text{count}(c_{i-2}c_{i-1}c')}$$

with Laplace smoothing to handle unseen trigrams:

$$\hat{P}_{\mathcal{M}}(c_i \mid c_{i-2}, c_{i-1}) = \frac{\text{count}(c_{i-2}c_{i-1}c_i) + 1}{\sum_{c'} \text{count}(c_{i-2}c_{i-1}c') + |\mathcal{V}|}$$

where $|\mathcal{V}| = 26$ is the vocabulary size (lowercase English alphabet).

**Definition 9 (Domain Perplexity).**

For a domain string $d = c_1 c_2 \ldots c_n$ with padding symbols:

$$\text{PP}(d) = \exp\left(-\frac{1}{n} \sum_{i=1}^{n} \log \hat{P}_{\mathcal{M}}(c_i \mid c_{i-2}, c_{i-1})\right)$$

Low perplexity indicates that the domain name follows natural English character patterns (e.g., `google`, `amazon`), while high perplexity signals randomized or gibberish strings characteristic of algorithmically generated phishing domains (e.g., `xk3mf9p2q`, `secur1ty-update-verif1cation`). In our experimental evaluation, the mean perplexity for legitimate domains is 12.4 compared to 43.7 for phishing domains.

### H. Typosquatting Detection via Edit Distance

Typosquatting—the registration of domain names that closely resemble legitimate brands with minor typographical variations—is a prevalent phishing technique. We employ the Damerau-Levenshtein distance [36] to quantify the similarity between extracted domain names and a curated list of 63 known brand names:

**Definition 10 (Damerau-Levenshtein Distance).**

The Damerau-Levenshtein distance $\text{DL}(s_1, s_2)$ between strings $s_1$ and $s_2$ is the minimum number of operations (insertions, deletions, substitutions, and transpositions of adjacent characters) required to transform $s_1$ into $s_2$:

$$\text{DL}(s_1, s_2) = d[|s_1|][|s_2|]$$

where $d[i][j]$ satisfies the recurrence:

$$d[i][j] = \min \begin{cases} d[i-1][j] + 1 & \text{(deletion)} \\ d[i][j-1] + 1 & \text{(insertion)} \\ d[i-1][j-1] + \mathbb{1}[s_1[i] \neq s_2[j]] & \text{(substitution)} \\ d[i-2][j-2] + \mathbb{1}[s_1[i] \neq s_2[j]] & \text{(transposition, if applicable)} \end{cases}$$

We define the typosquatting score as:

$$\text{TypoScore}(d) = \begin{cases} 0.95 & \text{if } \min_b \text{DL}(d, b) = 1 \\ 0.60 & \text{if } \min_b \text{DL}(d, b) = 2 \\ 0 & \text{otherwise} \end{cases}$$

where $b$ ranges over the set of known brands. A distance of 1 indicates a single-character deviation (e.g., `paypa1` vs. `paypal`), which strongly suggests intentional impersonation.

### I. Complete Feature Vector Specification

The complete 21-dimensional URL-only feature vector $\mathbf{x} \in \mathbb{R}^{21}$ is defined as:

$$\mathbf{x} = [x_1, x_2, \ldots, x_{21}]^T$$

| Index | Feature | Mathematical Definition |
|-------|---------|------------------------|
| 1 | URLLength | $\|u\|$ |
| 2 | DomainLength | $\|h\|$ |
| 3 | IsDomainIP | $\mathbb{1}[h \text{ matches IPv4}]$ |
| 4 | CharContinuationRate | $\text{CCR}(u)$ |
| 5 | TLDLegitimateProb | $P_{\text{TLD}}(\text{tld}(h))$ |
| 6 | URLCharProb | $\min(H(u)/6.3, 1.0)$ |
| 7 | TLDLength | $\|\text{tld}(h)\|$ |
| 8 | NoOfSubDomain | $\sigma(h)$ |
| 9 | HasObfuscation | $\mathbb{1}[N_o(u) > 0]$ |
| 10 | NoOfObfuscatedChar | $N_o(u)$ |
| 11 | ObfuscationRatio | $N_o(u) / \|u\|$ |
| 12 | NoOfLettersInURL | $N_\alpha(u)$ |
| 13 | LetterRatioInURL | $R_\alpha(u)$ |
| 14 | NoOfDegitsInURL | $N_\delta(u)$ |
| 15 | DegitRatioInURL | $R_\delta(u)$ |
| 16 | NoOfEqualsInURL | count of `=` in $u$ |
| 17 | NoOfQMarkInURL | count of `?` in $u$ |
| 18 | NoOfAmpersandInURL | count of `&` in $u$ |
| 19 | NoOfOtherSpecialCharsInURL | $N_s(u)$ |
| 20 | SpacialCharRatioInURL | $R_s(u)$ |
| 21 | IsHTTPS | $\mathbb{1}[u \text{ starts with https}]$ |

### J. Feature Normalization

Prior to model training, all features are normalized using the Robust Scaler transformation, which is resistant to outliers:

**Definition 11 (Robust Scaling).**

$$\tilde{x}_j = \frac{x_j - Q_2(x_j)}{Q_3(x_j) - Q_1(x_j)}$$

where $Q_1$, $Q_2$, and $Q_3$ denote the first quartile (25th percentile), median, and third quartile (75th percentile) of feature $j$ across the training set, respectively. This transformation is preferred over standard z-score normalization because URL features exhibit heavy-tailed distributions—legitimate URLs cluster in narrow ranges while phishing URLs can exhibit extreme outlier values for features such as URLLength and NoOfDegitsInURL.

### K. Stacking Ensemble Architecture

The PhishGuard v2 classification system employs a two-level stacking generalization architecture [28]:

**Level 0 (Base Classifiers).** Five heterogeneous classifiers $\{f_1, f_2, f_3, f_4, f_5\}$ are trained on the normalized feature vectors. Each base classifier $f_m$ produces a probabilistic output:

$$\hat{p}_m(\mathbf{x}) = P(y = 1 \mid \mathbf{x}; \theta_m)$$

To prevent information leakage in the stacking procedure, Level-0 predictions on the training set are generated through 5-fold stratified cross-validation: for each fold $k$, classifier $f_m$ is trained on the remaining 4 folds and produces predictions on fold $k$, ensuring that the meta-learner's training data consists of out-of-fold predictions [28].

**Level 1 (Meta-Classifier).** A regularized Logistic Regression meta-classifier $g$ receives the concatenated probability outputs of all base classifiers:

$$\mathbf{z} = [\hat{p}_1(\mathbf{x}), \hat{p}_2(\mathbf{x}), \hat{p}_3(\mathbf{x}), \hat{p}_4(\mathbf{x}), \hat{p}_5(\mathbf{x})]^T$$

The meta-classifier produces the final prediction:

$$\hat{y} = g(\mathbf{z}) = \sigma\left(\mathbf{w}^T \mathbf{z} + b\right)$$

where $\sigma(\cdot)$ is the logistic sigmoid function, $\mathbf{w} \in \mathbb{R}^5$ are the learned combination weights, and $b$ is the bias term. The weights are optimized by minimizing the regularized cross-entropy loss:

$$\mathcal{L}(\mathbf{w}, b) = -\frac{1}{N} \sum_{i=1}^{N} \left[y_i \log \hat{y}_i + (1 - y_i) \log(1 - \hat{y}_i)\right] + \frac{\lambda}{2} \|\mathbf{w}\|_2^2$$

where $\lambda = 1/C = 1.0$ is the regularization strength.

---
