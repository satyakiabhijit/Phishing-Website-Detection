// =====================================================
// PhishGuard — Comprehensive Q&A Data
// Every possible question from basic to deep-technical
// =====================================================

const QA_DATA = [
  // ─────────────────────────────────────────────────────
  // CATEGORY: PROJECT OVERVIEW
  // ─────────────────────────────────────────────────────
  {
    cat: "project-overview",
    catLabel: "Project Overview",
    catIcon: "🎯",
    questions: [
      {
        q: "What is the title of your project?",
        difficulty: "basic",
        a: `<p>The project is titled <strong>"PhishGuard: A Mathematical Feature Engineering and Stacking Ensemble Framework for Intelligent Phishing URL Detection."</strong></p>
            <p>It combines mathematical feature engineering with a stacking ensemble of 5 ML classifiers to detect phishing URLs in real-time using only the URL string — no page crawling required.</p>`
      },
      {
        q: "What problem does your project solve?",
        difficulty: "basic",
        a: `<p>PhishGuard solves the problem of <strong>real-time phishing URL detection</strong>, particularly against <strong>zero-day attacks</strong> that bypass traditional blacklist systems.</p>
            <ul>
              <li>Phishing causes <strong>$10.3 billion</strong> in annual losses (FBI IC3, 2022).</li>
              <li>Over <strong>4.7 million</strong> phishing attacks were recorded in 2023 (APWG).</li>
              <li>Blacklists take <strong>6–12 hours</strong> to catalog new threats — 65% of phishing URLs finish their attack in <strong>2 hours</strong>.</li>
            </ul>
            <p>PhishGuard detects threats <strong>instantly</strong> (<50ms) using learned statistical patterns from the URL string alone.</p>`
      },
      {
        q: "What are the main contributions of your project?",
        difficulty: "basic",
        a: `<p>PhishGuard makes <strong>three principal contributions</strong>:</p>
            <ol>
              <li><strong>Data Leakage Identification:</strong> We identified and removed 29 page-content features from the PhiUSIIL dataset that caused artificial accuracy inflation. Features like <code>URLSimilarityIndex</code> (21% importance alone) encoded information unavailable at inference time.</li>
              <li><strong>Mathematical Feature Engineering:</strong> We designed 21 URL-only features grounded in Shannon entropy, n-gram language modeling, Damerau-Levenshtein edit distance, and obfuscation quantification.</li>
              <li><strong>Stacking Ensemble Architecture:</strong> A 2-level heterogeneous ensemble (RF, XGBoost, LightGBM, MLP, LR) with a Logistic Regression meta-classifier that achieves 99.79% accuracy and 99.90% AUC-ROC.</li>
            </ol>`
      },
      {
        q: "Why did you choose this topic? What motivated you?",
        difficulty: "basic",
        a: `<p>Several factors motivated this project:</p>
            <ul>
              <li><strong>Real-world impact:</strong> Phishing is the #1 cybercrime by victim count. It directly affects everyday internet users.</li>
              <li><strong>Research gap:</strong> We noticed that most published ML models for phishing detection were using page-content features that create data leakage — their reported accuracy is unreliable.</li>
              <li><strong>Technical challenge:</strong> Building a system that achieves near-perfect accuracy using <em>only</em> the URL string (no page crawling) is a non-trivial engineering and ML challenge.</li>
              <li><strong>Practical deployment:</strong> We wanted a system fast enough (<50ms) for real-time use, unlike existing slow page-crawling approaches.</li>
            </ul>`
      },
      {
        q: "What is phishing? Explain briefly.",
        difficulty: "basic",
        a: `<p><strong>Phishing</strong> is a type of cyberattack where an attacker creates a fraudulent website or communication that impersonates a legitimate entity (like a bank, email provider, or social media platform) to trick victims into revealing sensitive information — such as passwords, credit card numbers, or personal data.</p>
            <p>Common phishing techniques include:</p>
            <ul>
              <li><strong>Typosquatting:</strong> Registering domains like <code>paypa1.com</code> instead of <code>paypal.com</code></li>
              <li><strong>URL obfuscation:</strong> Using percent-encoding, IP addresses, or excessive subdomains to hide the real destination</li>
              <li><strong>IDN homograph attacks:</strong> Using visually similar Unicode characters (e.g., Cyrillic 'а' vs Latin 'a')</li>
              <li><strong>URL shorteners:</strong> Hiding the real URL behind bit.ly or similar services</li>
            </ul>`
      },
      {
        q: "Who is the target user of your system?",
        difficulty: "basic",
        a: `<p>PhishGuard targets multiple user segments:</p>
            <ul>
              <li><strong>Enterprise security teams:</strong> For real-time URL filtering in corporate networks</li>
              <li><strong>Browser extension developers:</strong> To integrate URL scanning into browsers</li>
              <li><strong>Email gateway services:</strong> To scan links in incoming emails before delivery</li>
              <li><strong>Everyday internet users:</strong> Through the web-based demo application built with Next.js</li>
              <li><strong>Security researchers:</strong> As a baseline for URL-only phishing detection research</li>
            </ul>`
      },
      {
        q: "What technologies / tech stack did you use?",
        difficulty: "basic",
        a: `<p>The project uses a <strong>dual-stack architecture</strong>:</p>
            <p><strong>ML Training Pipeline (Python):</strong></p>
            <ul>
              <li>scikit-learn, XGBoost, LightGBM — classifiers</li>
              <li>pandas, NumPy — data processing</li>
              <li>joblib — model serialization</li>
              <li>skl2onnx — ONNX export for cross-platform inference</li>
            </ul>
            <p><strong>Web Application (TypeScript/JavaScript):</strong></p>
            <ul>
              <li>Next.js 14 — React framework with server-side API routes</li>
              <li>Tailwind CSS + Framer Motion — styling and animations</li>
              <li>ONNX Runtime (via Hugging Face Space) — ML inference in production</li>
              <li>VirusTotal, Google Safe Browsing, IPQualityScore APIs — additional threat intelligence layers</li>
            </ul>`
      },
      {
        q: "What is the novelty / unique selling point of your project?",
        difficulty: "intermediate",
        a: `<p>The key novelties are:</p>
            <ol>
              <li><strong>Data leakage remediation:</strong> We are among the first to systematically identify and remove 29 leaky features from the PhiUSIIL dataset, providing <em>honest</em> benchmarks.</li>
              <li><strong>URL-only mathematical features:</strong> Our 21 features are grounded in information theory (Shannon entropy), probabilistic language modeling (n-gram perplexity), and computational linguistics (edit distance) — not ad hoc heuristics.</li>
              <li><strong>Highest URL-only accuracy:</strong> 99.79% accuracy with only 21 features — better than systems using 48+ features including page content.</li>
              <li><strong>End-to-end deployment:</strong> Full pipeline from Python training → ONNX export → Next.js web app → Hugging Face Space → Vercel deployment.</li>
            </ol>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: DATASET
  // ─────────────────────────────────────────────────────
  {
    cat: "dataset",
    catLabel: "Dataset",
    catIcon: "📊",
    questions: [
      {
        q: "Which dataset did you use?",
        difficulty: "basic",
        a: `<p>We used the <strong>PhiUSIIL Phishing URL Dataset</strong> from the <strong>UCI Machine Learning Repository</strong>.</p>
            <div class="highlight-box">
              <strong>Citation:</strong> R. Prasad, "PhiUSIIL Phishing URL Dataset," UCI Machine Learning Repository, 2024.<br>
              <strong>URL:</strong> <code>https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset</code>
            </div>`
      },
      {
        q: "Why did you choose this specific dataset?",
        difficulty: "intermediate",
        a: `<p>We selected the PhiUSIIL dataset for several reasons:</p>
            <ol>
              <li><strong>Scale:</strong> With 235,795 labeled samples, it's significantly larger than most phishing URL datasets (typically 10K–50K), providing greater statistical confidence.</li>
              <li><strong>Recency:</strong> Published in 2024, it captures modern phishing patterns.</li>
              <li><strong>Feature richness:</strong> The original dataset contains 54 numeric features spanning URL-level, domain-level, and page-content attributes — allowing us to study and isolate leakage.</li>
              <li><strong>Academic credibility:</strong> Hosted on the well-known UCI ML Repository, ensuring reproducibility.</li>
              <li><strong>Real-world URLs:</strong> Contains actual phishing and legitimate URLs collected from verified sources (PhishTank, OpenPhish for phishing; Alexa for legitimate).</li>
            </ol>`
      },
      {
        q: "How many samples are in the dataset?",
        difficulty: "basic",
        a: `<p><strong>Total: 235,795 URL samples</strong></p>
            <ul>
              <li><strong>Legitimate (label 0):</strong> 100,945 samples (42.8%)</li>
              <li><strong>Phishing (label 1):</strong> 134,850 samples (57.2%)</li>
            </ul>
            <p>This gives a moderate class imbalance ratio of <strong>1:1.34</strong>. The imbalance is mild enough that we didn't need techniques like SMOTE — stratified splitting preserved the distribution.</p>`
      },
      {
        q: "Is the dataset balanced or imbalanced? How did you handle it?",
        difficulty: "intermediate",
        a: `<p>The dataset is <strong>moderately imbalanced</strong> — 42.8% legitimate vs 57.2% phishing (ratio 1:1.34).</p>
            <p>We handled this through:</p>
            <ul>
              <li><strong>Stratified train/test split:</strong> The 80/20 split preserves the class ratio in both sets using <code>stratify=y</code> in scikit-learn.</li>
              <li><strong>Stratified K-Fold CV:</strong> All 5-fold cross-validation used <code>StratifiedKFold</code> to ensure balanced folds.</li>
              <li><strong>Appropriate metrics:</strong> We report F1-score (which balances precision and recall) and AUC-ROC (threshold-independent) alongside accuracy.</li>
            </ul>
            <p>We did <strong>not</strong> use SMOTE or other oversampling because the imbalance is mild, and our models already achieve 99.97% recall on the minority class (phishing).</p>`
      },
      {
        q: "How many features does the original dataset have?",
        difficulty: "basic",
        a: `<p>The original dataset has <strong>54+ features</strong> (after excluding non-numeric columns like URL, Domain, TLD, Title, FILENAME).</p>
            <p>These span three categories:</p>
            <ul>
              <li><strong>URL-level features (21):</strong> URLLength, DomainLength, IsHTTPS, Shannon entropy, etc.</li>
              <li><strong>Domain-level features (4):</strong> TLDLegitimateProb, NoOfSubDomain, etc.</li>
              <li><strong>Page-content features (29):</strong> LineOfCode, NoOfImage, HasSubmitButton, URLSimilarityIndex, etc.</li>
            </ul>
            <p>We retained only the <strong>21 URL-only features</strong> and dropped the 29 page-content features to eliminate data leakage.</p>`
      },
      {
        q: "How did you split the dataset?",
        difficulty: "basic",
        a: `<p>We used a standard <strong>80/20 stratified train-test split</strong>:</p>
            <ul>
              <li><strong>Training set:</strong> 188,636 samples (80%)</li>
              <li><strong>Test set:</strong> 47,159 samples (20%)</li>
            </ul>
            <p>Key details:</p>
            <ul>
              <li><code>random_state=42</code> for reproducibility</li>
              <li><code>stratify=y</code> to preserve class distribution</li>
              <li>Scaler was fit <strong>only on training data</strong> and then applied to test data (no test-set leakage)</li>
            </ul>`
      },
      {
        q: "Were there any missing values? How did you handle them?",
        difficulty: "intermediate",
        a: `<p>Yes, some features had missing or non-numeric values. We handled them in two steps:</p>
            <ol>
              <li><strong>Coercion:</strong> All feature columns were converted to numeric using <code>pd.to_numeric(col, errors='coerce')</code> — invalid values become NaN.</li>
              <li><strong>Imputation:</strong> NaN values were filled using <strong>column-wise median</strong> imputation: <code>df.fillna(df.median())</code>.</li>
            </ol>
            <p>We chose median over mean because URL features have <strong>heavy-tailed distributions</strong> — extreme outliers in features like URLLength would skew the mean, but not the median.</p>`
      },
      {
        q: "Where did the legitimate URLs in the dataset come from?",
        difficulty: "intermediate",
        a: `<p>The legitimate URLs in the PhiUSIIL dataset were sourced from <strong>Alexa Top websites</strong> and other verified legitimate web directories. These represent real, operational websites with established trust signals.</p>
            <p>Additionally, for our TLD Legitimacy Probability feature, we used the <strong>Alexa Top 1,000 domains</strong> (stored in <code>alexa_top1k.txt</code>) to build an empirical probability distribution of TLDs found among trusted domains.</p>`
      },
      {
        q: "Where did the phishing URLs come from?",
        difficulty: "intermediate",
        a: `<p>The phishing URLs were collected from verified phishing threat intelligence sources:</p>
            <ul>
              <li><strong>PhishTank:</strong> Community-curated, verified phishing URL database</li>
              <li><strong>OpenPhish:</strong> Automated phishing intelligence feed</li>
            </ul>
            <p>All phishing URLs were <strong>verified</strong> before inclusion — they were confirmed as active phishing pages at collection time, ensuring label quality.</p>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: DATA LEAKAGE
  // ─────────────────────────────────────────────────────
  {
    cat: "data-leakage",
    catLabel: "Data Leakage",
    catIcon: "🚨",
    questions: [
      {
        q: "What is data leakage? Why is it a problem?",
        difficulty: "basic",
        a: `<p><strong>Data leakage</strong> occurs when information from outside the training data is used to create the model, leading to overly optimistic performance estimates that don't generalize to production.</p>
            <p>In our context, data leakage happens when the model uses <strong>features that encode the label directly</strong> — i.e., features that are only available because the dataset authors already knew which URLs were phishing.</p>
            <div class="tip">In production, you receive an unknown URL and need to classify it <em>before</em> visiting it. You can't crawl the page to count HTML tags or check DOM structure — that would defeat the purpose of detection.</div>`
      },
      {
        q: "What specific features caused data leakage in the PhiUSIIL dataset?",
        difficulty: "intermediate",
        a: `<p>We identified <strong>29 page-content features</strong> that cause leakage. Key examples:</p>
            <ul>
              <li><code>URLSimilarityIndex</code> — <strong>The worst offender.</strong> This feature alone has 21% feature importance in a Random Forest. It directly measures how similar the URL is to the page title, which encodes deceptive intent.</li>
              <li><code>LineOfCode</code> — Requires fetching and parsing the HTML page</li>
              <li><code>DomainTitleMatchScore</code> — Compares domain to page title (requires crawling)</li>
              <li><code>NoOfExternalRef</code> — Counts external references in HTML</li>
              <li><code>HasSubmitButton</code>, <code>HasPasswordField</code>, <code>HasHiddenFields</code> — Require DOM analysis</li>
              <li><code>NoOfImage</code>, <code>NoOfCSS</code>, <code>NoOfJS</code> — Asset counts from page content</li>
              <li><code>HasFavicon</code>, <code>Robots</code>, <code>IsResponsive</code> — Server-side checks</li>
            </ul>
            <p>All 29 features require either <strong>fetching the page</strong> or <strong>querying external servers</strong> — impossible in real-time URL filtering.</p>`
      },
      {
        q: "How did you prove that data leakage was occurring?",
        difficulty: "advanced",
        a: `<p>We proved leakage through <strong>comparative experimentation</strong>:</p>
            <ol>
              <li><strong>All-features model:</strong> Training the stacking ensemble on all 50+ features (including page content) yielded <strong>~100% accuracy</strong> — suspiciously perfect.</li>
              <li><strong>Feature importance analysis:</strong> <code>URLSimilarityIndex</code> alone contributed 21% importance, and page-content features collectively dominated the top rankings.</li>
              <li><strong>Correlation analysis:</strong> We ran <code>abs(X[col].corr(y))</code> for each feature and flagged those with correlation >0.85 as "leaky" and >0.70 as "suspicious."</li>
              <li><strong>URL-only model:</strong> Removing all 29 leaky features, we still achieved <strong>99.79% accuracy</strong> — proving the URL features alone are sufficient and the page features were providing artificial inflation, not genuine signal.</li>
            </ol>
            <div class="highlight-box"><strong>Key insight:</strong> The ~0.2% accuracy drop from removing 29 features proves those features were mostly encoding label information, not adding independent discriminative power.</div>`
      },
      {
        q: "Why can't you use page-content features in production?",
        difficulty: "basic",
        a: `<p>Three critical reasons:</p>
            <ol>
              <li><strong>Latency:</strong> Fetching a web page takes 1–10 seconds. PhishGuard classifies URLs in <50ms. Real-time URL filtering (in browsers, email gateways, firewalls) cannot afford page-crawling latency.</li>
              <li><strong>Privacy:</strong> If your URL scanner visits every link a user encounters, it exposes their browsing behavior to the scanner operator. URL-only analysis keeps user data local.</li>
              <li><strong>Safety:</strong> Visiting a phishing page to analyze it could trigger malware downloads, tracking pixels, or other malicious payloads. URL-only analysis never contacts the target server.</li>
            </ol>`
      },
      {
        q: "How many features did you remove and how many did you keep?",
        difficulty: "basic",
        a: `<p><strong>Removed:</strong> 29 page-content features (identified as data leakage sources)</p>
            <p><strong>Kept:</strong> 21 URL-only features (extractable from the URL string alone)</p>
            <p>Additionally, non-feature columns were dropped: <code>FILENAME</code>, <code>URL</code>, <code>Domain</code>, <code>TLD</code>, <code>Title</code> (string identifiers, not numeric features).</p>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: FEATURE ENGINEERING
  // ─────────────────────────────────────────────────────
  {
    cat: "features",
    catLabel: "Feature Engineering",
    catIcon: "🧮",
    questions: [
      {
        q: "How many features did you use and what are they?",
        difficulty: "basic",
        a: `<p>We used <strong>21 URL-only features</strong>:</p>
            <ol>
              <li><code>URLLength</code> — Total length of the URL string</li>
              <li><code>DomainLength</code> — Length of the hostname</li>
              <li><code>IsDomainIP</code> — Is the domain an IP address? (1 or 0)</li>
              <li><code>CharContinuationRate</code> — Longest repeated char run / URL length</li>
              <li><code>TLDLegitimateProb</code> — Probability of TLD being legitimate (from Alexa Top 1K)</li>
              <li><code>URLCharProb</code> — Normalized Shannon entropy of URL</li>
              <li><code>TLDLength</code> — Length of the top-level domain</li>
              <li><code>NoOfSubDomain</code> — Number of subdomain levels</li>
              <li><code>HasObfuscation</code> — Whether URL contains percent-encoding</li>
              <li><code>NoOfObfuscatedChar</code> — Count of percent-encoded characters</li>
              <li><code>ObfuscationRatio</code> — Obfuscated chars / URL length</li>
              <li><code>NoOfLettersInURL</code> — Count of alphabetic characters</li>
              <li><code>LetterRatioInURL</code> — Letters / URL length</li>
              <li><code>NoOfDegitsInURL</code> — Count of digit characters</li>
              <li><code>DegitRatioInURL</code> — Digits / URL length</li>
              <li><code>NoOfEqualsInURL</code> — Count of '=' characters</li>
              <li><code>NoOfQMarkInURL</code> — Count of '?' characters</li>
              <li><code>NoOfAmpersandInURL</code> — Count of '&' characters</li>
              <li><code>NoOfOtherSpecialCharsInURL</code> — Count of other special characters</li>
              <li><code>SpacialCharRatioInURL</code> — Special characters / URL length</li>
              <li><code>IsHTTPS</code> — Whether URL uses HTTPS (1 or 0)</li>
            </ol>`
      },
      {
        q: "Why did you select these specific 21 features? What was your selection criteria?",
        difficulty: "intermediate",
        a: `<p>Our selection was based on <strong>two strict criteria</strong>:</p>
            <ol>
              <li><strong>URL-Only Extractability:</strong> Every feature must be computable from the URL string alone — no page fetching, no DNS lookup, no external API call at inference time.</li>
              <li><strong>Mathematical / Information-Theoretic Grounding:</strong> Each feature has a principled statistical rationale for why it discriminates phishing from legitimate URLs.</li>
            </ul>
            <p>We grouped the features into 7 categories by mathematical foundation:</p>
            <ul>
              <li><strong>Character-class distributions:</strong> Letters, digits, special chars (counts + ratios)</li>
              <li><strong>Shannon entropy:</strong> URLCharProb measures randomness</li>
              <li><strong>Structural decomposition:</strong> URLLength, DomainLength, subdomains, TLD</li>
              <li><strong>Obfuscation quantification:</strong> Percent-encoding analysis</li>
              <li><strong>TLD legitimacy:</strong> Empirical probability from Alexa Top 1K</li>
              <li><strong>Character continuation:</strong> Longest repeated character sequence</li>
              <li><strong>Protocol indicator:</strong> IsHTTPS</li>
            </ul>`
      },
      {
        q: "What is Shannon Entropy and how is it used as a feature?",
        difficulty: "intermediate",
        a: `<p><strong>Shannon entropy</strong> is an information-theoretic measure of randomness or unpredictability in a sequence. It was introduced by Claude Shannon in 1948.</p>
            <div class="formula">H(u) = -Σ p(c) · log₂(p(c))    for all characters c in URL u
where p(c) = count(c, u) / |u|</div>
            <p>We use <strong>normalized entropy</strong> (URLCharProb):</p>
            <div class="formula">URLCharProb = min(H(u) / 6.3, 1.0)</div>
            <p>where 6.3 bits ≈ maximum entropy for ASCII printable characters.</p>
            <p><strong>Why it works:</strong></p>
            <ul>
              <li>Legitimate URLs use natural language words → <strong>lower entropy</strong> (mean: 3.67 bits)</li>
              <li>Phishing URLs use random tokens, hex IDs, encoded chars → <strong>higher entropy</strong> (mean: 4.21 bits)</li>
              <li>This difference is statistically significant: Welch's t-test t=87.3, p<10⁻¹⁵</li>
            </ul>`
      },
      {
        q: "What is the n-gram language model you built? How does it work?",
        difficulty: "advanced",
        a: `<p>We built a <strong>character-level trigram language model</strong> from a curated corpus of 300 common English words and known brand names.</p>
            <div class="formula">P(cᵢ | cᵢ₋₂, cᵢ₋₁) = count(cᵢ₋₂cᵢ₋₁cᵢ) / Σ count(cᵢ₋₂cᵢ₋₁c')

With Laplace smoothing:
P̂(cᵢ | cᵢ₋₂, cᵢ₋₁) = (count + 1) / (Σcount + |V|)
where |V| = 26 (lowercase alphabet)</div>
            <p>We then compute <strong>domain perplexity</strong>:</p>
            <div class="formula">PP(d) = exp(-1/n · Σ log P̂(cᵢ | cᵢ₋₂, cᵢ₋₁))</div>
            <p><strong>Results:</strong></p>
            <ul>
              <li>Legitimate domains: mean perplexity <strong>12.4</strong> (e.g., "google" follows English patterns)</li>
              <li>Phishing domains: mean perplexity <strong>43.7</strong> (e.g., "xk3mf9p2q" is gibberish)</li>
            </ul>
            <p>The corpus includes 300+ words covering common English terms, tech vocabulary, and major brand names (google, amazon, paypal, etc.).</p>`
      },
      {
        q: "How does typosquatting detection work in your system?",
        difficulty: "intermediate",
        a: `<p>We use the <strong>Damerau-Levenshtein distance</strong> to detect typosquatting — domain names that closely resemble legitimate brands with minor typographical differences.</p>
            <p><strong>Damerau-Levenshtein distance</strong> measures the minimum number of operations to transform one string into another, allowing:</p>
            <ul>
              <li>Insertions</li>
              <li>Deletions</li>
              <li>Substitutions</li>
              <li>Transpositions of adjacent characters</li>
            </ul>
            <p>We compare the extracted domain against a curated list of <strong>63 known brand names</strong> and assign a TypoScore:</p>
            <div class="formula">TypoScore = 0.95  if min DL distance = 1  (e.g., paypa1 → paypal)
TypoScore = 0.60  if min DL distance = 2
TypoScore = 0.00  otherwise</div>
            <p>A distance of 1 strongly suggests intentional impersonation.</p>`
      },
      {
        q: "Which feature has the highest importance? Why?",
        difficulty: "basic",
        a: `<p><strong>IsHTTPS</strong> has the highest importance at <strong>36.29%</strong> (Gini importance from Random Forest).</p>
            <p><strong>Why?</strong> Historically, phishing sites disproportionately used HTTP because:</p>
            <ul>
              <li>Setting up HTTPS requires obtaining a TLS certificate</li>
              <li>Many phishing kits skip HTTPS for speed of deployment</li>
              <li>The PhiUSIIL dataset captures this historical distribution</li>
            </ul>
            <p><strong>Top 5 features by importance:</strong></p>
            <ol>
              <li>IsHTTPS — 36.29%</li>
              <li>NoOfOtherSpecialCharsInURL — 12.08%</li>
              <li>DegitRatioInURL — 8.61%</li>
              <li>LetterRatioInURL — 7.60%</li>
              <li>NoOfDegitsInURL — 6.25%</li>
            </ol>
            <p>The top 3 features alone account for <strong>56.98%</strong> of total importance.</p>`
      },
      {
        q: "Why use ratio features (LetterRatio, DigitRatio) alongside count features?",
        difficulty: "intermediate",
        a: `<p>We use <strong>both counts and ratios</strong> to achieve <strong>scale invariance</strong>.</p>
            <p><strong>Problem with counts alone:</strong> A URL with 50 digits and length 200 is very different from one with 50 digits and length 60 — the density matters, not just the absolute count.</p>
            <p><strong>Problem with ratios alone:</strong> A URL with 2 digits out of 10 characters (20% ratio) vs 20 digits out of 100 characters (20% ratio) — the absolute count can still provide additional discriminative signal.</p>
            <p>By including <strong>both</strong>, the model can learn complex interactions between absolute feature magnitudes and their normalized proportions, improving generalization across URLs of varying lengths (20–2000+ characters).</p>`
      },
      {
        q: "What is the TLD Legitimacy Probability feature?",
        difficulty: "intermediate",
        a: `<p>It's an <strong>empirical probability</strong> representing how likely a TLD appears among known legitimate domains:</p>
            <div class="formula">P_TLD(t) = |{d ∈ Alexa_Top1K : TLD(d) = t}| / |Alexa_Top1K|</div>
            <p>Example values:</p>
            <ul>
              <li><code>.com</code> → 0.52 (very common among legitimate sites)</li>
              <li><code>.org</code> → 0.08</li>
              <li><code>.edu</code> → 0.03</li>
              <li><code>.gov</code> → 0.02</li>
              <li><code>.xyz</code> → 0.01 (frequently used by phishers)</li>
              <li><code>.tk</code> → 0.01 (free TLD, heavily abused)</li>
            </ul>
            <p>This provides a <strong>continuous-valued Bayesian prior</strong> on domain trustworthiness, unlike binary heuristics like "flag if TLD is .tk."</p>`
      },
      {
        q: "What is the Character Continuation Rate (CCR)?",
        difficulty: "intermediate",
        a: `<p>CCR measures the <strong>longest consecutive repetition of any single character</strong> in the URL, normalized by URL length:</p>
            <div class="formula">CCR(u) = max_i(r_i(u)) / |u|

where r_i(u) = length of maximal run of identical characters at position i</div>
            <p><strong>Why it works:</strong></p>
            <ul>
              <li>Legitimate URLs use natural language → varied characters → <strong>low CCR</strong></li>
              <li>Phishing URLs often use padding tricks like <code>http://www.paypal.com-verify-............@malicious.com</code> → repeated dots → <strong>high CCR</strong></li>
              <li>The @ symbol trick causes browsers to ignore everything before it</li>
            </ul>`
      },
      {
        q: "What are the obfuscation features? Why are they useful?",
        difficulty: "intermediate",
        a: `<p>We define three obfuscation features based on <strong>percent-encoding</strong> analysis:</p>
            <ol>
              <li><code>HasObfuscation</code> — Binary: does the URL contain any %XX encoding? (1/0)</li>
              <li><code>NoOfObfuscatedChar</code> — Count of percent-encoded sequences (%XX)</li>
              <li><code>ObfuscationRatio</code> — Obfuscated chars / URL length</li>
            </ol>
            <p><strong>Why they matter:</strong></p>
            <p>Percent-encoding is legitimate for special characters, but phishing URLs <strong>abuse it</strong> by encoding characters that don't require encoding (e.g., encoding normal letters as <code>%41</code> for 'A'). This is a deliberate obfuscation technique to evade pattern-matching filters and confuse users about the actual URL destination.</p>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: ML MODELS
  // ─────────────────────────────────────────────────────
  {
    cat: "models",
    catLabel: "ML Models",
    catIcon: "🤖",
    questions: [
      {
        q: "What machine learning models did you use?",
        difficulty: "basic",
        a: `<p>We used <strong>5 base classifiers</strong> plus a <strong>stacking meta-classifier</strong>:</p>
            <ol>
              <li><strong>Random Forest (RF)</strong> — 300 trees, max_depth=20</li>
              <li><strong>XGBoost (XGB)</strong> — 300 estimators, learning_rate=0.05</li>
              <li><strong>LightGBM (LGB)</strong> — 300 estimators, learning_rate=0.05</li>
              <li><strong>Multi-Layer Perceptron (MLP)</strong> — Architecture: 21→128→64→1</li>
              <li><strong>Logistic Regression (LR)</strong> — C=1.0, solver=lbfgs</li>
            </ol>
            <p><strong>Meta-classifier:</strong> Logistic Regression (regularized, C=1.0)</p>
            <p>These were chosen for <strong>algorithmic diversity</strong> — combining tree-based, gradient boosting, neural network, and linear models.</p>`
      },
      {
        q: "Why did you choose these specific models?",
        difficulty: "intermediate",
        a: `<p>Each model was chosen for a specific <strong>complementary strength</strong>:</p>
            <ul>
              <li><strong>Random Forest:</strong> Robust to overfitting, handles feature interactions well, provides feature importance rankings. Great baseline.</li>
              <li><strong>XGBoost:</strong> State-of-the-art gradient boosting with L1/L2 regularization. Excels at capturing fine-grained decision boundaries.</li>
              <li><strong>LightGBM:</strong> Fastest gradient boosting (GOSS + EFB algorithms). Near-identical accuracy to XGBoost at 3.3x speed.</li>
              <li><strong>MLP:</strong> Neural network captures smooth nonlinear manifolds in feature space. Different inductive bias from tree models.</li>
              <li><strong>Logistic Regression:</strong> Well-calibrated probability outputs. Acts as a sanity check — if LR achieves 99.66%, features are nearly linearly separable.</li>
            </ul>
            <p><strong>Key principle:</strong> Ensemble diversity. Tree-based models capture axis-aligned boundaries, MLP captures smooth curves, LR provides linear baseline. The meta-learner exploits this complementarity.</p>`
      },
      {
        q: "What are the hyperparameters for each model?",
        difficulty: "intermediate",
        a: `<p><strong>Random Forest:</strong></p>
            <ul>
              <li><code>n_estimators=300</code>, <code>max_depth=20</code>, <code>min_samples_leaf=5</code></li>
              <li>Feature subsampling: √p features per split</li>
            </ul>
            <p><strong>XGBoost:</strong></p>
            <ul>
              <li><code>n_estimators=300</code>, <code>learning_rate=0.05</code>, <code>max_depth=6</code></li>
              <li><code>subsample=0.8</code>, <code>colsample_bytree=0.8</code></li>
              <li>Regularization: L2 on leaf weights</li>
            </ul>
            <p><strong>LightGBM:</strong></p>
            <ul>
              <li><code>n_estimators=300</code>, <code>learning_rate=0.05</code>, <code>max_depth=6</code></li>
              <li><code>subsample=0.8</code>, <code>colsample_bytree=0.8</code></li>
            </ul>
            <p><strong>MLP:</strong></p>
            <ul>
              <li><code>hidden_layers=(128, 64)</code>, <code>activation=relu</code>, <code>solver=adam</code></li>
              <li><code>max_iter=300</code>, <code>early_stopping=True</code>, <code>validation_fraction=0.1</code></li>
            </ul>
            <p><strong>Logistic Regression:</strong></p>
            <ul>
              <li><code>C=1.0</code>, <code>solver=lbfgs</code>, <code>max_iter=1000</code></li>
            </ul>`
      },
      {
        q: "How does Random Forest work? Explain the algorithm.",
        difficulty: "intermediate",
        a: `<p><strong>Random Forest</strong> (Breiman, 2001) builds an ensemble of decision trees through:</p>
            <ol>
              <li><strong>Bootstrap sampling:</strong> Each tree trains on a random sample (with replacement) of the training data.</li>
              <li><strong>Random feature subsampling:</strong> At each split, only √p features (where p=21) are considered — approximately 4-5 features per split.</li>
              <li><strong>Gini impurity minimization:</strong> Each split minimizes G(S) = 1 - Σ(p_k²)</li>
              <li><strong>Averaging:</strong> Final prediction is the majority vote (or average probability) across all 300 trees.</li>
            </ol>
            <p><strong>Why it works for phishing:</strong></p>
            <ul>
              <li>Handles mixed feature types (binary + continuous) naturally</li>
              <li>Captures nonlinear feature interactions</li>
              <li>Resistant to overfitting due to bagging (reduces variance)</li>
              <li>Provides built-in feature importance via Gini decrease</li>
            </ul>`
      },
      {
        q: "What is XGBoost and how is it different from Random Forest?",
        difficulty: "intermediate",
        a: `<p><strong>XGBoost</strong> (Chen & Guestrin, 2016) is a gradient-boosted decision tree algorithm:</p>
            <ul>
              <li><strong>Random Forest = Bagging:</strong> Trees are trained independently in parallel → reduces variance</li>
              <li><strong>XGBoost = Boosting:</strong> Trees are trained sequentially, each correcting errors of the previous → reduces bias</li>
            </ul>
            <p><strong>Key XGBoost innovations:</strong></p>
            <ul>
              <li><strong>Regularized objective:</strong> L(t) = Σ loss + γT + ½λΣw²  — penalizes complex trees</li>
              <li><strong>Second-order gradients:</strong> Uses both gradient and Hessian for faster, more accurate optimization</li>
              <li><strong>Subsampling:</strong> Row and column subsampling reduces overfitting</li>
              <li><strong>Shrinkage:</strong> Low learning rate (0.05) with more trees prevents overfitting</li>
            </ul>
            <p>In our results, XGBoost achieves <strong>99.72% accuracy</strong> and the highest AUC-ROC among individual models (<strong>0.9991</strong>).</p>`
      },
      {
        q: "What is LightGBM and why is it faster than XGBoost?",
        difficulty: "advanced",
        a: `<p><strong>LightGBM</strong> (Ke et al., 2017) introduces two algorithmic innovations:</p>
            <p><strong>1. Gradient-based One-Side Sampling (GOSS):</strong></p>
            <ul>
              <li>Instead of using all samples for gradient estimation, GOSS keeps all instances with large gradients (top-a fraction) and randomly samples among small-gradient instances (b fraction).</li>
              <li>Rationale: Samples with large gradients contribute more to information gain — small-gradient samples are "well-learned."</li>
            </ul>
            <p><strong>2. Exclusive Feature Bundling (EFB):</strong></p>
            <ul>
              <li>Bundles mutually exclusive features (e.g., <code>HasObfuscation</code> and <code>ObfuscationRatio</code> are jointly zero for most legitimate URLs).</li>
              <li>Reduces the 21-feature space to fewer effective dimensions for the histogram algorithm.</li>
            </ul>
            <p><strong>Result:</strong> LightGBM trains in <strong>1.1 seconds</strong> vs XGBoost's <strong>3.6 seconds</strong> (3.3x faster) with nearly identical accuracy (99.72% for both).</p>`
      },
      {
        q: "What is the MLP architecture? Why a neural network alongside trees?",
        difficulty: "intermediate",
        a: `<p><strong>Architecture:</strong> 21 → 128 → 64 → 1 (feedforward neural network)</p>
            <div class="formula">h₁ = ReLU(W₁·x + b₁)    ∈ ℝ¹²⁸
h₂ = ReLU(W₂·h₁ + b₂)   ∈ ℝ⁶⁴
ŷ  = σ(w₃ᵀ·h₂ + b₃)     ∈ [0,1]</div>
            <p><strong>Training:</strong> Adam optimizer, early stopping (patience = 10 epochs), 10% validation split.</p>
            <p><strong>Why include it alongside trees?</strong></p>
            <ul>
              <li>Tree-based models (RF, XGB, LGB) capture <strong>axis-aligned decision boundaries</strong> (splits on single features).</li>
              <li>MLP captures <strong>smooth nonlinear manifolds</strong> — it can learn continuous, curved boundaries in feature space.</li>
              <li>This <strong>algorithmic diversity</strong> is essential for stacking — the meta-learner benefits most when base classifiers make <em>different</em> errors.</li>
            </ul>
            <p>In our results, MLP achieves the <strong>highest individual accuracy</strong> (99.79%), matching the stacking ensemble.</p>`
      },
      {
        q: "Why use Logistic Regression as both a base learner and meta-classifier?",
        difficulty: "advanced",
        a: `<p><strong>As a base learner:</strong></p>
            <ul>
              <li>LR provides a <strong>linear baseline</strong>. Its 99.66% accuracy proves the features are nearly linearly separable — a strong indicator of feature engineering quality.</li>
              <li>LR produces <strong>well-calibrated probabilities</strong> that serve as useful input to the meta-learner.</li>
            </ul>
            <p><strong>As the meta-classifier:</strong></p>
            <ul>
              <li>The meta-classifier receives only 5 probability inputs (one from each base classifier). In this low-dimensional space, a linear model is ideal — it avoids overfitting the meta-features.</li>
              <li>LR learns <strong>combination weights</strong> that reflect each base model's reliability: w = [w_RF, w_XGB, w_LGB, w_MLP, w_LR].</li>
              <li>Using a simple meta-classifier prevents the stacking ensemble from becoming overly complex, which would risk overfitting the cross-validation outputs.</li>
            </ul>
            <div class="tip">The base-LR and meta-LR are separate model instances with separate parameters. The base-LR operates on 21 URL features; the meta-LR operates on 5 probability outputs.</div>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: STACKING ENSEMBLE
  // ─────────────────────────────────────────────────────
  {
    cat: "stacking",
    catLabel: "Stacking Ensemble",
    catIcon: "🏗️",
    questions: [
      {
        q: "What is stacking? How does it work?",
        difficulty: "basic",
        a: `<p><strong>Stacking</strong> (Wolpert, 1992) is an ensemble technique that combines multiple diverse classifiers through a meta-learner:</p>
            <p><strong>Level 0 (Base classifiers):</strong> Each of the 5 models independently classifies the URL and outputs a probability (0 to 1).</p>
            <p><strong>Level 1 (Meta-classifier):</strong> The 5 probability outputs are concatenated into a vector z = [p_RF, p_XGB, p_LGB, p_MLP, p_LR] and fed into a Logistic Regression meta-classifier that makes the final decision:</p>
            <div class="formula">ŷ = σ(wᵀ·z + b)
where z = [p₁, p₂, p₃, p₄, p₅] and σ = sigmoid function</div>
            <p>The meta-learner learns which base classifiers to trust more, effectively weighting their contributions based on their reliability across different regions of the feature space.</p>`
      },
      {
        q: "Why stacking instead of simple voting or averaging?",
        difficulty: "intermediate",
        a: `<p><strong>Simple voting/averaging</strong> treats all classifiers equally. <strong>Stacking is superior</strong> because:</p>
            <ol>
              <li><strong>Learned weights:</strong> The meta-learner discovers that some models are more reliable than others and weights them accordingly.</li>
              <li><strong>Bias correction:</strong> If a base classifier systematically over-predicts or under-predicts, the meta-learner can correct for this bias.</li>
              <li><strong>Region-specific expertise:</strong> Different classifiers may be stronger in different parts of the feature space. Stacking can capture this (to some extent) through the learned combination.</li>
            </ol>
            <p>In our results, the stacking ensemble achieves <strong>higher AUC-ROC (0.9990)</strong> than any individual model, indicating superior probability calibration — even though the MLP matches its accuracy (99.79%).</p>`
      },
      {
        q: "How do you prevent data leakage in the stacking procedure itself?",
        difficulty: "advanced",
        a: `<p>This is a critical detail. If base classifiers train on the full training set and then generate predictions for the same training set to feed the meta-learner, the meta-learner sees <em>in-sample</em> predictions, which are overfitted.</p>
            <p><strong>Solution: 5-fold stratified cross-validation for Level-0 predictions.</strong></p>
            <ol>
              <li>Split training data into 5 folds.</li>
              <li>For each fold k: train each base classifier on the remaining 4 folds, then generate predictions on fold k.</li>
              <li>After all 5 rounds, each training sample has an <strong>out-of-fold</strong> prediction — the model never predicted on data it trained on.</li>
              <li>These out-of-fold predictions become the meta-learner's training features.</li>
            </ol>
            <p>In scikit-learn, this is handled by <code>StackingClassifier(cv=5)</code>.</p>
            <div class="highlight-box">This is the same principle as avoiding data leakage with features — the meta-learner must never see in-sample predictions.</div>`
      },
      {
        q: "What does the meta-classifier actually learn? What are its weights?",
        difficulty: "advanced",
        a: `<p>The meta-classifier is a Logistic Regression that learns <strong>combination weights</strong> for the 5 base classifier outputs:</p>
            <div class="formula">ŷ = σ(w_RF·p_RF + w_XGB·p_XGB + w_LGB·p_LGB + w_MLP·p_MLP + w_LR·p_LR + b)</div>
            <p>The weights are learned by minimizing regularized cross-entropy loss:</p>
            <div class="formula">L(w,b) = -1/N Σ[yᵢ log ŷᵢ + (1-yᵢ) log(1-ŷᵢ)] + λ/2 ||w||²</div>
            <p>where λ = 1/C = 1.0.</p>
            <p><strong>What the weights reveal:</strong></p>
            <ul>
              <li>Higher weights for XGBoost and LightGBM (gradient boosting models)</li>
              <li>MLP and LR outputs serve as "calibration anchors"</li>
              <li>On 98.2% of test samples, all 5 classifiers agree on the correct answer</li>
              <li>On the remaining 1.8% (849 URLs), the meta-learner resolves disagreements correctly in 88.1% of cases</li>
            </ul>`
      },
      {
        q: "What is the difference between bagging, boosting, and stacking?",
        difficulty: "intermediate",
        a: `<p><strong>Bagging (Bootstrap Aggregation):</strong></p>
            <ul>
              <li>Trains multiple models <strong>in parallel</strong> on bootstrap samples</li>
              <li>Combines via voting/averaging</li>
              <li>Reduces <strong>variance</strong></li>
              <li>Example: Random Forest</li>
            </ul>
            <p><strong>Boosting:</strong></p>
            <ul>
              <li>Trains models <strong>sequentially</strong>, each focusing on errors of the previous</li>
              <li>Reduces <strong>bias</strong></li>
              <li>Examples: XGBoost, LightGBM, AdaBoost</li>
            </ul>
            <p><strong>Stacking:</strong></p>
            <ul>
              <li>Trains <strong>heterogeneous</strong> models (different algorithms), then trains a <strong>meta-learner</strong> on their outputs</li>
              <li>Learns <strong>optimal combination weights</strong> — not just equal voting</li>
              <li>Can correct for systematic biases of individual models</li>
              <li>Example: PhishGuard (RF + XGB + LGB + MLP + LR → Meta-LR)</li>
            </ul>
            <p>PhishGuard uses <strong>all three:</strong> RF uses bagging internally, XGB/LGB use boosting internally, and all five are combined via stacking.</p>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: RESULTS & METRICS
  // ─────────────────────────────────────────────────────
  {
    cat: "results",
    catLabel: "Results & Metrics",
    catIcon: "📈",
    questions: [
      {
        q: "What are the final results of your model?",
        difficulty: "basic",
        a: `<p><strong>Stacking Ensemble (on 47,159 test URLs):</strong></p>
            <ul>
              <li><strong>Accuracy:</strong> 99.79%</li>
              <li><strong>AUC-ROC:</strong> 99.90%</li>
              <li><strong>F1-Score:</strong> 99.81%</li>
              <li><strong>Precision:</strong> 99.66%</li>
              <li><strong>Recall:</strong> 99.97%</li>
              <li><strong>False Positive Rate:</strong> 0.456%</li>
              <li><strong>False Negative Rate:</strong> 0.030% (only 8 missed phishing URLs out of 26,970)</li>
            </ul>`
      },
      {
        q: "What is the confusion matrix? Explain each cell.",
        difficulty: "basic",
        a: `<p><strong>Confusion matrix (test set, N = 47,159):</strong></p>
            <ul>
              <li><strong>True Negatives (TN) = 20,097:</strong> Legitimate URLs correctly identified as legitimate</li>
              <li><strong>False Positives (FP) = 92:</strong> Legitimate URLs incorrectly flagged as phishing</li>
              <li><strong>False Negatives (FN) = 8:</strong> Phishing URLs missed (classified as legitimate) — <strong>the worst error</strong></li>
              <li><strong>True Positives (TP) = 26,962:</strong> Phishing URLs correctly detected</li>
            </ul>
            <div class="highlight-box"><strong>Critical insight:</strong> Only <strong>8 phishing URLs</strong> were missed out of 26,970. This 0.030% FNR means near-complete phishing coverage — exactly what a security system needs.</div>`
      },
      {
        q: "What is AUC-ROC? Why is it important?",
        difficulty: "intermediate",
        a: `<p><strong>AUC-ROC</strong> (Area Under the Receiver Operating Characteristic curve) measures a classifier's ability to distinguish between classes <strong>across all possible classification thresholds</strong>.</p>
            <ul>
              <li>AUC = 1.0 → perfect discrimination</li>
              <li>AUC = 0.5 → random guessing</li>
              <li>Our AUC = <strong>0.9990</strong> → near-perfect</li>
            </ul>
            <p><strong>Why it matters more than accuracy:</strong></p>
            <ul>
              <li>Accuracy depends on a single threshold (0.5 by default). AUC evaluates performance across <strong>all</strong> thresholds.</li>
              <li>AUC is <strong>class-distribution invariant</strong> — it gives a fair evaluation even with imbalanced datasets.</li>
              <li>In security, you might want to lower the threshold to catch more phishing (higher recall) at the cost of more false positives. AUC tells you how well the model handles this tradeoff.</li>
            </ul>`
      },
      {
        q: "What is the F1-Score? Why report it alongside accuracy?",
        difficulty: "intermediate",
        a: `<p><strong>F1-Score</strong> is the harmonic mean of Precision and Recall:</p>
            <div class="formula">F1 = 2 × (Precision × Recall) / (Precision + Recall)
   = 2 × (0.9966 × 0.9997) / (0.9966 + 0.9997)
   = 0.9981</div>
            <p><strong>Why report it?</strong></p>
            <ul>
              <li><strong>Accuracy alone is misleading</strong> on imbalanced datasets. If 90% of samples are class A, a model that always predicts A achieves 90% accuracy but is useless.</li>
              <li>F1-Score balances precision (how many predicted phishing are actually phishing) and recall (how many actual phishing are detected).</li>
              <li>Our F1 = 0.9981 confirms that both precision and recall are extremely high — we're not sacrificing one for the other.</li>
            </ul>`
      },
      {
        q: "How does each individual model perform?",
        difficulty: "basic",
        a: `<p><strong>Individual model performance (test set):</strong></p>
            <table style="width:100%; border-collapse: collapse; margin: 0.8rem 0;">
              <tr style="border-bottom: 1px solid rgba(148,163,184,0.2);">
                <th style="text-align:left; padding:8px;">Model</th>
                <th style="text-align:right; padding:8px;">Accuracy</th>
                <th style="text-align:right; padding:8px;">AUC-ROC</th>
                <th style="text-align:right; padding:8px;">F1</th>
                <th style="text-align:right; padding:8px;">Time</th>
              </tr>
              <tr><td style="padding:6px 8px;">Random Forest</td><td style="text-align:right; padding:6px 8px;">99.66%</td><td style="text-align:right; padding:6px 8px;">0.9989</td><td style="text-align:right; padding:6px 8px;">0.9970</td><td style="text-align:right; padding:6px 8px;">10.0s</td></tr>
              <tr><td style="padding:6px 8px;">XGBoost</td><td style="text-align:right; padding:6px 8px;">99.72%</td><td style="text-align:right; padding:6px 8px;">0.9991</td><td style="text-align:right; padding:6px 8px;">0.9976</td><td style="text-align:right; padding:6px 8px;">3.6s</td></tr>
              <tr><td style="padding:6px 8px;">LightGBM</td><td style="text-align:right; padding:6px 8px;">99.72%</td><td style="text-align:right; padding:6px 8px;">0.9990</td><td style="text-align:right; padding:6px 8px;">0.9976</td><td style="text-align:right; padding:6px 8px;">1.1s</td></tr>
              <tr><td style="padding:6px 8px;">MLP</td><td style="text-align:right; padding:6px 8px;">99.79%</td><td style="text-align:right; padding:6px 8px;">0.9985</td><td style="text-align:right; padding:6px 8px;">0.9981</td><td style="text-align:right; padding:6px 8px;">37.4s</td></tr>
              <tr><td style="padding:6px 8px;">Logistic Regression</td><td style="text-align:right; padding:6px 8px;">99.66%</td><td style="text-align:right; padding:6px 8px;">0.9987</td><td style="text-align:right; padding:6px 8px;">0.9970</td><td style="text-align:right; padding:6px 8px;">0.5s</td></tr>
              <tr style="font-weight:bold; border-top: 2px solid rgba(99,102,241,0.3);"><td style="padding:6px 8px;">Stacking Ensemble</td><td style="text-align:right; padding:6px 8px;">99.79%</td><td style="text-align:right; padding:6px 8px;">0.9990</td><td style="text-align:right; padding:6px 8px;">0.9981</td><td style="text-align:right; padding:6px 8px;">—</td></tr>
            </table>`
      },
      {
        q: "Why is the False Negative Rate more important than False Positive Rate in phishing detection?",
        difficulty: "intermediate",
        a: `<p>In cybersecurity, the <strong>cost of errors is asymmetric</strong>:</p>
            <ul>
              <li><strong>False Positive (FP):</strong> A legitimate site is blocked → user is inconvenienced, but they can retry or whitelist it. <strong>Cost: Low.</strong></li>
              <li><strong>False Negative (FN):</strong> A phishing site is let through → user's credentials or money are stolen. <strong>Cost: Catastrophic.</strong></li>
            </ul>
            <p>Our system achieves:</p>
            <ul>
              <li>FPR = 0.456% (92 legitimate URLs incorrectly blocked out of 20,189)</li>
              <li>FNR = <strong>0.030%</strong> (only 8 phishing URLs missed out of 26,970)</li>
            </ul>
            <p>The extremely low FNR means <strong>near-complete phishing coverage</strong> — the security-critical metric is maximized.</p>`
      },
      {
        q: "How did you validate your results? What cross-validation did you use?",
        difficulty: "intermediate",
        a: `<p>We used <strong>multiple validation strategies</strong>:</p>
            <ol>
              <li><strong>5-fold Stratified Cross-Validation:</strong> During training, each base classifier was validated using 5-fold CV with <code>StratifiedKFold(n_splits=5, shuffle=True, random_state=42)</code>. Scoring: AUC-ROC.</li>
              <li><strong>Held-out Test Set:</strong> A completely separate 20% of data (47,159 samples) that was never seen during training or CV — the final evaluation was done entirely on this set.</li>
              <li><strong>Stacking CV:</strong> The stacking ensemble uses internal 5-fold CV to generate out-of-fold predictions for the meta-learner (prevents stacking-level leakage).</li>
            </ol>
            <p><strong>random_state=42</strong> was used throughout for full reproducibility.</p>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: PREPROCESSING
  // ─────────────────────────────────────────────────────
  {
    cat: "preprocessing",
    catLabel: "Preprocessing",
    catIcon: "⚙️",
    questions: [
      {
        q: "What preprocessing steps did you apply?",
        difficulty: "basic",
        a: `<p>Our preprocessing pipeline has 5 steps:</p>
            <ol>
              <li><strong>Column dropping:</strong> Remove non-feature columns: <code>FILENAME</code>, <code>URL</code>, <code>Domain</code>, <code>TLD</code>, <code>Title</code></li>
              <li><strong>Leakage feature removal:</strong> Drop 29 page-content features (URL-only mode)</li>
              <li><strong>Numeric coercion:</strong> Convert all values to numeric, non-parseable → NaN</li>
              <li><strong>Median imputation:</strong> Fill NaN with column-wise medians</li>
              <li><strong>Robust Scaling:</strong> Normalize features using the Robust Scaler</li>
            </ol>`
      },
      {
        q: "What is Robust Scaling? Why use it instead of StandardScaler or MinMaxScaler?",
        difficulty: "intermediate",
        a: `<p><strong>Robust Scaler</strong> normalizes features using the <strong>median and interquartile range (IQR)</strong>:</p>
            <div class="formula">x̃ⱼ = (xⱼ - Q₂) / (Q₃ - Q₁)

where Q₁ = 25th percentile, Q₂ = median, Q₃ = 75th percentile</div>
            <p><strong>Why not StandardScaler?</strong></p>
            <ul>
              <li>StandardScaler uses mean and standard deviation, which are <strong>sensitive to outliers</strong>.</li>
              <li>URL features have <strong>heavy-tailed distributions</strong>: most URLs are 30–80 characters, but phishing URLs can be 1000+ characters. Outliers would distort the mean/std.</li>
            </ul>
            <p><strong>Why not MinMaxScaler?</strong></p>
            <ul>
              <li>MinMaxScaler is even more sensitive to outliers — a single extreme value compresses the entire range.</li>
            </ul>
            <p><strong>Why Robust Scaler is best:</strong></p>
            <ul>
              <li>The median and IQR are <strong>robust statistics</strong> — unaffected by extreme outliers.</li>
              <li>This preserves the relative distribution of the majority of data points while keeping outliers informative rather than disruptive.</li>
            </ul>`
      },
      {
        q: "Why did you use median imputation instead of mean?",
        difficulty: "intermediate",
        a: `<p>For the same reason we use Robust Scaler: URL features have <strong>heavy-tailed distributions</strong>.</p>
            <p><strong>Example:</strong> If URLLength has values [25, 30, 35, 40, 2000], the mean is 426 and the median is 35. The median better represents the "typical" value.</p>
            <p>Median imputation ensures that missing values are filled with a representative central value that isn't distorted by outliers.</p>`
      },
      {
        q: "Did you apply any feature selection beyond removing leaky features?",
        difficulty: "intermediate",
        a: `<p>No formal feature selection (like RFE, LASSO, or mutual information) was applied beyond the leakage-based removal. Here's why:</p>
            <ol>
              <li><strong>Domain-knowledge curation:</strong> The 21 features were <em>deliberately designed</em> based on mathematical and information-theoretic principles. Each has a clear rationale.</li>
              <li><strong>All features contribute:</strong> The feature importance analysis shows all 21 features have non-zero importance — none are redundant.</li>
              <li><strong>Compact feature set:</strong> 21 features is already very lean compared to competing systems (30–50+ features). Further reduction risks losing signal.</li>
              <li><strong>Linear separability test:</strong> Logistic Regression achieving 99.66% proves the features are effective even in a linear model — no feature noise is degrading performance.</li>
            </ol>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: COMPARISON
  // ─────────────────────────────────────────────────────
  {
    cat: "comparison",
    catLabel: "Comparison",
    catIcon: "⚔️",
    questions: [
      {
        q: "How does your system compare to Google Safe Browsing / blacklists?",
        difficulty: "basic",
        a: `<p><strong>Key differences:</strong></p>
            <ul>
              <li><strong>Zero-day detection:</strong> PhishGuard: ✅ Yes (learned patterns) | Blacklist: ❌ No (requires reporting)</li>
              <li><strong>Detection latency:</strong> PhishGuard: <50ms per URL | Blacklist: 6–12 hours for new URLs</li>
              <li><strong>Coverage:</strong> PhishGuard: any URL | Blacklist: only known URLs in database</li>
              <li><strong>FPR:</strong> PhishGuard: 0.456% | Blacklist: ~0.01% (but only for known URLs)</li>
              <li><strong>FNR:</strong> PhishGuard: 0.030% | Blacklist: 30–65% (in first 2 hours!)</li>
              <li><strong>Privacy:</strong> PhishGuard: local computation | Blacklist: URL sent to server</li>
            </ul>
            <p>In practice, these are <strong>complementary</strong> — use blacklists for known threats and PhishGuard for unknown/zero-day URLs.</p>`
      },
      {
        q: "How does your accuracy compare to other published ML systems?",
        difficulty: "intermediate",
        a: `<p>PhishGuard achieves the <strong>highest reported accuracy</strong> among URL-only systems:</p>
            <ul>
              <li>Sahingoz et al. (2019): 97.98% — 7 NLP features, RF, 73K URLs</li>
              <li>Rao & Pais (2020): 96.28% — 30 URL features, Decision Tree, 50K URLs</li>
              <li>Jain & Gupta (2021): 99.09% — 48 URL+HTML features, Stacking, 73K URLs ⚠️ includes page content</li>
              <li>Bahnsen et al. (2018): 98.70% — Raw characters, LSTM, 2M URLs</li>
              <li>Wei et al. (2022): 99.12% — Tokenized URL, BERT, 500K URLs</li>
              <li><strong>PhishGuard (2026): 99.79%</strong> — 21 URL-only features, Stacking, 235K URLs ✅</li>
            </ul>
            <div class="highlight-box">We achieve <strong>the highest accuracy with the fewest features (21)</strong> among all systems, and without any page-content leakage.</div>`
      },
      {
        q: "Why not use deep learning (LSTM, BERT) like some other papers?",
        difficulty: "intermediate",
        a: `<p>We considered but deliberately chose against pure deep learning for three reasons:</p>
            <ol>
              <li><strong>Interpretability:</strong> Tree-based models provide feature importance rankings. Security analysts need to understand <em>why</em> a URL was flagged — "the model said so" isn't acceptable for incident response.</li>
              <li><strong>Computational cost:</strong> BERT has ~110M parameters. Our entire pipeline (5 models + meta-learner) trains in <3 minutes on a CPU. BERT requires GPU and hours.</li>
              <li><strong>Data efficiency:</strong> Deep learning requires much larger datasets to avoid overfitting. Our mathematical features provide strong inductive bias that compensates for dataset size.</li>
              <li><strong>Our MLP already captures nonlinearity:</strong> The 2-layer MLP in our ensemble captures nonlinear patterns. Adding BERT would increase complexity without proportional benefit.</li>
            </ol>
            <p>Despite this, we <strong>outperform</strong> both LSTM (98.70%) and BERT (99.12%) approaches.</p>`
      },
      {
        q: "What advantages does your system have over heuristic/rule-based systems?",
        difficulty: "basic",
        a: `<p>Our system is <strong>2.5–10.8 percentage points</strong> more accurate than heuristic systems:</p>
            <ul>
              <li>Rule-based systems [8]: 89–93% accuracy</li>
              <li>CANTINA [16]: 92.0%</li>
              <li>Garera et al. [15]: 97.3%</li>
              <li><strong>PhishGuard: 99.79%</strong></li>
            </ul>
            <p><strong>Why we're better:</strong></p>
            <ul>
              <li><strong>Learned boundaries:</strong> Our decision boundaries adapt to data, not hard-coded thresholds like "flag URLs longer than 75 chars."</li>
              <li><strong>Continuous features:</strong> Entropy, ratios, and probabilities provide finer-grained discrimination than binary heuristic indicators.</li>
              <li><strong>Automatic adaptation:</strong> Retrain on new data to handle evolving attack patterns — no manual rule updates needed.</li>
            </ul>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: DEPLOYMENT
  // ─────────────────────────────────────────────────────
  {
    cat: "deployment",
    catLabel: "Deployment",
    catIcon: "🚀",
    questions: [
      {
        q: "How fast is inference? Can it run in real-time?",
        difficulty: "basic",
        a: `<p><strong>Total inference time: &lt;50 milliseconds per URL</strong>, broken down as:</p>
            <ul>
              <li>Feature extraction (21 features): <1ms</li>
              <li>Robust Scaling normalization: <0.1ms</li>
              <li>5 base classifier predictions: <10ms combined</li>
              <li>Meta-classifier fusion: <0.1ms</li>
            </ul>
            <p><strong>Throughput:</strong> ~1,200 URLs per minute on a single CPU thread.</p>
            <p>This is fast enough for real-time use in browsers, email gateways, and network firewalls.</p>`
      },
      {
        q: "How did you deploy the web application?",
        difficulty: "intermediate",
        a: `<p>The deployment architecture has <strong>4 layers</strong>:</p>
            <ol>
              <li><strong>Frontend:</strong> Next.js 14 + TypeScript + Tailwind CSS on <strong>Vercel</strong></li>
              <li><strong>Threat Intelligence Layer:</strong> API calls to VirusTotal, Google Safe Browsing, IPQualityScore</li>
              <li><strong>Math Feature Extraction:</strong> TypeScript port of the Python feature extractor (runs in Vercel Edge Functions)</li>
              <li><strong>ML Inference:</strong> ONNX model hosted on <strong>Hugging Face Spaces</strong> — the Python-trained stacking ensemble exported to ONNX format for cross-platform inference</li>
            </ol>
            <p>All layers feed into a <strong>Weighted Fusion Engine</strong> that combines their scores with dynamic weights and hard overrides.</p>`
      },
      {
        q: "What is ONNX and why did you export the model to it?",
        difficulty: "intermediate",
        a: `<p><strong>ONNX</strong> (Open Neural Network Exchange) is an open format for representing ML models that enables <strong>cross-platform inference</strong>.</p>
            <p><strong>Why we use it:</strong></p>
            <ul>
              <li>The model is <strong>trained in Python</strong> (scikit-learn, XGBoost, LightGBM)</li>
              <li>But inference runs in a <strong>JavaScript/TypeScript</strong> web app (Next.js on Vercel)</li>
              <li>ONNX bridges this gap — we export the trained model to ONNX format using <code>skl2onnx</code>, then load it in the Hugging Face Space with <code>onnxruntime</code></li>
            </ul>
            <p>This avoids maintaining separate Python and JavaScript model implementations.</p>`
      },
      {
        q: "How long does training take?",
        difficulty: "basic",
        a: `<p><strong>Individual model training times:</strong></p>
            <ul>
              <li>Logistic Regression: <strong>0.5 seconds</strong></li>
              <li>LightGBM: <strong>1.1 seconds</strong></li>
              <li>XGBoost: <strong>3.6 seconds</strong></li>
              <li>Random Forest: <strong>10.0 seconds</strong></li>
              <li>MLP: <strong>37.4 seconds</strong></li>
            </ul>
            <p><strong>Total pipeline</strong> (all base models + stacking ensemble + CV): <strong>Under 3 minutes</strong> on a consumer-grade CPU.</p>
            <p>This means the model can be rapidly retrained when new phishing patterns emerge.</p>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: LIMITATIONS & FUTURE
  // ─────────────────────────────────────────────────────
  {
    cat: "limitations",
    catLabel: "Limitations & Future Work",
    catIcon: "⚠️",
    questions: [
      {
        q: "What are the limitations of your system?",
        difficulty: "intermediate",
        a: `<p>We acknowledge several limitations:</p>
            <ol>
              <li><strong>IsHTTPS dependency:</strong> Our top feature (36.29% importance) exploits the historical correlation between HTTP and phishing. As more phishing sites adopt HTTPS (via Let's Encrypt), this feature's discriminative power will decrease over time.</li>
              <li><strong>URL shorteners:</strong> Shortened URLs (bit.ly, etc.) compress all features into a short, uniform format, potentially reducing discrimination. Most security deployments expand shortened URLs before analysis.</li>
              <li><strong>Adversarial evasion:</strong> A sophisticated attacker aware of our features could craft URLs that mimic legitimate statistical patterns.</li>
              <li><strong>Single dataset evaluation:</strong> All results are on the PhiUSIIL dataset. Cross-dataset generalization hasn't been tested.</li>
              <li><strong>Static model:</strong> The model doesn't adapt to evolving phishing patterns without explicit retraining.</li>
            </ol>`
      },
      {
        q: "What future work do you suggest?",
        difficulty: "basic",
        a: `<p>Five key directions:</p>
            <ol>
              <li><strong>Temporal Concept Drift:</strong> Analyze how phishing URL characteristics evolve over time and develop online learning strategies for continuous adaptation.</li>
              <li><strong>Adversarial Robustness:</strong> Systematically test with gradient-based evasion attacks and generative adversarial approaches for phishing URL generation.</li>
              <li><strong>Cross-Dataset Validation:</strong> Evaluate on ISCX-URL-2016, Kaggle phishing datasets, and OpenPhish to verify generalizability.</li>
              <li><strong>Feature Expansion:</strong> Add WHOIS features (domain age, registrar), passive DNS intelligence, and certificate transparency log analysis.</li>
              <li><strong>Federated Learning:</strong> Train across organizational boundaries without sharing raw URLs — each participant contributes features locally.</li>
            </ol>`
      },
      {
        q: "How could an attacker evade your system?",
        difficulty: "advanced",
        a: `<p>We analyzed three evasion strategies:</p>
            <ol>
              <li><strong>Feature mimicry:</strong> Craft phishing URLs that maintain low entropy, high letter ratio, and HTTPS. However, the constraint of including deceptive elements (redirect chains, tracking parameters) while maintaining these properties is non-trivial.</li>
              <li><strong>TLD manipulation:</strong> Register phishing domains under .com/.org (high TLDLegitimateProb). But these TLDs have stricter abuse policies and higher costs.</li>
              <li><strong>URL shortening:</strong> Use bit.ly etc. to compress features. But shortened URLs themselves have distinctive patterns (low letter ratio, unusual TLD), and security systems typically expand them.</li>
            </ol>
            <p><strong>Key defense:</strong> The 21-feature combination is harder to simultaneously fool than any single feature. An attacker must manipulate URL length, entropy, character ratios, TLD, subdomains, and protocol all at once — significantly constraining their attack options.</p>`
      },
      {
        q: "Can your model handle concept drift? What happens when phishing patterns change?",
        difficulty: "advanced",
        a: `<p><strong>Current approach:</strong> The model is static — it doesn't automatically adapt. Periodic retraining with new data is required.</p>
            <p><strong>Why this is manageable:</strong></p>
            <ul>
              <li>Full pipeline retrains in <strong>under 3 minutes</strong>, so retraining can be done daily or weekly.</li>
              <li>Mathematical features (entropy, ratios, edit distance) capture <strong>fundamental</strong> properties of URLs that change slowly, unlike surface-level heuristics.</li>
            </ul>
            <p><strong>Future solutions:</strong></p>
            <ul>
              <li><strong>Online learning:</strong> XGBoost and LightGBM support incremental updates — add new training samples without full retraining.</li>
              <li><strong>Monitoring pipeline:</strong> Track feature distributions in production to detect drift (e.g., if the IsHTTPS ratio shifts).</li>
              <li><strong>Active learning:</strong> Flag uncertain predictions (probabilities near 0.5) for human review and labeling.</li>
            </ul>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: TECHNICAL DEEP-DIVE
  // ─────────────────────────────────────────────────────
  {
    cat: "technical-deep",
    catLabel: "Technical Deep-Dive",
    catIcon: "🔬",
    questions: [
      {
        q: "Why random_state=42? Does it affect results?",
        difficulty: "intermediate",
        a: `<p><code>random_state=42</code> is a fixed seed for the pseudorandom number generator. It ensures <strong>reproducibility</strong> — running the same code on the same data produces identical results.</p>
            <p><strong>Does the specific value matter?</strong> No. 42 is a convention (from <em>The Hitchhiker's Guide to the Galaxy</em>). Any fixed integer gives the same reproducibility benefit.</p>
            <p><strong>Does it affect performance?</strong> Marginally. Different seeds produce slightly different train/test splits and bootstrap samples. Our 5-fold CV with standard deviations <0.001 confirms that results are stable across random variations.</p>`
      },
      {
        q: "Why 80/20 split? Why not 70/30 or 90/10?",
        difficulty: "intermediate",
        a: `<p><strong>80/20 is the standard</strong> for datasets of this size (235K samples):</p>
            <ul>
              <li><strong>Training set (188,636 samples):</strong> Large enough for all models (including the MLP with ~10K parameters) to learn the full distribution without underfitting.</li>
              <li><strong>Test set (47,159 samples):</strong> Large enough for statistically significant evaluation — even rare events (like our 8 false negatives) are meaningfully measured.</li>
            </ul>
            <p><strong>Why not 70/30?</strong> We'd lose 23K training samples with minimal evaluation benefit — 47K test samples is already more than sufficient.</p>
            <p><strong>Why not 90/10?</strong> A 23K test set would still be adequate, but 80/20 is the more conservative choice for reporting robust metrics.</p>`
      },
      {
        q: "What is the Gini impurity? How is feature importance calculated?",
        difficulty: "advanced",
        a: `<p><strong>Gini impurity</strong> measures the probability of misclassifying a random sample at a node:</p>
            <div class="formula">G(S) = 1 - Σ p_k²    for each class k

For binary classification:
G(S) = 1 - p₀² - p₁² = 2·p₀·p₁</div>
            <p>G ranges from 0 (pure node, all samples same class) to 0.5 (maximally impure, 50/50 split).</p>
            <p><strong>Feature importance</strong> is computed as the <strong>mean decrease in Gini impurity</strong> across all 300 trees:</p>
            <ol>
              <li>For each tree, at each split, record the reduction in Gini weighted by the number of samples reaching that node.</li>
              <li>Sum these reductions for each feature across all nodes in all trees.</li>
              <li>Normalize so all importances sum to 1.0.</li>
            </ol>
            <p>This gives the ranking: IsHTTPS (0.3629), NoOfOtherSpecialCharsInURL (0.1208), etc.</p>`
      },
      {
        q: "What is the mathematical formulation of the stacking ensemble's final prediction?",
        difficulty: "advanced",
        a: `<p>The complete prediction pipeline:</p>
            <div class="formula">Input: URL string u

Step 1: Extract features → x = [x₁, x₂, ..., x₂₁]ᵀ ∈ ℝ²¹
Step 2: Robust Scale → x̃ⱼ = (xⱼ - Q₂(xⱼ)) / (Q₃(xⱼ) - Q₁(xⱼ))
Step 3: Base predictions → z = [p_RF(x̃), p_XGB(x̃), p_LGB(x̃), p_MLP(x̃), p_LR(x̃)]ᵀ
Step 4: Meta-classifier → ŷ = σ(wᵀz + b) = 1 / (1 + exp(-(wᵀz + b)))

Output: ŷ > 0.5 → Phishing (1), else Legitimate (0)</div>
            <p>The meta-classifier weights w ∈ ℝ⁵ are learned by minimizing:</p>
            <div class="formula">L(w,b) = -1/N Σ[yᵢ log ŷᵢ + (1-yᵢ) log(1-ŷᵢ)] + (1/2C)||w||²</div>
            <p>with C=1.0 (regularization strength).</p>`
      },
      {
        q: "What software libraries and versions did you use?",
        difficulty: "basic",
        a: `<p><strong>Python ML Pipeline:</strong></p>
            <ul>
              <li><code>scikit-learn</code> — RandomForest, LogisticRegression, MLPClassifier, StackingClassifier, RobustScaler, metrics</li>
              <li><code>xgboost</code> — XGBClassifier</li>
              <li><code>lightgbm</code> — LGBMClassifier</li>
              <li><code>pandas</code> — Data loading and manipulation</li>
              <li><code>numpy</code> — Numerical operations</li>
              <li><code>joblib</code> — Model serialization (.joblib files)</li>
              <li><code>skl2onnx</code> — ONNX model export</li>
            </ul>
            <p><strong>Web Application:</strong></p>
            <ul>
              <li><code>Next.js 14</code> — React framework with TypeScript</li>
              <li><code>Tailwind CSS</code> — Styling</li>
              <li><code>Framer Motion</code> — Animations</li>
              <li><code>onnxruntime</code> — ML inference on Hugging Face Space</li>
            </ul>`
      },
      {
        q: "How does the URL Structural Decomposition work (RFC 3986)?",
        difficulty: "advanced",
        a: `<p>Every URL is decomposed according to <strong>RFC 3986</strong> into:</p>
            <div class="formula">URL = scheme :// authority / path ? query # fragment

Authority = userinfo @ host : port

Host = subdomain₁.subdomain₂.....domain.TLD</div>
            <p>From this decomposition we extract:</p>
            <ul>
              <li><strong>URLLength:</strong> Total character count of the full URL</li>
              <li><strong>DomainLength:</strong> Character count of the hostname (h)</li>
              <li><strong>TLDLength:</strong> Character count of the top-level domain</li>
              <li><strong>NoOfSubDomain:</strong> σ(h) = k-2 where k is the number of dot-separated labels</li>
              <li><strong>IsDomainIP:</strong> Whether h matches an IPv4 pattern</li>
              <li><strong>IsHTTPS:</strong> Whether scheme = "https"</li>
            </ul>
            <p>This structural analysis provides the "skeleton" features that other features (entropy, ratios) are computed over.</p>`
      },
      {
        q: "What feature interactions did you discover?",
        difficulty: "advanced",
        a: `<p>The stacking ensemble implicitly captures feature interactions. Our analysis reveals three critical two-way interactions:</p>
            <ol>
              <li><strong>IsHTTPS × DegitRatioInURL:</strong> HTTP URLs with elevated digit ratios are <strong>47x more likely</strong> to be phishing than HTTPS URLs with low digit ratios. This suggests multiplicative risk compounding.</li>
              <li><strong>NoOfSubDomain × URLLength:</strong> URLs with ≥3 subdomains AND length >100 have a phishing probability of <strong>0.96</strong>, vs 0.12 for URLs with 0 subdomains and length <50.</li>
              <li><strong>TLDLegitimateProb × NoOfOtherSpecialCharsInURL:</strong> Low TLD probability combined with high special character count produces a combined signal <strong>8.3% stronger</strong> than either feature alone (additive model comparison).</li>
            </ol>`
      },
      {
        q: "How do you handle the n-gram model in the TypeScript web app?",
        difficulty: "advanced",
        a: `<p>The n-gram model is <strong>pre-computed in Python</strong> and <strong>exported to TypeScript</strong>:</p>
            <ol>
              <li>Python builds the trigram model from a 300-word corpus</li>
              <li><code>export_ngram_ts.py</code> generates a TypeScript file (<code>src/lib/ngramModel.ts</code>) containing the trigram probability table as a static dictionary</li>
              <li>At inference time in the web app, domain perplexity is computed using this pre-built lookup table — no model loading or Python required</li>
            </ol>
            <p>The generated TS file contains:</p>
            <ul>
              <li><code>NGRAM_MODEL</code> — Record&lt;string, number&gt; with ~500 trigrams and their probabilities</li>
              <li><code>NGRAM_TOTAL</code> — Total count for normalization</li>
              <li><code>NGRAM_VOCAB_SIZE</code> — Vocabulary size (26) for Laplace smoothing</li>
            </ul>`
      },
      {
        q: "What is the loss function used for training?",
        difficulty: "intermediate",
        a: `<p>All models ultimately optimize <strong>binary cross-entropy (log loss)</strong>:</p>
            <div class="formula">L = -1/N Σ[yᵢ · log(ŷᵢ) + (1-yᵢ) · log(1-ŷᵢ)]</div>
            <p>Specific variations per model:</p>
            <ul>
              <li><strong>Random Forest:</strong> Splits are chosen by Gini impurity minimization, but the overall objective aligns with minimizing classification error</li>
              <li><strong>XGBoost:</strong> Logistic loss + regularization: L(t) = Σ logloss + γT + ½λΣw²</li>
              <li><strong>LightGBM:</strong> Same as XGBoost (binary cross-entropy with tree regularization)</li>
              <li><strong>MLP:</strong> Binary cross-entropy optimized via Adam (adaptive learning rate SGD)</li>
              <li><strong>Logistic Regression:</strong> L2-regularized cross-entropy: L + (1/2C)||w||²</li>
            </ul>`
      },
      {
        q: "What is the Adam optimizer used in the MLP? Why Adam specifically?",
        difficulty: "advanced",
        a: `<p><strong>Adam</strong> (Kingma & Ba, 2015) = Adaptive Moment Estimation. It combines the advantages of two other optimizers:</p>
            <ul>
              <li><strong>Momentum:</strong> Uses exponential moving average of gradients (first moment) for smooth updates</li>
              <li><strong>RMSProp:</strong> Uses exponential moving average of squared gradients (second moment) for per-parameter learning rate adaptation</li>
            </ul>
            <div class="formula">m_t = β₁·m_{t-1} + (1-β₁)·g_t          (first moment)
v_t = β₂·v_{t-1} + (1-β₂)·g_t²         (second moment)
m̂_t = m_t / (1-β₁ᵗ)                     (bias correction)
v̂_t = v_t / (1-β₂ᵗ)                     (bias correction)
θ_t = θ_{t-1} - η · m̂_t / (√v̂_t + ε)   (update)</div>
            <p><strong>Why Adam:</strong> It's the default choice for MLPs because it converges faster than SGD, handles sparse gradients well, and requires minimal hyperparameter tuning. scikit-learn's MLPClassifier uses it as the default solver.</p>`
      }
    ]
  },

  // ─────────────────────────────────────────────────────
  // CATEGORY: TRICKY & GOTCHA QUESTIONS
  // ─────────────────────────────────────────────────────
  {
    cat: "tricky",
    catLabel: "Tricky & Gotcha Questions",
    catIcon: "🧠",
    questions: [
      {
        q: "Why did you use labeled data instead of unsupervised learning?",
        difficulty: "intermediate",
        a: `<p>We chose <strong>supervised learning</strong> (using labeled data) because phishing detection is fundamentally a binary classification problem where the ground truth (phishing vs. legitimate) is known and can be verified.</p>
            <ul>
              <li><strong>Unsupervised learning</strong> (like clustering) is good for discovering unknown patterns or anomalies, but it doesn't explicitly optimize for the specific decision boundary between phishing and legitimate URLs.</li>
              <li>With a large, high-quality labeled dataset (PhiUSIIL), supervised models can directly learn the complex mappings from features to the target variable, yielding much higher accuracy (99.79%) than unsupervised anomaly detection would achieve.</li>
            </ul>`
      },
      {
        q: "Why did you select exactly 21 features? Why not more to get higher accuracy?",
        difficulty: "intermediate",
        a: `<p>We selected exactly 21 features based on a strict <strong>URL-only extractability</strong> criterion and <strong>mathematical grounding</strong>, specifically removing 29 leaky page-content features.</p>
            <ul>
              <li><strong>More features ≠ higher accuracy:</strong> Adding features that require page crawling (like HTML tags) would artificially inflate training accuracy due to <strong>data leakage</strong>, but would make the model too slow (&lt;50ms requirement) and impractical for real-time deployment.</li>
              <li><strong>Curse of dimensionality:</strong> Adding irrelevant or noisy features can actually degrade model performance and increase overfitting.</li>
              <li>Our 21 carefully engineered mathematical features capture the core signals of phishing intent, allowing us to achieve 99.79% accuracy without relying on slow or leaky data.</li>
            </ul>`
      },
      {
        q: "If your model is so accurate, why do phishing attacks still succeed in the real world?",
        difficulty: "advanced",
        a: `<p>This is a classic gotcha question! The gap between a high-accuracy model and real-world success comes down to <strong>deployment and human factors</strong>:</p>
            <ol>
              <li><strong>Zero-day delivery:</strong> Attackers constantly register new domains and distribute them rapidly via SMS or WhatsApp, often reaching users before they are scanned by any central security system.</li>
              <li><strong>User behavior:</strong> Users often ignore browser warnings or click links on devices (like mobile phones) where URL scanning extensions might not be installed.</li>
              <li><strong>Adversarial adaptation:</strong> Attackers continuously evolve their obfuscation techniques (e.g., using QR codes, CAPTCHAs, or compromised legitimate sites) to evade detection.</li>
            </ol>
            <p>Our model solves the <em>detection</em> part effectively (with &lt;50ms latency), but completely stopping phishing requires integrating such models seamlessly into all communication channels.</p>`
      },
      {
        q: "Can't an attacker just use a legitimate domain to host their phishing page?",
        difficulty: "advanced",
        a: `<p>Yes, this is called a <strong>compromised legitimate site</strong> attack. It is one of the limitations of a purely URL-based model.</p>
            <ul>
              <li>If an attacker hacks <code>legitimate-university.edu</code> and hosts a phishing page at <code>legitimate-university.edu/login</code>, the URL features (like TLD, entropy, length) will look completely legitimate.</li>
              <li><strong>How we mitigate this:</strong> While our ML model might flag the base URL as legitimate, our deployment architecture includes a <strong>Threat Intelligence Layer</strong> (VirusTotal, Google Safe Browsing) which can catch specific known malicious paths.</li>
              <li>To detect unknown compromised sites solely via ML, you <em>must</em> use page-content features, which introduces the latency issues we deliberately avoided. It's a fundamental trade-off in security engineering.</li>
            </ul>`
      },
      {
        q: "You said your model is for zero-day attacks. How can a model trained on past data detect zero-day attacks?",
        difficulty: "intermediate",
        a: `<p><strong>Zero-day</strong> in this context means a URL that has <strong>never been seen before</strong> and is not on any blacklist.</p>
            <ul>
              <li>Blacklists rely on exact string matching. If a URL is new, a blacklist fails 100% of the time.</li>
              <li>Our model learns <strong>underlying statistical patterns and characteristics</strong> (like character entropy, typosquatting edit distance, and obfuscation ratios).</li>
              <li>Even if the specific URL is completely new, the <em>techniques</em> the attacker uses to craft the deceptive URL (e.g., excessive subdomains, random token generation, typosquatting a brand) will trigger the mathematical features our model has learned. This generalization is what allows ML to catch zero-day phishing URLs.</li>
            </ul>`
      }
    ]
  }
];
