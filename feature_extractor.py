"""
PhishGuard Feature Extractor — Layer 3: Mathematical & URL-Structural Models
Extracts ONLY features that are always reliably computable from the URL itself.

Mathematical Models Included:
  1. Typosquatting Score   — Damerau-Levenshtein vs Alexa top-1k
  2. Character N-gram LM   — Perplexity on legitimate domain character sequences
  3. Homoglyph Detection   — Unicode confusable characters (рaypal ≠ paypal)
  4. Shannon Entropy        — URL/domain/path entropy (DGA domain detection)
  5. Brand Impersonation   — Keyword-in-domain brand scoring
  6. URL Structural        — Standard lexical features (always available)
"""

import re
import os
import math
import socket
import logging
import itertools
from collections import Counter, defaultdict
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── Load Alexa Top-1k for Typosquatting Detection ───────────────────────────

def _load_alexa(path: str = None) -> List[str]:
    """Load Alexa top domains list."""
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alexa_top1k.txt")
    try:
        with open(path) as f:
            domains = [line.strip().lower() for line in f if line.strip()]
        # Extract just the SLD (e.g., "google" from "google.com")
        slds = []
        for d in domains:
            parts = d.split(".")
            if len(parts) >= 2:
                slds.append(parts[-2])  # second-level domain
        return list(set(slds))
    except FileNotFoundError:
        logger.warning("alexa_top1k.txt not found — typosquatting detection disabled")
        return []

ALEXA_SLDS = _load_alexa()

# ─── Known Brands ─────────────────────────────────────────────────────────────

KNOWN_BRANDS = [
    'google', 'facebook', 'amazon', 'microsoft', 'apple', 'netflix', 'paypal',
    'instagram', 'twitter', 'linkedin', 'yahoo', 'ebay', 'walmart', 'target',
    'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'americanexpress',
    'flipkart', 'myntra', 'snapdeal', 'paytm', 'phonepe', 'googlepay',
    'hdfc', 'icici', 'sbi', 'axis', 'kotak', 'github', 'gitlab',
    'stackoverflow', 'reddit', 'youtube', 'gmail', 'dropbox', 'spotify',
    'adobe', 'salesforce', 'oracle', 'whatsapp', 'telegram', 'discord',
    'slack', 'zoom', 'teams', 'openai', 'anthropic', 'claude', 'notion',
    'figma', 'canva', 'trello', 'asana', 'stripe', 'shopify', 'coinbase',
    'binance', 'revolut', 'nubank', 'wise', 'venmo', 'cashapp', 'zelle'
]

SHORTENING_SERVICES = [
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bl.ink', 'short.link', 'rb.gy', 'cutt.ly'
]

SUSPICIOUS_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click',
    'link', 'loan', 'racing', 'cricket', 'win', 'party', 'download',
    'stream', 'gdn', 'buzz', 'surf', 'zip', 'mov'
]

PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'log-in', 'account', 'verify', 'verification',
    'update', 'secure', 'banking', 'confirm', 'password', 'credential',
    'suspend', 'restrict', 'alert', 'unusual', 'expire', 'renew', 'unlock',
    'authenticate', 'wallet', 'submit', 'validation', 'authorize', 'reactivate'
]

# ─── Unicode Homoglyph Map ────────────────────────────────────────────────────
# Maps visually similar Unicode characters to their ASCII equivalents
HOMOGLYPH_MAP = {
    # Cyrillic → Latin
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
    'ν': 'v', 'х': 'x', 'і': 'i', 'ѕ': 's',
    # Greek → Latin
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'γ': 'y', 'τ': 't',
    # Lookalike digits/symbols
    '0': 'o', '1': 'l', '5': 's', '6': 'b', '8': 'b',
    # Fullwidth
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｇ': 'g', 'ｌ': 'l', 'ｍ': 'm',
    'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't',
}


# ═══════════════════════════════════════════════════════════════════════════════
# MATHEMATICAL MODEL 1: Damerau-Levenshtein Typosquatting Score
# ═══════════════════════════════════════════════════════════════════════════════

def _damerau_levenshtein(s1: str, s2: str) -> int:
    """
    Damerau-Levenshtein distance — allows transpositions in addition to
    insertions, deletions, substitutions. Better than plain Levenshtein
    for detecting human typos (e.g., 'gogle' → 'google').
    """
    len_s1, len_s2 = len(s1), len(s2)
    if abs(len_s1 - len_s2) > 3:  # Fast exit for very different lengths
        return max(len_s1, len_s2)

    d = [[0] * (len_s2 + 1) for _ in range(len_s1 + 1)]
    for i in range(len_s1 + 1):
        d[i][0] = i
    for j in range(len_s2 + 1):
        d[0][j] = j

    for i in range(1, len_s1 + 1):
        for j in range(1, len_s2 + 1):
            cost = 0 if s1[i-1] == s2[j-1] else 1
            d[i][j] = min(
                d[i-1][j] + 1,      # deletion
                d[i][j-1] + 1,      # insertion
                d[i-1][j-1] + cost  # substitution
            )
            if i > 1 and j > 1 and s1[i-1] == s2[j-2] and s1[i-2] == s2[j-1]:
                d[i][j] = min(d[i][j], d[i-2][j-2] + cost)  # transposition
    return d[len_s1][len_s2]


def typosquatting_score(domain: str, alexa_slds: List[str] = None) -> Tuple[float, str, int]:
    """
    Compute typosquatting score for a domain.

    Returns:
        score (0.0=safe, 1.0=definite squatting),
        closest_brand (the brand it's closest to),
        edit_distance
    """
    if alexa_slds is None:
        alexa_slds = ALEXA_SLDS

    if not alexa_slds or not domain:
        return 0.0, "", 99

    domain_clean = domain.lower().strip()

    # If domain IS a known brand exactly → safe (not squatting)
    if domain_clean in alexa_slds:
        return 0.0, domain_clean, 0

    # Find minimum DL distance to any legitimate brand
    min_dist = 99
    closest = ""
    for brand in alexa_slds:
        if abs(len(domain_clean) - len(brand)) > 4:
            continue  # Skip obviously different lengths
        dist = _damerau_levenshtein(domain_clean, brand)
        if dist < min_dist:
            min_dist = dist
            closest = brand

    # Score: dist=0 → exact match (safe), dist=1 → one char off (critical squatting)
    # dist=2 → likely squatting, dist≥3 → probably unrelated
    if min_dist == 0:
        score = 0.0
    elif min_dist == 1:
        score = 0.95  # Very likely typosquatting
    elif min_dist == 2:
        score = 0.60  # Possibly typosquatting
    elif min_dist == 3 and len(domain_clean) <= 8:
        score = 0.25  # Short domain with 3 changes — borderline
    else:
        score = 0.0

    return round(score, 4), closest, min_dist


# ═══════════════════════════════════════════════════════════════════════════════
# MATHEMATICAL MODEL 2: Character N-gram Language Model (Gibberish Detector)
# ═══════════════════════════════════════════════════════════════════════════════

class NgramLanguageModel:
    """
    Character-level n-gram language model trained on legitimate domain names.
    High perplexity = gibberish / DGA-generated domain.
    Low perplexity = natural-looking domain (like 'google', 'amazon').
    """

    def __init__(self, n: int = 3):
        self.n = n
        self.ngram_counts = defaultdict(Counter)
        self.context_totals = defaultdict(int)
        self.vocab = set()
        self._trained = False

    def train(self, domains: List[str]):
        """Train on list of legitimate domain SLDs."""
        self.ngram_counts.clear()
        self.context_totals.clear()
        self.vocab.clear()

        for domain in domains:
            domain = domain.lower().strip()
            padded = '^' * (self.n - 1) + domain + '$'
            for i in range(len(padded) - self.n + 1):
                ngram = padded[i:i + self.n]
                context = ngram[:-1]
                char = ngram[-1]
                self.ngram_counts[context][char] += 1
                self.context_totals[context] += 1
                self.vocab.add(char)

        self._trained = True

    def log_probability(self, domain: str) -> float:
        """
        Compute log-probability of domain under the LM.
        More negative = less likely to be legitimate.
        """
        if not self._trained:
            return -10.0

        domain = domain.lower().strip()
        padded = '^' * (self.n - 1) + domain + '$'
        log_prob = 0.0
        count = 0

        for i in range(len(padded) - self.n + 1):
            ngram = padded[i:i + self.n]
            context = ngram[:-1]
            char = ngram[-1]

            total = self.context_totals.get(context, 0)
            char_count = self.ngram_counts.get(context, {}).get(char, 0)

            # Laplace smoothing: (count + 1) / (total + vocab_size)
            prob = (char_count + 1) / (total + len(self.vocab) + 1)
            log_prob += math.log(prob)
            count += 1

        return log_prob / max(count, 1)  # Normalized per character

    def perplexity(self, domain: str) -> float:
        """Perplexity = exp(-log_prob). Lower = more legitimate-looking."""
        lp = self.log_probability(domain)
        return math.exp(-lp)


# Build and train the LM on startup using known legit brands
_ngram_lm = NgramLanguageModel(n=3)
if ALEXA_SLDS:
    _ngram_lm.train(ALEXA_SLDS + KNOWN_BRANDS)


def domain_perplexity_score(domain: str) -> float:
    """
    Returns score 0.0 (natural domain) – 1.0 (gibberish/DGA domain).
    Based on character n-gram perplexity relative to legitimate domains.
    """
    if not _ngram_lm._trained or not domain:
        return 0.0

    perp = _ngram_lm.perplexity(domain)

    # Typical perplexity ranges (empirically determined):
    # Legit domains (google, amazon, etc.): 2.0 – 8.0
    # Random/DGA domains (xj8kkl2.tk): 20.0 – 100.0+
    if perp < 8.0:
        return 0.0
    elif perp < 15.0:
        return 0.2
    elif perp < 30.0:
        return 0.5
    elif perp < 60.0:
        return 0.75
    else:
        return 1.0


# ═══════════════════════════════════════════════════════════════════════════════
# MATHEMATICAL MODEL 3: Homoglyph Detection
# ═══════════════════════════════════════════════════════════════════════════════

def homoglyph_score(domain: str) -> Tuple[float, str]:
    """
    Detect Unicode confusable characters in domain.
    e.g., рaypal.com uses Cyrillic 'р' instead of Latin 'p'.

    Returns:
        score (0.0=clean, 1.0=homoglyphs detected),
        normalized_domain (after replacing homoglyphs with ASCII)
    """
    normalized = ""
    homoglyphs_found = []

    for char in domain.lower():
        if char in HOMOGLYPH_MAP:
            normalized += HOMOGLYPH_MAP[char]
            if char not in '0156':  # Don't flag numeric homoglyphs (common in URLs)
                homoglyphs_found.append(char)
        else:
            normalized += char

    if homoglyphs_found:
        return 1.0, normalized

    # Also check if domain is non-ASCII (punycode / international)
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        return 0.8, domain  # Non-ASCII domain — suspicious

    return 0.0, domain


# ═══════════════════════════════════════════════════════════════════════════════
# MATHEMATICAL MODEL 4: Shannon Entropy
# ═══════════════════════════════════════════════════════════════════════════════

def shannon_entropy(s: str) -> float:
    """
    Shannon entropy of a string. H = -Σ p(c) * log2(p(c))
    - Legitimate domains: ~2.5 – 3.5 bits
    - DGA/random domains: ~3.8 – 4.5 bits
    - Repeating patterns: < 2.0 bits
    """
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def entropy_score(domain: str) -> float:
    """
    Returns 0.0 (normal entropy) – 1.0 (suspiciously high entropy / DGA).
    """
    h = shannon_entropy(domain)
    # Entropy > 3.7 → likely random/DGA
    if h < 3.0:
        return 0.0
    elif h < 3.5:
        return 0.2
    elif h < 3.8:
        return 0.5
    elif h < 4.2:
        return 0.75
    else:
        return 1.0


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _words_from(text: str) -> List[str]:
    return [w for w in re.split(r'[^a-zA-Z0-9]+', text) if w]


def _has_ip(hostname: str) -> bool:
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return bool(ip_pattern.match(hostname))


def _has_valid_uuid_in_path(path: str) -> bool:
    """Check if path contains a valid UUID — legitimate in modern web apps."""
    uuid_pattern = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        re.IGNORECASE
    )
    return bool(uuid_pattern.search(path))


def _ratio_digits_excluding_uuid(url: str, path: str) -> float:
    """
    Compute digit ratio, but exclude UUID digits in path (they are legitimate).
    This prevents claude.ai/chat/<uuid> from scoring high on digit ratio.
    """
    clean_url = url
    # Remove UUIDs from digit counting
    uuid_pattern = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        re.IGNORECASE
    )
    clean_url = uuid_pattern.sub('UUID', clean_url)  # Replace UUID with non-digit placeholder
    digits = sum(c.isdigit() for c in clean_url)
    return digits / len(clean_url) if len(clean_url) > 0 else 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN FEATURE EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

def extract_features(url: str, fetch_content: bool = False) -> Dict[str, Any]:
    """
    Extract URL-structural + mathematical features from a URL.
    Content fetching is disabled by default — the model only uses URL features
    that are ALWAYS reliably available.
    """

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed    = urlparse(url)
    hostname  = parsed.netloc.split(':')[0] or ''
    path      = parsed.path or ''
    query     = parsed.query or ''
    full_url  = url

    domain_parts = hostname.split('.')
    tld          = domain_parts[-1].lower() if domain_parts else ''
    domain_name  = domain_parts[-2].lower() if len(domain_parts) >= 2 else hostname.lower()
    subdomain    = '.'.join(domain_parts[:-2]).lower() if len(domain_parts) > 2 else ''

    features = {}

    # ── Standard URL Structural Features ──────────────────────────────────────
    features['length_url']      = len(full_url)
    features['length_hostname'] = len(hostname)
    features['ip']              = 1 if _has_ip(hostname) else 0
    features['nb_dots']         = full_url.count('.')
    features['nb_hyphens']      = full_url.count('-')
    features['nb_at']           = full_url.count('@')
    features['nb_qm']           = full_url.count('?')
    features['nb_and']          = full_url.count('&')
    features['nb_eq']           = full_url.count('=')
    features['nb_underscore']   = full_url.count('_')
    features['nb_tilde']        = full_url.count('~')
    features['nb_percent']      = full_url.count('%')
    features['nb_slash']        = full_url.count('/')
    features['nb_star']         = full_url.count('*')
    # Subtract 1 for the scheme colon (http: or https:) — only non-scheme colons are suspicious
    # e.g., https://site.com→ colon from scheme=1 (not suspicious), port :8080→ suspicious (extra colon)
    _raw_colon = full_url.count(':')
    _scheme_colons = 1 if '://' in full_url else 0
    features['nb_colon']        = max(0, _raw_colon - _scheme_colons)
    features['nb_comma']        = full_url.count(',')
    features['nb_semicolumn']   = full_url.count(';')
    features['nb_dollar']       = full_url.count('$')
    features['nb_space']        = full_url.count(' ') + full_url.count('%20')
    features['nb_www']          = full_url.lower().count('www')
    features['nb_com']          = full_url.lower().count('com')
    features['nb_subdomains']   = max(0, len(domain_parts) - 2)

    path_after_scheme = full_url.split('://', 1)[-1] if '://' in full_url else full_url
    features['nb_dslash']              = path_after_scheme.count('//')
    features['http_in_path']           = 1 if 'http' in path.lower() else 0
    features['https_token']            = 1 if 'https' in hostname.lower() else 0
    features['ratio_digits_url']       = _ratio_digits_excluding_uuid(full_url, path)
    features['ratio_digits_host']      = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    features['punycode']               = 1 if 'xn--' in hostname.lower() else 0
    features['port']                   = 1 if (re.search(r':\d+', parsed.netloc)
                                               and ':80' not in parsed.netloc
                                               and ':443' not in parsed.netloc) else 0
    features['tld_in_path']            = 1 if re.search(r'\.(com|org|net|io|ai)', path.lower()) else 0
    features['tld_in_subdomain']       = 1 if re.search(r'\.(com|org|net)', subdomain.lower()) else 0
    features['abnormal_subdomain']     = 1 if (len(domain_parts) > 3 or
                                               ('www' in subdomain and not subdomain.startswith('www'))) else 0
    features['prefix_suffix']          = 1 if '-' in domain_name else 0
    features['shortening_service']     = 1 if any(s in hostname.lower() for s in SHORTENING_SERVICES) else 0
    features['path_extension']         = 1 if re.search(r'\.\w{2,4}$', path) else 0
    features['nb_redirection']         = path_after_scheme.count('//')
    features['has_uuid_in_path']       = 1 if _has_valid_uuid_in_path(path) else 0
    # Detect raw IP address as hostname — a strong phishing signal
    # Matches: http://192.168.1.1/admin or http://1.2.3.4/login etc.
    _ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    features['ip']                     = 1 if _ip_pattern.match(hostname) else 0

    # Word stats
    url_words  = _words_from(full_url)
    host_words = _words_from(hostname)
    path_words = _words_from(path)

    features['length_words_raw']    = len(url_words)
    url_lens  = [len(w) for w in url_words]  or [0]
    host_lens = [len(w) for w in host_words] or [0]
    path_lens = [len(w) for w in path_words] or [0]
    features['shortest_words_raw']  = min(url_lens)
    features['shortest_word_host']  = min(host_lens)
    features['shortest_word_path']  = min(path_lens)
    features['longest_words_raw']   = max(url_lens)
    features['longest_word_host']   = max(host_lens)
    features['longest_word_path']   = max(path_lens)
    features['avg_words_raw']       = sum(url_lens)  / len(url_lens)
    features['avg_word_host']       = sum(host_lens) / len(host_lens)
    features['avg_word_path']       = sum(path_lens) / len(path_lens)

    char_repeat = max((len(list(g)) for _, g in itertools.groupby(full_url)), default=1)
    features['char_repeat'] = char_repeat

    # Phishing keywords
    url_lower = full_url.lower()
    features['phish_hints']        = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
    features['domain_in_brand']    = 1 if any(b in domain_name for b in KNOWN_BRANDS) else 0
    features['brand_in_subdomain'] = 1 if any(b in subdomain for b in KNOWN_BRANDS) else 0
    features['brand_in_path']      = 1 if any(b in path.lower() for b in KNOWN_BRANDS) else 0
    features['suspecious_tld']     = 1 if tld in SUSPICIOUS_TLDS else 0
    features['statistical_report'] = 0

    # Entropy features
    features['url_entropy']     = shannon_entropy(full_url)
    features['domain_entropy']  = shannon_entropy(domain_name)
    features['path_entropy']    = shannon_entropy(path)

    # ── MATHEMATICAL MODEL SCORES ──────────────────────────────────────────────

    # 1. Typosquatting (Damerau-Levenshtein vs Alexa top-1k)
    typo_score, closest_brand, edit_dist = typosquatting_score(domain_name)
    features['typosquatting_score']  = typo_score
    features['edit_dist_to_brand']   = min(edit_dist, 10)  # Cap at 10

    # 2. N-gram perplexity (gibberish domain detector)
    features['domain_perplexity_score'] = domain_perplexity_score(domain_name)

    # 3. Homoglyph detection
    hg_score, _ = homoglyph_score(domain_name)
    features['homoglyph_score'] = hg_score

    # 4. Entropy score (DGA domain detector)
    features['domain_entropy_score'] = entropy_score(domain_name)

    return features


def get_feature_names() -> List[str]:
    """Return ordered list of all feature names."""
    dummy = extract_features("http://example.com", fetch_content=False)
    return list(dummy.keys())


def get_math_scores(url: str) -> Dict[str, Any]:
    """
    Return just the mathematical model scores with full detail for UI display.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed   = urlparse(url)
    hostname = parsed.netloc.split(':')[0] or ''
    path     = parsed.path or ''

    domain_parts = hostname.split('.')
    domain_name  = domain_parts[-2].lower() if len(domain_parts) >= 2 else hostname.lower()

    typo_score, closest_brand, edit_dist = typosquatting_score(domain_name)
    perp      = _ngram_lm.perplexity(domain_name) if _ngram_lm._trained else 0
    hg_score, normalized = homoglyph_score(domain_name)
    h_entropy = shannon_entropy(domain_name)

    return {
        "typosquatting": {
            "score": typo_score,
            "closest_brand": closest_brand,
            "edit_distance": edit_dist,
            "label": "Critical" if typo_score > 0.8 else "Suspicious" if typo_score > 0.4 else "Safe"
        },
        "ngram_perplexity": {
            "score": domain_perplexity_score(domain_name),
            "raw_perplexity": round(perp, 2),
            "label": "Gibberish/DGA" if perp > 30 else "Unusual" if perp > 15 else "Natural"
        },
        "homoglyph": {
            "score": hg_score,
            "normalized_domain": normalized,
            "detected": hg_score > 0,
            "label": "Homoglyphs Detected" if hg_score > 0 else "Clean"
        },
        "entropy": {
            "score": entropy_score(domain_name),
            "raw_entropy": round(h_entropy, 3),
            "label": "High (DGA-like)" if h_entropy > 3.8 else "Normal"
        },
        "has_uuid": _has_valid_uuid_in_path(path),
        "domain_name": domain_name
    }


def get_feature_description(feature_name: str) -> str:
    """Human-readable description for UI display."""
    descs = {
        'length_url': 'URL length — phishing URLs tend to be very long',
        'nb_hyphens': 'Number of hyphens — used to mimic real domains (e.g., paypal-login)',
        'ratio_digits_url': 'Digit ratio in URL (UUIDs excluded)',
        'nb_subdomains': 'Number of subdomains — phishing uses many (e.g., evil.evil.paypal.com)',
        'prefix_suffix': 'Hyphen in domain name — common phishing pattern',
        'suspecious_tld': 'Suspicious TLD (.tk, .xyz, .top — free, high abuse)',
        'phish_hints': 'Phishing keywords in URL (login, verify, secure, account...)',
        'shortening_service': 'URL shortener — hides real destination',
        'typosquatting_score': 'How similar domain is to a known brand (Damerau-Levenshtein)',
        'domain_perplexity_score': 'Character n-gram perplexity — detects gibberish/DGA domains',
        'homoglyph_score': 'Unicode confusable characters (рaypal ≠ paypal)',
        'domain_entropy_score': 'Shannon entropy — high entropy = random/bot-generated domain',
        'brand_in_subdomain': 'Brand name in subdomain — e.g., paypal.evil.com',
        'https_token': '"https" in domain name (not protocol) — deceptive trick',
        'ip': 'IP address used instead of domain name',
        'punycode': 'Internationalized domain — can hide homoglyphs',
    }
    return descs.get(feature_name, feature_name.replace('_', ' ').title())
