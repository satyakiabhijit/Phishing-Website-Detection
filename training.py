import pandas as pd
import numpy as np
import re
import urllib.parse
from urllib.parse import urlparse, parse_qs
import tldextract
import pickle
import joblib
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import whois
from datetime import datetime, timedelta
import dns.resolver
import hashlib
import base64
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPClassifier
import xgboost as xgb
import lightgbm as lgb
import warnings

warnings.filterwarnings('ignore')


class AdvancedPhishingDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.models = {}
        self.ensemble_model = None

        # Comprehensive threat intelligence
        self.suspicious_keywords = [
            'login', 'secure', 'account', 'update', 'verify', 'suspended', 'limited',
            'confirm', 'click', 'here', 'now', 'urgent', 'expire', 'paypal', 'amazon',
            'apple', 'microsoft', 'google', 'facebook', 'bank', 'credit', 'card',
            'password', 'signin', 'outlook', 'netflix', 'spotify', 'instagram',
            'twitter', 'linkedin', 'ebay', 'walmart', 'target', 'costco', 'adobe',
            'dropbox', 'icloud', 'onedrive', 'chase', 'wellsfargo', 'citibank',
            'americanexpress', 'visa', 'mastercard', 'discover', 'cryptocurrency',
            'bitcoin', 'ethereum', 'blockchain', 'wallet', 'investment', 'trading'
        ]

        self.phishing_patterns = [
            r'[\w\.-]+\.(tk|ml|ga|cf|gq)',  # Suspicious TLDs
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # Hyphenated subdomains
            r'www\d+\.',  # Numbered www
            r'secure[a-z0-9]*\.',  # Secure variations
            r'[a-z]+(\.|-)[a-z]+(\.|-)[a-z]+\.(com|net|org)',  # Multi-level domains
        ]

        self.legitimate_domains = {
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
            'paypal.com', 'ebay.com', 'twitter.com', 'instagram.com', 'linkedin.com',
            'netflix.com', 'spotify.com', 'adobe.com', 'dropbox.com', 'github.com',
            'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'youtube.com'
        }

    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * np.log2(p) for p in prob])
        return entropy

    def _has_custom_port(self, netloc):
        """Check if URL has custom port"""
        return ':' in netloc and not netloc.endswith(':80') and not netloc.endswith(':443')

    def _extract_port(self, netloc):
        """Extract port number from netloc"""
        if ':' in netloc:
            try:
                return int(netloc.split(':')[-1])
            except ValueError:
                return 80
        return 80

    def _detect_brand_impersonation(self, domain):
        """Detect brand impersonation attempts"""
        score = 0
        for brand in self.legitimate_domains:
            brand_name = brand.split('.')[0]
            if brand_name in domain and domain != brand:
                score += 1
        return score

    def _detect_homograph_attack(self, domain):
        """Detect homograph/IDN attacks"""
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']  # Cyrillic look-alikes
        return sum(1 for char in domain if char in suspicious_chars)

    def _is_ip_address(self, domain):
        """Check if domain is an IP address"""
        try:
            socket.inet_aton(domain)
            return True
        except socket.error:
            return False

    def _is_url_shortener(self, domain):
        """Check if domain is a URL shortener"""
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
        return domain in shorteners

    def _vowel_consonant_ratio(self, text):
        """Calculate vowel to consonant ratio"""
        if not text:
            return 0
        vowels = sum(1 for c in text.lower() if c in 'aeiou')
        consonants = sum(1 for c in text.lower() if c.isalpha() and c not in 'aeiou')
        return vowels / consonants if consonants > 0 else 0

    def _longest_word_length(self, text):
        """Find longest word in domain"""
        words = re.findall(r'[a-zA-Z]+', text)
        return max(len(word) for word in words) if words else 0

    def _avg_word_length(self, text):
        """Calculate average word length"""
        words = re.findall(r'[a-zA-Z]+', text)
        return sum(len(word) for word in words) / len(words) if words else 0

    def _extract_network_features(self, url, domain):
        """Extract network-based features"""
        features = {}

        try:
            # Response time analysis
            start_time = datetime.now()
            response = requests.get(url, timeout=10, allow_redirects=True)
            response_time = (datetime.now() - start_time).total_seconds()

            features['response_time'] = response_time
            features['status_code'] = response.status_code
            features['redirect_count'] = len(response.history)
            features['final_url_different'] = 1 if response.url != url else 0

            # Content length and type
            features['content_length'] = len(response.content)
            features['content_type'] = 1 if 'text/html' in response.headers.get('content-type', '') else 0

        except requests.exceptions.RequestException:
            features['response_time'] = -1
            features['status_code'] = -1
            features['redirect_count'] = 0
            features['final_url_different'] = 0
            features['content_length'] = 0
            features['content_type'] = 0

        return features

    def _extract_content_features(self, url):
        """Extract HTML content-based features"""
        features = {}

        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')

            # HTML structure analysis
            features['form_count'] = len(soup.find_all('form'))
            features['input_count'] = len(soup.find_all('input'))
            features['password_field_count'] = len(soup.find_all('input', {'type': 'password'}))
            features['hidden_field_count'] = len(soup.find_all('input', {'type': 'hidden'}))

            # Link analysis
            links = soup.find_all('a', href=True)
            features['external_link_count'] = sum(1 for link in links
                                                  if urlparse(link['href']).netloc and not urlparse(link['href']).netloc.endswith(urlparse(url).netloc))
            features['total_link_count'] = len(links)

            # Image analysis
            images = soup.find_all('img')
            features['image_count'] = len(images)
            features['external_image_count'] = sum(1 for img in images
                                                   if img.get('src') and urlparse(img['src']).netloc and not urlparse(img['src']).netloc.endswith(
                urlparse(url).netloc))

            # Script analysis
            scripts = soup.find_all('script')
            features['script_count'] = len(scripts)
            features['external_script_count'] = sum(1 for script in scripts
                                                    if script.get('src') and urlparse(script['src']).netloc and not urlparse(script['src']).netloc.endswith(
                urlparse(url).netloc))

            # Content analysis
            text_content = soup.get_text().lower()
            features['page_text_length'] = len(text_content)
            features['suspicious_text_count'] = sum(1 for keyword in self.suspicious_keywords
                                                    if keyword in text_content)

            # Meta tag analysis
            features['has_favicon'] = 1 if soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon') else 0
            features['has_title'] = 1 if soup.find('title') else 0
            features['title_length'] = len(soup.find('title').get_text()) if soup.find('title') else 0

        except requests.exceptions.RequestException:
            # Default values for content features
            features.update({
                'form_count': 0, 'input_count': 0, 'password_field_count': 0,
                'hidden_field_count': 0, 'external_link_count': 0, 'total_link_count': 0,
                'image_count': 0, 'external_image_count': 0, 'script_count': 0,
                'external_script_count': 0, 'page_text_length': 0, 'suspicious_text_count': 0,
                'has_favicon': 0, 'has_title': 0, 'title_length': 0
            })

        return features

    def _extract_certificate_features(self, url):
        """Extract SSL certificate features"""
        features = {}

        try:
            if url.startswith('https://'):
                hostname = urlparse(url).netloc
                context = ssl.create_default_context()

                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()

                        # Certificate validity
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')

                        features['cert_days_until_expiry'] = (not_after - datetime.now()).days
                        features['cert_age_days'] = (datetime.now() - not_before).days
                        features['cert_is_expired'] = 1 if not_after < datetime.now() else 0
                        features['cert_is_self_signed'] = 1 if cert['issuer'] == cert['subject'] else 0

                        # Certificate issuer analysis
                        issuer = dict(x[0] for x in cert['issuer'])
                        trusted_cas = ['DigiCert', 'Let\'s Encrypt', 'Comodo', 'GeoTrust', 'Symantec']
                        features['cert_trusted_ca'] = 1 if any(
                            ca in issuer.get('organizationName', '') for ca in trusted_cas) else 0
            else:
                features.update({
                    'cert_days_until_expiry': -1, 'cert_age_days': -1,
                    'cert_is_expired': 0, 'cert_is_self_signed': 0, 'cert_trusted_ca': 0
                })

        except (socket.error, ssl.SSLError, ssl.CertificateError, ValueError):
            features.update({
                'cert_days_until_expiry': -1, 'cert_age_days': -1,
                'cert_is_expired': 0, 'cert_is_self_signed': 0, 'cert_trusted_ca': 0
            })

        return features

    def _extract_whois_features(self, domain):
        """Extract WHOIS-based features"""
        features = {}

        try:
            w = whois.whois(domain)

            # Domain age
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date and isinstance(creation_date, datetime):
                features['domain_age_days'] = (datetime.now() - creation_date).days
                features['domain_age_months'] = features['domain_age_days'] / 30
            else:
                features['domain_age_days'] = -1
                features['domain_age_months'] = -1

            # Expiration date
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            if expiration_date and isinstance(expiration_date, datetime):
                features['domain_expires_in_days'] = (expiration_date - datetime.now()).days
            else:
                features['domain_expires_in_days'] = -1

            # Registrar information
            features['has_registrar_info'] = 1 if w.registrar else 0
            features['has_registrant_info'] = 1 if w.registrant else 0

        except Exception:
            features.update({
                'domain_age_days': -1, 'domain_age_months': -1,
                'domain_expires_in_days': -1, 'has_registrar_info': 0,
                'has_registrant_info': 0
            })

        return features

    def _extract_dns_features(self, domain):
        """Extract DNS-based features"""
        features = {}

        try:
            # A record count
            a_records = dns.resolver.resolve(domain, 'A')
            features['a_record_count'] = len(a_records)

            # MX record existence
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                features['has_mx_record'] = 1
                features['mx_record_count'] = len(mx_records)
            except dns.resolver.NXDOMAIN:
                features['has_mx_record'] = 0
                features['mx_record_count'] = 0

            # NS record count
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                features['ns_record_count'] = len(ns_records)
            except dns.resolver.NXDOMAIN:
                features['ns_record_count'] = 0

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            features.update({
                'a_record_count': 0, 'has_mx_record': 0,
                'mx_record_count': 0, 'ns_record_count': 0
            })

        return features

    def _fill_default_network_features(self, features):
        """Fill default values for network features when not fetching content"""
        default_features = {
            'response_time': -1, 'status_code': -1, 'redirect_count': 0,
            'final_url_different': 0, 'content_length': 0, 'content_type': 0,
            'form_count': 0, 'input_count': 0, 'password_field_count': 0,
            'hidden_field_count': 0, 'external_link_count': 0, 'total_link_count': 0,
            'image_count': 0, 'external_image_count': 0, 'script_count': 0,
            'external_script_count': 0, 'page_text_length': 0, 'suspicious_text_count': 0,
            'has_favicon': 0, 'has_title': 0, 'title_length': 0,
            'cert_days_until_expiry': -1, 'cert_age_days': -1,
            'cert_is_expired': 0, 'cert_is_self_signed': 0, 'cert_trusted_ca': 0,
            'domain_age_days': -1, 'domain_age_months': -1,
            'domain_expires_in_days': -1, 'has_registrar_info': 0,
            'has_registrant_info': 0, 'a_record_count': 0, 'has_mx_record': 0,
            'mx_record_count': 0, 'ns_record_count': 0
        }
        features.update(default_features)

    def _get_default_features(self):
        """Return default feature set when extraction fails"""
        return {
            'url_length': 0, 'domain_length': 0, 'path_length': 0,
            'query_length': 0, 'fragment_length': 0, 'url_entropy': 0,
            'domain_entropy': 0, 'path_entropy': 0, 'url_digit_ratio': 0,
            'url_special_char_ratio': 0, 'domain_digit_ratio': 0,
            'subdomain_count': 0, 'is_subdomain': 0, 'has_www': 0,
            'domain_has_dash': 0, 'domain_has_numbers': 0, 'is_suspicious_tld': 0,
            'tld_length': 0, 'is_country_tld': 0, 'is_https': 0,
            'has_port': 0, 'port_number': 80, 'matches_phishing_pattern': 0,
            'suspicious_keyword_count': 0, 'brand_impersonation_score': 0,
            'homograph_attack_score': 0, 'has_redirect_params': 0,
            'query_param_count': 0, 'is_ip_address': 0, 'has_punycode': 0,
            'url_shortener': 0, 'vowel_consonant_ratio': 0,
            'longest_word_length': 0, 'avg_word_length': 0
        }

    def extract_comprehensive_features(self, url, fetch_content=True):
        """Extract 100+ advanced features from URL and content"""
        features = {}

        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            domain = parsed.netloc.lower()

            # === URL STRUCTURE FEATURES ===
            features['url_length'] = len(url)
            features['domain_length'] = len(domain)
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query) if parsed.query else 0
            features['fragment_length'] = len(parsed.fragment) if parsed.fragment else 0

            # URL composition analysis
            features['url_entropy'] = self._calculate_entropy(url)
            features['domain_entropy'] = self._calculate_entropy(domain)
            features['path_entropy'] = self._calculate_entropy(parsed.path)

            # Character analysis
            features['url_digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if url else 0
            features['url_special_char_ratio'] = sum(not c.isalnum() for c in url) / len(url) if url else 0
            features['domain_digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if domain else 0

            # === DOMAIN FEATURES ===
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['is_subdomain'] = 1 if extracted.subdomain else 0
            features['has_www'] = 1 if domain.startswith('www.') else 0
            features['domain_has_dash'] = 1 if '-' in extracted.domain else 0
            features['domain_has_numbers'] = 1 if any(c.isdigit() for c in extracted.domain) else 0

            # TLD analysis
            features['is_suspicious_tld'] = 1 if extracted.suffix in ['tk', 'ml', 'ga', 'cf', 'gq'] else 0
            features['tld_length'] = len(extracted.suffix) if extracted.suffix else 0
            features['is_country_tld'] = 1 if len(extracted.suffix) == 2 else 0

            # === SECURITY FEATURES ===
            features['is_https'] = 1 if parsed.scheme == 'https' else 0
            features['has_port'] = 1 if self._has_custom_port(parsed.netloc) else 0
            features['port_number'] = self._extract_port(parsed.netloc)

            # === SUSPICIOUS PATTERNS ===
            features['matches_phishing_pattern'] = sum(1 for pattern in self.phishing_patterns
                                                       if re.search(pattern, url, re.IGNORECASE))
            features['suspicious_keyword_count'] = sum(1 for keyword in self.suspicious_keywords
                                                       if keyword in url.lower())

            # Brand impersonation detection
            features['brand_impersonation_score'] = self._detect_brand_impersonation(domain)
            features['homograph_attack_score'] = self._detect_homograph_attack(domain)

            # === URL REDIRECTION FEATURES ===
            features['has_redirect_params'] = 1 if any(param in parsed.query.lower()
                                                       for param in ['redirect', 'url', 'link', 'goto']) else 0
            features['query_param_count'] = len(parse_qs(parsed.query))

            # === ADVANCED PATTERN MATCHING ===
            features['is_ip_address'] = 1 if self._is_ip_address(domain) else 0
            features['has_punycode'] = 1 if 'xn--' in domain else 0
            features['url_shortener'] = 1 if self._is_url_shortener(domain) else 0

            # === LEXICAL FEATURES ===
            features['vowel_consonant_ratio'] = self._vowel_consonant_ratio(extracted.domain)
            features['longest_word_length'] = self._longest_word_length(extracted.domain)
            features['avg_word_length'] = self._avg_word_length(extracted.domain)

            # === NETWORK FEATURES ===
            if fetch_content:
                network_features = self._extract_network_features(url, domain)
                features.update(network_features)

                # Content-based features
                content_features = self._extract_content_features(url)
                features.update(content_features)

                # Certificate features
                cert_features = self._extract_certificate_features(url)
                features.update(cert_features)

                # WHOIS features
                whois_features = self._extract_whois_features(domain)
                features.update(whois_features)

                # DNS features
                dns_features = self._extract_dns_features(domain)
                features.update(dns_features)
            else:
                # Fill with default values when not fetching content
                self._fill_default_network_features(features)
            return features

        except Exception as e:
            print(f"Error extracting features from {url}: {str(e)}")
            return self._get_default_features() # Return default features on error

    def _get_risk_level(self, phishing_prob):
        """Determine risk level based on phishing probability"""
        if phishing_prob >= 0.8:
            return 'Very High'
        elif phishing_prob >= 0.6:
            return 'High'
        elif phishing_prob >= 0.4:
            return 'Medium'
        elif phishing_prob >= 0.2:
            return 'Low'
        else:
            return 'Very Low'

    def _get_suspicious_indicators(self, features):
        """Identify suspicious indicators from features"""
        indicators = []

        if features.get('url_length', 0) > 100:
            indicators.append("Unusually long URL")

        if features.get('subdomain_count', 0) > 3:
            indicators.append("Multiple subdomains")

        if features.get('is_ip_address', 0) == 1:
            indicators.append("Uses IP address instead of domain")

        if features.get('suspicious_keyword_count', 0) > 2:
            indicators.append("Contains multiple suspicious keywords")

        if features.get('brand_impersonation_score', 0) > 0:
            indicators.append("Potential brand impersonation")

        if features.get('is_https', 0) == 0:
            indicators.append("Not using HTTPS")

        if features.get('is_suspicious_tld', 0) == 1:
            indicators.append("Uses suspicious top-level domain")

        if features.get('domain_age_days', -1) != -1 and features.get('domain_age_days', -1) < 30:
            indicators.append("Very new domain (less than 30 days)")

        if features.get('cert_is_self_signed', 0) == 1:
            indicators.append("Self-signed SSL certificate")

        if features.get('redirect_count', 0) > 3:
            indicators.append("Multiple redirects")

        return indicators

    def batch_predict(self, urls):
        """Predict multiple URLs efficiently"""
        results = []

        for url in urls:
            try:
                result = self.predict_single_url(url, detailed=False)
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'prediction': 'Error',
                    'error': str(e)
                })

        return results

    def save_models(self, model_dir='models'):
        """Save all trained models and scaler"""
        import os
        os.makedirs(model_dir, exist_ok=True)

        # Save scaler
        joblib.dump(self.scaler, f'{model_dir}/scaler.pkl')

        # Save individual models
        for name, model in self.models.items():
            joblib.dump(model, f'{model_dir}/{name}_model.pkl')

        # Save ensemble model
        if self.ensemble_model:
            joblib.dump(self.ensemble_model, f'{model_dir}/ensemble_model.pkl')

        print(f"Models saved to {model_dir}/")

    def load_models(self, model_dir='models'):
        """Load all trained models and scaler"""
        try:
            # Load scaler
            self.scaler = joblib.load(f'{model_dir}/scaler.pkl')

            # Load individual models
            model_names = ['random_forest', 'gradient_boosting', 'xgboost', 'lightgbm',
                           'logistic_regression', 'svm', 'neural_network']

            for name in model_names:
                try:
                    self.models[name] = joblib.load(f'{model_dir}/{name}_model.pkl')
                except FileNotFoundError:
                    print(f"Model {name} not found, skipping...")

            # Load ensemble model
            try:
                self.ensemble_model = joblib.load(f'{model_dir}/ensemble_model.pkl')
            except FileNotFoundError:
                print("Ensemble model not found")

            print(f"Models loaded from {model_dir}/")
            return True

        except Exception as e:
            print(f"Error loading models: {str(e)}")
            return False

    def evaluate_model_performance(self, test_urls, test_labels):
        """Comprehensive model evaluation"""
        if not self.ensemble_model:
            raise ValueError("No trained model found. Please train the model first.")

        predictions = []
        probabilities = []

        print("Evaluating model performance...")
        for url in test_urls:
            try:
                result = self.predict_single_url(url, detailed=False)
                predictions.append(1 if result['prediction'] == 'Phishing' else 0)
                probabilities.append(result['phishing_probability'])
            except:
                predictions.append(0)
                probabilities.append(0.0)

        # Calculate metrics
        accuracy = accuracy_score(test_labels, predictions)
        auc_roc = roc_auc_score(test_labels, probabilities)

        print("\n=== MODEL EVALUATION ===")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"AUC-ROC: {auc_roc:.4f}")
        print("\nClassification Report:")
        print(classification_report(test_labels, predictions))
        print("\nConfusion Matrix:")
        print(confusion_matrix(test_labels, predictions))

        return {
            'accuracy': accuracy,
            'auc_roc': auc_roc,
            'predictions': predictions,
            'probabilities': probabilities
        }

    def train_models(self, data_file=None, urls=None, labels=None):
        """Train multiple models with advanced techniques"""

        if data_file:
            # Load data from file (this path can still be used if a file is provided externally)
            df = pd.read_csv(data_file)
            urls = df['url'].tolist()
            labels = df['label'].tolist()

        if not urls or not labels:
            raise ValueError("No training data provided. Please provide URLs and labels or a data file.")

        print("Extracting features from training data...")
        feature_list = []
        valid_indices = []

        for i, url in enumerate(urls):
            try:
                features = self.extract_comprehensive_features(url, fetch_content=False)
                feature_list.append(features)
                valid_indices.append(i)
            except Exception as e:
                print(f"Skipping URL {i}: {url} due to error: {str(e)}")
                continue

        # Convert to DataFrame
        df_features = pd.DataFrame(feature_list)
        y = [labels[i] for i in valid_indices]

        # Handle missing values
        df_features = df_features.fillna(0)

        # Feature scaling
        X_scaled = self.scaler.fit_transform(df_features)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        print("Training multiple models...")

        # Individual models
        models_config = {
            'random_forest': RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=150, learning_rate=0.1, random_state=42),
            'xgboost': xgb.XGBClassifier(n_estimators=150, learning_rate=0.1, max_depth=8, random_state=42),
            'lightgbm': lgb.LGBMClassifier(n_estimators=150, learning_rate=0.1, max_depth=8, random_state=42),
            'logistic_regression': LogisticRegression(random_state=42, max_iter=1000),
            'svm': SVC(probability=True, random_state=42),
            'neural_network': MLPClassifier(hidden_layer_sizes=(100, 50), random_state=42, max_iter=500)
        }

        # Train individual models
        for name, model in models_config.items():
            print(f"Training {name}...")
            model.fit(X_train, y_train)
            train_score = model.score(X_train, y_train)
            test_score = model.score(X_test, y_test)
            print(f"{name} - Train: {train_score:.4f}, Test: {test_score:.4f}")
            self.models[name] = model

        # Create ensemble model
        print("Creating ensemble model...")
        ensemble_models = [
            ('rf', self.models['random_forest']),
            ('gb', self.models['gradient_boosting']),
            ('xgb', self.models['xgboost']),
            ('lgb', self.models['lightgbm'])
        ]

        self.ensemble_model = VotingClassifier(
            estimators=ensemble_models,
            voting='soft'
        )

        self.ensemble_model.fit(X_train, y_train)
        ensemble_score = self.ensemble_model.score(X_test, y_test)
        print(f"Ensemble Model Test Score: {ensemble_score:.4f}")

        # Detailed evaluation
        y_pred = self.ensemble_model.predict(X_test)
        y_pred_proba = self.ensemble_model.predict_proba(X_test)[:, 1]

        print("\n=== EVALUATION RESULTS ===")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print(f"AUC-ROC: {roc_auc_score(y_test, y_pred_proba):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))

        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': df_features.columns,
            'importance': self.models['random_forest'].feature_importances_
        }).sort_values('importance', ascending=False)

        print("\nTop 20 Most Important Features:")
        print(feature_importance.head(20))

        # Save models
        self.save_models()

        return {
            'accuracy': accuracy_score(y_test, y_pred),
            'auc_roc': roc_auc_score(y_test, y_pred_proba),
            'feature_importance': feature_importance
        }

    def predict_single_url(self, url, detailed=False):
        """Predict if a single URL is phishing"""
        try:
            features = self.extract_comprehensive_features(url, fetch_content=True)
            df_features = pd.DataFrame([features])
            df_features = df_features.fillna(0)

            # Ensure all required columns are present
            if hasattr(self.scaler, 'feature_names_in_'):
                expected_features = self.scaler.feature_names_in_
            else:
                expected_features = list(self._get_default_features().keys())
                dynamic_features_example = [
                    'response_time', 'status_code', 'redirect_count', 'final_url_different',
                    'content_length', 'content_type', 'form_count', 'input_count',
                    'password_field_count', 'hidden_field_count', 'external_link_count',
                    'total_link_count', 'image_count', 'external_image_count',
                    'script_count', 'external_script_count', 'page_text_length',
                    'suspicious_text_count', 'has_favicon', 'has_title', 'title_length',
                    'cert_days_until_expiry', 'cert_age_days', 'cert_is_expired',
                    'cert_is_self_signed', 'cert_trusted_ca', 'domain_age_days',
                    'domain_age_months', 'domain_expires_in_days', 'has_registrar_info',
                    'has_registrant_info', 'a_record_count', 'has_mx_record',
                    'mx_record_count', 'ns_record_count'
                ]
                for f in dynamic_features_example:
                    if f not in expected_features:
                        expected_features.append(f)

            for feature in expected_features:
                if feature not in df_features.columns:
                    df_features[feature] = 0

            # Reorder columns to match training
            df_features = df_features[expected_features]

            X_scaled = self.scaler.transform(df_features)

            # Ensemble prediction
            prediction = self.ensemble_model.predict(X_scaled)[0]
            probability = self.ensemble_model.predict_proba(X_scaled)[0]

            result = {
                'url': url,
                'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
                'phishing_probability': probability[1],
                'legitimate_probability': probability[0],
                'confidence': max(probability),
                'risk_level': self._get_risk_level(probability[1])
            }

            if detailed:
                # Individual model predictions
                individual_predictions = {}
                for name, model in self.models.items():
                    try:
                        pred_proba = model.predict_proba(X_scaled)[0]
                        individual_predictions[name] = {
                            'prediction': 'Phishing' if pred_proba[1] > 0.5 else 'Legitimate',
                            'phishing_probability': pred_proba[1]
                        }
                    except Exception as e:
                        print(f"Error predicting with individual model {name}: {e}")
                        pass # Model might not support predict_proba or other issues

                result['individual_models'] = individual_predictions
                result['features'] = features
                result['suspicious_indicators'] = self._get_suspicious_indicators(features)

            return result

        except Exception as e:
            return {
                'url': url,
                'prediction': 'Error',
                'phishing_probability': 0.5,
                'legitimate_probability': 0.5,
                'confidence': 0.0,
                'risk_level': 'Unknown',
                'error': str(e)
            }


# Example usage and testing
if __name__ == "__main__":
    # Initialize detector
    detector = AdvancedPhishingDetector()

    # Sample training data (Expanded lists provided by the user)
    legitimate_urls = [
        'https://www.google.com',
        'https://www.facebook.com',
        'https://www.amazon.com',
        'https://www.microsoft.com',
        'https://www.apple.com',
        'https://www.paypal.com',
        'https://www.ebay.com',
        'https://www.twitter.com',
        'https://www.instagram.com',
        'https://www.linkedin.com',
        'https://www.netflix.com',
        'https://www.spotify.com',
        'https://www.youtube.com',
        'https://www.github.com',
        'https://www.reddit.com',
        'https://www.wikipedia.org',
        'https://www.stackoverflow.com',
        'https://www.dropbox.com',
        'https://www.zoom.us',
        'https://www.slack.com',
        'https://www.adobe.com',
        'https://www.salesforce.com',
        'https://www.oracle.com',
        'https://www.ibm.com',
        'https://www.intel.com',
        'https://www.nvidia.com',
        'https://www.samsung.com',
        'https://www.sony.com',
        'https://www.hp.com',
        'https://www.dell.com',
        'https://www.cisco.com',
        'https://www.vmware.com',
        'https://www.shopify.com',
        'https://www.squarespace.com',
        'https://www.wordpress.com',
        'https://www.twitch.tv',
        'https://www.tiktok.com',
        'https://www.snapchat.com',
        'https://www.pinterest.com',
        'https://www.tumblr.com',
        'https://www.mailchimp.com',
        'https://www.constantcontact.com',
        'https://www.wix.com',
        'https://www.godaddy.com',
        'https://www.namecheap.com',
        'https://www.bluehost.com',
        'https://www.hostgator.com',
        'https://www.cloudflare.com',
        'https://www.aws.amazon.com',
        'https://www.azure.microsoft.com',
        'https://www.chase.com',
        'https://www.bankofamerica.com',
        'https://www.wellsfargo.com',
        'https://www.citibank.com',
        'https://www.capitalone.com',
        'https://www.americanexpress.com',
        'https://www.discover.com',
        'https://www.visa.com',
        'https://www.mastercard.com',
        'https://www.usbank.com',
        'https://www.pnc.com',
        'https://www.tdbank.com',
        'https://www.schwab.com',
        'https://www.fidelity.com',
        'https://www.vanguard.com',
        'https://www.etrade.com',
        'https://www.robinhood.com',
        'https://www.coinbase.com',
        'https://www.binance.com',
        'https://www.kraken.com',
        'https://www.gemini.com',
        'https://www.bitfinex.com',
        'https://www.walmart.com',
        'https://www.target.com',
        'https://www.bestbuy.com',
        'https://www.homedepot.com',
        'https://www.lowes.com',
        'https://www.macys.com',
        'https://www.kohls.com',
        'https://www.jcpenney.com',
        'https://www.nordstrom.com',
        'https://www.costco.com',
        'https://www.samsclub.com',
        'https://www.alibaba.com',
        'https://www.aliexpress.com',
        'https://www.wish.com',
        'https://www.etsy.com',
        'https://www.overstock.com',
        'https://www.wayfair.com',
        'https://www.booking.com',
        'https://www.expedia.com',
        'https://www.trivago.com',
        'https://www.hotels.com',
        'https://www.airbnb.com',
        'https://www.uber.com',
        'https://www.lyft.com',
        'https://www.doordash.com',
        'https://www.grubhub.com',
        'https://www.ubereats.com',
        'https://www.postmates.com',
        'https://www.instacart.com',
        'https://www.shipt.com',
        'https://www.cnn.com',
        'https://www.bbc.com',
        'https://www.nytimes.com',
        'https://www.washingtonpost.com',
        'https://www.reuters.com',
        'https://www.bloomberg.com',
        'https://www.wsj.com',
        'https://www.usatoday.com',
        'https://www.foxnews.com',
        'https://www.msnbc.com',
    ]

    phishing_urls = [
        'http://paypaI.com-security-update.tk',
        'https://amazon-security.ml',
        'http://apple-id-verify.ga',
        'https://microsoft-account-suspended.cf',
        'http://google-security-alert.gq',
        'https://facebook-security-check.tk',
        'http://instagram-verify-account.ml',
        'https://twitter-suspended-account.ga',
        'http://linkedin-account-limited.cf',
        'https://ebay-account-review.gq',
        'http://netfIix-billing-update.tk',
        'https://spotify-premium-expired.ml',
        'http://paypal-account-verification.ga',
        'https://amazon-prime-renewal.cf',
        'http://apple-icloud-storage.gq',
        'https://microsoft-office-expired.tk',
        'http://google-drive-storage-full.ml',
        'https://facebook-account-disabled.ga',
        'http://instagram-copyright-violation.cf',
        'https://twitter-account-suspended.gq',
        'http://linkedin-premium-expired.tk',
        'https://ebay-seller-fees-due.ml',
        'http://netflix-payment-failed.ga',
        'https://spotify-account-hacked.cf',
        'http://paypal-unusual-activity.gq',
        'https://amazon-order-cancelled.tk',
        'http://apple-app-store-refund.ml',
        'https://microsoft-security-breach.ga',
        'http://google-account-compromised.cf',
        'https://facebook-login-attempt.gq',
        'http://instagram-new-message.tk',
        'https://twitter-dm-notification.ml',
        'http://linkedin-connection-request.ga',
        'https://ebay-bid-confirmation.cf',
        'http://netflix-new-device-login.gq',
        'https://spotify-playlist-shared.tk',
        'http://paypal-money-received.ml',
        'https://amazon-package-delivery.ga',
        'http://apple-warranty-expired.cf',
        'https://microsoft-update-required.gq',
        'http://google-photos-backup-full.tk',
        'https://facebook-friend-request.ml',
        'http://instagram-story-mention.ga',
        'https://twitter-trending-notification.cf',
        'http://linkedin-job-alert.gq',
        'https://ebay-auction-ending.tk',
        'http://chase-bank-alert.ml',
        'https://bankofamerica-security.ga',
        'http://wellsfargo-account-locked.cf',
        'https://citibank-fraud-alert.gq',
        'http://capitalone-payment-due.tk',
        'https://americanexpress-reward.ml',
        'http://discover-cashback-ready.ga',
        'https://visa-transaction-declined.cf',
        'http://mastercard-security-code.gq',
        'https://usbank-mobile-banking.tk',
        'http://pnc-account-update.ml',
        'https://tdbank-wire-transfer.ga',
        'http://schwab-investment-alert.cf',
        'https://fidelity-portfolio-update.gq',
        'http://vanguard-dividend-payment.tk',
        'https://etrade-margin-call.ml',
        'http://robinhood-stock-alert.ga',
        'https://coinbase-price-alert.cf',
        'http://binance-withdrawal-confirm.gq',
        'https://kraken-deposit-received.tk',
        'http://gemini-account-verified.ml',
        'https://bitfinex-trading-suspended.ga',
        'http://walmart-order-ready.cf',
        'https://target-pickup-notification.gq',
        'http://bestbuy-price-match.tk',
        'https://homedepot-delivery-update.ml',
        'http://lowes-store-pickup.ga',
        'https://macys-sale-notification.cf',
        'http://kohls-rewards-earned.gq',
        'https://jcpenney-coupon-expires.tk',
        'http://nordstrom-item-restocked.ml',
        'https://costco-membership-renewal.ga',
        'http://samsclub-gas-discount.cf',
        'https://alibaba-supplier-message.gq',
        'http://aliexpress-shipment-delay.tk',
        'https://wish-order-processing.ml',
        'http://etsy-shop-notification.ga',
        'https://overstock-flash-sale.cf',
        'http://wayfair-delivery-scheduled.gq',
        'https://booking-reservation-confirm.tk',
        'http://expedia-flight-cancelled.ml',
        'https://trivago-price-drop.ga',
        'http://hotels-booking-modified.cf',
        'https://airbnb-host-message.gq',
        'http://uber-trip-receipt.tk',
        'https://lyft-ride-rating.ml',
        'http://doordash-order-delivered.ga',
        'https://grubhub-restaurant-closed.cf',
        'http://ubereats-refund-processed.gq',
        'https://postmates-delivery-issue.tk',
        'http://instacart-shopper-message.ml',
        'https://shipt-order-substitution.ga',
        'http://amazon-aws-billing.cf',
        'https://microsoft-azure-usage.gq',
        'http://google-cloud-quota.tk',
        'https://dropbox-storage-upgrade.ml',
        'http://zoom-meeting-recording.ga',
        'https://slack-workspace-invite.cf',
        'http://adobe-subscription-renewal.gq',
        'https://salesforce-license-expired.tk',
        'http://oracle-support-ticket.ml',
        'https://ibm-cloud-maintenance.ga',
        'http://intel-driver-update.cf',
        'https://nvidia-gpu-warranty.gq',
        'http://samsung-device-recall.tk',
        'https://sony-product-registration.ml',
        'http://hp-printer-cartridge.ga',
        'https://dell-warranty-extension.cf',
        'http://cisco-security-patch.gq',
        'https://vmware-license-activation.tk',
        'http://shopify-payment-gateway.ml',
        'https://squarespace-domain-renewal.ga',
        'http://wordpress-plugin-update.cf',
        'https://twitch-subscriber-badge.gq',
        'http://tiktok-video-violation.tk',
        'https://snapchat-friend-added.ml',
        'http://pinterest-board-shared.ga',
        'http://tumblr-post-flagged.cf',
        'http://mailchimp-campaign-sent.gq',
        'https://constantcontact-list-import.tk',
        'http://wix-site-published.ml',
        'https://godaddy-domain-transfer.ga',
        'http://namecheap-ssl-certificate.cf',
        'https://bluehost-backup-complete.gq',
        'http://hostgator-server-migration.tk',
        'https://cloudflare-ddos-protection.ml',
        'http://github-repository-forked.ga',
        'https://stackoverflow-answer-accepted.cf',
        'http://reddit-comment-reply.gq',
        'https://wikipedia-article-edited.tk',
        'http://youtube-video-monetized.ml',
        'https://netflix-account-sharing.ga',
        'http://spotify-family-plan.cf',
        'https://paypal-business-account.gq',
        'http://apple-developer-program.tk',
        'https://microsoft-partner-network.ml',
        'http://google-ads-campaign.ga',
        'https://facebook-business-manager.cf',
        'http://instagram-creator-fund.gq',
        'https://twitter-api-access.tk',
        'http://linkedin-sales-navigator.ml',
        'https://ebay-managed-payments.ga',
    ]

    # Process legitimate URLs for training
    print("Processing legitimate URLs...")
    full_urls = legitimate_urls + phishing_urls
    full_labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)


    # Train models
    print("Starting training process with expanded dataset...")
    try:
        results = detector.train_models(
            urls=full_urls,
            labels=full_labels
        )
        print("Training completed successfully!")

        # Test single prediction (using a new phishing URL not in training data for better test)
        test_url = "http://bad-phish.gq/login?user=admin"
        result = detector.predict_single_url(test_url, detailed=True)

        print(f"\n=== SINGLE URL PREDICTION ===")
        print(f"URL: {result['url']}")
        print(f"Prediction: {result['prediction']}")
        print(f"Phishing Probability: {result['phishing_probability']:.4f}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Suspicious Indicators: {result['suspicious_indicators']}")

    except Exception as e:
        print(f"Training or prediction failed: {str(e)}")
        print("Please ensure all dependencies are installed (e.g., `pip install -r requirements.txt`) and your internet connection is stable for feature extraction during training.")

