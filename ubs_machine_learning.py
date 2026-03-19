#!/usr/bin/env python3
"""
UBS Machine Learning Module
- Auto-Categorization of domains
- Pattern Recognition for tracking/malware
- Rule Suggestions
- Anomaly Detection
- ML-based domain analysis
"""

import re
import json
import math
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from datetime import datetime


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

@dataclass
class DomainFeatures:
    """Extracted features from a domain"""
    domain: str
    length: int
    subdomain_count: int
    has_numbers: bool
    has_hyphens: bool
    entropy: float
    tld: str
    suspicious_keywords: List[str]
    ngram_features: Dict[str, int]
    consonant_ratio: float
    vowel_ratio: float
    special_char_count: int


class FeatureExtractor:
    """Extract features from domains for ML analysis"""
    
    def __init__(self):
        # Suspicious keywords for different categories
        self.tracking_keywords = [
            'track', 'analytics', 'pixel', 'beacon', 'telemetry',
            'metrics', 'stats', 'collect', 'tag', 'event'
        ]
        
        self.ad_keywords = [
            'ad', 'ads', 'banner', 'promo', 'sponsor', 'affiliate',
            'campaign', 'marketing', 'advertis'
        ]
        
        self.malware_keywords = [
            'malware', 'virus', 'trojan', 'phish', 'scam', 'fake',
            'download', 'free', 'crack', 'keygen', 'hack'
        ]
        
        self.all_keywords = (
            self.tracking_keywords + 
            self.ad_keywords + 
            self.malware_keywords
        )
    
    def extract_features(self, domain: str) -> DomainFeatures:
        """Extract all features from domain"""
        
        # Basic features
        length = len(domain)
        parts = domain.split('.')
        subdomain_count = len(parts) - 2 if len(parts) > 2 else 0
        tld = parts[-1] if parts else ''
        
        # Character analysis
        has_numbers = bool(re.search(r'\d', domain))
        has_hyphens = '-' in domain
        special_char_count = len(re.findall(r'[^a-zA-Z0-9.]', domain))
        
        # Entropy calculation
        entropy = self._calculate_entropy(domain)
        
        # Keyword detection
        suspicious_keywords = [
            kw for kw in self.all_keywords 
            if kw in domain.lower()
        ]
        
        # N-gram features (character patterns)
        ngram_features = self._extract_ngrams(domain, n=2)
        
        # Vowel/consonant ratio
        vowels = len(re.findall(r'[aeiou]', domain.lower()))
        consonants = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]', domain.lower()))
        total_letters = vowels + consonants
        
        vowel_ratio = vowels / total_letters if total_letters > 0 else 0
        consonant_ratio = consonants / total_letters if total_letters > 0 else 0
        
        return DomainFeatures(
            domain=domain,
            length=length,
            subdomain_count=subdomain_count,
            has_numbers=has_numbers,
            has_hyphens=has_hyphens,
            entropy=entropy,
            tld=tld,
            suspicious_keywords=suspicious_keywords,
            ngram_features=ngram_features,
            consonant_ratio=consonant_ratio,
            vowel_ratio=vowel_ratio,
            special_char_count=special_char_count
        )
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of string"""
        if not s:
            return 0.0
        
        # Count character frequencies
        counts = Counter(s)
        length = len(s)
        
        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _extract_ngrams(self, s: str, n: int = 2) -> Dict[str, int]:
        """Extract character n-grams"""
        ngrams = {}
        s_clean = re.sub(r'[^a-z0-9]', '', s.lower())
        
        for i in range(len(s_clean) - n + 1):
            ngram = s_clean[i:i+n]
            ngrams[ngram] = ngrams.get(ngram, 0) + 1
        
        return ngrams


# ============================================================================
# AUTO-CATEGORIZATION
# ============================================================================

@dataclass
class CategoryPrediction:
    """Prediction result for domain categorization"""
    domain: str
    predicted_category: str
    confidence: float
    scores: Dict[str, float]
    reasoning: List[str]


class DomainCategorizer:
    """ML-based domain categorization"""
    
    def __init__(self):
        self.extractor = FeatureExtractor()
        
        # Training data (category patterns learned from existing rules)
        self.category_patterns = {
            'tracking': {
                'keywords': ['track', 'analytics', 'pixel', 'beacon', 'metrics', 'stats'],
                'tlds': ['io', 'net', 'com'],
                'avg_entropy': 3.5,
                'typical_length': (10, 30)
            },
            'ads': {
                'keywords': ['ad', 'ads', 'banner', 'sponsor', 'promo', 'doubleclick'],
                'tlds': ['net', 'com'],
                'avg_entropy': 3.0,
                'typical_length': (8, 25)
            },
            'malware': {
                'keywords': ['download', 'free', 'virus', 'phish', 'crack', 'keygen'],
                'tlds': ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'],
                'avg_entropy': 4.0,
                'typical_length': (15, 40)
            },
            'cdn': {
                'keywords': ['cdn', 'static', 'assets', 'media', 'img', 'cache'],
                'tlds': ['net', 'com', 'cloudfront'],
                'avg_entropy': 3.2,
                'typical_length': (10, 35)
            },
            'social': {
                'keywords': ['facebook', 'twitter', 'instagram', 'social', 'share'],
                'tlds': ['com', 'net'],
                'avg_entropy': 3.0,
                'typical_length': (8, 20)
            }
        }
        
        # Known suspicious TLDs
        self.suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 
            'date', 'racing', 'win', 'download', 'stream'
        }
    
    def train_from_parser(self, parser):
        """Train categorizer from existing parsed rules"""
        
        category_samples = defaultdict(list)
        
        for rule in parser.rules:
            if rule.rule_type.value == 'domain':
                category = rule.modifiers.get('category', 'unknown')
                if category != 'unknown':
                    features = self.extractor.extract_features(rule.pattern.replace('*.', ''))
                    category_samples[category].append(features)
        
        # Update patterns based on training data
        for category, samples in category_samples.items():
            if category not in self.category_patterns:
                self.category_patterns[category] = {
                    'keywords': [],
                    'tlds': [],
                    'avg_entropy': 3.0,
                    'typical_length': (10, 30)
                }
            
            # Calculate average entropy
            avg_entropy = sum(s.entropy for s in samples) / len(samples) if samples else 3.0
            self.category_patterns[category]['avg_entropy'] = avg_entropy
            
            # Collect common TLDs
            tlds = Counter(s.tld for s in samples)
            self.category_patterns[category]['tlds'] = [t for t, _ in tlds.most_common(5)]
            
            # Collect keywords
            all_keywords = []
            for s in samples:
                all_keywords.extend(s.suspicious_keywords)
            keyword_counts = Counter(all_keywords)
            self.category_patterns[category]['keywords'] = [k for k, _ in keyword_counts.most_common(10)]
        
        print(f"✅ Trained on {sum(len(s) for s in category_samples.values())} samples")
        print(f"   Categories: {', '.join(category_samples.keys())}")
    
    def predict_category(self, domain: str) -> CategoryPrediction:
        """Predict category for a domain"""
        
        features = self.extractor.extract_features(domain)
        scores = {}
        reasoning = []
        
        for category, patterns in self.category_patterns.items():
            score = 0.0
            
            # Keyword matching
            keyword_matches = [
                kw for kw in patterns['keywords']
                if kw in domain.lower()
            ]
            if keyword_matches:
                score += 0.4 * len(keyword_matches)
                reasoning.append(f"{category}: keywords {keyword_matches}")
            
            # TLD matching
            if features.tld in patterns['tlds']:
                score += 0.2
                reasoning.append(f"{category}: TLD .{features.tld}")
            
            # Entropy similarity
            entropy_diff = abs(features.entropy - patterns['avg_entropy'])
            if entropy_diff < 1.0:
                score += 0.2 * (1.0 - entropy_diff)
            
            # Length similarity
            min_len, max_len = patterns['typical_length']
            if min_len <= features.length <= max_len:
                score += 0.2
            
            scores[category] = score
        
        # Special checks
        if features.tld in self.suspicious_tlds:
            scores['malware'] = scores.get('malware', 0) + 0.5
            reasoning.append(f"malware: suspicious TLD .{features.tld}")
        
        if features.entropy > 4.5:
            scores['malware'] = scores.get('malware', 0) + 0.3
            reasoning.append(f"malware: high entropy ({features.entropy:.2f})")
        
        # Get best prediction
        if scores:
            best_category = max(scores.items(), key=lambda x: x[1])
            predicted_category = best_category[0]
            confidence = min(best_category[1], 1.0)
        else:
            predicted_category = 'unknown'
            confidence = 0.0
        
        return CategoryPrediction(
            domain=domain,
            predicted_category=predicted_category,
            confidence=confidence,
            scores=scores,
            reasoning=reasoning
        )
    
    def batch_categorize(self, domains: List[str]) -> List[CategoryPrediction]:
        """Categorize multiple domains"""
        return [self.predict_category(domain) for domain in domains]
    
    def suggest_category(self, domain: str, threshold: float = 0.5) -> Optional[str]:
        """Suggest category if confidence is above threshold"""
        prediction = self.predict_category(domain)
        
        if prediction.confidence >= threshold:
            return prediction.predicted_category
        
        return None


# ============================================================================
# PATTERN RECOGNITION
# ============================================================================

class PatternRecognizer:
    """Recognize patterns in domains for tracking/malware detection"""
    
    def __init__(self):
        self.extractor = FeatureExtractor()
        
        # Known pattern signatures
        self.tracking_patterns = [
            r'.*analytics.*',
            r'.*track.*',
            r'.*pixel.*',
            r'.*beacon.*',
            r'.*collect.*',
            r'.*telemetry.*',
            r'.*metrics.*'
        ]
        
        self.malware_patterns = [
            r'.*\d{5,}.*',  # Many numbers
            r'.*[a-z]{20,}.*',  # Very long strings
            r'.*-\d+-.*',  # Hyphen-number-hyphen pattern
            r'.*free.*download.*',
            r'.*crack.*',
            r'.*keygen.*'
        ]
        
        # Compile patterns
        self.compiled_tracking = [re.compile(p, re.IGNORECASE) for p in self.tracking_patterns]
        self.compiled_malware = [re.compile(p, re.IGNORECASE) for p in self.malware_patterns]
    
    def detect_tracking(self, domain: str) -> Dict:
        """Detect if domain is likely tracking"""
        
        matches = []
        for pattern in self.compiled_tracking:
            if pattern.match(domain):
                matches.append(pattern.pattern)
        
        features = self.extractor.extract_features(domain)
        
        # Additional heuristics
        is_tracking = False
        confidence = 0.0
        
        if matches:
            is_tracking = True
            confidence = min(len(matches) * 0.3, 0.9)
        
        # Check for common tracking subdomains
        if any(sub in domain.lower() for sub in ['analytics', 'track', 'pixel', 'stats']):
            is_tracking = True
            confidence = max(confidence, 0.7)
        
        return {
            'is_tracking': is_tracking,
            'confidence': confidence,
            'matched_patterns': matches,
            'features': features
        }
    
    def detect_malware(self, domain: str) -> Dict:
        """Detect if domain is likely malware"""
        
        matches = []
        for pattern in self.compiled_malware:
            if pattern.match(domain):
                matches.append(pattern.pattern)
        
        features = self.extractor.extract_features(domain)
        
        # Malware heuristics
        is_malware = False
        confidence = 0.0
        reasons = []
        
        if matches:
            is_malware = True
            confidence += min(len(matches) * 0.2, 0.6)
            reasons.append(f"Matched {len(matches)} malware patterns")
        
        # High entropy (random-looking)
        if features.entropy > 4.5:
            is_malware = True
            confidence += 0.3
            reasons.append(f"High entropy: {features.entropy:.2f}")
        
        # Suspicious TLD
        suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz'}
        if features.tld in suspicious_tlds:
            is_malware = True
            confidence += 0.4
            reasons.append(f"Suspicious TLD: .{features.tld}")
        
        # Very long domain
        if features.length > 50:
            confidence += 0.2
            reasons.append(f"Very long: {features.length} chars")
        
        # Many numbers
        number_count = len(re.findall(r'\d', domain))
        if number_count > 10:
            confidence += 0.2
            reasons.append(f"Many numbers: {number_count}")
        
        confidence = min(confidence, 1.0)
        
        return {
            'is_malware': is_malware,
            'confidence': confidence,
            'matched_patterns': matches,
            'reasons': reasons,
            'features': features
        }
    
    def analyze_domain(self, domain: str) -> Dict:
        """Complete analysis of domain"""
        
        tracking_result = self.detect_tracking(domain)
        malware_result = self.detect_malware(domain)
        
        # Determine primary classification
        if malware_result['is_malware'] and malware_result['confidence'] > 0.6:
            classification = 'malware'
            confidence = malware_result['confidence']
        elif tracking_result['is_tracking'] and tracking_result['confidence'] > 0.5:
            classification = 'tracking'
            confidence = tracking_result['confidence']
        else:
            classification = 'unknown'
            confidence = 0.0
        
        return {
            'domain': domain,
            'classification': classification,
            'confidence': confidence,
            'tracking_analysis': tracking_result,
            'malware_analysis': malware_result
        }


# ============================================================================
# RULE SUGGESTIONS
# ============================================================================

@dataclass
class RuleSuggestion:
    """Suggested rule for a domain"""
    domain: str
    suggested_rule: str
    category: str
    severity: str
    confidence: float
    reasoning: str


class RuleSuggester:
    """Suggest UBS rules based on domain analysis"""
    
    def __init__(self):
        self.categorizer = DomainCategorizer()
        self.recognizer = PatternRecognizer()
    
    def train(self, parser):
        """Train on existing rules"""
        self.categorizer.train_from_parser(parser)
    
    def suggest_rule(self, domain: str) -> RuleSuggestion:
        """Suggest a rule for a domain"""
        
        # Get category prediction
        category_pred = self.categorizer.predict_category(domain)
        
        # Get pattern analysis
        analysis = self.recognizer.analyze_domain(domain)
        
        # Determine severity
        if analysis['classification'] == 'malware':
            severity = 'critical' if analysis['confidence'] > 0.8 else 'high'
        elif analysis['classification'] == 'tracking':
            severity = 'medium'
        else:
            severity = 'low'
        
        # Build suggested rule
        category = category_pred.predicted_category
        
        # Check if wildcard would be better
        if '.' in domain:
            parts = domain.split('.')
            if len(parts) > 2 and parts[0] in ['www', 'api', 'cdn', 'static']:
                # Suggest wildcard
                base_domain = '.'.join(parts[-2:])
                suggested_domain = f"*.{base_domain}"
            else:
                suggested_domain = domain
        else:
            suggested_domain = domain
        
        suggested_rule = f"{suggested_domain} :severity={severity} :category={category}"
        
        # Add action if malware
        if analysis['classification'] == 'malware':
            suggested_rule += " :action=block :log"
        
        # Combine reasoning
        reasoning = f"Category: {category} ({category_pred.confidence:.2f}), "
        reasoning += f"Classification: {analysis['classification']} ({analysis['confidence']:.2f})"
        
        confidence = (category_pred.confidence + analysis['confidence']) / 2
        
        return RuleSuggestion(
            domain=domain,
            suggested_rule=suggested_rule,
            category=category,
            severity=severity,
            confidence=confidence,
            reasoning=reasoning
        )
    
    def suggest_rules_batch(self, domains: List[str], min_confidence: float = 0.5) -> List[RuleSuggestion]:
        """Suggest rules for multiple domains"""
        suggestions = []
        
        for domain in domains:
            suggestion = self.suggest_rule(domain)
            if suggestion.confidence >= min_confidence:
                suggestions.append(suggestion)
        
        return suggestions
    
    def print_suggestions(self, suggestions: List[RuleSuggestion]):
        """Print formatted rule suggestions"""
        
        if not suggestions:
            print("No suggestions above confidence threshold")
            return
        
        print(f"\n{'='*80}")
        print(f"RULE SUGGESTIONS ({len(suggestions)} domains)")
        print(f"{'='*80}\n")
        
        for i, suggestion in enumerate(suggestions, 1):
            conf_icon = '🟢' if suggestion.confidence > 0.7 else '🟡' if suggestion.confidence > 0.5 else '🔴'
            
            print(f"{i}. {conf_icon} {suggestion.domain}")
            print(f"   Suggested Rule: {suggestion.suggested_rule}")
            print(f"   Confidence: {suggestion.confidence:.2f}")
            print(f"   Reasoning: {suggestion.reasoning}")
            print()


# ============================================================================
# ANOMALY DETECTION
# ============================================================================

@dataclass
class Anomaly:
    """Detected anomaly"""
    domain: str
    anomaly_type: str
    score: float
    description: str
    features: DomainFeatures


class AnomalyDetector:
    """Detect anomalous domains"""
    
    def __init__(self):
        self.extractor = FeatureExtractor()
        
        # Baseline statistics (learned from training data)
        self.baseline = {
            'avg_length': 20.0,
            'avg_entropy': 3.5,
            'avg_subdomain_count': 1.0,
            'std_length': 10.0,
            'std_entropy': 1.0
        }
        
        # Anomaly thresholds (in standard deviations)
        self.length_threshold = 3.0
        self.entropy_threshold = 2.5
    
    def train_baseline(self, parser):
        """Learn baseline from existing rules"""
        
        features_list = []
        
        for rule in parser.rules:
            if rule.rule_type.value == 'domain':
                domain = rule.pattern.replace('*.', '')
                features = self.extractor.extract_features(domain)
                features_list.append(features)
        
        if not features_list:
            print("⚠️  No training data available")
            return
        
        # Calculate statistics
        lengths = [f.length for f in features_list]
        entropies = [f.entropy for f in features_list]
        subdomain_counts = [f.subdomain_count for f in features_list]
        
        self.baseline['avg_length'] = sum(lengths) / len(lengths)
        self.baseline['avg_entropy'] = sum(entropies) / len(entropies)
        self.baseline['avg_subdomain_count'] = sum(subdomain_counts) / len(subdomain_counts)
        
        # Calculate standard deviations
        self.baseline['std_length'] = math.sqrt(
            sum((x - self.baseline['avg_length']) ** 2 for x in lengths) / len(lengths)
        )
        self.baseline['std_entropy'] = math.sqrt(
            sum((x - self.baseline['avg_entropy']) ** 2 for x in entropies) / len(entropies)
        )
        
        print(f"✅ Baseline trained on {len(features_list)} domains")
        print(f"   Avg length: {self.baseline['avg_length']:.1f} ± {self.baseline['std_length']:.1f}")
        print(f"   Avg entropy: {self.baseline['avg_entropy']:.2f} ± {self.baseline['std_entropy']:.2f}")
    
    def detect_anomalies(self, domain: str) -> List[Anomaly]:
        """Detect anomalies in a domain"""
        
        features = self.extractor.extract_features(domain)
        anomalies = []
        
        # Length anomaly
        length_z_score = abs(
            (features.length - self.baseline['avg_length']) / self.baseline['std_length']
        ) if self.baseline['std_length'] > 0 else 0
        
        if length_z_score > self.length_threshold:
            anomalies.append(Anomaly(
                domain=domain,
                anomaly_type='length',
                score=length_z_score,
                description=f"Unusual length: {features.length} chars (z-score: {length_z_score:.2f})",
                features=features
            ))
        
        # Entropy anomaly
        entropy_z_score = abs(
            (features.entropy - self.baseline['avg_entropy']) / self.baseline['std_entropy']
        ) if self.baseline['std_entropy'] > 0 else 0
        
        if entropy_z_score > self.entropy_threshold:
            anomalies.append(Anomaly(
                domain=domain,
                anomaly_type='entropy',
                score=entropy_z_score,
                description=f"Unusual entropy: {features.entropy:.2f} (z-score: {entropy_z_score:.2f})",
                features=features
            ))
        
        # Suspicious patterns
        if features.entropy > 5.0 and features.length > 40:
            anomalies.append(Anomaly(
                domain=domain,
                anomaly_type='suspicious_pattern',
                score=5.0,
                description=f"High entropy + long length (possible DGA domain)",
                features=features
            ))
        
        # Many numbers
        number_ratio = len(re.findall(r'\d', domain)) / len(domain) if len(domain) > 0 else 0
        if number_ratio > 0.5:
            anomalies.append(Anomaly(
                domain=domain,
                anomaly_type='many_numbers',
                score=number_ratio * 10,
                description=f"High number ratio: {number_ratio:.2%}",
                features=features
            ))
        
        return anomalies
    
    def scan_domains(self, domains: List[str]) -> List[Anomaly]:
        """Scan multiple domains for anomalies"""
        
        all_anomalies = []
        
        for domain in domains:
            anomalies = self.detect_anomalies(domain)
            all_anomalies.extend(anomalies)
        
        # Sort by score (highest first)
        all_anomalies.sort(key=lambda x: x.score, reverse=True)
        
        return all_anomalies
    
    def print_anomaly_report(self, anomalies: List[Anomaly]):
        """Print anomaly detection report"""
        
        if not anomalies:
            print("\n✅ No anomalies detected")
            return
        
        print(f"\n{'='*80}")
        print(f"ANOMALY DETECTION REPORT")
        print(f"{'='*80}")
        print(f"Found {len(anomalies)} anomalies\n")
        
        # Group by domain
        by_domain = defaultdict(list)
        for anomaly in anomalies:
            by_domain[anomaly.domain].append(anomaly)
        
        for domain, domain_anomalies in sorted(by_domain.items(), 
                                              key=lambda x: max(a.score for a in x[1]), 
                                              reverse=True):
            max_score = max(a.score for a in domain_anomalies)
            icon = '🔴' if max_score > 5 else '🟠' if max_score > 3 else '🟡'
            
            print(f"{icon} {domain} (max score: {max_score:.2f})")
            for anomaly in domain_anomalies:
                print(f"   - {anomaly.anomaly_type}: {anomaly.description}")
            print()


# ============================================================================
# CLI INTEGRATION
# ============================================================================

def add_ml_commands(subparsers):
    """Add ML commands to CLI"""
    
    # Auto-categorize
    ml_cat_parser = subparsers.add_parser('ml-categorize',
                                          help='Auto-categorize domains using ML')
    ml_cat_parser.add_argument('file', help='UBS file to train on')
    ml_cat_parser.add_argument('--domains', nargs='+',
                              help='Domains to categorize')
    ml_cat_parser.add_argument('--input', help='File with domains (one per line)')
    ml_cat_parser.add_argument('--threshold', type=float, default=0.5,
                              help='Confidence threshold')
    
    # Suggest rules
    ml_suggest_parser = subparsers.add_parser('ml-suggest',
                                             help='Suggest rules for domains')
    ml_suggest_parser.add_argument('file', help='UBS file to train on')
    ml_suggest_parser.add_argument('--domains', nargs='+',
                                  help='Domains to analyze')
    ml_suggest_parser.add_argument('--input', help='File with domains')
    ml_suggest_parser.add_argument('--output', help='Output UBS file with suggestions')
    ml_suggest_parser.add_argument('--min-confidence', type=float, default=0.5,
                                  help='Minimum confidence threshold')
    
    # Detect anomalies
    ml_anomaly_parser = subparsers.add_parser('ml-detect-anomalies',
                                             help='Detect anomalous domains')
    ml_anomaly_parser.add_argument('file', help='UBS file to train on')
    ml_anomaly_parser.add_argument('--domains', nargs='+',
                                  help='Domains to check')
    ml_anomaly_parser.add_argument('--input', help='File with domains')


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    from ubs_parser import UBSParser
    
    example_ubs = """
! Title: ML Training Data
! Version: 1.0.0

[Tracking]
||analytics.google.com^ :category=tracker
||facebook.com/tr/* :category=tracker
tracker.example.com :category=tracker

[Malware]
evil123456.tk :severity=critical :category=malware
phishing-site.ml :severity=high :category=malware

[Ads]
||doubleclick.net^ :category=ads
adserver.com :category=ads
"""
    
    print("=== Machine Learning Module Demo ===\n")
    
    parser = UBSParser()
    parser.parse(example_ubs)
    
    # 1. Feature Extraction
    print("1. Feature Extraction:")
    extractor = FeatureExtractor()
    features = extractor.extract_features("suspicious-tracking123.com")
    print(f"   Domain: {features.domain}")
    print(f"   Length: {features.length}")
    print(f"   Entropy: {features.entropy:.2f}")
    print(f"   Keywords: {features.suspicious_keywords}")
    
    # 2. Auto-Categorization
    print("\n2. Auto-Categorization:")
    categorizer = DomainCategorizer()
    categorizer.train_from_parser(parser)
    
    test_domains = [
        "analytics-tracker.com",
        "malicious-download-free.tk",
        "ad-banner-server.net"
    ]
    
    for domain in test_domains:
        pred = categorizer.predict_category(domain)
        print(f"   {domain}")
        print(f"     → {pred.predicted_category} (confidence: {pred.confidence:.2f})")
    
    # 3. Pattern Recognition
    print("\n3. Pattern Recognition:")
    recognizer = PatternRecognizer()
    
    test_domains_pattern = [
        "track-pixel-analytics.com",
        "malware123456789.tk"
    ]
    
    for domain in test_domains_pattern:
        analysis = recognizer.analyze_domain(domain)
        print(f"   {domain}")
        print(f"     → {analysis['classification']} (confidence: {analysis['confidence']:.2f})")
    
    # 4. Rule Suggestions
    print("\n4. Rule Suggestions:")
    suggester = RuleSuggester()
    suggester.train(parser)
    
    new_domains = [
        "new-analytics-tracker.com",
        "suspicious-malware.tk"
    ]
    
    suggestions = suggester.suggest_rules_batch(new_domains, min_confidence=0.3)
    suggester.print_suggestions(suggestions)
    
    # 5. Anomaly Detection
    print("\n5. Anomaly Detection:")
    detector = AnomalyDetector()
    detector.train_baseline(parser)
    
    suspicious_domains = [
        "a" * 60 + ".com",  # Very long
        "xkcd123randomstring.tk",  # High entropy
        "12345-67890-domain.com"  # Many numbers
    ]
    
    anomalies = detector.scan_domains(suspicious_domains)
    detector.print_anomaly_report(anomalies)
    
    print("\n✅ Machine Learning module loaded successfully!")


# ============================================================================
# ADVANCED ML FEATURES
# ============================================================================

class AdvancedMLAnalyzer:
    """Advanced ML analysis combining all features"""
    
    def __init__(self, parser=None):
        self.categorizer = DomainCategorizer()
        self.recognizer = PatternRecognizer()
        self.suggester = RuleSuggester()
        self.anomaly_detector = AnomalyDetector()
        
        if parser:
            self.train(parser)
    
    def train(self, parser):
        """Train all ML components"""
        print("\n🎓 Training ML models...")
        
        self.categorizer.train_from_parser(parser)
        self.suggester.train(parser)
        self.anomaly_detector.train_baseline(parser)
        
        print("✅ All models trained")
    
    def analyze_domain_comprehensive(self, domain: str) -> Dict:
        """Comprehensive analysis of a domain"""
        
        # Get all analyses
        category_pred = self.categorizer.predict_category(domain)
        pattern_analysis = self.recognizer.analyze_domain(domain)
        anomalies = self.anomaly_detector.detect_anomalies(domain)
        suggestion = self.suggester.suggest_rule(domain)
        
        # Calculate risk score (0-100)
        risk_score = 0
        
        # Category-based risk
        if category_pred.predicted_category == 'malware':
            risk_score += 50 * category_pred.confidence
        elif category_pred.predicted_category in ['tracking', 'ads']:
            risk_score += 30 * category_pred.confidence
        
        # Pattern-based risk
        if pattern_analysis['classification'] == 'malware':
            risk_score += 30 * pattern_analysis['confidence']
        
        # Anomaly-based risk
        if anomalies:
            max_anomaly_score = max(a.score for a in anomalies)
            risk_score += min(max_anomaly_score * 5, 20)
        
        risk_score = min(risk_score, 100)
        
        # Determine threat level
        if risk_score >= 80:
            threat_level = 'CRITICAL'
        elif risk_score >= 60:
            threat_level = 'HIGH'
        elif risk_score >= 40:
            threat_level = 'MEDIUM'
        elif risk_score >= 20:
            threat_level = 'LOW'
        else:
            threat_level = 'MINIMAL'
        
        return {
            'domain': domain,
            'risk_score': risk_score,
            'threat_level': threat_level,
            'category_prediction': category_pred,
            'pattern_analysis': pattern_analysis,
            'anomalies': anomalies,
            'suggested_rule': suggestion,
            'recommendation': self._generate_recommendation(
                risk_score, threat_level, category_pred, pattern_analysis
            )
        }
    
    def _generate_recommendation(self, risk_score: float, threat_level: str,
                                 category_pred, pattern_analysis) -> str:
        """Generate action recommendation"""
        
        if threat_level == 'CRITICAL':
            return "🔴 BLOCK IMMEDIATELY - High confidence malicious domain"
        elif threat_level == 'HIGH':
            return "🟠 BLOCK RECOMMENDED - Likely malicious or unwanted"
        elif threat_level == 'MEDIUM':
            return "🟡 MONITOR - Potentially unwanted, consider blocking"
        elif threat_level == 'LOW':
            return "🟢 REVIEW - Low risk, manual review recommended"
        else:
            return "⚪ ALLOW - Minimal risk detected"
    
    def batch_analyze(self, domains: List[str]) -> List[Dict]:
        """Analyze multiple domains"""
        return [self.analyze_domain_comprehensive(domain) for domain in domains]
    
    def generate_report(self, analyses: List[Dict], output_file: str = None):
        """Generate comprehensive ML analysis report"""
        
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("COMPREHENSIVE ML ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Domains Analyzed: {len(analyses)}")
        report_lines.append("")
        
        # Summary by threat level
        threat_counts = Counter(a['threat_level'] for a in analyses)
        report_lines.append("THREAT LEVEL SUMMARY:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL']:
            count = threat_counts.get(level, 0)
            if count > 0:
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 
                       'LOW': '🟢', 'MINIMAL': '⚪'}[level]
                report_lines.append(f"  {icon} {level}: {count} domains")
        report_lines.append("")
        
        # Summary by category
        category_counts = Counter(a['category_prediction'].predicted_category for a in analyses)
        report_lines.append("CATEGORY DISTRIBUTION:")
        for category, count in category_counts.most_common():
            report_lines.append(f"  - {category}: {count} domains")
        report_lines.append("")
        
        # Detailed analysis
        report_lines.append("=" * 80)
        report_lines.append("DETAILED ANALYSIS")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Sort by risk score (highest first)
        sorted_analyses = sorted(analyses, key=lambda x: x['risk_score'], reverse=True)
        
        for i, analysis in enumerate(sorted_analyses, 1):
            threat_icon = {
                'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡',
                'LOW': '🟢', 'MINIMAL': '⚪'
            }.get(analysis['threat_level'], '⚪')
            
            report_lines.append(f"{i}. {threat_icon} {analysis['domain']}")
            report_lines.append(f"   Risk Score: {analysis['risk_score']:.1f}/100")
            report_lines.append(f"   Threat Level: {analysis['threat_level']}")
            report_lines.append(f"   Category: {analysis['category_prediction'].predicted_category} "
                              f"(conf: {analysis['category_prediction'].confidence:.2f})")
            report_lines.append(f"   Classification: {analysis['pattern_analysis']['classification']} "
                              f"(conf: {analysis['pattern_analysis']['confidence']:.2f})")
            
            if analysis['anomalies']:
                report_lines.append(f"   Anomalies: {len(analysis['anomalies'])} detected")
                for anomaly in analysis['anomalies'][:3]:  # Top 3
                    report_lines.append(f"     - {anomaly.description}")
            
            report_lines.append(f"   Suggested Rule: {analysis['suggested_rule'].suggested_rule}")
            report_lines.append(f"   Recommendation: {analysis['recommendation']}")
            report_lines.append("")
        
        report_text = "\n".join(report_lines)
        
        # Print to console
        print(report_text)
        
        # Save to file if requested
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\n✅ Report saved to: {output_file}")
        
        return report_text
    
    def export_suggested_rules(self, analyses: List[Dict], output_file: str,
                              min_confidence: float = 0.5):
        """Export suggested rules as UBS file"""
        
        lines = []
        lines.append("! Title: ML-Generated Rules")
        lines.append(f"! Version: 1.0.0")
        lines.append(f"! Generated: {datetime.now().strftime('%Y-%m-%d')}")
        lines.append(f"! Description: Rules suggested by ML analysis")
        lines.append("")
        
        # Group by threat level
        by_threat = defaultdict(list)
        for analysis in analyses:
            if analysis['suggested_rule'].confidence >= min_confidence:
                by_threat[analysis['threat_level']].append(analysis)
        
        # Output by threat level
        for threat_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if threat_level in by_threat:
                lines.append(f"[{threat_level}]")
                for analysis in sorted(by_threat[threat_level], 
                                     key=lambda x: x['risk_score'], 
                                     reverse=True):
                    lines.append(analysis['suggested_rule'].suggested_rule)
                lines.append("")
        
        content = "\n".join(lines)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        total_rules = sum(len(rules) for rules in by_threat.values())
        print(f"✅ Exported {total_rules} ML-suggested rules to: {output_file}")
        
        return content


# ============================================================================
# CLI COMMAND HANDLERS
# ============================================================================

def handle_ml_categorize_command(args):
    """Handle ml-categorize command"""
    from ubs_parser import UBSParser
    
    # Load and parse training file
    with open(args.file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = UBSParser()
    parser.parse(content)
    
    # Setup categorizer
    categorizer = DomainCategorizer()
    categorizer.train_from_parser(parser)
    
    # Get domains to categorize
    if args.domains:
        domains = args.domains
    elif args.input:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        print("❌ No domains provided. Use --domains or --input")
        return 1
    
    # Categorize
    print(f"\n🔍 Categorizing {len(domains)} domains...\n")
    
    predictions = categorizer.batch_categorize(domains)
    
    # Print results
    for pred in predictions:
        if pred.confidence >= args.threshold:
            conf_icon = '🟢' if pred.confidence > 0.7 else '🟡'
            print(f"{conf_icon} {pred.domain}")
            print(f"   → {pred.predicted_category} (confidence: {pred.confidence:.2f})")
            if pred.reasoning:
                print(f"   Reasoning: {pred.reasoning[0]}")
            print()
    
    return 0


def handle_ml_suggest_command(args):
    """Handle ml-suggest command"""
    from ubs_parser import UBSParser
    
    # Load and parse training file
    with open(args.file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = UBSParser()
    parser.parse(content)
    
    # Setup suggester
    suggester = RuleSuggester()
    suggester.train(parser)
    
    # Get domains
    if args.domains:
        domains = args.domains
    elif args.input:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        print("❌ No domains provided. Use --domains or --input")
        return 1
    
    # Generate suggestions
    print(f"\n🤖 Generating rule suggestions for {len(domains)} domains...\n")
    
    suggestions = suggester.suggest_rules_batch(domains, args.min_confidence)
    suggester.print_suggestions(suggestions)
    
    # Export if requested
    if args.output and suggestions:
        lines = [
            "! Title: ML-Suggested Rules",
            f"! Generated: {datetime.now().strftime('%Y-%m-%d')}",
            ""
        ]
        
        for suggestion in suggestions:
            lines.append(suggestion.suggested_rule)
        
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        print(f"✅ Exported {len(suggestions)} suggestions to: {args.output}")
    
    return 0


def handle_ml_detect_anomalies_command(args):
    """Handle ml-detect-anomalies command"""
    from ubs_parser import UBSParser
    
    # Load and parse training file
    with open(args.file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = UBSParser()
    parser.parse(content)
    
    # Setup detector
    detector = AnomalyDetector()
    detector.train_baseline(parser)
    
    # Get domains
    if args.domains:
        domains = args.domains
    elif args.input:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        print("❌ No domains provided. Use --domains or --input")
        return 1
    
    # Detect anomalies
    print(f"\n🔍 Scanning {len(domains)} domains for anomalies...\n")
    
    anomalies = detector.scan_domains(domains)
    detector.print_anomaly_report(anomalies)
    
    return 0


# Advanced ML command
def add_ml_advanced_command(subparsers):
    """Add advanced ML analysis command"""
    
    ml_analyze_parser = subparsers.add_parser('ml-analyze',
                                              help='Comprehensive ML analysis')
    ml_analyze_parser.add_argument('file', help='UBS file to train on')
    ml_analyze_parser.add_argument('--domains', nargs='+',
                                   help='Domains to analyze')
    ml_analyze_parser.add_argument('--input', help='File with domains')
    ml_analyze_parser.add_argument('--output', help='Output report file')
    ml_analyze_parser.add_argument('--export-rules', help='Export suggested rules to UBS file')
    ml_analyze_parser.add_argument('--min-confidence', type=float, default=0.5,
                                   help='Minimum confidence for rule export')


def handle_ml_analyze_command(args):
    """Handle ml-analyze command"""
    from ubs_parser import UBSParser
    
    # Load and parse
    with open(args.file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = UBSParser()
    parser.parse(content)
    
    # Setup advanced analyzer
    analyzer = AdvancedMLAnalyzer(parser)
    
    # Get domains
    if args.domains:
        domains = args.domains
    elif args.input:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        print("❌ No domains provided. Use --domains or --input")
        return 1
    
    # Analyze
    print(f"\n🤖 Running comprehensive ML analysis on {len(domains)} domains...\n")
    
    analyses = analyzer.batch_analyze(domains)
    
    # Generate report
    analyzer.generate_report(analyses, args.output)
    
    # Export rules if requested
    if args.export_rules:
        analyzer.export_suggested_rules(analyses, args.export_rules, args.min_confidence)
    
    return 0


if __name__ == "__main__":
    # Run demo
    pass
