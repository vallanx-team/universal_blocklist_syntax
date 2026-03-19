#!/usr/bin/env python3
"""
UBS Testing & Simulation Module
- URL Tester (already exists, but enhanced here)
- Traffic Simulator
- Performance Benchmarks
- False-Positive Detection
"""

import re
import time
import random
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from datetime import datetime, timedelta


# ============================================================================
# ENHANCED URL TESTER (extends existing URLTester)
# ============================================================================

@dataclass
class TestResult:
    """Enhanced test result with detailed information"""
    url: str
    blocked: bool
    action: str
    matching_rules: List[Dict]
    reason: str
    performance_ms: float = 0.0
    rule_chain: List[int] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class EnhancedURLTester:
    """Enhanced URL testing with detailed analysis"""
    
    def __init__(self, parser):
        self.parser = parser
        self._compiled_regexes = {}
        self.test_history = []
    
    def test_url(self, url: str, detailed: bool = False) -> TestResult:
        """
        Test if URL would be blocked
        
        Args:
            url: URL to test
            detailed: Include detailed matching information
        """
        import time
        from urllib.parse import urlparse
        
        start_time = time.time()
        
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        full_pattern = f"{domain}{path}"
        
        matching_rules = []
        rule_chain = []
        final_action = 'allow'
        reason = 'No matching rules'
        metadata = {}
        
        # Track which rules were evaluated
        evaluated_rules = 0
        
        # Check rules in order
        for idx, rule in enumerate(self.parser.rules):
            evaluated_rules += 1
            
            if self._matches_rule(rule, domain, full_pattern, url):
                rule_info = {
                    'line': rule.line_number,
                    'pattern': rule.pattern,
                    'type': rule.rule_type.value,
                    'action': rule.modifiers.get('action', 'block'),
                    'section': rule.section,
                    'severity': rule.modifiers.get('severity', 'unspecified')
                }
                
                matching_rules.append(rule_info)
                rule_chain.append(idx)
                
                # Whitelist takes precedence
                if rule.rule_type.value == 'whitelist' or rule.modifiers.get('action') == 'allow':
                    final_action = 'allow'
                    reason = f'Whitelisted by rule at line {rule.line_number} (pattern: {rule.pattern})'
                    break
                else:
                    final_action = rule.modifiers.get('action', 'block')
                    reason = f'Blocked by rule at line {rule.line_number} (pattern: {rule.pattern})'
        
        elapsed = (time.time() - start_time) * 1000  # ms
        
        # Add metadata if detailed
        if detailed:
            metadata = {
                'domain': domain,
                'path': path,
                'evaluated_rules': evaluated_rules,
                'total_rules': len(self.parser.rules),
                'match_percentage': (len(matching_rules) / len(self.parser.rules) * 100) if self.parser.rules else 0
            }
        
        result = TestResult(
            url=url,
            blocked=(final_action != 'allow'),
            action=final_action,
            matching_rules=matching_rules,
            reason=reason,
            performance_ms=round(elapsed, 3),
            rule_chain=rule_chain,
            metadata=metadata
        )
        
        # Store in history
        self.test_history.append(result)
        
        return result
    
    def _matches_rule(self, rule, domain: str, full_pattern: str, url: str) -> bool:
        """Check if rule matches the URL"""
        
        # Domain rules
        if rule.rule_type.value == 'domain':
            pattern = rule.pattern
            
            if rule.modifiers.get('regex'):
                if pattern not in self._compiled_regexes:
                    try:
                        self._compiled_regexes[pattern] = re.compile(pattern)
                    except:
                        return False
                return bool(self._compiled_regexes[pattern].search(domain))
            
            # Wildcard matching
            if pattern.startswith('*.'):
                pattern = pattern[2:]
                return domain.endswith(pattern) or domain == pattern
            
            # Exact match
            return domain == pattern
        
        # URL pattern rules
        elif rule.rule_type.value == 'url_pattern':
            pattern = rule.pattern
            
            # Simple substring match
            if '/' in pattern:
                return pattern in full_pattern
            else:
                return pattern in domain
        
        return False
    
    def batch_test(self, urls: List[str], detailed: bool = False) -> List[TestResult]:
        """Test multiple URLs"""
        return [self.test_url(url, detailed=detailed) for url in urls]
    
    def get_test_summary(self) -> Dict:
        """Get summary of all tests"""
        if not self.test_history:
            return {'message': 'No tests run yet'}
        
        blocked = sum(1 for r in self.test_history if r.blocked)
        allowed = len(self.test_history) - blocked
        
        avg_time = sum(r.performance_ms for r in self.test_history) / len(self.test_history)
        
        return {
            'total_tests': len(self.test_history),
            'blocked': blocked,
            'allowed': allowed,
            'block_rate': (blocked / len(self.test_history) * 100) if self.test_history else 0,
            'avg_performance_ms': round(avg_time, 3),
            'slowest_test_ms': max(r.performance_ms for r in self.test_history),
            'fastest_test_ms': min(r.performance_ms for r in self.test_history)
        }


# ============================================================================
# TRAFFIC SIMULATOR
# ============================================================================

@dataclass
class TrafficEntry:
    """Simulated traffic entry"""
    timestamp: datetime
    url: str
    domain: str
    method: str
    blocked: bool
    action: str
    rule_id: Optional[int] = None
    bytes_saved: int = 0


class TrafficSimulator:
    """Simulate traffic through blocklist rules"""
    
    def __init__(self, parser, tester: EnhancedURLTester):
        self.parser = parser
        self.tester = tester
        self.traffic_log = []
        
        # Common traffic patterns
        self.common_domains = [
            'google.com', 'facebook.com', 'twitter.com', 'youtube.com',
            'amazon.com', 'wikipedia.org', 'reddit.com', 'linkedin.com'
        ]
        
        self.ad_domains = [
            'doubleclick.net', 'googlesyndication.com', 'adserver.com',
            'ads.google.com', 'facebook.com/tr', 'analytics.google.com'
        ]
        
        self.malware_domains = [
            'evil-malware.com', 'phishing-site.net', 'malicious.org'
        ]
    
    def generate_traffic(self, num_requests: int = 1000, 
                        malicious_rate: float = 0.1,
                        ad_rate: float = 0.3) -> List[TrafficEntry]:
        """
        Generate simulated traffic
        
        Args:
            num_requests: Number of requests to generate
            malicious_rate: Percentage of malicious traffic (0.0-1.0)
            ad_rate: Percentage of ad/tracking traffic (0.0-1.0)
        """
        print(f"\n🔄 Generating {num_requests} simulated requests...")
        
        traffic = []
        start_time = datetime.now() - timedelta(hours=1)
        
        for i in range(num_requests):
            # Determine request type
            rand = random.random()
            
            if rand < malicious_rate:
                # Malicious traffic
                domain = random.choice(self.malware_domains)
                url = f"https://{domain}/malware.exe"
            elif rand < malicious_rate + ad_rate:
                # Ad/tracking traffic
                domain = random.choice(self.ad_domains)
                url = f"https://{domain}/track?id={random.randint(1000,9999)}"
            else:
                # Legitimate traffic
                domain = random.choice(self.common_domains)
                paths = ['/', '/page', '/article', '/search', '/profile']
                url = f"https://{domain}{random.choice(paths)}"
            
            # Test against rules
            result = self.tester.test_url(url)
            
            # Estimate bytes saved if blocked (simplified)
            bytes_saved = random.randint(10000, 500000) if result.blocked else 0
            
            entry = TrafficEntry(
                timestamp=start_time + timedelta(seconds=i * 3.6),  # Spread over 1 hour
                url=url,
                domain=domain,
                method=random.choice(['GET', 'POST']),
                blocked=result.blocked,
                action=result.action,
                rule_id=result.rule_chain[0] if result.rule_chain else None,
                bytes_saved=bytes_saved
            )
            
            traffic.append(entry)
        
        self.traffic_log.extend(traffic)
        
        print(f"✅ Generated {num_requests} requests")
        return traffic
    
    def analyze_traffic(self, traffic: Optional[List[TrafficEntry]] = None) -> Dict:
        """Analyze simulated traffic"""
        
        if traffic is None:
            traffic = self.traffic_log
        
        if not traffic:
            return {'message': 'No traffic to analyze'}
        
        blocked = [t for t in traffic if t.blocked]
        allowed = [t for t in traffic if not t.blocked]
        
        # Domain statistics
        domain_counts = Counter(t.domain for t in traffic)
        blocked_domains = Counter(t.domain for t in blocked)
        
        # Calculate bandwidth saved
        total_bytes_saved = sum(t.bytes_saved for t in blocked)
        
        # Time distribution
        if traffic:
            time_span = (traffic[-1].timestamp - traffic[0].timestamp).total_seconds()
            requests_per_second = len(traffic) / time_span if time_span > 0 else 0
        else:
            requests_per_second = 0
        
        analysis = {
            'total_requests': len(traffic),
            'blocked_requests': len(blocked),
            'allowed_requests': len(allowed),
            'block_rate': (len(blocked) / len(traffic) * 100) if traffic else 0,
            'bandwidth_saved_mb': round(total_bytes_saved / 1024 / 1024, 2),
            'requests_per_second': round(requests_per_second, 2),
            'top_blocked_domains': blocked_domains.most_common(10),
            'top_requested_domains': domain_counts.most_common(10),
            'unique_domains': len(domain_counts),
            'unique_blocked_domains': len(blocked_domains)
        }
        
        return analysis
    
    def print_traffic_report(self, analysis: Optional[Dict] = None):
        """Print formatted traffic analysis report"""
        
        if analysis is None:
            analysis = self.analyze_traffic()
        
        if 'message' in analysis:
            print(analysis['message'])
            return
        
        print(f"\n{'='*80}")
        print("TRAFFIC SIMULATION REPORT")
        print(f"{'='*80}")
        print(f"Total Requests:     {analysis['total_requests']}")
        print(f"Blocked:            {analysis['blocked_requests']} ({analysis['block_rate']:.1f}%)")
        print(f"Allowed:            {analysis['allowed_requests']}")
        print(f"Bandwidth Saved:    {analysis['bandwidth_saved_mb']} MB")
        print(f"Requests/Second:    {analysis['requests_per_second']:.2f}")
        print(f"Unique Domains:     {analysis['unique_domains']}")
        print(f"{'='*80}\n")
        
        if analysis['top_blocked_domains']:
            print("🚫 Top 10 Blocked Domains:")
            for domain, count in analysis['top_blocked_domains']:
                print(f"  {count:4d}x  {domain}")
        
        print()


# ============================================================================
# PERFORMANCE BENCHMARKS
# ============================================================================

class PerformanceBenchmark:
    """Benchmark blocklist performance"""
    
    def __init__(self, parser):
        self.parser = parser
        self.results = {}
    
    def benchmark_parsing(self, content: str, iterations: int = 10) -> Dict:
        """Benchmark parsing performance"""
        from ubs_parser import UBSParser
        
        print(f"\n⏱️  Benchmarking parsing ({iterations} iterations)...")
        
        times = []
        for i in range(iterations):
            parser = UBSParser()
            
            start = time.time()
            parser.parse(content)
            elapsed = time.time() - start
            
            times.append(elapsed)
        
        result = {
            'operation': 'parsing',
            'iterations': iterations,
            'avg_time_ms': round(sum(times) / len(times) * 1000, 3),
            'min_time_ms': round(min(times) * 1000, 3),
            'max_time_ms': round(max(times) * 1000, 3),
            'rules_parsed': len(self.parser.rules),
            'rules_per_second': round(len(self.parser.rules) / (sum(times) / len(times)), 0)
        }
        
        self.results['parsing'] = result
        return result
    
    def benchmark_lookups(self, test_domains: List[str], iterations: int = 100) -> Dict:
        """Benchmark domain lookup performance"""
        
        print(f"\n⏱️  Benchmarking lookups ({iterations} iterations × {len(test_domains)} domains)...")
        
        tester = EnhancedURLTester(self.parser)
        
        times = []
        for i in range(iterations):
            start = time.time()
            
            for domain in test_domains:
                tester.test_url(f"https://{domain}/")
            
            elapsed = time.time() - start
            times.append(elapsed)
        
        total_lookups = iterations * len(test_domains)
        avg_time = sum(times) / len(times)
        
        result = {
            'operation': 'lookups',
            'iterations': iterations,
            'domains_per_iteration': len(test_domains),
            'total_lookups': total_lookups,
            'avg_time_ms': round(avg_time * 1000, 3),
            'lookups_per_second': round(total_lookups / sum(times), 0),
            'avg_lookup_time_us': round(avg_time / len(test_domains) * 1000000, 1)
        }
        
        self.results['lookups'] = result
        return result
    
    def benchmark_conversions(self) -> Dict:
        """Benchmark conversion performance"""
        from ubs_parser import UBSConverter
        
        print(f"\n⏱️  Benchmarking conversions...")
        
        converter = UBSConverter(self.parser)
        
        formats = {
            'hosts': converter.to_hosts,
            'adblock': converter.to_adblock,
            'dnsmasq': converter.to_dnsmasq,
            'unbound': converter.to_unbound
        }
        
        results = {}
        
        for format_name, convert_func in formats.items():
            start = time.time()
            output = convert_func()
            elapsed = time.time() - start
            
            results[format_name] = {
                'time_ms': round(elapsed * 1000, 3),
                'output_size_kb': round(len(output) / 1024, 2),
                'rules_per_second': round(len(self.parser.rules) / elapsed, 0)
            }
        
        self.results['conversions'] = results
        return results
    
    def run_full_benchmark(self, content: str, test_domains: List[str]) -> Dict:
        """Run complete benchmark suite"""
        
        print(f"\n{'='*80}")
        print("PERFORMANCE BENCHMARK SUITE")
        print(f"{'='*80}")
        
        # Parsing
        parsing_result = self.benchmark_parsing(content, iterations=10)
        
        # Lookups
        lookup_result = self.benchmark_lookups(test_domains, iterations=100)
        
        # Conversions
        conversion_results = self.benchmark_conversions()
        
        # Print summary
        print(f"\n{'='*80}")
        print("BENCHMARK RESULTS")
        print(f"{'='*80}")
        
        print(f"\n📄 Parsing:")
        print(f"   Avg Time:        {parsing_result['avg_time_ms']:.3f} ms")
        print(f"   Rules/Second:    {parsing_result['rules_per_second']:,.0f}")
        
        print(f"\n🔍 Lookups:")
        print(f"   Avg Lookup:      {lookup_result['avg_lookup_time_us']:.1f} μs")
        print(f"   Lookups/Second:  {lookup_result['lookups_per_second']:,.0f}")
        
        print(f"\n🔄 Conversions:")
        for format_name, stats in conversion_results.items():
            print(f"   {format_name:10s}  {stats['time_ms']:6.1f} ms  ({stats['rules_per_second']:,} rules/s)")
        
        print(f"{'='*80}\n")
        
        return {
            'parsing': parsing_result,
            'lookups': lookup_result,
            'conversions': conversion_results
        }


# ============================================================================
# FALSE POSITIVE DETECTION
# ============================================================================

class FalsePositiveDetector:
    """Detect potential false positives in blocklist"""
    
    def __init__(self, parser):
        self.parser = parser
        self.known_safe_domains = [
            'google.com', 'facebook.com', 'twitter.com', 'amazon.com',
            'microsoft.com', 'apple.com', 'youtube.com', 'linkedin.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
            'paypal.com', 'ebay.com', 'netflix.com', 'cloudflare.com'
        ]
        
        self.cdn_patterns = [
            r'cdn\.',
            r'static\.',
            r'assets\.',
            r'media\.',
            r'img\.',
            r'images\.'
        ]
    
    def detect_false_positives(self) -> List[Dict]:
        """Detect potential false positives"""
        
        print("\n🔍 Detecting potential false positives...")
        
        false_positives = []
        
        for rule in self.parser.rules:
            if rule.rule_type.value != 'domain':
                continue
            
            pattern = rule.pattern.replace('*.', '')
            
            # Check against known safe domains
            for safe_domain in self.known_safe_domains:
                if pattern == safe_domain or pattern.endswith('.' + safe_domain):
                    false_positives.append({
                        'line': rule.line_number,
                        'pattern': rule.pattern,
                        'reason': f'Matches known safe domain: {safe_domain}',
                        'severity': 'high',
                        'suggestion': f'Review rule - {safe_domain} is generally considered safe'
                    })
            
            # Check for CDN/infrastructure patterns
            for cdn_pattern in self.cdn_patterns:
                if re.search(cdn_pattern, pattern):
                    false_positives.append({
                        'line': rule.line_number,
                        'pattern': rule.pattern,
                        'reason': 'Appears to be CDN/infrastructure domain',
                        'severity': 'medium',
                        'suggestion': 'CDN domains may break legitimate sites'
                    })
        
        print(f"   Found {len(false_positives)} potential false positives")
        
        return false_positives
    
    def print_false_positive_report(self, false_positives: Optional[List[Dict]] = None):
        """Print false positive report"""
        
        if false_positives is None:
            false_positives = self.detect_false_positives()
        
        if not false_positives:
            print("\n✅ No obvious false positives detected!")
            return
        
        print(f"\n{'='*80}")
        print("FALSE POSITIVE DETECTION REPORT")
        print(f"{'='*80}")
        print(f"Found {len(false_positives)} potential issues\n")
        
        for fp in false_positives:
            severity_icon = '🔴' if fp['severity'] == 'high' else '🟡'
            print(f"{severity_icon} [{fp['severity'].upper()}] Line {fp['line']}")
            print(f"   Pattern: {fp['pattern']}")
            print(f"   Reason: {fp['reason']}")
            print(f"   💡 {fp['suggestion']}")
            print()


# ============================================================================
# CLI INTEGRATION
# ============================================================================

def add_testing_commands(subparsers):
    """Add testing commands to CLI"""
    
    # Simulate traffic
    sim_parser = subparsers.add_parser('simulate',
                                       help='Simulate traffic through rules')
    sim_parser.add_argument('file', help='UBS file')
    sim_parser.add_argument('--requests', type=int, default=1000,
                           help='Number of requests to simulate')
    sim_parser.add_argument('--malicious-rate', type=float, default=0.1,
                           help='Rate of malicious traffic (0.0-1.0)')
    sim_parser.add_argument('--ad-rate', type=float, default=0.3,
                           help='Rate of ad/tracking traffic (0.0-1.0)')
    
    # Benchmark
    bench_parser = subparsers.add_parser('benchmark',
                                        help='Run performance benchmarks')
    bench_parser.add_argument('file', help='UBS file')
    bench_parser.add_argument('--quick', action='store_true',
                             help='Quick benchmark (fewer iterations)')
    
    # False positive detection
    fp_parser = subparsers.add_parser('check-false-positives',
                                     help='Detect false positives')
    fp_parser.add_argument('file', help='UBS file')


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    from ubs_parser import UBSParser
    
    example_ubs = """
! Title: Test Blocklist
! Version: 1.0.0

[Ads]
||doubleclick.net^
||googlesyndication.com^
ads.example.com

[Malware]
evil-malware.com :severity=critical
phishing-site.net :severity=high

[Tracking]
||analytics.google.com^ :third-party
||facebook.com/tr/*
"""
    
    print("=== Testing & Simulation Module Demo ===\n")
    
    parser = UBSParser()
    parser.parse(example_ubs)
    
    # 1. Enhanced URL Testing
    print("1. Enhanced URL Testing:")
    tester = EnhancedURLTester(parser)
    result = tester.test_url("https://ads.example.com/banner.gif", detailed=True)
    print(f"   URL: {result.url}")
    print(f"   Blocked: {result.blocked}")
    print(f"   Performance: {result.performance_ms}ms")
    
    # 2. Traffic Simulation
    print("\n2. Traffic Simulation:")
    simulator = TrafficSimulator(parser, tester)
    traffic = simulator.generate_traffic(num_requests=100, malicious_rate=0.2, ad_rate=0.3)
    analysis = simulator.analyze_traffic(traffic)
    simulator.print_traffic_report(analysis)
    
    # 3. Performance Benchmark
    print("\n3. Performance Benchmark:")
    benchmark = PerformanceBenchmark(parser)
    test_domains = ['example.com', 'google.com', 'ads.example.com', 'evil-malware.com']
    benchmark.run_full_benchmark(example_ubs, test_domains)
    
    # 4. False Positive Detection
    print("\n4. False Positive Detection:")
    fp_detector = FalsePositiveDetector(parser)
    fp_detector.print_false_positive_report()
    
    print("\n✅ Testing & Simulation module loaded successfully!")
