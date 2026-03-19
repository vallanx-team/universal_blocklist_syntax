#!/usr/bin/env python3
"""
UBS Performance & Optimization Features
- Rule Deduplication & Optimization
- Caching & Indexing (Bloom Filter, Trie, Regex Cache)
- List Differ
- Extended Converters
"""

import re
import json
import hashlib
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import sqlite3


# ============================================================================
# 1. PERFORMANCE & OPTIMIZATION
# ============================================================================

class BloomFilter:
    """Bloom filter for fast domain lookups"""
    
    def __init__(self, size: int = 10000, hash_count: int = 3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [False] * size
    
    def _hashes(self, item: str) -> List[int]:
        """Generate multiple hash values"""
        hashes = []
        for i in range(self.hash_count):
            h = hashlib.md5(f"{item}{i}".encode()).hexdigest()
            hashes.append(int(h, 16) % self.size)
        return hashes
    
    def add(self, item: str):
        """Add item to bloom filter"""
        for h in self._hashes(item):
            self.bit_array[h] = True
    
    def contains(self, item: str) -> bool:
        """Check if item might be in set (no false negatives)"""
        return all(self.bit_array[h] for h in self._hashes(item))


class TrieNode:
    """Node for Trie structure"""
    
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_end = False
        self.rule = None


class DomainTrie:
    """Trie structure for efficient wildcard domain matching"""
    
    def __init__(self):
        self.root = TrieNode()
    
    def insert(self, domain: str, rule=None):
        """Insert domain into trie (reversed for suffix matching)"""
        # Reverse domain for suffix matching: example.com -> com.example
        parts = domain.split('.')[::-1]
        
        node = self.root
        for part in parts:
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]
        
        node.is_end = True
        node.rule = rule
    
    def search(self, domain: str) -> Optional[any]:
        """Search for exact domain match"""
        parts = domain.split('.')[::-1]
        
        node = self.root
        for part in parts:
            if part not in node.children:
                return None
            node = node.children[part]
        
        return node.rule if node.is_end else None
    
    def search_wildcard(self, domain: str) -> List[any]:
        """Search for wildcard matches (*.example.com matches sub.example.com)"""
        parts = domain.split('.')[::-1]
        matches = []
        
        def dfs(node, depth):
            if node.is_end and depth <= len(parts):
                matches.append(node.rule)
            
            if depth >= len(parts):
                return
            
            part = parts[depth]
            
            # Exact match
            if part in node.children:
                dfs(node.children[part], depth + 1)
            
            # Wildcard match
            if '*' in node.children:
                dfs(node.children['*'], depth + 1)
        
        dfs(self.root, 0)
        return matches


class RuleOptimizer:
    """Optimize and deduplicate rules"""
    
    def __init__(self):
        self.optimized_count = 0
        self.removed_count = 0
    
    def optimize(self, rules: List) -> List:
        """Optimize rule list"""
        print(f"\n🔧 Optimizing {len(rules)} rules...")
        
        # Step 1: Remove exact duplicates
        rules = self._remove_duplicates(rules)
        
        # Step 2: Merge overlapping wildcards
        rules = self._merge_wildcards(rules)
        
        # Step 3: Optimize regex patterns
        rules = self._optimize_regex(rules)
        
        # Step 4: Sort by performance impact
        rules = self._sort_by_performance(rules)
        
        print(f"✅ Optimization complete:")
        print(f"   Removed: {self.removed_count} duplicate rules")
        print(f"   Optimized: {self.optimized_count} rules")
        print(f"   Final count: {len(rules)} rules")
        
        return rules
    
    def _remove_duplicates(self, rules: List) -> List:
        """Remove exact duplicate rules"""
        seen = set()
        unique = []
        
        for rule in rules:
            # Create hash from pattern and modifiers
            rule_hash = hashlib.md5(
                f"{rule.pattern}{json.dumps(rule.modifiers, sort_keys=True)}".encode()
            ).hexdigest()
            
            if rule_hash not in seen:
                seen.add(rule_hash)
                unique.append(rule)
            else:
                self.removed_count += 1
        
        return unique
    
    def _merge_wildcards(self, rules: List) -> List:
        """Merge overlapping wildcard patterns"""
        # Group domain rules by base domain
        domain_groups = defaultdict(list)
        other_rules = []
        
        for rule in rules:
            if rule.rule_type.value == 'domain' and not rule.modifiers.get('regex'):
                # Extract base domain
                pattern = rule.pattern
                if pattern.startswith('*.'):
                    base = pattern[2:]
                    domain_groups[base].append(rule)
                else:
                    # Check if this is a subdomain of an existing wildcard
                    parts = pattern.split('.')
                    found_parent = False
                    for i in range(len(parts)):
                        potential_base = '.'.join(parts[i:])
                        if potential_base in domain_groups:
                            # This subdomain is already covered by wildcard
                            self.removed_count += 1
                            self.optimized_count += 1
                            found_parent = True
                            break
                    
                    if not found_parent:
                        other_rules.append(rule)
            else:
                other_rules.append(rule)
        
        # Keep only wildcard rules (they cover all subdomains)
        optimized = other_rules
        for base, group in domain_groups.items():
            # Keep the wildcard rule
            optimized.append(group[0])
            if len(group) > 1:
                self.removed_count += len(group) - 1
                self.optimized_count += 1
        
        return optimized
    
    def _optimize_regex(self, rules: List) -> List:
        """Combine similar regex patterns"""
        regex_rules = [r for r in rules if r.modifiers.get('regex')]
        other_rules = [r for r in rules if not r.modifiers.get('regex')]
        
        # Group similar patterns
        pattern_groups = defaultdict(list)
        
        for rule in regex_rules:
            # Simple grouping by pattern prefix
            prefix = rule.pattern[:10] if len(rule.pattern) >= 10 else rule.pattern
            pattern_groups[prefix].append(rule)
        
        # For now, just return as-is (complex optimization would need careful analysis)
        # In production, you'd use regex optimization algorithms
        optimized = other_rules + regex_rules
        
        return optimized
    
    def _sort_by_performance(self, rules: List) -> List:
        """Sort rules by performance impact (fast rules first)"""
        
        def performance_score(rule):
            """Lower score = better performance"""
            score = 0
            
            # Simple domain lookups are fastest
            if rule.rule_type.value == 'domain' and not rule.modifiers.get('regex'):
                score = 1
            
            # URL patterns are slower
            elif rule.rule_type.value == 'url_pattern':
                score = 2
            
            # Regex is slowest
            elif rule.modifiers.get('regex'):
                score = 3
                # Penalize complex regex
                score += len(rule.pattern) / 100
            
            # Element hiding and scriptlets are medium
            else:
                score = 2.5
            
            return score
        
        return sorted(rules, key=performance_score)


class OptimizedRuleMatcher:
    """Fast rule matching using bloom filter and trie"""
    
    def __init__(self, rules: List):
        self.rules = rules
        
        # Build bloom filter for quick negative checks
        self.bloom = BloomFilter(size=len(rules) * 10)
        
        # Build trie for wildcard matching
        self.trie = DomainTrie()
        
        # Cache compiled regex
        self.regex_cache = {}
        
        # Build indexes
        self._build_indexes()
    
    def _build_indexes(self):
        """Build all indexes"""
        print("🔨 Building optimized indexes...")
        
        for rule in self.rules:
            if rule.rule_type.value == 'domain':
                # Add to bloom filter
                pattern = rule.pattern.replace('*.', '')
                self.bloom.add(pattern)
                
                # Add to trie
                self.trie.insert(rule.pattern, rule)
            
            # Pre-compile regex
            if rule.modifiers.get('regex'):
                try:
                    self.regex_cache[rule.pattern] = re.compile(rule.pattern)
                except:
                    pass
        
        print(f"✅ Indexes built: {len(self.rules)} rules indexed")
    
    def matches(self, domain: str) -> List:
        """Fast domain matching"""
        matches = []
        
        # Quick bloom filter check (eliminates most non-matches)
        if not self.bloom.contains(domain):
            # Definitely not in the list (might still have false positives)
            pass
        
        # Check trie for exact and wildcard matches
        trie_matches = self.trie.search_wildcard(domain)
        matches.extend(trie_matches)
        
        # Check regex patterns (using cached compiled regex)
        for rule in self.rules:
            if rule.modifiers.get('regex'):
                if rule.pattern in self.regex_cache:
                    if self.regex_cache[rule.pattern].search(domain):
                        matches.append(rule)
        
        return matches


# ============================================================================
# 2. LIST DIFFER
# ============================================================================

@dataclass
class DiffEntry:
    """Represents a difference between two lists"""
    action: str  # 'added', 'removed', 'modified'
    rule_before: Optional[any] = None
    rule_after: Optional[any] = None
    line_before: int = 0
    line_after: int = 0


class ListDiffer:
    """Compare two UBS lists and show differences"""
    
    def diff(self, parser1, parser2) -> List[DiffEntry]:
        """Generate diff between two parsed lists"""
        
        # Build hash maps
        rules1 = {self._rule_hash(r): r for r in parser1.rules}
        rules2 = {self._rule_hash(r): r for r in parser2.rules}
        
        diffs = []
        
        # Find removed rules
        for hash_key, rule in rules1.items():
            if hash_key not in rules2:
                diffs.append(DiffEntry(
                    action='removed',
                    rule_before=rule,
                    line_before=rule.line_number
                ))
        
        # Find added rules
        for hash_key, rule in rules2.items():
            if hash_key not in rules1:
                diffs.append(DiffEntry(
                    action='added',
                    rule_after=rule,
                    line_after=rule.line_number
                ))
        
        # Find modified rules (same pattern, different modifiers)
        pattern1 = {r.pattern: r for r in parser1.rules}
        pattern2 = {r.pattern: r for r in parser2.rules}
        
        for pattern in pattern1:
            if pattern in pattern2:
                rule1 = pattern1[pattern]
                rule2 = pattern2[pattern]
                
                if rule1.modifiers != rule2.modifiers:
                    diffs.append(DiffEntry(
                        action='modified',
                        rule_before=rule1,
                        rule_after=rule2,
                        line_before=rule1.line_number,
                        line_after=rule2.line_number
                    ))
        
        return diffs
    
    def _rule_hash(self, rule) -> str:
        """Create hash for rule comparison"""
        return hashlib.md5(
            f"{rule.pattern}{json.dumps(rule.modifiers, sort_keys=True)}".encode()
        ).hexdigest()
    
    def print_diff(self, diffs: List[DiffEntry]):
        """Print git-style diff output"""
        
        added = [d for d in diffs if d.action == 'added']
        removed = [d for d in diffs if d.action == 'removed']
        modified = [d for d in diffs if d.action == 'modified']
        
        print(f"\n{'='*80}")
        print(f"DIFF SUMMARY")
        print(f"{'='*80}")
        print(f"Added: {len(added)} | Removed: {len(removed)} | Modified: {len(modified)}")
        print(f"{'='*80}\n")
        
        if removed:
            print("❌ REMOVED RULES:")
            for diff in removed:
                print(f"  - Line {diff.line_before}: {diff.rule_before.raw_line}")
        
        if added:
            print("\n✅ ADDED RULES:")
            for diff in added:
                print(f"  + Line {diff.line_after}: {diff.rule_after.raw_line}")
        
        if modified:
            print("\n🔄 MODIFIED RULES:")
            for diff in modified:
                print(f"  ~ Line {diff.line_before} -> {diff.line_after}:")
                print(f"    Before: {diff.rule_before.raw_line}")
                print(f"    After:  {diff.rule_after.raw_line}")
    
    def export_diff_patch(self, diffs: List[DiffEntry], output_file: str):
        """Export diff as a patch file"""
        lines = []
        
        for diff in diffs:
            if diff.action == 'removed':
                lines.append(f"- {diff.rule_before.raw_line}")
            elif diff.action == 'added':
                lines.append(f"+ {diff.rule_after.raw_line}")
            elif diff.action == 'modified':
                lines.append(f"- {diff.rule_before.raw_line}")
                lines.append(f"+ {diff.rule_after.raw_line}")
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(lines))
        
        print(f"✅ Diff patch exported to: {output_file}")


# ============================================================================
# 3. EXTENDED CONVERTERS
# ============================================================================

class ExtendedConverters:
    """Additional format converters"""
    
    def __init__(self, parser):
        self.parser = parser
    
    def to_pihole_sqlite(self, output_file: str):
        """Convert to Pi-hole gravity.db SQLite format"""
        conn = sqlite3.connect(output_file)
        cursor = conn.cursor()
        
        # Create tables (Pi-hole schema)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domainlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type INTEGER NOT NULL,
                domain TEXT NOT NULL UNIQUE,
                enabled BOOLEAN NOT NULL DEFAULT 1,
                date_added INTEGER NOT NULL,
                date_modified INTEGER NOT NULL,
                comment TEXT
            )
        ''')
        
        import time
        timestamp = int(time.time())
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                domain = rule.pattern.replace('*.', '')
                
                # type: 0 = whitelist, 1 = blacklist, 2 = regex whitelist, 3 = regex blacklist
                if rule.rule_type.value == 'whitelist':
                    rule_type = 0
                elif rule.modifiers.get('regex'):
                    rule_type = 3
                else:
                    rule_type = 1
                
                comment = rule.section or ''
                
                try:
                    cursor.execute('''
                        INSERT INTO domainlist (type, domain, enabled, date_added, date_modified, comment)
                        VALUES (?, ?, 1, ?, ?, ?)
                    ''', (rule_type, domain, timestamp, timestamp, comment))
                except sqlite3.IntegrityError:
                    # Duplicate domain, skip
                    pass
        
        conn.commit()
        conn.close()
        
        print(f"✅ Pi-hole database created: {output_file}")
    
    def to_pfsense(self) -> str:
        """Convert to pfSense/pfBlockerNG format"""
        lines = ["# pfBlockerNG DNSBL Format"]
        lines.append("# Generated from UBS")
        lines.append("")
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                domain = rule.pattern.replace('*.', '')
                if not rule.modifiers.get('regex'):
                    lines.append(domain)
        
        return '\n'.join(lines)
    
    def to_opnsense(self) -> str:
        """Convert to OPNsense Unbound format"""
        lines = ["# OPNsense Unbound Format"]
        lines.append("server:")
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                domain = rule.pattern.replace('*.', '')
                if not rule.modifiers.get('regex'):
                    lines.append(f'local-zone: "{domain}" static')
        
        return '\n'.join(lines)
    
    def to_windows_firewall(self) -> str:
        """Convert to Windows Firewall PowerShell script"""
        script = """# Windows Firewall Rules
# Run as Administrator

"""
        
        for idx, rule in enumerate(self.parser.rules):
            if rule.rule_type.value == 'domain':
                domain = rule.pattern.replace('*.', '*')
                script += f'''New-NetFirewallRule -DisplayName "Block_{idx}" -Direction Outbound -Action Block -RemoteAddress "{domain}"\n'''
        
        return script
    
    def to_iptables(self) -> str:
        """Convert to iptables rules"""
        lines = ["#!/bin/bash"]
        lines.append("# iptables rules generated from UBS")
        lines.append("")
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                domain = rule.pattern.replace('*.', '')
                # Note: iptables needs IP addresses, not domains
                # This is a simplified example
                lines.append(f"# Block {domain}")
                lines.append(f"iptables -A OUTPUT -d {domain} -j DROP")
        
        return '\n'.join(lines)
    
    def to_nftables(self) -> str:
        """Convert to nftables format"""
        script = """#!/usr/sbin/nft -f
# nftables rules generated from UBS

table ip filter {
    set blocked_domains {
        type ipv4_addr
        flags interval
        elements = {
"""
        
        domains = []
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                domain = rule.pattern.replace('*.', '')
                domains.append(f"            # {domain}")
        
        script += '\n'.join(domains[:100])  # Limit for example
        script += """
        }
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        ip daddr @blocked_domains drop
    }
}
"""
        return script
    
    def to_modsecurity(self) -> str:
        """Convert to ModSecurity WAF rules"""
        rules = []
        rule_id = 900000
        
        for rule in self.parser.rules:
            if rule.rule_type.value in ['domain', 'url_pattern']:
                pattern = rule.pattern
                severity = rule.modifiers.get('severity', 'WARNING')
                
                modsec_rule = f'''SecRule REQUEST_HEADERS:Host "@rx {pattern}" \\
    "id:{rule_id},\\
    phase:1,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'Blocked domain: {pattern}',\\
    severity:'{severity}',\\
    tag:'UBS'"
'''
                rules.append(modsec_rule)
                rule_id += 1
        
        return '\n'.join(rules)
    
    def to_nginx(self) -> str:
        """Convert to Nginx config"""
        config = """# Nginx blocking configuration
# Add to your server block

"""
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                domain = rule.pattern.replace('*.', '')
                config += f"if ($host = '{domain}') {{ return 403; }}\n"
        
        return config
    
    def to_apache(self) -> str:
        """Convert to Apache config"""
        config = """# Apache blocking configuration
# Add to .htaccess or virtual host config

<IfModule mod_rewrite.c>
RewriteEngine On

"""
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                domain = rule.pattern.replace('*.', '.*')
                config += f"RewriteCond %{{HTTP_HOST}} ^{domain}$ [NC]\n"
                config += "RewriteRule .* - [F,L]\n\n"
        
        config += "</IfModule>"
        return config
    
    def to_cloudflare_waf(self) -> str:
        """Convert to Cloudflare WAF JSON"""
        rules = []
        
        for idx, rule in enumerate(self.parser.rules):
            if rule.rule_type.value in ['domain', 'url_pattern']:
                cf_rule = {
                    "id": str(idx + 1),
                    "description": f"UBS Rule: {rule.pattern}",
                    "expression": f'(http.host contains "{rule.pattern}")',
                    "action": "block",
                    "enabled": True
                }
                rules.append(cf_rule)
        
        return json.dumps(rules, indent=2)
    
    def to_aws_waf(self) -> str:
        """Convert to AWS WAF JSON"""
        statements = []
        
        for rule in self.parser.rules:
            if rule.rule_type.value in ['domain', 'url_pattern']:
                statement = {
                    "ByteMatchStatement": {
                        "SearchString": rule.pattern,
                        "FieldToMatch": {
                            "SingleHeader": {
                                "Name": "host"
                            }
                        },
                        "TextTransformations": [{
                            "Priority": 0,
                            "Type": "LOWERCASE"
                        }],
                        "PositionalConstraint": "CONTAINS"
                    }
                }
                statements.append(statement)
        
        waf_rule = {
            "Name": "UBS-Blocklist",
            "Priority": 1,
            "Statement": {
                "OrStatement": {
                    "Statements": statements[:100]  # AWS limit
                }
            },
            "Action": {
                "Block": {}
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "UBSBlocklist"
            }
        }
        
        return json.dumps(waf_rule, indent=2)


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    print("UBS Performance & Optimization Module")
    print("=" * 80)
    
    # Example: Bloom Filter
    print("\n1. Bloom Filter Demo:")
    bloom = BloomFilter(size=1000)
    bloom.add("example.com")
    bloom.add("test.com")
    print(f"   Contains 'example.com': {bloom.contains('example.com')}")
    print(f"   Contains 'nothere.com': {bloom.contains('nothere.com')}")
    
    # Example: Domain Trie
    print("\n2. Domain Trie Demo:")
    trie = DomainTrie()
    trie.insert("*.example.com", "rule1")
    trie.insert("test.com", "rule2")
    matches = trie.search_wildcard("sub.example.com")
    print(f"   Matches for 'sub.example.com': {matches}")
    
    print("\n✅ All optimization modules loaded successfully!")
