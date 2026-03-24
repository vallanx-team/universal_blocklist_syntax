#!/usr/bin/env python3
"""
Universal Blocklist Syntax (UBS) - Advanced Features
- Rule Validator & Tester
- List Merger
- Browser Extension Generator
- CLI with Batch Processing
"""

import re
import json
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse
import hashlib


# ============================================================================
# 1. RULE VALIDATOR & TESTER
# ============================================================================

class ValidationIssue(Enum):
    """Types of validation issues"""
    SYNTAX_ERROR = "syntax_error"
    INVALID_REGEX = "invalid_regex"
    SLOW_REGEX = "slow_regex"
    DUPLICATE_RULE = "duplicate_rule"
    CONFLICTING_RULE = "conflicting_rule"
    DEPRECATED_SYNTAX = "deprecated_syntax"
    MISSING_METADATA = "missing_metadata"
    INVALID_MODIFIER = "invalid_modifier"
    DEAD_DOMAIN = "dead_domain"
    WARNING = "warning"
    INFO = "info"


@dataclass
class Issue:
    """Validation issue"""
    type: ValidationIssue
    severity: str  # 'error', 'warning', 'info'
    line_number: int
    rule: str
    message: str
    suggestion: Optional[str] = None


class RuleValidator:
    """Validates UBS rules for correctness and performance"""
    
    def __init__(self, strict_mode: bool = False, check_dns: bool = False):
        self.strict_mode = strict_mode
        self.check_dns = check_dns
        self.issues: List[Issue] = []
        
        # Valid modifiers
        self.valid_modifiers = {
            # Basis
            'action', 'severity', 'category', 'log', 'block', 'allow',
    
            # AdBlock/uBlock
            'third-party', 'first-party', 'script', 'image', 'stylesheet',
            'domain', 'subdocument', 'xmlhttprequest', 'websocket',
            'webrtc', 'popup', 'popunder', 'document', 'font', 'media',
            'object', 'ping', 'other', 'important', 'badfilter',
            'genericblock', 'generichide', 'specifichide',
    
            # Proxy & Routing
            'proxy', 'fallback', 'redirect', 'redirect-rule',
    
            # Header Manipulation
            'remove-header', 'csp',
    
            # Formats
            'empty', 'mp4', 'inline-script', 'inline-font',
    
            # Metadata
            'msg', 'reason', 'all',
    
            # IDS/Suricata
            'protocol', 'port', 'content', 'sid', 'rev', 'classtype',
    
            # Rate Limiting
            'rate', 'limit', 'burst', 'timeout',
    
            # CSS/JS
            'selector', 'scriptlet',
    
            # Network
            'ttl', 'priority', 'weight', 'host', 'path', 'query',
    
            # Custom
            'comment', 'expires', 'updated'
        }
        
        # Performance-critical regex patterns
        self.slow_regex_patterns = [
            r'\.\*\.\*',  # Nested wildcards
            r'\(.*\)\+',  # Greedy quantifiers
            r'(?:.*){',   # Complex repetition
        ]
    
    def validate(self, parser) -> List[Issue]:
        """Validate all rules in parser"""
        self.issues = []
        
        # Check metadata
        if not parser.metadata.title and self.strict_mode:
            self.issues.append(Issue(
                type=ValidationIssue.MISSING_METADATA,
                severity='warning',
                line_number=0,
                rule='',
                message='Missing list title',
                suggestion='Add: ! Title: Your List Name'
            ))
        
        # Track duplicates
        seen_rules = {}
        
        for rule in parser.rules:
            # Skip comments
            if rule.rule_type.name == 'COMMENT':
                continue
            
            # Check for duplicates
            rule_key = rule.pattern.lower()
            if rule_key in seen_rules:
                self.issues.append(Issue(
                    type=ValidationIssue.DUPLICATE_RULE,
                    severity='warning',
                    line_number=rule.line_number,
                    rule=rule.raw_line,
                    message=f'Duplicate rule (first seen at line {seen_rules[rule_key]})',
                    suggestion='Remove duplicate'
                ))
            else:
                seen_rules[rule_key] = rule.line_number
            
            # Validate regex patterns
            if rule.pattern.startswith("~"):
                self._validate_regex(rule)
            
            # Validate modifiers
            self._validate_modifiers(rule)
            
            # Check DNS (if enabled)
            if self.check_dns and rule.rule_type.name in ['DOMAIN', 'DOMAIN_WILDCARD']:
                self._check_domain_dns(rule)
        
        return self.issues
    
    def _validate_regex(self, rule):
        """Validate regex pattern"""
        try:
            # Try to compile regex
            re.compile(rule.pattern)
            
            # Check for slow patterns
            for slow_pattern in self.slow_regex_patterns:
                if re.search(slow_pattern, rule.pattern):
                    self.issues.append(Issue(
                        type=ValidationIssue.SLOW_REGEX,
                        severity='warning',
                        line_number=rule.line_number,
                        rule=rule.raw_line,
                        message='Potentially slow regex pattern detected',
                        suggestion='Simplify regex or use domain matching'
                    ))
                    break
        
        except re.error as e:
            self.issues.append(Issue(
                type=ValidationIssue.INVALID_REGEX,
                severity='error',
                line_number=rule.line_number,
                rule=rule.raw_line,
                message=f'Invalid regex: {str(e)}',
                suggestion='Fix regex syntax'
            ))
    
    def _validate_modifiers(self, rule):
        """Validate rule modifiers"""
        # for modifier_name in rule.modifiers.keys():
        for modifier_name in rule.modifiers:
    
            # Skip numeric modifiers (port numbers)
            if modifier_name.isdigit():
                continue

            if modifier_name not in self.valid_modifiers:
                self.issues.append(Issue(
                    type=ValidationIssue.INVALID_MODIFIER,
                    severity='error' if self.strict_mode else 'warning',
                    line_number=rule.line_number,
                    rule=rule.raw_line,
                    message=f'Unknown modifier: {modifier_name}',
                    suggestion=f'Valid modifiers: {", ".join(sorted(self.valid_modifiers))}'
                ))
    
    def _check_domain_dns(self, rule):
        """Check if domain resolves (basic check)"""
        try:
            import socket
            domain = rule.pattern.replace('*.', '').strip()
            socket.gethostbyname(domain)
        except socket.gaierror:
            self.issues.append(Issue(
                type=ValidationIssue.DEAD_DOMAIN,
                severity='info',
                line_number=rule.line_number,
                rule=rule.raw_line,
                message='Domain does not resolve',
                suggestion='Verify domain is still active'
            ))
        except Exception:
            pass  # Skip DNS check on error
    
    def get_issues_by_severity(self, severity: str) -> List[Issue]:
        """Get issues filtered by severity"""
        return [i for i in self.issues if i.severity == severity]
    
    def has_errors(self) -> bool:
        """Check if there are any errors"""
        return any(i.severity == 'error' for i in self.issues)
    
    def print_report(self):
        """Print validation report"""
        if not self.issues:
            print("✅ No issues found!")
            return
        
        errors = self.get_issues_by_severity('error')
        warnings = self.get_issues_by_severity('warning')
        infos = self.get_issues_by_severity('info')
        
        print(f"\n{'='*80}")
        print(f"VALIDATION REPORT")
        print(f"{'='*80}")
        print(f"Errors: {len(errors)} | Warnings: {len(warnings)} | Info: {len(infos)}")
        print(f"{'='*80}\n")
        
        for issue in self.issues:
            icon = {'error': '❌', 'warning': '⚠️', 'info': 'ℹ️'}[issue.severity]
            print(f"{icon} Line {issue.line_number}: {issue.message}")
            print(f"   Rule: {issue.rule}")
            if issue.suggestion:
                print(f"   💡 Suggestion: {issue.suggestion}")
            print()
    
    def get_dns_check_summary(self) -> Dict[str, int]:
        """Get DNS check summary"""
        dead_domains = [i for i in self.issues if i.type == ValidationIssue.DEAD_DOMAIN]
        return {
            'checked': len([i for i in self.issues if i.type in [ValidationIssue.DEAD_DOMAIN]]),
            'dead': len(dead_domains)
        }


@dataclass
class TestResult:
    """Result of URL test"""
    url: str
    blocked: bool
    rule: Optional[object] = None
    reason: str = ""
    modifiers_applied: List[str] = field(default_factory=list)
    performance_ms: float = 0.0


class URLTester:
    """Test URLs against UBS rules"""
    
    def __init__(self, parser):
        self.parser = parser
        self.domain_rules = []
        self.url_rules = []
        self.regex_rules = []
        self.whitelist_rules = []
        
        # Organize rules by type for faster matching
        for rule in parser.rules:
            if rule.rule_type.name == "WHITELIST":
                self.whitelist_rules.append(rule)
            elif rule.rule_type.name in ['DOMAIN', 'DOMAIN_WILDCARD']:
                self.domain_rules.append(rule)
            elif rule.rule_type.name == 'URL_PATTERN':
                self.url_rules.append(rule)
            elif rule.pattern.startswith("~"):
                self.regex_rules.append(rule)
    
    def test_url(self, url: str) -> TestResult:
        """Test single URL"""
        import time
        start = time.time()
        
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        # Check whitelist first
        for rule in self.whitelist_rules:
            if self._matches_rule(url, domain, path, rule):
                elapsed = (time.time() - start) * 1000
                return TestResult(
                    url=url,
                    blocked=False,
                    rule=rule,
                    reason="Whitelisted",
                    modifiers_applied=rule.modifiers,
                    performance_ms=elapsed
                )
        
        # Check domain rules
        for rule in self.domain_rules:
            if self._matches_rule(url, domain, path, rule):
                elapsed = (time.time() - start) * 1000
                return TestResult(
                    url=url,
                    blocked=True,
                    rule=rule,
                    reason="Domain blocked",
                    modifiers_applied=list(rule.modifiers.keys()),
                    performance_ms=elapsed
                )
        
        # Check URL patterns
        for rule in self.url_rules:
            if self._matches_rule(url, domain, path, rule):
                elapsed = (time.time() - start) * 1000
                return TestResult(
                    url=url,
                    blocked=True,
                    rule=rule,
                    reason="URL pattern matched",
                    modifiers_applied=rule.modifiers,
                    performance_ms=elapsed
                )
        
        # Check regex
        for rule in self.regex_rules:
            if self._matches_rule(url, domain, path, rule):
                elapsed = (time.time() - start) * 1000
                return TestResult(
                    url=url,
                    blocked=True,
                    rule=rule,
                    reason="Regex matched",
                    modifiers_applied=rule.modifiers,
                    performance_ms=elapsed
                )
        
        elapsed = (time.time() - start) * 1000
        return TestResult(
            url=url,
            blocked=False,
            reason="No matching rule",
            performance_ms=elapsed
        )
    
    def _matches_rule(self, url: str, domain: str, path: str, rule) -> bool:
        """Check if URL matches rule"""
        if rule.rule_type.name == 'DOMAIN':
            return domain == rule.pattern or domain.endswith('.' + rule.pattern)
        
        elif rule.rule_type.name == 'DOMAIN_WILDCARD':
            pattern = rule.pattern.replace('*.', '')
            return domain == pattern or domain.endswith('.' + pattern)
        
        elif rule.rule_type.name == 'URL_PATTERN':
            # AdBlock-style URL pattern
            pattern = rule.pattern
            pattern = pattern.replace('||', '')
            pattern = pattern.replace('^', '[/?]')
            pattern = pattern.replace('*', '.*')
            try:
                return re.search(pattern, url) is not None
            except:
                return False
        
        elif rule.pattern.startswith("~"):
            try:
                return re.search(rule.pattern, url) is not None
            except:
                return False
        
        return False
    
    def batch_test(self, urls: List[str]) -> List[TestResult]:
        """Test multiple URLs"""
        return [self.test_url(url) for url in urls]
    
    def print_results(self, results: List[TestResult]):
        """Print test results"""
        blocked = [r for r in results if r.blocked]
        allowed = [r for r in results if not r.blocked]
        
        print(f"\n{'='*80}")
        print(f"TEST RESULTS")
        print(f"{'='*80}")
        print(f"Total: {len(results)} | Blocked: {len(blocked)} | Allowed: {len(allowed)}")
        print(f"{'='*80}\n")
        
        for result in results:
            icon = '🚫' if result.blocked else '✅'
            print(f"{icon} {result.url}")
            print(f"   Status: {'BLOCKED' if result.blocked else 'ALLOWED'}")
            print(f"   Reason: {result.reason}")
            if result.rule:
                print(f"   Rule: {result.rule.raw_line}")
            print(f"   Performance: {result.performance_ms:.2f}ms")
            print()


# ============================================================================
# 2. LIST MERGER
# ============================================================================

class ListMerger:
    """Merge multiple UBS lists"""
    
    def __init__(self):
        self.deduplicate = True
        self.preserve_comments = True
        self.conflict_strategy = 'first'  # 'first', 'last', 'strict', 'merge'
    
    def merge(self, parsers: Dict[str, object], priority_order: Optional[List[str]] = None) -> object:
        """
        Merge multiple parsers
        
        Args:
            parsers: Dict of {name: parser_object}
            priority_order: List of names in priority order (highest first)
        """
        from ubs_parser import UBSParser, ParsedRule, Metadata
        
        if not parsers:
            raise ValueError("No parsers provided")
        
        # Create new merged parser
        merged = UBSParser()
        merged.metadata = Metadata()
        
        # Set priority order
        if not priority_order:
            priority_order = list(parsers.keys())
        
        # Merge metadata from first parser
        first_parser = parsers[priority_order[0]]
        merged.metadata.title = f"Merged: {', '.join(parsers.keys())}"
        merged.metadata.version = "1.0.0"
        merged.metadata.updated = first_parser.metadata.updated
        
        # Track seen rules for deduplication
        seen_rules = {}  # pattern -> rule
        
        # Merge rules based on priority
        for source_name in priority_order:
            if source_name not in parsers:
                continue
            
            parser = parsers[source_name]
            
            for rule in parser.rules:
                rule_key = rule.pattern.lower()
                
                if self.deduplicate:
                    if rule_key in seen_rules:
                        # Handle conflict
                        if self.conflict_strategy == 'first':
                            continue  # Keep first occurrence
                        elif self.conflict_strategy == 'last':
                            seen_rules[rule_key] = rule  # Replace with last
                        elif self.conflict_strategy == 'strict':
                            # Check if rules are identical
                            existing = seen_rules[rule_key]
                            if existing.raw_line != rule.raw_line:
                                print(f"⚠️  Conflict: {rule.pattern}")
                                print(f"   Source 1: {existing.raw_line}")
                                print(f"   Source 2: {rule.raw_line}")
                        elif self.conflict_strategy == 'merge':
                            # Merge modifiers
                            existing = seen_rules[rule_key]
                            merged_modifiers = list(set(existing.modifiers + rule.modifiers))
                            existing.modifiers = merged_modifiers
                    else:
                        seen_rules[rule_key] = rule
                else:
                    # No deduplication, just add
                    merged.rules.append(rule)
        
        # Add deduplicated rules if enabled
        if self.deduplicate:
            merged.rules = list(seen_rules.values())
        
        return merged
    
    def export_merged(self, merged_parser, output_file: str):
        """Export merged list to file"""
        lines = []
        
        # Add metadata
        if merged_parser.metadata.title:
            lines.append(f"! Title: {merged_parser.metadata.title}")
        if merged_parser.metadata.version:
            lines.append(f"! Version: {merged_parser.metadata.version}")
        lines.append(f"! Updated: {merged_parser.metadata.updated}")
        lines.append("")
        
        # Add rules
        current_section = None
        for rule in merged_parser.rules:
            # Add section headers
            if rule.section != current_section and rule.section:
                lines.append(f"\n[{rule.section}]")
                current_section = rule.section
            
            lines.append(rule.raw_line)
        
        # Write file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        print(f"✅ Merged list saved: {output_file}")


# ============================================================================
# 3. BROWSER EXTENSION GENERATOR
# ============================================================================

class ExtensionGenerator:
    """Generate browser extensions from UBS rules"""
    
    def __init__(self, parser):
        self.parser = parser
    
    def generate_chrome_extension(self, output_dir: str):
        """Generate Chrome/Chromium extension"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate manifest.json
        manifest = {
            "manifest_version": 3,
            "name": self.parser.metadata.title or "UBS Blocker",
            "version": self.parser.metadata.version or "1.0.0",
            "description": "Content blocker generated from UBS rules",
            "permissions": ["declarativeNetRequest", "storage"],
            "host_permissions": ["<all_urls>"],
            "background": {
                "service_worker": "background.js"
            },
            "declarative_net_request": {
                "rule_resources": [{
                    "id": "ruleset_1",
                    "enabled": True,
                    "path": "rules.json"
                }]
            },
            "icons": {
                "16": "icon16.png",
                "48": "icon48.png",
                "128": "icon128.png"
            }
        }
        
        with open(output_path / "manifest.json", 'w') as f:
            json.dump(manifest, f, indent=2)
        
        # Generate rules.json (Declarative Net Request format)
        rules = []
        rule_id = 1
        
        for rule in self.parser.rules:
            if rule.rule_type.name == 'COMMENT' or rule.rule_type.name == "WHITELIST":
                continue
            
            dnr_rule = {
                "id": rule_id,
                "priority": 1,
                "action": {"type": "block"},
                "condition": {}
            }
            

            # Convert UBS rule to DNR format
            if rule.rule_type.name == 'DOMAIN':
                dnr_rule["condition"]["urlFilter"] = f"||{rule.pattern}^"
            elif rule.rule_type.name == 'DOMAIN_WILDCARD':
                dnr_rule["condition"]["urlFilter"] = rule.pattern.replace('*.', '*.')
            elif rule.rule_type.name == 'URL_PATTERN':
                dnr_rule["condition"]["urlFilter"] = rule.pattern
            
            # Add resource types if specified
            resource_types = []
            # for mod in rule.modifiers.keys():
            for mod in rule.modifiers:
                if mod in ['script', 'image', 'stylesheet', 'font', 'media']:
                    resource_types.append(mod)
            
            if resource_types:
                dnr_rule["condition"]["resourceTypes"] = resource_types
            else:
                dnr_rule["condition"]["resourceTypes"] = ["main_frame", "sub_frame"]
            
            rules.append(dnr_rule)
            rule_id += 1
        
        with open(output_path / "rules.json", 'w') as f:
            json.dump(rules, f, indent=2)
        
        # Generate background.js
        background_js = """
chrome.runtime.onInstalled.addListener(() => {
  console.log('UBS Blocker extension installed');
});

chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
  console.log('Blocked:', info.request.url);
});
"""
        
        with open(output_path / "background.js", 'w') as f:
            f.write(background_js)
        
        print(f"✅ Chrome extension generated: {output_dir}")
        print(f"   Load in Chrome: chrome://extensions/ → Load unpacked → {output_dir}")
    
    def generate_firefox_extension(self, output_dir: str):
        """Generate Firefox extension"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Similar to Chrome but with Firefox-specific manifest
        manifest = {
            "manifest_version": 2,
            "name": self.parser.metadata.title or "UBS Blocker",
            "version": self.parser.metadata.version or "1.0.0",
            "description": "Content blocker generated from UBS rules",
            "permissions": ["webRequest", "webRequestBlocking", "<all_urls>"],
            "background": {
                "scripts": ["background.js"]
            }
        }
        
        with open(output_path / "manifest.json", 'w') as f:
            json.dump(manifest, f, indent=2)
        
        # Generate background.js with webRequest API
        background_js = self._generate_firefox_background()
        
        with open(output_path / "background.js", 'w') as f:
            f.write(background_js)
        
        print(f"✅ Firefox extension generated: {output_dir}")
    
    def _generate_firefox_background(self) -> str:
        """Generate Firefox background script"""
        # Convert rules to JavaScript patterns
        patterns = []
        for rule in self.parser.rules:
            if rule.rule_type.name != 'COMMENT' and not rule.rule_type.name == "WHITELIST":
                pattern = rule.pattern.replace('*.', '*.')
                patterns.append(f'  "{pattern}"')
        
        return f"""
const blockedPatterns = [
{chr(10).join(patterns)}
];

function shouldBlock(url) {{
  for (let pattern of blockedPatterns) {{
    if (url.includes(pattern)) {{
      return true;
    }}
  }}
  return false;
}}

browser.webRequest.onBeforeRequest.addListener(
  function(details) {{
    if (shouldBlock(details.url)) {{
      console.log('Blocked:', details.url);
      return {{cancel: true}};
    }}
  }},
  {{urls: ["<all_urls>"]}},
  ["blocking"]
);
"""


# ============================================================================
# 4. CLI WITH BATCH PROCESSING
# ============================================================================

class UBSCLI:
    """Command-line interface for UBS tools"""
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description='Universal Blocklist Syntax (UBS) Tools',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self._setup_commands()
    
    def _setup_commands(self):
        """Setup CLI commands"""
        subparsers = self.parser.add_subparsers(dest='command', help='Commands')
        
        # Validate command
        validate_parser = subparsers.add_parser('validate', help='Validate UBS file')
        validate_parser.add_argument('file', help='UBS file to validate')
        validate_parser.add_argument('--strict', action='store_true', help='Strict mode')
        validate_parser.add_argument('--check-dns', action='store_true', help='Check DNS resolution')
        
        # Test command
        test_parser = subparsers.add_parser('test', help='Test URL against rules')
        test_parser.add_argument('file', help='UBS file')
        test_parser.add_argument('url', help='URL to test')
        test_parser.add_argument('--batch', help='File with URLs (one per line)')
        
        # Merge command
        merge_parser = subparsers.add_parser('merge', help='Merge multiple UBS files')
        merge_parser.add_argument('files', nargs='+', help='UBS files to merge')
        merge_parser.add_argument('-o', '--output', required=True, help='Output file')
        merge_parser.add_argument('--no-dedupe', action='store_true', help='Disable deduplication')
        
        # Extension command
        ext_parser = subparsers.add_parser('extension', help='Generate browser extension')
        ext_parser.add_argument('file', help='UBS file')
        ext_parser.add_argument('--browser', choices=['chrome', 'firefox'], required=True)
        ext_parser.add_argument('-o', '--output', required=True, help='Output directory')
        
        # Convert command
        convert_parser = subparsers.add_parser('convert', help='Convert UBS to other formats')
        convert_parser.add_argument('file', help='UBS file')
        convert_parser.add_argument('--format', required=True, 
                                   choices=['hosts', 'dnsmasq', 'pihole', 'adblock', 'json'])
        convert_parser.add_argument('-o', '--output', required=True, help='Output file')
        
        # Stats command
        stats_parser = subparsers.add_parser('stats', help='Show statistics')
        stats_parser.add_argument('file', help='UBS file')
    
    def run(self, args=None):
        """Run CLI"""
        parsed_args = self.parser.parse_args(args)
        
        if not parsed_args.command:
            self.parser.print_help()
            return
        
        # Route to appropriate command handler
        command_map = {
            'validate': self.cmd_validate,
            'test': self.cmd_test,
            'merge': self.cmd_merge,
            'extension': self.cmd_extension,
            'convert': self.cmd_convert,
            'stats': self.cmd_stats
        }
        
        handler = command_map.get(parsed_args.command)
        if handler:
            handler(parsed_args)
        else:
            print(f"Unknown command: {parsed_args.command}")
    
    def cmd_validate(self, args):
        """Validate command"""
        from ubs_parser import UBSParser
        
        print(f"Validating: {args.file}")
        
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        parser = UBSParser()
        parser.parse(content)
        
        validator = RuleValidator(strict_mode=args.strict, check_dns=args.check_dns)
        validator.validate(parser)
        validator.print_report()
        
        if validator.has_errors():
            sys.exit(1)
    
    def cmd_test(self, args):
        """Test command"""
        from ubs_parser import UBSParser
        
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        parser = UBSParser()
        parser.parse(content)
        
        tester = URLTester(parser)
        
        if args.batch:
            # Batch test
            with open(args.batch, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            results = tester.batch_test(urls)
            tester.print_results(results)
        else:
            # Single test
            result = tester.test_url(args.url)
            tester.print_results([result])
    
    def cmd_merge(self, args):
        """Merge command"""
        from ubs_parser import UBSParser
        
        print(f"Merging {len(args.files)} lists...")
        
        parsers = {}
        for file_path in args.files:
            name = Path(file_path).stem
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            parser = UBSParser()
            parser.parse(content)
            parsers[name] = parser
        
        merger = ListMerger()
        merger.deduplicate = not args.no_dedupe
        
        merged = merger.merge(parsers)
        merger.export_merged(merged, args.output)
    
    def cmd_extension(self, args):
        """Extension command"""
        from ubs_parser import UBSParser
        
        print(f"Generating {args.browser} extension...")
        
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        parser = UBSParser()
        parser.parse(content)
        
        generator = ExtensionGenerator(parser)
        
        if args.browser == 'chrome':
            generator.generate_chrome_extension(args.output)
        elif args.browser == 'firefox':
            generator.generate_firefox_extension(args.output)
    
    def cmd_convert(self, args):
        """Convert command"""
        from ubs_parser import UBSParser
        
        print(f"Converting to {args.format}...")
        
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        parser = UBSParser()
        parser.parse(content)
        
        # Simple format conversion
        output_lines = []
        
        if args.format == 'hosts':
            for rule in parser.rules:
                if rule.rule_type.name in ['DOMAIN', 'DOMAIN_WILDCARD']:
                    domain = rule.pattern.replace('*.', '')
                    output_lines.append(f"0.0.0.0 {domain}")
        
        elif args.format == 'dnsmasq':
            for rule in parser.rules:
                if rule.rule_type.name in ['DOMAIN', 'DOMAIN_WILDCARD']:
                    output_lines.append(f"address=/{rule.pattern}/")
        
        elif args.format == 'adblock':
            for rule in parser.rules:
                if rule.rule_type.name == 'URL_PATTERN':
                    output_lines.append(rule.raw_line)
                elif rule.rule_type.name in ['DOMAIN', 'DOMAIN_WILDCARD']:
                    output_lines.append(f"||{rule.pattern}^")
        
        elif args.format == 'json':
            data = {
                'metadata': {
                    'title': parser.metadata.title,
                    'version': parser.metadata.version
                },
                'rules': [
                    {
                        'pattern': rule.pattern,
                        'type': rule.rule_type.name,
                        'modifiers': rule.modifiers
                    }
                    for rule in parser.rules if rule.rule_type.name != 'COMMENT'
                ]
            }
            output_lines = [json.dumps(data, indent=2)]
        
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write('\n'.join(output_lines))
        
        print(f"✅ Converted to {args.format}: {args.output}")
    
    def cmd_stats(self, args):
        """Stats command"""
        from ubs_parser import UBSParser
        
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        parser = UBSParser()
        parser.parse(content)
        
        # Count by type
        type_counts = {}
        for rule in parser.rules:
            type_name = rule.rule_type.name
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        print(f"\n{'='*80}")
        print(f"STATISTICS: {args.file}")
        print(f"{'='*80}")
        print(f"Title: {parser.metadata.title or 'N/A'}")
        print(f"Version: {parser.metadata.version or 'N/A'}")
        print(f"Total Rules: {len(parser.rules)}")
        print(f"\nRules by Type:")
        for rule_type, count in sorted(type_counts.items()):
            print(f"  {rule_type}: {count}")
        print(f"{'='*80}\n")


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point"""
    cli = UBSCLI()
    cli.run()


if __name__ == '__main__':
    main()
