#!/usr/bin/env python3
"""
Universal Blocklist Syntax (UBS) Parser and Converter
Version: 1.0.0
"""

import re
import json
from typing import List, Dict, Optional, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class RuleType(Enum):
    """Types of blocklist rules"""
    DOMAIN = "domain"
    URL_PATTERN = "url_pattern"
    ELEMENT_HIDING = "element_hiding"
    SCRIPTLET = "scriptlet"
    SURICATA = "suricata"
    PROXY = "proxy"
    WHITELIST = "whitelist"
    HEADER_MODIFY = "header_modify"


class Action(Enum):
    """Available actions for rules"""
    BLOCK = "block"
    ALLOW = "allow"
    REDIRECT = "redirect"
    NULL = "null"
    NXDOMAIN = "nxdomain"
    DROP = "drop"
    ALERT = "alert"
    LOG = "log"


@dataclass
class Metadata:
    """List metadata from directives"""
    title: Optional[str] = None
    version: Optional[str] = None
    updated: Optional[str] = None
    expires: Optional[str] = None
    homepage: Optional[str] = None
    license: Optional[str] = None
    includes: List[str] = field(default_factory=list)
    targets: Set[str] = field(default_factory=set)


@dataclass
class Rule:
    """Parsed blocklist rule"""
    raw_line: str
    rule_type: RuleType
    pattern: str
    modifiers: Dict[str, Union[str, List[str], bool]] = field(default_factory=dict)
    section: Optional[str] = None
    line_number: int = 0
    
    def to_dict(self) -> Dict:
        """Convert rule to dictionary"""
        return {
            'type': self.rule_type.value,
            'pattern': self.pattern,
            'modifiers': self.modifiers,
            'section': self.section,
            'line': self.line_number
        }


class UBSParser:
    """Parser for Universal Blocklist Syntax"""
    
    def __init__(self):
        self.metadata = Metadata()
        self.rules: List[Rule] = []
        self.current_section: Optional[str] = None
        self.errors: List[str] = []
        
        # Regex patterns
        self.directive_pattern = re.compile(r'^!\s*(\w+):\s*(.+)$')
        self.section_pattern = re.compile(r'^\[(.+)\]$')
        self.modifier_pattern = re.compile(r':(\w+)(?:=([^:\s]+))?')
        self.domain_pattern = re.compile(r'^[\w\*\.\-]+$')
        self.regex_pattern = re.compile(r'^~(.+)$')
        self.url_pattern = re.compile(r'^\|\|(.+?)[\^\/]?')
        self.element_hiding_pattern = re.compile(r'^(.+?)##(.+)$')
        self.scriptlet_pattern = re.compile(r'^(.+?)#\+\+js\((.+)\)$')
        self.suricata_pattern = re.compile(r'^>>(\w+)(?::(\d+))?\s+(.+)$')
        self.proxy_pattern = re.compile(r'^(.+?)\s+:proxy=(.+)$')
        
    def parse(self, content: str) -> 'UBSParser':
        """Parse UBS content"""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
                
            # Remove inline comments
            if '#' in line and not line.startswith('#'):
                line = line.split('#')[0].strip()
            
            # Skip full-line comments
            if line.startswith('#'):
                continue
                
            try:
                self._parse_line(line, line_num)
            except Exception as e:
                self.errors.append(f"Line {line_num}: {str(e)}")
                
        return self
    
    def _parse_line(self, line: str, line_num: int):
        """Parse a single line"""
        
        # Check for directive
        if line.startswith('!'):
            self._parse_directive(line)
            return
            
        # Check for section
        section_match = self.section_pattern.match(line)
        if section_match:
            self.current_section = section_match.group(1)
            return
            
        # Parse rule
        rule = self._parse_rule(line, line_num)
        if rule:
            rule.section = self.current_section
            self.rules.append(rule)
    
    def _parse_directive(self, line: str):
        """Parse metadata directive"""
        match = self.directive_pattern.match(line)
        if not match:
            return
            
        key, value = match.groups()
        key = key.lower().replace('-', '_')
        
        if key == 'title':
            self.metadata.title = value
        elif key == 'version':
            self.metadata.version = value
        elif key == 'updated':
            self.metadata.updated = value
        elif key == 'expires':
            self.metadata.expires = value
        elif key == 'homepage':
            self.metadata.homepage = value
        elif key == 'license':
            self.metadata.license = value
        elif key == 'include':
            self.metadata.includes.append(value)
        elif key == 'target':
            self.metadata.targets.update(v.strip() for v in value.split(','))
    
    def _parse_rule(self, line: str, line_num: int) -> Optional[Rule]:
        """Parse a rule line"""
        
        # Extract modifiers
        modifiers = {}
        pattern = line
        
        if ':' in line:
            parts = line.split(':')
            pattern = parts[0].strip()
            modifier_str = ':'.join(parts[1:])
            modifiers = self._parse_modifiers(modifier_str)
        
        # Determine rule type and parse
        
        # Whitelist (starts with @)
        if pattern.startswith('@'):
            pattern = pattern[1:]
            rule_type = RuleType.WHITELIST
            modifiers['action'] = 'allow'
            
            # Check if it's a URL pattern
            if pattern.startswith('||'):
                pattern = self._extract_url_pattern(pattern)
                rule_type = RuleType.URL_PATTERN
        
        # Element hiding
        elif '##' in pattern:
            match = self.element_hiding_pattern.match(pattern)
            if match:
                domain, selector = match.groups()
                return Rule(
                    raw_line=line,
                    rule_type=RuleType.ELEMENT_HIDING,
                    pattern=pattern,
                    modifiers={'domain': domain, 'selector': selector, **modifiers},
                    line_number=line_num
                )
        
        # Scriptlet injection
        elif '#++js' in pattern:
            match = self.scriptlet_pattern.match(pattern)
            if match:
                domain, scriptlet = match.groups()
                return Rule(
                    raw_line=line,
                    rule_type=RuleType.SCRIPTLET,
                    pattern=pattern,
                    modifiers={'domain': domain, 'scriptlet': scriptlet, **modifiers},
                    line_number=line_num
                )
        
        # Suricata-style rule
        elif pattern.startswith('>>'):
            match = self.suricata_pattern.match(pattern)
            if match:
                protocol, port, content = match.groups()
                return Rule(
                    raw_line=line,
                    rule_type=RuleType.SURICATA,
                    pattern=pattern,
                    modifiers={
                        'protocol': protocol,
                        'port': port,
                        'content': content,
                        **modifiers
                    },
                    line_number=line_num
                )
        
        # Proxy rule
        elif 'proxy' in modifiers:
            rule_type = RuleType.PROXY
        
        # URL pattern (AdBlock-style)
        elif pattern.startswith('||'):
            pattern = self._extract_url_pattern(pattern)
            rule_type = RuleType.URL_PATTERN
        
        # Regex pattern
        elif pattern.startswith('~'):
            match = self.regex_pattern.match(pattern)
            if match:
                pattern = match.group(1)
                rule_type = RuleType.DOMAIN
                modifiers['regex'] = True
        
        # Simple domain
        elif self.domain_pattern.match(pattern):
            rule_type = RuleType.DOMAIN
        
        # Path pattern
        elif '/' in pattern:
            rule_type = RuleType.URL_PATTERN
        
        else:
            # Unknown pattern, treat as domain
            rule_type = RuleType.DOMAIN
        
        return Rule(
            raw_line=line,
            rule_type=rule_type,
            pattern=pattern,
            modifiers=modifiers,
            line_number=line_num
        )
    
    def _parse_modifiers(self, modifier_str: str) -> Dict:
        """Parse modifier string"""
        modifiers = {}
        
        for match in self.modifier_pattern.finditer(modifier_str):
            key, value = match.groups()
            
            if value:
                # Handle comma-separated values
                if '|' in value:
                    value = value.split('|')
                elif ',' in value:
                    value = value.split(',')
                    
            modifiers[key] = value if value else True
            
        return modifiers
    
    def _extract_url_pattern(self, pattern: str) -> str:
        """Extract URL pattern from AdBlock-style syntax"""
        # Remove || prefix
        pattern = pattern.replace('||', '')
        # Remove ^ suffix
        pattern = pattern.rstrip('^')
        return pattern
    
    def get_rules_by_type(self, rule_type: RuleType) -> List[Rule]:
        """Get all rules of a specific type"""
        return [rule for rule in self.rules if rule.rule_type == rule_type]
    
    def get_rules_by_section(self, section: str) -> List[Rule]:
        """Get all rules in a specific section"""
        return [rule for rule in self.rules if rule.section == section]
    
    def to_json(self) -> str:
        """Export parsed data as JSON"""
        return json.dumps({
            'metadata': {
                'title': self.metadata.title,
                'version': self.metadata.version,
                'updated': self.metadata.updated,
                'expires': self.metadata.expires,
                'homepage': self.metadata.homepage,
                'license': self.metadata.license,
                'includes': self.metadata.includes,
                'targets': list(self.metadata.targets)
            },
            'rules': [rule.to_dict() for rule in self.rules],
            'errors': self.errors
        }, indent=2)


class UBSConverter:
    """Convert UBS rules to various formats"""
    
    def __init__(self, parser: UBSParser):
        self.parser = parser
    
    def to_hosts(self, ip: str = "0.0.0.0") -> str:
        """Convert to hosts file format"""
        lines = ["# Converted from UBS format"]
        lines.append(f"# Generated: {datetime.now().isoformat()}")
        
        if self.parser.metadata.title:
            lines.append(f"# Title: {self.parser.metadata.title}")
        
        lines.append("")
        
        for rule in self.parser.rules:
            # Only process domain-level blocks
            if rule.rule_type == RuleType.DOMAIN and rule.modifiers.get('action') != 'allow':
                pattern = rule.pattern.replace('*.', '')
                if not rule.modifiers.get('regex'):
                    lines.append(f"{ip} {pattern}")
        
        return '\n'.join(lines)
    
    def to_adblock(self) -> str:
        """Convert to AdBlock Plus / uBlock Origin format"""
        lines = ["[Adblock Plus 2.0]"]
        
        if self.parser.metadata.title:
            lines.append(f"! Title: {self.parser.metadata.title}")
        if self.parser.metadata.version:
            lines.append(f"! Version: {self.parser.metadata.version}")
        if self.parser.metadata.homepage:
            lines.append(f"! Homepage: {self.parser.metadata.homepage}")
        
        lines.append("")
        
        for rule in self.parser.rules:
            adblock_rule = self._convert_to_adblock_rule(rule)
            if adblock_rule:
                lines.append(adblock_rule)
        
        return '\n'.join(lines)
    
    def _convert_to_adblock_rule(self, rule: Rule) -> Optional[str]:
        """Convert a single rule to AdBlock format"""
        
        if rule.rule_type == RuleType.ELEMENT_HIDING:
            return rule.pattern
        
        if rule.rule_type == RuleType.SCRIPTLET:
            return rule.pattern
        
        if rule.rule_type == RuleType.WHITELIST:
            prefix = "@@"
        else:
            prefix = ""
        
        if rule.rule_type in [RuleType.DOMAIN, RuleType.URL_PATTERN]:
            # Build AdBlock pattern
            pattern = f"{prefix}||{rule.pattern}^"
            
            # Add options
            options = []
            if 'third-party' in rule.modifiers:
                options.append('third-party')
            if 'script' in rule.modifiers:
                options.append('script')
            if 'image' in rule.modifiers:
                options.append('image')
            if 'xhr' in rule.modifiers:
                options.append('xmlhttprequest')
            if 'domain' in rule.modifiers:
                domains = rule.modifiers['domain']
                if isinstance(domains, list):
                    domains = '|'.join(domains)
                options.append(f'domain={domains}')
            
            if options:
                pattern += '$' + ','.join(options)
            
            return pattern
        
        return None
    
    def to_dnsmasq(self) -> str:
        """Convert to dnsmasq format"""
        lines = ["# Converted from UBS format"]
        lines.append("")
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.DOMAIN and rule.modifiers.get('action') != 'allow':
                pattern = rule.pattern.replace('*.', '')
                if not rule.modifiers.get('regex'):
                    lines.append(f"address=/{pattern}/0.0.0.0")
        
        return '\n'.join(lines)
    
    def to_unbound(self) -> str:
        """Convert to Unbound format"""
        lines = ["# Converted from UBS format"]
        lines.append("server:")
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.DOMAIN and rule.modifiers.get('action') != 'allow':
                pattern = rule.pattern.replace('*.', '')
                if not rule.modifiers.get('regex'):
                    lines.append(f'  local-zone: "{pattern}" always_nxdomain')
        
        return '\n'.join(lines)
    
    def to_bind(self) -> str:
        """Convert to BIND zone format"""
        lines = ["// Converted from UBS format"]
        lines.append("")
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.DOMAIN and rule.modifiers.get('action') != 'allow':
                pattern = rule.pattern.replace('*.', '')
                if not rule.modifiers.get('regex'):
                    lines.append(f'zone "{pattern}" {{ type master; file "/etc/bind/null.zone"; }};')
        
        return '\n'.join(lines)
    
    def to_squid(self) -> str:
        """Convert to Squid ACL format"""
        lines = ["# Converted from UBS format"]
        lines.append("")
        
        for rule in self.parser.rules:
            if rule.rule_type in [RuleType.DOMAIN, RuleType.URL_PATTERN]:
                if rule.modifiers.get('action') != 'allow':
                    pattern = rule.pattern.replace('*.', '.')
                    lines.append(f".{pattern}")
        
        return '\n'.join(lines)
    
    def to_proxy_pac(self) -> str:
        """Convert to Proxy Auto-Config (PAC) format"""
        lines = [
            'function FindProxyForURL(url, host) {',
            '  // Converted from UBS format',
            ''
        ]
        
        proxy_rules = self.parser.get_rules_by_type(RuleType.PROXY)
        block_rules = [r for r in self.parser.rules 
                      if r.rule_type == RuleType.DOMAIN 
                      and r.modifiers.get('action') != 'allow'
                      and r.rule_type != RuleType.PROXY]
        
        # Add proxy routing rules
        for rule in proxy_rules:
            pattern = rule.pattern.replace('*.', '')
            proxy = rule.modifiers.get('proxy', 'DIRECT')
            lines.append(f'  if (shExpMatch(host, "*{pattern}*")) {{')
            lines.append(f'    return "{proxy}";')
            lines.append('  }')
        
        # Add blocked domains
        if block_rules:
            lines.append('')
            lines.append('  // Blocked domains')
            for rule in block_rules[:10]:  # Limit for PAC performance
                pattern = rule.pattern.replace('*.', '')
                lines.append(f'  if (shExpMatch(host, "*{pattern}*")) {{')
                lines.append('    return "PROXY 127.0.0.1:1";  // Black hole')
                lines.append('  }')
        
        lines.append('')
        lines.append('  return "DIRECT";')
        lines.append('}')
        
        return '\n'.join(lines)
    
    def to_suricata(self) -> str:
        """Convert to Suricata rules format"""
        lines = ["# Converted from UBS format"]
        lines.append("")
        
        sid = 1000000  # Starting SID
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.SURICATA:
                protocol = rule.modifiers.get('protocol', 'tcp')
                port = rule.modifiers.get('port', 'any')
                content = rule.modifiers.get('content', '')
                msg = rule.modifiers.get('msg', 'UBS Rule')
                severity = rule.modifiers.get('severity', 'medium')
                
                # Parse content for actual string
                content_match = re.search(r'content:"([^"]+)"', content)
                if content_match:
                    content_str = content_match.group(1)
                    lines.append(
                        f'alert {protocol} any any -> any {port} '
                        f'(msg:"{msg}"; content:"{content_str}"; '
                        f'classtype:misc-activity; sid:{sid}; rev:1;)'
                    )
                    sid += 1
            
            elif rule.rule_type == RuleType.DOMAIN and rule.modifiers.get('severity'):
                # Convert high-severity domains to Suricata rules
                msg = f"Blocked domain: {rule.pattern}"
                lines.append(
                    f'alert dns any any -> any any '
                    f'(msg:"{msg}"; dns_query; content:"{rule.pattern}"; '
                    f'nocase; sid:{sid}; rev:1;)'
                )
                sid += 1
        
        return '\n'.join(lines)
    
    def to_little_snitch(self) -> str:
        """Convert to Little Snitch JSON format"""
        rules = []
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.DOMAIN:
                action = "deny" if rule.modifiers.get('action') != 'allow' else "allow"
                rules.append({
                    "action": action,
                    "process": "any",
                    "remote-domains": rule.pattern.replace('*.', ''),
                    "ports": "any",
                    "protocol": "any",
                    "notes": rule.section or "UBS Rule"
                })
        
        return json.dumps({"name": self.parser.metadata.title or "UBS Rules", "rules": rules}, indent=2)


# Example usage and CLI
if __name__ == "__main__":
    import sys
    
    # Example UBS content
    example_ubs = """
! Title: Example UBS Blocklist
! Version: 1.0.0
! Updated: 2025-10-10
! License: MIT
! Target: dns,browser,waf

[Malware-Domains]
evil-malware.com :severity=critical :category=malware
*.phishing.net :action=block :log

[Tracking]
||analytics.google.com^ :third-party :category=tracker
||facebook.com/tr/* :script
facebook.com##div[id^="cookie"]

[Proxy-Rules]
||internal.company.com :proxy=DIRECT
*.onion :proxy=SOCKS5 127.0.0.1:9050

[Whitelist]
@||paypal.com^
@@||cdn.cloudflare.com^ :first-party

[WAF-Rules]
>>http content:"<script>" :severity=high :msg="XSS Attempt"
"""
    
    print("=== UBS Parser & Converter Demo ===\n")
    
    # Parse
    parser = UBSParser()
    parser.parse(example_ubs)
    
    print(f"Parsed {len(parser.rules)} rules")
    print(f"Metadata: {parser.metadata.title} v{parser.metadata.version}\n")
    
    if parser.errors:
        print(f"Errors: {len(parser.errors)}")
        for error in parser.errors:
            print(f"  - {error}")
        print()
    
    # Convert
    converter = UBSConverter(parser)
    
    print("--- Hosts Format ---")
    print(converter.to_hosts()[:500])
    print("\n--- AdBlock Format ---")
    print(converter.to_adblock()[:500])
    print("\n--- Dnsmasq Format ---")
    print(converter.to_dnsmasq()[:500])
    print("\n--- JSON Export ---")
    print(parser.to_json()[:500])
