#!/usr/bin/env python3
"""
Universal Blocklist Syntax (UBS) Parser
Version 3.0 with Flexible Modifier Support

Supports both modifier syntaxes:
- AdBlock-Style: $third-party,script
- UBS-Native: :severity=high :category=malware
- Mixed: $third-party :severity=high

Author: Valanx UBS Team
License: MIT
"""

import re
from enum import Enum
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime


# ============================================================================
# ENUMS & DATA CLASSES
# ============================================================================

class RuleType(Enum):
    """Type of blocking rule"""
    DOMAIN = "domain"
    URL = "url"
    REGEX = "regex"
    CSS_SELECTOR = "css_selector"
    HTML_FILTER = "html_filter"
    WAF_RULE = "waf_rule"
    SURICATA_RULE = "suricata_rule"
    EXCEPTION = "exception"
    COMMENT = "comment"


class Action(Enum):
    """Action to take for a rule"""
    BLOCK = "block"
    ALLOW = "allow"
    DROP = "drop"
    LOG = "log"
    REDIRECT = "redirect"


class Severity(Enum):
    """Severity level for threats"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ModifierCategory(Enum):
    """Categories of modifiers for syntax handling"""
    ADBLOCK = "adblock"      # AdBlock-Style (uses $)
    UBS_NATIVE = "ubs"       # UBS-specific (uses :)
    SURICATA = "suricata"    # Suricata-specific
    COMMON = "common"        # Can use both


@dataclass
class ParsedModifier:
    """A parsed modifier with metadata"""
    name: str                    # Normalized name
    value: Optional[str]         # Value (if any)
    original_name: str           # Original name from file
    original_prefix: str         # Original prefix ($ or :)
    category: ModifierCategory   # Category of modifier
    line_position: int = 0       # Position in line


@dataclass
class Rule:
    """A single UBS rule"""
    rule_type: RuleType
    pattern: str
    action: Action = Action.BLOCK
    modifiers: Dict[str, Optional[str]] = field(default_factory=dict)
    severity: Optional[Severity] = None
    category: Optional[str] = None
    comment: Optional[str] = None
    line_number: int = 0
    raw_line: str = ""


@dataclass
class Metadata:
    """Metadata about the blocklist"""
    title: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    expires: Optional[str] = None
    last_modified: Optional[datetime] = None
    author: Optional[str] = None
    license: Optional[str] = None


# ============================================================================
# MODIFIER DEFINITIONS
# ============================================================================

# Modifier Categories
MODIFIER_CATEGORIES = {
    # AdBlock-Style Modifiers (prefer $)
    'third-party': ModifierCategory.ADBLOCK,
    'first-party': ModifierCategory.ADBLOCK,
    'script': ModifierCategory.ADBLOCK,
    'image': ModifierCategory.ADBLOCK,
    'stylesheet': ModifierCategory.ADBLOCK,
    'font': ModifierCategory.ADBLOCK,
    'media': ModifierCategory.ADBLOCK,
    'object': ModifierCategory.ADBLOCK,
    'xmlhttprequest': ModifierCategory.ADBLOCK,
    'websocket': ModifierCategory.ADBLOCK,
    'subdocument': ModifierCategory.ADBLOCK,
    'ping': ModifierCategory.ADBLOCK,
    'popup': ModifierCategory.ADBLOCK,
    'popunder': ModifierCategory.ADBLOCK,
    'document': ModifierCategory.ADBLOCK,
    'genericblock': ModifierCategory.ADBLOCK,
    'generichide': ModifierCategory.ADBLOCK,
    'specifichide': ModifierCategory.ADBLOCK,
    'badfilter': ModifierCategory.ADBLOCK,
    'csp': ModifierCategory.ADBLOCK,
    'redirect': ModifierCategory.ADBLOCK,
    'redirect-rule': ModifierCategory.ADBLOCK,
    'remove-header': ModifierCategory.ADBLOCK,
    'webrtc': ModifierCategory.ADBLOCK,
    'empty': ModifierCategory.ADBLOCK,
    'mp4': ModifierCategory.ADBLOCK,
    'inline-script': ModifierCategory.ADBLOCK,
    'inline-font': ModifierCategory.ADBLOCK,
    
    # UBS-Native Modifiers (prefer :)
    'severity': ModifierCategory.UBS_NATIVE,
    'category': ModifierCategory.UBS_NATIVE,
    'msg': ModifierCategory.UBS_NATIVE,
    'reason': ModifierCategory.UBS_NATIVE,
    'expires': ModifierCategory.UBS_NATIVE,
    'updated': ModifierCategory.UBS_NATIVE,
    'ttl': ModifierCategory.UBS_NATIVE,
    'rate-limit': ModifierCategory.UBS_NATIVE,
    'burst': ModifierCategory.UBS_NATIVE,
    'timeout': ModifierCategory.UBS_NATIVE,
    'proxy': ModifierCategory.UBS_NATIVE,
    'fallback': ModifierCategory.UBS_NATIVE,
    'weight': ModifierCategory.UBS_NATIVE,
    'priority': ModifierCategory.UBS_NATIVE,
    
    # Suricata-Specific
    'classtype': ModifierCategory.SURICATA,
    'sid': ModifierCategory.SURICATA,
    'rev': ModifierCategory.SURICATA,
    'content': ModifierCategory.SURICATA,
    
    # Common (both syntaxes allowed)
    'action': ModifierCategory.COMMON,
    'block': ModifierCategory.COMMON,
    'allow': ModifierCategory.COMMON,
    'log': ModifierCategory.COMMON,
    'domain': ModifierCategory.COMMON,
    'host': ModifierCategory.COMMON,
    'path': ModifierCategory.COMMON,
    'protocol': ModifierCategory.COMMON,
    'port': ModifierCategory.COMMON,
    'query': ModifierCategory.COMMON,
    'important': ModifierCategory.COMMON,
    'selector': ModifierCategory.COMMON,
    'other': ModifierCategory.COMMON,
    'all': ModifierCategory.COMMON,
}

# Valid modifiers set (for validation)
VALID_MODIFIERS = set(MODIFIER_CATEGORIES.keys())

# Modifier Aliases (shorthand forms)
MODIFIER_ALIASES = {
    'third': 'third-party',
    'first': 'first-party',
    '3p': 'third-party',
    '1p': 'first-party',
    '3rd': 'third-party',
    '1st': 'first-party',
    'thirdparty': 'third-party',
    'firstparty': 'first-party',
    'xhr': 'xmlhttprequest',
    'ws': 'websocket',
    'css': 'stylesheet',
    'img': 'image',
    'doc': 'document',
    'subdoc': 'subdocument',
    'frame': 'subdocument',
    'deny': 'block',
    'permit': 'allow',
    'drop': 'block',
    'popup-window': 'popup',
    'pop-up': 'popup',
}


# ============================================================================
# FLEXIBLE MODIFIER PARSER
# ============================================================================

class FlexibleModifierParser:
    """
    Parser that accepts both modifier syntaxes:
    - AdBlock-Style: $third-party,script
    - UBS-Native: :severity=high :category=malware
    - Mixed: $third-party :severity=high
    """
    
    def __init__(self, strict_syntax: bool = False):
        """
        Args:
            strict_syntax: If True, warns when wrong prefix is used for modifier category
        """
        self.strict_syntax = strict_syntax
        self.warnings: List[str] = []
        self.errors: List[str] = []
    
    def parse(self, rule_string: str) -> Tuple[str, List[ParsedModifier]]:
        """
        Parse a rule and extract modifiers
        
        Args:
            rule_string: Complete rule line
            
        Returns:
            (base_rule, modifiers): Base rule without modifiers and list of ParsedModifier
        """
        self.warnings.clear()
        self.errors.clear()
        
        # Find all modifiers (start with $ or :)
        modifiers: List[ParsedModifier] = []
        
        # Find base rule (everything before first modifier)
        match = re.search(r'([\$:])', rule_string)
        if match:
            base_rule = rule_string[:match.start()].strip()
            modifier_string = rule_string[match.start():]
        else:
            # No modifiers found
            return rule_string.strip(), []
        
        # Parse modifier string
        modifiers = self._parse_modifier_string(modifier_string)
        
        return base_rule, modifiers
    
    def _parse_modifier_string(self, modifier_string: str) -> List[ParsedModifier]:
        """Parse a modifier string with mixed prefixes"""
        modifiers = []
        
        # Pattern: ($ or :) followed by modifier-name (optional =value)
        # Supports: $name, :name, $name=value, :name=value, :name="value"
        # pattern = r'([\$:])([a-z0-9_-]+)(?:=([^\s\$:,]+|"[^"]*"))?'
        # Supports: $name, :name, $name=value, :name=value, :name="value" :name"val:value" :name="val val mod" :name="val, mod"
        pattern = r'([\$:])([a-z0-9_-]+)(?:=("[^"]*"|[^,\s\$:]+))?'
        
        for match in re.finditer(pattern, modifier_string, re.IGNORECASE):
            prefix = match.group(1)        # $ or :
            name = match.group(2).lower()  # modifier name
            value = match.group(3)         # optional value
            
            # Remove quotes from value if present
            if value and value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            
            # Normalize name (resolve aliases)
            original_name = name
            name = self._normalize_modifier_name(name)
            
            # Get category
            category = MODIFIER_CATEGORIES.get(name, ModifierCategory.COMMON)
            
            # Syntax validation (optional warning)
            if self.strict_syntax:
                expected_prefix = self._get_expected_prefix(category)
                if prefix != expected_prefix:
                    self.warnings.append(
                        f"Modifier '{original_name}' uses '{prefix}' but '{expected_prefix}' "
                        f"is recommended for {category.value} modifiers"
                    )
            
            # Check if modifier is valid
            if name not in VALID_MODIFIERS:
                self.errors.append(f"Unknown modifier: {original_name}")
            
            # Create parsed modifier
            parsed = ParsedModifier(
                name=name,
                value=value,
                original_name=original_name,
                original_prefix=prefix,
                category=category,
                line_position=match.start()
            )
            
            modifiers.append(parsed)
        
        return modifiers
    
    def _normalize_modifier_name(self, name: str) -> str:
        """Resolve aliases and normalize modifier name"""
        name = name.strip().lower()
        return MODIFIER_ALIASES.get(name, name)
    
    def _get_expected_prefix(self, category: ModifierCategory) -> str:
        """Get expected prefix for a modifier category"""
        if category == ModifierCategory.ADBLOCK:
            return '$'
        elif category in (ModifierCategory.UBS_NATIVE, ModifierCategory.SURICATA):
            return ':'
        else:  # COMMON
            return '$'  # Default to $


# ============================================================================
# MAIN UBS PARSER
# ============================================================================

class UBSParser:
    """
    Main parser for Universal Blocklist Syntax files
    Supports flexible modifier syntax (both $ and :)
    """
    
    def __init__(self, strict_syntax: bool = False):
        """
        Initialize parser
        
        Args:
            strict_syntax: If True, generates warnings for inconsistent syntax
        """
        self.rules: List[Rule] = []
        self.metadata = Metadata()
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.current_section: Optional[str] = None
        
        # Flexible modifier parser
        self.modifier_parser = FlexibleModifierParser(strict_syntax=strict_syntax)
    
    def parse(self, content: str) -> None:
        """
        Parse UBS file content
        
        Args:
            content: String content of UBS file
        """
        self.rules.clear()
        self.errors.clear()
        self.warnings.clear()
        
        lines = content.split('\n')
        
        for line_number, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
            
            # Parse line
            try:
                self._parse_line(line, line_number)
            except Exception as e:
                self.errors.append(f"Line {line_number}: Parse error - {str(e)}")
    
    def _parse_line(self, line: str, line_number: int) -> None:
        """Parse a single line"""
        
        # Metadata (starts with !)
        if line.startswith('!'):
            self._parse_metadata(line)
            return
        
        # Section header
        if line.startswith('[') and line.endswith(']'):
            self.current_section = line[1:-1]
            return
        
        # Comment (starts with #)
        if line.startswith('#'):
            return
        
        # CSS Selector
        if '##' in line or '#@#' in line:
            self._parse_css_selector(line, line_number)
            return
        
        # HTML Filter
        if '#$#' in line or '#@$#' in line:
            self._parse_html_filter(line, line_number)
            return
        
        # WAF Rule (starts with >>)
        if line.startswith('>>'):
            self._parse_waf_rule(line, line_number)
            return
        
        # Suricata Rule (starts with alert/drop/reject)
        if line.startswith(('alert', 'drop', 'reject', 'pass')):
            self._parse_suricata_rule(line, line_number)
            return
        
        # Exception rule (starts with @@)
        if line.startswith('@@'):
            self._parse_exception_rule(line[2:], line_number)
            return
        
        # Regular domain/URL rule
        self._parse_domain_rule(line, line_number)
    
    def _parse_metadata(self, line: str) -> None:
        """Parse metadata line"""
        line = line[1:].strip()  # Remove !
        
        if ':' not in line:
            return
        
        key, value = line.split(':', 1)
        key = key.strip().lower()
        value = value.strip()
        
        metadata_map = {
            'title': 'title',
            'version': 'version',
            'description': 'description',
            'homepage': 'homepage',
            'expires': 'expires',
            'author': 'author',
            'license': 'license',
        }
        
        if key in metadata_map:
            setattr(self.metadata, metadata_map[key], value)
    
    def _parse_domain_rule(self, line: str, line_number: int) -> None:
        """Parse domain or URL rule with flexible modifiers"""
        
        # Use flexible modifier parser
        base_rule, parsed_modifiers = self.modifier_parser.parse(line)
        
        # Convert to modifier dict
        modifiers = {}
        for mod in parsed_modifiers:
            modifiers[mod.name] = mod.value
        
        # Add warnings from modifier parser
        for warning in self.modifier_parser.warnings:
            self.warnings.append(f"Line {line_number}: {warning}")
        
        # Add errors from modifier parser
        for error in self.modifier_parser.errors:
            self.errors.append(f"Line {line_number}: {error}")
        
        # Determine rule type
        rule_type = self._detect_rule_type(base_rule)
        
        # Extract action
        action = Action.BLOCK
        if 'action' in modifiers:
            action_str = modifiers['action']
            try:
                action = Action(action_str.lower())
            except ValueError:
                self.warnings.append(f"Line {line_number}: Unknown action '{action_str}'")
        elif 'allow' in modifiers:
            action = Action.ALLOW
        elif 'block' in modifiers:
            action = Action.BLOCK
        
        # Extract severity
        severity = None
        if 'severity' in modifiers:
            try:
                severity = Severity(modifiers['severity'].lower())
            except (ValueError, AttributeError):
                self.warnings.append(f"Line {line_number}: Invalid severity")
        
        # Create rule
        rule = Rule(
            rule_type=rule_type,
            pattern=base_rule,
            action=action,
            modifiers=modifiers,
            severity=severity,
            category=modifiers.get('category'),
            comment=modifiers.get('msg') or modifiers.get('reason'),
            line_number=line_number,
            raw_line=line
        )
        
        self.rules.append(rule)
    
    def _parse_exception_rule(self, line: str, line_number: int) -> None:
        """Parse exception rule (whitelist)"""
        base_rule, parsed_modifiers = self.modifier_parser.parse(line)
        
        modifiers = {mod.name: mod.value for mod in parsed_modifiers}
        
        rule = Rule(
            rule_type=RuleType.EXCEPTION,
            pattern=base_rule,
            action=Action.ALLOW,
            modifiers=modifiers,
            comment=modifiers.get('reason'),
            line_number=line_number,
            raw_line=line
        )
        
        self.rules.append(rule)
    
    def _parse_css_selector(self, line: str, line_number: int) -> None:
        """Parse CSS selector rule"""
        if '#@#' in line:
            parts = line.split('#@#', 1)
            action = Action.ALLOW
        else:
            parts = line.split('##', 1)
            action = Action.BLOCK
        
        domain = parts[0] if parts[0] else None
        selector = parts[1] if len(parts) > 1 else ""
        
        rule = Rule(
            rule_type=RuleType.CSS_SELECTOR,
            pattern=selector,
            action=action,
            modifiers={'domain': domain} if domain else {},
            line_number=line_number,
            raw_line=line
        )
        
        self.rules.append(rule)
    
    def _parse_html_filter(self, line: str, line_number: int) -> None:
        """Parse HTML filter rule"""
        if '#@$#' in line:
            parts = line.split('#@$#', 1)
            action = Action.ALLOW
        else:
            parts = line.split('#$#', 1)
            action = Action.BLOCK
        
        domain = parts[0] if parts[0] else None
        filter_expr = parts[1] if len(parts) > 1 else ""
        
        rule = Rule(
            rule_type=RuleType.HTML_FILTER,
            pattern=filter_expr,
            action=action,
            modifiers={'domain': domain} if domain else {},
            line_number=line_number,
            raw_line=line
        )
        
        self.rules.append(rule)
    
    def _parse_waf_rule(self, line: str, line_number: int) -> None:
        """Parse WAF rule"""
        line = line[2:].strip()  # Remove >>
        
        base_rule, parsed_modifiers = self.modifier_parser.parse(line)
        modifiers = {mod.name: mod.value for mod in parsed_modifiers}
        
        severity = None
        if 'severity' in modifiers:
            try:
                severity = Severity(modifiers['severity'].lower())
            except ValueError:
                pass
        
        rule = Rule(
            rule_type=RuleType.WAF_RULE,
            pattern=base_rule,
            action=Action.DROP,
            modifiers=modifiers,
            severity=severity,
            category=modifiers.get('category'),
            comment=modifiers.get('msg'),
            line_number=line_number,
            raw_line=line
        )
        
        self.rules.append(rule)
    
    def _parse_suricata_rule(self, line: str, line_number: int) -> None:
        """Parse Suricata-style rule"""
        # Extract action
        action_match = re.match(r'^(alert|drop|reject|pass)\s+', line)
        if not action_match:
            return
        
        action_str = action_match.group(1)
        action = Action.BLOCK if action_str in ('alert', 'drop', 'reject') else Action.ALLOW
        
        # Extract modifiers from parentheses
        paren_match = re.search(r'\((.*?)\)', line)
        if paren_match:
            modifier_str = paren_match.group(1)
            # Parse Suricata-style modifiers
            modifiers = {}
            for part in modifier_str.split(';'):
                part = part.strip()
                if ':' in part:
                    key, value = part.split(':', 1)
                    modifiers[key.strip()] = value.strip().strip('"')
        else:
            modifiers = {}
        
        rule = Rule(
            rule_type=RuleType.SURICATA_RULE,
            pattern=line,
            action=action,
            modifiers=modifiers,
            comment=modifiers.get('msg'),
            line_number=line_number,
            raw_line=line
        )
        
        self.rules.append(rule)
    
    def _detect_rule_type(self, pattern: str) -> RuleType:
        """Detect type of rule from pattern"""
        
        # Check for regex patterns
        if pattern.startswith('/') and pattern.endswith('/'):
            return RuleType.REGEX
        
        # Check for URL patterns
        if any(indicator in pattern for indicator in ['://', '||', '^', '*', '|']):
            return RuleType.URL
        
        # Default to domain
        return RuleType.DOMAIN
    
    def get_statistics(self) -> Dict:
        """Get parsing statistics"""
        stats = {
            'total_rules': len(self.rules),
            'errors': len(self.errors),
            'warnings': len(self.warnings),
            'by_type': {},
            'by_action': {},
            'by_severity': {}
        }
        
        for rule in self.rules:
            # Count by type
            rule_type = rule.rule_type.value
            stats['by_type'][rule_type] = stats['by_type'].get(rule_type, 0) + 1
            
            # Count by action
            action = rule.action.value
            stats['by_action'][action] = stats['by_action'].get(action, 0) + 1
            
            # Count by severity
            if rule.severity:
                severity = rule.severity.value
                stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        
        return stats


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def parse_ubs_file(filepath: str) -> UBSParser:
    """
    Convenience function to parse a UBS file
    
    Args:
        filepath: Path to UBS file
        
    Returns:
        Parsed UBSParser object
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = UBSParser()
    parser.parse(content)
    
    return parser


def parse_ubs_string(content: str) -> UBSParser:
    """
    Convenience function to parse UBS content string
    
    Args:
        content: UBS file content as string
        
    Returns:
        Parsed UBSParser object
    """
    parser = UBSParser()
    parser.parse(content)
    return parser


# ============================================================================
# TESTING & EXAMPLES
# ============================================================================

if __name__ == '__main__':
    # Example UBS content with mixed syntax
    test_content = """
! Title: Test List
! Version: 1.0
! Expires: 1 day

[Tracking]
||analytics.google.com^:third-party :category=tracker
||facebook.com/tr/*$script :log

[Malware]
evil-malware.com :severity=critical :category=malware
*.phishing.net :action=block

[Ad-Blocking]
||ads.example.com^$third-party,script
/banner-ads/*$domain=~advertiser.com

[Whitelist]
@@||paypal.com^ :reason="Payment processor"
@@||cdn.cloudflare.com^$first-party
"""
    
    print("="*80)
    print("UBS PARSER TEST - Flexible Modifier Syntax")
    print("="*80)
    
    # Parse
    parser = UBSParser(strict_syntax=False)
    parser.parse(test_content)
    
    # Print statistics
    stats = parser.get_statistics()
    print(f"\n📊 Statistics:")
    print(f"   Total Rules: {stats['total_rules']}")
    print(f"   Errors: {stats['errors']}")
    print(f"   Warnings: {stats['warnings']}")
    
    print(f"\n📋 By Type:")
    for rule_type, count in stats['by_type'].items():
        print(f"   {rule_type}: {count}")
    
    print(f"\n⚡ By Action:")
    for action, count in stats['by_action'].items():
        print(f"   {action}: {count}")
    
    # Print errors and warnings
    if parser.errors:
        print(f"\n❌ Errors:")
        for error in parser.errors:
            print(f"   {error}")
    
    # if parser.warnings:
    #     print(f"\n⚠️  Warnings:".encode('utf-8', 'replace').decode())
    #     for warning in parser.warnings:
    #         print(f"   {warning}")
    
    # Adjusted for terminal output
    if parser.warnings:
        print("\n⚠️  Warnings:")
        for warning in parser.warnings:
            try:
                print(f"   {warning}")
            except UnicodeEncodeError:
                print(f"   {warning.encode('utf-8', 'replace').decode()}")

    # Print sample rules
    print(f"\n📝 Sample Rules:")
    for i, rule in enumerate(parser.rules[:5], 1):
        print(f"\n   Rule {i}:")
        print(f"   Type: {rule.rule_type.value}")
        print(f"   Pattern: {rule.pattern}")
        print(f"   Action: {rule.action.value}")
        print(f"   Modifiers: {rule.modifiers}")
        if rule.severity:
            print(f"   Severity: {rule.severity.value}")
    
    print("\n" + "="*80)