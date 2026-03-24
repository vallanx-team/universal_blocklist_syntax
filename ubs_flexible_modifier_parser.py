#!/usr/bin/env python3
"""
UBS Parser Extension: Flexible Modifier Syntax
Akzeptiert beide Syntaxen: $modifier und :modifier

Füge diesen Code zu deiner ubs_parser.py hinzu oder erstelle eine neue Datei
"""

from enum import Enum
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


# ============================================================================
# MODIFIER KATEGORIEN
# ============================================================================

class ModifierCategory(Enum):
    """Kategorien von Modifiern für bessere Organisation"""
    ADBLOCK = "adblock"      # AdBlock-Style (normalerweise $)
    UBS_NATIVE = "ubs"       # UBS-specific (normalerweise :)
    SURICATA = "suricata"    # Suricata-specific
    COMMON = "common"        # Kann beides sein


# Modifier mit ihrer Kategorie
MODIFIER_CATEGORIES = {
    # AdBlock-Style Modifier (bevorzugt mit $)
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
    
    # UBS-Native Modifier (bevorzugt mit :)
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
    
    # Suricata-Specific
    'classtype': ModifierCategory.SURICATA,
    'sid': ModifierCategory.SURICATA,
    'rev': ModifierCategory.SURICATA,
    'priority': ModifierCategory.SURICATA,
    'content': ModifierCategory.SURICATA,
    
    # Common (beide Syntaxen erlaubt)
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
    'weight': ModifierCategory.COMMON,
}


# Modifier Aliases (Kurzformen)
MODIFIER_ALIASES = {
    'third': 'third-party',
    'first': 'first-party',
    '3p': 'third-party',
    '1p': 'first-party',
    '3rd': 'third-party',
    '1st': 'first-party',
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
}


# ============================================================================
# FLEXIBLE MODIFIER PARSER
# ============================================================================

@dataclass
class ParsedModifier:
    """Ein geparster Modifier mit Metadaten"""
    name: str                    # Normalisierter Name
    value: Optional[str]         # Wert (falls vorhanden)
    original_name: str           # Original Name aus der Datei
    original_prefix: str         # Original Präfix ($ oder :)
    category: ModifierCategory   # Kategorie des Modifiers
    line_position: int = 0       # Position in der Zeile


class FlexibleModifierParser:
    """
    Parser der beide Modifier-Syntaxen akzeptiert:
    - AdBlock-Style: $third-party,script
    - UBS-Native: :severity=high :category=malware
    - Gemischt: $third-party :severity=high
    """
    
    def __init__(self, strict_syntax: bool = False):
        """
        Args:
            strict_syntax: Wenn True, warnt bei falscher Syntax für Modifier-Kategorie
        """
        self.strict_syntax = strict_syntax
        self.warnings: List[str] = []
        self.errors: List[str] = []
    
    def parse(self, rule_string: str) -> Tuple[str, List[ParsedModifier]]:
        """
        Parse eine Regel und extrahiere Modifier
        
        Args:
            rule_string: Die komplette Regel-Zeile
            
        Returns:
            (base_rule, modifiers): Basis-Regel ohne Modifier und Liste von ParsedModifier
        """
        self.warnings.clear()
        self.errors.clear()
        
        # Finde alle Modifier (beginnen mit $ oder :)
        modifiers: List[ParsedModifier] = []
        
        # Split bei $ und : aber behalte die Trennzeichen
        import re
        
        # Finde Base Rule (alles vor dem ersten Modifier)
        match = re.search(r'([\$:])', rule_string)
        if match:
            base_rule = rule_string[:match.start()].strip()
            modifier_string = rule_string[match.start():]
        else:
            # Keine Modifier gefunden
            return rule_string.strip(), []
        
        # Parse Modifier String
        modifiers = self._parse_modifier_string(modifier_string)
        
        return base_rule, modifiers
    
    def _parse_modifier_string(self, modifier_string: str) -> List[ParsedModifier]:
        """Parse einen Modifier-String mit gemischten Präfixen"""
        import re
        modifiers = []
        
        # Pattern: ($ oder :) gefolgt von modifier-name (optional =value)
        # Unterstützt: $name, :name, $name=value, :name=value, :name="value"
        pattern = r'([\$:])([a-z0-9_-]+)(?:=([^\s\$:]+|"[^"]*"))?'
        
        for match in re.finditer(pattern, modifier_string, re.IGNORECASE):
            prefix = match.group(1)        # $ oder :
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
    
    def to_normalized_string(self, base_rule: str, modifiers: List[ParsedModifier], 
                            target_syntax: str = 'mixed') -> str:
        """
        Convert back to rule string with normalized syntax
        
        Args:
            base_rule: Base rule without modifiers
            modifiers: List of parsed modifiers
            target_syntax: 'adblock' (all $), 'ubs' (all :), or 'mixed' (category-based)
        
        Returns:
            Normalized rule string
        """
        if not modifiers:
            return base_rule
        
        # Build modifier string
        mod_parts = []
        
        for mod in modifiers:
            # Determine prefix based on target syntax
            if target_syntax == 'adblock':
                prefix = '$'
            elif target_syntax == 'ubs':
                prefix = ':'
            else:  # mixed
                prefix = self._get_expected_prefix(mod.category)
            
            # Build modifier string
            if mod.value:
                # Escape value if it contains spaces
                if ' ' in mod.value:
                    mod_str = f'{prefix}{mod.name}="{mod.value}"'
                else:
                    mod_str = f'{prefix}{mod.name}={mod.value}'
            else:
                mod_str = f'{prefix}{mod.name}'
            
            mod_parts.append(mod_str)
        
        # Combine: AdBlock-style modifiers with $, others separate
        adblock_mods = [m for m in mod_parts if m.startswith('$')]
        ubs_mods = [m for m in mod_parts if m.startswith(':')]
        
        if target_syntax == 'mixed':
            # Combine AdBlock mods with commas, UBS mods with spaces
            result = base_rule
            if adblock_mods:
                result += '$' + ','.join(m[1:] for m in adblock_mods)
            if ubs_mods:
                result += ' ' + ' '.join(ubs_mods)
            return result.strip()
        else:
            # All with same prefix
            return base_rule + ''.join(mod_parts)


# ============================================================================
# INTEGRATION IN UBSParser
# ============================================================================

def integrate_flexible_parser_example():
    """
    Beispiel wie man FlexibleModifierParser in die UBSParser Klasse integriert
    """
    
    # In ubs_parser.py, in der parse() Methode:
    
    class UBSParser:
        def __init__(self):
            self.flexible_parser = FlexibleModifierParser(strict_syntax=False)
            # ... rest of init
        
        def _parse_rule(self, line: str, line_number: int):
            """Parse a single rule with flexible modifier syntax"""
            
            # Use flexible parser
            base_rule, modifiers = self.flexible_parser.parse(line)
            
            # Convert to your internal format
            modifier_dict = {}
            for mod in modifiers:
                modifier_dict[mod.name] = mod.value
            
            # Add warnings from parser
            for warning in self.flexible_parser.warnings:
                self.warnings.append(f"Line {line_number}: {warning}")
            
            # Create Rule object
            rule = Rule(
                pattern=base_rule,
                modifiers=modifier_dict,
                line_number=line_number,
                raw_line=line
            )
            
            return rule


# ============================================================================
# TESTS UND BEISPIELE
# ============================================================================

def test_flexible_parser():
    """Test cases for flexible modifier parser"""
    
    parser = FlexibleModifierParser(strict_syntax=False)
    
    test_cases = [
        # AdBlock-Style mit $
        "||example.com^$third-party,script,important",
        
        # UBS-Style mit :
        "evil.com :severity=critical :category=malware",
        
        # Gemischt
        "||ads.com^$third-party :severity=high :log",
        
        # Aliase
        "||tracker.com^:third :category=tracker",
        
        # Falsche Syntax (sollte trotzdem funktionieren)
        "||example.com^:third-party :script",
        "evil.com $severity=critical $category=malware",
        
        # Mit Werten in Quotes
        "domain.com :msg=\"SQL Injection\" :severity=high",
    ]
    
    print("="*80)
    print("FLEXIBLE MODIFIER PARSER - TEST RESULTS")
    print("="*80)
    
    for test_rule in test_cases:
        print(f"\n📝 Input:  {test_rule}")
        
        base_rule, modifiers = parser.parse(test_rule)
        
        print(f"   Base:   {base_rule}")
        print(f"   Modifiers ({len(modifiers)}):")
        
        for mod in modifiers:
            value_str = f"={mod.value}" if mod.value else ""
            category_str = f"[{mod.category.value}]"
            print(f"     - {mod.name}{value_str} {category_str} "
                  f"(original: {mod.original_prefix}{mod.original_name})")
        
        if parser.warnings:
            print("   ⚠️  Warnings:")
            for warn in parser.warnings:
                print(f"     - {warn}")
        
        # Show normalized versions
        print(f"   Normalized (mixed):  {parser.to_normalized_string(base_rule, modifiers, 'mixed')}")
        print(f"   Normalized (adblock): {parser.to_normalized_string(base_rule, modifiers, 'adblock')}")
        print(f"   Normalized (ubs):     {parser.to_normalized_string(base_rule, modifiers, 'ubs')}")
    
    print("\n" + "="*80)


# ============================================================================
# STANDALONE VERSION FÜR DIREKTEN IMPORT
# ============================================================================

def parse_rule_flexible(rule_string: str, 
                       strict_syntax: bool = False) -> Tuple[str, Dict[str, Optional[str]]]:
    """
    Standalone function to parse a rule with flexible modifier syntax
    
    Args:
        rule_string: The rule to parse
        strict_syntax: If True, warns about syntax inconsistencies
    
    Returns:
        (base_rule, modifiers_dict): Base rule and modifiers as dictionary
    
    Example:
        >>> base, mods = parse_rule_flexible("||ads.com^:third :severity=high")
        >>> print(base)
        "||ads.com^"
        >>> print(mods)
        {"third-party": None, "severity": "high"}
    """
    parser = FlexibleModifierParser(strict_syntax=strict_syntax)
    base_rule, parsed_modifiers = parser.parse(rule_string)
    
    # Convert to simple dict
    modifiers_dict = {mod.name: mod.value for mod in parsed_modifiers}
    
    return base_rule, modifiers_dict


if __name__ == '__main__':
    # Run tests
    test_flexible_parser()
    
    print("\n" + "="*80)
    print("STANDALONE FUNCTION TEST")
    print("="*80)
    
    # Test standalone function
    test_rule = "||tracker.com^:third :severity=high $script"
    base, mods = parse_rule_flexible(test_rule)
    print(f"\nInput:     {test_rule}")
    print(f"Base Rule: {base}")
    print(f"Modifiers: {mods}")
