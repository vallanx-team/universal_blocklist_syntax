#!/usr/bin/env python3
"""
Universal Blocklist Syntax (UBS) - TTL Extension
Version: 1.0.1 (Patched for String→Int TTL conversion)

Standalone extension for TTL (Time To Live) modification support.
This module extends UBSConverter without modifying the original ubs_parser.py

Usage:
    from ubs_parser import UBSParser
    from ubs_ttl_extension import UBSConverterTTL
    
    parser = UBSParser()
    parser.parse(content)
    
    # Use extended converter with TTL support
    converter = UBSConverterTTL(parser)
    print(converter.to_unbound_ttl())
"""

import os
import sys
from typing import Dict, List, Set, Tuple, Union


# Absoluter Pfad zu ubs_parser.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARSER_PATH = os.path.join(BASE_DIR, "ubs_parser.py")

try:
    from ubs_parser import UBSParser, RuleType, Rule
except ImportError:
    print("Error: ubs_parser.py not found. Please ensure it's in the same directory.")
    sys.exit(1)



# BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# if BASE_DIR not in sys.path:
#     sys.path.insert(0, BASE_DIR)

# try:
#     from ubs_parser import UBSConverter, UBSParser, RuleType, Rule
# except ImportError:
#     print("Error: ubs_parser.py not found. Please ensure it's in the same directory.")
#     exit(1)

class UBSConverter:
    def __init__(self, parser: UBSParser):
        self.parser = parser

    def convert(self):
        # Basis-Logik
        return getattr(self.parser, 'rules', [])



class UBSConverterTTL(UBSConverter):
    """
    Extended UBSConverter with TTL support.
    Inherits all original methods and adds TTL-specific conversions.
    """
    
    def __init__(self, parser: UBSParser):
        """Initialize with UBSParser instance"""
        super().__init__(parser)
        self.default_ttl = 300  # 5 minutes default
    
    def _get_ttl(self, rule: Rule, default: int = None) -> int:
        """
        Safely get TTL value from rule, converting string to int if needed.
        
        Args:
            rule: The rule to extract TTL from
            default: Default TTL if not specified (uses self.default_ttl if None)
        
        Returns:
            TTL as integer
        """
        if default is None:
            default = self.default_ttl
            
        ttl = rule.modifiers.get('ttl')
        
        if ttl is None:
            return default
        
        # Convert to int if it's a string
        try:
            return int(ttl)
        except (ValueError, TypeError):
            # If conversion fails, return default
            return default
    
    # ========================================================================
    # TTL-SPECIFIC CONVERSION METHODS
    # ========================================================================
    
    def to_unbound_ttl(self) -> str:
        """Convert to Unbound format with TTL support"""
        lines = ["# Converted from UBS format with TTL"]
        lines.append("server:")
        lines.append("")
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.DOMAIN:
                pattern = rule.pattern.replace('*.', '')
                
                if rule.modifiers.get('regex'):
                    continue
                
                # Get TTL value (now safely converted to int)
                ttl = self._get_ttl(rule)
                
                # Check action
                if rule.modifiers.get('action') == 'allow':
                    continue
                elif rule.modifiers.get('action') == 'null':
                    lines.append(f'  local-data: "{pattern}. {ttl} IN A 0.0.0.0"')
                elif rule.modifiers.get('action') == 'nxdomain':
                    lines.append(f'  local-zone: "{pattern}" static')
                    lines.append(f'  local-data: "{pattern}. {ttl} IN SOA localhost. nobody.invalid. 1 3600 1200 604800 {ttl}"')
                else:
                    lines.append(f'  local-zone: "{pattern}" always_nxdomain')
        
        return '\n'.join(lines)
    
    def to_bind_ttl(self) -> str:
        """Convert to BIND zone format with TTL support"""
        lines = ["// Converted from UBS format with TTL"]
        lines.append("")
        
        # Group rules by TTL for efficiency
        ttl_groups: Dict[int, List[str]] = {}
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.DOMAIN and rule.modifiers.get('action') != 'allow':
                pattern = rule.pattern.replace('*.', '')
                if not rule.modifiers.get('regex'):
                    ttl = self._get_ttl(rule)
                    
                    if ttl not in ttl_groups:
                        ttl_groups[ttl] = []
                    ttl_groups[ttl].append(pattern)
        
        # Generate BIND zones grouped by TTL
        for ttl, domains in sorted(ttl_groups.items()):
            lines.append(f"// Zones with TTL={ttl}s ({ttl//60} minutes)")
            for domain in domains:
                lines.append(f'zone "{domain}" {{ type master; file "/etc/bind/null-{ttl}.zone"; }};')
            lines.append("")
        
        # Generate example null zone files
        lines.append("// =====================================================")
        lines.append("// Example null zone file templates:")
        lines.append("// =====================================================")
        for ttl in sorted(ttl_groups.keys()):
            lines.append(f"")
            lines.append(f"// File: /etc/bind/null-{ttl}.zone")
            lines.append(f"$TTL {ttl}")
            lines.append('@ IN SOA localhost. root.localhost. (')
            lines.append('    1         ; Serial')
            lines.append('    3600      ; Refresh')
            lines.append('    1200      ; Retry')
            lines.append('    604800    ; Expire')
            lines.append(f'    {ttl} )   ; Negative Cache TTL')
            lines.append('@ IN NS localhost.')
            lines.append('@ IN A 0.0.0.0')
        
        return '\n'.join(lines)
    
    def to_dnsmasq_ttl(self) -> str:
        """Convert to dnsmasq format with TTL support"""
        lines = ["# Converted from UBS format with TTL"]
        lines.append("# Add to /etc/dnsmasq.conf or /etc/dnsmasq.d/blocklist.conf")
        lines.append("")
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.DOMAIN and rule.modifiers.get('action') != 'allow':
                pattern = rule.pattern.replace('*.', '')
                
                if rule.modifiers.get('regex'):
                    continue
                
                # Get TTL value - only use if explicitly set
                ttl_raw = rule.modifiers.get('ttl')
                
                if ttl_raw:
                    try:
                        ttl = int(ttl_raw)
                        # dnsmasq syntax: address=/domain/ip#ttl
                        lines.append(f"address=/{pattern}/0.0.0.0#{ttl}")
                    except (ValueError, TypeError):
                        # If conversion fails, use without TTL
                        lines.append(f"address=/{pattern}/0.0.0.0")
                else:
                    # Default without TTL
                    lines.append(f"address=/{pattern}/0.0.0.0")
        
        return '\n'.join(lines)
    
    def to_pihole_ttl(self) -> str:
        """Convert to Pi-hole format with TTL recommendations"""
        lines = ["# Converted from UBS format for Pi-hole"]
        lines.append("# Pi-hole uses system TTL settings globally")
        lines.append("#")
        lines.append("# To configure TTL in Pi-hole:")
        lines.append("# Edit /etc/pihole/pihole-FTL.conf and add:")
        lines.append("# BLOCK_TTL=300")
        lines.append("")
        
        # Collect unique TTL values and domains
        ttls: Set[int] = set()
        domains: List[str] = []
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.DOMAIN and rule.modifiers.get('action') != 'allow':
                pattern = rule.pattern.replace('*.', '')
                
                if not rule.modifiers.get('regex'):
                    domains.append(pattern)
                    ttl_raw = rule.modifiers.get('ttl')
                    if ttl_raw:
                        try:
                            ttls.add(int(ttl_raw))
                        except (ValueError, TypeError):
                            pass
        
        # Add TTL recommendations
        if ttls:
            avg_ttl = sum(ttls) // len(ttls)
            lines.append(f"# RECOMMENDED TTL SETTINGS:")
            lines.append(f"# Average TTL from rules: {avg_ttl}s ({avg_ttl//60} minutes)")
            lines.append(f"# All TTL values found: {sorted(ttls)}")
            lines.append(f"# Suggestion: BLOCK_TTL={avg_ttl}")
        else:
            lines.append(f"# No TTL modifiers found - using Pi-hole defaults")
        
        lines.append("")
        lines.append("# Domain blocklist:")
        
        # Add domains
        for domain in domains:
            lines.append(domain)
        
        return '\n'.join(lines)
    
    def to_coredns_ttl(self) -> str:
        """Convert to CoreDNS Corefile format with TTL"""
        lines = ["# Converted from UBS format for CoreDNS"]
        lines.append("# Add to Corefile (usually /etc/coredns/Corefile)")
        lines.append("")
        
        # Collect rules with TTL
        ttl_rules: Dict[int, List[str]] = {}
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.DOMAIN and rule.modifiers.get('action') != 'allow':
                pattern = rule.pattern.replace('*.', '')
                
                if not rule.modifiers.get('regex'):
                    ttl = self._get_ttl(rule)
                    if ttl not in ttl_rules:
                        ttl_rules[ttl] = []
                    ttl_rules[ttl].append(pattern)
        
        # Generate CoreDNS config
        lines.append(". {")
        lines.append("    # Forward to upstream DNS")
        lines.append("    forward . 8.8.8.8 8.8.4.4")
        lines.append("")
        lines.append("    # Block domains with custom TTL")
        
        for ttl, domains in sorted(ttl_rules.items()):
            lines.append(f"")
            lines.append(f"    # TTL={ttl}s ({ttl//60} minutes) - {len(domains)} domains")
            lines.append(f"    template IN A {{")
            
            # Create regex pattern for all domains with this TTL
            domain_patterns = [d.replace('.', '\\.') for d in domains[:10]]
            lines.append(f"        match \"({'|'.join(domain_patterns)})\"")
            lines.append(f"        answer \"{{{{ .Name }}}} {ttl} IN A 0.0.0.0\"")
            lines.append(f"        fallthrough")
            lines.append(f"    }}")
            
            if len(domains) > 10:
                lines.append(f"    # ... and {len(domains) - 10} more domains")
        
        lines.append("")
        lines.append("    # Logging and cache")
        lines.append("    log")
        lines.append("    errors")
        lines.append("    cache 30")
        lines.append("}")
        
        return '\n'.join(lines)
    
    def to_ttl_report(self) -> str:
        """Generate detailed TTL analysis report"""
        lines = ["=" * 70]
        lines.append("TTL ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append("")
        
        # Collect statistics
        ttl_stats: Dict[int, List[str]] = {}
        total_rules = 0
        rules_with_ttl = 0
        action_stats: Dict[str, int] = {}
        
        for rule in self.parser.rules:
            if rule.rule_type == RuleType.DOMAIN:
                total_rules += 1
                ttl_raw = rule.modifiers.get('ttl')
                action = rule.modifiers.get('action', 'block')
                
                # Count actions
                action_stats[action] = action_stats.get(action, 0) + 1
                
                if ttl_raw:
                    try:
                        ttl = int(ttl_raw)
                        rules_with_ttl += 1
                        if ttl not in ttl_stats:
                            ttl_stats[ttl] = []
                        ttl_stats[ttl].append(rule.pattern)
                    except (ValueError, TypeError):
                        # Invalid TTL value - skip
                        pass
        
        # General statistics
        lines.append("GENERAL STATISTICS")
        lines.append("-" * 70)
        lines.append(f"Total domain rules:        {total_rules}")
        lines.append(f"Rules with TTL specified:  {rules_with_ttl} ({rules_with_ttl*100//max(total_rules,1)}%)")
        lines.append(f"Rules without TTL:         {total_rules - rules_with_ttl} (will use default: {self.default_ttl}s)")
        lines.append("")
        
        # Action statistics
        lines.append("ACTION DISTRIBUTION")
        lines.append("-" * 70)
        for action, count in sorted(action_stats.items()):
            lines.append(f"  {action:15s} {count:5d} rules ({count*100//total_rules:3d}%)")
        lines.append("")
        
        # TTL distribution
        if ttl_stats:
            lines.append("TTL DISTRIBUTION")
            lines.append("-" * 70)
            lines.append(f"{'TTL (seconds)':<15} {'Time':<15} {'Rules':<10} {'Percentage'}")
            lines.append("-" * 70)
            
            for ttl in sorted(ttl_stats.keys()):
                domains = ttl_stats[ttl]
                time_str = self._format_ttl_time(ttl)
                percentage = len(domains) * 100 // rules_with_ttl
                lines.append(f"{ttl:<15} {time_str:<15} {len(domains):<10} {percentage}%")
            
            lines.append("")
            lines.append("TOP DOMAINS PER TTL")
            lines.append("-" * 70)
            
            for ttl in sorted(ttl_stats.keys()):
                domains = ttl_stats[ttl]
                lines.append(f"\nTTL={ttl}s ({self._format_ttl_time(ttl)}) - {len(domains)} domains:")
                for domain in domains[:5]:
                    lines.append(f"  • {domain}")
                if len(domains) > 5:
                    lines.append(f"  ... and {len(domains) - 5} more")
        else:
            lines.append("TTL DISTRIBUTION")
            lines.append("-" * 70)
            lines.append("⚠ No TTL values specified in any rules")
        
        lines.append("")
        
        # Recommendations
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 70)
        
        if rules_with_ttl == 0:
            lines.append("⚠ WARNING: No TTL values specified")
            lines.append("")
            lines.append("  Recommendation: Add TTL modifiers to your rules")
            lines.append("  Examples:")
            lines.append("    malware.com :ttl=60      # Critical, short TTL")
            lines.append("    tracker.com :ttl=300     # Standard, 5 minutes")
            lines.append("    stable-ad.com :ttl=3600  # Stable, 1 hour")
        else:
            avg_ttl = sum(k * len(v) for k, v in ttl_stats.items()) // rules_with_ttl
            lines.append(f"✓ Average TTL: {avg_ttl}s ({self._format_ttl_time(avg_ttl)})")
            lines.append("")
            
            if avg_ttl < 60:
                lines.append("⚠ WARNING: Very short average TTL detected")
                lines.append("  • May increase DNS query load significantly")
                lines.append("  • Consider increasing TTL to 300s (5 minutes) for most rules")
            elif avg_ttl > 3600:
                lines.append("⚠ NOTICE: Long average TTL detected")
                lines.append("  • Blocked domains will be cached for a long time")
                lines.append("  • Updates to blocklist will take longer to propagate")
                lines.append("  • Good for stable, well-known blocklists")
            else:
                lines.append("✓ TTL values are in a reasonable range")
            
            # Check for extreme values
            if ttl_stats:
                min_ttl = min(ttl_stats.keys())
                max_ttl = max(ttl_stats.keys())
                
                lines.append("")
                lines.append(f"TTL Range: {min_ttl}s to {max_ttl}s")
                
                if max_ttl / max(min_ttl, 1) > 100:
                    lines.append("⚠ Very wide TTL range detected - ensure this is intentional")
        
        lines.append("")
        lines.append("BEST PRACTICES")
        lines.append("-" * 70)
        lines.append("• Critical malware domains:    60-120s  (quick updates)")
        lines.append("• Standard tracking/ads:       300s     (5 minutes)")
        lines.append("• Stable known advertisers:    3600s    (1 hour)")
        lines.append("• Very stable blocklists:      86400s   (24 hours)")
        lines.append("")
        lines.append("=" * 70)
        
        return '\n'.join(lines)
    
    def _format_ttl_time(self, seconds: int) -> str:
        """Format TTL seconds into human-readable time"""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds//60}m"
        elif seconds < 86400:
            hours = seconds // 3600
            mins = (seconds % 3600) // 60
            return f"{hours}h {mins}m" if mins else f"{hours}h"
        else:
            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            return f"{days}d {hours}h" if hours else f"{days}d"
    
    # ========================================================================
    # ENHANCED VERSIONS OF ORIGINAL METHODS WITH TTL AWARENESS
    # ========================================================================
    
    def to_unbound(self) -> str:
        """
        Enhanced version of original to_unbound() with optional TTL support.
        Falls back to original behavior if no TTL modifiers present.
        """
        # Check if any rules have TTL modifiers
        has_ttl = any(rule.modifiers.get('ttl') for rule in self.parser.rules)
        
        if has_ttl:
            return self.to_unbound_ttl()
        else:
            return super().to_unbound()
    
    def to_bind(self) -> str:
        """
        Enhanced version of original to_bind() with optional TTL support.
        Falls back to original behavior if no TTL modifiers present.
        """
        has_ttl = any(rule.modifiers.get('ttl') for rule in self.parser.rules 
                     if rule.rule_type == RuleType.DOMAIN)
        
        if has_ttl:
            return self.to_bind_ttl()
        else:
            return super().to_bind()
    
    def to_dnsmasq(self) -> str:
        """
        Enhanced version of original to_dnsmasq() with optional TTL support.
        Falls back to original behavior if no TTL modifiers present.
        """
        has_ttl = any(rule.modifiers.get('ttl') for rule in self.parser.rules)
        
        if has_ttl:
            return self.to_dnsmasq_ttl()
        else:
            return super().to_dnsmasq()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def convert_with_ttl(ubs_content: str, format: str = 'unbound') -> str:
    """
    Convenience function to parse UBS content and convert to specified format.
    
    Args:
        ubs_content: UBS rule content as string
        format: Output format (unbound, bind, dnsmasq, pihole, coredns, report)
    
    Returns:
        Converted content as string
    """
    parser = UBSParser()
    parser.parse(ubs_content)
    
    converter = UBSConverterTTL(parser)
    
    format_map = {
        'unbound': converter.to_unbound_ttl,
        'bind': converter.to_bind_ttl,
        'dnsmasq': converter.to_dnsmasq_ttl,
        'pihole': converter.to_pihole_ttl,
        'coredns': converter.to_coredns_ttl,
        'report': converter.to_ttl_report,
    }
    
    if format not in format_map:
        raise ValueError(f"Unknown format: {format}. Available: {list(format_map.keys())}")
    
    return format_map[format]()


# ============================================================================
# DEMO / TESTING
# ============================================================================

if __name__ == "__main__":
    # Example UBS content with TTL modifiers
    example_ubs = """
! Title: Example UBS Blocklist with TTL
! Version: 1.0.0
! Updated: 2025-10-11
! License: MIT

[Critical-Malware]
# High-priority malware - very short TTL for quick updates
evil-malware.com :ttl=60 :severity=critical :category=malware
*.phishing-site.net :ttl=120 :action=nxdomain :severity=high

[Standard-Tracking]
# Regular tracking domains - standard 5 minute TTL
tracker.example.com :ttl=300 :category=tracker
analytics.ad-company.com :ttl=300 :action=null

[Stable-Advertisers]
# Well-known ad networks - 1 hour TTL
doubleclick.net :ttl=3600 :category=advertising
*.googlesyndication.com :ttl=3600

[Very-Stable-Blocklist]
# Permanent blocklist - 24 hour TTL
known-adserver.com :ttl=86400
spam-domain.net :ttl=86400

[No-TTL-Specified]
# These will use default TTL (300s)
default-tracker.com :category=tracker
another-domain.com
"""
    
    print("=" * 80)
    print("UBS TTL EXTENSION - DEMO")
    print("=" * 80)
    print()
    
    # Parse
    parser = UBSParser()
    parser.parse(example_ubs)
    
    print(f"✓ Parsed {len(parser.rules)} rules")
    print(f"✓ Metadata: {parser.metadata.title}")
    print()
    
    # Create extended converter
    converter = UBSConverterTTL(parser)
    
    # Test each format
    formats = [
        ('TTL Report', converter.to_ttl_report),
        ('Unbound with TTL', converter.to_unbound_ttl),
        ('BIND with TTL', converter.to_bind_ttl),
        ('Dnsmasq with TTL', converter.to_dnsmasq_ttl),
        ('Pi-hole with TTL', converter.to_pihole_ttl),
        ('CoreDNS with TTL', converter.to_coredns_ttl),
    ]
    
    for name, func in formats:
        print("=" * 80)
        print(f"{name.upper()}")
        print("=" * 80)
        result = func()
        # Show first 800 chars
        print(result[:800])
        if len(result) > 800:
            print(f"\n... ({len(result) - 800} more characters)")
        print()
        input("Press Enter to continue...")
