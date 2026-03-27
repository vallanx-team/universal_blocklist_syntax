#!/usr/bin/env python3
"""
UBS Smart Converter Module
- Automatic format detection
- Format-specific optimizations
- Batch conversion to all formats
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class TargetFormat(Enum):
    """Supported target formats"""
    # Basic formats
    HOSTS = "hosts"
    ADBLOCK = "adblock"
    DNSMASQ = "dnsmasq"
    UNBOUND = "unbound"
    BIND = "bind"
    SQUID = "squid"
    PROXY_PAC = "pac"
    SURICATA = "suricata"
    LITTLE_SNITCH = "littlesnitch"
    
    # Extended formats
    PIHOLE = "pihole"
    PFSENSE = "pfsense"
    OPNSENSE = "opnsense"
    WINDOWS_FW = "windows"
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    MODSECURITY = "modsecurity"
    NGINX = "nginx"
    APACHE = "apache"
    CLOUDFLARE_WAF = "cloudflare"
    AWS_WAF = "aws-waf"


@dataclass
class ConversionResult:
    """Result of a conversion operation"""
    format: str
    content: str
    file_path: Optional[str] = None
    success: bool = True
    error: Optional[str] = None
    optimizations_applied: List[str] = None
    
    def __post_init__(self):
        if self.optimizations_applied is None:
            self.optimizations_applied = []


class FormatDetector:
    """Automatically detect file format"""
    
    @staticmethod
    def detect_from_content(content: str) -> Optional[TargetFormat]:
        """Detect format from file content"""
        
        # Check first few lines
        lines = content.strip().split('\n')[:10]
        
        # Hosts format
        if any(re.match(r'^\d+\.\d+\.\d+\.\d+\s+\S+', line) for line in lines):
            return TargetFormat.HOSTS
        
        # AdBlock format
        if '[Adblock Plus' in content or content.startswith('!'):
            return TargetFormat.ADBLOCK
        
        # Dnsmasq
        if any(line.startswith('address=/') for line in lines):
            return TargetFormat.DNSMASQ
        
        # Unbound
        if 'local-zone:' in content and 'server:' in content:
            return TargetFormat.UNBOUND
        
        # BIND
        if 'zone "' in content and 'type master' in content:
            return TargetFormat.BIND
        
        # Suricata
        if any(line.startswith('alert ') for line in lines):
            return TargetFormat.SURICATA
        
        # Proxy PAC
        if 'FindProxyForURL' in content:
            return TargetFormat.PROXY_PAC
        
        # ModSecurity
        if 'SecRule' in content:
            return TargetFormat.MODSECURITY
        
        # Nginx
        if 'server {' in content or 'if ($host' in content:
            return TargetFormat.NGINX
        
        # Apache
        if 'RewriteEngine' in content or '<VirtualHost' in content:
            return TargetFormat.APACHE
        
        return None
    
    @staticmethod
    def detect_from_filename(filename: str) -> Optional[TargetFormat]:
        """Detect format from filename"""
        filename = filename.lower()
        
        if filename.endswith('.hosts') or filename == 'hosts':
            return TargetFormat.HOSTS
        elif filename.endswith('.txt') and 'adblock' in filename:
            return TargetFormat.ADBLOCK
        elif filename.endswith('.conf'):
            if 'dnsmasq' in filename:
                return TargetFormat.DNSMASQ
            elif 'unbound' in filename:
                return TargetFormat.UNBOUND
            elif 'nginx' in filename:
                return TargetFormat.NGINX
            elif 'apache' in filename:
                return TargetFormat.APACHE
        elif filename.endswith('.rules'):
            return TargetFormat.SURICATA
        elif filename.endswith('.pac'):
            return TargetFormat.PROXY_PAC
        elif filename.endswith('.db'):
            return TargetFormat.PIHOLE
        elif filename.endswith('.json'):
            if 'cloudflare' in filename or 'cf-' in filename:
                return TargetFormat.CLOUDFLARE_WAF
            elif 'aws' in filename:
                return TargetFormat.AWS_WAF
            elif 'littlesnitch' in filename:
                return TargetFormat.LITTLE_SNITCH
        
        return None


class FormatOptimizer:
    """Apply format-specific optimizations"""
    
    def __init__(self, parser):
        self.parser = parser
    
    def optimize_for_format(self, target_format: TargetFormat) -> Tuple[List, List[str]]:
        """
        Optimize rules for specific target format
        Returns: (optimized_rules, list_of_optimizations_applied)
        """
        rules = self.parser.rules.copy()
        optimizations = []
        
        if target_format in [TargetFormat.HOSTS, TargetFormat.DNSMASQ, 
                            TargetFormat.UNBOUND, TargetFormat.BIND]:
            # DNS-level formats: only keep domain rules
            original_count = len(rules)
            rules = [r for r in rules if r.rule_type.value == 'domain']
            if len(rules) < original_count:
                optimizations.append(f"Filtered to domain-only rules ({len(rules)}/{original_count})")
            
            # Remove regex rules (not supported)
            rules = [r for r in rules if not r.modifiers.get('regex')]
            optimizations.append("Removed regex patterns (not supported in DNS)")
        
        elif target_format == TargetFormat.ADBLOCK:
            # Keep URL patterns and element hiding
            optimizations.append("Optimized for browser-based blocking")
        
        elif target_format in [TargetFormat.MODSECURITY, TargetFormat.NGINX, 
                               TargetFormat.APACHE]:
            # WAF formats: prioritize high-severity rules
            high_severity = [r for r in rules if r.modifiers.get('severity') in ['high', 'critical']]
            if high_severity:
                rules = high_severity + [r for r in rules if r not in high_severity]
                optimizations.append(f"Prioritized {len(high_severity)} high-severity rules")
        
        elif target_format == TargetFormat.SURICATA:
            # IDS format: keep rules with severity or content
            rules = [r for r in rules if r.modifiers.get('severity') or 
                    r.rule_type.value == 'suricata']
            optimizations.append("Filtered to security-relevant rules")
        
        elif target_format in [TargetFormat.PIHOLE, TargetFormat.PFSENSE]:
            # Remove duplicates more aggressively
            seen = set()
            unique_rules = []
            for r in rules:
                pattern = r.pattern.replace('*.', '')
                if pattern not in seen:
                    seen.add(pattern)
                    unique_rules.append(r)
            if len(unique_rules) < len(rules):
                optimizations.append(f"Removed {len(rules) - len(unique_rules)} duplicate patterns")
            rules = unique_rules
        
        return rules, optimizations


class SmartConverter:
    """
    Smart converter with automatic format detection and optimization
    """
    
    def __init__(self, parser):
        self.parser = parser
        self.detector = FormatDetector()
        self.optimizer = FormatOptimizer(parser)
    
    def convert_auto(self, target: str, optimize: bool = True) -> ConversionResult:
        """
        Automatically detect format and convert
        
        Args:
            target: filename or format name
            optimize: apply format-specific optimizations
        """
        # Try to detect format
        detected_format = self.detector.detect_from_filename(target)
        
        if not detected_format:
            # Try parsing as format name
            try:
                detected_format = TargetFormat(target.lower())
            except ValueError:
                return ConversionResult(
                    format="unknown",
                    content="",
                    success=False,
                    error=f"Could not detect format from: {target}"
                )
        
        return self.convert(detected_format, optimize=optimize)
    
    def convert(self, target_format: TargetFormat, optimize: bool = True) -> ConversionResult:
        """
        Convert to specific format with optional optimization
        """
        try:
            # Apply optimizations
            optimizations = []
            if optimize:
                original_rules = list(self.parser.rules)
                optimized_rules, optimizations = self.optimizer.optimize_for_format(target_format)
                # Temporarily replace rules
                self.parser.rules = optimized_rules

            # Convert based on format
            content = self._do_conversion(target_format)

            # Restore original rules
            if optimize:
                self.parser.rules = original_rules
            
            return ConversionResult(
                format=target_format.value,
                content=content,
                success=True,
                optimizations_applied=optimizations
            )
        
        except Exception as e:
            return ConversionResult(
                format=target_format.value,
                content="",
                success=False,
                error=str(e)
            )
    
    def _do_conversion(self, target_format: TargetFormat) -> str:
        """Perform the actual conversion"""
        from ubs_parser import UBSConverter
        from ubs_performance_optimization import ExtendedConverters
        
        basic_converter = UBSConverter(self.parser)
        extended_converter = ExtendedConverters(self.parser)
        
        # Basic formats
        if target_format == TargetFormat.HOSTS:
            return basic_converter.to_hosts()
        elif target_format == TargetFormat.ADBLOCK:
            return basic_converter.to_adblock()
        elif target_format == TargetFormat.DNSMASQ:
            return basic_converter.to_dnsmasq()
        elif target_format == TargetFormat.UNBOUND:
            return basic_converter.to_unbound()
        elif target_format == TargetFormat.BIND:
            return basic_converter.to_bind()
        elif target_format == TargetFormat.SQUID:
            return basic_converter.to_squid()
        elif target_format == TargetFormat.PROXY_PAC:
            return basic_converter.to_proxy_pac()
        elif target_format == TargetFormat.SURICATA:
            return basic_converter.to_suricata()
        elif target_format == TargetFormat.LITTLE_SNITCH:
            return basic_converter.to_little_snitch()
        
        # Extended formats
        elif target_format == TargetFormat.PFSENSE:
            return extended_converter.to_pfsense()
        elif target_format == TargetFormat.OPNSENSE:
            return extended_converter.to_opnsense()
        elif target_format == TargetFormat.WINDOWS_FW:
            return extended_converter.to_windows_firewall()
        elif target_format == TargetFormat.IPTABLES:
            return extended_converter.to_iptables()
        elif target_format == TargetFormat.NFTABLES:
            return extended_converter.to_nftables()
        elif target_format == TargetFormat.MODSECURITY:
            return extended_converter.to_modsecurity()
        elif target_format == TargetFormat.NGINX:
            return extended_converter.to_nginx()
        elif target_format == TargetFormat.APACHE:
            return extended_converter.to_apache()
        elif target_format == TargetFormat.CLOUDFLARE_WAF:
            return extended_converter.to_cloudflare_waf()
        elif target_format == TargetFormat.AWS_WAF:
            return extended_converter.to_aws_waf()
        
        else:
            raise ValueError(f"Unsupported format: {target_format}")
    
    def batch_convert_all(self, output_dir: Path, optimize: bool = True) -> Dict[str, ConversionResult]:
        """
        Convert to ALL supported formats at once
        
        Returns: dict mapping format name to ConversionResult
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        results = {}
        
        # Define output filenames for each format
        format_files = {
            TargetFormat.HOSTS: "blocklist.hosts",
            TargetFormat.ADBLOCK: "blocklist.txt",
            TargetFormat.DNSMASQ: "dnsmasq.conf",
            TargetFormat.UNBOUND: "unbound.conf",
            TargetFormat.BIND: "bind.conf",
            TargetFormat.SQUID: "squid.acl",
            TargetFormat.PROXY_PAC: "proxy.pac",
            TargetFormat.SURICATA: "suricata.rules",
            TargetFormat.LITTLE_SNITCH: "littlesnitch.json",
            TargetFormat.PFSENSE: "pfsense.txt",
            TargetFormat.OPNSENSE: "opnsense.conf",
            TargetFormat.WINDOWS_FW: "windows-firewall.ps1",
            TargetFormat.IPTABLES: "iptables.sh",
            TargetFormat.NFTABLES: "nftables.conf",
            TargetFormat.MODSECURITY: "modsecurity.conf",
            TargetFormat.NGINX: "nginx-block.conf",
            TargetFormat.APACHE: "apache-block.conf",
            TargetFormat.CLOUDFLARE_WAF: "cloudflare-waf.json",
            TargetFormat.AWS_WAF: "aws-waf.json",
        }
        
        print(f"\n🔄 Batch converting to {len(format_files)} formats...")
        
        for target_format, filename in format_files.items():
            result = self.convert(target_format, optimize=optimize)
            
            if result.success:
                file_path = output_dir / filename
                
                # Special handling for SQLite (Pi-hole)
                if target_format == TargetFormat.PIHOLE:
                    file_path = output_dir / "gravity.db"
                    from ubs_performance_optimization import ExtendedConverters
                    extended = ExtendedConverters(self.parser)
                    extended.to_pihole_sqlite(str(file_path))
                    result.file_path = str(file_path)
                    print(f"  ✅ {target_format.value}: {filename}")
                else:
                    # Write text-based formats
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(result.content)
                    result.file_path = str(file_path)
                    
                    # Show optimizations if any
                    if result.optimizations_applied:
                        print(f"  ✅ {target_format.value}: {filename} ({', '.join(result.optimizations_applied)})")
                    else:
                        print(f"  ✅ {target_format.value}: {filename}")
            else:
                print(f"  ❌ {target_format.value}: {result.error}")
            
            results[target_format.value] = result
        
        # Pi-hole special case
        if TargetFormat.PIHOLE not in format_files:
            try:
                from ubs_performance_optimization import ExtendedConverters
                extended = ExtendedConverters(self.parser)
                file_path = output_dir / "gravity.db"
                extended.to_pihole_sqlite(str(file_path))
                results['pihole'] = ConversionResult(
                    format='pihole',
                    content='',
                    file_path=str(file_path),
                    success=True
                )
                print(f"  ✅ pihole: gravity.db")
            except Exception as e:
                results['pihole'] = ConversionResult(
                    format='pihole',
                    content='',
                    success=False,
                    error=str(e)
                )
        
        successful = sum(1 for r in results.values() if r.success)
        print(f"\n✅ Batch conversion complete: {successful}/{len(results)} formats successful")
        print(f"📁 Output directory: {output_dir.absolute()}")
        
        return results
    
    def print_conversion_summary(self, results: Dict[str, ConversionResult]):
        """Print summary of batch conversion"""
        
        print(f"\n{'='*80}")
        print("BATCH CONVERSION SUMMARY")
        print(f"{'='*80}")
        
        successful = [r for r in results.values() if r.success]
        failed = [r for r in results.values() if not r.success]
        
        print(f"Total: {len(results)} | Success: {len(successful)} | Failed: {len(failed)}")
        print(f"{'='*80}\n")
        
        if successful:
            print("✅ SUCCESSFUL CONVERSIONS:")
            for result in successful:
                opts = f" ({', '.join(result.optimizations_applied)})" if result.optimizations_applied else ""
                print(f"  - {result.format}: {result.file_path}{opts}")
        
        if failed:
            print("\n❌ FAILED CONVERSIONS:")
            for result in failed:
                print(f"  - {result.format}: {result.error}")


# ============================================================================
# CLI INTEGRATION
# ============================================================================

def add_smart_converter_commands(subparsers):
    """Add smart converter commands to CLI"""
    
    # Smart convert command
    smart_parser = subparsers.add_parser('smart-convert',
                                         help='Smart convert with auto-detection')
    smart_parser.add_argument('file', help='UBS file')
    smart_parser.add_argument('target', 
                             help='Target format or filename')
    smart_parser.add_argument('--output', '-o',
                             help='Output file (optional)')
    smart_parser.add_argument('--no-optimize', action='store_true',
                             help='Disable format-specific optimizations')
    
    # Batch convert all command
    batch_all_parser = subparsers.add_parser('convert-all',
                                            help='Convert to ALL formats at once')
    batch_all_parser.add_argument('file', help='UBS file')
    batch_all_parser.add_argument('--output', '-o', default='./output',
                                 help='Output directory')
    batch_all_parser.add_argument('--no-optimize', action='store_true',
                                  help='Disable optimizations')


def handle_smart_convert_command(args):
    """Handle smart convert command"""
    from ubs_parser import UBSParser
    
    print(f"Smart converting: {args.file}")
    
    with open(args.file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = UBSParser()
    parser.parse(content)
    
    converter = SmartConverter(parser)
    result = converter.convert_auto(args.target, optimize=not args.no_optimize)
    
    if result.success:
        output_file = args.output or f"output.{result.format}"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(result.content)
        
        print(f"\n✅ Converted to {result.format}: {output_file}")
        
        if result.optimizations_applied:
            print(f"\nOptimizations applied:")
            for opt in result.optimizations_applied:
                print(f"  - {opt}")
    else:
        print(f"\n❌ Conversion failed: {result.error}")
        return 1
    
    return 0


def handle_convert_all_command(args):
    """Handle convert-all command"""
    from ubs_parser import UBSParser
    
    print(f"Batch converting: {args.file}")
    
    with open(args.file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = UBSParser()
    parser.parse(content)
    
    converter = SmartConverter(parser)
    results = converter.batch_convert_all(
        Path(args.output),
        optimize=not args.no_optimize
    )
    
    converter.print_conversion_summary(results)
    
    # Return error code if any conversions failed
    failed = sum(1 for r in results.values() if not r.success)
    return 1 if failed > 0 else 0


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    from ubs_parser import UBSParser
    
    example_ubs = """
! Title: Smart Converter Test
! Version: 1.0.0

[Tracking]
||analytics.com^ :third-party
||ads.example.com^ :severity=high
facebook.com##.cookie-banner

[Malware]
evil.com :severity=critical :category=malware
*.phishing.net :severity=high
"""
    
    print("=== Smart Converter Demo ===\n")
    
    parser = UBSParser()
    parser.parse(example_ubs)
    
    converter = SmartConverter(parser)
    
    # Auto-detect and convert
    print("1. Auto-detection from filename:")
    result = converter.convert_auto("blocklist.hosts", optimize=True)
    print(f"   Detected format: {result.format}")
    print(f"   Optimizations: {result.optimizations_applied}")
    
    # Convert to specific format
    print("\n2. Convert to AdBlock with optimization:")
    result = converter.convert(TargetFormat.ADBLOCK, optimize=True)
    print(f"   Success: {result.success}")
    print(f"   Content preview: {result.content[:100]}...")
    
    print("\n✅ Smart Converter module loaded successfully!")
