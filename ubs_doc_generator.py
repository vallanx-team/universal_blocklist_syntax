#!/usr/bin/env python3
"""
UBS Documentation Generator Module
- Auto-generate Markdown documentation
- Rule coverage reports
- Example usage per section
- Statistics and visualizations
"""

import json
from pathlib import Path
from typing import List, Dict, Optional
from collections import Counter, defaultdict
from datetime import datetime


class DocumentationGenerator:
    """Generate comprehensive documentation for UBS lists"""
    
    def __init__(self, parser):
        self.parser = parser
    
    def generate_full_documentation(self, output_file: str = "README.md"):
        """Generate complete documentation"""
        sections = [
            self._generate_header(),
            self._generate_overview(),
            self._generate_statistics(),
            self._generate_section_details(),
            self._generate_rule_examples(),
            self._generate_usage_guide(),
            self._generate_coverage_report(),
            self._generate_changelog()
        ]
        
        doc = "\n\n".join(sections)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(doc)
        
        print(f"✅ Documentation generated: {output_file}")
        return doc
    
    def _generate_header(self) -> str:
        """Generate documentation header"""
        title = self.parser.metadata.title or "UBS Blocklist"
        version = self.parser.metadata.version or "1.0.0"
        
        header = f"""# {title}

**Version:** {version}  
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
"""
        
        if self.parser.metadata.homepage:
            header += f"**Homepage:** {self.parser.metadata.homepage}  \n"
        
        if self.parser.metadata.license:
            header += f"**License:** {self.parser.metadata.license}  \n"
        
        if self.parser.metadata.expires:
            header += f"**Update Frequency:** {self.parser.metadata.expires}  \n"
        
        return header
    
    def _generate_overview(self) -> str:
        """Generate overview section"""
        targets = ', '.join(self.parser.metadata.targets) if self.parser.metadata.targets else 'All'
        
        overview = f"""## 📋 Overview

This blocklist contains **{len(self.parser.rules)} rules** designed for {targets} platforms.

### What's Blocked

This list blocks various categories of content including:
"""
        
        # Extract categories from modifiers
        categories = set()
        for rule in self.parser.rules:
            if 'category' in rule.modifiers:
                cat = rule.modifiers['category']
                if isinstance(cat, list):
                    categories.update(cat)
                else:
                    categories.add(cat)
        
        if categories:
            for category in sorted(categories):
                overview += f"- {category.title()}\n"
        else:
            overview += "- Various tracking and malicious domains\n"
        
        return overview
    
    def _generate_statistics(self) -> str:
        """Generate statistics section"""
        stats = f"""## 📊 Statistics

### Rule Distribution

| Metric | Count |
|--------|-------|
| **Total Rules** | {len(self.parser.rules)} |
"""
        
        # By type
        type_counts = Counter(r.rule_type.value for r in self.parser.rules)
        for rule_type, count in type_counts.most_common():
            stats += f"| {rule_type.replace('_', ' ').title()} | {count} |\n"
        
        # By severity
        severity_counts = Counter(
            r.modifiers.get('severity', 'unspecified') 
            for r in self.parser.rules
        )
        
        if any(s != 'unspecified' for s in severity_counts.keys()):
            stats += "\n### Severity Distribution\n\n"
            stats += "| Severity | Count |\n"
            stats += "|----------|-------|\n"
            
            for severity in ['critical', 'high', 'medium', 'low', 'unspecified']:
                if severity in severity_counts:
                    count = severity_counts[severity]
                    emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 
                            'low': '🟢', 'unspecified': '⚪'}.get(severity, '')
                    stats += f"| {emoji} {severity.title()} | {count} |\n"
        
        # By category
        category_counts = defaultdict(int)
        for rule in self.parser.rules:
            if 'category' in rule.modifiers:
                cat = rule.modifiers['category']
                if isinstance(cat, list):
                    for c in cat:
                        category_counts[c] += 1
                else:
                    category_counts[cat] += 1
        
        if category_counts:
            stats += "\n### Category Distribution\n\n"
            stats += "| Category | Count |\n"
            stats += "|----------|-------|\n"
            
            for category, count in sorted(category_counts.items(), key=lambda x: -x[1])[:10]:
                stats += f"| {category.title()} | {count} |\n"
        
        return stats
    
    def _generate_section_details(self) -> str:
        """Generate section-by-section breakdown"""
        section_rules = defaultdict(list)
        
        for rule in self.parser.rules:
            section = rule.section or "Uncategorized"
            section_rules[section].append(rule)
        
        if len(section_rules) <= 1:
            return ""
        
        details = "## 📑 Sections\n\n"
        
        for section, rules in sorted(section_rules.items()):
            details += f"### {section}\n\n"
            details += f"**Rules:** {len(rules)}  \n"
            
            # Count types in this section
            types = Counter(r.rule_type.value for r in rules)
            details += f"**Types:** {', '.join(f'{t} ({c})' for t, c in types.most_common())}  \n\n"
            
            # Show example rules (up to 5)
            if rules:
                details += "**Example Rules:**\n```\n"
                for rule in rules[:5]:
                    details += f"{rule.raw_line}\n"
                if len(rules) > 5:
                    details += f"... and {len(rules) - 5} more\n"
                details += "```\n\n"
        
        return details
    
    def _generate_rule_examples(self) -> str:
        """Generate examples for each rule type"""
        examples = "## 💡 Rule Examples\n\n"
        examples += "This section shows examples of different rule types used in this list.\n\n"
        
        # Group by type
        by_type = defaultdict(list)
        for rule in self.parser.rules:
            by_type[rule.rule_type.value].append(rule)
        
        type_descriptions = {
            'domain': 'Domain blocking rules block entire domains and their subdomains.',
            'url_pattern': 'URL pattern rules block specific paths or patterns.',
            'element_hiding': 'Element hiding rules remove specific page elements.',
            'scriptlet': 'Scriptlet rules inject code to modify page behavior.',
            'suricata': 'Suricata rules detect and block network threats.',
            'proxy': 'Proxy rules route traffic through specified proxies.',
            'whitelist': 'Whitelist rules explicitly allow certain domains.'
        }
        
        for rule_type, rules in sorted(by_type.items()):
            examples += f"### {rule_type.replace('_', ' ').title()} Rules\n\n"
            
            if rule_type in type_descriptions:
                examples += f"{type_descriptions[rule_type]}\n\n"
            
            examples += f"**Count:** {len(rules)} rules\n\n"
            examples += "**Examples:**\n```\n"
            
            for rule in rules[:3]:
                examples += f"{rule.raw_line}\n"
            
            examples += "```\n\n"
        
        return examples
    
    def _generate_usage_guide(self) -> str:
        """Generate usage guide"""
        usage = """## 🚀 Usage Guide

### Compatible Platforms

This blocklist can be used with:

"""
        
        targets = self.parser.metadata.targets
        if 'dns' in targets or not targets:
            usage += """#### DNS-Level Blocking
- **Pi-hole**: Add as custom blocklist
- **AdGuard Home**: Import as blocklist
- **Unbound**: Convert to unbound format
- **dnsmasq**: Convert to dnsmasq format

"""
        
        if 'browser' in targets or not targets:
            usage += """#### Browser Extensions
- **uBlock Origin**: Import as filter list
- **AdBlock Plus**: Add as subscription
- **AdGuard**: Import as custom filter

"""
        
        if 'waf' in targets or not targets:
            usage += """#### Web Application Firewalls
- **ModSecurity**: Convert to ModSecurity rules
- **Nginx**: Convert to nginx config
- **Apache**: Convert to Apache config

"""
        
        usage += """### Installation

#### Using UBS Tools

```bash
# Convert to your preferred format
ubs-tool convert blocklist.ubs --format hosts --output blocklist.txt

# Or convert to all formats
ubs-tool convert-all blocklist.ubs --output ./output/
```

#### Manual Installation

1. Download the list
2. Convert to your platform's format
3. Import into your blocking software
4. Update regularly (recommended: daily)

"""
        
        return usage
    
    def _generate_coverage_report(self) -> str:
        """Generate coverage report"""
        report = """## 📈 Coverage Report

### Domain Coverage

"""
        
        # Count unique base domains
        domains = set()
        wildcards = set()
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                pattern = rule.pattern
                if pattern.startswith('*.'):
                    wildcards.add(pattern[2:])
                else:
                    domains.add(pattern)
        
        report += f"- **Unique Domains:** {len(domains)}\n"
        report += f"- **Wildcard Rules:** {len(wildcards)}\n"
        report += f"- **Estimated Coverage:** {len(domains) + len(wildcards) * 10} domains (approx)\n\n"
        
        # Top blocked domains by TLD
        tlds = Counter()
        for domain in domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                tlds[parts[-1]] += 1
        
        if tlds:
            report += "### Top Blocked TLDs\n\n"
            report += "| TLD | Count |\n"
            report += "|-----|-------|\n"
            
            for tld, count in tlds.most_common(10):
                report += f"| .{tld} | {count} |\n"
            
            report += "\n"
        
        # Action distribution
        actions = Counter()
        for rule in self.parser.rules:
            action = rule.modifiers.get('action', 'block')
            actions[action] += 1
        
        report += "### Action Distribution\n\n"
        report += "| Action | Count |\n"
        report += "|--------|-------|\n"
        
        for action, count in actions.most_common():
            report += f"| {action.title()} | {count} |\n"
        
        return report
    
    def _generate_changelog(self) -> str:
        """Generate changelog section"""
        changelog = """## 📝 Changelog

"""
        
        if self.parser.metadata.updated:
            changelog += f"### {self.parser.metadata.version or 'Current Version'} - {self.parser.metadata.updated}\n\n"
            changelog += "- Initial release\n"
            changelog += f"- {len(self.parser.rules)} rules included\n"
        else:
            changelog += "No changelog available.\n"
        
        changelog += """
---

## 🔄 Updates

To stay up-to-date with the latest rules:

1. **Automatic Updates**: Configure your blocking software to auto-update
2. **Manual Updates**: Check for updates regularly
3. **Subscribe**: Watch this repository for changes

## 🐛 Reporting Issues

Found a false positive or missing domain? Please report:

1. The domain/URL in question
2. Why it should/shouldn't be blocked
3. Any supporting evidence

## 📜 License

"""
        
        if self.parser.metadata.license:
            changelog += f"This list is licensed under {self.parser.metadata.license}.\n"
        else:
            changelog += "Please check the license before use.\n"
        
        return changelog
    
    def generate_quick_reference(self, output_file: str = "QUICK_REFERENCE.md"):
        """Generate a quick reference card"""
        ref = f"""# {self.parser.metadata.title or 'Blocklist'} - Quick Reference

## 📊 At a Glance

- **Total Rules:** {len(self.parser.rules)}
- **Version:** {self.parser.metadata.version or 'N/A'}
- **Last Updated:** {self.parser.metadata.updated or 'N/A'}

## 🎯 Top Categories

"""
        
        # Top categories
        category_counts = Counter()
        for rule in self.parser.rules:
            if 'category' in rule.modifiers:
                cat = rule.modifiers['category']
                if isinstance(cat, list):
                    for c in cat:
                        category_counts[c] += 1
                else:
                    category_counts[cat] += 1
        
        for category, count in category_counts.most_common(5):
            ref += f"- **{category.title()}**: {count} rules\n"
        
        ref += """

## 🚀 Quick Start

### Pi-hole
```bash
ubs-tool convert-extended list.ubs --format pihole --output gravity.db
```

### Browser (AdBlock)
```bash
ubs-tool convert list.ubs --format adblock --output blocklist.txt
```

### Firewall
```bash
ubs-tool convert-extended list.ubs --format iptables --output firewall.sh
```

## 📞 Support

For detailed documentation, see README.md
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(ref)
        
        print(f"✅ Quick reference generated: {output_file}")
        return ref
    
    def generate_json_report(self, output_file: str = "report.json"):
        """Generate machine-readable JSON report"""
        
        # Collect statistics
        type_counts = Counter(r.rule_type.value for r in self.parser.rules)
        severity_counts = Counter(
            r.modifiers.get('severity', 'unspecified') 
            for r in self.parser.rules
        )
        category_counts = Counter()
        
        for rule in self.parser.rules:
            if 'category' in rule.modifiers:
                cat = rule.modifiers['category']
                if isinstance(cat, list):
                    for c in cat:
                        category_counts[c] += 1
                else:
                    category_counts[cat] += 1
        
        # Section breakdown
        section_stats = defaultdict(lambda: {'count': 0, 'types': Counter()})
        for rule in self.parser.rules:
            section = rule.section or 'uncategorized'
            section_stats[section]['count'] += 1
            section_stats[section]['types'][rule.rule_type.value] += 1
        
        # Build report
        report = {
            'metadata': {
                'title': self.parser.metadata.title,
                'version': self.parser.metadata.version,
                'updated': self.parser.metadata.updated,
                'expires': self.parser.metadata.expires,
                'homepage': self.parser.metadata.homepage,
                'license': self.parser.metadata.license,
                'targets': list(self.parser.metadata.targets)
            },
            'statistics': {
                'total_rules': len(self.parser.rules),
                'by_type': dict(type_counts),
                'by_severity': dict(severity_counts),
                'by_category': dict(category_counts),
                'by_section': {
                    section: {
                        'count': data['count'],
                        'types': dict(data['types'])
                    }
                    for section, data in section_stats.items()
                }
            },
            'coverage': {
                'unique_domains': len(set(
                    r.pattern for r in self.parser.rules 
                    if r.rule_type.value == 'domain'
                )),
                'wildcard_rules': len([
                    r for r in self.parser.rules 
                    if r.pattern.startswith('*.')
                ])
            },
            'generated': datetime.now().isoformat()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ JSON report generated: {output_file}")
        return report
    
    def generate_html_report(self, output_file: str = "report.html"):
        """Generate interactive HTML report"""
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.parser.metadata.title or 'Blocklist'} - Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            color: #667eea;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }}
        .section {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .section h2 {{
            margin-top: 0;
            color: #667eea;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-critical {{ background: #fee; color: #c00; }}
        .badge-high {{ background: #ffe; color: #c60; }}
        .badge-medium {{ background: #ffa; color: #960; }}
        .badge-low {{ background: #efe; color: #060; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{self.parser.metadata.title or 'Blocklist Report'}</h1>
        <p><strong>Version:</strong> {self.parser.metadata.version or 'N/A'} | 
           <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Rules</h3>
            <div class="stat-value">{len(self.parser.rules)}</div>
        </div>
"""
        
        # Add more stat cards
        type_counts = Counter(r.rule_type.value for r in self.parser.rules)
        for rule_type, count in list(type_counts.most_common())[:3]:
            html += f"""
        <div class="stat-card">
            <h3>{rule_type.replace('_', ' ').title()}</h3>
            <div class="stat-value">{count}</div>
        </div>
"""
        
        html += """
    </div>
    
    <div class="section">
        <h2>📊 Rule Distribution</h2>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
"""
        
        total = len(self.parser.rules)
        for rule_type, count in type_counts.most_common():
            percentage = (count / total * 100) if total > 0 else 0
            html += f"""
                <tr>
                    <td>{rule_type.replace('_', ' ').title()}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
    </div>
"""
        
        # Severity distribution
        severity_counts = Counter(
            r.modifiers.get('severity', 'unspecified') 
            for r in self.parser.rules
        )
        
        if any(s != 'unspecified' for s in severity_counts.keys()):
            html += """
    <div class="section">
        <h2>🎯 Severity Distribution</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
            
            for severity in ['critical', 'high', 'medium', 'low', 'unspecified']:
                if severity in severity_counts:
                    count = severity_counts[severity]
                    badge_class = f"badge-{severity}" if severity != 'unspecified' else ""
                    html += f"""
                <tr>
                    <td><span class="badge {badge_class}">{severity.upper()}</span></td>
                    <td>{count}</td>
                </tr>
"""
            
            html += """
            </tbody>
        </table>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"✅ HTML report generated: {output_file}")
        return html


# ============================================================================
# CLI INTEGRATION
# ============================================================================

def add_documentation_commands(subparsers):
    """Add documentation commands to CLI"""
    
    # Generate docs
    docs_parser = subparsers.add_parser('generate-docs',
                                        help='Generate documentation')
    docs_parser.add_argument('file', help='UBS file')
    docs_parser.add_argument('--output', '-o', default='README.md',
                            help='Output file')
    docs_parser.add_argument('--format', choices=['markdown', 'html', 'json', 'all'],
                            default='markdown',
                            help='Output format')
    docs_parser.add_argument('--quick-ref', action='store_true',
                            help='Also generate quick reference')


def handle_generate_docs_command(args):
    """Handle generate-docs command"""
    from ubs_parser import UBSParser
    
    print(f"Generating documentation for: {args.file}")
    
    with open(args.file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = UBSParser()
    parser.parse(content)
    
    generator = DocumentationGenerator(parser)
    
    if args.format == 'markdown' or args.format == 'all':
        generator.generate_full_documentation(args.output)
    
    if args.format == 'html' or args.format == 'all':
        html_output = args.output.replace('.md', '.html')
        generator.generate_html_report(html_output)
    
    if args.format == 'json' or args.format == 'all':
        json_output = args.output.replace('.md', '.json')
        generator.generate_json_report(json_output)
    
    if args.quick_ref or args.format == 'all':
        generator.generate_quick_reference('QUICK_REFERENCE.md')
    
    print("\n✅ Documentation generation complete!")
    return 0


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    from ubs_parser import UBSParser
    
    example_ubs = """
! Title: Example Security Blocklist
! Version: 2.1.0
! Updated: 2025-10-10
! License: MIT
! Target: dns,browser,waf

[Malware-Domains]
evil-malware.com :severity=critical :category=malware
dangerous-site.net :severity=high :category=malware
*.phishing.org :severity=critical :category=phishing

[Tracking]
||analytics.google.com^ :third-party :category=tracker
||facebook.com/tr/* :script :category=tracker
ads.example.com :severity=low :category=ads

[Ad-Networks]
||doubleclick.net^ :category=ads
||adserver.com^ :severity=low :category=ads

[Whitelist]
@||paypal.com^ :reason="Payment processor"
@@||cdn.cloudflare.com^ :first-party
"""
    
    print("=== Documentation Generator Demo ===\n")
    
    parser = UBSParser()
    parser.parse(example_ubs)
    
    generator = DocumentationGenerator(parser)
    
    # Generate all documentation
    print("1. Generating Markdown documentation...")
    generator.generate_full_documentation("DEMO_README.md")
    
    print("\n2. Generating Quick Reference...")
    generator.generate_quick_reference("DEMO_QUICK_REF.md")
    
    print("\n3. Generating JSON report...")
    report = generator.generate_json_report("DEMO_REPORT.json")
    print(f"   Total rules: {report['statistics']['total_rules']}")
    
    print("\n4. Generating HTML report...")
    generator.generate_html_report("DEMO_REPORT.html")
    
    print("\n✅ Documentation Generator module loaded successfully!")
    print("\nGenerated files:")
    print("  - DEMO_README.md (Full documentation)")
    print("  - DEMO_QUICK_REF.md (Quick reference)")
    print("  - DEMO_REPORT.json (Machine-readable report)")
    print("  - DEMO_REPORT.html (Interactive HTML report)")
