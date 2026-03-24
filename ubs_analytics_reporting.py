#!/usr/bin/env python3
"""
UBS Analytics & Reporting Module
- Statistics Generator
- Coverage Reports
- Performance Metrics
- Visualization (ASCII/HTML)
"""

import json
from typing import List, Dict, Optional, Tuple
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime


# ============================================================================
# STATISTICS GENERATOR
# ============================================================================

@dataclass
class RuleStatistics:
    """Comprehensive rule statistics"""
    total_rules: int
    by_type: Dict[str, int]
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    by_section: Dict[str, int]
    by_action: Dict[str, int]
    unique_domains: int
    wildcard_count: int
    regex_count: int


class StatisticsGenerator:
    """Generate comprehensive statistics"""
    
    def __init__(self, parser):
        self.parser = parser
    
    def generate_statistics(self) -> RuleStatistics:
        """Generate complete statistics"""
        
        # Count by type
        by_type = Counter(r.rule_type.value for r in self.parser.rules)
        
        # Count by severity
        by_severity = Counter()
        for rule in self.parser.rules:
            severity = rule.modifiers.get('severity', 'unspecified')
            by_severity[severity] += 1
        
        # Count by category
        by_category = Counter()
        for rule in self.parser.rules:
            if 'category' in rule.modifiers:
                cat = rule.modifiers['category']
                if isinstance(cat, list):
                    for c in cat:
                        by_category[c] += 1
                else:
                    by_category[cat] += 1
        
        # Count by section
        by_section = Counter(r.section or 'uncategorized' for r in self.parser.rules)
        
        # Count by action
        by_action = Counter()
        for rule in self.parser.rules:
            action = rule.modifiers.get('action', 'block')
            by_action[action] += 1
        
        # Unique domains
        unique_domains = len(set(
            r.pattern for r in self.parser.rules 
            if r.rule_type.value == 'domain' and not r.modifiers.get('regex')
        ))
        
        # Wildcard count
        wildcard_count = len([
            r for r in self.parser.rules 
            if r.pattern.startswith('*.')
        ])
        
        # Regex count
        regex_count = len([
            r for r in self.parser.rules 
            if r.modifiers.get('regex')
        ])
        
        return RuleStatistics(
            total_rules=len(self.parser.rules),
            by_type=dict(by_type),
            by_severity=dict(by_severity),
            by_category=dict(by_category),
            by_section=dict(by_section),
            by_action=dict(by_action),
            unique_domains=unique_domains,
            wildcard_count=wildcard_count,
            regex_count=regex_count
        )
    
    def generate_coverage_report(self) -> Dict:
        """Generate coverage report"""
        
        # Collect all domains
        domains = set()
        wildcards = set()
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                if rule.pattern.startswith('*.'):
                    wildcards.add(rule.pattern[2:])
                else:
                    domains.add(rule.pattern)
        
        # Analyze TLDs
        tlds = Counter()
        for domain in domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                tlds[parts[-1]] += 1
        
        # Estimate coverage
        estimated_coverage = len(domains) + len(wildcards) * 10
        
        return {
            'unique_domains': len(domains),
            'wildcard_rules': len(wildcards),
            'estimated_coverage': estimated_coverage,
            'top_tlds': dict(tlds.most_common(10)),
            'coverage_by_tld': dict(tlds)
        }
    
    def generate_performance_metrics(self) -> Dict:
        """Generate performance-related metrics"""
        
        # Complexity metrics
        avg_pattern_length = sum(len(r.pattern) for r in self.parser.rules) / len(self.parser.rules) if self.parser.rules else 0
        
        # Count modifiers
        total_modifiers = sum(len(r.modifiers) for r in self.parser.rules)
        avg_modifiers = total_modifiers / len(self.parser.rules) if self.parser.rules else 0
        
        # Regex complexity
        regex_rules = [r for r in self.parser.rules if r.modifiers.get('regex')]
        avg_regex_length = sum(len(r.pattern) for r in regex_rules) / len(regex_rules) if regex_rules else 0
        
        return {
            'total_rules': len(self.parser.rules),
            'avg_pattern_length': round(avg_pattern_length, 2),
            'avg_modifiers_per_rule': round(avg_modifiers, 2),
            'regex_rules': len(regex_rules),
            'avg_regex_length': round(avg_regex_length, 2),
            'complexity_score': round(avg_pattern_length + avg_modifiers * 10, 2)
        }
    
    def get_top_blocked_domains(self, limit: int = 10) -> List[Tuple[str, Dict]]:
        """Get top domains by severity/category"""
        
        domain_info = []
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                info = {
                    'pattern': rule.pattern,
                    'severity': rule.modifiers.get('severity', 'unspecified'),
                    'category': rule.modifiers.get('category', 'uncategorized'),
                    'section': rule.section or 'uncategorized'
                }
                domain_info.append(info)
        
        # Sort by severity priority
        severity_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unspecified': 0}
        sorted_domains = sorted(
            domain_info,
            key=lambda x: severity_priority.get(x['severity'], 0),
            reverse=True
        )
        
        return sorted_domains[:limit]
    
    def print_statistics_report(self):
        """Print comprehensive statistics report"""
        
        stats = self.generate_statistics()
        coverage = self.generate_coverage_report()
        performance = self.generate_performance_metrics()
        
        print(f"\n{'='*80}")
        print("COMPREHENSIVE STATISTICS REPORT")
        print(f"{'='*80}\n")
        
        # Basic stats
        print("📊 Rule Distribution:")
        print(f"   Total Rules:        {stats.total_rules}")
        print(f"   Unique Domains:     {stats.unique_domains}")
        print(f"   Wildcard Rules:     {stats.wildcard_count}")
        print(f"   Regex Rules:        {stats.regex_count}")
        
        # By type
        print("\n📋 By Type:")
        for rule_type, count in sorted(stats.by_type.items(), key=lambda x: -x[1]):
            percentage = (count / stats.total_rules * 100) if stats.total_rules else 0
            print(f"   {rule_type:20s}  {count:6d}  ({percentage:5.1f}%)")
        
        # By severity
        if any(s != 'unspecified' for s in stats.by_severity.keys()):
            print("\n🎯 By Severity:")
            for severity in ['critical', 'high', 'medium', 'low', 'unspecified']:
                if severity in stats.by_severity:
                    count = stats.by_severity[severity]
                    emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 
                            'low': '🟢', 'unspecified': '⚪'}.get(severity, '')
                    print(f"   {emoji} {severity:15s}  {count:6d}")
        
        # By category
        if stats.by_category:
            print("\n🏷️  By Category:")
            for category, count in sorted(stats.by_category.items(), key=lambda x: -x[1])[:10]:
                print(f"   {category:20s}  {count:6d}")
        
        # Coverage
        print(f"\n📈 Coverage:")
        print(f"   Unique Domains:     {coverage['unique_domains']}")
        print(f"   Wildcard Rules:     {coverage['wildcard_rules']}")
        print(f"   Est. Coverage:      {coverage['estimated_coverage']} domains")
        
        if coverage['top_tlds']:
            print(f"\n🌐 Top TLDs:")
            for tld, count in list(coverage['top_tlds'].items())[:5]:
                print(f"   .{tld:15s}  {count:6d}")
        
        # Performance metrics
        print(f"\n⚡ Performance Metrics:")
        print(f"   Avg Pattern Length: {performance['avg_pattern_length']:.1f} chars")
        print(f"   Avg Modifiers:      {performance['avg_modifiers_per_rule']:.1f}")
        print(f"   Complexity Score:   {performance['complexity_score']:.1f}")
        
        # Top blocked domains
        print(f"\n🚫 Top 10 High-Severity Domains:")
        top_domains = self.get_top_blocked_domains(10)
        for i, domain in enumerate(top_domains, 1):
            severity = domain['severity']
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 
                    'low': '🟢', 'unspecified': '⚪'}.get(severity, '')
            print(f"   {i:2d}. {emoji} {domain['pattern']:40s} [{domain['category']}]")
        
        print(f"\n{'='*80}\n")


# ============================================================================
# VISUALIZATION
# ============================================================================

class Visualizer:
    """Create visualizations (ASCII and HTML)"""
    
    def __init__(self, parser):
        self.parser = parser
    
    def create_bar_chart(self, data: Dict[str, int], title: str, width: int = 60) -> str:
        """Create ASCII bar chart"""
        
        if not data:
            return "No data to display"
        
        # Sort by value
        sorted_data = sorted(data.items(), key=lambda x: -x[1])
        max_value = max(v for k, v in sorted_data) if sorted_data else 1
        
        chart = f"\n{title}\n"
        chart += "=" * (width + 20) + "\n\n"
        
        for label, value in sorted_data[:15]:  # Top 15
            bar_length = int((value / max_value) * width) if max_value > 0 else 0
            bar = "█" * bar_length
            chart += f"{label:20s} {bar} {value}\n"
        
        return chart
    
    def create_pie_chart_ascii(self, data: Dict[str, int], title: str) -> str:
        """Create ASCII pie chart representation"""
        
        if not data:
            return "No data to display"
        
        total = sum(data.values())
        
        chart = f"\n{title}\n"
        chart += "=" * 50 + "\n\n"
        
        for label, value in sorted(data.items(), key=lambda x: -x[1]):
            percentage = (value / total * 100) if total > 0 else 0
            blocks = int(percentage / 2)  # 50 chars = 100%
            bar = "▓" * blocks + "░" * (50 - blocks)
            chart += f"{label:20s} {bar} {percentage:5.1f}%\n"
        
        return chart
    
    def create_domain_tree(self, max_depth: int = 3) -> str:
        """Create domain tree visualization"""
        
        # Build tree structure
        tree = defaultdict(lambda: defaultdict(set))
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                pattern = rule.pattern.replace('*.', '')
                parts = pattern.split('.')
                
                if len(parts) >= 2:
                    tld = parts[-1]
                    domain = parts[-2] if len(parts) >= 2 else ''
                    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
                    
                    tree[tld][domain].add(subdomain if subdomain else '(root)')
        
        # Format tree
        output = "\n🌳 Domain Tree\n"
        output += "=" * 60 + "\n\n"
        
        for tld in sorted(tree.keys())[:10]:  # Top 10 TLDs
            output += f"📁 .{tld}\n"
            
            domains = tree[tld]
            for i, (domain, subdomains) in enumerate(sorted(domains.items())[:5]):  # Top 5 per TLD
                is_last = (i == min(4, len(domains) - 1))
                connector = "└──" if is_last else "├──"
                
                output += f"   {connector} {domain}\n"
                
                for j, subdomain in enumerate(sorted(subdomains)[:3]):  # Top 3 subdomains
                    is_last_sub = (j == min(2, len(subdomains) - 1))
                    sub_connector = "└──" if is_last_sub else "├──"
                    indent = "       " if is_last else "   │   "
                    
                    if subdomain != '(root)':
                        output += f"{indent}{sub_connector} {subdomain}\n"
            
            if len(domains) > 5:
                output += f"   └── ... and {len(domains) - 5} more\n"
            output += "\n"
        
        return output
    
    def create_heatmap_ascii(self, title: str = "Rule Overlap Heatmap") -> str:
        """Create ASCII heatmap for rule overlaps"""
        
        # Group domains by base
        domain_groups = defaultdict(list)
        
        for rule in self.parser.rules:
            if rule.rule_type.value == 'domain':
                pattern = rule.pattern.replace('*.', '')
                parts = pattern.split('.')
                
                if len(parts) >= 2:
                    base = '.'.join(parts[-2:])
                    domain_groups[base].append(pattern)
        
        # Find overlaps
        overlaps = []
        for base, patterns in domain_groups.items():
            if len(patterns) > 1:
                overlaps.append((base, len(patterns)))
        
        overlaps.sort(key=lambda x: -x[1])
        
        # Create heatmap
        output = f"\n{title}\n"
        output += "=" * 60 + "\n\n"
        
        max_overlap = max(o[1] for o in overlaps) if overlaps else 1
        
        for base, count in overlaps[:20]:
            intensity = int((count / max_overlap) * 10) if max_overlap > 0 else 0
            
            # Color intensity with different characters
            chars = [' ', '░', '▒', '▓', '█']
            char_index = min(intensity // 2, len(chars) - 1)
            heat = chars[char_index] * 20
            
            output += f"{base:30s} {heat} {count} rules\n"
        
        return output
    
    def create_html_dashboard(self, output_file: str = "dashboard.html"):
        """Create interactive HTML dashboard"""
        
        stats_gen = StatisticsGenerator(self.parser)
        stats = stats_gen.generate_statistics()
        coverage = stats_gen.generate_coverage_report()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UBS Analytics Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }}
        .stat-card h3 {{
            color: #667eea;
            font-size: 14px;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stat-value {{
            font-size: 42px;
            font-weight: bold;
            color: #2d3748;
        }}
        .stat-label {{
            color: #718096;
            font-size: 14px;
            margin-top: 5px;
        }}
        .chart-section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .chart-section h2 {{
            color: #2d3748;
            margin-bottom: 20px;
            font-size: 24px;
        }}
        .bar {{
            display: flex;
            align-items: center;
            margin-bottom: 15px;
        }}
        .bar-label {{
            width: 200px;
            font-size: 14px;
            color: #4a5568;
        }}
        .bar-track {{
            flex: 1;
            height: 30px;
            background: #e2e8f0;
            border-radius: 15px;
            overflow: hidden;
            margin: 0 15px;
        }}
        .bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            border-radius: 15px;
            transition: width 0.5s ease;
        }}
        .bar-value {{
            width: 80px;
            text-align: right;
            font-weight: 600;
            color: #2d3748;
        }}
        .severity-critical {{ background: linear-gradient(90deg, #f56565 0%, #c53030 100%); }}
        .severity-high {{ background: linear-gradient(90deg, #ed8936 0%, #dd6b20 100%); }}
        .severity-medium {{ background: linear-gradient(90deg, #ecc94b 0%, #d69e2e 100%); }}
        .severity-low {{ background: linear-gradient(90deg, #48bb78 0%, #38a169 100%); }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background: #f7fafc;
            font-weight: 600;
            color: #4a5568;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-critical {{ background: #fed7d7; color: #c53030; }}
        .badge-high {{ background: #feebc8; color: #c05621; }}
        .badge-medium {{ background: #fefcbf; color: #b7791f; }}
        .badge-low {{ background: #c6f6d5; color: #276749; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{self.parser.metadata.title or 'UBS Analytics Dashboard'}</h1>
            <p><strong>Version:</strong> {self.parser.metadata.version or 'N/A'} | 
               <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Rules</h3>
                <div class="stat-value">{stats.total_rules:,}</div>
            </div>
            <div class="stat-card">
                <h3>Unique Domains</h3>
                <div class="stat-value">{stats.unique_domains:,}</div>
            </div>
            <div class="stat-card">
                <h3>Wildcard Rules</h3>
                <div class="stat-value">{stats.wildcard_count:,}</div>
            </div>
            <div class="stat-card">
                <h3>Coverage</h3>
                <div class="stat-value">{coverage['estimated_coverage']:,}</div>
                <div class="stat-label">Estimated domains</div>
            </div>
        </div>
"""
        
        # Rule type distribution
        html += """
        <div class="chart-section">
            <h2>📊 Rule Distribution by Type</h2>
"""
        
        max_value = max(stats.by_type.values()) if stats.by_type else 1
        for rule_type, count in sorted(stats.by_type.items(), key=lambda x: -x[1]):
            percentage = (count / stats.total_rules * 100) if stats.total_rules else 0
            width = (count / max_value * 100) if max_value else 0
            
            html += f"""
            <div class="bar">
                <div class="bar-label">{rule_type.replace('_', ' ').title()}</div>
                <div class="bar-track">
                    <div class="bar-fill" style="width: {width}%"></div>
                </div>
                <div class="bar-value">{count:,} ({percentage:.1f}%)</div>
            </div>
"""
        
        html += """
        </div>
"""
        
        # Severity distribution
        if any(s != 'unspecified' for s in stats.by_severity.keys()):
            html += """
        <div class="chart-section">
            <h2>🎯 Severity Distribution</h2>
"""
            
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in stats.by_severity:
                    count = stats.by_severity[severity]
                    percentage = (count / stats.total_rules * 100) if stats.total_rules else 0
                    
                    html += f"""
            <div class="bar">
                <div class="bar-label">{severity.title()}</div>
                <div class="bar-track">
                    <div class="bar-fill severity-{severity}" style="width: {percentage}%"></div>
                </div>
                <div class="bar-value">{count:,} ({percentage:.1f}%)</div>
            </div>
"""
            
            html += """
        </div>
"""
        
        # Top domains
        html += """
        <div class="chart-section">
            <h2>🚫 Top High-Severity Domains</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Domain</th>
                        <th>Severity</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        top_domains = stats_gen.get_top_blocked_domains(20)
        for i, domain in enumerate(top_domains, 1):
            severity = domain['severity']
            badge_class = f"badge-{severity}" if severity != 'unspecified' else ""
            
            html += f"""
                    <tr>
                        <td>{i}</td>
                        <td><code>{domain['pattern']}</code></td>
                        <td><span class="badge {badge_class}">{severity.upper()}</span></td>
                        <td>{domain['category']}</td>
                    </tr>
"""
        
        html += """
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"✅ HTML dashboard created: {output_file}")
        return html


# ============================================================================
# CLI INTEGRATION
# ============================================================================

def add_analytics_commands(subparsers):
    """Add analytics commands to CLI"""
    
    # Statistics
    stats_parser = subparsers.add_parser('analytics',
                                        help='Generate analytics and visualizations')
    stats_parser.add_argument('file', help='UBS file')
    stats_parser.add_argument('--format', choices=['text', 'html', 'json', 'all'],
                             default='text',
                             help='Output format')
    stats_parser.add_argument('--output', '-o',
                             help='Output file (for HTML/JSON)')
    stats_parser.add_argument('--charts', action='store_true',
                             help='Include ASCII charts')


def handle_analytics_command(args):
    """Handle analytics command"""
    from ubs_parser import UBSParser
    
    print(f"Generating analytics for: {args.file}")
    
    with open(args.file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = UBSParser()
    parser.parse(content)
    
    stats_gen = StatisticsGenerator(parser)
    visualizer = Visualizer(parser)
    
    if args.format in ['text', 'all']:
        stats_gen.print_statistics_report()
        
        if args.charts:
            # Generate ASCII charts
            stats = stats_gen.generate_statistics()
            
            print(visualizer.create_bar_chart(
                stats.by_type,
                "Rule Distribution by Type"
            ))
            
            if stats.by_category:
                print(visualizer.create_pie_chart_ascii(
                    dict(list(stats.by_category.items())[:10]),
                    "Top 10 Categories"
                ))
            
            print(visualizer.create_domain_tree())
            print(visualizer.create_heatmap_ascii())
    
    if args.format in ['html', 'all']:
        output_file = args.output or 'analytics_dashboard.html'
        visualizer.create_html_dashboard(output_file)
    
    if args.format in ['json', 'all']:
        stats = stats_gen.generate_statistics()
        coverage = stats_gen.generate_coverage_report()
        performance = stats_gen.generate_performance_metrics()
        
        report = {
            'statistics': {
                'total_rules': stats.total_rules,
                'by_type': stats.by_type,
                'by_severity': stats.by_severity,
                'by_category': stats.by_category,
                'by_section': stats.by_section
            },
            'coverage': coverage,
            'performance': performance,
            'generated': datetime.now().isoformat()
        }
        
        output_file = args.output or 'analytics_report.json'
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ JSON report saved: {output_file}")
    
    return 0


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    from ubs_parser import UBSParser
    
    example_ubs = """
! Title: Analytics Demo List
! Version: 1.0.0

[Malware]
evil-malware.com :severity=critical :category=malware
dangerous.net :severity=high :category=malware
*.phishing.org :severity=critical :category=phishing

[Tracking]
||analytics.google.com^ :third-party :category=tracker
||facebook.com/tr/* :category=tracker :severity=medium
ads.example.com :severity=low :category=ads

[Ads]
||doubleclick.net^ :category=ads
||adserver.com^ :severity=low :category=ads
*.advertising.com :category=ads
"""
    
    print("=== Analytics & Reporting Module Demo ===\n")
    
    parser = UBSParser()
    parser.parse(example_ubs)
    
    # 1. Statistics Generator
    print("1. Statistics Generator:")
    stats_gen = StatisticsGenerator(parser)
    stats_gen.print_statistics_report()
    
    # 2. ASCII Visualizations
    print("\n2. ASCII Visualizations:")
    visualizer = Visualizer(parser)
    
    stats = stats_gen.generate_statistics()
    print(visualizer.create_bar_chart(stats.by_type, "Rule Types"))
    print(visualizer.create_pie_chart_ascii(stats.by_category, "Categories"))
    print(visualizer.create_domain_tree())
    
    # 3. HTML Dashboard
    print("\n3. HTML Dashboard:")
    visualizer.create_html_dashboard("demo_dashboard.html")
    
    print("\n✅ Analytics & Reporting module loaded successfully!")
