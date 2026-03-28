# Universal Blacklist Syntax (UBS)

A unified, extensible syntax for creating blocklists compatible with multiple filtering platforms — DNS blockers, browsers, WAF, IDS/IPS systems, and proxies. Write your rules once, deploy them everywhere.

---

## Quick Links

1. [Tutorial](https://github.com/vallanx-team/universal_blocklist_syntax/blob/main/docs/01%20Universal%20Blocklist%20Syntax%20-%20Tutorial.md)
2. [Documentation](https://github.com/vallanx-team/universal_blocklist_syntax/blob/main/docs/02%20UBS%20-%20Complete%20Documentation.md)
3. [Complete References](https://github.com/vallanx-team/universal_blocklist_syntax/blob/main/docs/03%20UBS%20-%20Complete%20Reference.md)

---

## Features

- **21+ export formats** — hosts, AdBlock/uBlock, dnsmasq, Unbound, BIND, Pi-hole, Squid, Suricata, iptables, nftables, ModSecurity, nginx, Apache, Cloudflare WAF, AWS WAF, and more
- **ML-based domain analysis** — auto-categorization, risk scoring, anomaly detection, DGA domain detection
- **Performance-optimized matching** — Bloom filter (O(1) lookups), domain Trie for wildcard matching, regex caching
- **Built-in REST API** — 6 endpoints, webhook support, remote list auto-updating, GitHub integration
- **Configuration profiles** — production, development, testing profiles via YAML/JSON
- **Zero external dependencies** — pure Python standard library (Python 3.7+)

---

## Installation

```bash
# No pip install required — pure Python standard library
python3 --version  # Python 3.7+ required

# Optional: install PyYAML for full YAML config support (has fallback without it)
pip install pyyaml
```

Clone or download the repository and run any module directly.

---

## Quick Start

```python
from ubs_parser import UBSParser, UBSConverter

# Parse a UBS file
parser = UBSParser()
with open('rules.ubs', 'r') as f:
    parser.parse(f.read())

# Convert to hosts format
converter = UBSConverter(parser)
print(converter.to_hosts())

# Convert to AdBlock format
print(converter.to_adblock())
```

**Convert to all 21 formats at once:**

```python
from ubs_smart_converter import SmartConverter

converter = SmartConverter()
converter.batch_convert_all('rules.ubs', output_dir='./output/')
```

**Start the REST API server:**

```bash
python ubs_api_integration.py
# API available at http://localhost:8080
```

---

## UBS Syntax

### Basic Structure

```
! Title: My Blocklist          # Metadata header
! Version: 1.0.0
! Expires: 1 day
! Target: dns,browser,waf

[Malware]                      # Section
evil-malware.com :severity=critical :category=malware

[Tracking]
||analytics.google.com^ :third-party :category=tracker :ttl=3600

[Ads]
||doubleclick.net^ :category=ads

[Browser-Specific]
##.advertisement               # Element hiding (CSS selector)
facebook.com##div[data-testid="sponsored"]

[Whitelist]
@@||paypal.com^ :reason="Payment processor"
@||trusted-api.example.com
```

### Rule Types

| Type | Syntax | Example |
|------|--------|---------|
| Domain | `domain.com` | `malware.net :severity=critical` |
| Wildcard | `*.domain.com` | `*.ads.example.com` |
| AdBlock-style | `\|\|domain.com^` | `\|\|tracker.net^ $third-party` |
| URL pattern | `/path/*` | `/ads/* :domain=example.com` |
| Regex | `~/pattern/` | `~/evil[0-9]+\.com/ :regex` |
| Element hiding | `##selector` | `##div[id^="ad-"]` |
| Scriptlet | `##+js(...)` | `example.com##+js(abort-on-property-read, adblock)` |
| Suricata/IDS | `>>tcp:80 content:"..."` | `>>http content:"union select" :severity=critical` |
| Proxy routing | `\|\|domain :proxy=...` | `*.onion :proxy=SOCKS5 127.0.0.1:9050` |
| Whitelist | `@@\|\|domain^` or `@domain` | `@@\|\|cdn.example.com^` |
| Header modify | `:header=name:value` | `\|\|tracker.net^ :header=referer:` |

### Modifiers

```
# Action
:block  :allow  :redirect=URL  :null  :nxdomain  :drop  :alert  :log

# Context
:third-party  :first-party  :script  :image  :xhr  :websocket  :domain=x.com

# Security
:severity=critical|high|medium|low
:category=malware|tracker|ads|phishing|crypto
:threat-score=85
:cve=CVE-2024-1234

# Performance
:ttl=3600  :cache=true  :weight=10  :important

# Network
:protocol=http  :port=443  :method=POST  :ip=192.168.0.0/24

# Technical
:regex  :case-sensitive
```

AdBlock `$` modifiers are also supported: `$third-party,script`, `$domain=example.com`, etc.

---

## Modules

| Module | Purpose |
|--------|---------|
| `ubs_parser.py` | Core parser and basic converters (9 formats). Start here. |
| `ubs_performance_optimization.py` | Bloom filter, DomainTrie, rule deduplication, extended converters (12 more formats), list diffing |
| `ubs_smart_converter.py` | Auto-detects output format from filename/content; batch convert to all 21 formats |
| `ubs_api_integration.py` | Built-in HTTP server, REST API, webhooks, remote list auto-update, GitHub integration |
| `ubs_machine_learning.py` | Feature extraction, domain categorization, risk scoring, anomaly detection |
| `ubs_config_system.py` | YAML/JSON config, profile management (prod/dev/test), auto-loading from `.ubsrc` |
| `ubs_doc_generator.py` | Auto-generates markdown/HTML documentation from a parsed list |
| `ubs_testing_simulation.py` | URL blocking simulation, traffic simulation, performance benchmarks, false-positive detection |

All modules depend on `ubs_parser.py` and are independently usable.

---

## Export Formats

**Basic (via `UBSConverter` in `ubs_parser.py`):**
hosts · AdBlock Plus/uBlock Origin · dnsmasq · Unbound · BIND · Squid ACL · Proxy PAC · Suricata · Little Snitch

**Extended (via `ExtendedConverters` in `ubs_performance_optimization.py`):**
Pi-hole (SQLite gravity.db) · pfSense/pfBlockerNG · OPNsense · Windows Firewall (PowerShell) · iptables · nftables · ModSecurity · nginx · Apache · Cloudflare WAF (JSON) · AWS WAF (JSON)

---

## CLI Usage

Each module has a `__main__` block. The primary CLI entry point is `ubs_parser.py`:

```bash
# Parse and show stats
python ubs_parser.py parse blocklist.ubs

# Convert to a specific format
python ubs_parser.py convert blocklist.ubs --format hosts -o blocklist.hosts
python ubs_parser.py convert blocklist.ubs --format dnsmasq -o dnsmasq.conf

# Validate rules
python ubs_parser.py validate blocklist.ubs --strict

# Test if a URL would be blocked
python ubs_parser.py test blocklist.ubs --url https://ads.example.com

# Convert to ALL formats at once
python ubs_smart_converter.py blocklist.ubs --output ./output/

# Start the API server
python ubs_api_integration.py --host 0.0.0.0 --port 8080

# ML analysis
python ubs_machine_learning.py analyze blocklist.ubs --input domains.txt --output report.txt
```

---

## REST API

Start the server:

```bash
python ubs_api_integration.py
```

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API info |
| `/health` | GET | Health check |
| `/parse` | POST | Parse UBS content, returns structured JSON |
| `/convert` | POST | Convert to a target format |
| `/validate` | POST | Validate rules, returns errors/warnings |
| `/lookup?domain=X` | GET | Check if a domain is blocked |
| `/stats` | GET | Statistics about the loaded list |

> **Note:** The API has no built-in authentication. It is intended for local or trusted network use only.

**Webhook support:**

```python
from ubs_api_integration import WebhookManager

wm = WebhookManager()
wm.add_webhook(
    url="https://your-server.com/hook",
    events=["list_updated", "rule_added"],
    secret="hmac-secret"   # optional HMAC-SHA256 signing
)
```

---

## Machine Learning

The ML module (`ubs_machine_learning.py`) requires no external libraries.

```python
from ubs_parser import UBSParser
from ubs_machine_learning import AdvancedMLAnalyzer

parser = UBSParser()
with open('rules.ubs') as f:
    parser.parse(f.read())

analyzer = AdvancedMLAnalyzer(parser)

# Analyze a single domain
result = analyzer.analyze_domain_comprehensive("suspicious-tracker123.tk")
print(f"Risk Score:   {result['risk_score']:.1f}/100")
print(f"Threat Level: {result['threat_level']}")       # MINIMAL / LOW / MEDIUM / HIGH / CRITICAL
print(f"Category:     {result['category_prediction'].predicted_category}")
print(f"Suggested:    {result['suggested_rule'].suggested_rule}")

# Batch analyze and export auto-generated rules
analyses = analyzer.batch_analyze(["domain1.com", "malware.tk", "tracker.net"])
analyzer.export_suggested_rules(analyses, "auto-rules.ubs", min_confidence=0.7)
```

**Feature extraction** covers: domain length, Shannon entropy, subdomain depth, character distribution, vowel/consonant ratio, n-gram analysis, suspicious keyword detection.

**Risk score thresholds:**

| Score | Threat Level | Recommendation |
|-------|-------------|----------------|
| 80–100 | CRITICAL | Block immediately |
| 60–80 | HIGH | Block recommended |
| 40–60 | MEDIUM | Review manually |
| 20–40 | LOW | Monitor |
| 0–20 | MINIMAL | Likely safe |

---

## Configuration

UBS auto-loads config from `.ubsrc`, `~/.config/ubs/config.yaml`, or `~/.ubs/config.yaml`.

```bash
# Initialize a config file
python ubs_config_system.py config-init --output .ubsrc

# Switch profiles
python ubs_config_system.py profile load production
```

Config supports YAML (with PyYAML) or JSON, with a built-in fallback YAML parser.

---

## Performance

With the optimized matcher (`ubs_performance_optimization.py`):

| Rules | Parse | Lookup | Convert |
|-------|-------|--------|---------|
| 1,000 | ~50ms | <1ms | ~100ms |
| 10,000 | ~500ms | <1ms | ~200ms |
| 100,000 | ~5s | ~2ms | ~2s |

---

## License

MIT License
