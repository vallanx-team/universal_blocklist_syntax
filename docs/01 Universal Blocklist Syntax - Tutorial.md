# Vallanx Universal Blocklist Syntax - Tutorial

## 📚 Step-by-Step Guide

Welcome to the comprehensive tutorial for the **Vallanx Universal Blocklist Syntax (UBS)**!

This tutorial takes you from the absolute basics to advanced features like Machine Learning and API integration.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Tutorial 1: Creating Your First Blocklist](#tutorial-1-creating-your-first-blocklist)
3. [Tutorial 2: Mastering Domain Blocking](#tutorial-2-mastering-domain-blocking)
4. [Tutorial 3: URL Filtering & Patterns](#tutorial-3-url-filtering--patterns)
5. [Tutorial 4: Using Modifiers Effectively](#tutorial-4-using-modifiers-effectively)
6. [Tutorial 5: Merging Lists](#tutorial-5-merging-lists)
7. [Tutorial 6: Export & Conversion](#tutorial-6-export--conversion)
8. [Tutorial 7: Using Machine Learning](#tutorial-7-using-machine-learning)
9. [Tutorial 8: Optimizing Performance](#tutorial-8-optimizing-performance)
10. [Tutorial 9: Using the REST API](#tutorial-9-using-the-rest-api)
11. [Tutorial 10: Production Deployment](#tutorial-10-production-deployment)
12. [Tutorial 11: Using the TTL Extension](#tutorial-11-using-the-ttl-extension)
13. [Tutorial 12: Flexible Modifiers](#tutorial-12-flexible-modifiers)
14. [Practical Projects](#practical-projects)

---

## Getting Started

### Prerequisites

Before you begin, make sure:

```bash
# Check Python version
python3 --version
# Output should be >= 3.7, e.g. "Python 3.9.7"

# Create working directory
mkdir ubs-tutorial
cd ubs-tutorial

# Prepare modules (assuming you already have them)
# Copy all 12 modules into this folder
ls *.py
# Should show: ubs_parser.py, ubs_advanced_features.py, etc.
```

### Initialize Configuration

```bash
# Create configuration file
python3 ubs_advanced_features.py config-init --output ubs-config.yaml

# Display configuration
python3 ubs_config_system.py config-show
```

**Output:**
```yaml
parser:
  strict_mode: false
  max_rules: 1000000
validation:
  check_dns: false
  dns_timeout: 2.0
  dns_limit: 100
performance:
  use_bloom_filter: true
  use_trie: true
  cache_regex: true
...
```

---

## Tutorial 1: Creating Your First Blocklist

### Step 1.1: Minimal Blocklist

Create your first UBS file:

```bash
cat > my-first-list.ubs << 'EOF'
! Title: My First Blocklist
! Version: 1.0.0
! Author: Your Name
! Description: Learning project for UBS

[Tracking]
# Block Google Analytics
analytics.google.com

# Block Facebook Pixel
pixel.facebook.com

[Ads]
# Block Google Ads
doubleclick.net
googlesyndication.com
EOF
```

### Step 1.2: Validate

```bash
python3 ubs_advanced_features.py validate my-first-list.ubs
```

**Successful output:**
```
✓ Syntax valid
✓ 4 rules parsed
✓ 2 sections found
✓ No duplicates
✓ No conflicts
```

### Step 1.3: First Conversion

```bash
# Convert to hosts format
python3 ubs_parser.py convert my-first-list.ubs \
  --format hosts \
  --output blocklist.txt

# Display result
cat blocklist.txt
```

**Output:**
```
# Generated from my-first-list.ubs
# Title: My First Blocklist
# Version: 1.0.0
# Rules: 4

0.0.0.0 analytics.google.com
0.0.0.0 pixel.facebook.com
0.0.0.0 doubleclick.net
0.0.0.0 googlesyndication.com
```

### Step 1.4: System Integration (Linux/Mac)

```bash
# Backup the hosts file
sudo cp /etc/hosts /etc/hosts.backup

# Append our rules
sudo cat blocklist.txt >> /etc/hosts

# Test
ping analytics.google.com
# Should resolve to 0.0.0.0
```

**🎉 Congratulations!** You have created your first working blocklist!

---

## Tutorial 2: Mastering Domain Blocking

### Step 2.1: Different Domain Types

Create `domains-tutorial.ubs`:

```bash
cat > domains-tutorial.ubs << 'EOF'
! Title: Domain Blocking Tutorial
! Version: 1.0.0

[Simple-Domains]
# Blocks ONLY the exact domain (not subdomains!)
example.com

# Also blocks www
www.example.com

[Wildcard-Domains]
# Blocks ALL subdomains of tracker.com
*.tracker.com
# Examples: ads.tracker.com, api.tracker.com, sub.domain.tracker.com

# Blocks all .tk domains (CAUTION: very broad!)
*.tk

# Blocks all domains containing "ads"
*ads*
# Examples: myads.com, advertisingnetwork.com, ads-server.net

[Complex-Wildcards]
# Blocks all subdomains starting with "tracker-"
tracker-*.example.com
# Examples: tracker-api.example.com, tracker-pixel.example.com

# Blocks patterns with multiple wildcards
*-ads-*.com
# Examples: my-ads-network.com, best-ads-server.com
EOF
```

### Step 2.2: Testing

```bash
# Validate
python3 ubs_advanced_features.py validate domains-tutorial.ubs

# Convert and check rule count
python3 ubs_parser.py convert domains-tutorial.ubs \
  --format hosts \
  --output domains-test.txt

# Count the rules
grep -c "^0.0.0.0" domains-test.txt
```

### Step 2.3: Test a Specific URL

```bash
# Test whether a URL is matched
python3 ubs_advanced_features.py test domains-tutorial.ubs \
  --url https://ads.tracker.com/pixel.gif
```

**Output:**
```
✓ BLOCKED
Rule: *.tracker.com
Section: Wildcard-Domains
Type: DOMAIN
Match: ads.tracker.com
```

---

## Tutorial 3: URL Filtering & Patterns

### Step 3.1: URL Patterns

Create `url-patterns-tutorial.ubs`:

```bash
cat > url-patterns-tutorial.ubs << 'EOF'
! Title: URL Patterns Tutorial
! Version: 1.0.0

[URL-Basics]
# AdBlock style: || = domain anchor, ^ = separator
||example.com^
# Blocks: example.com, www.example.com, sub.example.com
# Does NOT block: notexample.com

# URL with path
||example.com/tracking/
# Blocks: example.com/tracking/pixel.gif
# Does NOT block: example.com/analytics/

[Path-Patterns]
# Wildcard in path
||cdn.example.com/ads/*
# Blocks: cdn.example.com/ads/banner.jpg, cdn.example.com/ads/v2/track.js

# Multiple path segments
||api.example.com/v1/*/track
# Blocks: api.example.com/v1/mobile/track, api.example.com/v1/web/track

[Regex-Patterns]
# Regex for complex patterns (enclosed between / characters!)
/^https:\/\/ads\d+\.example\.com\//
# Blocks: https://ads1.example.com/, https://ads999.example.com/
# Does NOT block: http://ads1.example.com/ (due to https)

# Regex with alternatives
/^https?:\/\/(tracker|analytics|pixel)\.example\.com\//
# Blocks: http://tracker.example.com/, https://analytics.example.com/

# Regex for file extensions
/.*\.(exe|dll|scr|bat)$/
# Blocks downloads: malware.com/virus.exe, bad.com/trojan.dll

[Full-URLs]
# Block exact URL
https://evil.com/malware/download.exe

# With query parameters
https://tracker.com/pixel?id=123&type=track
EOF
```

### Step 3.2: Test Regex

```bash
# Test various URLs
python3 ubs_advanced_features.py test url-patterns-tutorial.ubs \
  --url https://ads123.example.com/banner.jpg

python3 ubs_advanced_features.py test url-patterns-tutorial.ubs \
  --url https://tracker.example.com/api/v1/track

python3 ubs_advanced_features.py test url-patterns-tutorial.ubs \
  --url https://evil.com/malware/download.exe
```

### Step 3.3: Batch Testing

Create `test-urls.txt`:

```bash
cat > test-urls.txt << 'EOF'
https://ads1.example.com/
https://ads999.example.com/
https://tracker.example.com/
https://normal-site.com/
https://cdn.example.com/ads/banner.jpg
https://cdn.example.com/images/logo.png
EOF
```

Test all URLs:

```bash
python3 ubs_advanced_features.py test url-patterns-tutorial.ubs \
  --batch test-urls.txt
```

**Output:**
```
Testing 6 URLs...

✓ BLOCKED: https://ads1.example.com/
  Rule: /^https:\/\/ads\d+\.example\.com\//

✓ BLOCKED: https://ads999.example.com/
  Rule: /^https:\/\/ads\d+\.example\.com\//

✓ BLOCKED: https://tracker.example.com/
  Rule: /^https?:\/\/(tracker|analytics|pixel)\.example\.com\//

✗ ALLOWED: https://normal-site.com/
  No matching rule

✓ BLOCKED: https://cdn.example.com/ads/banner.jpg
  Rule: ||cdn.example.com/ads/*

✗ ALLOWED: https://cdn.example.com/images/logo.png
  No matching rule

Summary:
  Blocked: 4/6 (66.67%)
  Allowed: 2/6 (33.33%)
```

---

## Tutorial 4: Using Modifiers Effectively

### Step 4.1: Basic Modifiers

Create `modifiers-tutorial.ubs`:

```bash
cat > modifiers-tutorial.ubs << 'EOF'
! Title: Modifiers Tutorial
! Version: 1.0.0

[Categorization]
# Add category and severity
||analytics.google.com^ :category=tracking :severity=medium
||facebook.com/tr/* :category=tracking :severity=high
||doubleclick.net^ :category=ads :severity=low
evil-malware.tk :category=malware :severity=critical

[Actions]
# Default is :action=block
normal-block.com :action=block

# Drop without response
silent-drop.com :action=drop

# Enable logging
suspicious.com :action=block :log

# Important: Overrides whitelist
super-critical.tk :action=block :important :log

[Context]
# Only block third-party
||tracker.com^ :third-party :category=tracking

# Only on a specific domain
||ads.com^ :domain=mysite.com

# On multiple domains
||tracker.com^ :domain=site1.com|site2.com|site3.com

# All except internal
||analytics.com^ :domain=~internal.company.com

[Resource-Types]
# Only block JavaScript
||tracking.com^ $script :category=tracking

# Multiple types
||ads.com^ $script,image,stylesheet

# AJAX requests
||api.tracking.com^ $xhr :category=tracking

# WebSockets
||realtime.tracker.com^ $websocket

[Performance]
# Caching for expensive checks
slow-dns.com :cache=3600 :severity=medium

# Rate limiting
api-abuse.com :rate-limit=100/hour :action=block :log

# Priority
critical-first.tk :priority=1000 :severity=critical
normal.com :priority=100
low-priority.com :priority=10

[Documentation]
# Add reasons
tracker.com :category=tracking :msg="Known tracker - see report #123"
@@cdn.cloudflare.com^ :reason="CDN needed for site functionality"
EOF
```

### Step 4.2: Whitelist / Exceptions

```bash
cat > whitelist-tutorial.ubs << 'EOF'
! Title: Whitelist Tutorial
! Version: 1.0.0

[Blocklist]
# Block all subdomains
*.example.com :category=tracking :severity=medium

# Block all analytics
||analytics.*.com^ :category=tracking

[Whitelist]
# BUT allow these specific subdomains
@@||trusted.example.com^ :reason="Internal service"
@@||cdn.example.com^ :reason="CDN required"
@@||api.example.com^ :reason="API access required"

# Allow specific analytics
@@||analytics.mycompany.com^ :reason="Internal analytics (GDPR-compliant)"

[Testing]
# These should be blocked
tracking.example.com :category=tracking
ads.example.com :category=ads

# These are allowed (by whitelist)
# trusted.example.com -> ALLOWED
# cdn.example.com -> ALLOWED
EOF
```

### Step 4.3: Test Modifiers

```bash
# Validate
python3 ubs_advanced_features.py validate modifiers-tutorial.ubs --strict

# Test URLs
python3 ubs_advanced_features.py test whitelist-tutorial.ubs \
  --url https://tracking.example.com

python3 ubs_advanced_features.py test whitelist-tutorial.ubs \
  --url https://trusted.example.com
```

**Output:**
```
Test 1: https://tracking.example.com
✓ BLOCKED
  Rule: *.example.com
  Category: tracking
  Severity: medium

Test 2: https://trusted.example.com
✗ ALLOWED (Whitelisted)
  Whitelist Rule: @@||trusted.example.com^
  Reason: Internal service
```

---

## Tutorial 5: Merging Lists

### Step 5.1: Create Multiple Lists

Create three lists:

**corporate-rules.ubs:**
```bash
cat > corporate-rules.ubs << 'EOF'
! Title: Corporate Security Rules
! Version: 1.0.0
! Priority: HIGH

[Corporate-Malware]
known-threat.tk :severity=critical :category=malware
corporate-blocklist.ml :severity=high :category=malware

[Corporate-Tracking]
||analytics.competitor.com^ :category=tracking :severity=high
EOF
```

**community-list.ubs:**
```bash
cat > community-list.ubs << 'EOF'
! Title: Community Blocklist
! Version: 2.5.0
! Priority: MEDIUM

[Tracking]
||analytics.google.com^ :category=tracking :severity=medium
||facebook.com/tr/* :category=tracking :severity=medium

[Ads]
||doubleclick.net^ :category=ads :severity=low
||googlesyndication.com^ :category=ads :severity=low

[Malware]
evil-site.tk :severity=critical :category=malware
EOF
```

**custom-whitelist.ubs:**
```bash
cat > custom-whitelist.ubs << 'EOF'
! Title: Custom Whitelist
! Version: 1.0.0
! Priority: CRITICAL

[Trusted-Services]
@@||cdn.cloudflare.com^ :reason="CDN required"
@@||paypal.com^ :reason="Payment processor"
@@||stripe.com^ :reason="Payment processor"
EOF
```

### Step 5.2: Merge Lists

```bash
# With priority order
python3 ubs_advanced_features.py merge \
  custom-whitelist.ubs \
  corporate-rules.ubs \
  community-list.ubs \
  --output merged-list.ubs \
  --priority custom-whitelist corporate-rules community-list
```

**Explanation:**
- `custom-whitelist.ubs` has the highest priority (exceptions override everything)
- `corporate-rules.ubs` has medium priority (corporate rules before community)
- `community-list.ubs` has the lowest priority

### Step 5.3: Analyze the Result

```bash
# Display merged list
cat merged-list.ubs

# Statistics
python3 ubs_analytics_reporting.py stats merged-list.ubs
```

**Output:**
```
Statistics for merged-list.ubs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Rules: 11
Sections: 5

By Type:
  DOMAIN: 4
  URL: 5
  EXCEPTION: 3

By Category:
  tracking: 3
  ads: 2
  malware: 3
  trusted: 3

By Severity:
  critical: 2
  high: 2
  medium: 3
  low: 4
```

### Step 5.4: Diff Between Lists

```bash
# Show differences between two lists
python3 ubs_performance_optimization.py diff \
  community-list.ubs \
  merged-list.ubs \
  --patch changes.patch
```

**Output:**
```
Differences between community-list.ubs and merged-list.ubs:

+ Added (6 rules):
  + known-threat.tk :severity=critical :category=malware
  + corporate-blocklist.ml :severity=high :category=malware
  + ||analytics.competitor.com^ :category=tracking :severity=high
  + @@||cdn.cloudflare.com^ :reason="CDN required"
  + @@||paypal.com^ :reason="Payment processor"
  + @@||stripe.com^ :reason="Payment processor"

- Removed (0 rules):

~ Modified (0 rules):

Summary:
  +6 added
  -0 removed
  ~0 modified
```

---

## Tutorial 6: Export & Conversion

### Step 6.1: Basic Formats

```bash
# Hosts format
python3 ubs_parser.py convert merged-list.ubs \
  --format hosts \
  --output export-hosts.txt

# AdBlock format
python3 ubs_parser.py convert merged-list.ubs \
  --format adblock \
  --output export-adblock.txt

# Dnsmasq
python3 ubs_parser.py convert merged-list.ubs \
  --format dnsmasq \
  --output export-dnsmasq.conf

# Pi-hole (SQLite)
python3 ubs_performance_optimization.py convert-extended merged-list.ubs \
  --format pihole \
  --output gravity.db
```

### Step 6.2: Extended Formats

```bash
# Nginx configuration
python3 ubs_performance_optimization.py convert-extended merged-list.ubs \
  --format nginx \
  --output nginx-block.conf

# iptables script
python3 ubs_performance_optimization.py convert-extended merged-list.ubs \
  --format iptables \
  --output iptables-block.sh

# Cloudflare WAF (JSON)
python3 ubs_performance_optimization.py convert-extended merged-list.ubs \
  --format cloudflare \
  --output cloudflare-waf.json

# AWS WAF (JSON)
python3 ubs_performance_optimization.py convert-extended merged-list.ubs \
  --format aws-waf \
  --output aws-waf.json
```

### Step 6.3: Generate Browser Extensions

```bash
# Chrome/Edge Extension
python3 ubs_advanced_features.py extension merged-list.ubs \
  --browser chrome \
  --output ./chrome-extension/ \
  --name "My Blocklist"

# Firefox Extension
python3 ubs_advanced_features.py extension merged-list.ubs \
  --browser firefox \
  --output ./firefox-extension/ \
  --name "My Blocklist"

# Safari Content Blocker
python3 ubs_advanced_features.py extension merged-list.ubs \
  --browser safari \
  --output ./safari-extension/ \
  --name "My Blocklist"
```

### Step 6.4: All Formats at Once

```bash
# Batch conversion
python3 ubs_smart_converter.py convert-all merged-list.ubs \
  --output ./all-formats/

# Display result
ls -lh all-formats/
```

**Output:**
```
all-formats/
├── blocklist.hosts (12 KB)
├── blocklist.adblock (8 KB)
├── blocklist.dnsmasq (10 KB)
├── blocklist.unbound (14 KB)
├── blocklist.bind (11 KB)
├── blocklist.squid (5 KB)
├── blocklist.pac (18 KB)
├── suricata.rules (22 KB)
├── littlesnitch.json (15 KB)
├── gravity.db (24 KB)
├── nginx-block.conf (6 KB)
├── apache-block.conf (8 KB)
├── iptables-block.sh (9 KB)
├── cloudflare-waf.json (20 KB)
├── aws-waf.json (19 KB)
└── export.json (25 KB)
```

### Step 6.5: Smart Conversion (Auto-Detect)

```bash
# Target format is automatically detected
python3 ubs_smart_converter.py smart-convert \
  merged-list.ubs \
  output.hosts

python3 ubs_smart_converter.py smart-convert \
  merged-list.ubs \
  output.dnsmasq

python3 ubs_smart_converter.py smart-convert \
  merged-list.ubs \
  output.adblock
```

---

## Tutorial 7: Using Machine Learning

### Step 7.1: ML Basics - Domain Categorization

Create `ml-test-domains.txt`:

```bash
cat > ml-test-domains.txt << 'EOF'
tracking-pixel-analytics.com
ads-network-server.net
malicious-download-free.tk
crypto-miner-js.ml
cdn-static-assets.cloudflare.com
payment-gateway-secure.com
EOF
```

Categorize automatically:

```bash
python3 ubs_machine_learning.py ml-categorize merged-list.ubs \
  --input ml-test-domains.txt \
  --threshold 0.6
```

**Output:**
```
Machine Learning: Auto-Categorization
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Training on 11 existing rules...
✓ Model trained

Categorizing 6 domains:

🟢 tracking-pixel-analytics.com
   → tracking (confidence: 0.87)
   Reasoning: tracking: keywords ['tracking', 'analytics', 'pixel']

🟢 ads-network-server.net
   → ads (confidence: 0.79)
   Reasoning: ads: keywords ['ads', 'network']

🟢 malicious-download-free.tk
   → malware (confidence: 0.92)
   Reasoning: malware: keywords ['malicious', 'download', 'free'], suspicious TLD: .tk

🟢 crypto-miner-js.ml
   → crypto (confidence: 0.85)
   Reasoning: crypto: keywords ['crypto', 'miner'], suspicious TLD: .ml

🟡 cdn-static-assets.cloudflare.com
   → cdn (confidence: 0.65)
   Reasoning: cdn: keywords ['cdn', 'static', 'assets']

🟡 payment-gateway-secure.com
   → payment (confidence: 0.62)
   Reasoning: payment: keywords ['payment', 'gateway']
```

### Step 7.2: Automatic Rule Generation

```bash
python3 ubs_machine_learning.py ml-suggest merged-list.ubs \
  --input ml-test-domains.txt \
  --output ml-suggested-rules.ubs \
  --min-confidence 0.7
```

**Output file `ml-suggested-rules.ubs`:**
```ubs
! Title: ML-Generated Rules
! Generated: 2026-03-28 10:30:00
! Base List: merged-list.ubs
! Confidence Threshold: 0.7
! Total Suggestions: 4

[CRITICAL]
! Confidence: 0.92
*.malicious-download-free.tk :severity=critical :category=malware :action=block :log

[HIGH]
! Confidence: 0.85
*.crypto-miner-js.ml :severity=high :category=crypto :action=block :log

[MEDIUM]
! Confidence: 0.87
tracking-pixel-analytics.com :severity=medium :category=tracking

! Confidence: 0.79
ads-network-server.net :severity=medium :category=ads
```

### Step 7.3: Anomaly Detection (DGA Domains)

Test suspicious domains:

```bash
cat > suspicious-domains.txt << 'EOF'
xkcd1a2b3c4d5e6f7g8h9i.tk
qwertyuiopasdfghjkl123.ml
randomstring987654321.ga
normal-website.com
google.com
EOF
```

```bash
python3 ubs_machine_learning.py ml-detect-anomalies merged-list.ubs \
  --input suspicious-domains.txt
```

**Output:**
```
Machine Learning: Anomaly Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Training baseline on 11 rules...
✓ Baseline established

Scanning 5 domains:

🔴 xkcd1a2b3c4d5e6f7g8h9i.tk (max score: 7.2)
   Anomalies detected: 4
   - length: Unusual length: 25 (z-score: 4.12)
   - entropy: Unusual entropy: 4.85 (z-score: 3.98)
   - suspicious_pattern: High entropy + long length (possible DGA domain)
   - suspicious_tld: Suspicious TLD: .tk

🔴 qwertyuiopasdfghjkl123.ml (max score: 6.8)
   Anomalies detected: 4
   - length: Unusual length: 27 (z-score: 4.45)
   - entropy: Unusual entropy: 4.32 (z-score: 3.56)
   - suspicious_pattern: High entropy + long length (possible DGA domain)
   - suspicious_tld: Suspicious TLD: .ml

🔴 randomstring987654321.ga (max score: 6.5)
   Anomalies detected: 4
   - length: Unusual length: 24 (z-score: 3.89)
   - entropy: Unusual entropy: 4.18 (z-score: 3.42)
   - suspicious_pattern: High entropy + long length (possible DGA domain)
   - suspicious_tld: Suspicious TLD: .ga

🟢 normal-website.com (max score: 0.0)
   No anomalies detected

🟢 google.com (max score: 0.0)
   No anomalies detected

Summary:
  🔴 High risk: 3 domains
  🟡 Medium risk: 0 domains
  🟢 Normal: 2 domains
```

### Step 7.4: Comprehensive ML Analysis

```bash
python3 ubs_machine_learning.py ml-analyze merged-list.ubs \
  --input ml-test-domains.txt \
  --output ml-comprehensive-report.txt \
  --export-rules ml-high-confidence.ubs \
  --min-confidence 0.8
```

**Report output (`ml-comprehensive-report.txt`):**
```
================================================================================
COMPREHENSIVE ML ANALYSIS REPORT
================================================================================
Generated: 2026-03-28 10:45:00
Base List: merged-list.ubs
Domains Analyzed: 6
Minimum Confidence: 0.8

THREAT LEVEL SUMMARY:
  🔴 CRITICAL: 1 domain
  🟠 HIGH: 1 domain
  🟡 MEDIUM: 2 domains
  🟢 LOW: 2 domains
  ⚪ MINIMAL: 0 domains

CATEGORY DISTRIBUTION:
  - malware: 1 domain
  - crypto: 1 domain
  - tracking: 1 domain
  - ads: 1 domain
  - cdn: 1 domain
  - payment: 1 domain

CONFIDENCE DISTRIBUTION:
  - High (≥0.8): 3 domains
  - Medium (0.6-0.8): 2 domains
  - Low (<0.6): 1 domain

================================================================================
DETAILED ANALYSIS
================================================================================

1. 🔴 malicious-download-free.tk
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Risk Score: 95.8/100
   Threat Level: CRITICAL
   Category: malware (confidence: 0.92)
   Classification: malware (confidence: 0.96)

   Anomalies Detected: 2
     - Suspicious TLD: .tk
     - Many numbers: 0

   Pattern Analysis:
     - Is Malware: Yes (confidence: 0.96)
     - Reasons: suspicious_tld, keyword_match, suspicious_keywords

   Suggested Rule:
     *.malicious-download-free.tk :severity=critical :category=malware :action=block :log

   Recommendation:
     🔴 BLOCK IMMEDIATELY - High confidence malicious domain

2. 🟠 crypto-miner-js.ml
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Risk Score: 78.3/100
   Threat Level: HIGH
   Category: crypto (confidence: 0.85)
   Classification: crypto (confidence: 0.88)

   Anomalies Detected: 1
     - Suspicious TLD: .ml

   Suggested Rule:
     *.crypto-miner-js.ml :severity=high :category=crypto :action=block :log

   Recommendation:
     🟠 BLOCK RECOMMENDED - Likely malicious or unwanted

3. 🟡 tracking-pixel-analytics.com
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Risk Score: 52.1/100
   Threat Level: MEDIUM
   Category: tracking (confidence: 0.87)
   Classification: tracking (confidence: 0.84)

   Suggested Rule:
     tracking-pixel-analytics.com :severity=medium :category=tracking

   Recommendation:
     🟡 REVIEW - Consider blocking based on privacy policy

[... additional domains ...]

================================================================================
RECOMMENDATIONS
================================================================================

Immediate Actions (CRITICAL):
  1. Block malicious-download-free.tk immediately

High Priority (HIGH):
  1. Review and likely block crypto-miner-js.ml

Review (MEDIUM):
  1. Evaluate tracking-pixel-analytics.com against privacy policy
  2. Evaluate ads-network-server.net for ad-blocking needs

Monitor (LOW):
  1. cdn-static-assets.cloudflare.com appears benign
  2. payment-gateway-secure.com appears benign

================================================================================
EXPORTED RULES
================================================================================

High-confidence rules (≥0.8) have been exported to:
  ml-high-confidence.ubs

These rules can be merged with your existing blocklist:
  python3 ubs_advanced_features.py merge merged-list.ubs ml-high-confidence.ubs --output updated-list.ubs
```

---

## Tutorial 8: Optimizing Performance

### Step 8.1: Optimize the List

```bash
# Before: Measure size and performance
python3 ubs_testing_simulation.py benchmark merged-list.ubs > before-benchmark.txt

# Optimize
python3 ubs_performance_optimization.py optimize merged-list.ubs \
  --output optimized-list.ubs \
  --aggressive

# After: Benchmark
python3 ubs_testing_simulation.py benchmark optimized-list.ubs > after-benchmark.txt

# Compare
diff before-benchmark.txt after-benchmark.txt
```

**Optimizations:**
- Duplicate removal
- Wildcard merging (e.g., `ads.com` + `tracker.ads.com` → `*.ads.com`)
- Regex optimization
- Performance sorting (fast rules first)

### Step 8.2: Performance Metrics

```bash
python3 ubs_testing_simulation.py benchmark optimized-list.ubs
```

**Output:**
```
Performance Benchmark
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

List: optimized-list.ubs
Rules: 11
Unique Domains: 8

Parsing Performance:
  Parse Time: 2.3ms
  Rules/sec: 4,782

Lookup Performance (1000 random tests):
  Average: 0.12ms per lookup
  Min: 0.08ms
  Max: 0.45ms
  95th percentile: 0.18ms
  99th percentile: 0.32ms

Memory Usage:
  Bloom Filter: 512 bytes
  Trie Structure: 2.1 KB
  Regex Cache: 1.8 KB
  Total: 4.4 KB

Throughput:
  Lookups/sec: 8,333
  Requests/sec (estimated): 7,500

Performance Grade: A+
```

### Step 8.3: Traffic Simulation

```bash
python3 ubs_testing_simulation.py simulate optimized-list.ubs \
  --requests 10000 \
  --malicious-rate 0.2
```

**Output:**
```
Traffic Simulation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Configuration:
  Total Requests: 10,000
  Malicious Rate: 20%
  Expected Malicious: 2,000

Running simulation...
[████████████████████████████████████] 100%

Results:
  Malicious Requests: 2,012 (20.12%)
  Benign Requests: 7,988 (79.88%)

Blocking Performance:
  True Positives: 1,897 (94.28%)
  False Negatives: 115 (5.72%)
  True Negatives: 7,823 (97.93%)
  False Positives: 165 (2.07%)

Metrics:
  Precision: 91.99%
  Recall: 94.28%
  F1 Score: 93.12%
  Accuracy: 97.20%

Average Response Time: 0.14ms

Performance Grade: A
```

### Step 8.4: False Positive Checks

```bash
python3 ubs_testing_simulation.py check-false-positives optimized-list.ubs
```

**Output:**
```
False Positive Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Testing against common legitimate domains...

✓ google.com - ALLOWED
✓ youtube.com - ALLOWED
✓ facebook.com - ALLOWED
✓ amazon.com - ALLOWED
✓ microsoft.com - ALLOWED
✗ cloudflare.com - BLOCKED (whitelisted)
✓ github.com - ALLOWED
✓ stackoverflow.com - ALLOWED
✓ wikipedia.org - ALLOWED
✓ reddit.com - ALLOWED

Summary:
  Legitimate domains tested: 100
  False Positives: 1 (1.0%)
  Whitelisted: 1

False Positive Rate: 0.0%
Grade: EXCELLENT
```

---

## Tutorial 9: Using the REST API

### Step 9.1: Start the API Server

```bash
# Start API server
python3 ubs_api_integration.py api-server \
  --host 0.0.0.0 \
  --port 8080 &

# Save process ID
API_PID=$!
echo $API_PID > api.pid
```

**Server output:**
```
UBS REST API Server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Host: 0.0.0.0
Port: 8080

Available Endpoints:
  GET  /health        - Health check
  POST /parse         - Parse UBS content
  POST /convert       - Convert to format
  POST /validate      - Validate syntax
  GET  /lookup        - Lookup domain/URL
  GET  /stats         - Statistics

Server running at http://0.0.0.0:8080
```

### Step 9.2: Test API Endpoints

**Health Check:**
```bash
curl http://localhost:8080/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "3.1.0",
  "uptime": 123.45,
  "rules_loaded": 11
}
```

**Parse UBS:**
```bash
curl -X POST http://localhost:8080/parse \
  -H "Content-Type: application/json" \
  -d '{
    "content": "tracker.com :category=tracking\nads.com :category=ads"
  }'
```

**Response:**
```json
{
  "success": true,
  "rules": 2,
  "sections": 0,
  "metadata": {},
  "rules_detail": [
    {
      "pattern": "tracker.com",
      "type": "DOMAIN",
      "modifiers": {
        "category": "tracking"
      }
    },
    {
      "pattern": "ads.com",
      "type": "DOMAIN",
      "modifiers": {
        "category": "ads"
      }
    }
  ]
}
```

**Convert:**
```bash
curl -X POST http://localhost:8080/convert \
  -H "Content-Type: application/json" \
  -d '{
    "content": "tracker.com\nads.com",
    "format": "hosts"
  }'
```

**Response:**
```json
{
  "success": true,
  "format": "hosts",
  "output": "0.0.0.0 tracker.com\n0.0.0.0 ads.com\n"
}
```

**Lookup:**
```bash
curl "http://localhost:8080/lookup?url=https://tracker.com/pixel.gif"
```

**Response:**
```json
{
  "blocked": true,
  "rule": "tracker.com",
  "type": "DOMAIN",
  "section": null,
  "modifiers": {
    "category": "tracking"
  },
  "match": "tracker.com"
}
```

**Statistics:**
```bash
curl http://localhost:8080/stats
```

**Response:**
```json
{
  "total_rules": 11,
  "sections": 5,
  "by_type": {
    "DOMAIN": 4,
    "URL": 5,
    "EXCEPTION": 3
  },
  "by_category": {
    "tracking": 3,
    "ads": 2,
    "malware": 3,
    "trusted": 3
  },
  "by_severity": {
    "critical": 2,
    "high": 2,
    "medium": 3,
    "low": 4
  }
}
```

### Step 9.3: Configure Webhooks

```python
# webhook-config.py
from ubs_api_integration import WebhookManager

manager = WebhookManager()

# Webhook for list updates
manager.add_webhook(
    url="https://alerts.example.com/webhook",
    events=['list_updated', 'validation_failed'],
    secret="my-secret-key"
)

# Webhook for anomalies
manager.add_webhook(
    url="https://security.example.com/ml-alerts",
    events=['anomaly_detected', 'high_risk_domain'],
    secret="security-secret"
)

# Test webhook
manager.trigger('list_updated', {
    'timestamp': '2026-03-28T10:00:00Z',
    'rules_added': 5,
    'rules_removed': 2
})
```

### Step 9.4: Set Up Auto-Updates

```bash
# Add remote lists
python3 ubs_api_integration.py auto-update \
  --add community https://blocklists.example.com/community.ubs \
  --add threat-intel https://threats.example.com/latest.ubs \
  --start
```

**Output:**
```
Auto-Update System
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Added Lists:
  1. community
     URL: https://blocklists.example.com/community.ubs
     Interval: 3600s (1 hour)

  2. threat-intel
     URL: https://threats.example.com/latest.ubs
     Interval: 3600s (1 hour)

Auto-update started
Next update in: 3600s
```

---

## Tutorial 10: Production Deployment

### Step 10.1: Complete Workflow

Create `production-deploy.sh`:

```bash
#!/bin/bash
# Production Deployment Script

set -e  # Exit on error

echo "🚀 UBS Production Deployment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Load configuration
echo "📋 Loading production profile..."
python3 ubs_config_system.py profile load production

# 2. Merge lists
echo "📦 Merging blocklists..."
python3 ubs_advanced_features.py merge \
  corporate-rules.ubs \
  community-list.ubs \
  ml-generated.ubs \
  --output base-list.ubs \
  --priority corporate-rules community-list ml-generated

# 3. Validation
echo "✓ Validating..."
python3 ubs_advanced_features.py validate base-list.ubs \
  --strict \
  --check-dns \
  --dns-limit 500

# 4. ML analysis of new domains
if [ -f new-domains.txt ]; then
  echo "🤖 Running ML analysis on new domains..."
  python3 ubs_machine_learning.py ml-analyze base-list.ubs \
    --input new-domains.txt \
    --output ml-report.txt \
    --export-rules ml-suggestions.ubs \
    --min-confidence 0.8

  # 5. Merge ML rules
  if [ -f ml-suggestions.ubs ]; then
    echo "📦 Merging ML suggestions..."
    python3 ubs_advanced_features.py merge \
      base-list.ubs \
      ml-suggestions.ubs \
      --output enhanced-list.ubs \
      --priority base-list ml-suggestions
    cp enhanced-list.ubs base-list.ubs
  fi
fi

# 6. Optimization
echo "⚡ Optimizing..."
python3 ubs_performance_optimization.py optimize base-list.ubs \
  --output final-list.ubs \
  --aggressive

# 7. False positive check
echo "🔍 Checking for false positives..."
python3 ubs_testing_simulation.py check-false-positives final-list.ubs

# 8. Performance test
echo "📊 Running benchmark..."
python3 ubs_testing_simulation.py benchmark final-list.ubs \
  > production-benchmark.txt

# 9. Traffic simulation
echo "🌐 Simulating traffic..."
python3 ubs_testing_simulation.py simulate final-list.ubs \
  --requests 100000 \
  --malicious-rate 0.15 \
  > production-simulation.txt

# 10. Generate analytics
echo "📈 Generating analytics..."
python3 ubs_analytics_reporting.py analytics final-list.ubs \
  --format all \
  --output ./production-reports/

# 11. Generate documentation
echo "📚 Generating documentation..."
python3 ubs_doc_generator.py generate-docs final-list.ubs \
  --format all \
  --quick-ref

# 12. Export to all formats
echo "📤 Exporting to all formats..."
python3 ubs_smart_converter.py convert-all final-list.ubs \
  --output ./production-export/

# 13. Backup old version
if [ -f /production/current.ubs ]; then
  echo "💾 Backing up old version..."
  cp /production/current.ubs /production/backup-$(date +%Y%m%d-%H%M%S).ubs
fi

# 14. Deploy new version
echo "🎯 Deploying new version..."
cp final-list.ubs /production/current.ubs
cp -r production-export/* /production/formats/

# 15. Restart services
echo "🔄 Restarting services..."
# sudo systemctl reload dnsmasq
# sudo systemctl reload nginx
# ... additional services

echo "✅ Deployment complete!"
echo ""
echo "📊 Statistics:"
python3 ubs_analytics_reporting.py stats /production/current.ubs

echo ""
echo "📈 Reports available at: ./production-reports/"
echo "📤 Exports available at: ./production-export/"
```

Run:

```bash
chmod +x production-deploy.sh
./production-deploy.sh
```

### Step 10.2: Set Up Monitoring

Create `monitoring.sh`:

```bash
#!/bin/bash
# Continuous Monitoring Script

while true; do
  echo "🔍 Monitoring UBS System - $(date)"

  # API Health Check
  STATUS=$(curl -s http://localhost:8080/health | jq -r '.status')
  if [ "$STATUS" != "healthy" ]; then
    echo "⚠️ API Server unhealthy!"
    # Send alert
  fi

  # Performance check
  python3 ubs_testing_simulation.py benchmark /production/current.ubs \
    --quick \
    > /tmp/current-benchmark.txt

  # Check false positive rate
  FP_RATE=$(python3 ubs_testing_simulation.py check-false-positives \
    /production/current.ubs | grep "False Positive Rate" | awk '{print $4}')

  if (( $(echo "$FP_RATE > 2.0" | bc -l) )); then
    echo "⚠️ High false positive rate: $FP_RATE%"
    # Send alert
  fi

  # Sleep 5 minutes
  sleep 300
done
```

### Step 10.3: Automatic Updates

Create cron job:

```bash
# crontab -e

# Daily update at 2 AM
0 2 * * * /path/to/production-deploy.sh >> /var/log/ubs-deploy.log 2>&1

# Hourly monitoring
0 * * * * /path/to/monitoring.sh >> /var/log/ubs-monitor.log 2>&1

# Weekly report (Sundays at 8 AM)
0 8 * * 0 python3 /path/to/ubs_analytics_reporting.py analytics /production/current.ubs --format html --output /var/www/reports/weekly-$(date +\%Y\%m\%d).html
```

---

## Tutorial 11: Using the TTL Extension

### Step 11.1: TTL Basics

The TTL (Time-to-Live) Extension allows you to set expiration times for individual rules. This enables temporary blocks or time-limited exceptions.

Create `ttl-tutorial.ubs`:

```bash
cat > ttl-tutorial.ubs << 'EOF'
! Title: TTL Tutorial
! Version: 1.0.0

[Temporary-Blocks]
# Temporary block for 24 hours
phishing-campaign-2026.com :ttl=86400 :severity=critical :category=phishing

# Block for 1 week
suspicious-new-domain.tk :ttl=604800 :severity=high :category=malware

# Permanent block (default, no TTL)
known-malware.com :severity=critical :category=malware

[Temporary-Whitelist]
# Allow CDN temporarily for 1 hour (e.g., during maintenance)
@@||maintenance-cdn.example.com^ :ttl=3600 :reason="Maintenance window"

# Allow marketing campaign for 30 days
@@||campaign.partner.com^ :ttl=2592000 :reason="Marketing partnership Q1/2026"
EOF
```

### Step 11.2: Conversion with TTL

```python
# ttl-convert.py
from ubs_parser import UBSParser
from ubs_ttl_extension import UBSConverterTTL

# Parse the list
parser = UBSParser()
with open('ttl-tutorial.ubs', 'r') as f:
    parser.parse(f.read())

# TTL-aware conversion
converter = UBSConverterTTL()

# Hosts format with TTL comments
hosts_output = converter.convert_to_hosts(parser.rules)
print(hosts_output)

# Dnsmasq format with TTL
dnsmasq_output = converter.convert_to_dnsmasq(parser.rules)
print(dnsmasq_output)
```

### Step 11.3: Detecting Expired Rules

```python
# ttl-cleanup.py
from ubs_parser import UBSParser
from ubs_ttl_extension import UBSConverterTTL

parser = UBSParser()
with open('ttl-tutorial.ubs', 'r') as f:
    parser.parse(f.read())

converter = UBSConverterTTL()

# Filter active vs. expired rules
for rule in parser.rules:
    ttl = rule.modifiers.get('ttl')
    if ttl:
        print(f"  {rule.pattern} - TTL: {ttl}s")
    else:
        print(f"  {rule.pattern} - Permanent")
```

---

## Tutorial 12: Flexible Modifiers

### Step 12.1: The Flexible Modifier Parser

The `ubs_flexible_modifier_parser.py` module provides extended parsing capabilities for complex modifier combinations.

```python
# flexible-modifiers.py
from ubs_flexible_modifier_parser import FlexibleModifierParser

fmp = FlexibleModifierParser()

# Parse complex modifier strings
modifiers = fmp.parse(":category=tracking :severity=high :third-party :domain=site1.com|site2.com")
print(modifiers)
# {'category': 'tracking', 'severity': 'high', 'third-party': True, 'domain': ['site1.com', 'site2.com']}
```

### Step 12.2: Define Custom Modifiers

```python
# custom-modifiers.py
from ubs_flexible_modifier_parser import FlexibleModifierParser

fmp = FlexibleModifierParser()

# Custom modifiers with validation
custom_rule = "||tracker.com^ :category=tracking :response-code=403 :redirect=https://blocked.local"
modifiers = fmp.parse(custom_rule.split('^')[1].strip())
print(modifiers)
```

### Step 12.3: Modifier Validation

```python
# validate-modifiers.py
from ubs_flexible_modifier_parser import FlexibleModifierParser

fmp = FlexibleModifierParser()

# Known modifiers
known = ['category', 'severity', 'action', 'third-party', 'domain', 'ttl', 'log', 'important']

test_strings = [
    ":category=tracking :severity=high",
    ":category=invalid_value :unknown-modifier",
    ":severity=critical :ttl=3600 :log"
]

for s in test_strings:
    parsed = fmp.parse(s)
    unknown = [k for k in parsed.keys() if k not in known]
    if unknown:
        print(f"  Unknown modifiers: {unknown}")
    else:
        print(f"  All modifiers valid")
```

---

## Practical Projects

### Project 1: Enterprise Blocklist

**Goal:** Complete blocklist for a corporate network

**Requirements:**
- Block tracking & analytics
- Block ad networks
- Block malware & phishing
- Allow CDNs and business tools
- ML for automatic categorization
- Daily updates
- Performance monitoring

**Solution:**

```bash
# 1. Collect base lists
cat > enterprise-tracking.ubs << 'EOF'
! Title: Enterprise Tracking Blocklist
! Version: 1.0.0

[Tracking]
||analytics.google.com^ :category=tracking :severity=high :third-party
||facebook.com/tr/* :category=tracking :severity=high
||hotjar.com^ :category=tracking :severity=medium
||mouseflow.com^ :category=tracking :severity=medium
EOF

cat > enterprise-ads.ubs << 'EOF'
! Title: Enterprise Ads Blocklist
! Version: 1.0.0

[Advertising]
||doubleclick.net^ :category=ads :severity=medium
||googlesyndication.com^ :category=ads :severity=medium
||adnxs.com^ :category=ads :severity=low
EOF

cat > enterprise-malware.ubs << 'EOF'
! Title: Enterprise Malware Blocklist
! Version: 1.0.0

[Critical-Threats]
*.tk :severity=critical :category=malware :regex
*.ml :severity=critical :category=malware :regex
*.ga :severity=critical :category=malware :regex
EOF

cat > enterprise-whitelist.ubs << 'EOF'
! Title: Enterprise Whitelist
! Version: 1.0.0

[Business-Services]
@@||office365.com^ :reason="Microsoft Office"
@@||slack.com^ :reason="Team Communication"
@@||zoom.us^ :reason="Video Conferencing"
@@||github.com^ :reason="Development"
@@||aws.amazon.com^ :reason="Cloud Infrastructure"
@@||cloudflare.com^ :reason="CDN & Security"
EOF

# 2. Merge
python3 ubs_advanced_features.py merge \
  enterprise-whitelist.ubs \
  enterprise-malware.ubs \
  enterprise-tracking.ubs \
  enterprise-ads.ubs \
  --output enterprise-combined.ubs \
  --priority enterprise-whitelist enterprise-malware enterprise-tracking enterprise-ads

# 3. ML training & auto-categorization
# Collect new suspicious domains from logs
grep -oE '([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}' /var/log/squid/access.log | \
  sort | uniq > discovered-domains.txt

# ML analysis
python3 ubs_machine_learning.py ml-analyze enterprise-combined.ubs \
  --input discovered-domains.txt \
  --output enterprise-ml-report.txt \
  --export-rules enterprise-ml-additions.ubs \
  --min-confidence 0.85

# 4. Merge ML results
python3 ubs_advanced_features.py merge \
  enterprise-combined.ubs \
  enterprise-ml-additions.ubs \
  --output enterprise-final.ubs

# 5. Optimize
python3 ubs_performance_optimization.py optimize enterprise-final.ubs \
  --output enterprise-optimized.ubs \
  --aggressive

# 6. Export for various systems
mkdir -p /etc/ubs/enterprise/

# DNS (Dnsmasq)
python3 ubs_parser.py convert enterprise-optimized.ubs \
  --format dnsmasq \
  --output /etc/ubs/enterprise/dnsmasq.conf

# Proxy (Squid)
python3 ubs_parser.py convert enterprise-optimized.ubs \
  --format squid \
  --output /etc/ubs/enterprise/squid.acl

# Firewall (iptables)
python3 ubs_performance_optimization.py convert-extended enterprise-optimized.ubs \
  --format iptables \
  --output /etc/ubs/enterprise/firewall.sh

# Web server (Nginx)
python3 ubs_performance_optimization.py convert-extended enterprise-optimized.ubs \
  --format nginx \
  --output /etc/ubs/enterprise/nginx-block.conf

# 7. Monitoring & reports
python3 ubs_analytics_reporting.py analytics enterprise-optimized.ubs \
  --format html \
  --output /var/www/ubs-reports/enterprise-dashboard.html
```

### Project 2: Privacy-Focused Browser Extension

**Goal:** Browser extension for maximum data privacy

```bash
# 1. Create privacy list
cat > privacy-ultimate.ubs << 'EOF'
! Title: Ultimate Privacy Blocklist
! Version: 1.0.0
! Description: Maximum privacy protection

[Tracking-Scripts]
||analytics.google.com^ $script :category=tracking :severity=high
||google-analytics.com^ $script :category=tracking :severity=high
||googletagmanager.com^ $script :category=tracking :severity=high
||facebook.com^ $script,xhr :category=tracking :severity=high

[Tracking-Pixels]
||facebook.com/tr/* $image :category=tracking :severity=high
||pixel.quantserve.com^ $image :category=tracking :severity=medium

[Fingerprinting]
||fingerprintjs.com^ $script :category=fingerprinting :severity=critical
||maxmind.com^ $script :category=fingerprinting :severity=high

[Social-Media-Widgets]
||connect.facebook.net^ $script,subdocument :category=social :severity=medium
||platform.twitter.com^ $script,subdocument :category=social :severity=medium
||platform.linkedin.com^ $script,subdocument :category=social :severity=medium

[Ads]
||doubleclick.net^ $script,image,xhr :category=ads :severity=low
||googlesyndication.com^ $script,subdocument :category=ads :severity=low

[CDN-Whitelist]
@@||cdnjs.cloudflare.com^ $script :reason="Public CDN"
@@||cdn.jsdelivr.net^ $script :reason="Public CDN"
EOF

# 2. Generate browser extensions
python3 ubs_advanced_features.py extension privacy-ultimate.ubs \
  --browser chrome \
  --output ./chrome-privacy-extension/ \
  --name "Ultimate Privacy"

python3 ubs_advanced_features.py extension privacy-ultimate.ubs \
  --browser firefox \
  --output ./firefox-privacy-extension/ \
  --name "Ultimate Privacy"

# 3. Install extension (Chrome)
# chrome://extensions -> Load unpacked -> chrome-privacy-extension/
```

### Project 3: Automated Threat Intelligence

**Goal:** Automated system for threat detection with ML

```python
#!/usr/bin/env python3
# automated-threat-intel.py

import time
from datetime import datetime
from ubs_parser import UBSParser
from ubs_machine_learning import AdvancedMLAnalyzer
from ubs_api_integration import ListUpdater, WebhookManager

# Load base list
parser = UBSParser()
with open('base-rules.ubs', 'r') as f:
    parser.parse(f.read())

# Initialize ML analyzer
analyzer = AdvancedMLAnalyzer(parser)

# Configure auto-updater
updater = ListUpdater()
updater.add_remote_list(
    "threat-feed",
    "https://threatintel.example.com/domains.txt",
    update_interval=3600  # 1 hour
)

# Webhook for alerts
updater.webhook_manager.add_webhook(
    url="https://security.example.com/webhook",
    events=['high_risk_detected', 'anomaly_detected'],
    secret="security-secret-key"
)

def process_new_domains(domains):
    """Process new domains with ML"""

    print(f"🤖 Analyzing {len(domains)} new domains...")

    # Comprehensive ML analysis
    analyses = analyzer.batch_analyze(domains)

    # Filter by risk
    critical = [a for a in analyses if a['threat_level'] == 'CRITICAL']
    high = [a for a in analyses if a['threat_level'] == 'HIGH']

    # Critical threats
    if critical:
        print(f"🔴 CRITICAL: {len(critical)} domains detected!")

        # Export auto-block rules
        analyzer.export_suggested_rules(
            critical,
            f"auto-block-critical-{datetime.now().strftime('%Y%m%d')}.ubs",
            min_confidence=0.9
        )

        # Generate report
        analyzer.generate_report(
            critical,
            f"critical-threats-{datetime.now().strftime('%Y%m%d')}.txt"
        )

        # Trigger webhook
        updater.webhook_manager.trigger('high_risk_detected', {
            'level': 'CRITICAL',
            'count': len(critical),
            'domains': [a['domain'] for a in critical],
            'timestamp': datetime.now().isoformat()
        })

    # High risk
    if high:
        print(f"🟠 HIGH: {len(high)} domains detected!")

        analyzer.export_suggested_rules(
            high,
            f"review-high-{datetime.now().strftime('%Y%m%d')}.ubs",
            min_confidence=0.8
        )

    # Overall report
    analyzer.generate_report(
        analyses,
        f"daily-analysis-{datetime.now().strftime('%Y%m%d')}.txt"
    )

# Callback for new domains
def on_list_updated(list_name, new_domains):
    print(f"📥 List '{list_name}' updated with {len(new_domains)} new domains")
    process_new_domains(new_domains)

updater.on_update_callback = on_list_updated

# Start system
print("🚀 Automated Threat Intelligence System")
print("   ML-based domain analysis")
print("   Real-time threat detection")
print("   Automatic rule generation")
print("")

updater.start_auto_update()

# Infinite loop (or run as daemon)
try:
    while True:
        time.sleep(60)
except KeyboardInterrupt:
    print("\n⏹️  Stopping system...")
    updater.stop_auto_update()
```

---

## Summary

You have now learned:

✅ **Basics**
- Creating and validating UBS files
- Domain blocking with various pattern types
- URL filtering and regex patterns

✅ **Advanced**
- Modifiers for detailed control
- Merging and organizing lists
- Export to 21+ different formats

✅ **Machine Learning**
- Auto-categorization of domains
- Automatic rule generation
- Anomaly detection (DGA domains)
- Comprehensive risk analysis

✅ **TTL Extension**
- Time-limited rules
- Temporary blocks and exceptions
- Automatic cleanup of expired rules

✅ **Flexible Modifiers**
- Extended modifier parsing
- Custom modifiers
- Modifier validation

✅ **Performance & Production**
- Optimizing lists
- Performance benchmarks
- Traffic simulation
- Production deployment

✅ **Integration**
- Using the REST API
- Configuring webhooks
- Setting up auto-updates
- Establishing monitoring

✅ **Practical**
- Enterprise blocklist
- Browser extension
- Automated threat intelligence

---

**🎉 Congratulations!** You are now a UBS expert!

**Next Steps:**
1. Implement your own practical projects
2. Customize ML features for your use cases
3. Use the TTL Extension for time-controlled rules
4. Leverage flexible modifiers for advanced configuration
5. Contribute to the community

**Vallanx Universal Blocklist Syntax v3.1 - Happy Blocking!** 🛡️
