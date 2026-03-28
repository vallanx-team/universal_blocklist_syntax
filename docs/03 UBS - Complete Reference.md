# Universal Blocklist Syntax (UBS) - Complete Reference

## 📋 Table of Contents

1. [Introduction](#introduction)
2. [Basic Syntax](#basic-syntax)
3. [Rule Types](#rule-types)
4. [Modifiers](#modifiers)
5. [Metadata & Directives](#metadata--directives)
6. [Sections](#sections)
7. [Practical Examples](#practical-examples)
8. [Conversion Targets](#conversion-targets)

---

## Introduction

**UBS (Universal Blocklist Syntax)** is a unified, extensible syntax for block and whitelists, compatible with:

- ✅ DNS blockers (Pi-hole, AdGuard Home, Unbound, BIND)
- ✅ Browser extensions (AdBlock Plus, uBlock Origin)
- ✅ Web Application Firewalls (WAF)
- ✅ IDS/IPS systems (Suricata, Snort)
- ✅ Proxy servers (Squid, SOCKS5)

---

## Basic Syntax

### Comments

```
# Comment on its own line
! Metadata comment
```

### Rule Structure

```
<pattern> <modifiers>
```

**Examples:**
```
example.com
example.com :severity=high
||example.com^ $third-party
```

---

## Rule Types

### 1. Domain Rule (DOMAIN)

**Simple domain:**
```
example.com
malware.net
tracker.org
```

**With wildcard:**
```
*.ads.example.com
*.tracking.*
```

**With AdBlock syntax:**
```
||example.com^
||ads.example.com/banner^
```

---

### 2. URL Pattern (URL_PATTERN)

```
||example.com/ads/*
||tracker.net^$third-party
/ads/* :domain=example.com
```

**With regex:**
```
~.*\.(tk|ml|ga)$ :regex :severity=high
~/evil[0-9]+\.com/ :regex
```

---

### 3. Element Hiding (ELEMENT_HIDING)

**CSS selectors:**
```
##.advertisement
##div[id^="ad-"]
###banner-ad
example.com##.cookie-banner
```

**Domain-specific:**
```
example.com##.ads
facebook.com##div[data-testid="cookie-banner"]
```

---

### 4. Scriptlet (SCRIPTLET)

```
##+js(script-name, arg1, arg2)
example.com##+js(abort-on-property-read, adBlockDetected)
```

---

### 5. Suricata/IDS (SURICATA)

```
alert tcp any any -> any 80 (msg:"Malware"; content:"evil.exe"; :severity=high)
>>tcp:80 content:"eval(atob(" :action=alert :msg="Obfuscated JS"
>>http content:"<script>malicious" :severity=critical
```

---

### 6. Proxy Routing (PROXY)

```
||company-internal.com :proxy=DIRECT
||blocked-site.com :proxy=SOCKS5 127.0.0.1:9050
*.onion :proxy=SOCKS5 127.0.0.1:9050 :fallback=DIRECT
```

---

### 7. Whitelist (WHITELIST)

**With @ prefix:**
```
@||trusted.com^
@example.com
```

**With @@ (AdBlock-style):**
```
@@||example.com/ads.js^ :domain=mysite.com
@@||cdn.cloudflare.com^ :first-party
```

---

### 8. Header Modification (HEADER_MODIFY)

```
||example.com^ :header=set-cookie:blocked
||tracker.net^ :header=referer:
```

---

## Modifiers

### 🎯 Action Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| `:block` | Block (default) | `evil.com :block` |
| `:allow` | Explicitly allow | `safe.com :allow` |
| `:redirect=URL` | Redirect | `ads.com :redirect=about:blank` |
| `:null` | DNS to 0.0.0.0 | `tracker.net :null` |
| `:nxdomain` | DNS NXDOMAIN | `malware.com :nxdomain` |
| `:drop` | Drop packets | `evil.com :drop` |
| `:alert` | Warn only | `suspicious.com :alert` |
| `:log` | Enable logging | `test.com :log` |

---

### 📊 Context Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| `:domain=x.com` | Only on specific domains | `/ads/* :domain=example.com` |
| `:third-party` | Third-party only | `tracker.net :third-party` |
| `:first-party` | Same-origin only | `cdn.com :first-party` |
| `:script` | JavaScript only | `evil.js :script` |
| `:image` | Images only | `banner.jpg :image` |
| `:xhr` | AJAX/Fetch only | `api.com :xhr` |
| `:websocket` | WebSocket connections | `ws.com :websocket` |
| `:document` | Document itself | `page.html :document` |
| `:stylesheet` | CSS files | `style.css :stylesheet` |
| `:font` | Web fonts | `font.woff :font` |
| `:media` | Audio/video | `video.mp4 :media` |
| `:subdocument` | iFrames | `frame.html :subdocument` |
| `:ping` | Beacon/ping | `track.com :ping` |

---

### 🌐 Network Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| `:protocol=http` | HTTP/HTTPS/TCP/UDP | `evil.com :protocol=http` |
| `:port=80` | Port number | `evil.com :port=443` |
| `:method=POST` | HTTP method | `api.com :method=POST` |
| `:ip=192.168.1.0/24` | IP range | `evil.com :ip=10.0.0.0/8` |

---

### 🔒 Security Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| `:severity=critical` | Severity level (low/medium/high/critical) | `malware.com :severity=critical` |
| `:category=malware` | Category (malware/tracker/ads/crypto/phishing) | `evil.com :category=malware` |
| `:cve=CVE-2024-1234` | CVE reference | `vuln.com :cve=CVE-2024-1234` |
| `:threat-score=85` | Threat score (0-100) | `suspicious.com :threat-score=75` |
| `:reason="text"` | Reason | `block.com :reason="Known malware"` |

---

### ⏱️ Performance Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| `:ttl=3600` | DNS TTL in seconds | `ads.com :ttl=86400` |
| `:cache=true` | Allow caching | `static.com :cache=true` |
| `:rate-limit=10/min` | Rate limiting | `api.com :rate-limit=100/hour` |
| `:rate=10` | Rate value | `api.com :rate=100` |
| `:limit=min` | Limit unit (min/hour/day) | `api.com :limit=hour` |
| `:weight=5` | Rule priority | `important.com :weight=10` |
| `:important` | High priority | `critical.com :important` |

---

### 🔧 Technical Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| `:regex` | Enable regex pattern | `~/evil[0-9]+\.com/ :regex` |
| `:case-sensitive` | Case-sensitive match | `Ads.com :case-sensitive` |
| `:match-case` | Alias for case-sensitive | `Banner.jpg :match-case` |

---

### 🔀 AdBlock-Style Modifiers

UBS also supports **AdBlock Plus/uBlock Origin syntax** with `$`:

```
||example.com^ $third-party,script
||tracker.net^ $image,domain=example.com
||ads.com^ $~first-party
```

**Aliases:**
- `$third` = `:third-party`
- `$3p` = `:third-party`
- `$1p` = `:first-party`
- `$xhr` = `:xmlhttprequest`
- `$css` = `:stylesheet`
- `$img` = `:image`
- `$doc` = `:document`
- `$frame` = `:subdocument`

---

## Metadata & Directives

### Metadata Header

```
! Title: My Custom Blocklist
! Version: 1.2.3
! Description: Blocks trackers and malware
! Author: John Doe
! Homepage: https://example.com
! License: MIT
! Updated: 2025-10-12
! Expires: 7 days
```

---

### Build Directives

```
! Include: https://other-list.com/list.txt
! Require-Version: UBS/1.0
! Target: dns,browser,waf,proxy
```

**Targets:**
- `dns` - DNS blockers (Pi-hole, Unbound)
- `browser` - Browser extensions
- `waf` - Web Application Firewalls
- `proxy` - Proxy servers
- `ids` - IDS/IPS systems

---

## Sections

Organize rules into sections:

```
[DNS-Level-Blocks]
malware.com :severity=critical
tracker.net :category=tracker

[Browser-Specific]
||ads.example.com^ :third-party
##.advertisement

[WAF-Rules]
>>http content:"<script>" :severity=high
>>tcp:443 content:"exploit" :action=drop

[Whitelist]
@||trusted-payment.com^
@@||cdn.example.com^

[Proxy-Routing]
||internal.company.com :proxy=DIRECT
*.onion :proxy=SOCKS5 127.0.0.1:9050

[Tracking-Scripts]
||analytics.google.com^ :script :third-party
||facebook.com/tr/* :xhr :log

[Crypto-Mining]
||coinhive.com^ :category=crypto :severity=high
||cryptoloot.pro^ :category=crypto :severity=high

[Phishing]
*.phishing.net :severity=critical :category=phishing
evil-bank-login.com :severity=critical :redirect=about:blank
```

---

## Practical Examples

### Example 1: Simple Blocklist

```
! Title: Basic Blocklist
! Version: 1.0.0
! Expires: 1 day

[Malware]
evil-malware.com :severity=critical :category=malware
dangerous.net :severity=high :category=malware

[Tracking]
||analytics.google.com^ :third-party :category=tracker
||facebook.com/tr/* :category=tracker :severity=medium

[Ads]
||doubleclick.net^ :category=ads
||adserver.com^ :severity=low :category=ads
```

---

### Example 2: Advanced List with TTL

```
! Title: Advanced Blocklist with TTL
! Version: 2.0.0
! Target: dns,browser

[High-Risk-Malware]
malware-command-control.com :severity=critical :ttl=86400 :category=malware
*.phishing-site.* :severity=critical :ttl=604800 :regex

[Tracking-Networks]
||tracker.net^ :third-party :ttl=3600 :category=tracker
||analytics-cdn.com^ :script :ttl=7200 :log

[Ad-Networks-With-Fast-TTL]
||ads.example.com^ :ttl=300 :category=ads
||banner-network.net^ :ttl=600 :category=ads
```

---

### Example 3: Browser Extension Rules

```
! Title: Browser Protection List
! Target: browser

[Element-Hiding]
##.advertisement
##div[class*="ad-"]
###cookie-banner
facebook.com##div[data-testid="sponsored"]
youtube.com##.ytp-ad-overlay-container

[Script-Blocking]
||evil-tracker.com/script.js^ :script :third-party
||crypto-miner.net^ :script :severity=high

[Cosmetic-Filters]
example.com##.popup-overlay
news.com###newsletter-popup
```

---

### Example 4: WAF Rules

```
! Title: WAF Protection Rules
! Target: waf

[SQL-Injection-Detection]
>>http content:"union select" :severity=critical :msg="SQL Injection"
>>http content:"' or 1=1" :action=block :log

[XSS-Protection]
>>http content:"<script>" :severity=high :msg="XSS Attempt"
>>http content:"eval(atob(" :action=drop :category=malware

[Rate-Limiting]
||*/wp-admin/admin-ajax.php :method=POST :rate-limit=10/min
||*/api/* :rate-limit=100/hour :log
```

---

### Example 5: Multi-Target Complete List

```
! Title: Universal Security & Privacy List
! Version: 3.0.0
! Description: Comprehensive protection list for all platforms
! Author: Vallanx Security Team
! Homepage: https://vallanx.com
! License: MIT
! Updated: 2025-10-12
! Expires: 1 day
! Target: dns,browser,waf,proxy

# ============================================
# CRITICAL MALWARE DOMAINS
# ============================================

[Critical-Malware]
evil-malware-c2.com :severity=critical :category=malware :ttl=86400
*.cryptolocker.* :severity=critical :regex :nxdomain
ransomware-download.net :severity=critical :drop :log

# ============================================
# PHISHING & SOCIAL ENGINEERING
# ============================================

[Phishing]
*.phishing-paypal.* :severity=critical :category=phishing :redirect=about:blank
fake-bank-login.com :severity=critical :nxdomain
secure-login-verify-*.com :severity=high :regex :log

# ============================================
# TRACKING & ANALYTICS
# ============================================

[Tracking-Networks]
||analytics.google.com^ :third-party :category=tracker :ttl=3600
||facebook.com/tr/* :xhr :category=tracker :log
||doubleclick.net^ :third-party :category=tracker

[Browser-Element-Hiding]
##.cookie-consent-banner
##div[class*="tracking"]
facebook.com##div[data-testid="sponsored"]
youtube.com##.video-ads

# ============================================
# AD NETWORKS
# ============================================

[Advertising]
||ads.example.com^ :category=ads :ttl=600
||banner-cdn.net^ :image :category=ads
/ads/* :domain=~advertiser.com :category=ads

# ============================================
# CRYPTO MINING
# ============================================

[Crypto-Mining]
||coinhive.com^ :script :severity=high :category=crypto
||cryptoloot.pro^ :script :severity=high :category=crypto
||coin-hive.com^ :drop :log

# ============================================
# WAF PROTECTION
# ============================================

[WAF-Rules]
>>http content:"union select" :severity=critical :msg="SQL Injection"
>>http content:"<script>" :severity=high :msg="XSS Attempt"
>>http content:"eval(atob(" :action=drop :category=malware
||*/wp-admin/admin-ajax.php :method=POST :rate-limit=10/min

# ============================================
# PROXY ROUTING
# ============================================

[Proxy-Rules]
||company-internal.* :proxy=DIRECT
||blocked-region.com :proxy=SOCKS5 127.0.0.1:9050
*.onion :proxy=SOCKS5 127.0.0.1:9050 :fallback=DIRECT

# ============================================
# WHITELIST / EXCEPTIONS
# ============================================

[Whitelist]
@@||paypal.com^ :reason="Payment processor"
@@||cdn.cloudflare.com^ :first-party :reason="CDN"
@||trusted-api.example.com :reason="Internal API"

# ============================================
# CUSTOM HEADER MODIFICATION
# ============================================

[Header-Modification]
||tracker-with-cookies.com^ :header=set-cookie:blocked
||referer-tracker.net^ :header=referer:
```

---

## Conversion Targets

UBS can be converted to **21+ formats**:

### DNS Blockers
1. **hosts** - Standard /etc/hosts format
2. **adblock** - AdBlock Plus format
3. **dnsmasq** - Dnsmasq address=/domain/
4. **unbound** - Unbound local-zone
5. **bind** - BIND RPZ (Response Policy Zone)
6. **pihole** - Pi-hole format
7. **adguard** - AdGuard Home format
8. **blocky** - Blocky DNS proxy
9. **coredns** - CoreDNS format
10. **dnscrypt** - DNSCrypt blacklist

### Browser & WAF
11. **ublock** - uBlock Origin format
12. **adblock-plus** - ABP extended
13. **privoxy** - Privoxy action file
14. **squid** - Squid ACL
15. **pac** - Proxy Auto-Config

### IDS/IPS
16. **suricata** - Suricata rules
17. **snort** - Snort rules format

### Windows
18. **windows-hosts** - Windows hosts format
19. **windows-firewall** - Windows Firewall rules

### Other
20. **json** - JSON export
21. **csv** - CSV export

---

## CLI Usage

```bash
# Parse UBS file
python3 ubs_parser.py parse blocklist.ubs

# Convert to format
python3 ubs_parser.py convert blocklist.ubs --format hosts -o blocklist.hosts

# Validate
python3 ubs_parser.py validate blocklist.ubs

# Statistics
python3 ubs_parser.py analytics blocklist.ubs --format html

# Test URL
python3 ubs_parser.py test blocklist.ubs --url https://evil.com
```

---

## Web Interface

```
http://localhost:5000/
```

**Features:**
- 📁 Drag & drop upload
- 🔄 Live conversion (21 formats)
- ✅ Validation
- 📊 Analytics dashboard
- 🤖 ML-based domain analysis
- 📖 API documentation

---

## API Endpoints

```
POST   /api/parse          # Parse UBS file
GET    /api/convert        # Convert to format
GET    /api/validate       # Validate rules
POST   /api/ml-analyze     # ML analysis
GET    /api/stats          # Statistics
GET    /api/docs           # API documentation
```

---

## Best Practices

### ✅ Recommended Practices

1. **Always include metadata:**
   ```
   ! Title: My Blocklist
   ! Version: 1.0.0
   ! Updated: 2025-10-12
   ```

2. **Use sections** for organization

3. **Severity levels** for important rules:
   ```
   malware.com :severity=critical
   ```

4. **Optimize TTL** for performance:
   ```
   ads.com :ttl=3600  # 1 hour
   ```

5. **Categories** for better reporting:
   ```
   tracker.net :category=tracker
   ```

6. **Comments** for documentation:
   ```
   # Blocks known malware C2 servers
   evil.com :severity=critical
   ```

### ❌ Things to Avoid

1. No duplicate rules
2. No overly broad wildcards (`*.*`)
3. No regex without the `:regex` modifier
4. No untested rules in production

---

## Support & Documentation

- 📖 **GitHub:** https://github.com/vallanx-team/universal_blocklist_syntax
- 🌐 **Website:** https://vallanx.com/universal-blocklist-syntax

---

**Version:** UBS 3.0
**Last Updated:** 2025-10-12
**License:** MIT