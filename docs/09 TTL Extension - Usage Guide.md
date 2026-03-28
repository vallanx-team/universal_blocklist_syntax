# UBS TTL Extension - Integration Guide

## 📁 File Structure

```
your_project/
├── ubs_parser.py              # Original parser (UNCHANGED!)
├── ubs_ttl_extension.py       # New TTL extension
└── your_script.py             # Your script
```

## 🚀 Quick Start

### 1. Basic usage

```python
from ubs_parser import UBSParser
from ubs_ttl_extension import UBSConverterTTL

# Parse UBS content
content = """
malware.com :ttl=60 :severity=critical
tracker.com :ttl=300 :category=tracker
stable-ad.com :ttl=3600
"""

parser = UBSParser()
parser.parse(content)

# Use the TTL-extended converter
converter = UBSConverterTTL(parser)

# Various formats with TTL
print(converter.to_unbound_ttl())
print(converter.to_dnsmasq_ttl())
print(converter.to_ttl_report())
```

### 2. Convenience function (even simpler!)

```python
from ubs_ttl_extension import convert_with_ttl

content = "malware.com :ttl=60"

# Convert directly without parser setup
print(convert_with_ttl(content, format='unbound'))
print(convert_with_ttl(content, format='report'))
```

## 🔧 Integration into existing scripts

### Before (without TTL extension):

```python
from ubs_parser import UBSParser, UBSConverter

parser = UBSParser()
parser.parse(content)

converter = UBSConverter(parser)
print(converter.to_unbound())  # Original without TTL
```

### After (with TTL extension):

```python
from ubs_parser import UBSParser
from ubs_ttl_extension import UBSConverterTTL  # Only change this line!

parser = UBSParser()
parser.parse(content)

converter = UBSConverterTTL(parser)  # Only change here!
print(converter.to_unbound())  # Automatically uses TTL if present
```

**That's it!** Only 2 lines to change — `ubs_parser.py` stays untouched! 🎉

## 📊 Available methods

### TTL-specific methods:

```python
converter = UBSConverterTTL(parser)

# New TTL methods
converter.to_unbound_ttl()      # Unbound with TTL
converter.to_bind_ttl()         # BIND with TTL groups
converter.to_dnsmasq_ttl()      # Dnsmasq with TTL
converter.to_pihole_ttl()       # Pi-hole with TTL recommendations
converter.to_coredns_ttl()      # CoreDNS with TTL
converter.to_ttl_report()       # Detailed TTL report

# Original methods (automatically TTL-aware!)
converter.to_unbound()          # Uses TTL if present
converter.to_bind()             # Uses TTL if present
converter.to_dnsmasq()          # Uses TTL if present

# All other original methods continue to work
converter.to_hosts()
converter.to_adblock()
converter.to_squid()
# etc.
```

## 🎯 CLI Integration

### Option 1: Integrate into existing CLI

```python
# In your CLI file (e.g. ubs_cli.py)
import argparse
from ubs_parser import UBSParser
from ubs_ttl_extension import UBSConverterTTL

def main():
    parser_cli = argparse.ArgumentParser()
    parser_cli.add_argument('file', help='UBS file')
    parser_cli.add_argument('--format', choices=['unbound', 'bind', 'dnsmasq'])
    parser_cli.add_argument('--ttl', action='store_true', help='Use TTL extension')

    args = parser_cli.parse_args()

    # Parse UBS file
    with open(args.file) as f:
        content = f.read()

    parser = UBSParser()
    parser.parse(content)

    # Choose converter
    if args.ttl:
        converter = UBSConverterTTL(parser)
    else:
        from ubs_parser import UBSConverter
        converter = UBSConverter(parser)

    # Convert
    if args.format == 'unbound':
        print(converter.to_unbound())
    # etc.

if __name__ == '__main__':
    main()
```

### Option 2: Standalone TTL CLI

```bash
# Create ubs_ttl_cli.py
#!/usr/bin/env python3
import sys
from ubs_ttl_extension import convert_with_ttl

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: ubs_ttl_cli.py <file.ubs> <format>")
        print("Formats: unbound, bind, dnsmasq, pihole, coredns, report")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        content = f.read()

    print(convert_with_ttl(content, format=sys.argv[2]))
```

```bash
# Usage
chmod +x ubs_ttl_cli.py
./ubs_ttl_cli.py rules.ubs report
./ubs_ttl_cli.py rules.ubs unbound > /etc/unbound/blocklist.conf
```

## 📝 UBS syntax with TTL

```
# Short TTL for critical malware (1 minute)
malware.com :ttl=60 :severity=critical

# Standard TTL for trackers (5 minutes)
tracker.com :ttl=300 :category=tracker

# Long TTL for stable blocklists (1 hour)
stable-ad.com :ttl=3600

# Very long TTL for permanent blocks (24 hours)
spam.com :ttl=86400

# Combined with actions
bad-cdn.com :action=null :ttl=600
temp-block.com :action=nxdomain :ttl=180

# Without TTL = default (300s)
default-domain.com
```

## 🔍 TTL report example

```python
converter = UBSConverterTTL(parser)
print(converter.to_ttl_report())
```

Output:
```
======================================================================
TTL ANALYSIS REPORT
======================================================================

GENERAL STATISTICS
----------------------------------------------------------------------
Total domain rules:        45
Rules with TTL specified:  38 (84%)
Rules without TTL:         7 (will use default: 300s)

TTL DISTRIBUTION
----------------------------------------------------------------------
TTL (seconds)   Time            Rules      Percentage
----------------------------------------------------------------------
60              1m              5          13%
300             5m              20         52%
3600            1h              10         26%
86400           1d              3          7%

RECOMMENDATIONS
----------------------------------------------------------------------
✓ Average TTL: 1245s (20m 45s)
✓ TTL values are in a reasonable range
```

## ⚠️ Important notes

### ✅ Advantages of this approach:

1. **`ubs_parser.py` remains unchanged** — no merge conflicts!
2. **Backwards compatible** — existing scripts continue to work
3. **Modular** — TTL extension can be updated independently
4. **Easy to test** — isolated functionality
5. **Automatic TTL detection** — original methods use TTL when present

### 📌 What the extension does:

- **Inherits from `UBSConverter`** — all original methods available
- **Overrides** `to_unbound()`, `to_bind()`, `to_dnsmasq()` intelligently
- **Adds** dedicated `*_ttl()` methods
- **Validates** TTL values automatically
- **Generates** detailed reports

### 🚫 No changes needed in:

- ✅ `ubs_parser.py` — stays original!
- ✅ Existing scripts — continue to work
- ✅ Parser logic — TTL is just another modifier

## 🧪 Testing

```python
# test_ttl_extension.py
from ubs_parser import UBSParser
from ubs_ttl_extension import UBSConverterTTL

def test_ttl():
    content = "malware.com :ttl=60"
    parser = UBSParser()
    parser.parse(content)

    converter = UBSConverterTTL(parser)
    result = converter.to_ttl_report()

    assert "60" in result
    assert "malware.com" in result
    print("✓ TTL Extension test passed!")

if __name__ == '__main__':
    test_ttl()
```

## 🎓 Example: From scratch

```python
#!/usr/bin/env python3
"""
Complete example: UBS with TTL extension
"""

from ubs_parser import UBSParser
from ubs_ttl_extension import UBSConverterTTL

# 1. Define UBS content
ubs_rules = """
! Title: My Blocklist
! Version: 1.0.0

[Critical]
malware.com :ttl=60 :severity=critical

[Standard]
tracker.com :ttl=300
ads.example.com :ttl=300

[Stable]
known-ad.net :ttl=3600
"""

# 2. Parse
parser = UBSParser()
parser.parse(ubs_rules)

# 3. Convert with TTL extension
converter = UBSConverterTTL(parser)

# 4. Generate various outputs
print("=== TTL REPORT ===")
print(converter.to_ttl_report())

print("\n=== UNBOUND CONFIG ===")
print(converter.to_unbound_ttl())

print("\n=== DNSMASQ CONFIG ===")
print(converter.to_dnsmasq_ttl())

# 5. Save to files
with open('/tmp/unbound_blocklist.conf', 'w') as f:
    f.write(converter.to_unbound_ttl())

with open('/tmp/dnsmasq_blocklist.conf', 'w') as f:
    f.write(converter.to_dnsmasq_ttl())

with open('/tmp/ttl_report.txt', 'w') as f:
    f.write(converter.to_ttl_report())

print("\n✓ Files generated successfully!")
```

## 📚 Further resources

- Original parser: `ubs_parser.py`
- TTL extension: `ubs_ttl_extension.py`

---

**Summary:** The TTL extension is a **standalone file** that inherits from `UBSConverter`. Import it with `from ubs_ttl_extension import UBSConverterTTL` and use it in place of `UBSConverter`. That's all there is to it! 🚀
