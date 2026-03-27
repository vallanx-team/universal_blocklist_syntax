## **Key principles for training data:**

### 1. **Quantity per category** 📊

- **Minimum:** 10–15 examples per category
- **Optimal:** 20–30 examples per category
- **More = better precision**

### 2. **Diversity of examples** 🌈

```
Tracking:
✅ analytics.google.com   (well-known)
✅ tracker-xyz123.io      (generic)
✅ pixel.facebook.com     (specific)
✅ *.tracking.example.com (wildcard)

Malware:
✅ evil.tk                (suspicious TLD)
✅ xkcd123random.com      (high entropy)
✅ free-crack-download.net (suspicious keywords)
✅ very-long-suspicious-domain-name-12345.xyz (length)
```

### 3. **Realistic domains** 🎯

- Use **real known trackers** (Google Analytics, Facebook Pixel)
- Use **real ad networks** (DoubleClick, Criteo)
- Use **real malware patterns** (known suspicious TLDs like .tk, .ml, .ga)

### 4. **Severity distribution** ⚠️

```
Critical: Malware, Phishing (20%)
High:     Crypto-mining, Aggressive tracking (30%)
Medium:   Standard tracking, Social media (40%)
Low:      Ads, CDN (10%)
```

### 5. **Feature examples for ML** 🤖

The ML model learns from:

**Keywords:**

- `track`, `analytics`, `pixel` → Tracking
- `ad`, `banner`, `promo` → Ads
- `malware`, `phish`, `crack` → Malware

**TLDs:**

- `.com`, `.net`, `.io` → Normal
- `.tk`, `.ml`, `.ga`, `.cf`, `.gq` → Suspicious

**Domain length:**

- 10–30 characters → Normal
- 40+ characters → Suspicious

**Entropy:**

- 3.0–3.5 → Normal
- 4.5+ → High (suspicious)

### 6. **Special patterns for AppNexus domains** 🎯

ubs

```ubs
[AppNexus-Training]
# Real AppNexus patterns
01.att-dns-forwarder.nym2.appnexus.com :category=ads :severity=low
01.att-radius-proxy.lax1.appnexus.com :category=ads :severity=low
*.appnexus.com :category=ads :severity=low
*.appnexus.net :category=ads :severity=low

# Datacenter patterns (nym2 = New York Metro 2, lax1 = Los Angeles 1)
*.nym*.appnexus.com :category=ads :severity=low :regex
*.lax*.appnexus.com :category=ads :severity=low :regex
*.fra*.appnexus.com :category=ads :severity=low :regex
```

## **Performance tips:**

1. **Expand regularly** — Add new domains as you encounter them
2. **Keep it balanced** — Each category should have a similar number of examples
3. **Test & iterate** — Analyse results and improve training data accordingly
4. **Don't forget the whitelist** — Also train on "good" domains!

**With this dataset your ML analysis should work with high precision!** 🚀
