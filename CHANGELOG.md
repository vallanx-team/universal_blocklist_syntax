# Changelog

All notable changes to Universal Blocklist Syntax (UBS) are documented here.

---

## [3.0.0] - Machine Learning Module

### Added
- **`ubs_machine_learning.py`** — Pure Python ML module (no TensorFlow/PyTorch)
- `FeatureExtractor`: Domain length, entropy, n-gram analysis, character ratios, Shannon entropy
- `DomainCategorizer`: ML-based categorization (tracking, ads, malware, cdn, social) with confidence scoring
- `PatternRecognizer`: Tracking/malware pattern detection, regex signatures, suspicious TLD detection
- `RuleSuggester`: Automatic rule generation with severity scoring and wildcard suggestions
- `AnomalyDetector`: Baseline learning, Z-score anomaly detection, DGA domain identification
- `AdvancedMLAnalyzer`: Risk scoring (0–100), threat levels (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL), batch analysis, report/rule export
- 4 new CLI commands: `ml-categorize`, `ml-suggest`, `ml-detect-anomalies`, `ml-analyze`

### Stats
- Modules: 10 | Features: 120+ | CLI Commands: 30+ | Lines of Code: ~7,500

---

## [2.0.0] - Smart Converter, REST API & Documentation Generator

### Added
- **`ubs_smart_converter.py`**: Auto-detects output format from filename/content; `batch_convert_all()` converts to all 21 formats at once
- **`ubs_api_integration.py`**: Built-in HTTP REST API (no Flask/FastAPI) with 6 endpoints (`/parse`, `/convert`, `/validate`, `/lookup`, `/stats`, `/health`); `WebhookManager` with HMAC-SHA256 signing; `ListUpdater` for remote auto-update with daemon mode; `GitHubIntegration` for file fetching with ETag caching
- **`ubs_doc_generator.py`**: Auto-generates Markdown documentation, rule coverage reports, HTML report (interactive), JSON report, Quick Reference Card
- New CLI commands: `smart-convert`, `convert-all`, `api-server`, `auto-update`, `github`, `generate-docs`
- Testing & simulation: `simulate`, `benchmark`, `check-false-positives`, `optimize`, `analytics`

### Stats
- Modules: 6 | Features: 80+ | Export formats: 21 | CLI Commands: 15+ | API Endpoints: 6 | Lines of Code: ~4,300 | External dependencies: 0

---

## [1.2.0] - DNS Check

### Added
- Dead domain detection via parallel DNS lookups (up to 100 domains simultaneously, configurable)
- Result caching to avoid repeated lookups
- Thread pool with 10 worker threads
- `--check-dns` and `--dns-limit` flags for the `validate` CLI command
- `validator.get_dns_check_summary()` returning `{checked, alive, dead, unknown}` counts

---

## [1.1.0] - Validator, Merger & Browser Extension Generator

### Added
- **`RuleValidator`**: Syntax checking with detailed error messages, performance warnings, duplicate/conflict detection, regex validation, modifier compatibility checking
- **`URLTester`**: Tests URLs against rules with performance measurement; batch testing via `--batch`
- **`ListMerger`**: Merges multiple lists with deduplication, conflict resolution (blacklist vs. whitelist), priority system, and metadata merging
- **`ExtensionGenerator`**: Generates ready-to-use browser extensions
  - Chrome/Edge (Manifest V3, `declarativeNetRequest`)
  - Firefox (WebExtensions, `webRequest` API)
  - Safari Content Blocker (JSON format)
  - Full extension structure: manifest, background script, content script, popup UI with stats, SVG icon
- CLI commands: `validate`, `convert`, `merge`, `test`, `extension`, `batch-convert`, `stats`

---

## [1.0.0] - Initial Release

### Added
- **`UBSParser`**: Parses UBS syntax into typed `Rule` dataclasses; supports domains, URL patterns, element hiding, scriptlets, Suricata rules, proxy rules; extracts metadata from `! Key: Value` directives; processes `[Section]` headers; full modifier support (`:action=block`, `:severity=high`, etc.); error handling with line numbers
- **`UBSConverter`**: Converts `Rule` objects to 9 output formats:
  - `hosts` (0.0.0.0 domain.com)
  - AdBlock Plus / uBlock Origin
  - dnsmasq (`address=/domain/0.0.0.0`)
  - Unbound (`local-zone`)
  - BIND (zone definitions)
  - Squid ACL
  - Proxy PAC (JavaScript)
  - Suricata rules
  - Little Snitch (JSON)
- Core data types: `Rule`, `Metadata`, `RuleType` (8 types), `Action` (8 actions)
- JSON export
- Regex and wildcard pattern support
