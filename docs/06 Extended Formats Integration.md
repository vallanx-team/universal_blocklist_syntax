
### 📋 Overview of Changes

```
application.py
├── HOME_TEMPLATE (Frontend Select Box)
└── /api/convert Route (Backend API)

ubs_performance_optimization.py
└── ExtendedConverters Class
    ├── to_pihole() → NEW
    ├── to_pfsense() → NEW
    ├── to_opnsense() → NEW
    ├── to_windows_firewall() → NEW
    ├── to_iptables() → NEW
    ├── to_nftables() → NEW
    ├── to_nginx() → NEW
    ├── to_apache() → NEW
    ├── to_cloudflare_waf() → NEW
    ├── to_aws_waf() → NEW
    ├── to_modsecurity() → NEW
    └── to_pihole_sqlite() → Fix bugs

ubs_smart_converter.py
├── batch_convert_all() → extend format_files
└── _do_conversion() → ALREADY DONE ✓
```

---

## 1️⃣ Frontend: application.py (HOME_TEMPLATE)

**File:** `application.py`
**Line:** ~350-365 (inside HOME_TEMPLATE)
**Action:** Extend the select box

### 1️⃣ **Frontend: application.py** (HOME_TEMPLATE)

**Line ~350-360** - Extend the select box:

python

```python
<select id="formatSelect" class="btn" style="width: 100%; margin-bottom: 10px;">
    <!-- Basic Formats -->
    <option value="hosts">Hosts</option>
    <option value="adblock">AdBlock</option>
    <option value="dnsmasq">Dnsmasq</option>
    <option value="unbound">Unbound</option>
    <option value="bind">BIND</option>

    <!-- Extended Formats -->
    <option value="pihole">Pi-hole</option>
    <option value="pfsense">pfSense</option>
    <option value="opnsense">OPNsense</option>
    <option value="windows">Windows Firewall</option>
    <option value="iptables">iptables</option>
    <option value="nftables">nftables</option>
    <option value="nginx">Nginx</option>
    <option value="apache">Apache</option>
    <option value="cloudflare">Cloudflare WAF</option>
    <option value="aws-waf">AWS WAF</option>
    <option value="modsecurity">ModSecurity</option>
</select>
```

## 2️⃣ Backend API: application.py (@app.route('/api/convert'))

**File:** `application.py`
**Line:** ~620-680 (the api_convert function)
**Action:** Replace the entire function

### D) Add to Backend (api_convert extensions):

python

```python
'pgl': 'p2p',
'mikrotik': 'rsc',
'cisco': 'txt',
'juniper': 'txt',
'ipset': 'sh',
```


python

```python
@app.route('/api/convert')
def api_convert():
    """Convert current file to format"""
    global global_parser

    if global_parser is None:
        return jsonify({"error": "No file parsed yet. Upload a file first."}), 400

    format_name = request.args.get('format', 'hosts')

    try:
        if SmartConverter is None:
            return jsonify({"error": "SmartConverter module not available"}), 500

        converter = SmartConverter(global_parser)

        # Format mapping: frontend name → TargetFormat enum name
        format_mapping = {
            'windows': 'windows_fw',
            'cloudflare': 'cloudflare_waf',
            'aws-waf': 'aws_waf',
            'proxy_pac': 'proxy_pac'
        }

        # Convert format name
        actual_format = format_mapping.get(format_name, format_name)

        # Try to convert
        try:
            format_enum = TargetFormat(actual_format)
            result = converter.convert(format_enum, optimize=True)
        except (ValueError, AttributeError):
            result = converter.convert_auto(actual_format, optimize=True)

        if result.success:
            # File extension mapping
            extensions = {
                'hosts': 'txt',
                'adblock': 'txt',
                'dnsmasq': 'conf',
                'unbound': 'conf',
                'bind': 'conf',
                'squid': 'acl',
                'proxy_pac': 'pac',
                'suricata': 'rules',
                'pihole': 'list',
                'pfsense': 'txt',
                'opnsense': 'conf',
                'windows': 'ps1',
                'iptables': 'sh',
                'nftables': 'conf',
                'nginx': 'conf',
                'apache': 'conf',
                'cloudflare': 'json',
                'aws-waf': 'json',
                'modsecurity': 'conf'
            }

            # Select file extension and mimetype
            extension = extensions.get(format_name, 'txt')

            if extension == 'json':
                mimetype = 'application/json'
            elif extension in ['sh', 'ps1']:
                mimetype = 'text/x-shellscript'
            else:
                mimetype = 'text/plain'

            filename = f"blocklist_{format_name}.{extension}"

            return send_file(
                BytesIO(result.content.encode('utf-8')),
                mimetype=mimetype,
                as_attachment=True,
                download_name=filename
            )
        else:
            return jsonify({"error": result.error}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

---

## 3️⃣ Converter Implementations: ubs_performance_optimization.py

**File:** `ubs_performance_optimization.py`
**Action:** Find the `ExtendedConverters` class and add ALL methods
### Example: pfSense

python

```python
def to_pfsense(self) -> str:
    """Convert to pfSense alias format"""
    lines = ["# pfSense Aliases - Converted from UBS"]
    lines.append("# Add to Firewall > Aliases > URLs")
    lines.append("")

    for rule in self.parser.rules:
        if rule.rule_type == RuleType.DOMAIN and rule.action == Action.BLOCK:
            domain = rule.pattern.replace('*.', '').replace('||', '').replace('^', '')
            if domain and '/' not in domain:
                lines.append(domain)

    return '\n'.join(lines)
```

---
## 4️⃣ Batch Converter: ubs_smart_converter.py

**File:** `ubs_smart_converter.py`
**Method:** `batch_convert_all()`
**Action:** Extend the `format_files` dictionary

python

```python
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

    # Extended Formats
    TargetFormat.PIHOLE: "pihole.list",
    TargetFormat.PFSENSE: "pfsense.txt",
    TargetFormat.OPNSENSE: "opnsense.conf",
    TargetFormat.WINDOWS_FW: "windows-firewall.ps1",
    TargetFormat.IPTABLES: "iptables.sh",
    TargetFormat.NFTABLES: "nftables.conf",
    TargetFormat.NGINX: "nginx-block.conf",
    TargetFormat.APACHE: "apache-block.conf",
    TargetFormat.CLOUDFLARE_WAF: "cloudflare-waf.json",
    TargetFormat.AWS_WAF: "aws-waf.json",
    TargetFormat.MODSECURITY: "modsecurity.conf"
}
```


### B) Add to `ubs_smart_converter.py` → `_do_conversion()`:

python

```python
# Add inside the _do_conversion() method:

elif target_format == TargetFormat.PGL:
    return extended_converter.to_pgl()
elif target_format == TargetFormat.MIKROTIK:
    return extended_converter.to_mikrotik()
elif target_format == TargetFormat.CISCO:
    return extended_converter.to_cisco()
elif target_format == TargetFormat.JUNIPER:
    return extended_converter.to_juniper()
elif target_format == TargetFormat.IPSET:
    return extended_converter.to_ipset()
```


---


## 5️⃣ Extend TargetFormat

### In `ubs_smart_converter.py` -> `TargetFormat`

Starting at line 7:

````
    class TargetFormat(Enum):"
    """Supported target form

       AWS_WAF = "aws-waf"
       MODSECURITY = "modsecurity"
````


---

## 6️⃣ Optional: Extend API Docs

**File:** `application.py`
**Method:** `api_docs_json()`
**Action:** Update the format list

python

```python
"params": {
    "format": "hosts|adblock|dnsmasq|unbound|bind|squid|proxy_pac|suricata|pihole|pfsense|opnsense|windows|iptables|nftables|nginx|apache|cloudflare|aws-waf|modsecurity"
}
```

---

## ✅ Final Checklist

- [ ]  **1. Frontend:** Select box extended in HOME_TEMPLATE
- [ ]  **2. Backend:** api_convert() route updated with format mapping & extensions
- [ ]  **3. Converter:** All 11 methods implemented in ExtendedConverters
- [ ]  **4. Batch:** format_files dictionary extended
- [ ] **5. Complete TargetFormat**
- [ ]  **6. Docs:** API documentation updated (optional)
- [ ]  **7. Test:** Test each format individually

## 🧪 Test Commands

bash

```bash
# After uploading a UBS file:
curl -u user:pass "http://localhost:5000/api/convert?format=pihole" -o test.list
curl -u user:pass "http://localhost:5000/api/convert?format=nginx" -o test.conf
curl -u user:pass "http://localhost:5000/api/convert?format=cloudflare" -o test.json
```

**Done!** 🎉
