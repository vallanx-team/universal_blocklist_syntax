
**Here is the complete guide for adding modifiers to the whitelist:**

---

## **Where is the modifier whitelist?**

The whitelist is located in:

```
/home/ubs/www/ubs_advanced_features.py
```

**Line ~60-78** in the `RuleValidator.__init__()` method.

---

## **Guide: Adding new modifiers**

### **Step 1: Open the file**

bash

```bash
nano /home/ubs/www/ubs_advanced_features.py
```

---

### **Step 2: Navigate to the modifier list**

Press `Ctrl+W` (Search) and type: `valid_modifiers`

You will then see:

python

```python
self.valid_modifiers = {
    'action', 'severity', 'category', 'log', 'block', 'allow',
    'third-party', 'first-party', 'script', 'image', 'stylesheet',
    'domain', 'subdocument', 'xmlhttprequest', 'websocket',
    'webrtc', 'popup', 'popunder', 'document', 'font', 'media',
    'object', 'ping', 'other', 'important', 'badfilter',
    'genericblock', 'generichide', 'specifichide', 'proxy',
    'fallback', 'remove-header', 'csp', 'redirect', 'redirect-rule',
    'empty', 'mp4', 'all', 'inline-script', 'inline-font',
    'msg', 'reason', 'protocol', 'port', 'content', 'rate', 'limit',
    'selector', 'scriptlet'
}
```

---

### **Step 3: Add new modifiers**

**Format:**

- Each modifier is wrapped in **single quotes** (`'modifier'`)
- Modifiers are separated by **commas**
- Each line ends with a **comma** (except the last line before `}`)

**Example — add more modifiers:**

python

```python
self.valid_modifiers = {
    'action', 'severity', 'category', 'log', 'block', 'allow',
    'third-party', 'first-party', 'script', 'image', 'stylesheet',
    'domain', 'subdocument', 'xmlhttprequest', 'websocket',
    'webrtc', 'popup', 'popunder', 'document', 'font', 'media',
    'object', 'ping', 'other', 'important', 'badfilter',
    'genericblock', 'generichide', 'specifichide', 'proxy',
    'fallback', 'remove-header', 'csp', 'redirect', 'redirect-rule',
    'empty', 'mp4', 'all', 'inline-script', 'inline-font',
    'msg', 'reason', 'protocol', 'port', 'content', 'rate', 'limit',
    'selector', 'scriptlet',
    # New modifiers (examples):
    'timeout', 'ttl', 'priority', 'weight'  # ← Add new ones here
}
```

---

### **Step 4: Save**

- `Ctrl+O` (Save)
- `Enter` (Confirm)
- `Ctrl+X` (Exit)

---

### **Step 5: Restart Flask**

bash

```bash
# In the terminal where Flask is running: Ctrl+C

# Clear cache (important!)
rm -rf /home/ubs/www/__pycache__

# Restart Flask
python3 application.py
```

---

### **Step 6: Test**

In the browser:

1. Go to `https://ubs.alwaysdata.net/`
2. Upload the file **again**
3. Click "Validate"

The new modifiers should now be accepted! ✅

---

## **Common modifiers that might be missing:**

Here is an extended list in case you need more:

python

```python
self.valid_modifiers = {
    # Basic
    'action', 'severity', 'category', 'log', 'block', 'allow',

    # AdBlock/uBlock
    'third-party', 'first-party', 'script', 'image', 'stylesheet',
    'domain', 'subdocument', 'xmlhttprequest', 'websocket',
    'webrtc', 'popup', 'popunder', 'document', 'font', 'media',
    'object', 'ping', 'other', 'important', 'badfilter',
    'genericblock', 'generichide', 'specifichide',

    # Proxy & Routing
    'proxy', 'fallback', 'redirect', 'redirect-rule',

    # Header Manipulation
    'remove-header', 'csp',

    # Formats
    'empty', 'mp4', 'inline-script', 'inline-font',

    # Metadata
    'msg', 'reason', 'all',

    # IDS/Suricata
    'protocol', 'port', 'content', 'sid', 'rev', 'classtype',

    # Rate Limiting
    'rate', 'limit', 'burst', 'timeout',

    # CSS/JS
    'selector', 'scriptlet',

    # Network
    'ttl', 'priority', 'weight', 'host', 'path', 'query',

    # Custom
    'comment', 'expires', 'updated'
}
```

---

## **Summary:**

1. **Open:** `/home/ubs/www/ubs_advanced_features.py`
2. **Search:** `valid_modifiers`
3. **Add:** New modifiers on the line before `}`
4. **Format:** `'modifier_name',` (with comma!)
5. **Save & Restart:** Clear cache, restart Flask
6. **Test:** Re-upload the file

**Done!** 🎉


---

# Is this the only place where modifiers need to be / can be changed? Or do I also need to add new modifiers in other modules / locations?

Examined modifier validation across various software modules.

11 sec.

**Great question! Let me explain this systematically:**

---

## **Short answer:**

**No, this is the ONLY place for validation.** But there are other places where modifiers are **used** (but not validated).

---

## **Detailed overview:**

### **1. ubs_advanced_features.py (RuleValidator) ← THIS is what we changed**

python

```python
self.valid_modifiers = { ... }
```

**This is the ONLY whitelist for validation.**

- ✅ Only used during validation
- ✅ Does not affect any other functionality
- ✅ Adding new modifiers here = they will be accepted

---

### **2. ubs_parser.py (UBSParser) — No whitelist!**

python

```python
def _parse_modifiers(self, modifier_str: str) -> Dict:
    """Parse modifier string"""
    modifiers = {}
    for match in self.modifier_pattern.finditer(modifier_str):
        key, value = match.groups()
        modifiers[key] = value if value else True
    return modifiers
```

**The parser accepts ALL modifiers automatically!**

- ✅ No whitelist
- ✅ No validation
- ✅ Simply stores everything as a dictionary
- ⚠️ Meaning: you can use ANY modifier you like (e.g. `:my_custom_modifier=value`)

---

### **3. Converters (e.g. ubs_smart_converter.py) — Use modifiers**

The converters **read** modifiers but do **not** validate them:

python

```python
# Example from a converter:
if 'severity' in rule.modifiers:
    severity = rule.modifiers['severity']

if 'third-party' in rule.modifiers:
    # Handle third-party blocking
```

**What does this mean?**

- ✅ Converters only look for **known** modifiers
- ✅ Unknown modifiers are simply **ignored**
- ⚠️ If you want to use a new modifier functionally, you must **implement it in the converter**

---

## **Practical example:**

**Scenario:** You want to add a new modifier `:ttl=3600`.

### **Step 1: Extend the whitelist (to avoid validation errors)**

bash

```bash
nano /home/ubs/www/ubs_advanced_features.py
```

Add: `'ttl'`

### **Step 2: Parser (nothing to do!)**

The parser accepts `:ttl=3600` automatically.

### **Step 3: Adjust the converter (ONLY if you want TTL to be functional)**

bash

```bash
nano /home/ubs/www/ubs_smart_converter.py
```

Find the section where BIND zones are generated, for example:

python

```python
def to_bind(self) -> str:
    lines = []
    for rule in self.parser.rules:
        if rule.rule_type == RuleType.DOMAIN:
            # NEW: Use TTL if present
            ttl = rule.modifiers.get('ttl', 86400)  # Default: 24h
            lines.append(f'zone "{rule.pattern}" {{ttl {ttl}; ...}};')
    return '\n'.join(lines)
```

---

## **Where modifiers are used (overview):**

| Module | Function | Whitelist? | Behaviour with unknown modifier |
|---|---|---|---|
| **ubs_parser.py** | Parses modifiers | ❌ No | Accepts all |
| **ubs_advanced_features.py** | Validates modifiers | ✅ **Yes — change here!** | Shows error |
| **ubs_smart_converter.py** | Uses modifiers during conversion | ❌ No | Ignores unknown |
| **ubs_machine_learning.py** | Uses modifiers as features | ❌ No | Ignores unknown |
| **ubs_analytics_reporting.py** | Counts modifiers | ❌ No | Counts all |

---

## **When do you need to change what?**

### **Only allow validation (no errors):**

```
✅ ONLY ubs_advanced_features.py → valid_modifiers
```

### **Modifier should also be used functionally:**

```
✅ ubs_advanced_features.py → valid_modifiers (for validation)
✅ ubs_smart_converter.py → add converter logic
✅ OR other modules where the modifier is needed
```

### **Example: New `:priority=high` modifier**

**Accept only (no functionality):**

python

```python
# In ubs_advanced_features.py
self.valid_modifiers = {
    ...,
    'priority'  # ← Sufficient!
}
```

**Also use (e.g. in Suricata export):**

python

```python
# In ubs_smart_converter.py
def to_suricata(self):
    for rule in self.parser.rules:
        priority = rule.modifiers.get('priority', 1)  # Default: 1
        # Use priority when generating output
```

---

## **Summary:**

✅ **Validation:** Only `ubs_advanced_features.py` → `valid_modifiers`
✅ **Parsing:** `ubs_parser.py` accepts everything automatically
⚠️ **Functionality:** Converters must be updated if the modifier should also be used
✅ **Best practice:** Add to the whitelist first, test, then optionally implement functionality

**For most new modifiers, adding them to the whitelist is all you need!** 🎯
