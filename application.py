#!/usr/bin/env python3
"""
Vallanx Universal Blocklist Syntax (UBS) - Web Application
For deployment on alwaysdata shared hosting with venv

This application provides:
- Web interface for UBS management
- REST API endpoints
- File upload/download
- ML analysis via web
- Real-time conversion

Author: Vallanx UBS Team
Version: 3.0
"""

import os
import sys
import json
import tempfile
import traceback
from pathlib import Path
from datetime import datetime
from io import BytesIO, StringIO
from functools import wraps
from flask import Response
from markupsafe import escape as html_escape

# Flask is required — install via: pip install flask
try:
    from flask import Flask, request, jsonify, render_template_string, send_file, redirect, url_for
except ImportError:
    print("Flask not found. Please install it: pip install flask", file=sys.stderr)
    sys.exit(1)

# Import UBS modules (ensure they're in the same directory or PYTHONPATH)
import_errors = []

try:
    from ubs_parser import UBSParser
except ImportError as e:
    import_errors.append(f"ubs_parser: {e}")
    UBSParser = None

try:
    from ubs_ttl_extension import UBSConverterTTL
except ImportError as e:
    import_errors.append(f"ubs_ttl_extension: {e}")
    UBSConverterTTL = None

try:
    from ubs_advanced_features import RuleValidator, URLTester
except ImportError as e:
    import_errors.append(f"ubs_advanced_features: {e}")
    RuleValidator = None
    URLTester = None

try:
    from ubs_smart_converter import SmartConverter, TargetFormat
except ImportError as e:
    import_errors.append(f"ubs_smart_converter: {e}")
    SmartConverter = None
    TargetFormat = None

try:
    from ubs_machine_learning import DomainCategorizer, AdvancedMLAnalyzer
except ImportError as e:
    import_errors.append(f"ubs_machine_learning: {e}")
    DomainCategorizer = None
    AdvancedMLAnalyzer = None

try:
    from ubs_analytics_reporting import StatisticsGenerator, Visualizer
except ImportError as e:
    import_errors.append(f"ubs_analytics_reporting: {e}")
    StatisticsGenerator = None
    Visualizer = None

# Check if critical module loaded
if UBSParser is None:
    print("\n" + "="*80)
    print("CRITICAL ERROR: ubs_parser could not be imported!")
    print("="*80)
    print("Import errors:")
    for error in import_errors:
        print(f"  - {error}")
    print("\nCurrent directory:", os.getcwd())
    print("Python files in directory:")
    for f in os.listdir('.'):
        if f.endswith('.py'):
            print(f"  - {f}")
    print("="*80)
    sys.exit(1)

# Show warnings for optional modules
if import_errors:
    print("Warning: Some optional UBS modules not found:")
    for error in import_errors:
        print(f"  - {error}")

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# Global storage (in production, use database)
global_parser = None
global_ml_analyzer = None

# ============================================================================
# PASSWORD PROTECTION
# ============================================================================

ADMIN_USER = os.getenv("UBS_ADMIN_USER")
ADMIN_PASS = os.getenv("UBS_ADMIN_PASS")

def check_auth(username, password):
    """This function is called to check if a username / password combination is valid."""
    return username == ADMIN_USER and password == ADMIN_PASS

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})


# ============================================================================
# TEMPLATE LOADER
# ============================================================================

def load_docs_template():
    """Load the docs.html template from disk"""
    docs_path = Path(__file__).parent / 'docs.html'
    
    if docs_path.exists():
        try:
            with open(docs_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"Warning: Could not read docs.html: {e}")
    
    # Fallback: Basic inline template if docs.html doesn't exist
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>UBS API Documentation</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                max-width: 1200px; 
                margin: 0 auto; 
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 { color: #667eea; }
            .endpoint { 
                background: #f5f5f5; 
                padding: 20px; 
                margin: 15px 0; 
                border-radius: 8px;
                border-left: 4px solid #667eea;
            }
            .method { 
                font-weight: bold; 
                padding: 5px 10px;
                border-radius: 4px;
                color: white;
            }
            .method.get { background: #48bb78; }
            .method.post { background: #4299e1; }
            code {
                background: #2d3748;
                color: #e2e8f0;
                padding: 15px;
                display: block;
                border-radius: 5px;
                margin: 10px 0;
                overflow-x: auto;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ UBS REST API Documentation</h1>
            <p><strong>Base URL:</strong> <code style="display:inline;padding:5px;">{{ base_url }}</code></p>
            <p>Version 3.0 | Universal Blocklist Syntax</p>
            
            <div class="endpoint">
                <p><span class="method post">POST</span> <strong>/api/parse</strong></p>
                <p>Parse UBS file and load into memory</p>
                <code>curl -X POST {{ base_url }}/api/parse -u user:pass -F "file=@blocklist.ubs"</code>
            </div>
            
            <div class="endpoint">
                <p><span class="method get">GET</span> <strong>/api/convert?format=FORMAT</strong></p>
                <p>Convert to specified format (hosts, adblock, dnsmasq, etc.)</p>
                <code>curl -X GET "{{ base_url }}/api/convert?format=hosts" -u user:pass -o output.txt</code>
            </div>
            
            <div class="endpoint">
                <p><span class="method get">GET</span> <strong>/api/validate</strong></p>
                <p>Validate current file for errors and warnings</p>
                <code>curl -X GET {{ base_url }}/api/validate -u user:pass</code>
            </div>
            
            <div class="endpoint">
                <p><span class="method post">POST</span> <strong>/api/ml-analyze</strong></p>
                <p>ML analysis of domains (requires parsed file)</p>
                <code>curl -X POST {{ base_url }}/api/ml-analyze -u user:pass \\
  -H "Content-Type: application/json" \\
  -d '{"domains": ["example.com"]}'</code>
            </div>
            
            <div class="endpoint">
                <p><span class="method get">GET</span> <strong>/api/stats</strong></p>
                <p>Get statistics about current file</p>
                <code>curl -X GET {{ base_url }}/api/stats -u user:pass</code>
            </div>
            
            <p style="margin-top: 30px; text-align: center;">
                <a href="/" style="color: #667eea;">← Zurück zur Hauptseite</a> | 
                <a href="/api/docs/json" style="color: #667eea;">JSON Format</a>
            </p>
        </div>
    </body>
    </html>
    """

# ============================================================================
# HTML TEMPLATES
# ============================================================================

HOME_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UBS - Universal Blocklist Syntax</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            margin-bottom: 30px;
            text-align: center;
        }
        h1 { color: #667eea; font-size: 2.5em; margin-bottom: 10px; }
        .tagline { color: #718096; font-size: 1.1em; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            transition: transform 0.3s;
        }
        .card:hover { transform: translateY(-5px); }
        .card h2 { color: #667eea; margin-bottom: 15px; }
        .card p { color: #4a5568; margin-bottom: 20px; }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
            border: none;
            cursor: pointer;
            font-size: 1em;
        }
        .btn:hover { background: #5a67d8; }
        .upload-area {
            border: 2px dashed #cbd5e0;
            padding: 40px;
            text-align: center;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .upload-area:hover {
            border-color: #667eea;
            background: #f7fafc;
        }
        .stats {
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            gap: 20px;
        }
        .stat {
            text-align: center;
            padding: 20px;
            background: #f7fafc;
            border-radius: 10px;
            min-width: 150px;
        }
        .stat-value {
            font-size: 2.5em;
            color: #667eea;
            font-weight: bold;
        }
        .stat-label {
            color: #718096;
            margin-top: 5px;
        }
        footer {
            text-align: center;
            color: white;
            margin-top: 40px;
            padding: 20px;
        }
        input[type="file"] { display: none; }
        .alert {
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
            display: none;
        }
        .alert-success { background: #c6f6d5; color: #22543d; }
        .alert-error { background: #fed7d7; color: #742a2a; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Universal Blocklist Syntax</h1>
            <p class="tagline">Web Interface v3.0 - Machine Learning Powered</p>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value">10</div>
                    <div class="stat-label">Modules</div>
                </div>
                <div class="stat">
                    <div class="stat-value">120+</div>
                    <div class="stat-label">Features</div>
                </div>
                <div class="stat">
                    <div class="stat-value">21</div>
                    <div class="stat-label">Export Formats</div>
                </div>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <h2>📤 Upload & Parse</h2>
                <p>Upload your UBS file for parsing and analysis</p>
                <form id="uploadForm" enctype="multipart/form-data">
                    <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                        <p>📁 Click to upload UBS file</p>
                        <input type="file" id="fileInput" name="file" accept=".ubs,.txt">
                    </div>
                    <button type="submit" class="btn" style="margin-top: 15px; width: 100%;">Parse File</button>
                </form>
                <div id="uploadAlert" class="alert"></div>
            </div>

            <div class="card">
                <h2>🔄 Convert</h2>
                <p>Convert UBS to any format</p>
                <form id="convertForm">
                    <select id="formatSelect" class="btn" style="width: 100%; margin-bottom: 10px;">
                        <option value="hosts">Hosts</option>
                        <option value="adblock">AdBlock</option>
                        <option value="dnsmasq">Dnsmasq</option>
                        <option value="pihole">Pi-hole</option>
                        <option value="nginx">Nginx</option>
                        <option value="cloudflare">Cloudflare WAF</option>
                    </select>
                    <button type="submit" class="btn" style="width: 100%;">Convert & Download</button>
                </form>
            </div>

            <div class="card">
                <h2>🤖 ML Analysis</h2>
                <p>Analyze domains with Machine Learning</p>
                <form id="mlForm">
                    <textarea id="domainsInput" placeholder="Enter domains (one per line)" 
                              style="width: 100%; height: 100px; padding: 10px; border: 1px solid #cbd5e0; border-radius: 5px; margin-bottom: 10px;"></textarea>
                    <button type="submit" class="btn" style="width: 100%;">Analyze with ML</button>
                </form>
                <div id="mlResults" style="margin-top: 15px;"></div>
            </div>

            <div class="card">
                <h2>✅ Validate</h2>
                <p>Validate UBS syntax and check for issues</p>
                <a href="/validate" class="btn" style="width: 100%; text-align: center; display: block;">Validate Current File</a>
            </div>

            <div class="card">
                <h2>📊 Analytics</h2>
                <p>View statistics and visualizations</p>
                <a href="/analytics" class="btn" style="width: 100%; text-align: center; display: block;">View Analytics</a>
            </div>

            <div class="card">
                <h2>📖 API Documentation</h2>
                <p>REST API for developers</p>
                <a href="/api/docs" class="btn" style="width: 100%; text-align: center; display: block;">View API Docs</a>
            </div>
        </div>

        <footer>
            <p><strong>UBS Web Application</strong> | Running on alwaysdata</p>
            <p style="opacity: 0.8; margin-top: 5px;">Version 3.0 | MIT License</p>
        </footer>
    </div>

    <script>
        // File upload
        document.getElementById('fileInput').addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name;
            if (fileName) {
                document.querySelector('.upload-area p').textContent = `📁 ${fileName}`;
            }
        });

        document.getElementById('uploadForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const alert = document.getElementById('uploadAlert');
            
            try {
                const response = await fetch('/api/parse', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                
                alert.className = 'alert alert-success';
                alert.style.display = 'block';
                alert.textContent = `✅ Parsed ${data.rules_count} rules successfully!`;
            } catch (error) {
                alert.className = 'alert alert-error';
                alert.style.display = 'block';
                alert.textContent = `❌ Error: ${error.message}`;
            }
        });

        // Convert
        document.getElementById('convertForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const format = document.getElementById('formatSelect').value;
            
            window.location.href = `/api/convert?format=${format}`;
        });

        // ML Analysis
        document.getElementById('mlForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const domains = document.getElementById('domainsInput').value.split('\\n').filter(d => d.trim());
            const resultsDiv = document.getElementById('mlResults');
            
            resultsDiv.innerHTML = '<p>🔄 Analyzing...</p>';
            
            try {
                const response = await fetch('/api/ml-analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domains })
                });
                const data = await response.json();
                
                let html = '<div style="max-height: 300px; overflow-y: auto;">';
                data.analyses.forEach(analysis => {
                    const icon = analysis.threat_level === 'CRITICAL' ? '🔴' :
                                 analysis.threat_level === 'HIGH' ? '🟠' :
                                 analysis.threat_level === 'MEDIUM' ? '🟡' : '🟢';
                    html += `
                        <div style="padding: 10px; margin: 5px 0; background: #f7fafc; border-radius: 5px;">
                            <strong>${icon} ${analysis.domain}</strong><br>
                            <small>Risk: ${analysis.risk_score.toFixed(1)}/100 | ${analysis.threat_level}</small>
                        </div>
                    `;
                });
                html += '</div>';
                resultsDiv.innerHTML = html;
            } catch (error) {
                resultsDiv.innerHTML = `<p style="color: red;">❌ Error: ${error.message}</p>`;
            }
        });
    </script>
</body>
</html>
"""

# ============================================================================
# WEB ROUTES
# ============================================================================

# Passwort Schutz
@app.before_request
def require_login():
    from flask import request
    auth = request.authorization
    if not auth or not check_auth(auth.username, auth.password):
        return authenticate()

@app.route('/')
def home():
    """Home page with web interface"""
    return render_template_string(HOME_TEMPLATE)

@app.route('/api/docs')
def api_docs():
    """API documentation - HTML version"""
    try:
        # Load template
        template = load_docs_template()
        
        # Get base URL
        base_url = request.url_root.rstrip('/')
        
        # Render with base_url
        return render_template_string(template, base_url=base_url)
    
    except Exception as e:
        # Fallback to JSON if template loading fails
        return jsonify({
            "error": "Could not load HTML template",
            "message": str(e),
            "fallback": "Use /api/docs/json for JSON format"
        }), 500

@app.route('/api/docs/json')
def api_docs_json():
    """API documentation - JSON version"""
    docs = {
        "title": "UBS REST API Documentation",
        "version": "3.0",
        "base_url": request.url_root.rstrip('/'),
        "authentication": "HTTP Basic Auth required",
        "endpoints": [
            {
                "path": "/api/parse",
                "method": "POST",
                "description": "Parse UBS file",
                "body": "multipart/form-data with 'file' field",
                "response": {
                    "success": "boolean",
                    "rules_count": "integer",
                    "metadata": "object",
                    "errors": "array"
                }
            },
            {
                "path": "/api/convert",
                "method": "GET",
                "description": "Convert to format",
                "params": {
                    "format": "hosts|adblock|dnsmasq|unbound|bind|proxypac|squid|littlesnitch|pgl|suricata|opnsense|pfsense|mikrotik|cisco|juniper|ipset|nftables|iptables|nginx|cloudflare"
                },
                "response": "File download (text/plain)"
            },
            {
                "path": "/api/validate",
                "method": "GET",
                "description": "Validate current file",
                "response": {
                    "valid": "boolean",
                    "issues": "array",
                    "stats": "object"
                }
            },
            {
                "path": "/api/ml-analyze",
                "method": "POST",
                "description": "ML analysis of domains",
                "body": "JSON: {domains: [...]}",
                "response": {
                    "success": "boolean",
                    "count": "integer",
                    "analyses": "array"
                }
            },
            {
                "path": "/api/stats",
                "method": "GET",
                "description": "Get statistics",
                "response": {
                    "total_rules": "integer",
                    "by_type": "object",
                    "by_severity": "object",
                    "unique_domains": "integer"
                }
            }
        ]
    }
    return jsonify(docs)

@app.route('/api/parse', methods=['POST'])
def api_parse():
    """Parse uploaded UBS file"""
    global global_parser
    
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Empty filename"}), 400
        
        # Read file content
        content = file.read().decode('utf-8')
        
        # Parse
        parser = UBSParser()
        parser.parse(content)
        
        # Store globally
        global_parser = parser
        
        return jsonify({
            "success": True,
            "rules_count": len(parser.rules),
            "metadata": {
                "title": parser.metadata.title,
                "version": parser.metadata.version
            },
            "errors": parser.errors,
            "warnings": getattr(parser, 'warnings', [])
        })
    
    except Exception as e:
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500

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
        
        # Try to convert
        try:
            format_enum = TargetFormat(format_name)
            result = converter.convert(format_enum, optimize=True)
        except (ValueError, AttributeError):
            result = converter.convert_auto(format_name, optimize=True)
        
        if result.success:
            # Return as downloadable file
            filename = f"blocklist.{format_name}"
            
            return send_file(
                BytesIO(result.content.encode('utf-8')),
                mimetype='text/plain',
                as_attachment=True,
                download_name=filename
            )
        else:
            return jsonify({"error": result.error}), 500
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/validate')
def api_validate():
    """Validate current file"""
    global global_parser
    
    if global_parser is None:
        return jsonify({"error": "No file parsed yet"}), 400
    
    try:
        if RuleValidator is None:
            return jsonify({"error": "RuleValidator module not available"}), 500
            
        validator = RuleValidator(strict_mode=True, check_dns=False)
        issues = validator.validate(global_parser)
        
        return jsonify({
            "valid": len([i for i in issues if i.severity == 'error']) == 0,
            "issues": [
                {
                    "severity": issue.severity,
                    "line": issue.line_number,
                    "message": issue.message,
                    "suggestion": issue.suggestion
                }
                for issue in issues
            ],
            "stats": {
                "errors": len([i for i in issues if i.severity == 'error']),
                "warnings": len([i for i in issues if i.severity == 'warning']),
                "info": len([i for i in issues if i.severity == 'info'])
            }
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ml-analyze', methods=['POST'])
def api_ml_analyze():
    """ML analysis of domains"""
    global global_parser, global_ml_analyzer
    
    if global_parser is None:
        return jsonify({"error": "No file parsed yet. Upload a training file first."}), 400
    
    try:
        if AdvancedMLAnalyzer is None:
            return jsonify({"error": "AdvancedMLAnalyzer module not available"}), 500
            
        data = request.get_json()
        domains = data.get('domains', [])
        
        if not domains:
            return jsonify({"error": "No domains provided"}), 400
        
        # Initialize or reuse ML analyzer
        if global_ml_analyzer is None:
            global_ml_analyzer = AdvancedMLAnalyzer(global_parser)
        
        # Analyze domains
        analyses = global_ml_analyzer.batch_analyze(domains)
        
        return jsonify({
            "success": True,
            "count": len(analyses),
            "analyses": [
                {
                    "domain": a['domain'],
                    "risk_score": a['risk_score'],
                    "threat_level": a['threat_level'],
                    # "category": a['category_prediction'].predicted_category,
                    # "confidence": a['category_prediction'].confidence,
                    "category": getattr(a.get('category_prediction'), 'predicted_category', None),
                    "confidence": getattr(a.get('category_prediction'), 'confidence', None),
                    "recommendation": a['recommendation']
                }
                for a in analyses
            ]
        })
    
    except Exception as e:
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500

@app.route('/api/stats')
def api_stats():
    """Get statistics"""
    global global_parser
    
    if global_parser is None:
        return jsonify({"error": "No file parsed yet"}), 400
    
    try:
        if StatisticsGenerator is None:
            return jsonify({"error": "StatisticsGenerator module not available"}), 500
            
        stats_gen = StatisticsGenerator(global_parser)
        stats = stats_gen.generate_statistics()
        
        return jsonify({
            "total_rules": stats.total_rules,
            "by_type": stats.by_type,
            "by_severity": stats.by_severity,
            "by_category": stats.by_category,
            "unique_domains": stats.unique_domains,
            "wildcard_count": stats.wildcard_count
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/validate')
def validate_page():
    """Validation results page"""
    import sys
    global global_parser
    
    print("\n" + "="*80, file=sys.stderr)
    print("DEBUG: /validate called", file=sys.stderr)
    print("="*80 + "\n", file=sys.stderr)
    
    if global_parser is None:
        print("ERROR: global_parser is None", file=sys.stderr)
        return redirect(url_for('home'))
    
    if RuleValidator is None:
        return "<h1>Error</h1><p>RuleValidator module not available</p>", 500
    
    try:
        print(f"DEBUG: Parser has {len(global_parser.rules)} rules", file=sys.stderr)
        print("DEBUG: Importing RuleValidator...", file=sys.stderr)
        
        print("DEBUG: Creating RuleValidator instance...", file=sys.stderr)
        validator = RuleValidator(strict_mode=True)
        
        print("DEBUG: Calling validate()...", file=sys.stderr)
        issues = validator.validate(global_parser)
        
        print(f"DEBUG: Validation complete! Found {len(issues)} issues", file=sys.stderr)
        
        # Generate HTML (existing code)
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Validation Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; background: #f5f7fa; }}
                .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
                h1 {{ color: #667eea; }}
                .issue {{ padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .error {{ background: #fed7d7; color: #742a2a; }}
                .warning {{ background: #feebc8; color: #7c2d12; }}
                .info {{ background: #bee3f8; color: #1e4e8c; }}
                .btn {{ display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>✅ Validation Results</h1>
                <p><strong>Total Rules:</strong> {len(global_parser.rules)}</p>
                <p><strong>Errors:</strong> {len([i for i in issues if i.severity == 'error'])}</p>
                <p><strong>Warnings:</strong> {len([i for i in issues if i.severity == 'warning'])}</p>
                <p><strong>Info:</strong> {len([i for i in issues if i.severity == 'info'])}</p>
                
                <h2>Issues</h2>
        """
        
        for issue in issues[:50]:
            html += f"""
                <div class="issue {html_escape(issue.severity)}">
                    <strong>[{html_escape(issue.severity.upper())}] Line {issue.line_number}</strong><br>
                    {html_escape(issue.message)}<br>
                    {f'<em>💡 {html_escape(issue.suggestion)}</em>' if issue.suggestion else ''}
                </div>
            """
        
        html += """
                <a href="/" class="btn">← Back to Home</a>
            </div>
        </body>
        </html>
        """
        
        return render_template_string(html)
        
    except Exception as e:
        print("\n" + "!"*80, file=sys.stderr)
        print("EXCEPTION CAUGHT IN /validate:", file=sys.stderr)
        print(f"Type: {type(e).__name__}", file=sys.stderr)
        print(f"Message: {str(e)}", file=sys.stderr)
        print("!"*80 + "\n", file=sys.stderr)
        
        import traceback
        traceback.print_exc(file=sys.stderr)
        
        return f"<h1>Error</h1><pre>{traceback.format_exc()}</pre>", 500

@app.route('/analytics')
def analytics_page():
    """Analytics page"""
    global global_parser
    
    if global_parser is None:
        return redirect(url_for('home'))
    
    if StatisticsGenerator is None:
        return "<h1>Error</h1><p>StatisticsGenerator module not available</p>", 500
    
    stats_gen = StatisticsGenerator(global_parser)
    stats = stats_gen.generate_statistics()
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Analytics</title>
        <style>
            body {{ font-family: Arial, sans-serif; padding: 20px; background: #f5f7fa; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            h1 {{ color: #667eea; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
            th {{ background: #667eea; color: white; }}
            .btn {{ display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📊 Analytics Dashboard</h1>
            
            <h2>Overview</h2>
            <table>
                <tr><td>Total Rules</td><td><strong>{stats.total_rules}</strong></td></tr>
                <tr><td>Unique Domains</td><td><strong>{stats.unique_domains}</strong></td></tr>
                <tr><td>Wildcard Rules</td><td><strong>{stats.wildcard_count}</strong></td></tr>
                <tr><td>Regex Rules</td><td><strong>{stats.regex_count}</strong></td></tr>
            </table>
            
            <h2>By Type</h2>
            <table>
                <tr><th>Type</th><th>Count</th></tr>
    """
    
    for rule_type, count in sorted(stats.by_type.items(), key=lambda x: -x[1]):
        html += f"<tr><td>{html_escape(str(rule_type))}</td><td>{count}</td></tr>"
    
    html += """
            </table>
            
            <a href="/" class="btn">← Back to Home</a>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(html)

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error", "details": str(e)}), 500

# ============================================================================
# MAIN APPLICATION (for alwaysdata)
# ============================================================================

# This is the WSGI application object that alwaysdata will use
application = app

if __name__ == '__main__':
    # For local testing only — never run with debug=True in production
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    print("🚀 Starting UBS Web Application...")
    print("📍 Open http://localhost:5000 in your browser")
    app.run(debug=debug_mode, host='127.0.0.1', port=5000)
