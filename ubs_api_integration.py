#!/usr/bin/env python3
"""
UBS REST API & Integration Module
- REST API endpoints
- Webhook support
- Auto-update from remote lists
- GitHub integration
"""

import json
import hashlib
import time
import threading
from pathlib import Path
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request


# ============================================================================
# REST API
# ============================================================================

@dataclass
class APIResponse:
    """Standard API response format"""
    success: bool
    data: Optional[Dict] = None
    error: Optional[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


class UBSAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for UBS API"""
    
    # Class-level storage (in production, use a database)
    parsers_cache = {}
    validation_cache = {}
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        if path == '/':
            self._send_response(200, {
                'message': 'UBS API Server',
                'version': '1.0.0',
                'endpoints': [
                    'GET  /health',
                    'POST /parse',
                    'POST /convert',
                    'POST /validate',
                    'GET  /lookup?domain=example.com',
                    'GET  /stats',
                ]
            })
        
        elif path == '/health':
            self._handle_health()
        
        elif path == '/lookup':
            domain = query_params.get('domain', [None])[0]
            if domain:
                self._handle_lookup(domain)
            else:
                self._send_error(400, "Missing 'domain' parameter")
        
        elif path == '/stats':
            self._handle_stats()
        
        else:
            self._send_error(404, "Endpoint not found")
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except json.JSONDecodeError:
            self._send_error(400, "Invalid JSON")
            return
        
        if path == '/parse':
            self._handle_parse(data)
        
        elif path == '/convert':
            self._handle_convert(data)
        
        elif path == '/validate':
            self._handle_validate(data)
        
        else:
            self._send_error(404, "Endpoint not found")
    
    def _handle_health(self):
        """Health check endpoint"""
        self._send_response(200, {
            'status': 'healthy',
            'cached_parsers': len(self.parsers_cache),
            'uptime': 'N/A'  # Would track actual uptime in production
        })
    
    def _handle_parse(self, data: Dict):
        """Parse UBS content - POST /parse"""
        from ubs_parser import UBSParser
        
        content = data.get('content')
        if not content:
            self._send_error(400, "Missing 'content' field")
            return
        
        try:
            parser = UBSParser()
            parser.parse(content)
            
            # Cache the parser
            cache_key = hashlib.md5(content.encode()).hexdigest()
            self.parsers_cache[cache_key] = parser
            
            response_data = {
                'cache_key': cache_key,
                'rules_count': len(parser.rules),
                'metadata': {
                    'title': parser.metadata.title,
                    'version': parser.metadata.version,
                    'targets': list(parser.metadata.targets)
                },
                'rules': [rule.to_dict() for rule in parser.rules[:100]],  # Limit for response size
                'errors': parser.errors
            }
            
            self._send_response(200, response_data)
        
        except Exception as e:
            self._send_error(500, f"Parse error: {str(e)}")
    
    def _handle_convert(self, data: Dict):
        """Convert to format - POST /convert"""
        from ubs_parser import UBSParser, UBSConverter
        
        content = data.get('content')
        cache_key = data.get('cache_key')
        target_format = data.get('format', 'hosts')
        
        # Get parser from cache or parse content
        if cache_key and cache_key in self.parsers_cache:
            parser = self.parsers_cache[cache_key]
        elif content:
            parser = UBSParser()
            parser.parse(content)
        else:
            self._send_error(400, "Missing 'content' or 'cache_key'")
            return
        
        try:
            # Try to import TTL extension
            try:
                from ubs_ttl_extension import UBSConverterTTL
                converter = UBSConverterTTL(parser)
            except ImportError:
                converter = UBSConverter(parser)
            
            # Map format names to converter methods
            format_methods = {
                'hosts': converter.to_hosts,
                'adblock': converter.to_adblock,
                'dnsmasq': converter.to_dnsmasq,
                'unbound': converter.to_unbound,
                'bind': converter.to_bind,
                'squid': converter.to_squid,
                'pac': converter.to_proxy_pac,
                'suricata': converter.to_suricata,
                'littlesnitch': converter.to_little_snitch,
            }
            
            # Add TTL methods if available
            if hasattr(converter, 'to_unbound_ttl'):
                format_methods.update({
                    'unbound_ttl': converter.to_unbound_ttl,
                    'bind_ttl': converter.to_bind_ttl,
                    'dnsmasq_ttl': converter.to_dnsmasq_ttl,
                    'pihole_ttl': converter.to_pihole_ttl,
                    'coredns_ttl': converter.to_coredns_ttl,
                })
            
            if target_format not in format_methods:
                self._send_error(400, f"Unknown format: {target_format}. Available: {list(format_methods.keys())}")
                return
            
            # Convert
            result = format_methods[target_format]()
            
            self._send_response(200, {
                'format': target_format,
                'content': result,
                'rules_count': len(parser.rules)
            })
        
        except Exception as e:
            self._send_error(500, f"Conversion error: {str(e)}")
    
    def _handle_validate(self, data: Dict):
        """Validate UBS content - POST /validate"""
        from ubs_parser import UBSParser
        
        content = data.get('content')
        
        if not content:
            self._send_error(400, "Missing 'content' field")
            return
        
        try:
            parser = UBSParser()
            parser.parse(content)
            
            # Try to import advanced features for validation
            try:
                from ubs_advanced_features import RuleValidator
                
                strict = data.get('strict', False)
                check_dns = data.get('check_dns', False)
                
                validator = RuleValidator(strict_mode=strict, check_dns=check_dns)
                issues = validator.validate(parser)
                
                response_data = {
                    'valid': len([i for i in issues if i.severity == 'error']) == 0,
                    'issues': [
                        {
                            'severity': issue.severity,
                            'line': issue.line,
                            'message': issue.message,
                            'suggestion': issue.suggestion
                        }
                        for issue in issues
                    ],
                    'stats': {
                        'errors': len([i for i in issues if i.severity == 'error']),
                        'warnings': len([i for i in issues if i.severity == 'warning']),
                        'info': len([i for i in issues if i.severity == 'info'])
                    }
                }
                
                if check_dns:
                    dns_summary = validator.get_dns_check_summary()
                    response_data['dns_check'] = dns_summary
            
            except ImportError:
                # Fallback: Basic validation using parser errors
                response_data = {
                    'valid': len(parser.errors) == 0,
                    'issues': [
                        {
                            'severity': 'error',
                            'line': 0,
                            'message': error,
                            'suggestion': None
                        }
                        for error in parser.errors
                    ],
                    'stats': {
                        'errors': len(parser.errors),
                        'warnings': 0,
                        'info': 0
                    }
                }
            
            self._send_response(200, response_data)
        
        except Exception as e:
            self._send_error(500, f"Validation error: {str(e)}")
    
    def _handle_lookup(self, domain: str):
        """Lookup if domain is blocked - GET /lookup?domain=example.com"""
        from ubs_parser import UBSParser, RuleType
        
        # In production, would have a persistent parser
        # For demo, return error if no parser cached
        if not self.parsers_cache:
            self._send_error(400, "No rules loaded. Parse a list first via POST /parse")
            return
        
        # Use the most recent parser
        parser = list(self.parsers_cache.values())[-1]
        
        try:
            # Try to import advanced features
            try:
                from ubs_advanced_features import URLTester
                tester = URLTester(parser)
                result = tester.test_url(f"https://{domain}/")
                
                response_data = {
                    'domain': domain,
                    'blocked': result.blocked,
                    'action': result.action,
                    'reason': result.reason,
                    'matching_rules': result.matching_rules,
                    'performance_ms': result.performance_ms
                }
            
            except ImportError:
                # Fallback: Basic lookup
                blocked = False
                matching_rules = []
                
                for rule in parser.rules:
                    if rule.rule_type == RuleType.DOMAIN:
                        if domain == rule.pattern or domain.endswith('.' + rule.pattern):
                            blocked = True
                            matching_rules.append(rule.pattern)
                
                response_data = {
                    'domain': domain,
                    'blocked': blocked,
                    'action': 'block' if blocked else 'allow',
                    'reason': 'Domain match' if blocked else 'No match',
                    'matching_rules': matching_rules,
                    'performance_ms': 0
                }
            
            self._send_response(200, response_data)
        
        except Exception as e:
            self._send_error(500, f"Lookup error: {str(e)}")
    
    def _handle_stats(self):
        """Get statistics - GET /stats"""
        if not self.parsers_cache:
            self._send_error(400, "No rules loaded")
            return
        
        parser = list(self.parsers_cache.values())[-1]
        
        from collections import Counter
        
        type_counts = Counter(r.rule_type.value for r in parser.rules)
        
        response_data = {
            'total_rules': len(parser.rules),
            'by_type': dict(type_counts),
            'metadata': {
                'title': parser.metadata.title,
                'version': parser.metadata.version
            }
        }
        
        self._send_response(200, response_data)
    
    def _send_response(self, status_code: int, data: Dict):
        """Send JSON response"""
        response = APIResponse(success=True, data=data)
        
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        self.wfile.write(response.to_json().encode('utf-8'))
    
    def _send_error(self, status_code: int, message: str):
        """Send error response"""
        response = APIResponse(success=False, error=message)
        
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        self.wfile.write(response.to_json().encode('utf-8'))
    
    def log_message(self, format, *args):
        """Override to customize logging"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {format % args}")


class UBSAPIServer:
    """UBS REST API Server"""
    
    def __init__(self, host: str = 'localhost', port: int = 8080):
        self.host = host
        self.port = port
        self.server = None
    
    def start(self, blocking: bool = True):
        """Start the API server"""
        self.server = HTTPServer((self.host, self.port), UBSAPIHandler)
        
        print(f"\n🚀 UBS API Server starting...")
        print(f"   Host: {self.host}")
        print(f"   Port: {self.port}")
        print(f"   URL: http://{self.host}:{self.port}")
        print(f"\n📡 Endpoints available:")
        print(f"   GET  http://{self.host}:{self.port}/health")
        print(f"   POST http://{self.host}:{self.port}/parse")
        print(f"   POST http://{self.host}:{self.port}/convert")
        print(f"   POST http://{self.host}:{self.port}/validate")
        print(f"   GET  http://{self.host}:{self.port}/lookup?domain=example.com")
        print(f"   GET  http://{self.host}:{self.port}/stats")
        print(f"\n✅ Server ready! Press Ctrl+C to stop.\n")
        
        if blocking:
            try:
                self.server.serve_forever()
            except KeyboardInterrupt:
                print("\n\n🛑 Shutting down server...")
                self.stop()
        else:
            # Run in background thread
            thread = threading.Thread(target=self.server.serve_forever)
            thread.daemon = True
            thread.start()
    
    def stop(self):
        """Stop the server"""
        if self.server:
            self.server.shutdown()
            print("✅ Server stopped")


# ============================================================================
# WEBHOOK SUPPORT
# ============================================================================

@dataclass
class WebhookConfig:
    """Webhook configuration"""
    url: str
    events: List[str]  # 'rule_added', 'rule_removed', 'list_updated'
    secret: Optional[str] = None
    enabled: bool = True


class WebhookManager:
    """Manage webhooks for list updates"""
    
    def __init__(self):
        self.webhooks: List[WebhookConfig] = []
    
    def add_webhook(self, url: str, events: List[str], secret: Optional[str] = None):
        """Register a webhook"""
        webhook = WebhookConfig(url=url, events=events, secret=secret)
        self.webhooks.append(webhook)
        print(f"✅ Webhook registered: {url} for events {events}")
    
    def trigger(self, event: str, data: Dict):
        """Trigger webhooks for an event"""
        for webhook in self.webhooks:
            if not webhook.enabled:
                continue
            
            if event in webhook.events:
                self._send_webhook(webhook, event, data)
    
    def _send_webhook(self, webhook: WebhookConfig, event: str, data: Dict):
        """Send webhook HTTP request"""
        payload = {
            'event': event,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        
        # Add signature if secret is set
        if webhook.secret:
            signature = hashlib.sha256(
                f"{webhook.secret}{json.dumps(payload)}".encode()
            ).hexdigest()
            headers = {
                'Content-Type': 'application/json',
                'X-UBS-Signature': signature
            }
        else:
            headers = {'Content-Type': 'application/json'}
        
        try:
            req = urllib.request.Request(
                webhook.url,
                data=json.dumps(payload).encode('utf-8'),
                headers=headers,
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    print(f"✅ Webhook delivered: {event} -> {webhook.url}")
                else:
                    print(f"⚠️  Webhook failed: {event} -> {webhook.url} (status {response.status})")
        
        except Exception as e:
            print(f"❌ Webhook error: {event} -> {webhook.url}: {str(e)}")


# ============================================================================
# AUTO-UPDATE FROM REMOTE LISTS
# ============================================================================

@dataclass
class RemoteList:
    """Configuration for remote list"""
    name: str
    url: str
    update_interval: int = 3600  # seconds (1 hour default)
    last_updated: Optional[datetime] = None
    last_hash: Optional[str] = None
    enabled: bool = True


class ListUpdater:
    """Auto-update lists from remote sources"""
    
    def __init__(self, storage_path: Path = Path('./lists')):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.remote_lists: List[RemoteList] = []
        self.webhook_manager = WebhookManager()
        self.update_thread = None
        self.running = False
    
    def add_remote_list(self, name: str, url: str, update_interval: int = 3600):
        """Add a remote list to track"""
        remote_list = RemoteList(
            name=name,
            url=url,
            update_interval=update_interval
        )
        self.remote_lists.append(remote_list)
        print(f"✅ Remote list added: {name} ({url})")
    
    def fetch_list(self, remote_list: RemoteList) -> Optional[str]:
        """Fetch content from remote list"""
        try:
            print(f"📥 Fetching: {remote_list.name} from {remote_list.url}")
            
            req = urllib.request.Request(
                remote_list.url,
                headers={'User-Agent': 'UBS-Updater/1.0'}
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8')
                return content
        
        except Exception as e:
            print(f"❌ Failed to fetch {remote_list.name}: {str(e)}")
            return None
    
    def check_for_updates(self, remote_list: RemoteList) -> bool:
        """Check if list has updates"""
        content = self.fetch_list(remote_list)
        
        if content is None:
            return False
        
        # Calculate hash
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        # Check if changed
        if remote_list.last_hash and content_hash == remote_list.last_hash:
            print(f"  ℹ️  No changes for {remote_list.name}")
            return False
        
        # Save to disk
        file_path = self.storage_path / f"{remote_list.name}.ubs"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # Update metadata
        old_hash = remote_list.last_hash
        remote_list.last_hash = content_hash
        remote_list.last_updated = datetime.now()
        
        print(f"  ✅ Updated: {remote_list.name} (saved to {file_path})")
        
        # Trigger webhook
        self.webhook_manager.trigger('list_updated', {
            'list_name': remote_list.name,
            'url': remote_list.url,
            'old_hash': old_hash,
            'new_hash': content_hash,
            'file_path': str(file_path)
        })
        
        return True
    
    def update_all(self):
        """Update all remote lists"""
        print(f"\n🔄 Checking {len(self.remote_lists)} remote lists for updates...")
        
        updated_count = 0
        for remote_list in self.remote_lists:
            if not remote_list.enabled:
                continue
            
            if self.check_for_updates(remote_list):
                updated_count += 1
        
        print(f"\n✅ Update check complete: {updated_count}/{len(self.remote_lists)} lists updated")
    
    def start_auto_update(self, check_interval: int = 60):
        """Start automatic update checker in background"""
        self.running = True
        
        def update_loop():
            while self.running:
                for remote_list in self.remote_lists:
                    if not remote_list.enabled:
                        continue
                    
                    # Check if it's time to update
                    if remote_list.last_updated is None:
                        self.check_for_updates(remote_list)
                    else:
                        elapsed = (datetime.now() - remote_list.last_updated).total_seconds()
                        if elapsed >= remote_list.update_interval:
                            self.check_for_updates(remote_list)
                
                # Wait before next check
                time.sleep(check_interval)
        
        self.update_thread = threading.Thread(target=update_loop)
        self.update_thread.daemon = True
        self.update_thread.start()
        
        print(f"✅ Auto-updater started (checking every {check_interval}s)")
    
    def stop_auto_update(self):
        """Stop automatic updates"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        print("✅ Auto-updater stopped")


# ============================================================================
# GITHUB INTEGRATION
# ============================================================================

class GitHubIntegration:
    """Integration with GitHub repositories"""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.base_url = "https://api.github.com"
    
    def fetch_from_repo(self, repo: str, path: str, branch: str = 'main') -> Optional[str]:
        """
        Fetch file from GitHub repository
        
        Args:
            repo: Repository in format 'owner/repo'
            path: Path to file in repo
            branch: Branch name
        """
        url = f"{self.base_url}/repos/{repo}/contents/{path}?ref={branch}"
        
        headers = {'Accept': 'application/vnd.github.v3.raw'}
        if self.token:
            headers['Authorization'] = f'token {self.token}'
        
        try:
            req = urllib.request.Request(url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8')
                print(f"✅ Fetched from GitHub: {repo}/{path}")
                return content
        
        except Exception as e:
            print(f"❌ GitHub fetch failed: {str(e)}")
            return None
    
    def watch_repo(self, repo: str, path: str, callback: Callable[[str], None]):
        """
        Watch a GitHub repository file for changes
        Uses GitHub's ETag for efficient polling
        """
        url = f"{self.base_url}/repos/{repo}/contents/{path}"
        last_etag = None
        
        while True:
            headers = {'Accept': 'application/vnd.github.v3.raw'}
            if self.token:
                headers['Authorization'] = f'token {self.token}'
            if last_etag:
                headers['If-None-Match'] = last_etag
            
            try:
                req = urllib.request.Request(url, headers=headers)
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    etag = response.headers.get('ETag')
                    
                    if etag != last_etag:
                        content = response.read().decode('utf-8')
                        callback(content)
                        last_etag = etag
                        print(f"✅ GitHub update detected: {repo}/{path}")
                    else:
                        print(f"  ℹ️  No changes in {repo}/{path}")
            
            except urllib.error.HTTPError as e:
                if e.code == 304:
                    # Not modified
                    print(f"  ℹ️  No changes in {repo}/{path}")
                else:
                    print(f"❌ GitHub error: {str(e)}")
            except Exception as e:
                print(f"❌ Watch error: {str(e)}")
            
            # Wait before next check (respect rate limits)
            time.sleep(300)  # 5 minutes


# ============================================================================
# CLI INTEGRATION
# ============================================================================

def add_api_commands(subparsers):
    """Add API commands to CLI"""
    
    # Start API server
    api_server_parser = subparsers.add_parser('api-server',
                                              help='Start REST API server')
    api_server_parser.add_argument('--host', default='localhost',
                                   help='Host to bind to')
    api_server_parser.add_argument('--port', type=int, default=8080,
                                   help='Port to listen on')
    
    # Auto-update
    update_parser = subparsers.add_parser('auto-update',
                                         help='Auto-update from remote lists')
    update_parser.add_argument('--add', nargs=2, metavar=('NAME', 'URL'),
                              help='Add remote list')
    update_parser.add_argument('--start', action='store_true',
                              help='Start auto-updater daemon')
    update_parser.add_argument('--check', action='store_true',
                              help='Check for updates now')
    
    # GitHub integration
    github_parser = subparsers.add_parser('github',
                                         help='GitHub integration')
    github_parser.add_argument('--fetch', nargs=2, metavar=('REPO', 'PATH'),
                              help='Fetch from GitHub repo')
    github_parser.add_argument('--token', help='GitHub access token')
    github_parser.add_argument('--output', '-o', help='Output file')


def handle_api_server_command(args):
    """Handle api-server command"""
    server = UBSAPIServer(host=args.host, port=args.port)
    server.start(blocking=True)
    return 0


def handle_auto_update_command(args):
    """Handle auto-update command"""
    updater = ListUpdater()
    
    if args.add:
        name, url = args.add
        updater.add_remote_list(name, url)
        updater.update_all()
    
    elif args.check:
        # Load configured lists (in production, would persist config)
        print("No lists configured. Use --add to add lists.")
    
    elif args.start:
        updater.start_auto_update()
        print("Press Ctrl+C to stop...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            updater.stop_auto_update()
    
    return 0


def handle_github_command(args):
    """Handle github command"""
    github = GitHubIntegration(token=args.token)
    
    if args.fetch:
        repo, path = args.fetch
        content = github.fetch_from_repo(repo, path)
        
        if content:
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"✅ Saved to: {args.output}")
            else:
                print(content[:500] + "...")
        else:
            return 1
    
    return 0


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    print("=== UBS API & Integration Module ===\n")
    
    # Example 1: Start API Server (non-blocking for demo)
    print("1. Starting API Server (background)...")
    server = UBSAPIServer(port=8080)
    # server.start(blocking=False)  # Uncomment to actually start
    print("   (Demo mode - server not actually started)\n")
    
    # Example 2: Webhook Manager
    print("2. Webhook Manager Demo:")
    webhook_mgr = WebhookManager()
    webhook_mgr.add_webhook(
        url="https://example.com/webhook",
        events=['list_updated', 'rule_added']
    )
    print()
    
    # Example 3: Remote List Updater
    print("3. List Updater Demo:")
    updater = ListUpdater()
    updater.add_remote_list(
        name="example-list",
        url="https://example.com/blocklist.ubs",
        update_interval=3600
    )
    print()
    
    # Example 4: GitHub Integration
    print("4. GitHub Integration Demo:")
    github = GitHubIntegration()
    # content = github.fetch_from_repo("owner/repo", "lists/blocklist.ubs")
    print("   (Demo mode - not fetching)\n")
    
    print("✅ All API & Integration modules loaded successfully!")
