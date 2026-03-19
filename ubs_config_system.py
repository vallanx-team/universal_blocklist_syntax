#!/usr/bin/env python3
"""
UBS Configuration System Module
- YAML/JSON configuration file support
- Parser configuration
- Converter configuration
- Validation configuration
- Profile management
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict, field


# ============================================================================
# CONFIGURATION DATA CLASSES
# ============================================================================

@dataclass
class ParserConfig:
    """Parser configuration"""
    strict_mode: bool = False
    allow_regex: bool = True
    allow_wildcards: bool = True
    max_pattern_length: int = 500
    skip_invalid_rules: bool = False
    case_sensitive: bool = False


@dataclass
class ConverterConfig:
    """Converter configuration"""
    hosts_ip: str = "0.0.0.0"
    optimize: bool = True
    deduplicate: bool = True
    sort_rules: bool = True
    include_comments: bool = True
    output_encoding: str = "utf-8"


@dataclass
class ValidationConfig:
    """Validation configuration"""
    check_dns: bool = False
    dns_limit: int = 100
    dns_timeout: int = 5
    warn_slow_regex: bool = True
    warn_duplicates: bool = True
    check_conflicts: bool = True
    require_metadata: bool = False


@dataclass
class PerformanceConfig:
    """Performance configuration"""
    use_bloom_filter: bool = True
    use_trie: bool = True
    cache_regex: bool = True
    parallel_dns_checks: bool = True
    max_workers: int = 10


@dataclass
class OutputConfig:
    """Output configuration"""
    format: str = "hosts"
    output_dir: str = "./output"
    filename_template: str = "blocklist_{format}.{ext}"
    create_backup: bool = True
    backup_dir: str = "./backups"


@dataclass
class UBSConfig:
    """Main UBS configuration"""
    parser: ParserConfig = field(default_factory=ParserConfig)
    converter: ConverterConfig = field(default_factory=ConverterConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    
    # Additional settings
    log_level: str = "INFO"
    config_version: str = "1.0"


# ============================================================================
# CONFIGURATION MANAGER
# ============================================================================

class ConfigManager:
    """Manage UBS configurations"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.config = UBSConfig()
        self.profiles: Dict[str, UBSConfig] = {}
        
        # Default config locations
        self.config_paths = [
            Path.cwd() / "ubs-config.yaml",
            Path.cwd() / "ubs-config.json",
            Path.cwd() / ".ubsrc",
            Path.home() / ".config" / "ubs" / "config.yaml",
            Path.home() / ".ubs" / "config.yaml"
        ]
        
        # Load config if file provided or found
        if config_file:
            self.load_config(config_file)
        else:
            self._auto_load_config()
    
    def _auto_load_config(self):
        """Automatically load config from default locations"""
        for path in self.config_paths:
            if path.exists():
                try:
                    self.load_config(str(path))
                    print(f"✅ Loaded config from: {path}")
                    return
                except Exception as e:
                    print(f"⚠️  Failed to load {path}: {e}")
    
    def load_config(self, config_file: str):
        """Load configuration from file"""
        path = Path(config_file)
        
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")
        
        # Determine format from extension
        if path.suffix in ['.yaml', '.yml']:
            self._load_yaml(path)
        elif path.suffix == '.json':
            self._load_json(path)
        else:
            # Try JSON first, then YAML
            try:
                self._load_json(path)
            except:
                self._load_yaml(path)
        
        self.config_file = config_file
    
    def _load_yaml(self, path: Path):
        """Load YAML configuration"""
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                self._apply_config_dict(data)
        except ImportError:
            # Fallback: simple YAML parser for basic configs
            with open(path, 'r', encoding='utf-8') as f:
                data = self._simple_yaml_parse(f.read())
                self._apply_config_dict(data)
    
    def _simple_yaml_parse(self, content: str) -> Dict:
        """Simple YAML parser for basic key-value configs"""
        data = {}
        current_section = None
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Section header
            if line.endswith(':') and not line.startswith(' '):
                current_section = line[:-1]
                data[current_section] = {}
            # Key-value pair
            elif ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                # Parse value type
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value.isdigit():
                    value = int(value)
                elif value.startswith('"') or value.startswith("'"):
                    value = value.strip('"\'')
                
                if current_section:
                    data[current_section][key] = value
                else:
                    data[key] = value
        
        return data
    
    def _load_json(self, path: Path):
        """Load JSON configuration"""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            self._apply_config_dict(data)
    
    def _apply_config_dict(self, data: Dict):
        """Apply configuration dictionary to config object"""
        
        # Parser config
        if 'parser' in data:
            parser_data = data['parser']
            self.config.parser = ParserConfig(**{
                k: v for k, v in parser_data.items()
                if k in ParserConfig.__dataclass_fields__
            })
        
        # Converter config
        if 'converter' in data:
            converter_data = data['converter']
            self.config.converter = ConverterConfig(**{
                k: v for k, v in converter_data.items()
                if k in ConverterConfig.__dataclass_fields__
            })
        
        # Validation config
        if 'validation' in data:
            validation_data = data['validation']
            self.config.validation = ValidationConfig(**{
                k: v for k, v in validation_data.items()
                if k in ValidationConfig.__dataclass_fields__
            })
        
        # Performance config
        if 'performance' in data:
            performance_data = data['performance']
            self.config.performance = PerformanceConfig(**{
                k: v for k, v in performance_data.items()
                if k in PerformanceConfig.__dataclass_fields__
            })
        
        # Output config
        if 'output' in data:
            output_data = data['output']
            self.config.output = OutputConfig(**{
                k: v for k, v in output_data.items()
                if k in OutputConfig.__dataclass_fields__
            })
        
        # Global settings
        if 'log_level' in data:
            self.config.log_level = data['log_level']
        if 'config_version' in data:
            self.config.config_version = data['config_version']
        
        # Load profiles if present
        if 'profiles' in data:
            for profile_name, profile_data in data['profiles'].items():
                self.profiles[profile_name] = self._dict_to_config(profile_data)
    
    def _dict_to_config(self, data: Dict) -> UBSConfig:
        """Convert dictionary to UBSConfig"""
        config = UBSConfig()
        
        if 'parser' in data:
            config.parser = ParserConfig(**data['parser'])
        if 'converter' in data:
            config.converter = ConverterConfig(**data['converter'])
        if 'validation' in data:
            config.validation = ValidationConfig(**data['validation'])
        if 'performance' in data:
            config.performance = PerformanceConfig(**data['performance'])
        if 'output' in data:
            config.output = OutputConfig(**data['output'])
        
        return config
    
    def save_config(self, output_file: Optional[str] = None, format: str = 'yaml'):
        """Save configuration to file"""
        
        output_file = output_file or self.config_file or 'ubs-config.yaml'
        path = Path(output_file)
        
        config_dict = self._config_to_dict()
        
        if format == 'yaml' or path.suffix in ['.yaml', '.yml']:
            self._save_yaml(path, config_dict)
        else:
            self._save_json(path, config_dict)
        
        print(f"✅ Configuration saved to: {output_file}")
    
    def _config_to_dict(self) -> Dict:
        """Convert config to dictionary"""
        return {
            'parser': asdict(self.config.parser),
            'converter': asdict(self.config.converter),
            'validation': asdict(self.config.validation),
            'performance': asdict(self.config.performance),
            'output': asdict(self.config.output),
            'log_level': self.config.log_level,
            'config_version': self.config.config_version,
            'profiles': {
                name: self._config_to_dict_single(cfg)
                for name, cfg in self.profiles.items()
            } if self.profiles else {}
        }
    
    def _config_to_dict_single(self, config: UBSConfig) -> Dict:
        """Convert single config to dict"""
        return {
            'parser': asdict(config.parser),
            'converter': asdict(config.converter),
            'validation': asdict(config.validation),
            'performance': asdict(config.performance),
            'output': asdict(config.output)
        }
    
    def _save_yaml(self, path: Path, data: Dict):
        """Save as YAML"""
        try:
            import yaml
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        except ImportError:
            # Fallback: simple YAML writer
            with open(path, 'w', encoding='utf-8') as f:
                self._simple_yaml_write(f, data)
    
    def _simple_yaml_write(self, f, data: Dict, indent: int = 0):
        """Simple YAML writer"""
        for key, value in data.items():
            if isinstance(value, dict):
                f.write(f"{'  ' * indent}{key}:\n")
                self._simple_yaml_write(f, value, indent + 1)
            elif isinstance(value, bool):
                f.write(f"{'  ' * indent}{key}: {str(value).lower()}\n")
            elif isinstance(value, str):
                f.write(f"{'  ' * indent}{key}: \"{value}\"\n")
            else:
                f.write(f"{'  ' * indent}{key}: {value}\n")
    
    def _save_json(self, path: Path, data: Dict):
        """Save as JSON"""
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def create_profile(self, name: str, config: Optional[UBSConfig] = None):
        """Create a configuration profile"""
        if config is None:
            config = UBSConfig()
        
        self.profiles[name] = config
        print(f"✅ Profile '{name}' created")
    
    def load_profile(self, name: str):
        """Load a configuration profile"""
        if name not in self.profiles:
            raise ValueError(f"Profile '{name}' not found")
        
        self.config = self.profiles[name]
        print(f"✅ Profile '{name}' loaded")
    
    def list_profiles(self):
        """List all available profiles"""
        if not self.profiles:
            print("No profiles available")
            return
        
        print("\n📋 Available Profiles:")
        for name in self.profiles.keys():
            print(f"  - {name}")
    
    def generate_default_config(self, output_file: str = 'ubs-config.yaml'):
        """Generate default configuration file"""
        
        # Create with examples and comments
        if output_file.endswith('.yaml') or output_file.endswith('.yml'):
            self._generate_default_yaml(output_file)
        else:
            self.save_config(output_file, format='json')
    
    def _generate_default_yaml(self, output_file: str):
        """Generate default YAML config with comments"""
        
        yaml_content = """# UBS Configuration File
# Version: 1.0

# Parser Configuration
parser:
  strict_mode: false              # Enable strict parsing rules
  allow_regex: true               # Allow regex patterns
  allow_wildcards: true           # Allow wildcard patterns
  max_pattern_length: 500         # Maximum pattern length
  skip_invalid_rules: false       # Skip invalid rules instead of erroring
  case_sensitive: false           # Case-sensitive domain matching

# Converter Configuration
converter:
  hosts_ip: "0.0.0.0"            # IP address for hosts format
  optimize: true                  # Optimize rules during conversion
  deduplicate: true               # Remove duplicate rules
  sort_rules: true                # Sort rules alphabetically
  include_comments: true          # Include comments in output
  output_encoding: "utf-8"        # Output file encoding

# Validation Configuration
validation:
  check_dns: false                # Check if domains resolve (slower)
  dns_limit: 100                  # Maximum domains to DNS check
  dns_timeout: 5                  # DNS timeout in seconds
  warn_slow_regex: true           # Warn about slow regex patterns
  warn_duplicates: true           # Warn about duplicate rules
  check_conflicts: true           # Check for blacklist/whitelist conflicts
  require_metadata: false         # Require metadata fields

# Performance Configuration
performance:
  use_bloom_filter: true          # Use Bloom filter for fast lookups
  use_trie: true                  # Use Trie for wildcard matching
  cache_regex: true               # Cache compiled regex patterns
  parallel_dns_checks: true       # Parallel DNS checking
  max_workers: 10                 # Max parallel workers

# Output Configuration
output:
  format: "hosts"                 # Default output format
  output_dir: "./output"          # Output directory
  filename_template: "blocklist_{format}.{ext}"  # Filename template
  create_backup: true             # Create backups before overwrite
  backup_dir: "./backups"         # Backup directory

# Global Settings
log_level: "INFO"                 # Log level: DEBUG, INFO, WARNING, ERROR
config_version: "1.0"             # Config file version

# Configuration Profiles
# You can define multiple profiles for different use cases
profiles:
  
  # Production profile - strict and optimized
  production:
    parser:
      strict_mode: true
      skip_invalid_rules: false
    converter:
      optimize: true
      deduplicate: true
    validation:
      check_dns: true
      dns_limit: 500
      require_metadata: true
    performance:
      use_bloom_filter: true
      use_trie: true
      max_workers: 20
  
  # Development profile - permissive and fast
  development:
    parser:
      strict_mode: false
      skip_invalid_rules: true
    converter:
      optimize: false
      deduplicate: false
    validation:
      check_dns: false
      warn_slow_regex: false
    performance:
      use_bloom_filter: false
      use_trie: false
  
  # Testing profile - thorough validation
  testing:
    parser:
      strict_mode: true
    validation:
      check_dns: true
      dns_limit: 1000
      warn_slow_regex: true
      warn_duplicates: true
      check_conflicts: true
    performance:
      parallel_dns_checks: true
      max_workers: 50
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        
        print(f"✅ Default configuration generated: {output_file}")
    
    def print_config(self):
        """Print current configuration"""
        
        print(f"\n{'='*80}")
        print("CURRENT CONFIGURATION")
        print(f"{'='*80}\n")
        
        print("📄 Parser:")
        for key, value in asdict(self.config.parser).items():
            print(f"   {key:25s} = {value}")
        
        print("\n🔄 Converter:")
        for key, value in asdict(self.config.converter).items():
            print(f"   {key:25s} = {value}")
        
        print("\n✅ Validation:")
        for key, value in asdict(self.config.validation).items():
            print(f"   {key:25s} = {value}")
        
        print("\n⚡ Performance:")
        for key, value in asdict(self.config.performance).items():
            print(f"   {key:25s} = {value}")
        
        print("\n📁 Output:")
        for key, value in asdict(self.config.output).items():
            print(f"   {key:25s} = {value}")
        
        print(f"\n🌐 Global:")
        print(f"   log_level                 = {self.config.log_level}")
        print(f"   config_version            = {self.config.config_version}")
        
        if self.profiles:
            print(f"\n📋 Profiles: {', '.join(self.profiles.keys())}")
        
        print(f"\n{'='*80}\n")


# ============================================================================
# CONFIGURATION HELPERS
# ============================================================================

def apply_config_to_parser(parser, config: ParserConfig):
    """Apply configuration to parser"""
    # These would be implemented in the actual parser
    parser.strict_mode = config.strict_mode
    parser.allow_regex = config.allow_regex
    parser.allow_wildcards = config.allow_wildcards
    # etc.


def apply_config_to_validator(validator, config: ValidationConfig):
    """Apply configuration to validator"""
    validator.check_dns = config.check_dns
    validator.dns_limit = config.dns_limit
    # etc.


# ============================================================================
# CLI INTEGRATION
# ============================================================================

def add_config_commands(subparsers):
    """Add configuration commands to CLI"""
    
    # Config show
    config_show_parser = subparsers.add_parser('config-show',
                                               help='Show current configuration')
    config_show_parser.add_argument('--file', help='Config file to load')
    
    # Config init
    config_init_parser = subparsers.add_parser('config-init',
                                              help='Initialize configuration file')
    config_init_parser.add_argument('--output', '-o', default='ubs-config.yaml',
                                   help='Output file')
    config_init_parser.add_argument('--format', choices=['yaml', 'json'],
                                   default='yaml',
                                   help='Config format')
    
    # Config edit
    config_edit_parser = subparsers.add_parser('config-edit',
                                              help='Edit configuration value')
    config_edit_parser.add_argument('key', help='Config key (e.g., parser.strict_mode)')
    config_edit_parser.add_argument('value', help='New value')
    config_edit_parser.add_argument('--file', help='Config file')
    
    # Profile management
    profile_parser = subparsers.add_parser('profile',
                                          help='Manage configuration profiles')
    profile_parser.add_argument('action', choices=['list', 'load', 'create'],
                               help='Profile action')
    profile_parser.add_argument('name', nargs='?', help='Profile name')
    profile_parser.add_argument('--file', help='Config file')


def handle_config_show_command(args):
    """Handle config-show command"""
    
    config_mgr = ConfigManager(args.file if hasattr(args, 'file') and args.file else None)
    config_mgr.print_config()
    
    return 0


def handle_config_init_command(args):
    """Handle config-init command"""
    
    config_mgr = ConfigManager()
    config_mgr.generate_default_config(args.output)
    
    print(f"\n✅ Configuration file created: {args.output}")
    print(f"   Edit this file to customize your UBS settings")
    
    return 0


def handle_config_edit_command(args):
    """Handle config-edit command"""
    
    config_mgr = ConfigManager(args.file)
    
    # Parse key (e.g., "parser.strict_mode")
    parts = args.key.split('.')
    
    if len(parts) != 2:
        print(f"❌ Invalid key format. Use: section.key (e.g., parser.strict_mode)")
        return 1
    
    section, key = parts
    
    # Parse value
    value = args.value
    if value.lower() == 'true':
        value = True
    elif value.lower() == 'false':
        value = False
    elif value.isdigit():
        value = int(value)
    
    # Apply change
    if section == 'parser':
        setattr(config_mgr.config.parser, key, value)
    elif section == 'converter':
        setattr(config_mgr.config.converter, key, value)
    elif section == 'validation':
        setattr(config_mgr.config.validation, key, value)
    elif section == 'performance':
        setattr(config_mgr.config.performance, key, value)
    elif section == 'output':
        setattr(config_mgr.config.output, key, value)
    else:
        print(f"❌ Unknown section: {section}")
        return 1
    
    # Save
    config_mgr.save_config()
    
    print(f"✅ Configuration updated: {args.key} = {value}")
    
    return 0


def handle_profile_command(args):
    """Handle profile command"""
    
    config_mgr = ConfigManager(args.file if hasattr(args, 'file') and args.file else None)
    
    if args.action == 'list':
        config_mgr.list_profiles()
    
    elif args.action == 'load':
        if not args.name:
            print("❌ Profile name required")
            return 1
        
        try:
            config_mgr.load_profile(args.name)
            config_mgr.save_config()
        except ValueError as e:
            print(f"❌ {e}")
            return 1
    
    elif args.action == 'create':
        if not args.name:
            print("❌ Profile name required")
            return 1
        
        config_mgr.create_profile(args.name)
        config_mgr.save_config()
    
    return 0


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    print("=== Configuration System Module Demo ===\n")
    
    # 1. Create configuration manager
    print("1. Configuration Manager:")
    config_mgr = ConfigManager()
    
    # 2. Generate default config
    print("\n2. Generating default configuration:")
    config_mgr.generate_default_config("demo-config.yaml")
    
    # 3. Show current config
    print("\n3. Current Configuration:")
    config_mgr.print_config()
    
    # 4. Create profile
    print("\n4. Creating profiles:")
    prod_config = UBSConfig()
    prod_config.parser.strict_mode = True
    prod_config.validation.check_dns = True
    config_mgr.create_profile("production", prod_config)
    
    dev_config = UBSConfig()
    dev_config.parser.strict_mode = False
    dev_config.validation.check_dns = False
    config_mgr.create_profile("development", dev_config)
    
    # 5. List profiles
    print("\n5. Available Profiles:")
    config_mgr.list_profiles()
    
    # 6. Save config with profiles
    print("\n6. Saving configuration:")
    config_mgr.save_config("demo-config-with-profiles.yaml")
    
    print("\n✅ Configuration System module loaded successfully!")
    print("\nGenerated files:")
    print("  - demo-config.yaml (Default configuration)")
    print("  - demo-config-with-profiles.yaml (With profiles)")
