"""
Enhanced Configuration Management System v2.0
Comprehensive configuration with validation, merging, environment variables, and schema validation
"""

import json
import os
import yaml
import toml
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Type, Tuple
from dataclasses import dataclass, field
from enum import Enum
import jsonschema
from jsonschema import validate, ValidationError as JsonSchemaValidationError
import logging
from copy import deepcopy
import re
import socket

from ..core.exceptions import ConfigurationError, ValidationError


class ConfigFormat(Enum):
    """Supported configuration formats"""
    JSON = "json"
    YAML = "yaml"
    YML = "yml"
    TOML = "toml"
    INI = "ini"


@dataclass
class ConfigSource:
    """Configuration source information"""
    name: str
    path: Optional[str] = None
    priority: int = 0  # Higher number = higher priority
    format: Optional[ConfigFormat] = None
    loaded: bool = False
    error: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnvironmentMapping:
    """Environment variable mapping configuration"""
    env_var: str
    config_path: str
    value_type: Type = str
    default: Any = None
    required: bool = False
    description: str = ""


class ConfigurationSchema:
    """Configuration schema definition and validation"""
    
    SCHEMA = {
        "type": "object",
        "properties": {
            "general": {
                "type": "object",
                "properties": {
                    "version": {"type": "string", "pattern": r"^\d+\.\d+(\.\d+)?$"},
                    "timeout": {"type": "integer", "minimum": 1, "maximum": 3600},
                    "threads": {"type": "integer", "minimum": 1, "maximum": 500},
                    "rate_limit": {"type": "integer", "minimum": 1},
                    "verbose": {"type": "boolean"},
                    "offline_mode": {"type": "boolean"},
                    "light_mode": {"type": "boolean"},
                    "output_format": {"type": "string", "enum": ["json", "yaml", "xml", "csv"]},
                    "save_raw_output": {"type": "boolean"},
                    "working_directory": {"type": "string"},
                    "temp_directory": {"type": "string"}
                },
                "required": ["version", "timeout", "threads"],
                "additionalProperties": True
            },
            "scanning": {
                "type": "object",
                "properties": {
                    "nmap": {
                        "type": "object",
                        "properties": {
                            "basic_flags": {"type": "string"},
                            "aggressive_flags": {"type": "string"},
                            "timeout": {"type": "integer", "minimum": 1},
                            "max_ports": {"type": "integer", "minimum": 1, "maximum": 65535},
                            "output_format": {"type": "string", "enum": ["xml", "json", "text"]},
                            "timing_template": {"type": "integer", "minimum": 0, "maximum": 5}
                        },
                        "additionalProperties": True
                    },
                    "masscan": {
                        "type": "object",
                        "properties": {
                            "rate": {"type": "integer", "minimum": 1},
                            "timeout": {"type": "integer", "minimum": 1},
                            "max_rate": {"type": "integer", "minimum": 1}
                        },
                        "additionalProperties": True
                    }
                },
                "additionalProperties": True
            },
            "reporting": {
                "type": "object",
                "properties": {
                    "generate_html": {"type": "boolean"},
                    "generate_json": {"type": "boolean"},
                    "generate_csv": {"type": "boolean"},
                    "generate_pdf": {"type": "boolean"},
                    "include_screenshots": {"type": "boolean"},
                    "risk_scoring": {"type": "boolean"},
                    "compliance_mapping": {"type": "boolean"},
                    "template_directory": {"type": "string"},
                    "output_directory": {"type": "string"}
                },
                "additionalProperties": True
            },
            "logging": {
                "type": "object",
                "properties": {
                    "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
                    "file_logging": {"type": "boolean"},
                    "console_logging": {"type": "boolean"},
                    "max_file_size": {"type": "string"},
                    "backup_count": {"type": "integer", "minimum": 1},
                    "log_directory": {"type": "string"},
                    "format": {"type": "string"},
                    "json_format": {"type": "boolean"}
                },
                "additionalProperties": True
            },
            "dashboard": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean"},
                    "host": {"type": "string"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "debug": {"type": "boolean"},
                    "auto_refresh": {"type": "integer", "minimum": 1},
                    "enable_websockets": {"type": "boolean"},
                    "ssl_enabled": {"type": "boolean"},
                    "ssl_cert": {"type": "string"},
                    "ssl_key": {"type": "string"}
                },
                "additionalProperties": True
            },
            "api": {
                "type": "object",
                "properties": {
                    "shodan_api_key": {"type": ["string", "null"]},
                    "censys_api_id": {"type": ["string", "null"]},
                    "censys_api_secret": {"type": ["string", "null"]},
                    "virustotal_api_key": {"type": ["string", "null"]},
                    "github_token": {"type": ["string", "null"]},
                    "rate_limits": {
                        "type": "object",
                        "patternProperties": {
                            ".*": {"type": "integer", "minimum": 1}
                        }
                    }
                },
                "additionalProperties": True
            },
            "network": {
                "type": "object",
                "properties": {
                    "proxy": {
                        "type": ["object", "null"],
                        "properties": {
                            "http": {"type": "string"},
                            "https": {"type": "string"},
                            "socks": {"type": "string"}
                        }
                    },
                    "user_agent": {"type": "string"},
                    "timeout": {"type": "integer", "minimum": 1},
                    "retries": {"type": "integer", "minimum": 0},
                    "verify_ssl": {"type": "boolean"}
                },
                "additionalProperties": True
            }
        },
        "required": ["general"],
        "additionalProperties": True
    }
    
    def validate(self, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate configuration against schema
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        try:
            from jsonschema import validate, ValidationError, draft7_format_checker
            
            # Validate against schema
            validate(config, self.SCHEMA, format_checker=draft7_format_checker)
            return True, []
            
        except ValidationError as e:
            return False, [str(e)]
        except Exception as e:
            return False, [f"Schema validation error: {str(e)}"]
    
    def get_schema(self) -> Dict[str, Any]:
        """Get the JSON schema"""
        return self.SCHEMA.copy()
    
    @classmethod
    def validate_config(cls, config: Dict[str, Any]) -> None:
        """Validate configuration against schema"""
        try:
            validate(instance=config, schema=cls.SCHEMA)
        except JsonSchemaValidationError as e:
            raise ValidationError(f"Configuration validation failed: {e.message}")
    
    @classmethod
    def get_schema_documentation(cls) -> Dict[str, Any]:
        """Generate human-readable schema documentation"""
        return {
            "description": "ReconTool v2.0 Configuration Schema",
            "version": "2.0",
            "sections": {
                "general": "General application settings",
                "scanning": "Scanning tool configurations",
                "reporting": "Report generation settings",
                "logging": "Logging and monitoring configuration",
                "dashboard": "Web dashboard settings",
                "api": "External API configurations",
                "network": "Network and proxy settings"
            },
            "required_sections": ["general"],
            "schema": cls.SCHEMA
        }


class EnhancedConfigManager:
    """Enhanced configuration manager with comprehensive features"""
    
    def __init__(self, config_file: Optional[str] = None, 
                 load_defaults: bool = True,
                 load_environment: bool = True,
                 validate_schema: bool = True):
        """
        Initialize enhanced configuration manager
        
        Args:
            config_file: Primary configuration file path
            load_defaults: Whether to load default configuration
            load_environment: Whether to load environment variables
            validate_schema: Whether to validate against schema
        """
        self.logger = logging.getLogger(__name__)
        self.validate_schema = validate_schema
        
        # Configuration sources (ordered by priority)
        self.sources: List[ConfigSource] = []
        self.merged_config: Dict[str, Any] = {}
        
        # Environment variable mappings
        self.env_mappings = self._define_environment_mappings()
        
        # Initialize configuration
        if load_defaults:
            self._load_default_config()
        
        if config_file:
            self.load_config_file(config_file)
        
        if load_environment:
            self._load_environment_variables()
        
        # Merge all sources
        self._merge_all_sources()
        
        # Validate final configuration
        if self.validate_schema:
            self._validate_final_config()
    
    def _define_environment_mappings(self) -> List[EnvironmentMapping]:
        """Define environment variable mappings"""
        return [
            # General settings
            EnvironmentMapping("RECON_TIMEOUT", "general.timeout", int, 300),
            EnvironmentMapping("RECON_THREADS", "general.threads", int, 20),
            EnvironmentMapping("RECON_VERBOSE", "general.verbose", bool, False),
            EnvironmentMapping("RECON_OUTPUT_FORMAT", "general.output_format", str, "json"),
            EnvironmentMapping("RECON_WORKING_DIR", "general.working_directory", str),
            
            # API Keys
            EnvironmentMapping("SHODAN_API_KEY", "api.shodan_api_key", str),
            EnvironmentMapping("CENSYS_API_ID", "api.censys_api_id", str),
            EnvironmentMapping("CENSYS_API_SECRET", "api.censys_api_secret", str),
            EnvironmentMapping("VIRUSTOTAL_API_KEY", "api.virustotal_api_key", str),
            EnvironmentMapping("GITHUB_TOKEN", "api.github_token", str),
            
            # Network settings
            EnvironmentMapping("HTTP_PROXY", "network.proxy.http", str),
            EnvironmentMapping("HTTPS_PROXY", "network.proxy.https", str),
            EnvironmentMapping("RECON_USER_AGENT", "network.user_agent", str),
            EnvironmentMapping("RECON_VERIFY_SSL", "network.verify_ssl", bool, True),
            
            # Dashboard settings
            EnvironmentMapping("RECON_DASHBOARD_HOST", "dashboard.host", str, "127.0.0.1"),
            EnvironmentMapping("RECON_DASHBOARD_PORT", "dashboard.port", int, 8080),
            EnvironmentMapping("RECON_DASHBOARD_DEBUG", "dashboard.debug", bool, False),
            
            # Logging settings
            EnvironmentMapping("RECON_LOG_LEVEL", "logging.level", str, "INFO"),
            EnvironmentMapping("RECON_LOG_DIR", "logging.log_directory", str),
            EnvironmentMapping("RECON_LOG_FORMAT", "logging.format", str),
            
            # Tool-specific settings
            EnvironmentMapping("NMAP_TIMEOUT", "scanning.nmap.timeout", int, 600),
            EnvironmentMapping("MASSCAN_RATE", "scanning.masscan.rate", int, 1000),
            
            # Reporting settings
            EnvironmentMapping("RECON_OUTPUT_DIR", "reporting.output_directory", str),
            EnvironmentMapping("RECON_GENERATE_PDF", "reporting.generate_pdf", bool, False),
        ]
    
    def _load_default_config(self) -> None:
        """Load default configuration"""
        try:
            from .defaults import DEFAULT_CONFIG
            
            source = ConfigSource(
                name="defaults",
                priority=0,
                loaded=True,
                data=deepcopy(DEFAULT_CONFIG)
            )
            self.sources.append(source)
            self.logger.debug("Default configuration loaded")
            
        except ImportError as e:
            self.logger.warning(f"Could not load default configuration: {e}")
    
    def load_config_file(self, config_file: str, priority: int = 100) -> bool:
        """
        Load configuration from file with format auto-detection
        
        Args:
            config_file: Path to configuration file
            priority: Priority of this source (higher = more important)
            
        Returns:
            bool: True if loaded successfully
        """
        config_path = Path(config_file)
        
        if not config_path.exists():
            error = f"Configuration file not found: {config_file}"
            self.logger.warning(error)
            source = ConfigSource(
                name=f"file:{config_file}",
                path=config_file,
                priority=priority,
                loaded=False,
                error=error
            )
            self.sources.append(source)
            return False
        
        # Detect format
        format_type = self._detect_config_format(config_path)
        
        try:
            # Load based on format
            if format_type == ConfigFormat.JSON:
                data = self._load_json_config(config_path)
            elif format_type in [ConfigFormat.YAML, ConfigFormat.YML]:
                data = self._load_yaml_config(config_path)
            elif format_type == ConfigFormat.TOML:
                data = self._load_toml_config(config_path)
            else:
                raise ConfigurationError(f"Unsupported configuration format: {format_type}")
            
            source = ConfigSource(
                name=f"file:{config_file}",
                path=config_file,
                priority=priority,
                format=format_type,
                loaded=True,
                data=data
            )
            self.sources.append(source)
            
            self.logger.info(f"✅ Configuration loaded from: {config_file} (format: {format_type.value})")
            return True
            
        except Exception as e:
            error = f"Error loading config file {config_file}: {str(e)}"
            self.logger.error(error)
            source = ConfigSource(
                name=f"file:{config_file}",
                path=config_file,
                priority=priority,
                format=format_type,
                loaded=False,
                error=error
            )
            self.sources.append(source)
            return False
    
    def _detect_config_format(self, config_path: Path) -> ConfigFormat:
        """Detect configuration file format"""
        suffix = config_path.suffix.lower()
        
        if suffix == '.json':
            return ConfigFormat.JSON
        elif suffix in ['.yaml', '.yml']:
            return ConfigFormat.YAML
        elif suffix == '.toml':
            return ConfigFormat.TOML
        else:
            # Try to detect by content
            try:
                with open(config_path, 'r') as f:
                    content = f.read().strip()
                
                # Try JSON first
                try:
                    json.loads(content)
                    return ConfigFormat.JSON
                except:
                    pass
                
                # Try YAML
                try:
                    yaml.safe_load(content)
                    return ConfigFormat.YAML
                except:
                    pass
                
                # Try TOML
                try:
                    toml.loads(content)
                    return ConfigFormat.TOML
                except:
                    pass
                
            except Exception:
                pass
        
        # Default to JSON
        return ConfigFormat.JSON
    
    def _load_json_config(self, config_path: Path) -> Dict[str, Any]:
        """Load JSON configuration"""
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def _load_yaml_config(self, config_path: Path) -> Dict[str, Any]:
        """Load YAML configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except ImportError:
            raise ConfigurationError("PyYAML not installed. Install with: pip install PyYAML")
    
    def _load_toml_config(self, config_path: Path) -> Dict[str, Any]:
        """Load TOML configuration"""
        try:
            return toml.load(config_path)
        except ImportError:
            raise ConfigurationError("toml not installed. Install with: pip install toml")
    
    def _load_environment_variables(self) -> None:
        """Load configuration from environment variables"""
        env_data = {}
        loaded_vars = []
        
        for mapping in self.env_mappings:
            env_value = os.getenv(mapping.env_var)
            
            if env_value is not None:
                try:
                    # Convert to appropriate type
                    if mapping.value_type == bool:
                        parsed_value = env_value.lower() in ('true', '1', 'yes', 'on')
                    elif mapping.value_type == int:
                        parsed_value = int(env_value)
                    elif mapping.value_type == float:
                        parsed_value = float(env_value)
                    else:
                        parsed_value = env_value
                    
                    # Set in nested dictionary
                    self._set_nested_value(env_data, mapping.config_path, parsed_value)
                    loaded_vars.append(f"{mapping.env_var} -> {mapping.config_path}")
                    
                except (ValueError, TypeError) as e:
                    self.logger.warning(f"Invalid environment variable value {mapping.env_var}={env_value}: {e}")
            
            elif mapping.required:
                self.logger.warning(f"Required environment variable not set: {mapping.env_var}")
        
        if env_data:
            source = ConfigSource(
                name="environment",
                priority=200,  # Higher priority than files
                loaded=True,
                data=env_data
            )
            self.sources.append(source)
            self.logger.info(f"✅ Loaded {len(loaded_vars)} environment variables")
            self.logger.debug(f"Environment variables: {loaded_vars}")
    
    def _set_nested_value(self, data: Dict[str, Any], path: str, value: Any) -> None:
        """Set value in nested dictionary using dot notation"""
        keys = path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def add_config_source(self, name: str, data: Dict[str, Any], priority: int = 50) -> None:
        """Add custom configuration source"""
        source = ConfigSource(
            name=name,
            priority=priority,
            loaded=True,
            data=deepcopy(data)
        )
        self.sources.append(source)
        
        # Re-merge all sources
        self._merge_all_sources()
        
        if self.validate_schema:
            self._validate_final_config()
    
    def _merge_all_sources(self) -> None:
        """Merge all configuration sources by priority"""
        # Sort sources by priority (lowest to highest)
        sorted_sources = sorted(self.sources, key=lambda s: s.priority)
        
        merged = {}
        for source in sorted_sources:
            if source.loaded:
                self._deep_merge(merged, source.data)
        
        self.merged_config = merged
        self.logger.debug(f"Merged configuration from {len([s for s in self.sources if s.loaded])} sources")
    
    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        """Deep merge two dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _validate_final_config(self) -> None:
        """Validate final merged configuration"""
        try:
            schema = ConfigurationSchema()
            is_valid, errors = schema.validate(self.merged_config)
            if not is_valid:
                error_msg = f"Configuration validation failed: {'; '.join(errors)}"
                self.logger.error(error_msg)
                raise ValueError(error_msg)
            self.logger.debug("Configuration validation passed")
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
            raise
    
    def get(self, path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            path: Configuration path (e.g., 'general.timeout')
            default: Default value if not found
            
        Returns:
            Configuration value
        """
        try:
            keys = path.split('.')
            current = self.merged_config
            
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return default
            
            return current
            
        except Exception:
            return default
    
    def set(self, path: str, value: Any, source_name: str = "runtime") -> None:
        """
        Set configuration value using dot notation
        
        Args:
            path: Configuration path (e.g., 'general.timeout')
            value: Value to set
            source_name: Name of the source setting this value
        """
        # Update or create runtime source
        runtime_source = None
        for source in self.sources:
            if source.name == source_name:
                runtime_source = source
                break
        
        if runtime_source is None:
            runtime_source = ConfigSource(
                name=source_name,
                priority=300,  # High priority for runtime changes
                loaded=True,
                data={}
            )
            self.sources.append(runtime_source)
        
        self._set_nested_value(runtime_source.data, path, value)
        
        # Re-merge
        self._merge_all_sources()
        
        if self.validate_schema:
            try:
                self._validate_final_config()
            except ValidationError as e:
                # Rollback the change
                self._remove_nested_value(runtime_source.data, path)
                self._merge_all_sources()
                raise ConfigurationError(f"Invalid configuration value: {e}")
    
    def _remove_nested_value(self, data: Dict[str, Any], path: str) -> None:
        """Remove value from nested dictionary"""
        keys = path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                return
            current = current[key]
        
        if keys[-1] in current:
            del current[keys[-1]]
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        return self.get(section, {})
    
    def has_section(self, section: str) -> bool:
        """Check if configuration section exists"""
        return section in self.merged_config
    
    def has_key(self, path: str) -> bool:
        """Check if configuration key exists"""
        return self.get(path) is not None
    
    def save_config(self, config_file: str, format_type: ConfigFormat = ConfigFormat.JSON,
                   include_sources: bool = False) -> bool:
        """
        Save current configuration to file
        
        Args:
            config_file: Path to save configuration
            format_type: Output format
            include_sources: Whether to include source information
            
        Returns:
            bool: True if saved successfully
        """
        try:
            config_path = Path(config_file)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            output_data = deepcopy(self.merged_config)
            
            if include_sources:
                output_data['_metadata'] = {
                    'sources': [
                        {
                            'name': s.name,
                            'path': s.path,
                            'priority': s.priority,
                            'loaded': s.loaded,
                            'format': s.format.value if s.format else None,
                            'error': s.error
                        }
                        for s in self.sources
                    ],
                    'environment_mappings': [
                        {
                            'env_var': m.env_var,
                            'config_path': m.config_path,
                            'type': m.value_type.__name__,
                            'description': m.description
                        }
                        for m in self.env_mappings
                    ]
                }
            
            with open(config_path, 'w') as f:
                if format_type == ConfigFormat.JSON:
                    json.dump(output_data, f, indent=2, default=str)
                elif format_type in [ConfigFormat.YAML, ConfigFormat.YML]:
                    yaml.dump(output_data, f, default_flow_style=False, indent=2)
                elif format_type == ConfigFormat.TOML:
                    toml.dump(output_data, f)
                else:
                    raise ConfigurationError(f"Unsupported output format: {format_type}")
            
            self.logger.info(f"✅ Configuration saved to: {config_file}")
            return True
            
        except Exception as e:
            error = f"Error saving configuration: {str(e)}"
            self.logger.error(error)
            return False
    
    def export_schema(self, schema_file: str) -> bool:
        """Export configuration schema documentation"""
        try:
            schema_path = Path(schema_file)
            schema_path.parent.mkdir(parents=True, exist_ok=True)
            
            schema_doc = ConfigurationSchema.get_schema_documentation()
            
            with open(schema_path, 'w') as f:
                json.dump(schema_doc, f, indent=2)
            
            self.logger.info(f"✅ Configuration schema exported to: {schema_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting schema: {str(e)}")
            return False
    
    def get_environment_variables_help(self) -> List[Dict[str, str]]:
        """Get help information for environment variables"""
        return [
            {
                'env_var': m.env_var,
                'config_path': m.config_path,
                'type': m.value_type.__name__,
                'default': str(m.default) if m.default is not None else 'None',
                'required': str(m.required),
                'description': m.description or f"Maps to {m.config_path}"
            }
            for m in self.env_mappings
        ]
    
    def validate_configuration(self) -> Dict[str, Any]:
        """
        Comprehensive configuration validation
        
        Returns:
            Dict with validation results
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'sources': [],
            'environment_status': {},
            'schema_validation': {'valid': True, 'errors': []}
        }
        
        # Validate sources
        for source in self.sources:
            source_info = {
                'name': source.name,
                'loaded': source.loaded,
                'priority': source.priority,
                'error': source.error
            }
            
            if source.error:
                results['errors'].append(f"Source '{source.name}': {source.error}")
                results['valid'] = False
            
            results['sources'].append(source_info)
        
        # Check environment variables
        for mapping in self.env_mappings:
            env_value = os.getenv(mapping.env_var)
            status = {
                'set': env_value is not None,
                'required': mapping.required,
                'value_type': mapping.value_type.__name__
            }
            
            if mapping.required and env_value is None:
                results['warnings'].append(f"Required environment variable not set: {mapping.env_var}")
            
            results['environment_status'][mapping.env_var] = status
        
        # Schema validation
        try:
            schema = ConfigurationSchema()
            is_valid, errors = schema.validate(self.merged_config)
            if not is_valid:
                results['schema_validation']['valid'] = False
                results['schema_validation']['errors'].extend(errors)
                results['valid'] = False
        except Exception as e:
            results['schema_validation']['valid'] = False
            results['schema_validation']['errors'].append(f"Schema validation error: {str(e)}")
            results['valid'] = False
        
        # Add summary
        if results['valid']:
            results['summary'] = "Configuration validation passed"
        else:
            results['summary'] = f"Configuration validation failed with {len(results['errors'])} errors"
        
        return results
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get summary of current configuration"""
        return {
            'sources_loaded': len([s for s in self.sources if s.loaded]),
            'sources_failed': len([s for s in self.sources if not s.loaded]),
            'environment_vars_loaded': len([m for m in self.env_mappings if os.getenv(m.env_var) is not None]),
            'total_config_keys': len(self._flatten_dict(self.merged_config)),
            'sections': list(self.merged_config.keys()),
            'validation_enabled': self.validate_schema
        }
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    
    def reload_configuration(self) -> bool:
        """Reload all configuration sources"""
        try:
            # Clear current sources
            file_sources = [(s.path, s.priority) for s in self.sources if s.path]
            self.sources.clear()
            self.merged_config.clear()
            
            # Reload defaults
            self._load_default_config()
            
            # Reload file sources
            for file_path, priority in file_sources:
                self.load_config_file(file_path, priority)
            
            # Reload environment variables
            self._load_environment_variables()
            
            # Merge and validate
            self._merge_all_sources()
            
            if self.validate_schema:
                self._validate_final_config()
            
            self.logger.info("✅ Configuration reloaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error reloading configuration: {str(e)}")
            return False
    
    def list_environment_variables(self) -> List[Dict[str, Any]]:
        """
        List all loaded environment variables with their values
        
        Returns:
            List of environment variable information
        """
        env_vars = []
        for mapping in self.env_mappings:
            env_value = os.getenv(mapping.env_var)
            if env_value is not None:
                env_vars.append({
                    'name': mapping.env_var,
                    'value': env_value,
                    'config_path': mapping.config_path,
                    'type': mapping.value_type.__name__,
                    'description': mapping.description
                })
        return env_vars
    
    def get_config_sources(self) -> Dict[ConfigSource, int]:
        """
        Get count of configuration keys by source
        
        Returns:
            Dictionary mapping source types to key counts
        """
        source_counts = {}
        
        # Count by source type
        for source in self.sources:
            if source.loaded and source.config:
                key_count = len(self._flatten_dict(source.config))
                source_type = self._get_source_type(source)
                source_counts[source_type] = source_counts.get(source_type, 0) + key_count
        
        return source_counts
    
    def _get_source_type(self, source) -> ConfigSource:
        """Determine source type from ConfigSource object"""
        if source.name == 'defaults':
            return ConfigSource.DEFAULTS
        elif source.name == 'environment':
            return ConfigSource.ENVIRONMENT
        elif source.name == 'runtime':
            return ConfigSource.RUNTIME
        else:
            return ConfigSource.FILE
    
    def export_config(self, include_defaults: bool = True) -> Dict[str, Any]:
        """
        Export current configuration
        
        Args:
            include_defaults: Whether to include default values
            
        Returns:
            Configuration dictionary
        """
        if include_defaults:
            return self.merged_config.copy()
        else:
            # Export only non-default values
            exported = {}
            defaults = self._get_defaults_config()
            
            for key, value in self.merged_config.items():
                if key not in defaults or defaults[key] != value:
                    exported[key] = value
            
            return exported
    
    def _get_defaults_config(self) -> Dict[str, Any]:
        """Get defaults configuration"""
        for source in self.sources:
            if source.name == 'defaults' and source.loaded:
                return source.config
        return {}
    
    @classmethod
    def detect_config_format(cls, file_path: str) -> ConfigFormat:
        """
        Detect configuration file format from file extension
        
        Args:
            file_path: Path to configuration file
            
        Returns:
            Detected ConfigFormat
        """
        path = Path(file_path)
        extension = path.suffix.lower()
        
        if extension in ['.json']:
            return ConfigFormat.JSON
        elif extension in ['.yaml', '.yml']:
            return ConfigFormat.YAML
        elif extension in ['.toml']:
            return ConfigFormat.TOML
        else:
            # Default to JSON for unknown extensions
            return ConfigFormat.JSON


# Convenience function for creating enhanced config manager
def create_config_manager(config_file: Optional[str] = None, **kwargs) -> EnhancedConfigManager:
    """Create enhanced configuration manager with defaults"""
    return EnhancedConfigManager(config_file=config_file, **kwargs)


# Global configuration instance (optional)
_global_config: Optional[EnhancedConfigManager] = None


def get_global_config() -> EnhancedConfigManager:
    """Get global configuration instance"""
    global _global_config
    if _global_config is None:
        _global_config = EnhancedConfigManager()
    return _global_config


def set_global_config(config: EnhancedConfigManager) -> None:
    """Set global configuration instance"""
    global _global_config
    _global_config = config
