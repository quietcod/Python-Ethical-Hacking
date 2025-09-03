#!/usr/bin/env python3
"""
Configuration Management - Clean Architecture
Centralized configuration loading and management
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from files and environment"""
    
    # Default configuration
    config = {
        'app': {
            'name': 'recon-tool-v3',
            'version': '3.0.0',
            'description': 'Professional reconnaissance toolkit'
        },
        'scanning': {
            'default_timeout': 300,
            'max_concurrent_tools': 5,
            'output_directory': './results',
            'default_format': 'json'
        },
        'logging': {
            'level': 'INFO',
            'file_logging': True,
            'console_logging': True,
            'log_directory': './logs'
        },
        'tools': {
            'install_missing': False,
            'verify_installation': True,
            'tool_timeout': 120
        },
        'security': {
            'validate_targets': True,
            'sanitize_inputs': True,
            'max_target_length': 253
        }
    }
    
    # Load from configuration files
    config_dir = Path('config')
    
    # Load defaults.json
    defaults_file = config_dir / 'defaults.json'
    if defaults_file.exists():
        try:
            with open(defaults_file, 'r') as f:
                file_config = json.load(f)
                config = merge_configs(config, file_config)
        except Exception as e:
            print(f"Warning: Failed to load {defaults_file}: {e}")
    
    # Override with environment variables
    config = apply_env_overrides(config)
    
    return config

def merge_configs(base_config: Dict, override_config: Dict) -> Dict:
    """Merge two configuration dictionaries"""
    result = base_config.copy()
    
    for key, value in override_config.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
    
    return result

def apply_env_overrides(config: Dict) -> Dict:
    """Apply environment variable overrides to configuration"""
    
    # Mapping of environment variables to config paths
    env_mappings = {
        'RECON_LOG_LEVEL': ['logging', 'level'],
        'RECON_OUTPUT_DIR': ['scanning', 'output_directory'],
        'RECON_TIMEOUT': ['scanning', 'default_timeout']
    }
    
    for env_var, config_path in env_mappings.items():
        env_value = os.getenv(env_var)
        if env_value:
            # Navigate to the config location
            current = config
            for key in config_path[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            
            # Set the value
            final_key = config_path[-1]
            if env_var == 'RECON_TIMEOUT':
                try:
                    current[final_key] = int(env_value)
                except ValueError:
                    print(f"Warning: Invalid timeout value: {env_value}")
            else:
                current[final_key] = env_value
    
    return config

def get_default_config():
    """Get default configuration"""
    return load_config()

class ConfigManager:
    """Enhanced configuration management"""
    
    def __init__(self, config_path=None):
        self.config = load_config(config_path)
    
    def get_tool_config(self, tool_name):
        """Get tool-specific configuration"""
        tool_configs = self.config.get('tool_configs', {})
        return tool_configs.get(tool_name, {})
    
    def get_scan_profile(self, profile_name):
        """Get predefined scan profile"""
        profiles = self.config.get('scan_profiles', {})
        return profiles.get(profile_name, {})
    
    def validate_config(self):
        """Validate configuration integrity"""
        required_sections = ['app', 'scanning', 'logging', 'tools']
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing config section: {section}")
        return True
