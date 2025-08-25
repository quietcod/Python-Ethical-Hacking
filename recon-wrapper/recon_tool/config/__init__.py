"""
Configuration Management System
Centralized configuration loading and management
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional

from .defaults import DEFAULT_CONFIG
from .validation import ConfigValidator


class ConfigManager:
    """Central configuration manager"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = DEFAULT_CONFIG.copy()
        self.validator = ConfigValidator()
        
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, config_file: str) -> bool:
        """Load configuration from file"""
        try:
            config_path = Path(config_file)
            if not config_path.exists():
                print(f"⚠️  Config file not found: {config_file}")
                return False
            
            with open(config_path, 'r') as f:
                user_config = json.load(f)
            
            # Validate configuration
            if not self.validator.validate(user_config):
                print(f"⚠️  Invalid configuration format")
                return False
            
            # Merge with defaults
            self._merge_config(self.config, user_config)
            print(f"✅ Configuration loaded from: {config_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error loading config: {str(e)}")
            return False
    
    def _merge_config(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, section: str, key: str = None, default: Any = None) -> Any:
        """Get configuration value"""
        try:
            section_config = self.config.get(section, {})
            if key is None:
                return section_config
            return section_config.get(key, default)
        except:
            return default
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        return self.config.get(section, {})
    
    def set(self, section: str, key: str, value: Any) -> None:
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
    
    def save_config(self, config_file: str) -> bool:
        """Save current configuration to file"""
        try:
            config_path = Path(config_file)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            print(f"✅ Configuration saved to: {config_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error saving config: {str(e)}")
            return False
