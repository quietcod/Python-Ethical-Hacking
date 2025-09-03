"""
Configuration Management System v2.0
Enhanced configuration with validation, merging, environment variables, and schema validation
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional

from .defaults import DEFAULT_CONFIG
from .validation import ConfigValidator

# Import enhanced configuration manager
try:
    from .enhanced_config import (
        EnhancedConfigManager, 
        ConfigurationSchema,
        ConfigFormat,
        ConfigSource,
        EnvironmentMapping,
        create_config_manager,
        get_global_config,
        set_global_config
    )
    ENHANCED_CONFIG_AVAILABLE = True
except ImportError as e:
    ENHANCED_CONFIG_AVAILABLE = False
    print(f"⚠️  Enhanced configuration not available: {e}")


class ConfigManager:
    """
    Legacy configuration manager with enhanced features fallback
    
    This class provides backward compatibility while offering enhanced
    features when available. Use EnhancedConfigManager directly for
    full feature access.
    """
    
    def __init__(self, config_file: Optional[str] = None, use_enhanced: bool = True):
        """
        Initialize configuration manager
        
        Args:
            config_file: Configuration file path
            use_enhanced: Whether to use enhanced config manager if available
        """
        self.use_enhanced = use_enhanced and ENHANCED_CONFIG_AVAILABLE
        
        if self.use_enhanced:
            # Use enhanced configuration manager
            self._enhanced_manager = EnhancedConfigManager(
                config_file=config_file,
                load_defaults=True,
                load_environment=True,
                validate_schema=True
            )
            self.config = self._enhanced_manager.merged_config
        else:
            # Fall back to legacy implementation
            self.config = DEFAULT_CONFIG.copy()
            self.validator = ConfigValidator()
            
            if config_file:
                self.load_config(config_file)
    
    def load_config(self, config_file: str) -> bool:
        """Load configuration from file"""
        if self.use_enhanced:
            return self._enhanced_manager.load_config_file(config_file)
        
        # Legacy implementation
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
        if self.use_enhanced:
            if key is None:
                return self._enhanced_manager.get_section(section)
            else:
                return self._enhanced_manager.get(f"{section}.{key}", default)
        
        # Legacy implementation
        try:
            section_config = self.config.get(section, {})
            if key is None:
                return section_config
            return section_config.get(key, default)
        except:
            return default
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        if self.use_enhanced:
            return self._enhanced_manager.get_section(section)
        
        return self.config.get(section, {})
    
    def set(self, section: str, key: str, value: Any) -> None:
        """Set configuration value"""
        if self.use_enhanced:
            self._enhanced_manager.set(f"{section}.{key}", value)
            self.config = self._enhanced_manager.merged_config
        else:
            # Legacy implementation
            if section not in self.config:
                self.config[section] = {}
            self.config[section][key] = value
    
    def save_config(self, config_file: str) -> bool:
        """Save current configuration to file"""
        if self.use_enhanced:
            return self._enhanced_manager.save_config(config_file, ConfigFormat.JSON)
        
        # Legacy implementation
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
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Validate current configuration"""
        if self.use_enhanced:
            return self._enhanced_manager.validate_configuration()
        
        # Basic validation for legacy
        return {
            'valid': self.validator.validate(self.config) if hasattr(self, 'validator') else True,
            'errors': [],
            'warnings': [],
            'enhanced_features': False
        }
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary"""
        if self.use_enhanced:
            summary = self._enhanced_manager.get_config_summary()
            summary['enhanced_features'] = True
            return summary
        
        return {
            'enhanced_features': False,
            'sections': list(self.config.keys()),
            'total_config_keys': len(self._flatten_dict(self.config)),
            'validation_enabled': hasattr(self, 'validator')
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
    
    @property
    def enhanced_manager(self) -> Optional['EnhancedConfigManager']:
        """Get access to enhanced manager if available"""
        return getattr(self, '_enhanced_manager', None)
