"""
Configuration Validation
Validates configuration files and settings
"""

from typing import Dict, Any, List
import ipaddress


class ConfigValidator:
    """Configuration validation class"""
    
    def __init__(self):
        self.required_sections = [
            "general", "scanning", "reporting", "logging"
        ]
        
        self.validation_rules = {
            "general": {
                "timeout": (int, lambda x: x > 0),
                "threads": (int, lambda x: 1 <= x <= 200),
                "rate_limit": (int, lambda x: x > 0)
            },
            "scanning": {
                "nmap": dict,
                "masscan": dict
            },
            "dashboard": {
                "port": (int, lambda x: 1 <= x <= 65535),
                "host": (str, self._validate_ip_or_hostname)
            }
        }
    
    def validate(self, config: Dict[str, Any]) -> bool:
        """Validate configuration dictionary"""
        try:
            # Check required sections
            for section in self.required_sections:
                if section not in config:
                    print(f"❌ Missing required section: {section}")
                    return False
            
            # Validate section contents
            for section, rules in self.validation_rules.items():
                if section in config:
                    if not self._validate_section(config[section], rules, section):
                        return False
            
            return True
            
        except Exception as e:
            print(f"❌ Validation error: {str(e)}")
            return False
    
    def _validate_section(self, section_config: Dict[str, Any], 
                         rules: Dict[str, Any], section_name: str) -> bool:
        """Validate individual section"""
        for key, rule in rules.items():
            if key in section_config:
                value = section_config[key]
                
                if isinstance(rule, tuple):
                    expected_type, validator = rule
                    
                    # Check type
                    if not isinstance(value, expected_type):
                        print(f"❌ {section_name}.{key}: Expected {expected_type.__name__}, got {type(value).__name__}")
                        return False
                    
                    # Check validation function
                    if callable(validator) and not validator(value):
                        print(f"❌ {section_name}.{key}: Value validation failed")
                        return False
                        
                elif isinstance(rule, type):
                    if not isinstance(value, rule):
                        print(f"❌ {section_name}.{key}: Expected {rule.__name__}, got {type(value).__name__}")
                        return False
        
        return True
    
    def _validate_ip_or_hostname(self, value: str) -> bool:
        """Validate IP address or hostname"""
        try:
            # Try to parse as IP address
            ipaddress.ip_address(value)
            return True
        except:
            # Check if it's a valid hostname
            if isinstance(value, str) and len(value) > 0:
                return True
            return False
    
    def get_config_schema(self) -> Dict[str, Any]:
        """Get configuration schema for documentation"""
        return {
            "general": {
                "timeout": "int: Timeout in seconds (>0)",
                "threads": "int: Number of threads (1-200)",
                "rate_limit": "int: Rate limit for requests (>0)",
                "verbose": "bool: Enable verbose output",
                "offline_mode": "bool: Run in offline mode"
            },
            "scanning": {
                "nmap": "dict: Nmap-specific settings",
                "masscan": "dict: Masscan-specific settings"
            },
            "dashboard": {
                "port": "int: Dashboard port (1-65535)",
                "host": "str: Dashboard host IP or hostname"
            }
        }
