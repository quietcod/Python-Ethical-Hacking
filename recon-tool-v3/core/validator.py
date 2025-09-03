#!/usr/bin/env python3
"""
Input Validator - Clean Architecture
Validation of targets, configurations, and user inputs
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Optional

class TargetValidator:
    """Validates and normalizes reconnaissance targets"""
    
    def __init__(self):
        self.domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
    
    def validate_target(self, target: str) -> str:
        """Validate and normalize target input"""
        if not target or not target.strip():
            raise ValueError("Target cannot be empty")
        
        target = target.strip()
        
        # Check if it's a URL
        if target.startswith(('http://', 'https://')):
            return self._validate_url(target)
        
        # Check if it's an IP address
        if self._is_ip_address(target):
            return self._validate_ip(target)
        
        # Assume it's a domain name
        return self._validate_domain(target)
    
    def _validate_url(self, url: str) -> str:
        """Validate URL and extract domain"""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                raise ValueError("Invalid URL format")
            
            # Extract domain from URL
            domain = parsed.netloc.split(':')[0]  # Remove port if present
            return self._validate_domain(domain)
            
        except Exception as e:
            raise ValueError(f"Invalid URL: {e}")
    
    def _validate_ip(self, ip: str) -> str:
        """Validate IP address"""
        try:
            # This will raise an exception if invalid
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")
    
    def _validate_domain(self, domain: str) -> str:
        """Validate domain name"""
        if not domain:
            raise ValueError("Domain cannot be empty")
        
        # Check length
        if len(domain) > 253:
            raise ValueError("Domain name too long")
        
        # Check format using regex
        if not self.domain_pattern.match(domain):
            raise ValueError(f"Invalid domain format: {domain}")
        
        # Additional checks
        if domain.startswith('-') or domain.endswith('-'):
            raise ValueError("Domain cannot start or end with hyphen")
        
        if '..' in domain:
            raise ValueError("Domain cannot contain consecutive dots")
        
        return domain.lower()
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target looks like an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def get_target_type(self, target: str) -> str:
        """Determine the type of target"""
        if self._is_ip_address(target):
            return 'ip'
        elif target.startswith(('http://', 'https://')):
            return 'url'
        else:
            return 'domain'

class ConfigValidator:
    """Validates configuration parameters"""
    
    def validate_scan_params(self, params: dict) -> dict:
        """Validate scan parameters"""
        validated = {}
        
        # Required parameters
        if 'target' not in params:
            raise ValueError("Target is required")
        
        target_validator = TargetValidator()
        validated['target'] = target_validator.validate_target(params['target'])
        
        # Optional parameters with defaults
        validated['profile'] = self._validate_profile(params.get('profile'))
        validated['tools'] = self._validate_tools(params.get('tools'))
        validated['output_dir'] = self._validate_output_dir(params.get('output_dir', './results'))
        validated['output_format'] = self._validate_output_format(params.get('output_format', 'json'))
        validated['verbose'] = bool(params.get('verbose', False))
        validated['timeout'] = self._validate_timeout(params.get('timeout', 300))
        
        return validated
    
    def _validate_profile(self, profile: Optional[str]) -> Optional[str]:
        """Validate scan profile"""
        if profile is None:
            return None
        
        from tools import SCAN_PROFILES
        valid_profiles = list(SCAN_PROFILES.keys())
        
        if profile not in valid_profiles:
            raise ValueError(f"Invalid profile '{profile}'. Valid options: {', '.join(valid_profiles)}")
        
        return profile
    
    def _validate_tools(self, tools: Optional[list]) -> Optional[list]:
        """Validate tool list"""
        if tools is None:
            return None
        
        if not isinstance(tools, list):
            raise ValueError("Tools must be a list")
        
        from tools import TOOL_REGISTRY
        all_tools = []
        for category, category_tools in TOOL_REGISTRY.items():
            all_tools.extend(category_tools.keys())
        
        invalid_tools = [tool for tool in tools if tool not in all_tools]
        if invalid_tools:
            raise ValueError(f"Invalid tools: {', '.join(invalid_tools)}")
        
        return tools
    
    def _validate_output_dir(self, output_dir: str) -> str:
        """Validate output directory"""
        if not output_dir:
            raise ValueError("Output directory cannot be empty")
        
        # Basic path validation
        if any(char in output_dir for char in ['<', '>', '|', '?', '*']):
            raise ValueError("Invalid characters in output directory path")
        
        return output_dir
    
    def _validate_output_format(self, output_format: str) -> str:
        """Validate output format"""
        valid_formats = ['json', 'html', 'markdown', 'pdf']
        
        if output_format not in valid_formats:
            raise ValueError(f"Invalid output format '{output_format}'. Valid options: {', '.join(valid_formats)}")
        
        return output_format
    
    def _validate_timeout(self, timeout: int) -> int:
        """Validate timeout value"""
        try:
            timeout = int(timeout)
            if timeout <= 0:
                raise ValueError("Timeout must be positive")
            if timeout > 3600:  # 1 hour max
                raise ValueError("Timeout cannot exceed 3600 seconds")
            return timeout
        except (ValueError, TypeError):
            raise ValueError("Timeout must be a positive integer")

# Legacy function wrappers for compatibility
def validate_target(target):
    """Legacy wrapper for target validation"""
    validator = TargetValidator()
    return validator.validate_target(target)

def validate_scan_config(config):
    """Legacy wrapper for scan configuration validation"""
    validator = ConfigValidator()
    return validator.validate_scan_params(config)

def validate_tool_selection(tools):
    """Legacy wrapper for tool validation"""
    validator = ConfigValidator()
    return validator._validate_tools(tools)
