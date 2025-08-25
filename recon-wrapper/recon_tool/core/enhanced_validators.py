"""
Enhanced Input Validators v2.0
Comprehensive validation system with strict requirements
"""

import re
import socket
import ipaddress
import shutil
import subprocess
import dns.resolver
from typing import List, Dict, Any, Optional, Union, Tuple
from urllib.parse import urlparse
from pathlib import Path

from .exceptions import ValidationError, ToolNotFoundError


class EnhancedTargetValidator:
    """Enhanced target validator with strict validation requirements"""
    
    def __init__(self, 
                 check_dns_resolution: bool = True, 
                 allow_private_ips: bool = True,
                 require_tld: bool = True,
                 verify_tools: bool = True):
        """
        Initialize enhanced validator
        
        Args:
            check_dns_resolution: Whether to verify domain DNS resolution
            allow_private_ips: Whether to allow private IP addresses
            require_tld: Whether to require valid TLD for domains
            verify_tools: Whether to verify tool availability before validation
        """
        self.check_dns_resolution = check_dns_resolution
        self.allow_private_ips = allow_private_ips
        self.require_tld = require_tld
        self.verify_tools = verify_tools
        
        # Valid TLDs (comprehensive list)
        self.valid_tlds = {
            # Generic TLDs
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'biz', 'info', 'name',
            'pro', 'museum', 'coop', 'travel', 'jobs', 'mobi', 'tel', 'asia', 'cat',
            'post', 'xxx', 'aero', 'arpa', 'local', 'localhost',
            # New gTLDs
            'app', 'dev', 'tech', 'cloud', 'site', 'online', 'store', 'blog', 'news',
            'email', 'social', 'video', 'photo', 'music', 'game', 'shop', 'work',
            # Country codes (sample - expand as needed)
            'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'in', 'mx',
            'it', 'es', 'nl', 'se', 'no', 'dk', 'fi', 'pl', 'ch', 'at', 'be', 'ie',
            'nz', 'za', 'kr', 'sg', 'hk', 'tw', 'th', 'my', 'id', 'ph', 'vn',
            # Special domains
            'io', 'co', 'me', 'tv', 'cc', 'ly', 'sh', 'tk', 'ml', 'ga', 'cf'
        }
        
        # Required tools for different validation types
        self.required_tools = {
            'dns': ['dig', 'nslookup'],
            'network': ['ping', 'nmap'],
            'web': ['curl', 'wget']
        }
    
    def validate_domain(self, domain: str, check_dns: Optional[bool] = None) -> Dict[str, Any]:
        """
        Enhanced domain validation with strict requirements
        
        Args:
            domain: Domain to validate
            check_dns: Override DNS resolution check setting
            
        Returns:
            Dict with validation results and metadata
            
        Raises:
            ValidationError: If domain is invalid
        """
        if check_dns is None:
            check_dns = self.check_dns_resolution
            
        if not domain or not isinstance(domain, str):
            raise ValidationError("Domain cannot be empty", field="domain", value=domain)
        
        # Clean and normalize
        domain = domain.strip().lower()
        
        # Remove protocol if accidentally included
        if domain.startswith(('http://', 'https://')):
            raise ValidationError(
                "Domain should not include protocol (http:// or https://). Use just the domain name.",
                field="domain", 
                value=domain
            )
        
        # Special handling for localhost in strict mode
        if domain == 'localhost' and self.require_tld:
            # Allow localhost even in strict mode as it's a special case
            return {
                "type": "domain",
                "value": domain,
                "valid": True,
                "labels": [domain],
                "tld": None,
                "subdomain": None,
                "apex_domain": domain,
                "dns_resolves": True,  # localhost always resolves
                "validation_timestamp": self._get_timestamp()
            }
        
        # Remove trailing dot (FQDN format)
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Basic length validation
        if len(domain) > 253:
            raise ValidationError("Domain name too long (RFC limit: 253 characters)", field="domain", value=domain)
        
        if len(domain) < 3:  # Minimum meaningful domain
            raise ValidationError("Domain name too short (minimum 3 characters)", field="domain", value=domain)
        
        # Character validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            raise ValidationError(
                "Domain contains invalid characters. Only letters, numbers, dots, and hyphens allowed.",
                field="domain", 
                value=domain
            )
        
        # Check for invalid patterns
        if domain.startswith('-') or domain.endswith('-'):
            raise ValidationError("Domain cannot start or end with hyphen", field="domain", value=domain)
        
        if domain.startswith('.') or domain.endswith('.'):
            raise ValidationError("Domain cannot start or end with dot", field="domain", value=domain)
        
        if '..' in domain:
            raise ValidationError("Domain cannot contain consecutive dots", field="domain", value=domain)
        
        # Split into labels
        labels = domain.split('.')
        
        # TLD requirement
        if self.require_tld and len(labels) < 2:
            # Special exceptions for localhost and test domains
            if domain not in ['localhost', 'test.local']:
                raise ValidationError(
                    f"Domain '{domain}' must have a valid TLD (e.g., 'example.com', not just 'example')",
                    field="domain",
                    value=domain
                )
        
        # Validate each label
        for i, label in enumerate(labels):
            if not label:
                raise ValidationError("Domain labels cannot be empty", field="domain", value=domain)
            
            if len(label) > 63:
                raise ValidationError(
                    f"Domain label '{label}' too long (RFC limit: 63 characters)",
                    field="domain", 
                    value=domain
                )
            
            if label.startswith('-') or label.endswith('-'):
                raise ValidationError(
                    f"Domain label '{label}' cannot start or end with hyphen",
                    field="domain", 
                    value=domain
                )
            
            # Check for valid characters in label
            if not re.match(r'^[a-zA-Z0-9-]+$', label):
                raise ValidationError(
                    f"Domain label '{label}' contains invalid characters",
                    field="domain", 
                    value=domain
                )
        
        # TLD validation
        if len(labels) >= 2:
            tld = labels[-1]
            
            # TLD cannot be purely numeric
            if tld.isdigit():
                raise ValidationError("Top-level domain cannot be purely numeric", field="domain", value=domain)
            
            # TLD length validation
            if len(tld) < 2:
                raise ValidationError(
                    "Top-level domain must be at least 2 characters",
                    field="domain", 
                    value=domain
                )
            
            # Check against valid TLD list (if required)
            if self.require_tld and tld not in self.valid_tlds:
                raise ValidationError(
                    f"Invalid top-level domain '{tld}'. Must be a recognized TLD.",
                    field="domain",
                    value=domain
                )
        
        # DNS resolution check
        dns_resolves = False
        resolution_error = None
        
        if check_dns and domain not in ['localhost', 'test.local']:
            try:
                # Try multiple resolution methods
                dns_resolves = self._check_dns_resolution(domain)
                if not dns_resolves:
                    resolution_error = f"Domain '{domain}' does not resolve via DNS"
            except Exception as e:
                resolution_error = f"DNS resolution error: {str(e)}"
            
            # Fail validation if DNS doesn't resolve
            if not dns_resolves and resolution_error:
                raise ValidationError(
                    f"{resolution_error}. Use --skip-dns-check to bypass DNS validation.",
                    field="domain",
                    value=domain
                )
        
        # Return validation results
        return {
            "type": "domain",
            "value": domain,
            "valid": True,
            "labels": labels,
            "tld": labels[-1] if len(labels) > 1 else None,
            "subdomain": '.'.join(labels[:-2]) if len(labels) > 2 else None,
            "apex_domain": '.'.join(labels[-2:]) if len(labels) > 1 else domain,
            "dns_resolves": dns_resolves,
            "validation_timestamp": self._get_timestamp()
        }
    
    def _check_dns_resolution(self, domain: str) -> bool:
        """Enhanced DNS resolution check using multiple methods"""
        try:
            # Method 1: Standard socket resolution
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            pass
        
        try:
            # Method 2: DNS resolver (if available)
            resolver = dns.resolver.Resolver()
            resolver.resolve(domain, 'A')
            return True
        except:
            pass
        
        try:
            # Method 3: Try IPv6 resolution
            socket.getaddrinfo(domain, None, socket.AF_INET6)
            return True
        except:
            pass
        
        return False
    
    def validate_ip(self, ip: str) -> Dict[str, Any]:
        """Enhanced IP address validation"""
        if not ip or not isinstance(ip, str):
            raise ValidationError("IP address cannot be empty", field="ip", value=ip)
        
        ip = ip.strip()
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check private IP policy
            if not self.allow_private_ips and ip_obj.is_private:
                raise ValidationError(
                    f"Private IP address '{ip}' not allowed. Use --allow-private to enable.",
                    field="ip",
                    value=ip
                )
            
            # Reject certain special addresses
            if ip_obj.is_loopback and str(ip_obj) not in ['127.0.0.1', '::1']:
                raise ValidationError("Loopback addresses not valid for scanning", field="ip", value=ip)
            
            # Allow IPv6 loopback
            if str(ip_obj) == '::1':
                pass  # IPv6 loopback is allowed
            elif ip_obj.is_multicast:
                raise ValidationError("Multicast addresses not valid for scanning", field="ip", value=ip)
            elif hasattr(ip_obj, 'is_reserved') and ip_obj.is_reserved and not ip_obj.is_loopback:
                raise ValidationError("Reserved IP addresses not valid for scanning", field="ip", value=ip)
            
            if ip_obj.is_unspecified:
                raise ValidationError("Unspecified IP addresses not valid for scanning", field="ip", value=ip)
            
            return {
                "type": "ip",
                "value": str(ip_obj),
                "valid": True,
                "version": ip_obj.version,
                "is_private": ip_obj.is_private,
                "is_multicast": ip_obj.is_multicast,
                "is_loopback": ip_obj.is_loopback,
                "is_global": ip_obj.is_global,
                "validation_timestamp": self._get_timestamp()
            }
            
        except ValueError as e:
            raise ValidationError(f"Invalid IP address format: {str(e)}", field="ip", value=ip)
    
    def validate_cidr(self, cidr: str) -> Dict[str, Any]:
        """Enhanced CIDR notation validation with safety checks"""
        if not cidr or not isinstance(cidr, str):
            raise ValidationError("CIDR notation cannot be empty", field="cidr", value=cidr)
        
        cidr = cidr.strip()
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # Safety checks for network size
            if network.version == 4:
                # IPv4 network size limits - be more permissive for /8
                if network.prefixlen < 8:  # Larger than /8
                    raise ValidationError(
                        f"IPv4 network too large (/{network.prefixlen}). Maximum /8 allowed.",
                        field="cidr",
                        value=cidr
                    )
                # Allow /8 networks (16M addresses is acceptable for scanning)
            else:
                # IPv6 network size limits - be more permissive
                if network.prefixlen < 32:  # Allow down to /32 for IPv6
                    raise ValidationError(
                        f"IPv6 network too large (/{network.prefixlen}). Maximum /32 allowed.",
                        field="cidr",
                        value=cidr
                    )
            
            # Check private network policy
            if not self.allow_private_ips and network.is_private:
                raise ValidationError(
                    f"Private network '{cidr}' not allowed. Use --allow-private to enable.",
                    field="cidr",
                    value=cidr
                )
            
            return {
                "type": "cidr",
                "value": str(network),
                "valid": True,
                "network_address": str(network.network_address),
                "broadcast_address": str(network.broadcast_address) if network.version == 4 else None,
                "num_addresses": network.num_addresses,
                "prefix_length": network.prefixlen,
                "version": network.version,
                "is_private": network.is_private,
                "validation_timestamp": self._get_timestamp()
            }
            
        except ValueError as e:
            raise ValidationError(f"Invalid CIDR notation: {str(e)}", field="cidr", value=cidr)
    
    def validate_file_path(self, file_path: str, check_exists: bool = True, check_readable: bool = True) -> Dict[str, Any]:
        """Enhanced file path validation with existence and permission checks"""
        if not file_path or not isinstance(file_path, str):
            raise ValidationError("File path cannot be empty", field="file_path", value=file_path)
        
        try:
            path = Path(file_path).expanduser().resolve()
            
            if check_exists and not path.exists():
                raise ValidationError(f"File does not exist: {path}", field="file_path", value=file_path)
            
            if check_exists and not path.is_file():
                raise ValidationError(f"Path is not a file: {path}", field="file_path", value=file_path)
            
            if check_readable and check_exists:
                try:
                    with open(path, 'r') as f:
                        f.read(1)  # Try to read one character
                except PermissionError:
                    raise ValidationError(f"File is not readable: {path}", field="file_path", value=file_path)
                except UnicodeDecodeError:
                    raise ValidationError(f"File is not a text file: {path}", field="file_path", value=file_path)
            
            # Get file metadata if exists
            file_info = {}
            if path.exists():
                stat = path.stat()
                file_info = {
                    "size_bytes": stat.st_size,
                    "readable": path.is_file() and path.stat().st_mode & 0o444,
                    "writable": path.is_file() and path.stat().st_mode & 0o222,
                    "modified_time": stat.st_mtime
                }
            
            return {
                "type": "file",
                "value": str(path),
                "valid": True,
                "exists": path.exists(),
                "absolute_path": str(path),
                "parent_dir": str(path.parent),
                "file_info": file_info,
                "validation_timestamp": self._get_timestamp()
            }
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Invalid file path: {str(e)}", field="file_path", value=file_path)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for validation metadata"""
        from datetime import datetime
        return datetime.now().isoformat()


class ToolAvailabilityValidator:
    """Validator for tool availability and dependencies"""
    
    def __init__(self):
        """Initialize tool validator"""
        self.tool_cache = {}
        self.required_tools = {
            'network': {
                'nmap': {'command': 'nmap', 'version_flag': '--version', 'critical': True},
                'masscan': {'command': 'masscan', 'version_flag': '--version', 'critical': False},
                'ping': {'command': 'ping', 'version_flag': '-V', 'critical': True}
            },
            'dns': {
                'dig': {'command': 'dig', 'version_flag': '-v', 'critical': True},
                'nslookup': {'command': 'nslookup', 'version_flag': '-version', 'critical': False}
            },
            'web': {
                'curl': {'command': 'curl', 'version_flag': '--version', 'critical': True},
                'wget': {'command': 'wget', 'version_flag': '--version', 'critical': False}
            },
            'ssl': {
                'openssl': {'command': 'openssl', 'version_flag': 'version', 'critical': True}
            },
            'subdomain': {
                'subfinder': {'command': 'subfinder', 'version_flag': '-version', 'critical': False},
                'assetfinder': {'command': 'assetfinder', 'version_flag': '--version', 'critical': False}
            }
        }
    
    def check_tool_availability(self, tool_name: str) -> Dict[str, Any]:
        """
        Check if a specific tool is available
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            Dict with tool availability information
        """
        if tool_name in self.tool_cache:
            return self.tool_cache[tool_name]
        
        # Find tool configuration
        tool_config = None
        tool_category = None
        
        for category, tools in self.required_tools.items():
            if tool_name in tools:
                tool_config = tools[tool_name]
                tool_category = category
                break
        
        if not tool_config:
            result = {
                "tool": tool_name,
                "available": False,
                "error": f"Unknown tool '{tool_name}'",
                "category": None,
                "critical": False
            }
            self.tool_cache[tool_name] = result
            return result
        
        # Check if tool is in PATH
        tool_path = shutil.which(tool_config['command'])
        if not tool_path:
            result = {
                "tool": tool_name,
                "available": False,
                "error": f"Tool '{tool_name}' not found in PATH",
                "category": tool_category,
                "critical": tool_config.get('critical', False),
                "install_suggestion": self._get_install_suggestion(tool_name)
            }
            self.tool_cache[tool_name] = result
            return result
        
        # Try to get version information
        version_info = None
        try:
            version_cmd = [tool_config['command']]
            if tool_config.get('version_flag'):
                version_cmd.append(tool_config['version_flag'])
            
            result_proc = subprocess.run(
                version_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result_proc.returncode == 0:
                version_info = result_proc.stdout.strip()
            else:
                version_info = result_proc.stderr.strip()
                
        except Exception as e:
            version_info = f"Version check failed: {str(e)}"
        
        result = {
            "tool": tool_name,
            "available": True,
            "path": tool_path,
            "version_info": version_info,
            "category": tool_category,
            "critical": tool_config.get('critical', False)
        }
        
        self.tool_cache[tool_name] = result
        return result
    
    def check_all_tools(self) -> Dict[str, Dict[str, Any]]:
        """Check availability of all configured tools"""
        results = {}
        
        for category, tools in self.required_tools.items():
            results[category] = {}
            for tool_name in tools:
                results[category][tool_name] = self.check_tool_availability(tool_name)
        
        return results
    
    def validate_required_tools(self, tool_list: List[str]) -> Dict[str, Any]:
        """
        Validate that required tools are available
        
        Args:
            tool_list: List of tool names to validate
            
        Returns:
            Dict with validation results
            
        Raises:
            ToolNotFoundError: If critical tools are missing
        """
        missing_tools = []
        missing_critical = []
        available_tools = []
        
        for tool_name in tool_list:
            tool_info = self.check_tool_availability(tool_name)
            
            if tool_info['available']:
                available_tools.append(tool_name)
            else:
                missing_tools.append(tool_name)
                if tool_info.get('critical', False):
                    missing_critical.append(tool_name)
        
        # Raise error if critical tools are missing
        if missing_critical:
            install_suggestions = []
            for tool in missing_critical:
                suggestion = self._get_install_suggestion(tool)
                if suggestion:
                    install_suggestions.append(f"  • {tool}: {suggestion}")
            
            error_msg = f"Critical tools missing: {', '.join(missing_critical)}"
            if install_suggestions:
                error_msg += f"\n\nInstallation suggestions:\n" + "\n".join(install_suggestions)
            
            raise ToolNotFoundError(error_msg)
        
        return {
            "all_available": len(missing_tools) == 0,
            "available_tools": available_tools,
            "missing_tools": missing_tools,
            "missing_critical": missing_critical,
            "total_requested": len(tool_list),
            "total_available": len(available_tools)
        }
    
    def _get_install_suggestion(self, tool_name: str) -> str:
        """Get installation suggestion for a tool"""
        suggestions = {
            'nmap': 'sudo apt-get install nmap (Debian/Ubuntu) or brew install nmap (macOS)',
            'masscan': 'sudo apt-get install masscan (Debian/Ubuntu) or brew install masscan (macOS)',
            'dig': 'sudo apt-get install dnsutils (Debian/Ubuntu) or brew install bind (macOS)',
            'curl': 'sudo apt-get install curl (Debian/Ubuntu) or brew install curl (macOS)',
            'wget': 'sudo apt-get install wget (Debian/Ubuntu) or brew install wget (macOS)',
            'openssl': 'sudo apt-get install openssl (Debian/Ubuntu) or brew install openssl (macOS)',
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest'
        }
        
        return suggestions.get(tool_name, f"Please install {tool_name} manually")


class EnhancedInputValidator:
    """Main enhanced input validator combining all validation types"""
    
    def __init__(self, 
                 check_dns_resolution: bool = True,
                 allow_private_ips: bool = True,
                 require_tld: bool = True,
                 verify_tools: bool = True):
        """Initialize enhanced input validator"""
        self.target_validator = EnhancedTargetValidator(
            check_dns_resolution=check_dns_resolution,
            allow_private_ips=allow_private_ips,
            require_tld=require_tld,
            verify_tools=verify_tools
        )
        self.tool_validator = ToolAvailabilityValidator()
    
    def validate_target(self, target: str) -> Dict[str, Any]:
        """
        Comprehensive target validation
        
        Args:
            target: Target string to validate
            
        Returns:
            Dict with validation results and metadata
        """
        if not target or not isinstance(target, str):
            raise ValidationError("Target cannot be empty", field="target", value=target)
        
        target = target.strip()
        
        # Determine target type and validate accordingly
        if target.startswith(('http://', 'https://')):
            return self._validate_url(target)
        elif '/' in target and self._looks_like_cidr(target):
            return self.target_validator.validate_cidr(target)
        elif self._is_ip_address(target):
            return self.target_validator.validate_ip(target)
        else:
            return self.target_validator.validate_domain(target)
    
    def _looks_like_cidr(self, target: str) -> bool:
        """Check if target looks like CIDR notation"""
        if '/' not in target:
            return False
        
        try:
            parts = target.split('/')
            if len(parts) != 2:
                return False
            
            # Check if second part is a number (prefix length)
            int(parts[1])
            
            # Check if first part looks like an IP
            return self._is_ip_address(parts[0])
        except:
            return False
    
    def validate_targets_file(self, file_path: str) -> Dict[str, Any]:
        """
        Validate targets file and its contents
        
        Args:
            file_path: Path to targets file
            
        Returns:
            Dict with file validation and target validation results
        """
        # First validate the file itself
        file_info = self.target_validator.validate_file_path(file_path)
        
        # Then validate the targets within
        targets = []
        invalid_targets = []
        line_number = 0
        
        try:
            with open(file_info['absolute_path'], 'r', encoding='utf-8') as f:
                for line in f:
                    line_number += 1
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        target_info = self.validate_target(line)
                        target_info['line_number'] = line_number
                        targets.append(target_info)
                    except ValidationError as e:
                        invalid_targets.append({
                            'line_number': line_number,
                            'target': line,
                            'error': str(e)
                        })
        
        except Exception as e:
            raise ValidationError(f"Error reading targets file: {str(e)}", field="targets_file", value=file_path)
        
        if not targets and not invalid_targets:
            raise ValidationError("No targets found in file", field="targets_file", value=file_path)
        
        return {
            "file_info": file_info,
            "valid_targets": targets,
            "invalid_targets": invalid_targets,
            "total_lines": line_number,
            "valid_count": len(targets),
            "invalid_count": len(invalid_targets)
        }
    
    def validate_scan_tools(self, requested_tools: List[str]) -> Dict[str, Any]:
        """
        Validate that requested scanning tools are available
        
        Args:
            requested_tools: List of tool names requested for scanning
            
        Returns:
            Dict with tool validation results
        """
        return self.tool_validator.validate_required_tools(requested_tools)
    
    def _validate_url(self, url: str) -> Dict[str, Any]:
        """Validate URL format"""
        try:
            parsed = urlparse(url)
            
            if not parsed.scheme or not parsed.netloc:
                raise ValidationError("Invalid URL format", field="target", value=url)
            
            if parsed.scheme not in ['http', 'https']:
                raise ValidationError("URL scheme must be http or https", field="target", value=url)
            
            # Validate the hostname part
            hostname = parsed.hostname
            if not hostname:
                raise ValidationError("URL must have a valid hostname", field="target", value=url)
            
            # Validate hostname using domain or IP validation
            try:
                if self._is_ip_address(hostname):
                    ip_info = self.target_validator.validate_ip(hostname)
                    hostname_info = ip_info
                else:
                    domain_info = self.target_validator.validate_domain(hostname)
                    hostname_info = domain_info
            except ValidationError as e:
                raise ValidationError(f"Invalid hostname in URL: {str(e)}", field="target", value=url)
            
            return {
                "type": "url",
                "value": url,
                "valid": True,
                "scheme": parsed.scheme,
                "hostname": hostname,
                "port": parsed.port,
                "path": parsed.path,
                "is_secure": parsed.scheme == 'https',
                "hostname_info": hostname_info,
                "validation_timestamp": self.target_validator._get_timestamp()
            }
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Invalid URL: {str(e)}", field="target", value=url)
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


# Convenience functions for backward compatibility
def validate_domain_strict(domain: str, check_dns: bool = True, require_tld: bool = True) -> bool:
    """
    Strict domain validation function
    
    Args:
        domain: Domain to validate
        check_dns: Whether to check DNS resolution
        require_tld: Whether to require valid TLD
        
    Returns:
        True if valid
        
    Raises:
        ValidationError: If domain is invalid
    """
    validator = EnhancedTargetValidator(
        check_dns_resolution=check_dns,
        require_tld=require_tld
    )
    result = validator.validate_domain(domain)
    return result['valid']


def validate_tools_available(tools: List[str]) -> Dict[str, Any]:
    """
    Validate that tools are available
    
    Args:
        tools: List of tool names to check
        
    Returns:
        Dict with availability results
        
    Raises:
        ToolNotFoundError: If critical tools are missing
    """
    validator = ToolAvailabilityValidator()
    return validator.validate_required_tools(tools)


def get_tool_install_suggestions(missing_tools: List[str]) -> List[str]:
    """
    Get installation suggestions for missing tools
    
    Args:
        missing_tools: List of missing tool names
        
    Returns:
        List of installation suggestions
    """
    validator = ToolAvailabilityValidator()
    suggestions = []
    
    for tool in missing_tools:
        suggestion = validator._get_install_suggestion(tool)
        suggestions.append(f"{tool}: {suggestion}")
    
    return suggestions
