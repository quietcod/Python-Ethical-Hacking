"""
Input Validators
Validation functions for user inputs and configuration
"""

import re
import ipaddress
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse
from pathlib import Path

from .exceptions import ValidationError


class TargetValidator:
    """Simple target validator class"""
    
    def validate_domain(self, domain: str) -> bool:
        """Validate domain format"""
        if not domain:
            return False
        
        # Basic domain validation regex
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        return bool(re.match(domain_pattern, domain)) and len(domain) <= 253
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


class InputValidator:
    """Main validator class for user inputs"""
    
    @staticmethod
    def validate_target(target: str) -> Dict[str, Any]:
        """
        Validate target input and determine target type
        Returns: {"type": "ip|domain|url|cidr", "value": "normalized_value", "valid": bool}
        """
        if not target or not isinstance(target, str):
            raise ValidationError("Target cannot be empty", field="target", value=target)
        
        target = target.strip()
        
        # Check if it's a URL
        if target.startswith(('http://', 'https://')):
            return InputValidator._validate_url(target)
        
        # Check if it's CIDR notation
        if '/' in target:
            return InputValidator._validate_cidr(target)
        
        # Check if it's IP address
        if InputValidator._is_ip_address(target):
            return InputValidator._validate_ip(target)
        
        # Assume it's a domain
        return InputValidator._validate_domain(target)
    
    @staticmethod
    def _validate_ip(ip: str) -> Dict[str, Any]:
        """Validate IP address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return {
                "type": "ip",
                "value": str(ip_obj),
                "valid": True,
                "version": ip_obj.version,
                "is_private": ip_obj.is_private,
                "is_multicast": ip_obj.is_multicast,
                "is_loopback": ip_obj.is_loopback
            }
        except ValueError as e:
            raise ValidationError(f"Invalid IP address: {str(e)}", field="target", value=ip)
    
    @staticmethod
    def _validate_domain(domain: str) -> Dict[str, Any]:
        """Validate domain name"""
        if not domain or len(domain) > 253:
            raise ValidationError("Domain name too long or empty", field="target", value=domain)
        
        # Remove trailing dot
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Check if it looks like a domain
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        if not domain_pattern.match(domain):
            raise ValidationError("Invalid domain name format", field="target", value=domain)
        
        # Check for at least one dot (except for single words like localhost)
        labels = domain.split('.')
        if len(labels) < 2 and domain not in ['localhost']:
            raise ValidationError("Domain must have at least one dot", field="target", value=domain)
        
        return {
            "type": "domain",
            "value": domain.lower(),
            "valid": True,
            "labels": labels,
            "tld": labels[-1] if len(labels) > 1 else None
        }
    
    @staticmethod
    def _validate_url(url: str) -> Dict[str, Any]:
        """Validate URL"""
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
            
            return {
                "type": "url",
                "value": url,
                "valid": True,
                "scheme": parsed.scheme,
                "hostname": hostname,
                "port": parsed.port,
                "path": parsed.path,
                "is_secure": parsed.scheme == 'https'
            }
            
        except Exception as e:
            raise ValidationError(f"Invalid URL: {str(e)}", field="target", value=url)
    
    @staticmethod
    def _validate_cidr(cidr: str) -> Dict[str, Any]:
        """Validate CIDR notation"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # Check if network is too large
            if network.num_addresses > 65536:  # /16 for IPv4
                raise ValidationError("Network range too large (max /16)", field="target", value=cidr)
            
            return {
                "type": "cidr",
                "value": str(network),
                "valid": True,
                "network_address": str(network.network_address),
                "broadcast_address": str(network.broadcast_address),
                "num_addresses": network.num_addresses,
                "version": network.version,
                "is_private": network.is_private
            }
            
        except ValueError as e:
            raise ValidationError(f"Invalid CIDR notation: {str(e)}", field="target", value=cidr)
    
    @staticmethod
    def _is_ip_address(value: str) -> bool:
        """Check if value is an IP address"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port_range(port_range: str) -> List[int]:
        """Validate and parse port range"""
        if not port_range or not isinstance(port_range, str):
            raise ValidationError("Port range cannot be empty", field="ports", value=port_range)
        
        ports = []
        
        try:
            for part in port_range.split(','):
                part = part.strip()
                
                if '-' in part:
                    # Range like 80-90
                    start_str, end_str = part.split('-', 1)
                    start_port = int(start_str.strip())
                    end_port = int(end_str.strip())
                    
                    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                        raise ValidationError("Ports must be between 1 and 65535", field="ports", value=part)
                    
                    if start_port > end_port:
                        raise ValidationError("Invalid port range: start > end", field="ports", value=part)
                    
                    if end_port - start_port > 1000:
                        raise ValidationError("Port range too large (max 1000 ports)", field="ports", value=part)
                    
                    ports.extend(range(start_port, end_port + 1))
                else:
                    # Single port
                    port = int(part)
                    if not (1 <= port <= 65535):
                        raise ValidationError("Port must be between 1 and 65535", field="ports", value=part)
                    ports.append(port)
            
            if len(ports) > 1000:
                raise ValidationError("Too many ports specified (max 1000)", field="ports", value=port_range)
            
            return sorted(list(set(ports)))
            
        except ValueError as e:
            raise ValidationError(f"Invalid port format: {str(e)}", field="ports", value=port_range)
    
    @staticmethod
    def validate_output_directory(output_dir: str) -> Path:
        """Validate output directory"""
        if not output_dir or not isinstance(output_dir, str):
            raise ValidationError("Output directory cannot be empty", field="output_dir", value=output_dir)
        
        try:
            path = Path(output_dir).expanduser().resolve()
            
            # Check if parent directory exists and is writable
            if not path.parent.exists():
                raise ValidationError("Parent directory does not exist", field="output_dir", value=str(path.parent))
            
            if not path.parent.is_dir():
                raise ValidationError("Parent is not a directory", field="output_dir", value=str(path.parent))
            
            # Create directory if it doesn't exist
            try:
                path.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                raise ValidationError("No permission to create directory", field="output_dir", value=str(path))
            
            # Check if directory is writable
            if not path.is_dir():
                raise ValidationError("Path is not a directory", field="output_dir", value=str(path))
            
            test_file = path / ".write_test"
            try:
                test_file.touch()
                test_file.unlink()
            except PermissionError:
                raise ValidationError("Directory is not writable", field="output_dir", value=str(path))
            
            return path
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Invalid output directory: {str(e)}", field="output_dir", value=output_dir)
    
    @staticmethod
    def validate_scan_type(scan_type: str, available_types: List[str]) -> str:
        """Validate scan type"""
        if not scan_type or not isinstance(scan_type, str):
            raise ValidationError("Scan type cannot be empty", field="scan_type", value=scan_type)
        
        scan_type = scan_type.lower().strip()
        
        if scan_type not in available_types:
            raise ValidationError(
                f"Invalid scan type. Available types: {', '.join(available_types)}", 
                field="scan_type", 
                value=scan_type
            )
        
        return scan_type
    
    @staticmethod
    def validate_timeout(timeout: Union[int, float, str]) -> float:
        """Validate timeout value"""
        try:
            timeout_val = float(timeout)
            
            if timeout_val <= 0:
                raise ValidationError("Timeout must be positive", field="timeout", value=str(timeout))
            
            if timeout_val > 3600:  # 1 hour max
                raise ValidationError("Timeout too large (max 3600 seconds)", field="timeout", value=str(timeout))
            
            return timeout_val
            
        except (ValueError, TypeError):
            raise ValidationError("Invalid timeout format", field="timeout", value=str(timeout))
    
    @staticmethod
    def validate_threads(threads: Union[int, str]) -> int:
        """Validate thread count"""
        try:
            thread_count = int(threads)
            
            if thread_count <= 0:
                raise ValidationError("Thread count must be positive", field="threads", value=str(threads))
            
            if thread_count > 100:
                raise ValidationError("Too many threads (max 100)", field="threads", value=str(threads))
            
            return thread_count
            
        except (ValueError, TypeError):
            raise ValidationError("Invalid thread count format", field="threads", value=str(threads))
    
    @staticmethod
    def validate_wordlist_path(wordlist_path: str) -> Path:
        """Validate wordlist file path"""
        if not wordlist_path or not isinstance(wordlist_path, str):
            raise ValidationError("Wordlist path cannot be empty", field="wordlist", value=wordlist_path)
        
        try:
            path = Path(wordlist_path).expanduser().resolve()
            
            if not path.exists():
                raise ValidationError("Wordlist file does not exist", field="wordlist", value=str(path))
            
            if not path.is_file():
                raise ValidationError("Wordlist path is not a file", field="wordlist", value=str(path))
            
            # Check if file is readable
            try:
                with open(path, 'r') as f:
                    f.read(1)
            except PermissionError:
                raise ValidationError("Wordlist file is not readable", field="wordlist", value=str(path))
            except UnicodeDecodeError:
                raise ValidationError("Wordlist file is not a text file", field="wordlist", value=str(path))
            
            return path
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Invalid wordlist path: {str(e)}", field="wordlist", value=wordlist_path)


class ConfigValidator:
    """Validator for configuration files and settings"""
    
    @staticmethod
    def validate_config_structure(config: Dict[str, Any], schema: Dict[str, Any]) -> None:
        """Validate configuration against schema"""
        ConfigValidator._validate_dict_against_schema(config, schema, "config")
    
    @staticmethod
    def _validate_dict_against_schema(data: Dict[str, Any], schema: Dict[str, Any], path: str) -> None:
        """Recursively validate dictionary against schema"""
        for key, schema_value in schema.items():
            current_path = f"{path}.{key}"
            
            if key not in data:
                if schema_value.get("required", False):
                    raise ValidationError(f"Required configuration key missing: {current_path}")
                continue
            
            value = data[key]
            
            # Check type
            expected_type = schema_value.get("type")
            if expected_type and not isinstance(value, expected_type):
                raise ValidationError(
                    f"Invalid type for {current_path}: expected {expected_type.__name__}, got {type(value).__name__}"
                )
            
            # Check nested dictionaries
            if isinstance(schema_value, dict) and "type" not in schema_value:
                if isinstance(value, dict):
                    ConfigValidator._validate_dict_against_schema(value, schema_value, current_path)
            
            # Custom validation
            validator_func = schema_value.get("validator")
            if validator_func and callable(validator_func):
                try:
                    validator_func(value)
                except Exception as e:
                    raise ValidationError(f"Validation failed for {current_path}: {str(e)}")
    
    @staticmethod
    def validate_tool_config(tool_config: Dict[str, Any]) -> None:
        """Validate tool-specific configuration"""
        required_fields = ["name", "command", "enabled"]
        
        for field in required_fields:
            if field not in tool_config:
                raise ValidationError(f"Tool config missing required field: {field}")
        
        if not isinstance(tool_config["enabled"], bool):
            raise ValidationError("Tool 'enabled' field must be boolean")
        
        if not isinstance(tool_config["name"], str) or not tool_config["name"].strip():
            raise ValidationError("Tool 'name' must be non-empty string")
        
        if not isinstance(tool_config["command"], str) or not tool_config["command"].strip():
            raise ValidationError("Tool 'command' must be non-empty string")


# Validation decorators
def validate_input(validator_func):
    """Decorator to validate function inputs"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Apply validation
            validator_func(*args, **kwargs)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def validate_target_input(func):
    """Decorator to validate target input"""
    def wrapper(self, target, *args, **kwargs):
        validated_target = InputValidator.validate_target(target)
        return func(self, validated_target, *args, **kwargs)
    return wrapper
