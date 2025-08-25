"""
Utility Functions
Common utilities used throughout the application
"""

import ipaddress
import re
import socket
import subprocess
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Tuple
from urllib.parse import urlparse
import hashlib
import json


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr_str: str) -> bool:
    """Check if string is a valid CIDR notation"""
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Check if string is a valid domain name"""
    if not domain or len(domain) > 253:
        return False
    
    # Remove trailing dot if present
    if domain.endswith('.'):
        domain = domain[:-1]
    
    # Check each label
    labels = domain.split('.')
    if len(labels) < 2:
        return False
    
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return False
    
    return True


def is_valid_url(url: str) -> bool:
    """Check if string is a valid URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def expand_ip_range(ip_range: str) -> List[str]:
    """Expand IP range to list of individual IPs"""
    try:
        if '/' in ip_range:
            # CIDR notation
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        elif '-' in ip_range:
            # Range notation (e.g., 192.168.1.1-192.168.1.10)
            start_ip, end_ip = ip_range.split('-', 1)
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            
            if start.version != end.version:
                return []
            
            result = []
            current = start
            while current <= end:
                result.append(str(current))
                current += 1
                if len(result) > 1000:  # Prevent excessive ranges
                    break
            return result
        else:
            # Single IP
            if is_valid_ip(ip_range):
                return [ip_range]
    except:
        pass
    return []


def resolve_hostname(hostname: str, timeout: float = 5.0) -> Optional[str]:
    """Resolve hostname to IP address"""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except:
        return None


def reverse_dns_lookup(ip: str, timeout: float = 5.0) -> Optional[str]:
    """Perform reverse DNS lookup"""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except:
        return None


def get_network_interface_ips() -> List[str]:
    """Get IP addresses of network interfaces"""
    try:
        import netifaces
        ips = []
        for interface in netifaces.interfaces():
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                for addr in addresses[netifaces.AF_INET]:
                    ip = addr.get('addr')
                    if ip and ip != '127.0.0.1':
                        ips.append(ip)
        return ips
    except ImportError:
        # Fallback method
        try:
            hostname = socket.gethostname()
            return [socket.gethostbyname(hostname)]
        except:
            return []


def run_command(command: str, timeout: int = 30, shell: bool = True) -> Tuple[int, str, str]:
    """Run shell command and return (return_code, stdout, stderr)"""
    try:
        process = subprocess.Popen(
            command,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        stdout, stderr = process.communicate()
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        process.kill()
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def run_command_async(command: str, shell: bool = True) -> subprocess.Popen:
    """Run command asynchronously and return process handle"""
    return subprocess.Popen(
        command,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )


def check_tool_installed(tool_name: str) -> bool:
    """Check if a tool is installed and available"""
    try:
        subprocess.run(
            ["which", tool_name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_missing_tools(required_tools: List[str]) -> List[str]:
    """Get list of missing tools from required tools list"""
    return [tool for tool in required_tools if not check_tool_installed(tool)]


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"


def format_duration(seconds: float) -> str:
    """Format duration in human readable format"""
    if seconds < 1:
        return f"{seconds:.2f}s"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def generate_scan_id() -> str:
    """Generate unique scan ID"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_id = str(uuid.uuid4())[:8]
    return f"scan_{timestamp}_{unique_id}"


def calculate_file_hash(file_path: Path, algorithm: str = "sha256") -> Optional[str]:
    """Calculate hash of file"""
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except:
        return None


def safe_filename(filename: str) -> str:
    """Create safe filename by removing/replacing invalid characters"""
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    return filename


def create_directory_structure(base_path: Path, structure: Dict[str, Any]) -> None:
    """Create directory structure from nested dictionary"""
    base_path.mkdir(exist_ok=True)
    
    for name, content in structure.items():
        path = base_path / name
        if isinstance(content, dict):
            # It's a directory
            create_directory_structure(path, content)
        else:
            # It's a file - create parent directory
            path.parent.mkdir(parents=True, exist_ok=True)


def merge_dictionaries(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dictionaries(result[key], value)
        else:
            result[key] = value
    
    return result


def sanitize_input(input_str: str) -> str:
    """Sanitize user input to prevent command injection"""
    # Remove or escape potentially dangerous characters
    input_str = re.sub(r'[;&|`$(){}[\]<>]', '', input_str)
    # Remove multiple spaces
    input_str = re.sub(r'\s+', ' ', input_str).strip()
    return input_str


def parse_port_range(port_range: str) -> List[int]:
    """Parse port range string to list of ports"""
    ports = []
    
    for part in port_range.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-', 1))
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ports.extend(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                continue
    
    return sorted(list(set(ports)))


def get_local_ip() -> Optional[str]:
    """Get local IP address"""
    try:
        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return None


def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if port is open on host"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except:
        return False


def get_timestamp() -> str:
    """Get current timestamp as ISO format string"""
    return datetime.now().isoformat()


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Parse ISO format timestamp string"""
    try:
        return datetime.fromisoformat(timestamp_str)
    except:
        return None


class ProgressTracker:
    """Track progress of operations"""
    
    def __init__(self, total: int, description: str = "Progress"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
    
    def update(self, increment: int = 1) -> None:
        """Update progress"""
        self.current = min(self.current + increment, self.total)
    
    def get_percentage(self) -> float:
        """Get completion percentage"""
        if self.total == 0:
            return 100.0
        return (self.current / self.total) * 100
    
    def get_eta(self) -> Optional[float]:
        """Get estimated time to completion"""
        if self.current == 0:
            return None
        
        elapsed = time.time() - self.start_time
        rate = self.current / elapsed
        remaining = self.total - self.current
        
        if rate > 0:
            return remaining / rate
        return None
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status"""
        return {
            "description": self.description,
            "current": self.current,
            "total": self.total,
            "percentage": self.get_percentage(),
            "eta": self.get_eta(),
            "elapsed": time.time() - self.start_time
        }
