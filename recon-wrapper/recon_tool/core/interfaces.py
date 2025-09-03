"""
Interface Standardization System
Professional interfaces for all ReconTool components
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Protocol, runtime_checkable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class ScanType(Enum):
    """Standard scan types"""
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"
    STEALTH = "stealth"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"


class TargetType(Enum):
    """Standard target types"""
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    FILE = "file"


class ScanStatus(Enum):
    """Standard scan statuses"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class Severity(Enum):
    """Standard severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanResult:
    """Standard scan result structure"""
    tool_name: str
    target: str
    scan_type: ScanType
    status: ScanStatus
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    results: Optional[Dict[str, Any]] = None
    errors: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class Vulnerability:
    """Standard vulnerability structure"""
    id: str
    title: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    references: Optional[List[str]] = None
    affected_component: Optional[str] = None
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class PortInfo:
    """Standard port information structure"""
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    vulnerabilities: Optional[List[Vulnerability]] = None


@dataclass
class HostInfo:
    """Standard host information structure"""
    ip: str
    hostname: Optional[str] = None
    operating_system: Optional[str] = None
    ports: Optional[List[PortInfo]] = None
    services: Optional[List[str]] = None
    vulnerabilities: Optional[List[Vulnerability]] = None
    metadata: Optional[Dict[str, Any]] = None


# Core Interfaces

@runtime_checkable
class ILogger(Protocol):
    """Standard logger interface"""
    
    def debug(self, message: str, **kwargs) -> None: ...
    def info(self, message: str, **kwargs) -> None: ...
    def warning(self, message: str, **kwargs) -> None: ...
    def error(self, message: str, **kwargs) -> None: ...
    def critical(self, message: str, **kwargs) -> None: ...


@runtime_checkable
class IConfigManager(Protocol):
    """Standard configuration manager interface"""
    
    def get(self, key: str, default: Any = None) -> Any: ...
    def set(self, key: str, value: Any) -> None: ...
    def get_section(self, section: str) -> Dict[str, Any]: ...
    def save(self) -> None: ...
    def load(self) -> None: ...


@runtime_checkable
class IValidator(Protocol):
    """Standard validator interface"""
    
    def validate_target(self, target: str) -> bool: ...
    def get_target_type(self, target: str) -> TargetType: ...
    def normalize_target(self, target: str) -> str: ...


class IScanTool(ABC):
    """Standard interface for all scan tools"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Tool version"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Tool description"""
        pass
    
    @property
    @abstractmethod
    def supported_targets(self) -> List[TargetType]:
        """Supported target types"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if tool is available"""
        pass
    
    @abstractmethod
    def scan(self, target: str, scan_type: ScanType = ScanType.QUICK, 
             **options) -> ScanResult:
        """Execute scan"""
        pass
    
    @abstractmethod
    def validate_options(self, **options) -> bool:
        """Validate scan options"""
        pass
    
    def get_default_options(self, scan_type: ScanType) -> Dict[str, Any]:
        """Get default options for scan type"""
        return {}


class IPortScanner(IScanTool):
    """Interface for port scanning tools"""
    
    @abstractmethod
    def quick_scan(self, target: str) -> ScanResult:
        """Quick port scan"""
        pass
    
    @abstractmethod
    def full_scan(self, target: str) -> ScanResult:
        """Full port scan"""
        pass
    
    @abstractmethod
    def service_detection(self, target: str, ports: List[int]) -> ScanResult:
        """Service detection on specific ports"""
        pass


class IWebScanner(IScanTool):
    """Interface for web scanning tools"""
    
    @abstractmethod
    def scan_vulnerabilities(self, url: str) -> ScanResult:
        """Scan for web vulnerabilities"""
        pass
    
    @abstractmethod
    def directory_scan(self, url: str, wordlist: Optional[str] = None) -> ScanResult:
        """Directory enumeration"""
        pass
    
    @abstractmethod
    def technology_detection(self, url: str) -> ScanResult:
        """Detect web technologies"""
        pass


class ISubdomainScanner(IScanTool):
    """Interface for subdomain enumeration tools"""
    
    @abstractmethod
    def enumerate_subdomains(self, domain: str) -> ScanResult:
        """Enumerate subdomains"""
        pass
    
    @abstractmethod
    def bruteforce_subdomains(self, domain: str, wordlist: Optional[str] = None) -> ScanResult:
        """Bruteforce subdomain discovery"""
        pass


class IVulnerabilityScanner(IScanTool):
    """Interface for vulnerability scanning tools"""
    
    @abstractmethod
    def scan_vulnerabilities(self, target: str, port: Optional[int] = None) -> ScanResult:
        """Scan for vulnerabilities"""
        pass
    
    @abstractmethod
    def get_exploit_info(self, vulnerability_id: str) -> Optional[Dict[str, Any]]:
        """Get exploit information for vulnerability"""
        pass


class IOSINTTool(IScanTool):
    """Interface for OSINT tools"""
    
    @abstractmethod
    def gather_information(self, target: str) -> ScanResult:
        """Gather OSINT information"""
        pass
    
    @abstractmethod
    def search_breaches(self, email: str) -> ScanResult:
        """Search for data breaches"""
        pass


class IReportGenerator(ABC):
    """Interface for report generators"""
    
    @property
    @abstractmethod
    def format_name(self) -> str:
        """Report format name"""
        pass
    
    @property
    @abstractmethod
    def file_extension(self) -> str:
        """File extension for this format"""
        pass
    
    @abstractmethod
    def generate(self, scan_results: List[ScanResult], output_path: Path, 
                **options) -> Path:
        """Generate report"""
        pass
    
    @abstractmethod
    def supports_interactive(self) -> bool:
        """Check if format supports interactive elements"""
        pass


class IOrchestrator(ABC):
    """Interface for scan orchestrators"""
    
    @abstractmethod
    def initialize(self, target: str, scan_type: ScanType, 
                  output_dir: Path, **options) -> bool:
        """Initialize orchestrator"""
        pass
    
    @abstractmethod
    def start_scan(self) -> bool:
        """Start scanning process"""
        pass
    
    @abstractmethod
    def stop_scan(self) -> bool:
        """Stop scanning process"""
        pass
    
    @abstractmethod
    def pause_scan(self) -> bool:
        """Pause scanning process"""
        pass
    
    @abstractmethod
    def resume_scan(self) -> bool:
        """Resume scanning process"""
        pass
    
    @abstractmethod
    def get_status(self) -> ScanStatus:
        """Get current scan status"""
        pass
    
    @abstractmethod
    def get_progress(self) -> float:
        """Get scan progress (0.0 to 1.0)"""
        pass
    
    @abstractmethod
    def get_results(self) -> List[ScanResult]:
        """Get scan results"""
        pass


class IPlugin(ABC):
    """Interface for plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description"""
        pass
    
    @property
    @abstractmethod
    def author(self) -> str:
        """Plugin author"""
        pass
    
    @abstractmethod
    def initialize(self, container) -> bool:
        """Initialize plugin with DI container"""
        pass
    
    @abstractmethod
    def configure_services(self, container) -> None:
        """Configure services in DI container"""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass


class IStateManager(ABC):
    """Interface for state management"""
    
    @abstractmethod
    def save_state(self, state: Dict[str, Any], checkpoint_name: str) -> bool:
        """Save current state"""
        pass
    
    @abstractmethod
    def load_state(self, checkpoint_name: str) -> Optional[Dict[str, Any]]:
        """Load saved state"""
        pass
    
    @abstractmethod
    def list_checkpoints(self) -> List[str]:
        """List available checkpoints"""
        pass
    
    @abstractmethod
    def delete_checkpoint(self, checkpoint_name: str) -> bool:
        """Delete a checkpoint"""
        pass


class IResourceMonitor(ABC):
    """Interface for resource monitoring"""
    
    @abstractmethod
    def start_monitoring(self) -> None:
        """Start resource monitoring"""
        pass
    
    @abstractmethod
    def stop_monitoring(self) -> None:
        """Stop resource monitoring"""
        pass
    
    @abstractmethod
    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        pass
    
    @abstractmethod
    def get_memory_usage(self) -> Dict[str, float]:
        """Get memory usage information"""
        pass
    
    @abstractmethod
    def get_disk_usage(self) -> Dict[str, float]:
        """Get disk usage information"""
        pass
    
    @abstractmethod
    def get_network_stats(self) -> Dict[str, Any]:
        """Get network statistics"""
        pass


# Interface compliance checker
class InterfaceValidator:
    """Validates interface implementations"""
    
    @staticmethod
    def validate_tool(tool: Any) -> List[str]:
        """Validate tool interface compliance"""
        errors = []
        
        if not isinstance(tool, IScanTool):
            errors.append(f"{tool.__class__.__name__} does not implement IScanTool")
        
        # Check properties (these are properties, not methods)
        required_properties = ['name', 'version', 'description', 'supported_targets']
        for prop in required_properties:
            if not hasattr(tool, prop):
                errors.append(f"Missing required property: {prop}")
        
        # Check methods
        required_methods = ['is_available', 'scan', 'validate_options']
        for method in required_methods:
            if not hasattr(tool, method):
                errors.append(f"Missing required method: {method}")
            elif not callable(getattr(tool, method)):
                errors.append(f"{method} is not callable")
        
        return errors
    
    @staticmethod
    def validate_plugin(plugin: Any) -> List[str]:
        """Validate plugin interface compliance"""
        errors = []
        
        if not isinstance(plugin, IPlugin):
            errors.append(f"{plugin.__class__.__name__} does not implement IPlugin")
        
        required_methods = ['name', 'version', 'description', 'author',
                          'initialize', 'configure_services', 'cleanup']
        
        for method in required_methods:
            if not hasattr(plugin, method):
                errors.append(f"Missing required method: {method}")
        
        return errors
    
    @staticmethod
    def validate_orchestrator(orchestrator: Any) -> List[str]:
        """Validate orchestrator interface compliance"""
        errors = []
        
        if not isinstance(orchestrator, IOrchestrator):
            errors.append(f"{orchestrator.__class__.__name__} does not implement IOrchestrator")
        
        required_methods = ['initialize', 'start_scan', 'stop_scan', 'pause_scan',
                          'resume_scan', 'get_status', 'get_progress', 'get_results']
        
        for method in required_methods:
            if not hasattr(orchestrator, method):
                errors.append(f"Missing required method: {method}")
        
        return errors


# Standard exceptions for interface implementations
class InterfaceError(Exception):
    """Base exception for interface errors"""
    pass


class ToolNotAvailableError(InterfaceError):
    """Tool is not available for use"""
    pass


class InvalidTargetError(InterfaceError):
    """Target is not valid for this tool"""
    pass


class ScanError(InterfaceError):
    """Error during scanning"""
    pass


class ConfigurationError(InterfaceError):
    """Configuration error"""
    pass


class PluginError(InterfaceError):
    """Plugin-related error"""
    pass
