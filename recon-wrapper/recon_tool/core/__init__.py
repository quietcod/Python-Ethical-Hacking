"""
Core Module
Core functionality for the ReconTool package
"""

# Import core utilities and exceptions first
from .exceptions import *
from .utils import *
from .validators import InputValidator, ConfigValidator

# Try to import other modules, but don't fail if they have issues
try:
    from .logger import setup_logger, ReconLogger
except ImportError as e:
    print(f"Warning: Logger import failed: {e}")
    setup_logger = None
    ReconLogger = None

try:
    from .state import StateManager
except ImportError as e:
    print(f"Warning: State manager import failed: {e}")
    StateManager = None

try:
    from .monitor import SystemMonitor
except ImportError as e:
    print(f"Warning: Monitor import failed: {e}")
    SystemMonitor = None

# Only import orchestrator if other components are available
try:
    # Use simple orchestrator that works with current structure
    from .simple_orchestrator import ReconOrchestrator
    print("Using SimpleOrchestrator (development mode)")
except ImportError as e:
    print(f"Warning: Simple orchestrator import failed: {e}")
    try:
        # Fallback to full orchestrator if available
        if all([setup_logger, StateManager, SystemMonitor]):
            from .orchestrator import ReconOrchestrator
        else:
            ReconOrchestrator = None
    except ImportError as e:
        print(f"Warning: Orchestrator import failed: {e}")
        ReconOrchestrator = None

__all__ = [
    # Core classes (if available)
    'ReconOrchestrator',
    'ReconLogger', 
    'StateManager',
    'SystemMonitor',
    'InputValidator',
    'ConfigValidator',
    'setup_logger',
    
    # Exceptions
    'ReconToolError',
    'ConfigurationError',
    'ValidationError',
    'ToolNotFoundError',
    'NetworkError',
    'ScanError',
    'ParsingError',
    'FileSystemError',
    'ExecutionError',
    'ResourceError',
    'TimeoutError',
    'PermissionError',
    'PluginError',
    'StateError',
    'DependencyError',
    
    # Utilities (from utils.py)
    'is_valid_ip',
    'is_valid_cidr',
    'is_valid_domain',
    'is_valid_url',
    'expand_ip_range',
    'resolve_hostname',
    'reverse_dns_lookup',
    'run_command',
    'run_command_async',
    'check_tool_installed',
    'get_missing_tools',
    'format_file_size',
    'format_duration',
    'generate_scan_id',
    'calculate_file_hash',
    'safe_filename',
    'create_directory_structure',
    'merge_dictionaries',
    'sanitize_input',
    'parse_port_range',
    'get_local_ip',
    'is_port_open',
    'get_timestamp',
    'parse_timestamp',
    'ProgressTracker'
]
