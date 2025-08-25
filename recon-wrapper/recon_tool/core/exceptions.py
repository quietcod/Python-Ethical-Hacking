"""
Custom Exceptions
Application-specific exception classes
"""


class ReconToolError(Exception):
    """Base exception for ReconTool errors"""
    
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "UNKNOWN_ERROR"
        self.details = details or {}
    
    def __str__(self):
        return f"[{self.error_code}] {self.message}"


class ConfigurationError(ReconToolError):
    """Raised when there's a configuration error"""
    
    def __init__(self, message: str, config_key: str = None, **kwargs):
        super().__init__(message, "CONFIG_ERROR", kwargs)
        self.config_key = config_key


class ValidationError(ReconToolError):
    """Raised when input validation fails"""
    
    def __init__(self, message: str, field: str = None, value: str = None, **kwargs):
        details = kwargs.copy()
        if field:
            details["field"] = field
        if value:
            details["value"] = value
        super().__init__(message, "VALIDATION_ERROR", details)
        self.field = field
        self.value = value


class ToolNotFoundError(ReconToolError):
    """Raised when a required tool is not installed"""
    
    def __init__(self, tool_name: str, **kwargs):
        message = f"Required tool '{tool_name}' is not installed or not in PATH"
        super().__init__(message, "TOOL_NOT_FOUND", kwargs)
        self.tool_name = tool_name


class NetworkError(ReconToolError):
    """Raised when there's a network-related error"""
    
    def __init__(self, message: str, host: str = None, port: int = None, **kwargs):
        details = kwargs.copy()
        if host:
            details["host"] = host
        if port:
            details["port"] = port
        super().__init__(message, "NETWORK_ERROR", details)
        self.host = host
        self.port = port


class ScanError(ReconToolError):
    """Raised when a scan operation fails"""
    
    def __init__(self, message: str, scan_type: str = None, target: str = None, **kwargs):
        details = kwargs.copy()
        if scan_type:
            details["scan_type"] = scan_type
        if target:
            details["target"] = target
        super().__init__(message, "SCAN_ERROR", details)
        self.scan_type = scan_type
        self.target = target


class ParsingError(ReconToolError):
    """Raised when parsing output fails"""
    
    def __init__(self, message: str, parser: str = None, output: str = None, **kwargs):
        details = kwargs.copy()
        if parser:
            details["parser"] = parser
        if output:
            details["output"] = output[:500]  # Limit output length
        super().__init__(message, "PARSING_ERROR", details)
        self.parser = parser
        self.output = output


class FileSystemError(ReconToolError):
    """Raised when there's a file system error"""
    
    def __init__(self, message: str, path: str = None, operation: str = None, **kwargs):
        details = kwargs.copy()
        if path:
            details["path"] = path
        if operation:
            details["operation"] = operation
        super().__init__(message, "FILESYSTEM_ERROR", details)
        self.path = path
        self.operation = operation


class ExecutionError(ReconToolError):
    """Raised when command execution fails"""
    
    def __init__(self, message: str, command: str = None, return_code: int = None, 
                 stdout: str = None, stderr: str = None, **kwargs):
        details = kwargs.copy()
        if command:
            details["command"] = command
        if return_code is not None:
            details["return_code"] = return_code
        if stdout:
            details["stdout"] = stdout[:500]  # Limit output length
        if stderr:
            details["stderr"] = stderr[:500]
        super().__init__(message, "EXECUTION_ERROR", details)
        self.command = command
        self.return_code = return_code
        self.stdout = stdout
        self.stderr = stderr


class ResourceError(ReconToolError):
    """Raised when there's a resource-related error"""
    
    def __init__(self, message: str, resource_type: str = None, **kwargs):
        details = kwargs.copy()
        if resource_type:
            details["resource_type"] = resource_type
        super().__init__(message, "RESOURCE_ERROR", details)
        self.resource_type = resource_type


class TimeoutError(ReconToolError):
    """Raised when an operation times out"""
    
    def __init__(self, message: str, timeout: float = None, operation: str = None, **kwargs):
        details = kwargs.copy()
        if timeout:
            details["timeout"] = timeout
        if operation:
            details["operation"] = operation
        super().__init__(message, "TIMEOUT_ERROR", details)
        self.timeout = timeout
        self.operation = operation


class PermissionError(ReconToolError):
    """Raised when there's a permission error"""
    
    def __init__(self, message: str, path: str = None, required_permission: str = None, **kwargs):
        details = kwargs.copy()
        if path:
            details["path"] = path
        if required_permission:
            details["required_permission"] = required_permission
        super().__init__(message, "PERMISSION_ERROR", details)
        self.path = path
        self.required_permission = required_permission


class PluginError(ReconToolError):
    """Raised when there's a plugin-related error"""
    
    def __init__(self, message: str, plugin_name: str = None, **kwargs):
        details = kwargs.copy()
        if plugin_name:
            details["plugin_name"] = plugin_name
        super().__init__(message, "PLUGIN_ERROR", details)
        self.plugin_name = plugin_name


class StateError(ReconToolError):
    """Raised when there's a state management error"""
    
    def __init__(self, message: str, state: str = None, **kwargs):
        details = kwargs.copy()
        if state:
            details["state"] = state
        super().__init__(message, "STATE_ERROR", details)
        self.state = state


class DependencyError(ReconToolError):
    """Raised when there's a dependency error"""
    
    def __init__(self, message: str, dependency: str = None, **kwargs):
        details = kwargs.copy()
        if dependency:
            details["dependency"] = dependency
        super().__init__(message, "DEPENDENCY_ERROR", details)
        self.dependency = dependency


# Exception handler decorator
def handle_exceptions(default_return=None, reraise=False):
    """Decorator to handle exceptions in functions"""
    
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except ReconToolError:
                if reraise:
                    raise
                return default_return
            except Exception as e:
                if reraise:
                    raise ReconToolError(f"Unexpected error in {func.__name__}: {str(e)}")
                return default_return
        return wrapper
    return decorator


# Context manager for error handling
class ErrorHandler:
    """Context manager for error handling"""
    
    def __init__(self, logger=None, reraise=True, default_return=None):
        self.logger = logger
        self.reraise = reraise
        self.default_return = default_return
        self.exception = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.exception = exc_val
            
            if self.logger:
                if isinstance(exc_val, ReconToolError):
                    self.logger.error(f"{exc_val.error_code}: {exc_val.message}")
                else:
                    self.logger.error(f"Unexpected error: {str(exc_val)}")
            
            if not self.reraise:
                return True  # Suppress the exception
        
        return False
    
    def get_result(self):
        """Get result if exception was suppressed"""
        if self.exception and not self.reraise:
            return self.default_return
        return None
