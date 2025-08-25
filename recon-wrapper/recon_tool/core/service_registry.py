"""
Service Registration and Configuration
Professional dependency injection setup for ReconTool
"""

from pathlib import Path
from typing import Dict, Any

from .dependency_injection import DIContainer, get_container
from .interfaces import (
    ILogger, IConfigManager, IValidator, IOrchestrator, 
    IStateManager, IResourceMonitor
)
from .logger import ReconLogger
from .enhanced_orchestrator import EnhancedOrchestrator

# Import existing components (these would need to be updated to implement interfaces)
try:
    from ..config import ConfigManager
    from .validators import TargetValidator
    from .state import StateManager
    from .monitor import SystemMonitor
except ImportError:
    # Fallback implementations for missing components
    class ConfigManager:
        def __init__(self, config_file=None):
            self.config = {}
        def get(self, key, default=None):
            return self.config.get(key, default)
        def set(self, key, value):
            self.config[key] = value
        def get_section(self, section):
            return self.config.get(section, {})
        def save(self): pass
        def load(self): pass
    
    class TargetValidator:
        def validate_target(self, target): return True
        def get_target_type(self, target): 
            from .interfaces import TargetType
            return TargetType.DOMAIN
        def normalize_target(self, target): return target
    
    class StateManager:
        def save_state(self, state, name): return True
        def load_state(self, name): return None
        def list_checkpoints(self): return []
        def delete_checkpoint(self, name): return True
    
    class SystemMonitor:
        def start_monitoring(self): pass
        def stop_monitoring(self): pass
        def get_cpu_usage(self): return 0.0
        def get_memory_usage(self): return {"used": 0, "total": 0}
        def get_disk_usage(self): return {"used": 0, "total": 0}
        def get_network_stats(self): return {}


class ServiceConfiguration:
    """Professional service configuration for dependency injection"""
    
    @staticmethod
    def configure_core_services(container: DIContainer) -> None:
        """Configure core ReconTool services"""
        
        # Register configuration manager
        container.register_singleton(
            IConfigManager,
            ConfigManager,
            factory=lambda: ConfigManager()
        )
        
        # Register validator
        container.register_singleton(
            IValidator,
            TargetValidator
        )
        
        # Register state manager
        container.register_scoped(
            IStateManager,
            StateManager
        )
        
        # Register resource monitor
        container.register_singleton(
            IResourceMonitor,
            SystemMonitor
        )
        
        # Register logger with factory
        container.register_singleton(
            ILogger,
            factory=ServiceConfiguration._create_logger
        )
        
        # Register orchestrator
        container.register_scoped(
            IOrchestrator,
            EnhancedOrchestrator
        )
    
    @staticmethod
    def _create_logger() -> ILogger:
        """Factory function for creating logger"""
        container = get_container()
        config_manager = container.resolve(IConfigManager)
        
        # Create output directory for logs
        output_dir = Path("logs")
        output_dir.mkdir(exist_ok=True)
        
        return ReconLogger(output_dir, config_manager)
    
    @staticmethod
    def configure_tool_services(container: DIContainer) -> None:
        """Configure tool services"""
        # This would register all scan tools
        # For now, we'll register placeholder tools
        
        # Tool registration would look like:
        # container.register_transient(IPortScanner, NmapTool)
        # container.register_transient(IWebScanner, NiktoTool)
        # etc.
        
        pass
    
    @staticmethod
    def configure_plugin_services(container: DIContainer) -> None:
        """Configure plugin-related services"""
        from .plugin_system import PluginManager
        
        # Register plugin manager as singleton
        container.register_singleton(
            PluginManager,
            factory=lambda: PluginManager(container)
        )
    
    @staticmethod
    def configure_reporting_services(container: DIContainer) -> None:
        """Configure reporting services"""
        # This would register report generators
        # container.register_transient(IReportGenerator, HTMLReportGenerator)
        # container.register_transient(IReportGenerator, PDFReportGenerator)
        # etc.
        
        pass
    
    @staticmethod
    def configure_all_services(container: DIContainer) -> None:
        """Configure all services in the container"""
        ServiceConfiguration.configure_core_services(container)
        ServiceConfiguration.configure_tool_services(container)
        ServiceConfiguration.configure_plugin_services(container)
        ServiceConfiguration.configure_reporting_services(container)


def bootstrap_application() -> DIContainer:
    """Bootstrap the entire application with dependency injection"""
    container = get_container()
    
    # Configure all services
    ServiceConfiguration.configure_all_services(container)
    
    # Initialize plugin system
    from .plugin_system import bootstrap_plugin_system
    plugin_results = bootstrap_plugin_system()
    
    # Log bootstrap results
    try:
        logger = container.resolve(ILogger)
        logger.info("Application bootstrap completed",
                   plugins_discovered=plugin_results.get("discovered", 0),
                   plugins_enabled=len(plugin_results.get("enabled_plugins", [])))
    except:
        print(f"Application bootstrap completed: {plugin_results}")
    
    return container


class DIServiceLocator:
    """Service locator pattern for easy access to services"""
    
    def __init__(self, container: DIContainer):
        self.container = container
    
    @property
    def logger(self) -> ILogger:
        return self.container.resolve(ILogger)
    
    @property
    def config(self) -> IConfigManager:
        return self.container.resolve(IConfigManager)
    
    @property
    def validator(self) -> IValidator:
        return self.container.resolve(IValidator)
    
    @property
    def orchestrator(self) -> IOrchestrator:
        return self.container.resolve(IOrchestrator)
    
    @property
    def state_manager(self) -> IStateManager:
        return self.container.resolve(IStateManager)
    
    @property
    def resource_monitor(self) -> IResourceMonitor:
        return self.container.resolve(IResourceMonitor)
    
    def create_scope(self, scope_name: str):
        """Create a new DI scope"""
        return self.container.create_scope(scope_name)


# Global service locator
_service_locator = None


def get_services() -> DIServiceLocator:
    """Get the global service locator"""
    global _service_locator
    if _service_locator is None:
        container = bootstrap_application()
        _service_locator = DIServiceLocator(container)
    return _service_locator


def reset_services():
    """Reset the service locator (useful for testing)"""
    global _service_locator
    _service_locator = None


# Convenience functions for common services
def get_logger() -> ILogger:
    """Get the logger service"""
    return get_services().logger


def get_config() -> IConfigManager:
    """Get the configuration service"""
    return get_services().config


def get_orchestrator() -> IOrchestrator:
    """Get the orchestrator service"""
    return get_services().orchestrator
