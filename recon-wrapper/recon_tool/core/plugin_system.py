"""
Plugin Loading System
Professional plugin architecture with dynamic loading and management
"""

import importlib
import importlib.util
import inspect
import json
import sys
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Type, Set
from dataclasses import dataclass, asdict
from packaging import version

from .interfaces import IPlugin, InterfaceValidator, PluginError
from .dependency_injection import DIContainer, get_container


@dataclass
class PluginMetadata:
    """Plugin metadata structure"""
    name: str
    version: str
    description: str
    author: str
    min_recon_version: str
    max_recon_version: Optional[str] = None
    dependencies: Optional[List[str]] = None
    entry_point: str = "plugin"
    enabled: bool = True
    priority: int = 100
    category: str = "general"
    tags: Optional[List[str]] = None
    website: Optional[str] = None
    license: Optional[str] = None


@dataclass
class PluginInfo:
    """Complete plugin information"""
    metadata: PluginMetadata
    path: Path
    module: Optional[Any] = None
    instance: Optional[IPlugin] = None
    loaded: bool = False
    initialized: bool = False
    errors: Optional[List[str]] = None


class PluginManager:
    """Professional plugin management system"""
    
    def __init__(self, container: Optional[DIContainer] = None):
        self.container = container or get_container()
        self.plugins: Dict[str, PluginInfo] = {}
        self.plugin_paths: List[Path] = []
        self.enabled_plugins: Set[str] = set()
        self.recon_version = "2.0.0"
        self._lock = threading.RLock()
        
        # Default plugin directories
        self.add_plugin_path(Path(__file__).parent.parent / "plugins")
        self.add_plugin_path(Path.home() / ".recon_tool" / "plugins")
        self.add_plugin_path(Path("/etc/recon_tool/plugins"))
    
    def add_plugin_path(self, path: Path) -> None:
        """Add a directory to search for plugins"""
        if path.exists() and path.is_dir() and path not in self.plugin_paths:
            self.plugin_paths.append(path)
    
    def discover_plugins(self) -> List[PluginInfo]:
        """Discover all available plugins"""
        discovered = []
        
        for plugin_dir in self.plugin_paths:
            if not plugin_dir.exists():
                continue
            
            # Look for plugin directories
            for item in plugin_dir.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    plugin_info = self._discover_plugin(item)
                    if plugin_info:
                        discovered.append(plugin_info)
                        self.plugins[plugin_info.metadata.name] = plugin_info
        
        return discovered
    
    def _discover_plugin(self, plugin_path: Path) -> Optional[PluginInfo]:
        """Discover a single plugin"""
        try:
            # Look for plugin.json metadata
            metadata_file = plugin_path / "plugin.json"
            if not metadata_file.exists():
                return None
            
            # Load metadata
            with open(metadata_file) as f:
                metadata_dict = json.load(f)
            
            metadata = PluginMetadata(**metadata_dict)
            
            # Validate entry point file
            entry_file = plugin_path / f"{metadata.entry_point}.py"
            if not entry_file.exists():
                return None
            
            return PluginInfo(
                metadata=metadata,
                path=plugin_path,
                errors=[]
            )
            
        except Exception as e:
            return PluginInfo(
                metadata=PluginMetadata(
                    name=plugin_path.name,
                    version="unknown",
                    description="Failed to load metadata",
                    author="unknown",
                    min_recon_version="0.0.0"
                ),
                path=plugin_path,
                errors=[f"Discovery failed: {str(e)}"]
            )
    
    def load_plugin(self, plugin_name: str) -> bool:
        """Load a specific plugin"""
        with self._lock:
            if plugin_name not in self.plugins:
                raise PluginError(f"Plugin '{plugin_name}' not found")
            
            plugin_info = self.plugins[plugin_name]
            
            # Check if already loaded
            if plugin_info.loaded:
                return True
            
            try:
                # Validate compatibility
                if not self._check_compatibility(plugin_info.metadata):
                    plugin_info.errors = [f"Incompatible with ReconTool {self.recon_version}"]
                    return False
                
                # Load module
                module = self._load_module(plugin_info)
                if not module:
                    return False
                
                plugin_info.module = module
                
                # Get plugin class
                plugin_class = self._find_plugin_class(module)
                if not plugin_class:
                    plugin_info.errors = ["No valid plugin class found"]
                    return False
                
                # Validate interface compliance
                errors = InterfaceValidator.validate_plugin(plugin_class)
                if errors:
                    plugin_info.errors = errors
                    return False
                
                # Create instance
                plugin_info.instance = plugin_class()
                plugin_info.loaded = True
                
                return True
                
            except Exception as e:
                plugin_info.errors = [f"Load failed: {str(e)}"]
                return False
    
    def _load_module(self, plugin_info: PluginInfo) -> Optional[Any]:
        """Load plugin module"""
        try:
            entry_file = plugin_info.path / f"{plugin_info.metadata.entry_point}.py"
            module_name = f"recon_plugin_{plugin_info.metadata.name}"
            
            # Load module from file
            spec = importlib.util.spec_from_file_location(module_name, entry_file)
            if not spec or not spec.loader:
                return None
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            return module
            
        except Exception as e:
            plugin_info.errors = [f"Module load failed: {str(e)}"]
            return None
    
    def _find_plugin_class(self, module: Any) -> Optional[Type[IPlugin]]:
        """Find the plugin class in the module"""
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, IPlugin) and 
                obj is not IPlugin):
                return obj
        return None
    
    def _check_compatibility(self, metadata: PluginMetadata) -> bool:
        """Check if plugin is compatible with current ReconTool version"""
        try:
            current_version = version.parse(self.recon_version)
            min_version = version.parse(metadata.min_recon_version)
            
            if current_version < min_version:
                return False
            
            if metadata.max_recon_version:
                max_version = version.parse(metadata.max_recon_version)
                if current_version > max_version:
                    return False
            
            return True
            
        except Exception:
            return False
    
    def initialize_plugin(self, plugin_name: str) -> bool:
        """Initialize a loaded plugin"""
        with self._lock:
            if plugin_name not in self.plugins:
                return False
            
            plugin_info = self.plugins[plugin_name]
            
            if not plugin_info.loaded or not plugin_info.instance:
                return False
            
            if plugin_info.initialized:
                return True
            
            try:
                # Initialize plugin
                success = plugin_info.instance.initialize(self.container)
                if not success:
                    plugin_info.errors = ["Plugin initialization failed"]
                    return False
                
                # Configure services
                plugin_info.instance.configure_services(self.container)
                
                plugin_info.initialized = True
                self.enabled_plugins.add(plugin_name)
                
                return True
                
            except Exception as e:
                plugin_info.errors = [f"Initialization failed: {str(e)}"]
                return False
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        with self._lock:
            if plugin_name not in self.plugins:
                return False
            
            plugin_info = self.plugins[plugin_name]
            
            try:
                # Cleanup plugin
                if plugin_info.instance:
                    plugin_info.instance.cleanup()
                
                # Remove from enabled plugins
                self.enabled_plugins.discard(plugin_name)
                
                # Reset plugin state
                plugin_info.loaded = False
                plugin_info.initialized = False
                plugin_info.instance = None
                plugin_info.module = None
                
                return True
                
            except Exception as e:
                plugin_info.errors = [f"Unload failed: {str(e)}"]
                return False
    
    def load_all_plugins(self) -> Dict[str, bool]:
        """Load all discovered plugins"""
        results = {}
        
        # Discover plugins first
        self.discover_plugins()
        
        # Sort by priority
        sorted_plugins = sorted(
            self.plugins.items(),
            key=lambda x: x[1].metadata.priority
        )
        
        for plugin_name, plugin_info in sorted_plugins:
            if plugin_info.metadata.enabled:
                results[plugin_name] = self.load_plugin(plugin_name)
        
        return results
    
    def initialize_all_plugins(self) -> Dict[str, bool]:
        """Initialize all loaded plugins"""
        results = {}
        
        for plugin_name, plugin_info in self.plugins.items():
            if plugin_info.loaded and plugin_info.metadata.enabled:
                results[plugin_name] = self.initialize_plugin(plugin_name)
        
        return results
    
    def get_plugin_info(self, plugin_name: str) -> Optional[PluginInfo]:
        """Get information about a plugin"""
        return self.plugins.get(plugin_name)
    
    def get_all_plugins(self) -> Dict[str, PluginInfo]:
        """Get information about all plugins"""
        return self.plugins.copy()
    
    def get_enabled_plugins(self) -> List[str]:
        """Get list of enabled plugin names"""
        return list(self.enabled_plugins)
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].metadata.enabled = True
            return self.load_plugin(plugin_name) and self.initialize_plugin(plugin_name)
        return False
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].metadata.enabled = False
            return self.unload_plugin(plugin_name)
        return False
    
    def get_plugins_by_category(self, category: str) -> List[PluginInfo]:
        """Get plugins by category"""
        return [
            plugin_info for plugin_info in self.plugins.values()
            if plugin_info.metadata.category == category
        ]
    
    def get_plugins_by_tag(self, tag: str) -> List[PluginInfo]:
        """Get plugins by tag"""
        return [
            plugin_info for plugin_info in self.plugins.values()
            if plugin_info.metadata.tags and tag in plugin_info.metadata.tags
        ]
    
    def export_plugin_list(self, output_path: Path) -> None:
        """Export plugin list to JSON"""
        plugin_data = {}
        
        for name, info in self.plugins.items():
            plugin_data[name] = {
                "metadata": asdict(info.metadata),
                "path": str(info.path),
                "loaded": info.loaded,
                "initialized": info.initialized,
                "errors": info.errors or []
            }
        
        with open(output_path, 'w') as f:
            json.dump(plugin_data, f, indent=2)
    
    def create_plugin_template(self, plugin_name: str, plugin_dir: Path) -> None:
        """Create a template for a new plugin"""
        plugin_path = plugin_dir / plugin_name
        plugin_path.mkdir(parents=True, exist_ok=True)
        
        # Create plugin.json
        metadata = PluginMetadata(
            name=plugin_name,
            version="1.0.0",
            description=f"ReconTool plugin: {plugin_name}",
            author="Plugin Developer",
            min_recon_version="2.0.0",
            entry_point="plugin"
        )
        
        with open(plugin_path / "plugin.json", 'w') as f:
            json.dump(asdict(metadata), f, indent=2)
        
        # Create plugin.py template
        plugin_template = f'''"""
{plugin_name} Plugin
{metadata.description}
"""

from recon_tool.core.interfaces import IPlugin
from recon_tool.core.dependency_injection import DIContainer


class {plugin_name.title()}Plugin(IPlugin):
    """Main plugin class"""
    
    @property
    def name(self) -> str:
        return "{plugin_name}"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def description(self) -> str:
        return "{metadata.description}"
    
    @property
    def author(self) -> str:
        return "{metadata.author}"
    
    def initialize(self, container: DIContainer) -> bool:
        """Initialize the plugin"""
        # Add your initialization code here
        return True
    
    def configure_services(self, container: DIContainer) -> None:
        """Configure services in the DI container"""
        # Register your services here
        # Example: container.register_singleton(IMyService, MyServiceImpl)
        pass
    
    def cleanup(self) -> None:
        """Cleanup plugin resources"""
        # Add cleanup code here
        pass


# Plugin entry point
plugin = {plugin_name.title()}Plugin()
'''
        
        with open(plugin_path / "plugin.py", 'w') as f:
            f.write(plugin_template)
        
        # Create README.md
        readme_content = f'''# {plugin_name} Plugin

{metadata.description}

## Installation

1. Copy this directory to your ReconTool plugins folder
2. Enable the plugin in ReconTool configuration

## Configuration

Add any configuration options here.

## Usage

Describe how to use your plugin.

## Development

This plugin was created using the ReconTool plugin template.
'''
        
        with open(plugin_path / "README.md", 'w') as f:
            f.write(readme_content)


# Global plugin manager instance
_plugin_manager = None
_plugin_manager_lock = threading.Lock()


def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance"""
    global _plugin_manager
    
    with _plugin_manager_lock:
        if _plugin_manager is None:
            _plugin_manager = PluginManager()
        return _plugin_manager


def load_plugins() -> Dict[str, bool]:
    """Load all plugins using global manager"""
    manager = get_plugin_manager()
    return manager.load_all_plugins()


def initialize_plugins() -> Dict[str, bool]:
    """Initialize all plugins using global manager"""
    manager = get_plugin_manager()
    return manager.initialize_all_plugins()


def bootstrap_plugin_system() -> Dict[str, Any]:
    """Bootstrap the entire plugin system"""
    manager = get_plugin_manager()
    
    # Discover plugins
    discovered = manager.discover_plugins()
    
    # Load plugins
    load_results = manager.load_all_plugins()
    
    # Initialize plugins
    init_results = manager.initialize_all_plugins()
    
    return {
        "discovered": len(discovered),
        "load_results": load_results,
        "init_results": init_results,
        "enabled_plugins": manager.get_enabled_plugins()
    }
