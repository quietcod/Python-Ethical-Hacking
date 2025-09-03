"""
Tool Loader - Dynamic Tool Import Manager
Handles robust importing of reconnaissance tool classes
"""

import os
import sys
import importlib
import importlib.util
from pathlib import Path
from typing import Dict, Any, Optional, Type


class ToolLoader:
    """Dynamic tool loader that handles various import scenarios"""
    
    def __init__(self):
        self.loaded_tools = {}
        self.tool_paths = {
            'PortScanner': 'recon_tool/tools/network/port_scanner.py',
            'SubdomainEnumerator': 'recon_tool/tools/web/subdomain_enumerator.py',
            'WebScanner': 'recon_tool/tools/web/web_scanner.py',
            'SSLScanner': 'recon_tool/tools/network/ssl_scanner.py',
            'DNSScanner': 'recon_tool/tools/network/dns_scanner.py',
            'DirectoryScanner': 'recon_tool/tools/web/directory_scanner.py',
            'VulnerabilityScanner': 'recon_tool/tools/security/vulnerability_scanner.py',
            'OSINTCollector': 'recon_tool/tools/osint/osint_collector.py'
        }
    
    def load_tool(self, tool_name: str) -> Optional[Type]:
        """Load a specific tool class by name"""
        if tool_name in self.loaded_tools:
            return self.loaded_tools[tool_name]
        
        # Try different import methods
        tool_class = None
        
        # Method 1: Standard module import
        tool_class = self._try_standard_import(tool_name)
        
        # Method 2: Direct file import
        if tool_class is None:
            tool_class = self._try_file_import(tool_name)
        
        # Method 3: Path manipulation import
        if tool_class is None:
            tool_class = self._try_path_import(tool_name)
        
        if tool_class is not None:
            self.loaded_tools[tool_name] = tool_class
            print(f"✅ {tool_name} loaded successfully")
        else:
            print(f"❌ {tool_name} failed to load")
        
        return tool_class
    
    def _try_standard_import(self, tool_name: str) -> Optional[Type]:
        """Try standard module import"""
        try:
            module_map = {
                'PortScanner': 'recon_tool.tools.network.port_scanner',
                'SubdomainEnumerator': 'recon_tool.tools.web.subdomain_enumerator',
                'WebScanner': 'recon_tool.tools.web.web_scanner',
                'SSLScanner': 'recon_tool.tools.network.ssl_scanner',
                'DNSScanner': 'recon_tool.tools.network.dns_scanner',
                'DirectoryScanner': 'recon_tool.tools.web.directory_scanner',
                'VulnerabilityScanner': 'recon_tool.tools.security.vulnerability_scanner',
                'OSINTCollector': 'recon_tool.tools.osint.osint_collector'
            }
            
            if tool_name in module_map:
                module = importlib.import_module(module_map[tool_name])
                return getattr(module, tool_name)
                
        except (ImportError, AttributeError) as e:
            print(f"Standard import failed for {tool_name}: {e}")
        
        return None
    
    def _try_file_import(self, tool_name: str) -> Optional[Type]:
        """Try direct file import using importlib.util"""
        try:
            if tool_name not in self.tool_paths:
                return None
            
            # Get current working directory
            current_dir = Path.cwd()
            tool_file = current_dir / self.tool_paths[tool_name]
            
            if not tool_file.exists():
                # Try relative to this file
                current_file_dir = Path(__file__).parent
                tool_file = current_file_dir.parent / self.tool_paths[tool_name].replace('recon_tool/', '')
            
            if not tool_file.exists():
                return None
            
            # Load module from file
            spec = importlib.util.spec_from_file_location(f"{tool_name}_module", tool_file)
            if spec is None or spec.loader is None:
                return None
                
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            return getattr(module, tool_name)
            
        except Exception as e:
            print(f"File import failed for {tool_name}: {e}")
        
        return None
    
    def _try_path_import(self, tool_name: str) -> Optional[Type]:
        """Try import with modified sys.path"""
        try:
            # Add various paths to sys.path
            current_dir = Path(__file__).parent
            possible_paths = [
                current_dir.parent,  # recon_tool directory
                current_dir.parent.parent,  # project root
                Path.cwd(),  # current working directory
            ]
            
            original_path = sys.path.copy()
            
            for path in possible_paths:
                if str(path) not in sys.path:
                    sys.path.insert(0, str(path))
            
            try:
                # Try relative imports
                module_map = {
                    'PortScanner': 'tools.network.port_scanner',
                    'SubdomainEnumerator': 'tools.web.subdomain_enumerator',
                    'WebScanner': 'tools.web.web_scanner',
                    'SSLScanner': 'tools.network.ssl_scanner',
                    'DNSScanner': 'tools.network.dns_scanner',
                    'DirectoryScanner': 'tools.web.directory_scanner',
                    'VulnerabilityScanner': 'tools.security.vulnerability_scanner',
                    'OSINTCollector': 'tools.osint.osint_collector'
                }
                
                if tool_name in module_map:
                    module = importlib.import_module(module_map[tool_name])
                    return getattr(module, tool_name)
                    
            finally:
                # Restore original sys.path
                sys.path = original_path
                
        except Exception as e:
            print(f"Path import failed for {tool_name}: {e}")
        
        return None
    
    def load_all_tools(self) -> Dict[str, Optional[Type]]:
        """Load all tool classes"""
        print("🔧 Loading tool classes...")
        
        tools = {}
        for tool_name in self.tool_paths.keys():
            tools[tool_name] = self.load_tool(tool_name)
        
        successful_loads = len([t for t in tools.values() if t is not None])
        total_tools = len(tools)
        
        print(f"📊 Tool loading summary: {successful_loads}/{total_tools} tools loaded successfully")
        
        return tools
    
    def get_tool_status(self) -> Dict[str, bool]:
        """Get the status of all tools"""
        status = {}
        for tool_name in self.tool_paths.keys():
            status[tool_name] = tool_name in self.loaded_tools and self.loaded_tools[tool_name] is not None
        return status


# Global tool loader instance
_tool_loader = ToolLoader()


def get_tool_class(tool_name: str) -> Optional[Type]:
    """Get a tool class by name"""
    return _tool_loader.load_tool(tool_name)


def load_all_tools() -> Dict[str, Optional[Type]]:
    """Load all available tool classes"""
    return _tool_loader.load_all_tools()


def get_tool_status() -> Dict[str, bool]:
    """Get the loading status of all tools"""
    return _tool_loader.get_tool_status()
