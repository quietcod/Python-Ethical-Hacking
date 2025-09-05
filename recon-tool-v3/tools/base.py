#!/usr/bin/env python3
"""
Base Tool Interface - Clean Architecture
Common interface for all reconnaissance tools with real command execution
"""

import subprocess
import shutil
import json
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from pathlib import Path

class BaseTool(ABC):
    """Base class for all reconnaissance tools with real execution capabilities"""
    
    def __init__(self, config: Dict, logger):
        """Initialize tool with configuration and logger"""
        self.config = config
        self.logger = logger
        self.tool_name = self.__class__.__name__
        self.start_time = None
        self.end_time = None
        self.command_name = getattr(self, 'command_name', self.tool_name.lower())
        self.version = getattr(self, 'version', '1.0.0')
        self.description = getattr(self, 'description', 'Reconnaissance tool')
        self.category = getattr(self, 'category', 'general')
    
    @abstractmethod
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute the tool scan against target"""
        pass
    
    def verify_installation(self) -> bool:
        """Verify if the tool is installed and accessible"""
        try:
            result = shutil.which(self.command_name)
            if result:
                self.logger.debug(f"✅ {self.command_name} found at: {result}")
                return True
            else:
                self.logger.warning(f"❌ {self.command_name} not found in PATH")
                return False
        except Exception as e:
            self.logger.error(f"❌ Error checking {self.command_name} installation: {e}")
            return False
    
    def get_version(self) -> Optional[str]:
        """Get tool version"""
        try:
            version_args = getattr(self, 'version_args', ['--version'])
            result = self.execute_command([self.command_name] + version_args, timeout=10)
            
            if result.returncode == 0:
                version_output = result.stdout.strip()
                self.logger.debug(f"🔍 {self.command_name} version: {version_output}")
                return version_output
            else:
                self.logger.warning(f"⚠️ Could not get {self.command_name} version")
                return None
                
        except Exception as e:
            self.logger.debug(f"Version check failed for {self.command_name}: {e}")
            return None
    
    def execute_command(self, cmd: List[str], timeout: int = 300, capture_output: bool = True) -> subprocess.CompletedProcess:
        """Execute command with proper error handling and timeout"""
        try:
            self.logger.debug(f"🔧 Executing: {' '.join(cmd)}")
            
            # Set up subprocess arguments
            kwargs = {
                'timeout': timeout,
                'text': True,
                'capture_output': capture_output
            }
            
            # Execute command
            result = subprocess.run(cmd, **kwargs)
            
            # Log execution details
            if result.returncode == 0:
                self.logger.debug(f"✅ Command succeeded: {cmd[0]}")
            else:
                self.logger.warning(f"⚠️ Command failed with code {result.returncode}: {cmd[0]}")
                if result.stderr:
                    self.logger.debug(f"Error output: {result.stderr[:500]}")
            
            return result
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"⏰ Command timed out after {timeout}s: {cmd[0]}")
            raise
        except FileNotFoundError:
            self.logger.error(f"🚫 Command not found: {cmd[0]}")
            raise
        except Exception as e:
            self.logger.error(f"❌ Command execution failed: {e}")
            raise
    
    def parse_json_output(self, output: str) -> Dict:
        """Parse JSON output from tools"""
        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            self.logger.error(f"❌ Failed to parse JSON output: {e}")
            return {}
    
    def parse_xml_output(self, output: str) -> ET.Element:
        """Parse XML output from tools"""
        try:
            return ET.fromstring(output)
        except ET.ParseError as e:
            self.logger.error(f"❌ Failed to parse XML output: {e}")
            return None
    
    def save_raw_output(self, output: str, target: str, extension: str = 'txt') -> str:
        """Save raw tool output to file"""
        try:
            output_dir = Path('results') / 'raw_output'
            output_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.command_name}_{target.replace('.', '_')}_{timestamp}.{extension}"
            filepath = output_dir / filename
            
            with open(filepath, 'w') as f:
                f.write(output)
            
            self.logger.debug(f"💾 Raw output saved: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save raw output: {e}")
            return ""
    
    def _start_scan(self, target: str) -> None:
        """Mark scan start and log"""
        self.start_time = datetime.now()
        self.logger.info(f"🔧 Starting {self.tool_name} scan against {target}")
    
    def _end_scan(self, success: bool = True) -> None:
        """Mark scan end and log duration"""
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        status = "✅" if success else "❌"
        self.logger.info(f"{status} {self.tool_name} completed in {duration:.1f}s")
    
    def _log_error(self, error: str) -> None:
        """Log tool error"""
        self.logger.error(f"❌ {self.tool_name} failed: {error}")
    
    def _log_finding(self, finding_type: str, description: str, severity: str = 'info') -> None:
        """Log a finding from this tool"""
        severity_icon = {
            'critical': '🔴',
            'high': '🟠', 
            'medium': '🟡',
            'low': '🔵',
            'info': 'ℹ️'
        }.get(severity, 'ℹ️')
        
        self.logger.info(f"{severity_icon} [{self.tool_name}] {finding_type}: {description}")
    
    def get_tool_info(self) -> Dict:
        """Get comprehensive tool information"""
        return {
            'name': self.tool_name,
            'command': self.command_name,
            'version': self.version,
            'description': self.description,
            'category': self.category,
            'installed': self.verify_installation(),
            'actual_version': self.get_version()
        }

class PlaceholderTool(BaseTool):
    """Placeholder implementation for tools not yet implemented"""
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Generate placeholder scan results"""
        self._start_scan(target)
        
        # Simulate scan time
        import time
        time.sleep(1)
        
        # Generate placeholder results
        results = {
            'tool': self.tool_name,
            'target': target,
            'status': 'placeholder',
            'timestamp': datetime.now().isoformat(),
            'message': f'This is a placeholder implementation for {self.tool_name}',
            'findings': [
                {
                    'type': 'info',
                    'description': f'Placeholder finding 1 for {target}',
                    'severity': 'info'
                },
                {
                    'type': 'info', 
                    'description': f'Placeholder finding 2 for {target}',
                    'severity': 'info'
                }
            ],
            'metadata': {
                'scan_duration': 1.0,
                'implementation_status': 'pending'
            }
        }
        
        # Log placeholder findings
        for finding in results['findings']:
            self._log_finding(finding['type'], finding['description'], finding['severity'])
        
        self._end_scan(success=True)
        return results

class RealTool(BaseTool):
    """Base class for real tool implementations"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.installation_verified = False
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute real tool scan with installation verification"""
        self._start_scan(target)
        
        # Verify installation before execution
        if not self.installation_verified:
            if not self.verify_installation():
                return self._handle_missing_tool(target)
            self.installation_verified = True
        
        try:
            # Execute the actual tool
            results = self._execute_real_scan(target, scan_params)
            self._end_scan(success=True)
            return results
            
        except Exception as e:
            self._log_error(str(e))
            self._end_scan(success=False)
            return self._handle_scan_error(target, str(e))
    
    @abstractmethod
    def _execute_real_scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute the real tool scan - implemented by subclasses"""
        pass
    
    def _handle_missing_tool(self, target: str) -> Dict:
        """Handle case where tool is not installed"""
        return {
            'tool': self.tool_name,
            'target': target,
            'status': 'tool_missing',
            'timestamp': datetime.now().isoformat(),
            'error': f'{self.command_name} is not installed or not found in PATH',
            'install_hint': f'Install {self.command_name} and ensure it is in your PATH',
            'findings': []
        }
    
    def _handle_scan_error(self, target: str, error: str) -> Dict:
        """Handle scan execution errors"""
        return {
            'tool': self.tool_name,
            'target': target,
            'status': 'error',
            'timestamp': datetime.now().isoformat(),
            'error': error,
            'findings': []
        }
