#!/usr/bin/env python3
"""
Base Tool Interface - Clean Architecture
Common interface for all reconnaissance tools
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from datetime import datetime

class BaseTool(ABC):
    """Base class for all reconnaissance tools"""
    
    def __init__(self, config: Dict, logger):
        """Initialize tool with configuration and logger"""
        self.config = config
        self.logger = logger
        self.tool_name = self.__class__.__name__
        self.start_time = None
        self.end_time = None
    
    @abstractmethod
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute the tool scan against target"""
        pass
    
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
        """Get tool information"""
        return {
            'name': self.tool_name,
            'version': getattr(self, 'version', '1.0.0'),
            'description': getattr(self, 'description', 'Reconnaissance tool'),
            'category': getattr(self, 'category', 'general')
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
