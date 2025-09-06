#!/usr/bin/env python3
"""
Nikto Web Vulnerability Scanner - Real Implementation
Web application security scanning using Nikto
"""

import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class NiktoScanner(BaseTool):
    """Real Nikto web vulnerability scanner implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "nikto"
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute nikto scan against target"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting NiktoScanner scan against {target}")
            
            if not self.verify_installation():
                return self._create_error_result("Nikto not installed")
            
            # Unified command building
            cmd = ['nikto', '-h', target, '-Format', 'txt', '-nointeractive']
            
            # Add scan options
            if port := scan_params.get('port'):
                cmd.extend(['-p', str(port)])
            if ssl := scan_params.get('ssl'):
                cmd.append('-ssl')
            if timeout := scan_params.get('timeout', 10):
                cmd.extend(['-timeout', str(timeout)])
            
            # Execute with walrus operator
            if (result := self.execute_command(cmd, timeout=600)).returncode not in [0, 1]:
                return self._create_error_result(f"Nikto scan failed: {result.stderr}")
            
            # Parse and build results
            vulnerabilities = self._parse_output(result.stdout, target)
            self.save_raw_output(result.stdout, target, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(f"✅ NiktoScanner completed in {duration:.1f}s - {len(vulnerabilities)} vulnerabilities")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'nikto_web_scan',
                'duration': duration,
                'vulnerabilities': vulnerabilities,
                'summary': {'total_found': len(vulnerabilities)}
            }
            
        except Exception as e:
            self.logger.error(f"❌ NiktoScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_output(self, output: str, target: str) -> List[Dict]:
        """Parse nikto output with unified approach"""
        vulnerabilities = []
        
        for line in output.strip().split('\n'):
            # Parse nikto output format: + <method> <uri>: <description> - <osvdb_id>
            if line.startswith('+ ') and ':' in line:
                try:
                    # Extract method and URI
                    parts = line[2:].split(': ', 1)
                    if len(parts) == 2:
                        method_uri, description = parts
                        
                        # Extract OSVDB ID if present
                        osvdb_id = None
                        if ' - OSVDB-' in description:
                            desc_parts = description.split(' - OSVDB-')
                            description = desc_parts[0]
                            if len(desc_parts) > 1:
                                osvdb_id = desc_parts[1].split()[0]
                        
                        vulnerabilities.append({
                            'method_uri': method_uri.strip(),
                            'description': description.strip(),
                            'osvdb_id': osvdb_id,
                            'target': target,
                            'found_at': datetime.now().isoformat()
                        })
                except:
                    continue
        
        return vulnerabilities
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'nikto_web_scan',
            'vulnerabilities': [],
            'summary': {'total_found': 0}
        }
