#!/usr/bin/env python3
"""
Nuclei Vulnerability Scanner - Real Implementation
Template-based vulnerability detection using Project Discovery's Nuclei
"""

import json
import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class NucleiScanner(BaseTool):
    """Real Nuclei vulnerability scanner implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "nuclei"
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute nuclei vulnerability scan against target"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting NucleiScanner scan against {target}")
            
            if not self.verify_installation():
                return self._create_error_result("Nuclei not installed")
            
            # Unified command building
            cmd = ["nuclei", "-target", target, "-j"]
            if template := scan_params.get('template'):
                cmd.extend(["-t", template])
            if severity := scan_params.get('severity'):
                cmd.extend(["-s", severity])
            if limit := scan_params.get('limit'):
                cmd.extend(["-rl", str(limit)])
            
            # Execute with walrus operator
            if (result := self.execute_command(cmd, timeout=300)).returncode != 0:
                return self._create_error_result(f"Nuclei execution failed: {result.stderr}")
            
            # Parse and build results
            vulnerabilities = self._parse_output(result.stdout)
            self.save_raw_output(result.stdout, target, 'json')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(f"✅ NucleiScanner completed in {duration:.1f}s - {len(vulnerabilities)} findings")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'nuclei_vulnerability_scan',
                'duration': duration,
                'vulnerabilities': vulnerabilities,
                'summary': {'total_findings': len(vulnerabilities)}
            }
            
        except Exception as e:
            self.logger.error(f"❌ NucleiScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_output(self, output: str) -> List[Dict]:
        """Parse nuclei JSON output with unified approach"""
        vulnerabilities = []
        
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    if finding := json.loads(line):
                        vulnerabilities.append({
                            'template_id': finding.get('template-id', 'unknown'),
                            'name': finding.get('info', {}).get('name', 'Unknown'),
                            'severity': finding.get('info', {}).get('severity', 'info'),
                            'description': finding.get('info', {}).get('description', ''),
                            'target': finding.get('host', ''),
                            'matched_at': finding.get('matched-at', ''),
                            'timestamp': finding.get('timestamp', datetime.now().isoformat())
                        })
                except json.JSONDecodeError:
                    continue
        
        return vulnerabilities
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'nuclei_vulnerability_scan',
            'vulnerabilities': [],
            'summary': {'total_findings': 0}
        }
