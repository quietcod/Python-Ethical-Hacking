#!/usr/bin/env python3
"""
Httpx - Clean Architecture
Real fast HTTP probe and analysis implementation
"""

import json
import re
from datetime import datetime
from typing import Dict, List
from .base import RealTool

class HttpxProbe(RealTool):
    """Real Httpx HTTP probing implementation"""
    
    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.command_name = "httpx"
    
    def _execute_real_scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute real Httpx scan against target"""
        try:
            # Unified command building
            cmd = [
                "httpx", "-json", "-u", target, "-status-code", "-title", 
                "-tech-detect", "-server", "-follow-redirects", "-silent",
                "-timeout", str(scan_params.get('timeout', 10)), "-retries", "2",
                "-ports", "80,443,8080,8443,8000"
            ]
            
            # Execute with walrus operator
            if (result := self.execute_command(cmd, timeout=120)).returncode != 0:
                raise Exception(f"Httpx failed with return code {result.returncode}")
            
            # Parse and build results
            probe_results = self._parse_output(result.stdout)
            raw_file = self.save_raw_output(result.stdout, target, 'json')
            
            return {
                'tool': self.tool_name,
                'target': target,
                'status': 'success',
                'timestamp': datetime.now().isoformat(),
                'live_hosts': probe_results,
                'total_live_hosts': len(probe_results),
                'raw_output_file': raw_file,
                'findings': self._extract_findings(probe_results, target)
            }
            
        except Exception as e:
            raise Exception(f"Httpx execution failed: {e}")
    
    def _parse_output(self, output: str) -> List[Dict]:
        """Parse httpx JSON output with single method"""
        results = []
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    if (result := json.loads(line)) and 'url' in result and 'status_code' in result:
                        results.append(result)
                except json.JSONDecodeError:
                    continue
        return results
    
    def _extract_findings(self, probe_results: List[Dict], target: str) -> List[Dict]:
        """Extract findings with unified analysis"""
        if not probe_results:
            return [{'type': 'no_live_hosts', 'description': f'No live HTTP services found for {target}', 'severity': 'info'}]
        
        findings = [{'type': 'live_http_services', 'description': f'Found {len(probe_results)} live HTTP services', 'severity': 'info'}]
        
        for result in probe_results:
            url, status, title = result.get('url', ''), result.get('status_code', 0), result.get('title', '')
            
            # Status code analysis
            if status in [401, 403]:
                findings.append({'type': 'auth_required', 'description': f'{url} requires authentication (HTTP {status})', 'severity': 'medium'})
            elif status in [500, 502, 503]:
                findings.append({'type': 'server_error', 'description': f'{url} server error (HTTP {status})', 'severity': 'low'})
            
            # Title analysis with single regex
            if title and re.search(r'(admin|login|dashboard|panel|control|test|dev|api)', title.lower()):
                findings.append({'type': 'interesting_title', 'description': f'{url} has interesting title: "{title}"', 'severity': 'medium'})
            
            # Technology detection
            if tech := result.get('tech', []):
                findings.append({'type': 'tech_detected', 'description': f'{url} uses: {", ".join(tech)}', 'severity': 'info'})
        
        return findings
