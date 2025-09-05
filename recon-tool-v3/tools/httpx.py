#!/usr/bin/env python3
"""
Httpx - Clean Architecture
Real fast HTTP probe and analysis implementation
"""

import json
from typing import Dict, List
from .base import RealTool

class HttpxProbe(RealTool):
    """Real Httpx HTTP probing implementation"""
    
    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.command_name = "httpx"
        self.version = "1.3.7"
        self.description = "Fast HTTP probe and analysis"
        self.category = "web_discovery"
        self.version_args = ["-version"]
    
    def _execute_real_scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute real Httpx scan against target"""
        
        # Build httpx command
        cmd = self._build_httpx_command(target, scan_params)
        
        # Execute httpx
        try:
            result = self.execute_command(cmd, timeout=120)
            
            if result.returncode != 0:
                raise Exception(f"Httpx failed with return code {result.returncode}")
            
            # Parse JSON output
            probe_results = self._parse_httpx_output(result.stdout, target)
            
            # Save raw output
            raw_file = self.save_raw_output(result.stdout, target, 'json')
            
            # Build results
            results = {
                'tool': self.tool_name,
                'target': target,
                'status': 'success',
                'timestamp': self._get_current_timestamp(),
                'live_hosts': probe_results,
                'total_live_hosts': len(probe_results),
                'raw_output_file': raw_file,
                'findings': self._extract_httpx_findings(probe_results, target)
            }
            
            # Log findings
            self._log_httpx_findings(results)
            
            return results
            
        except Exception as e:
            raise Exception(f"Httpx execution failed: {e}")
    
    def _build_httpx_command(self, target: str, scan_params: Dict) -> List[str]:
        """Build httpx command with comprehensive probing"""
        
        # Base command with JSON output
        cmd = ["httpx", "-json"]
        
        # Add target
        cmd.extend(["-u", target])
        
        # Add common probe options
        cmd.extend([
            "-status-code",      # Include status code
            "-content-length",   # Include content length
            "-title",           # Extract page title
            "-tech-detect",     # Technology detection
            "-server",          # Server header
            "-method",          # HTTP method
            "-follow-redirects", # Follow redirects
            "-silent"           # Silent mode for clean JSON output
        ])
        
        # Add timeout
        timeout = scan_params.get('timeout', 10)
        cmd.extend(["-timeout", str(timeout)])
        
        # Add retries
        cmd.extend(["-retries", "2"])
        
        # Add common ports for comprehensive probing
        cmd.extend(["-ports", "80,443,8080,8443,8000,8888,9000"])
        
        return cmd
    
    def _parse_httpx_output(self, output: str, target: str) -> List[Dict]:
        """Parse httpx JSON output"""
        results = []
        
        if not output.strip():
            return results
        
        # Parse each line as JSON (httpx outputs one JSON object per line)
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                result = json.loads(line)
                if self._is_valid_result(result, target):
                    results.append(result)
            except json.JSONDecodeError as e:
                self.logger.debug(f"Failed to parse httpx line: {line} - {e}")
                continue
        
        return results
    
    def _is_valid_result(self, result: Dict, target: str) -> bool:
        """Validate httpx result"""
        # Should have URL and status code
        if 'url' not in result or 'status_code' not in result:
            return False
        
        # URL should contain target domain
        url = result.get('url', '')
        if target not in url:
            return False
        
        return True
    
    def _extract_httpx_findings(self, probe_results: List[Dict], target: str) -> List[Dict]:
        """Extract findings from httpx probe results"""
        findings = []
        
        if not probe_results:
            findings.append({
                'type': 'no_live_hosts',
                'description': f'No live HTTP services found for {target}',
                'severity': 'info',
                'details': {}
            })
            return findings
        
        # Live hosts finding
        findings.append({
            'type': 'live_http_services',
            'description': f'Found {len(probe_results)} live HTTP services for {target}',
            'severity': 'info',
            'details': {
                'count': len(probe_results),
                'urls': [result.get('url') for result in probe_results]
            }
        })
        
        # Analyze each result for interesting findings
        for result in probe_results:
            url = result.get('url', '')
            status_code = result.get('status_code', 0)
            title = result.get('title', '')
            server = result.get('webserver', '')
            tech = result.get('tech', [])
            
            # Interesting status codes
            if status_code in [401, 403]:
                findings.append({
                    'type': 'authentication_required',
                    'description': f'{url} requires authentication (HTTP {status_code})',
                    'severity': 'medium',
                    'details': result
                })
            
            elif status_code in [500, 502, 503]:
                findings.append({
                    'type': 'server_error',
                    'description': f'{url} returning server error (HTTP {status_code})',
                    'severity': 'low',
                    'details': result
                })
            
            # Interesting titles
            if title:
                interesting_titles = [
                    'admin', 'login', 'dashboard', 'panel', 'control',
                    'test', 'dev', 'staging', 'api', 'swagger'
                ]
                
                if any(keyword in title.lower() for keyword in interesting_titles):
                    findings.append({
                        'type': 'interesting_page_title',
                        'description': f'{url} has interesting title: "{title}"',
                        'severity': 'medium',
                        'details': result
                    })
            
            # Technology detection
            if tech:
                findings.append({
                    'type': 'technology_detection',
                    'description': f'{url} uses technologies: {", ".join(tech)}',
                    'severity': 'info',
                    'details': {
                        'url': url,
                        'technologies': tech
                    }
                })
            
            # Server header analysis
            if server:
                findings.append({
                    'type': 'server_software',
                    'description': f'{url} running {server}',
                    'severity': 'info',
                    'details': {
                        'url': url,
                        'server': server
                    }
                })
        
        return findings
    
    def _log_httpx_findings(self, results: Dict) -> None:
        """Log httpx findings"""
        for finding in results['findings']:
            self._log_finding(finding['type'], finding['description'], finding['severity'])
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
