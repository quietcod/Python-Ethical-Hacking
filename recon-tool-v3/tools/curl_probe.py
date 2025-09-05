#!/usr/bin/env python3
"""
Curl-based Web Prober - Clean Architecture
Simple HTTP probing using curl as alternative to httpx
"""

import json
import re
from typing import Dict, List
from .base import RealTool

class CurlProbe(RealTool):
    """Curl-based HTTP probing implementation"""
    
    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.command_name = "curl"
        self.version = "7.68.0"
        self.description = "HTTP probing using curl"
        self.category = "web_discovery"
        self.version_args = ["--version"]
    
    def _execute_real_scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute curl-based HTTP probing"""
        
        # Test common HTTP/HTTPS endpoints
        urls_to_test = [
            f"http://{target}",
            f"https://{target}",
            f"http://www.{target}",
            f"https://www.{target}"
        ]
        
        live_hosts = []
        
        # Test each URL
        for url in urls_to_test:
            try:
                result = self._probe_url(url)
                if result:
                    live_hosts.append(result)
            except Exception as e:
                self.logger.debug(f"Failed to probe {url}: {e}")
        
        # Build results
        results = {
            'tool': self.tool_name,
            'target': target,
            'status': 'success',
            'timestamp': self._get_current_timestamp(),
            'urls_tested': urls_to_test,
            'live_hosts': live_hosts,
            'total_live_hosts': len(live_hosts),
            'findings': self._extract_curl_findings(live_hosts, target)
        }
        
        # Log findings
        self._log_curl_findings(results)
        
        return results
    
    def _probe_url(self, url: str) -> Dict:
        """Probe a single URL with curl"""
        
        # Build curl command for detailed probing
        cmd = [
            "curl", "-s", "-I",  # Silent, head request only
            "--max-time", "10",   # 10 second timeout
            "--connect-timeout", "5",  # 5 second connect timeout
            "-L",                 # Follow redirects
            "-w", "STATUS_CODE:%{http_code}\\nCONTENT_LENGTH:%{size_download}\\nTOTAL_TIME:%{time_total}\\n",
            url
        ]
        
        try:
            result = self.execute_command(cmd, timeout=15)
            
            if result.returncode == 0:
                return self._parse_curl_response(url, result.stdout)
            else:
                self.logger.debug(f"Curl failed for {url}: return code {result.returncode}")
                return None
                
        except Exception as e:
            self.logger.debug(f"Curl probe failed for {url}: {e}")
            return None
    
    def _parse_curl_response(self, url: str, output: str) -> Dict:
        """Parse curl response"""
        
        # Extract status code from curl output
        status_match = re.search(r'STATUS_CODE:(\d+)', output)
        status_code = int(status_match.group(1)) if status_match else 0
        
        # Extract content length
        length_match = re.search(r'CONTENT_LENGTH:(\d+)', output)
        content_length = int(length_match.group(1)) if length_match else 0
        
        # Extract total time
        time_match = re.search(r'TOTAL_TIME:([\d.]+)', output)
        total_time = float(time_match.group(1)) if time_match else 0
        
        # Extract server header
        server_match = re.search(r'Server:\s*([^\r\n]+)', output, re.IGNORECASE)
        server = server_match.group(1).strip() if server_match else ""
        
        # Extract content type
        content_type_match = re.search(r'Content-Type:\s*([^\r\n]+)', output, re.IGNORECASE)
        content_type = content_type_match.group(1).strip() if content_type_match else ""
        
        return {
            'url': url,
            'status_code': status_code,
            'content_length': content_length,
            'response_time': total_time,
            'server': server,
            'content_type': content_type,
            'accessible': status_code > 0 and status_code < 400
        }
    
    def _extract_curl_findings(self, probe_results: List[Dict], target: str) -> List[Dict]:
        """Extract findings from curl probe results"""
        findings = []
        
        if not probe_results:
            findings.append({
                'type': 'no_live_hosts',
                'description': f'No live HTTP services found for {target}',
                'severity': 'info',
                'details': {}
            })
            return findings
        
        # Accessible services
        accessible = [r for r in probe_results if r.get('accessible', False)]
        if accessible:
            findings.append({
                'type': 'live_http_services',
                'description': f'Found {len(accessible)} accessible HTTP services',
                'severity': 'info',
                'details': {
                    'count': len(accessible),
                    'urls': [r['url'] for r in accessible]
                }
            })
        
        # Analyze each accessible service
        for result in accessible:
            url = result.get('url')
            status_code = result.get('status_code')
            server = result.get('server', '')
            
            # Server software detection
            if server:
                findings.append({
                    'type': 'server_software',
                    'description': f'{url} running {server}',
                    'severity': 'info',
                    'details': result
                })
            
            # HTTPS availability
            if url.startswith('https://'):
                findings.append({
                    'type': 'https_available',
                    'description': f'HTTPS available on {url}',
                    'severity': 'info',
                    'details': result
                })
        
        return findings
    
    def _log_curl_findings(self, results: Dict) -> None:
        """Log curl findings"""
        for finding in results['findings']:
            self._log_finding(finding['type'], finding['description'], finding['severity'])
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
