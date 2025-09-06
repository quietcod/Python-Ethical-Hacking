#!/usr/bin/env python3
"""
Curl-based Web Prober - Streamlined Implementation
Minimal HTTP probing using curl as alternative to httpx
"""

import re
from datetime import datetime
from typing import Dict, List
from .base import RealTool

class CurlProbe(RealTool):
    """Streamlined Curl-based HTTP probing implementation"""
    
    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.command_name = "curl"
        self.description = "HTTP probing using curl"
        self.category = "web_discovery"
        
        # Minimal configuration
        self.timeout = config.get('timeout', 10)
    
    def _execute_real_scan(self, target: str, scan_params: Dict = None) -> Dict:
        """Execute curl-based HTTP probing"""
        if scan_params is None:
            scan_params = {}
            
        start_time = datetime.now()
        
        # Generate and probe URLs
        urls = self._get_urls(target, scan_params.get('scan_type', 'standard'))
        live_hosts = [result for url in urls if (result := self._probe_url(url))]
        
        return self._build_result(target, urls, live_hosts, start_time)
    
    def _get_urls(self, target: str, scan_type: str) -> List[str]:
        """Generate URLs based on scan type"""
        url_patterns = {
            'quick': [f"http://{target}", f"https://{target}"],
            'standard': [f"http://{target}", f"https://{target}", 
                        f"http://www.{target}", f"https://www.{target}"],
            'comprehensive': [f"http://{target}", f"https://{target}",
                             f"http://www.{target}", f"https://www.{target}",
                             f"http://mail.{target}", f"https://mail.{target}"]
        }
        return url_patterns.get(scan_type, url_patterns['standard'])
    
    def _probe_url(self, url: str) -> Dict:
        """Probe single URL with curl"""
        cmd = ["curl", "-s", "-I", "--max-time", str(self.timeout),
               "-w", "STATUS:%{http_code}|TIME:%{time_total}", url]
        
        try:
            result = self.execute_command(cmd, timeout=self.timeout + 2)
            if result.returncode != 0:
                return None
                
            # Parse response efficiently
            output = result.stdout
            status_match = re.search(r'STATUS:(\d+)', output)
            time_match = re.search(r'TIME:([\d.]+)', output)
            server_match = re.search(r'Server:\s*([^\r\n]+)', output, re.IGNORECASE)
            
            status_code = int(status_match.group(1)) if status_match else 0
            if not (200 <= status_code < 400):
                return None
                
            return {
                'url': url,
                'status_code': status_code,
                'response_time': float(time_match.group(1)) if time_match else 0,
                'server': server_match.group(1).strip() if server_match else '',
                'https': url.startswith('https://')
            }
            
        except Exception:
            return None
    
    def _build_result(self, target: str, urls: List[str], live_hosts: List[Dict], start_time: datetime) -> Dict:
        """Build result with summary"""
        duration = (datetime.now() - start_time).total_seconds()
        https_count = sum(1 for h in live_hosts if h['https'])
        servers = {h['server'] for h in live_hosts if h['server']}
        
        self.logger.info(f"✅ CurlProbe: {len(live_hosts)}/{len(urls)} hosts accessible "
                        f"({https_count} HTTPS, {len(servers)} unique servers)")
        
        return {
            'status': 'success',
            'target': target,
            'duration': duration,
            'live_hosts': live_hosts,
            'summary': {
                'total_tested': len(urls),
                'total_accessible': len(live_hosts),
                'https_available': https_count,
                'unique_servers': len(servers),
                'servers': list(servers)
            }
        }
    
    # Convenience methods
    def quick_probe(self, target: str) -> Dict:
        """Quick HTTP/HTTPS probe"""
        return self._execute_real_scan(target, {'scan_type': 'quick'})
