#!/usr/bin/env python3
"""
Waybackurls Historical Subdomain Discovery - Optimized for Historical Intelligence
Historical URL and subdomain discovery using waybackurls tool
Specialized for: Historical subdomain discovery, archived URL analysis, timeline-based reconnaissance
"""

import re
from datetime import datetime
from typing import Dict, List, Set
from urllib.parse import urlparse, parse_qs

from .base import BaseTool

class WaybackurlsDiscovery(BaseTool):
    """Optimized Waybackurls for historical subdomain and URL discovery"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "waybackurls"
        self.specialization = "historical_subdomain_discovery"
        
    def scan(self, domain: str, scan_params: Dict) -> Dict:
        """Execute historical waybackurls subdomain discovery"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting WaybackurlsDiscovery HISTORICAL analysis against {domain}")
            
            if not self.verify_installation():
                return self._create_error_result("waybackurls not installed")
            
            # Historical discovery command
            cmd = ['waybackurls', domain]
            
            # Historical analysis options
            if scan_params.get('get_versions', True):
                cmd.append('-get-versions')
            if scan_params.get('dates'):
                cmd.extend(['-dates', scan_params['dates']])
            
            # Execute with extended timeout for historical data retrieval
            result = self.execute_command(cmd, timeout=300)  # 5 minutes for historical analysis
            if result.returncode not in [0, 1]:
                return self._create_error_result(f"Waybackurls historical scan failed: {result.stderr}")
            
            # Parse with focus on subdomain extraction
            findings = self._parse_historical_output(result.stdout, domain)
            self.save_raw_output(result.stdout, domain, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            
            # Historical analysis statistics
            subdomain_count = len([f for f in findings if f.get('type') == 'subdomain'])
            url_count = len([f for f in findings if f.get('type') == 'historical_url'])
            unique_subdomains = len(set(f.get('subdomain') for f in findings if f.get('subdomain')))
            
            self.logger.info(f"✅ WaybackurlsDiscovery HISTORICAL analysis completed in {duration:.1f}s - {unique_subdomains} unique subdomains, {url_count} historical URLs")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'waybackurls_historical_subdomain_discovery',
                'specialization': 'historical_subdomain_discovery',
                'duration': duration,
                'findings': findings,
                'summary': {
                    'total_findings': len(findings),
                    'unique_subdomains': unique_subdomains,
                    'historical_urls': url_count,
                    'subdomain_findings': subdomain_count,
                    'optimization': 'Historical subdomain discovery and archived URL analysis'
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ WaybackurlsDiscovery error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_historical_output(self, output: str, domain: str) -> List[Dict]:
        """Parse waybackurls output with focus on subdomain extraction"""
        findings = []
        seen_subdomains = set()
        seen_urls = set()
        
        for line in output.split('\n'):
            line = line.strip()
            if not line or not line.startswith('http'):
                continue
            
            try:
                parsed_url = urlparse(line)
                hostname = parsed_url.netloc.lower()
                
                # Extract subdomain if it's part of the target domain
                if domain in hostname:
                    if hostname not in seen_subdomains:
                        seen_subdomains.add(hostname)
                        
                        finding = {
                            'type': 'subdomain',
                            'subdomain': hostname,
                            'domain': domain,
                            'source': 'waybackurls_historical',
                            'method': 'historical_discovery',
                            'risk_level': self._assess_historical_risk(hostname, parsed_url.path),
                            'details': f"Historical subdomain discovered in archived URLs"
                        }
                        findings.append(finding)
                
                # Also track interesting historical URLs
                if line not in seen_urls and self._is_interesting_url(parsed_url):
                    seen_urls.add(line)
                    
                    finding = {
                        'type': 'historical_url',
                        'url': line,
                        'subdomain': hostname if domain in hostname else None,
                        'path': parsed_url.path,
                        'query': parsed_url.query,
                        'source': 'waybackurls_historical',
                        'method': 'archived_discovery',
                        'risk_level': self._assess_url_risk(parsed_url),
                        'details': f"Interesting historical URL - {self._categorize_url(parsed_url)}"
                    }
                    findings.append(finding)
                    
            except Exception:
                continue
        
        return findings
    
    def _assess_historical_risk(self, subdomain: str, path: str = '') -> str:
        """Risk assessment for historical subdomains"""
        subdomain_lower = subdomain.lower()
        path_lower = path.lower()
        
        # High-risk historical indicators
        high_risk = ['admin', 'api', 'dev', 'test', 'staging', 'beta', 'internal', 'old', 'legacy']
        if any(indicator in subdomain_lower for indicator in high_risk):
            return 'HIGH'
        
        # Medium-risk for interesting paths
        if any(keyword in path_lower for keyword in ['admin', 'api', 'config', 'backup']):
            return 'MEDIUM'
        
        return 'LOW'
    
    def _is_interesting_url(self, parsed_url) -> bool:
        """Check if URL is interesting for historical analysis"""
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        
        # Interesting patterns
        interesting_patterns = [
            'admin', 'api', 'config', 'backup', 'old', 'legacy', 'test', 'dev',
            '.sql', '.bak', '.backup', '.old', '.env', '.config'
        ]
        
        return any(pattern in path or pattern in query for pattern in interesting_patterns)
    
    def _assess_url_risk(self, parsed_url) -> str:
        """Risk assessment for historical URLs"""
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        
        # High-risk URL patterns
        if any(pattern in path for pattern in ['admin', 'config', 'backup', '.sql', '.env']):
            return 'HIGH'
        
        # Medium-risk patterns
        if any(pattern in path for pattern in ['api', 'test', 'dev', 'old']):
            return 'MEDIUM'
        
        return 'LOW'
    
    def _categorize_url(self, parsed_url) -> str:
        """Categorize URL for better understanding"""
        path = parsed_url.path.lower()
        
        if 'admin' in path:
            return "Administrative interface"
        elif 'api' in path:
            return "API endpoint"
        elif any(ext in path for ext in ['.sql', '.bak', '.backup']):
            return "Backup/database file"
        elif any(keyword in path for keyword in ['config', '.env']):
            return "Configuration file"
        elif any(keyword in path for keyword in ['test', 'dev']):
            return "Development/testing resource"
        else:
            return "Historical resource"
    
    def verify_installation(self) -> bool:
        """Verify waybackurls installation"""
        try:
            result = self.execute_command(['waybackurls', '-h'], timeout=10)
            return result.returncode == 0
        except Exception:
            return False
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'waybackurls_historical_subdomain_discovery',
            'findings': [],
            'summary': {'total_findings': 0}
        }
