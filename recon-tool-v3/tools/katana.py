#!/usr/bin/env python3
"""
Katana Web Crawler - Optimized for Active Subdomain Crawling
Fast web crawling, endpoint discovery, and active subdomain enumeration using katana
Specialized for: Active subdomain crawling, live endpoint discovery, dynamic reconnaissance
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Set
from urllib.parse import urlparse

from .base import BaseTool

class KatanaCrawler(BaseTool):
    """Optimized Katana for active subdomain crawling and dynamic endpoint discovery"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "katana"
        self.specialization = "active_subdomain_crawling"
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute ACTIVE subdomain crawling optimized for dynamic discovery"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"�️ Starting KatanaCrawler ACTIVE subdomain crawling against {target}")
            
            if not self.verify_installation():
                return self._create_error_result("katana not installed")
            
            # ACTIVE SUBDOMAIN CRAWLING optimized command building
            crawl_mode = scan_params.get('crawl_mode', 'subdomain_focused')
            
            # Subdomain-focused crawling profiles
            crawl_profiles = {
                'subdomain_focused': ['-js-crawl', '-form-extraction', '-depth', '3'],
                'deep_discovery': ['-js-crawl', '-form-extraction', '-depth', '5', '-timeout', '60'],
                'javascript_heavy': ['-js-crawl', '-js-parse', '-depth', '4'],
                'comprehensive': ['-js-crawl', '-form-extraction', '-depth', '6', '-passive']
            }
            
            cmd = ['katana', '-u', target]
            cmd.extend(crawl_profiles.get(crawl_mode, crawl_profiles['subdomain_focused']))
            
            # Active subdomain discovery optimizations
            cmd.extend(['-output', '/tmp/katana_output.txt', '-json'])
            
            # Enhanced crawling for subdomain discovery
            if scan_params.get('aggressive_crawling', True):
                cmd.extend(['-concurrency', '20'])  # Higher concurrency for speed
                cmd.extend(['-timeout', '30'])      # Balanced timeout
            
            # JavaScript analysis for subdomain discovery
            if scan_params.get('js_analysis', True):
                cmd.extend(['-js-parse'])
            
            # Form extraction for potential subdomain references
            if scan_params.get('form_extraction', True):
                cmd.extend(['-form-extraction'])
            
            # Custom headers for better access
            default_headers = [
                'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            ]
            headers = scan_params.get('headers', default_headers)
            for header in headers:
                cmd.extend(['-header', header])
            
            # Extended timeout for comprehensive crawling
            timeout = scan_params.get('timeout', 900)  # 15 minutes for active crawling
            
            # Execute active crawling
            result = self.execute_command(cmd, timeout=timeout)
            if result.returncode != 0:
                return self._create_error_result(f"Katana active subdomain crawling failed: {result.stderr}")
            
            # Parse with active subdomain discovery focus
            findings = self._parse_active_subdomain_output(result.stdout, target, crawl_mode)
            self.save_raw_output(result.stdout, target, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            
            # Active subdomain crawling statistics
            subdomains_found = len([f for f in findings if f.get('type') == 'subdomain'])
            endpoints_found = len([f for f in findings if f.get('type') == 'endpoint'])
            js_files_found = len([f for f in findings if f.get('type') == 'javascript_file'])
            
            self.logger.info(f"🕷️ KatanaCrawler ACTIVE subdomain crawling completed in {duration:.1f}s - {subdomains_found} subdomains, {endpoints_found} endpoints, {js_files_found} JS files")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'katana_active_subdomain_crawling',
                'specialization': 'active_subdomain_crawling',
                'duration': duration,
                'findings': findings,
                'summary': {
                    'total_findings': len(findings),
                    'subdomains_discovered': subdomains_found,
                    'endpoints_discovered': endpoints_found,
                    'javascript_files': js_files_found,
                    'crawl_mode': crawl_mode,
                    'optimization': 'Active subdomain crawling and dynamic endpoint discovery'
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ KatanaCrawler error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_active_subdomain_output(self, output: str, target: str, crawl_mode: str) -> List[Dict]:
        """Parse katana output with focus on active subdomain discovery"""
        findings = []
        seen_subdomains = set()
        seen_endpoints = set()
        seen_js_files = set()
        
        # Try to parse JSON output first
        try:
            with open('/tmp/katana_output.txt', 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        url = data.get('url', '')
                        if not url:
                            continue
                        
                        parsed_url = urlparse(url)
                        hostname = parsed_url.netloc.lower()
                        
                        # Extract subdomain if it's part of the target domain
                        if target in hostname and hostname not in seen_subdomains:
                            seen_subdomains.add(hostname)
                            
                            finding = {
                                'type': 'subdomain',
                                'subdomain': hostname,
                                'domain': target,
                                'url': url,
                                'method': data.get('method', 'GET'),
                                'status_code': data.get('status_code', 0),
                                'source': 'katana_active_crawl',
                                'method_discovery': 'active_crawling',
                                'risk_level': self._assess_subdomain_risk(hostname, parsed_url.path),
                                'details': f"Active subdomain discovered via crawling - Status: {data.get('status_code', 'unknown')}"
                            }
                            findings.append(finding)
                        
                        # Extract interesting endpoints
                        endpoint_key = f"{hostname}{parsed_url.path}"
                        if endpoint_key not in seen_endpoints and self._is_interesting_endpoint(parsed_url):
                            seen_endpoints.add(endpoint_key)
                            
                            finding = {
                                'type': 'endpoint',
                                'url': url,
                                'path': parsed_url.path,
                                'method': data.get('method', 'GET'),
                                'status_code': data.get('status_code', 0),
                                'content_type': data.get('content_type', ''),
                                'source': 'katana_active_crawl',
                                'method_discovery': 'endpoint_crawling',
                                'risk_level': self._assess_endpoint_risk(parsed_url),
                                'details': f"Interesting endpoint discovered - {self._categorize_endpoint(parsed_url)}"
                            }
                            findings.append(finding)
                        
                        # Extract JavaScript files for potential subdomain references
                        if parsed_url.path.endswith('.js') and url not in seen_js_files:
                            seen_js_files.add(url)
                            
                            finding = {
                                'type': 'javascript_file',
                                'url': url,
                                'filename': parsed_url.path.split('/')[-1],
                                'status_code': data.get('status_code', 0),
                                'content_length': data.get('content_length', 0),
                                'source': 'katana_active_crawl',
                                'method_discovery': 'js_discovery',
                                'risk_level': 'LOW',
                                'details': f"JavaScript file discovered - potential subdomain references"
                            }
                            findings.append(finding)
                            
                    except (json.JSONDecodeError, KeyError):
                        continue
                        
        except FileNotFoundError:
            # Fallback to parsing stdout if file not found
            self.logger.warning("Katana output file not found, parsing stdout")
            
        # Also parse stdout as fallback
        for line in output.split('\n'):
            line = line.strip()
            if line and line.startswith('http'):
                try:
                    parsed_url = urlparse(line)
                    hostname = parsed_url.netloc.lower()
                    
                    if target in hostname and hostname not in seen_subdomains:
                        seen_subdomains.add(hostname)
                        
                        finding = {
                            'type': 'subdomain',
                            'subdomain': hostname,
                            'domain': target,
                            'url': line,
                            'source': 'katana_active_crawl_stdout',
                            'method_discovery': 'active_crawling_fallback',
                            'risk_level': self._assess_subdomain_risk(hostname, parsed_url.path),
                            'details': "Active subdomain discovered via crawling (stdout parsing)"
                        }
                        findings.append(finding)
                        
                except Exception:
                    continue
        
        return findings
    
    def _assess_subdomain_risk(self, subdomain: str, path: str = '') -> str:
        """Risk assessment for discovered subdomains"""
        subdomain_lower = subdomain.lower()
        path_lower = path.lower()
        
        # High-risk subdomain patterns
        high_risk = ['admin', 'api', 'dev', 'test', 'staging', 'beta', 'internal', 'mgmt', 'vpn']
        if any(pattern in subdomain_lower for pattern in high_risk):
            return 'HIGH'
        
        # Medium-risk for certain paths
        if any(keyword in path_lower for keyword in ['admin', 'api', 'login', 'auth']):
            return 'MEDIUM'
        
        return 'LOW'
    
    def _is_interesting_endpoint(self, parsed_url) -> bool:
        """Check if endpoint is interesting for subdomain discovery"""
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        
        # Interesting endpoint patterns
        interesting_patterns = [
            'api', 'admin', 'login', 'auth', 'config', 'dashboard', 'panel',
            'upload', 'download', 'backup', 'test', 'dev', 'staging'
        ]
        
        return any(pattern in path or pattern in query for pattern in interesting_patterns)
    
    def _assess_endpoint_risk(self, parsed_url) -> str:
        """Risk assessment for discovered endpoints"""
        path = parsed_url.path.lower()
        
        # High-risk endpoint patterns
        if any(pattern in path for pattern in ['admin', 'config', 'backup', 'upload', 'exec']):
            return 'HIGH'
        
        # Medium-risk patterns
        if any(pattern in path for pattern in ['api', 'login', 'auth', 'panel']):
            return 'MEDIUM'
        
        return 'LOW'
    
    def _categorize_endpoint(self, parsed_url) -> str:
        """Categorize endpoint for better understanding"""
        path = parsed_url.path.lower()
        
        if 'admin' in path:
            return "Administrative interface"
        elif 'api' in path:
            return "API endpoint"
        elif any(keyword in path for keyword in ['login', 'auth']):
            return "Authentication interface"
        elif 'upload' in path:
            return "File upload interface"
        elif any(keyword in path for keyword in ['config', 'settings']):
            return "Configuration interface"
        else:
            return "Web endpoint"
    
    def _parse_output(self, output: str, scan_type: str) -> Dict:
        """Parse katana output with unified approach"""
        crawl_data = {
            'urls': [],
            'js_files': [],
            'forms': [],
            'endpoints': []
        }
        
        # Try to parse JSON output first
        try:
            with open('/tmp/katana_output.txt', 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        url = data.get('url', '')
                        if url:
                            crawl_data['urls'].append({
                                'url': url,
                                'method': data.get('method', 'GET'),
                                'status_code': data.get('status_code', 0),
                                'content_length': data.get('content_length', 0),
                                'content_type': data.get('content_type', ''),
                                'found_at': datetime.now().isoformat()
                            })
                            
                            # Categorize URLs
                            if url.endswith('.js'):
                                crawl_data['js_files'].append(url)
                            elif 'api' in url.lower() or '/v1/' in url or '/v2/' in url:
                                crawl_data['endpoints'].append(url)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            # Fallback to text parsing
            for line in output.strip().split('\n'):
                line = line.strip()
                
                # Extract URLs
                if line.startswith('http'):
                    crawl_data['urls'].append({
                        'url': line,
                        'method': 'GET',
                        'found_at': datetime.now().isoformat()
                    })
                    
                    # Categorize URLs
                    if line.endswith('.js'):
                        crawl_data['js_files'].append(line)
                    elif 'api' in line.lower():
                        crawl_data['endpoints'].append(line)
                
                # Parse form information
                elif 'form' in line.lower():
                    if match := re.search(r'form.*action="([^"]+)"', line):
                        crawl_data['forms'].append({
                            'action': match.group(1),
                            'found_at': datetime.now().isoformat()
                        })
        
        # Remove duplicates
        crawl_data['js_files'] = list(set(crawl_data['js_files']))
        crawl_data['endpoints'] = list(set(crawl_data['endpoints']))
        
        return crawl_data
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'katana_crawl',
            'crawl_data': {},
            'summary': {'urls_discovered': 0}
        }
