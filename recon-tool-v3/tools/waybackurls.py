#!/usr/bin/env python3
"""
Waybackurls Historical URL Discovery - Phase 4 Implementation
Real historical URL discovery using waybackurls tool
"""

import json
import subprocess
import re
from datetime import datetime
from typing import Dict, Any, List, Set, Optional
from urllib.parse import urlparse, parse_qs

from .base import BaseTool

class WaybackurlsDiscovery(BaseTool):
    """Real waybackurls historical URL discovery implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "waybackurls"
        self.version = "latest"
        self.description = "Historical URL discovery from Wayback Machine"
        self.category = "url_discovery"
        
        # Configuration
        self.dates = config.get('dates', None)  # Date range filter
        self.get_versions = config.get('get_versions', False)
        self.no_subs = config.get('no_subs', False)
        self.timeout = config.get('timeout', 120)
        
    def scan(self, domain: str, scan_params: Dict) -> Dict:
        """Execute waybackurls scan against target domain"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting WaybackurlsDiscovery scan against {domain}")
            
            # Verify tool installation
            if not self.verify_installation():
                return self._create_error_result("waybackurls not installed")
            
            # Execute URL discovery
            urls = self.discover_historical_urls(domain, scan_params)
            
            # Analyze discovered URLs
            analysis = self._analyze_urls(urls, domain)
            
            # Extract useful information
            parameters = self.extract_parameters(urls)
            sensitive_paths = self.find_sensitive_paths(urls)
            interesting_files = self._find_interesting_files(urls)
            
            # Save raw output
            self.save_raw_output('\n'.join(urls), domain, 'txt')
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            self.logger.info(f"ℹ️ [WaybackurlsDiscovery] Found {len(urls)} historical URLs")
            self.logger.info(f"✅ WaybackurlsDiscovery completed in {duration:.1f}s")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'waybackurls_discovery',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'discovered_urls': urls,
                'url_analysis': analysis,
                'parameters': list(parameters),
                'sensitive_paths': sensitive_paths,
                'interesting_files': interesting_files,
                'summary': {
                    'total_urls': len(urls),
                    'unique_parameters': len(parameters),
                    'sensitive_paths_count': len(sensitive_paths),
                    'interesting_files_count': len(interesting_files)
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ WaybackurlsDiscovery error: {e}")
            return self._create_error_result(str(e))
    
    def discover_historical_urls(self, domain: str, scan_params: Dict = {}) -> List[str]:
        """Discover URLs from Wayback Machine"""
        try:
            # Build waybackurls command
            cmd = [self.command_name, domain]
            
            # Add date filter if specified
            dates = scan_params.get('dates', self.dates)
            if dates:
                cmd.extend(['-dates', dates])
            
            # Add version filter if specified
            if scan_params.get('get_versions', self.get_versions):
                cmd.append('-get-versions')
            
            # Add no subdomains filter if specified
            if scan_params.get('no_subs', self.no_subs):
                cmd.append('-no-subs')
            
            # Execute waybackurls
            result = self.execute_command(cmd, timeout=self.timeout)
            
            if result.returncode != 0:
                self.logger.warning(f"waybackurls returned non-zero exit code: {result.returncode}")
                if result.stderr:
                    self.logger.warning(f"waybackurls stderr: {result.stderr}")
            
            # Parse URLs from output
            urls = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    url = line.strip()
                    if url and url.startswith('http'):
                        urls.append(url)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_urls = []
            for url in urls:
                if url not in seen:
                    seen.add(url)
                    unique_urls.append(url)
            
            return unique_urls
            
        except Exception as e:
            self.logger.error(f"Error discovering historical URLs: {e}")
            return []
    
    def filter_by_extension(self, urls: List[str], extensions: List[str]) -> List[str]:
        """Filter URLs by file extensions"""
        filtered_urls = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path.lower()
                
                for ext in extensions:
                    if path.endswith(f'.{ext.lower()}'):
                        filtered_urls.append(url)
                        break
                        
            except Exception:
                continue
        
        return filtered_urls
    
    def extract_parameters(self, urls: List[str]) -> Set[str]:
        """Extract unique parameters from historical URLs"""
        parameters = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    query_params = parse_qs(parsed.query)
                    for param_name in query_params.keys():
                        parameters.add(param_name)
                        
            except Exception:
                continue
        
        return parameters
    
    def find_sensitive_paths(self, urls: List[str]) -> List[Dict[str, str]]:
        """Identify potentially sensitive paths"""
        sensitive_patterns = {
            'admin_panels': [
                '/admin', '/administrator', '/panel', '/control', '/manage',
                '/wp-admin', '/admin.php', '/administrator.php'
            ],
            'config_files': [
                '.env', 'config.php', 'web.config', 'app.config',
                'database.yml', 'settings.py', '.htaccess'
            ],
            'backup_files': [
                '.bak', '.backup', '.old', '.orig', '.save',
                'backup.sql', 'dump.sql', 'database.sql'
            ],
            'development': [
                '/test', '/dev', '/staging', '/debug', '/temp',
                'phpinfo.php', 'test.php', 'debug.php'
            ],
            'api_endpoints': [
                '/api/', '/rest/', '/v1/', '/v2/', '/graphql',
                '/swagger', '/openapi', '/api-docs'
            ],
            'sensitive_dirs': [
                '/config/', '/backup/', '/private/', '/internal/',
                '/uploads/', '/files/', '/documents/'
            ]
        }
        
        sensitive_paths = []
        
        for url in urls:
            url_lower = url.lower()
            
            for category, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    if pattern in url_lower:
                        sensitive_paths.append({
                            'url': url,
                            'category': category,
                            'pattern': pattern,
                            'reason': f'Contains sensitive pattern: {pattern}'
                        })
                        break  # Only categorize once per URL
        
        return sensitive_paths
    
    def _analyze_urls(self, urls: List[str], domain: str) -> Dict[str, Any]:
        """Analyze discovered URLs for patterns and insights"""
        analysis = {
            'total_count': len(urls),
            'domains': {},
            'extensions': {},
            'directories': {},
            'parameters_count': 0,
            'https_vs_http': {'https': 0, 'http': 0},
            'path_depth': {'shallow': 0, 'medium': 0, 'deep': 0}
        }
        
        for url in urls:
            try:
                parsed = urlparse(url)
                
                # Domain analysis
                domain_name = parsed.netloc
                analysis['domains'][domain_name] = analysis['domains'].get(domain_name, 0) + 1
                
                # Protocol analysis
                if parsed.scheme == 'https':
                    analysis['https_vs_http']['https'] += 1
                else:
                    analysis['https_vs_http']['http'] += 1
                
                # Extension analysis
                path = parsed.path
                if '.' in path:
                    ext = path.split('.')[-1].lower()
                    if len(ext) <= 5:  # Reasonable extension length
                        analysis['extensions'][ext] = analysis['extensions'].get(ext, 0) + 1
                
                # Directory analysis
                if '/' in path:
                    dirs = [d for d in path.split('/') if d]
                    if dirs:
                        first_dir = dirs[0]
                        analysis['directories'][first_dir] = analysis['directories'].get(first_dir, 0) + 1
                        
                        # Path depth analysis
                        depth = len(dirs)
                        if depth <= 2:
                            analysis['path_depth']['shallow'] += 1
                        elif depth <= 4:
                            analysis['path_depth']['medium'] += 1
                        else:
                            analysis['path_depth']['deep'] += 1
                
                # Parameter analysis
                if parsed.query:
                    analysis['parameters_count'] += 1
                    
            except Exception:
                continue
        
        # Sort top results
        analysis['top_extensions'] = dict(sorted(analysis['extensions'].items(), 
                                                key=lambda x: x[1], reverse=True)[:10])
        analysis['top_directories'] = dict(sorted(analysis['directories'].items(), 
                                                 key=lambda x: x[1], reverse=True)[:15])
        
        return analysis
    
    def _find_interesting_files(self, urls: List[str]) -> List[Dict[str, str]]:
        """Find interesting files in discovered URLs"""
        interesting_extensions = {
            'documents': ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'],
            'configs': ['xml', 'json', 'yaml', 'yml', 'ini', 'conf'],
            'backups': ['bak', 'backup', 'old', 'orig', 'save'],
            'databases': ['sql', 'db', 'sqlite', 'mdb'],
            'logs': ['log', 'txt'],
            'development': ['php', 'asp', 'aspx', 'jsp', 'py', 'rb']
        }
        
        interesting_files = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path.lower()
                
                if '.' in path:
                    ext = path.split('.')[-1]
                    filename = path.split('/')[-1] if '/' in path else path
                    
                    for category, extensions in interesting_extensions.items():
                        if ext in extensions:
                            interesting_files.append({
                                'url': url,
                                'filename': filename,
                                'extension': ext,
                                'category': category
                            })
                            break
                            
            except Exception:
                continue
        
        return interesting_files
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'waybackurls_discovery',
            'timestamp': datetime.now().isoformat(),
            'discovered_urls': [],
            'summary': {'total_urls': 0}
        }
    
    def quick_discovery(self, domain: str) -> Dict:
        """Convenience method for quick URL discovery"""
        scan_params = {
            'no_subs': True,  # Only main domain
            'timeout': 60
        }
        return self.scan(domain, scan_params)
    
    def comprehensive_discovery(self, domain: str) -> Dict:
        """Convenience method for comprehensive URL discovery"""
        scan_params = {
            'get_versions': True,  # Include version information
            'timeout': 180
        }
        return self.scan(domain, scan_params)
