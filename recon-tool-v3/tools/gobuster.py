#!/usr/bin/env python3
"""
Gobuster Directory Scanner - Real Implementation
Directory and file brute-forcing using Gobuster
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from .base import BaseTool

class GobusterScanner(BaseTool):
    """Real Gobuster directory/file scanner implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "gobuster"
        self.version = "3.0+"
        self.description = "Directory and file brute-forcer"
        self.category = "web"
        
        # Gobuster-specific configuration
        self.wordlists = {
            'common': '/usr/share/wordlists/dirb/common.txt',
            'medium': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            'small': '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
            'big': '/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt'
        }
        self.threads = config.get('threads', 10)
        self.timeout = config.get('timeout', 10)
        self.extensions = config.get('extensions', ['php', 'html', 'txt', 'js', 'css', 'json', 'xml'])
        self.status_codes = config.get('status_codes', [200, 204, 301, 302, 307, 401, 403])
        self.user_agent = config.get('user_agent', 'gobuster/3.0')
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute gobuster scan against target"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting GobusterScanner scan against {target}")
            
            # Verify tool installation
            if not self.verify_installation():
                return self._create_error_result("Gobuster not installed")
            
            # Determine scan type
            scan_type = scan_params.get('scan_type', 'dir')
            
            if scan_type == 'dir':
                return self._directory_scan(target, scan_params)
            elif scan_type == 'dns':
                return self._dns_scan(target, scan_params)
            elif scan_type == 'vhost':
                return self._vhost_scan(target, scan_params)
            else:
                return self._create_error_result(f"Unknown scan type: {scan_type}")
                
        except Exception as e:
            self.logger.error(f"❌ GobusterScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _directory_scan(self, target: str, scan_params: Dict) -> Dict:
        """Perform directory/file enumeration"""
        try:
            # Build gobuster command
            cmd = self._build_dir_command(target, scan_params)
            
            # Execute gobuster scan
            result = self.execute_command(cmd, timeout=600)  # 10 minute timeout
            
            if result.returncode != 0:
                return self._create_error_result(f"Gobuster directory scan failed: {result.stderr}")
            
            # Parse results
            results = self._parse_dir_output(result.stdout, target)
            
            # Save raw output
            self.save_raw_output(result.stdout, target, 'txt')
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            # Log findings summary
            found_count = len(results.get('directories', []))
            self.logger.info(f"ℹ️ [GobusterScanner] directories: Found {found_count} accessible paths")
            
            self.logger.info(f"✅ GobusterScanner completed in {duration:.1f}s")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'gobuster_directory_scan',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'directories': results.get('directories', []),
                'summary': {
                    'total_found': found_count,
                    'status_codes': results.get('status_codes', {}),
                    'interesting_files': results.get('interesting_files', []),
                    'wordlist_used': results.get('wordlist_used', ''),
                    'extensions_tested': results.get('extensions_tested', [])
                },
                'raw_output_file': results.get('raw_output_file', None)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Directory scan error: {e}")
            return self._create_error_result(str(e))
    
    def _dns_scan(self, target: str, scan_params: Dict) -> Dict:
        """Perform DNS subdomain enumeration"""
        try:
            # Build gobuster dns command
            cmd = self._build_dns_command(target, scan_params)
            
            # Execute gobuster scan
            result = self.execute_command(cmd, timeout=300)
            
            if result.returncode != 0:
                return self._create_error_result(f"Gobuster DNS scan failed: {result.stderr}")
            
            # Parse results
            results = self._parse_dns_output(result.stdout, target)
            
            # Save raw output
            self.save_raw_output(result.stdout, target, 'txt')
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            # Log findings summary
            found_count = len(results.get('subdomains', []))
            self.logger.info(f"ℹ️ [GobusterScanner] subdomains: Found {found_count} subdomains")
            
            self.logger.info(f"✅ GobusterScanner DNS completed in {duration:.1f}s")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'gobuster_dns_scan',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'subdomains': results.get('subdomains', []),
                'summary': {
                    'total_found': found_count,
                    'wordlist_used': results.get('wordlist_used', ''),
                    'resolver_used': results.get('resolver_used', '')
                },
                'raw_output_file': results.get('raw_output_file', None)
            }
            
        except Exception as e:
            self.logger.error(f"❌ DNS scan error: {e}")
            return self._create_error_result(str(e))
    
    def _vhost_scan(self, target: str, scan_params: Dict) -> Dict:
        """Perform virtual host enumeration"""
        try:
            # Build gobuster vhost command
            cmd = self._build_vhost_command(target, scan_params)
            
            # Execute gobuster scan
            result = self.execute_command(cmd, timeout=300)
            
            if result.returncode != 0:
                return self._create_error_result(f"Gobuster vhost scan failed: {result.stderr}")
            
            # Parse results
            results = self._parse_vhost_output(result.stdout, target)
            
            # Save raw output
            self.save_raw_output(result.stdout, target, 'txt')
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            # Log findings summary
            found_count = len(results.get('vhosts', []))
            self.logger.info(f"ℹ️ [GobusterScanner] vhosts: Found {found_count} virtual hosts")
            
            self.logger.info(f"✅ GobusterScanner vhost completed in {duration:.1f}s")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'gobuster_vhost_scan',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'vhosts': results.get('vhosts', []),
                'summary': {
                    'total_found': found_count,
                    'wordlist_used': results.get('wordlist_used', ''),
                    'base_url': results.get('base_url', target)
                },
                'raw_output_file': results.get('raw_output_file', None)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Vhost scan error: {e}")
            return self._create_error_result(str(e))
    
    def _build_dir_command(self, target: str, scan_params: Dict) -> List[str]:
        """Build gobuster directory command"""
        cmd = [self.command_name, 'dir']
        
        # Target URL
        cmd.extend(['-u', target])
        
        # Wordlist selection
        wordlist_name = scan_params.get('wordlist', 'common')
        wordlist_path = scan_params.get('wordlist_path', self.wordlists.get(wordlist_name, self.wordlists['common']))
        
        if os.path.exists(wordlist_path):
            cmd.extend(['-w', wordlist_path])
        else:
            # Fallback to a simpler wordlist or create one
            cmd.extend(['-w', '/usr/share/wordlists/dirb/common.txt'])
        
        # Extensions
        extensions = scan_params.get('extensions', self.extensions[:5])  # Limit to 5 for performance
        if extensions:
            cmd.extend(['-x', ','.join(extensions)])
        
        # Status codes - disable blacklist when setting custom codes
        status_codes = scan_params.get('status_codes', [200, 301, 302])  # Simplified status codes
        if status_codes:
            cmd.extend(['-s', ','.join(map(str, status_codes))])
            cmd.extend(['--status-codes-blacklist', ''])  # Disable default blacklist
        
        # Performance options
        cmd.extend(['-t', str(scan_params.get('threads', self.threads))])
        cmd.extend(['--timeout', f"{scan_params.get('timeout', self.timeout)}s"])
        
        # User agent
        cmd.extend(['-a', scan_params.get('user_agent', self.user_agent)])
        
        # Output options
        cmd.extend(['-q'])  # Quiet mode for cleaner parsing
        
        # Additional options
        if scan_params.get('follow_redirects', False):
            cmd.extend(['-r'])
        
        # Remove the -l flag as it doesn't exist in gobuster
        
        return cmd
    
    def _build_dns_command(self, target: str, scan_params: Dict) -> List[str]:
        """Build gobuster DNS command"""
        cmd = [self.command_name, 'dns']
        
        # Target domain
        cmd.extend(['-d', target])
        
        # Wordlist selection
        wordlist_name = scan_params.get('wordlist', 'common')
        wordlist_path = scan_params.get('wordlist_path', self.wordlists.get(wordlist_name, self.wordlists['common']))
        
        if os.path.exists(wordlist_path):
            cmd.extend(['-w', wordlist_path])
        else:
            cmd.extend(['-w', '/usr/share/wordlists/dirb/common.txt'])
        
        # Performance options
        cmd.extend(['-t', str(scan_params.get('threads', self.threads))])
        cmd.extend(['--timeout', f"{scan_params.get('timeout', self.timeout)}s"])
        
        # DNS resolver
        resolver = scan_params.get('resolver', '8.8.8.8')
        cmd.extend(['-r', resolver])
        
        # Output options
        cmd.extend(['-q'])  # Quiet mode
        
        return cmd
    
    def _build_vhost_command(self, target: str, scan_params: Dict) -> List[str]:
        """Build gobuster vhost command"""
        cmd = [self.command_name, 'vhost']
        
        # Target URL
        cmd.extend(['-u', target])
        
        # Wordlist selection
        wordlist_name = scan_params.get('wordlist', 'common')
        wordlist_path = scan_params.get('wordlist_path', self.wordlists.get(wordlist_name, self.wordlists['common']))
        
        if os.path.exists(wordlist_path):
            cmd.extend(['-w', wordlist_path])
        else:
            cmd.extend(['-w', '/usr/share/wordlists/dirb/common.txt'])
        
        # Performance options
        cmd.extend(['-t', str(scan_params.get('threads', self.threads))])
        cmd.extend(['--timeout', f"{scan_params.get('timeout', self.timeout)}s"])
        
        # Output options
        cmd.extend(['-q'])  # Quiet mode
        
        return cmd
    
    def _parse_dir_output(self, output: str, target: str) -> Dict:
        """Parse gobuster directory output"""
        directories = []
        status_codes = {}
        interesting_files = []
        
        try:
            lines = output.strip().split('\n')
            for line in lines:
                line = line.strip()
                if not line or line.startswith('='):
                    continue
                
                # Parse gobuster output format: /path (Status: 200) [Size: 1234]
                if '(Status:' in line:
                    try:
                        path_part = line.split('(Status:')[0].strip()
                        status_part = line.split('(Status:')[1].split(')')[0].strip()
                        
                        # Extract size if present
                        size = None
                        if '[Size:' in line:
                            size_part = line.split('[Size:')[1].split(']')[0].strip()
                            try:
                                size = int(size_part)
                            except:
                                pass
                        
                        entry = {
                            'path': path_part,
                            'status_code': int(status_part),
                            'url': f"{target.rstrip('/')}{path_part}",
                            'size': size,
                            'found_at': datetime.now().isoformat()
                        }
                        
                        directories.append(entry)
                        
                        # Track status codes
                        status_codes[status_part] = status_codes.get(status_part, 0) + 1
                        
                        # Identify interesting files
                        if self._is_interesting_file(path_part):
                            interesting_files.append(entry)
                            
                    except Exception as e:
                        self.logger.debug(f"Failed to parse line: {line} - {e}")
                        continue
                        
        except Exception as e:
            self.logger.warning(f"⚠️ Error parsing gobuster output: {e}")
        
        return {
            'directories': directories,
            'status_codes': status_codes,
            'interesting_files': interesting_files
        }
    
    def _parse_dns_output(self, output: str, target: str) -> Dict:
        """Parse gobuster DNS output"""
        subdomains = []
        
        try:
            lines = output.strip().split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Parse DNS output format: Found: subdomain.domain.com
                if 'Found:' in line:
                    try:
                        subdomain = line.split('Found:')[1].strip()
                        entry = {
                            'subdomain': subdomain,
                            'found_at': datetime.now().isoformat()
                        }
                        subdomains.append(entry)
                    except:
                        continue
                        
        except Exception as e:
            self.logger.warning(f"⚠️ Error parsing gobuster DNS output: {e}")
        
        return {
            'subdomains': subdomains
        }
    
    def _parse_vhost_output(self, output: str, target: str) -> Dict:
        """Parse gobuster vhost output"""
        vhosts = []
        
        try:
            lines = output.strip().split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Parse vhost output format: Found: vhost.domain.com (Status: 200) [Size: 1234]
                if 'Found:' in line:
                    try:
                        vhost_part = line.split('Found:')[1].split('(Status:')[0].strip()
                        status_part = line.split('(Status:')[1].split(')')[0].strip()
                        
                        entry = {
                            'vhost': vhost_part,
                            'status_code': int(status_part),
                            'found_at': datetime.now().isoformat()
                        }
                        vhosts.append(entry)
                    except:
                        continue
                        
        except Exception as e:
            self.logger.warning(f"⚠️ Error parsing gobuster vhost output: {e}")
        
        return {
            'vhosts': vhosts
        }
    
    def _is_interesting_file(self, path: str) -> bool:
        """Identify interesting files based on path"""
        interesting_patterns = [
            'admin', 'login', 'config', 'backup', 'test', 'dev',
            '.env', '.git', '.svn', 'robots.txt', 'sitemap.xml',
            'phpinfo', 'info.php', 'status', 'health', 'debug'
        ]
        
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in interesting_patterns)
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'gobuster_scan',
            'timestamp': datetime.now().isoformat(),
            'directories': [],
            'summary': {'total_found': 0}
        }
    
    def directory_scan(self, target: str, wordlist: str = 'common') -> Dict:
        """Convenience method for directory scanning"""
        scan_params = {
            'scan_type': 'dir',
            'wordlist': wordlist,
            'extensions': ['php', 'html', 'txt', 'js'],
            'threads': 10
        }
        return self.scan(target, scan_params)
    
    def file_scan(self, target: str, extensions: List[str] = None) -> Dict:
        """Convenience method for file scanning"""
        if extensions is None:
            extensions = ['php', 'html', 'txt', 'js', 'css', 'json', 'xml', 'log', 'bak']
        
        scan_params = {
            'scan_type': 'dir',
            'wordlist': 'medium',
            'extensions': extensions,
            'threads': 15
        }
        return self.scan(target, scan_params)
    
    def subdomain_scan(self, domain: str) -> Dict:
        """Convenience method for subdomain enumeration"""
        scan_params = {
            'scan_type': 'dns',
            'wordlist': 'common',
            'threads': 20
        }
        return self.scan(domain, scan_params)
    
    def vhost_scan(self, target: str) -> Dict:
        """Convenience method for virtual host enumeration"""
        scan_params = {
            'scan_type': 'vhost',
            'wordlist': 'common',
            'threads': 10
        }
        return self.scan(target, scan_params)
