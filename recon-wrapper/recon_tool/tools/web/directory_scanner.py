"""
Directory Scanner
Web directory and file discovery
"""

import json
import logging
import random
import time
from pathlib import Path
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse

import requests

from ...core.exceptions import ScanError


class DirectoryScanner:
    """Web directory and file discovery scanner"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        
        # Create directory output directory
        self.dir_dir = output_dir / 'directory'
        self.dir_dir.mkdir(exist_ok=True)
        
        # Common wordlists (built-in for basic scanning)
        self.common_directories = [
            'admin', 'administrator', 'api', 'app', 'apps', 'backup', 'backups',
            'bin', 'blog', 'cache', 'cgi-bin', 'config', 'css', 'data', 'db',
            'dev', 'doc', 'docs', 'downloads', 'etc', 'files', 'home', 'html',
            'images', 'img', 'includes', 'js', 'lib', 'log', 'logs', 'mail',
            'media', 'old', 'pages', 'private', 'public', 'scripts', 'src',
            'static', 'temp', 'test', 'tmp', 'uploads', 'user', 'users',
            'var', 'web', 'www'
        ]
        
        self.common_files = [
            'robots.txt', 'sitemap.xml', 'admin.php', 'config.php', 'login.php',
            'index.html', 'index.php', 'test.php', 'info.php', 'phpinfo.php',
            'backup.sql', 'database.sql', 'config.txt', 'readme.txt', 'changelog.txt',
            '.htaccess', '.git', '.svn', '.env', 'web.config', 'crossdomain.xml',
            'favicon.ico', 'apple-touch-icon.png', 'manifest.json'
        ]
        
        self.common_extensions = ['php', 'html', 'htm', 'asp', 'aspx', 'jsp', 'txt', 'xml', 'json']
    
    def scan_directories(self, target: str, wordlist_file: str = None) -> Dict[str, Any]:
        """Run comprehensive directory scanning"""
        self.logger.info(f"Starting directory scan for {target}")
        
        results = {
            'target': target,
            'directories_found': [],
            'files_found': [],
            'interesting_files': [],
            'error_pages': {},
            'response_analysis': {},
            'redirects': [],
            'security_files': []
        }
        
        try:
            # Prepare base URL
            base_url = self._prepare_base_url(target)
            
            # Load wordlist
            wordlist = self._load_wordlist(wordlist_file)
            
            # Perform baseline analysis
            self._analyze_baseline_responses(base_url, results)
            
            # Directory enumeration
            self._enumerate_directories(base_url, wordlist, results)
            
            # File enumeration
            self._enumerate_files(base_url, wordlist, results)
            
            # Check for interesting files
            self._check_interesting_files(base_url, results)
            
            # Check for security-related files
            self._check_security_files(base_url, results)
            
            # Analyze response patterns
            self._analyze_response_patterns(results)
            
            # Save results
            self._save_directory_results(target, results)
            
        except Exception as e:
            self.logger.error(f"Directory scan failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _prepare_base_url(self, target: str) -> str:
        """Prepare base URL for directory scanning"""
        if not target.startswith('http'):
            # Try HTTPS first, then HTTP
            for scheme in ['https', 'http']:
                test_url = f"{scheme}://{target}"
                try:
                    response = requests.head(test_url, timeout=10, allow_redirects=True)
                    if response.status_code < 400:
                        return test_url
                except:
                    continue
            
            # Default to HTTP if no response
            return f"http://{target}"
        else:
            return target
    
    def _load_wordlist(self, wordlist_file: str = None) -> List[str]:
        """Load wordlist from file or use built-in wordlist"""
        wordlist = []
        
        if wordlist_file and Path(wordlist_file).exists():
            try:
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                self.logger.info(f"Loaded {len(wordlist)} words from {wordlist_file}")
            except Exception as e:
                self.logger.warning(f"Error loading wordlist {wordlist_file}: {str(e)}")
                self.logger.info("Using built-in wordlist")
                wordlist = self.common_directories[:]
        else:
            self.logger.info("Using built-in wordlist")
            wordlist = self.common_directories[:]
        
        return wordlist
    
    def _analyze_baseline_responses(self, base_url: str, results: Dict[str, Any]) -> None:
        """Analyze baseline responses to understand normal behavior"""
        self.logger.info("Analyzing baseline responses")
        
        baseline = {
            'status_codes': {},
            'content_lengths': {},
            'response_times': [],
            'server_info': {}
        }
        
        try:
            # Test main page
            response = requests.get(base_url, timeout=10, allow_redirects=True)
            
            baseline['main_page'] = {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('Content-Type', ''),
                'server': response.headers.get('Server', ''),
                'response_time': response.elapsed.total_seconds()
            }
            
            # Test non-existent page to understand 404 behavior
            random_path = f"/{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=20))}"
            not_found_url = urljoin(base_url, random_path)
            
            try:
                not_found_response = requests.get(not_found_url, timeout=10, allow_redirects=False)
                
                baseline['not_found'] = {
                    'status_code': not_found_response.status_code,
                    'content_length': len(not_found_response.content),
                    'content_type': not_found_response.headers.get('Content-Type', ''),
                    'response_time': not_found_response.elapsed.total_seconds()
                }
            except Exception as e:
                baseline['not_found'] = {'error': str(e)}
            
            # Test forbidden path
            forbidden_url = urljoin(base_url, '/admin')
            try:
                forbidden_response = requests.get(forbidden_url, timeout=10, allow_redirects=False)
                
                baseline['forbidden_test'] = {
                    'status_code': forbidden_response.status_code,
                    'content_length': len(forbidden_response.content),
                    'content_type': forbidden_response.headers.get('Content-Type', ''),
                    'response_time': forbidden_response.elapsed.total_seconds()
                }
            except Exception as e:
                baseline['forbidden_test'] = {'error': str(e)}
            
        except Exception as e:
            self.logger.error(f"Baseline analysis failed: {str(e)}")
            baseline['error'] = str(e)
        
        results['baseline_analysis'] = baseline
    
    def _enumerate_directories(self, base_url: str, wordlist: List[str], results: Dict[str, Any]) -> None:
        """Enumerate directories using wordlist"""
        self.logger.info(f"Enumerating directories with {len(wordlist)} words")
        
        directories_found = []
        request_count = 0
        
        try:
            for directory in wordlist:
                if request_count > 1000:  # Limit requests to prevent overwhelming
                    self.logger.warning("Request limit reached, stopping directory enumeration")
                    break
                
                # Test with and without trailing slash
                for path_variant in [directory, f"{directory}/"]:
                    try:
                        url = urljoin(base_url, path_variant)
                        response = requests.get(url, timeout=10, allow_redirects=False)
                        
                        directory_info = {
                            'path': path_variant,
                            'url': url,
                            'status_code': response.status_code,
                            'content_length': len(response.content),
                            'content_type': response.headers.get('Content-Type', ''),
                            'server': response.headers.get('Server', ''),
                            'response_time': response.elapsed.total_seconds()
                        }
                        
                        # Check if this looks like a valid directory
                        if self._is_interesting_response(response, results.get('baseline_analysis', {})):
                            directory_info['interesting'] = True
                            
                            # Check for directory listing
                            if self._has_directory_listing(response):
                                directory_info['directory_listing'] = True
                            
                            # Check for redirects
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                directory_info['redirect_location'] = location
                                
                                results['redirects'].append({
                                    'from': url,
                                    'to': location,
                                    'status_code': response.status_code
                                })
                            
                            directories_found.append(directory_info)
                            self.logger.debug(f"Found directory: {path_variant} [{response.status_code}]")
                        
                        request_count += 1
                        
                        # Rate limiting
                        time.sleep(0.1)
                        
                    except requests.exceptions.RequestException as e:
                        self.logger.debug(f"Request failed for {path_variant}: {str(e)}")
                        continue
                    except Exception as e:
                        self.logger.debug(f"Error testing directory {path_variant}: {str(e)}")
                        continue
        
        except Exception as e:
            self.logger.error(f"Directory enumeration error: {str(e)}")
        
        results['directories_found'] = directories_found
        self.logger.info(f"Found {len(directories_found)} interesting directories")
    
    def _enumerate_files(self, base_url: str, wordlist: List[str], results: Dict[str, Any]) -> None:
        """Enumerate files using wordlist and extensions"""
        self.logger.info("Enumerating files")
        
        files_found = []
        request_count = 0
        
        try:
            # Test common files first
            for filename in self.common_files:
                if request_count > 500:  # Limit file enumeration
                    break
                
                try:
                    url = urljoin(base_url, filename)
                    response = requests.get(url, timeout=10, allow_redirects=False)
                    
                    file_info = {
                        'filename': filename,
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('Content-Type', ''),
                        'response_time': response.elapsed.total_seconds()
                    }
                    
                    if self._is_interesting_response(response, results.get('baseline_analysis', {})):
                        file_info['interesting'] = True
                        
                        # Analyze file content
                        content_analysis = self._analyze_file_content(response, filename)
                        file_info.update(content_analysis)
                        
                        files_found.append(file_info)
                        self.logger.debug(f"Found file: {filename} [{response.status_code}]")
                    
                    request_count += 1
                    time.sleep(0.05)
                    
                except Exception as e:
                    self.logger.debug(f"Error testing file {filename}: {str(e)}")
                    continue
            
            # Test wordlist with extensions (limited subset)
            limited_wordlist = wordlist[:50] if len(wordlist) > 50 else wordlist
            limited_extensions = self.common_extensions[:3]  # Limit extensions
            
            for word in limited_wordlist:
                if request_count > 500:
                    break
                
                for ext in limited_extensions:
                    filename = f"{word}.{ext}"
                    
                    try:
                        url = urljoin(base_url, filename)
                        response = requests.get(url, timeout=10, allow_redirects=False)
                        
                        if self._is_interesting_response(response, results.get('baseline_analysis', {})):
                            file_info = {
                                'filename': filename,
                                'url': url,
                                'status_code': response.status_code,
                                'content_length': len(response.content),
                                'content_type': response.headers.get('Content-Type', ''),
                                'response_time': response.elapsed.total_seconds(),
                                'interesting': True
                            }
                            
                            content_analysis = self._analyze_file_content(response, filename)
                            file_info.update(content_analysis)
                            
                            files_found.append(file_info)
                            self.logger.debug(f"Found file: {filename} [{response.status_code}]")
                        
                        request_count += 1
                        time.sleep(0.05)
                        
                    except Exception as e:
                        self.logger.debug(f"Error testing file {filename}: {str(e)}")
                        continue
        
        except Exception as e:
            self.logger.error(f"File enumeration error: {str(e)}")
        
        results['files_found'] = files_found
        self.logger.info(f"Found {len(files_found)} interesting files")
    
    def _check_interesting_files(self, base_url: str, results: Dict[str, Any]) -> None:
        """Check for specific interesting files"""
        self.logger.info("Checking for interesting files")
        
        interesting_files = []
        
        # Specific interesting files to check
        interesting_targets = [
            # Configuration files
            {'path': '.env', 'type': 'configuration', 'risk': 'high'},
            {'path': 'config.php', 'type': 'configuration', 'risk': 'medium'},
            {'path': 'wp-config.php', 'type': 'configuration', 'risk': 'high'},
            {'path': 'web.config', 'type': 'configuration', 'risk': 'medium'},
            
            # Backup files
            {'path': 'backup.sql', 'type': 'backup', 'risk': 'high'},
            {'path': 'database.sql', 'type': 'backup', 'risk': 'high'},
            {'path': 'dump.sql', 'type': 'backup', 'risk': 'high'},
            {'path': 'backup.zip', 'type': 'backup', 'risk': 'medium'},
            
            # Debug/Info files
            {'path': 'phpinfo.php', 'type': 'info', 'risk': 'medium'},
            {'path': 'info.php', 'type': 'info', 'risk': 'medium'},
            {'path': 'test.php', 'type': 'debug', 'risk': 'low'},
            
            # Version control
            {'path': '.git/config', 'type': 'version_control', 'risk': 'high'},
            {'path': '.svn/entries', 'type': 'version_control', 'risk': 'medium'},
            {'path': '.hg/hgrc', 'type': 'version_control', 'risk': 'medium'},
            
            # Server files
            {'path': 'server-status', 'type': 'server_info', 'risk': 'medium'},
            {'path': 'server-info', 'type': 'server_info', 'risk': 'medium'},
            
            # Admin interfaces
            {'path': 'phpmyadmin/', 'type': 'admin', 'risk': 'high'},
            {'path': 'adminer.php', 'type': 'admin', 'risk': 'high'},
            {'path': 'admin.php', 'type': 'admin', 'risk': 'medium'}
        ]
        
        for target in interesting_targets:
            try:
                url = urljoin(base_url, target['path'])
                response = requests.get(url, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    file_info = {
                        'path': target['path'],
                        'url': url,
                        'type': target['type'],
                        'risk_level': target['risk'],
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('Content-Type', '')
                    }
                    
                    # Additional analysis for specific file types
                    if target['type'] == 'info' and 'php' in target['path']:
                        if 'phpinfo()' in response.text or 'PHP Version' in response.text:
                            file_info['contains_phpinfo'] = True
                    
                    elif target['type'] == 'backup' and target['path'].endswith('.sql'):
                        if any(keyword in response.text.lower() for keyword in ['create table', 'insert into', 'drop table']):
                            file_info['contains_sql'] = True
                    
                    elif target['type'] == 'configuration':
                        if any(keyword in response.text.lower() for keyword in ['password', 'secret', 'key', 'token']):
                            file_info['contains_secrets'] = True
                    
                    interesting_files.append(file_info)
                    self.logger.info(f"Found interesting file: {target['path']} (Risk: {target['risk']})")
                
                time.sleep(0.1)
                
            except Exception as e:
                self.logger.debug(f"Error checking interesting file {target['path']}: {str(e)}")
                continue
        
        results['interesting_files'] = interesting_files
    
    def _check_security_files(self, base_url: str, results: Dict[str, Any]) -> None:
        """Check for security-related files"""
        self.logger.info("Checking for security files")
        
        security_files = []
        
        security_targets = [
            {'path': 'robots.txt', 'description': 'Robot exclusion file'},
            {'path': 'security.txt', 'description': 'Security policy file'},
            {'path': '.well-known/security.txt', 'description': 'Security policy file (RFC location)'},
            {'path': 'crossdomain.xml', 'description': 'Flash cross-domain policy'},
            {'path': 'clientaccesspolicy.xml', 'description': 'Silverlight cross-domain policy'},
            {'path': 'sitemap.xml', 'description': 'XML sitemap'},
            {'path': 'humans.txt', 'description': 'Humans file'}
        ]
        
        for target in security_targets:
            try:
                url = urljoin(base_url, target['path'])
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    file_info = {
                        'path': target['path'],
                        'url': url,
                        'description': target['description'],
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_preview': response.text[:200]  # First 200 chars
                    }
                    
                    # Analyze content for security implications
                    if target['path'] == 'robots.txt':
                        disallowed_paths = []
                        for line in response.text.split('\n'):
                            if line.strip().startswith('Disallow:'):
                                path = line.split(':', 1)[1].strip()
                                if path and path != '/':
                                    disallowed_paths.append(path)
                        
                        if disallowed_paths:
                            file_info['disallowed_paths'] = disallowed_paths[:10]  # Limit to 10
                    
                    security_files.append(file_info)
                    self.logger.debug(f"Found security file: {target['path']}")
                
                time.sleep(0.1)
                
            except Exception as e:
                self.logger.debug(f"Error checking security file {target['path']}: {str(e)}")
                continue
        
        results['security_files'] = security_files
    
    def _is_interesting_response(self, response: requests.Response, baseline: Dict[str, Any]) -> bool:
        """Determine if a response is interesting based on baseline analysis"""
        status_code = response.status_code
        content_length = len(response.content)
        
        # Always interesting status codes
        if status_code in [200, 201, 202, 301, 302, 403]:
            return True
        
        # Check against baseline 404 response
        baseline_404 = baseline.get('not_found', {})
        if baseline_404:
            baseline_status = baseline_404.get('status_code')
            baseline_length = baseline_404.get('content_length', 0)
            
            # Different status code from baseline 404
            if status_code != baseline_status:
                return True
            
            # Significantly different content length
            if abs(content_length - baseline_length) > 100:
                return True
        
        return False
    
    def _has_directory_listing(self, response: requests.Response) -> bool:
        """Check if response contains directory listing"""
        if response.status_code != 200:
            return False
        
        content = response.text.lower()
        
        # Common directory listing indicators
        listing_indicators = [
            'index of /',
            'directory listing for',
            'parent directory',
            '<title>index of',
            '[dir]',
            'folder.gif',
            'last modified'
        ]
        
        return any(indicator in content for indicator in listing_indicators)
    
    def _analyze_file_content(self, response: requests.Response, filename: str) -> Dict[str, Any]:
        """Analyze file content for interesting characteristics"""
        analysis = {}
        
        try:
            content_type = response.headers.get('Content-Type', '').lower()
            content = response.text
            
            # File type analysis
            if filename.endswith('.php'):
                if '<?php' in content:
                    analysis['contains_php_code'] = True
                if any(keyword in content.lower() for keyword in ['mysql_connect', 'mysqli_connect', 'pdo']):
                    analysis['contains_database_code'] = True
            
            elif filename.endswith('.sql'):
                if any(keyword in content.lower() for keyword in ['create table', 'insert into', 'select']):
                    analysis['valid_sql_file'] = True
            
            elif filename.endswith('.txt'):
                # Check for common sensitive information patterns
                sensitive_patterns = ['password', 'secret', 'key', 'token', 'api_key']
                if any(pattern in content.lower() for pattern in sensitive_patterns):
                    analysis['contains_sensitive_info'] = True
            
            # General content analysis
            if content.strip():
                analysis['has_content'] = True
                analysis['content_length'] = len(content)
                
                # Check for error messages
                error_patterns = ['error', 'exception', 'warning', 'fatal']
                if any(pattern in content.lower() for pattern in error_patterns):
                    analysis['contains_errors'] = True
        
        except Exception as e:
            analysis['analysis_error'] = str(e)
        
        return analysis
    
    def _analyze_response_patterns(self, results: Dict[str, Any]) -> None:
        """Analyze response patterns for insights"""
        self.logger.info("Analyzing response patterns")
        
        analysis = {
            'status_code_distribution': {},
            'content_type_distribution': {},
            'average_response_time': 0,
            'large_responses': [],
            'potential_false_positives': []
        }
        
        try:
            all_responses = []
            all_responses.extend(results.get('directories_found', []))
            all_responses.extend(results.get('files_found', []))
            
            if not all_responses:
                results['response_analysis'] = analysis
                return
            
            # Analyze status codes
            status_codes = [r.get('status_code', 0) for r in all_responses]
            for code in status_codes:
                analysis['status_code_distribution'][str(code)] = analysis['status_code_distribution'].get(str(code), 0) + 1
            
            # Analyze content types
            content_types = [r.get('content_type', '').split(';')[0] for r in all_responses]
            for ct in content_types:
                if ct:
                    analysis['content_type_distribution'][ct] = analysis['content_type_distribution'].get(ct, 0) + 1
            
            # Average response time
            response_times = [r.get('response_time', 0) for r in all_responses if r.get('response_time')]
            if response_times:
                analysis['average_response_time'] = sum(response_times) / len(response_times)
            
            # Find large responses (potential for further investigation)
            for response in all_responses:
                content_length = response.get('content_length', 0)
                if content_length > 10000:  # > 10KB
                    analysis['large_responses'].append({
                        'path': response.get('path') or response.get('filename'),
                        'content_length': content_length,
                        'url': response.get('url')
                    })
            
            # Identify potential false positives (same response for multiple paths)
            response_signatures = {}
            for response in all_responses:
                signature = f"{response.get('status_code')}_{response.get('content_length')}"
                if signature not in response_signatures:
                    response_signatures[signature] = []
                response_signatures[signature].append(response.get('path') or response.get('filename'))
            
            for signature, paths in response_signatures.items():
                if len(paths) > 5:  # Same response for many paths
                    analysis['potential_false_positives'].append({
                        'signature': signature,
                        'path_count': len(paths),
                        'sample_paths': paths[:3]
                    })
        
        except Exception as e:
            self.logger.error(f"Response pattern analysis error: {str(e)}")
            analysis['error'] = str(e)
        
        results['response_analysis'] = analysis
    
    def _save_directory_results(self, target: str, results: Dict[str, Any]) -> None:
        """Save directory scan results"""
        sanitized_target = target.replace(':', '_').replace('/', '_')
        
        # Save JSON results
        json_file = self.dir_dir / f'{sanitized_target}_directory_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"Directory results saved to {json_file}")
        
        # Create human-readable summary
        txt_file = self.dir_dir / f'{sanitized_target}_directory_summary.txt'
        
        with open(txt_file, 'w') as f:
            f.write(f"Directory Scan Summary for {target}\n")
            f.write("=" * 50 + "\n\n")
            
            # Directories found
            directories = results.get('directories_found', [])
            f.write(f"Directories Found: {len(directories)}\n")
            if directories:
                f.write("Notable Directories:\n")
                for directory in directories[:10]:  # Limit to 10
                    status = directory.get('status_code', 'N/A')
                    path = directory.get('path', 'N/A')
                    f.write(f"  {path} [{status}]")
                    
                    if directory.get('directory_listing'):
                        f.write(" (Directory Listing)")
                    if directory.get('redirect_location'):
                        f.write(f" -> {directory['redirect_location']}")
                    f.write("\n")
                f.write("\n")
            
            # Files found
            files = results.get('files_found', [])
            f.write(f"Files Found: {len(files)}\n")
            if files:
                f.write("Notable Files:\n")
                for file in files[:10]:  # Limit to 10
                    status = file.get('status_code', 'N/A')
                    filename = file.get('filename', 'N/A')
                    size = file.get('content_length', 0)
                    f.write(f"  {filename} [{status}] ({size} bytes)")
                    
                    if file.get('contains_php_code'):
                        f.write(" (PHP Code)")
                    if file.get('contains_sensitive_info'):
                        f.write(" (Sensitive Info)")
                    f.write("\n")
                f.write("\n")
            
            # Interesting files
            interesting = results.get('interesting_files', [])
            if interesting:
                f.write(f"Interesting Files ({len(interesting)}):\n")
                for file in interesting:
                    path = file.get('path', 'N/A')
                    risk = file.get('risk_level', 'unknown')
                    file_type = file.get('type', 'unknown')
                    f.write(f"  {path} - {file_type} (Risk: {risk})")
                    
                    if file.get('contains_secrets'):
                        f.write(" ⚠️ Contains secrets")
                    if file.get('contains_phpinfo'):
                        f.write(" ⚠️ PHP Info")
                    if file.get('contains_sql'):
                        f.write(" ⚠️ SQL Content")
                    f.write("\n")
                f.write("\n")
            
            # Security files
            security_files = results.get('security_files', [])
            if security_files:
                f.write(f"Security Files ({len(security_files)}):\n")
                for file in security_files:
                    path = file.get('path', 'N/A')
                    desc = file.get('description', 'N/A')
                    f.write(f"  {path} - {desc}\n")
                    
                    if file.get('disallowed_paths'):
                        f.write(f"    Disallowed paths: {', '.join(file['disallowed_paths'][:3])}\n")
                f.write("\n")
            
            # Response analysis
            response_analysis = results.get('response_analysis', {})
            if response_analysis:
                f.write("Response Analysis:\n")
                
                status_dist = response_analysis.get('status_code_distribution', {})
                f.write(f"  Status Code Distribution: {dict(status_dist)}\n")
                
                avg_time = response_analysis.get('average_response_time', 0)
                f.write(f"  Average Response Time: {avg_time:.2f}s\n")
                
                large_responses = response_analysis.get('large_responses', [])
                if large_responses:
                    f.write(f"  Large Responses ({len(large_responses)}):\n")
                    for large in large_responses[:3]:
                        f.write(f"    {large.get('path', 'N/A')} ({large.get('content_length', 0)} bytes)\n")
                
                false_positives = response_analysis.get('potential_false_positives', [])
                if false_positives:
                    f.write(f"  Potential False Positives: {len(false_positives)} patterns\n")
        
        self.logger.info(f"Directory summary saved to {txt_file}")
