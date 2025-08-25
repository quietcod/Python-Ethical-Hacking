"""
Web Scanner
Comprehensive web application scanning and analysis
"""

import json
import logging
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin

import requests

from ...core.exceptions import ScanError, ToolNotFoundError
from ...core.utils import check_tool_installed


class WebScanner:
    """Web application scanner wrapper with multiple tools support"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        
        # Create web output directory
        self.web_dir = output_dir / 'web'
        self.web_dir.mkdir(exist_ok=True)
        
    def scan_target(self, target: str) -> Dict[str, Any]:
        """Run comprehensive web application scan"""
        self.logger.info(f"Starting web application scan for {target}")
        
        results = {
            'target': target,
            'nikto': {},
            'technology_stack': {},
            'security_headers': {},
            'directories': []
        }
        
        # Determine if target is HTTP/HTTPS accessible
        urls = self._get_web_urls(target)
        
        for url in urls[:2]:  # Limit to 2 URLs
            self.logger.info(f"Scanning {url}")
            
            # Run Nikto scan
            nikto_results = self._run_nikto(url)
            results['nikto'][url] = nikto_results
            
            # Technology stack detection
            tech_stack = self._detect_technology_stack(url)
            results['technology_stack'][url] = tech_stack
            
            # Security headers analysis
            headers = self._analyze_security_headers(url)
            results['security_headers'][url] = headers
            
            # Directory brute force
            directories = self._brute_force_dirs(url)
            results['directories'].extend(directories)
            
            # Enhanced directory discovery with modern tools
            enhanced_dirs = self._enhanced_directory_discovery(url)
            results['directories'].extend(enhanced_dirs)
        
        # Save results
        self._save_web_results(target, results)
        
        return results
    
    def _get_web_urls(self, target: str) -> List[str]:
        """Get HTTP/HTTPS URLs for target"""
        urls = []
        
        # If target is already a URL, use it
        if target.startswith('http'):
            urls.append(target)
        else:
            # Try both HTTP and HTTPS
            for scheme in ['https', 'http']:
                url = f"{scheme}://{target}"
                try:
                    response = requests.head(url, timeout=10, allow_redirects=True)
                    if response.status_code < 400:
                        urls.append(url)
                except:
                    continue
        
        return urls if urls else [f"http://{target}"]  # Fallback
    
    def _run_nikto(self, url: str) -> Dict[str, Any]:
        """Run Nikto web vulnerability scanner"""
        try:
            if not check_tool_installed('nikto'):
                self.logger.warning("Nikto not available")
                return {'error': 'Tool not available'}
                
            self.logger.info(f"Running Nikto on {url}")
            
            output_file = self.web_dir / f'nikto_{self._sanitize_url(url)}.txt'
            
            cmd = [
                'nikto',
                '-h', url,
                '-output', str(output_file),
                '-Format', 'txt'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('timeout', 300)
            )
            
            nikto_results = {
                'return_code': result.returncode,
                'findings': []
            }
            
            if output_file.exists():
                with open(output_file, 'r') as f:
                    content = f.read()
                    # Simple parsing of Nikto output
                    lines = content.split('\n')
                    for line in lines:
                        if line.startswith('+'):
                            nikto_results['findings'].append(line.strip())
            
            return nikto_results
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.warning(f"Nikto error: {str(e)}")
            return {'error': str(e)}
    
    def _detect_technology_stack(self, url: str) -> Dict[str, Any]:
        """Enhanced technology stack detection with Wappalyzer-style analysis"""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            tech_stack = {
                'server': response.headers.get('Server', ''),
                'powered_by': response.headers.get('X-Powered-By', ''),
                'framework': [],
                'cms': [],
                'programming_language': [],
                'web_servers': [],
                'databases': [],
                'javascript_libraries': [],
                'cdn': [],
                'analytics': [],
                'confidence_score': 0
            }
            
            # Analyze headers, content, and scripts
            content = response.text.lower()
            headers = response.headers
            
            # Enhanced detection patterns
            detection_patterns = {
                'cms': [
                    ('WordPress', r'wp-content|wp-includes|wordpress|wp-json', 'meta[name="generator"][content*="wordpress"]'),
                    ('Drupal', r'drupal|sites/default|misc/drupal\.js', 'meta[name="generator"][content*="drupal"]'),
                    ('Joomla', r'joomla|com_content|media/jui', 'meta[name="generator"][content*="joomla"]'),
                    ('Magento', r'magento|mage/|skin/frontend', 'var BLANK_URL'),
                    ('Shopify', r'shopify|cdn\.shopify\.com', 'shopify'),
                    ('PrestaShop', r'prestashop|ps_', 'prestashop'),
                ],
                'frameworks': [
                    ('React', r'react|__react|data-reactroot', '_react'),
                    ('Angular', r'angular|ng-|angularjs', 'angular'),
                    ('Vue.js', r'vue\.js|__vue__|v-if|v-for', 'vue'),
                    ('Laravel', r'laravel_session|laravel_token', 'laravel'),
                    ('Django', r'django|csrfmiddlewaretoken', 'django'),
                    ('Ruby on Rails', r'rails|csrf-token|authenticity_token', 'rails'),
                    ('Express.js', r'express|x-powered-by.*express', 'express'),
                    ('Spring', r'spring|jsessionid|java_session', 'spring'),
                ],
                'languages': [
                    ('PHP', r'\.php|php|x-powered-by.*php', 'phpsessid'),
                    ('ASP.NET', r'\.aspx|asp\.net|x-aspnet-version', 'asp.net_sessionid'),
                    ('Java', r'\.jsp|\.jsf|jsessionid', 'java'),
                    ('Python', r'\.py|django|flask|wsgi', 'python'),
                    ('Node.js', r'node\.js|express|x-powered-by.*express', 'nodejs'),
                    ('Ruby', r'\.rb|rails|ruby', 'ruby'),
                ],
                'servers': [
                    ('Apache', r'apache|httpd', 'server.*apache'),
                    ('Nginx', r'nginx', 'server.*nginx'),
                    ('IIS', r'iis|microsoft-iis', 'server.*iis'),
                    ('LiteSpeed', r'litespeed|lsws', 'server.*litespeed'),
                    ('Cloudflare', r'cloudflare|cf-ray', 'cf-ray'),
                ],
                'js_libraries': [
                    ('jQuery', r'jquery|jquery\.min\.js', 'jquery'),
                    ('Bootstrap', r'bootstrap|bootstrap\.min\.css', 'bootstrap'),
                    ('Modernizr', r'modernizr', 'modernizr'),
                    ('Underscore.js', r'underscore\.js|_\.', 'underscore'),
                    ('Moment.js', r'moment\.js', 'moment'),
                ],
                'analytics': [
                    ('Google Analytics', r'google-analytics|ga\.js|gtag', 'ua-'),
                    ('Google Tag Manager', r'googletagmanager', 'gtm'),
                    ('Adobe Analytics', r'omniture|adobe.*analytics', 'omniture'),
                    ('Hotjar', r'hotjar', 'hotjar'),
                ],
                'cdn': [
                    ('Cloudflare', r'cloudflare|cf-ray', 'cf-ray'),
                    ('AWS CloudFront', r'cloudfront', 'cloudfront'),
                    ('Fastly', r'fastly', 'fastly'),
                    ('MaxCDN', r'maxcdn', 'maxcdn'),
                ]
            }
            
            confidence = 0
            
            # Check each category
            for category, patterns in detection_patterns.items():
                for tech_name, content_pattern, header_pattern in patterns:
                    score = 0
                    
                    # Check content patterns
                    if re.search(content_pattern, content):
                        score += 1
                        
                    # Check header patterns
                    for header_name, header_value in headers.items():
                        if re.search(header_pattern, f"{header_name}: {header_value}".lower()):
                            score += 2  # Headers are more reliable
                            
                    if score > 0:
                        category_key = category.rstrip('s')  # Remove 's' for dict key
                        if category_key not in tech_stack:
                            tech_stack[category_key] = []
                        tech_stack[category_key].append({
                            'name': tech_name,
                            'confidence': min(score * 33, 100)  # Cap at 100%
                        })
                        confidence += score
            
            # Special detection for specific technologies
            self._detect_cms_specific(url, tech_stack, content, headers)
            self._detect_api_technologies(url, tech_stack)
            
            tech_stack['confidence_score'] = min(confidence * 10, 100)
            return tech_stack
            
        except Exception as e:
            self.logger.error(f"Error detecting technology stack: {str(e)}")
            return {}
    
    def _detect_cms_specific(self, url: str, tech_stack: Dict[str, Any], content: str, headers: Dict[str, str]) -> None:
        """Specific CMS detection with version discovery"""
        try:
            # WordPress specific
            if any('wordpress' in item['name'].lower() for item in tech_stack.get('cms', [])):
                wp_version = self._get_wordpress_version(url, content)
                if wp_version:
                    for item in tech_stack['cms']:
                        if 'wordpress' in item['name'].lower():
                            item['version'] = wp_version
                            
            # Check for admin panels
            admin_paths = [
                '/wp-admin/', '/admin/', '/administrator/', '/admin.php',
                '/wp-login.php', '/login/', '/dashboard/'
            ]
            
            accessible_admin = []
            for path in admin_paths:
                try:
                    admin_url = urljoin(url, path)
                    resp = requests.get(admin_url, timeout=5, allow_redirects=True)
                    if resp.status_code == 200:
                        accessible_admin.append(path)
                except:
                    continue
                    
            if accessible_admin:
                tech_stack['admin_panels'] = accessible_admin
                
        except Exception as e:
            self.logger.debug(f"CMS specific detection error: {str(e)}")
    
    def _get_wordpress_version(self, url: str, content: str) -> Optional[str]:
        """Get WordPress version"""
        try:
            # Check generator meta tag
            version_match = re.search(r'wordpress\s+([\d\.]+)', content)
            if version_match:
                return version_match.group(1)
                
            # Check readme.html
            readme_url = urljoin(url, '/readme.html')
            resp = requests.get(readme_url, timeout=5)
            if resp.status_code == 200:
                version_match = re.search(r'version\s+([\d\.]+)', resp.text.lower())
                if version_match:
                    return version_match.group(1)
                    
        except Exception:
            pass
        return None
    
    def _detect_api_technologies(self, url: str, tech_stack: Dict[str, Any]) -> None:
        """Detect API-related technologies"""
        try:
            api_endpoints = [
                '/api/', '/api/v1/', '/api/v2/', '/rest/', '/graphql',
                '/swagger/', '/openapi.json', '/api-docs'
            ]
            
            api_info = []
            for endpoint in api_endpoints:
                try:
                    api_url = urljoin(url, endpoint)
                    resp = requests.get(api_url, timeout=5)
                    if resp.status_code in [200, 401, 403]:  # API exists but may need auth
                        api_info.append({
                            'endpoint': endpoint,
                            'status': resp.status_code,
                            'content_type': resp.headers.get('Content-Type', '')
                        })
                except:
                    continue
                    
            if api_info:
                tech_stack['api_endpoints'] = api_info
                
        except Exception as e:
            self.logger.debug(f"API detection error: {str(e)}")
    
    def api_fuzzing(self, base_url: str, endpoints: Optional[List[str]] = None) -> Dict[str, Any]:
        """Enhanced API fuzzing and enumeration"""
        try:
            self.logger.info(f"Starting API fuzzing for: {base_url}")
            
            results = {
                'discovered_endpoints': [],
                'parameter_fuzzing': {},
                'authentication_tests': {},
                'rate_limiting': {},
                'security_headers': {}
            }
            
            if not endpoints:
                endpoints = self._discover_api_endpoints(base_url)
            
            for endpoint in endpoints:
                full_url = urljoin(base_url, endpoint)
                self.logger.info(f"Testing endpoint: {endpoint}")
                
                # Test different HTTP methods
                methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
                endpoint_results = {}
                
                for method in methods:
                    try:
                        resp = requests.request(method, full_url, timeout=10)
                        endpoint_results[method] = {
                            'status_code': resp.status_code,
                            'response_time': resp.elapsed.total_seconds(),
                            'content_length': len(resp.content),
                            'headers': dict(resp.headers)
                        }
                        
                        # Check for interesting responses
                        if resp.status_code in [200, 201, 202, 400, 401, 403, 422]:
                            endpoint_results[method]['interesting'] = True
                            
                    except Exception as e:
                        endpoint_results[method] = {'error': str(e)}
                
                results['discovered_endpoints'].append({
                    'endpoint': endpoint,
                    'methods': endpoint_results
                })
                
                # Parameter fuzzing for GET endpoints
                if endpoint_results.get('GET', {}).get('status_code') == 200:
                    param_results = self._fuzz_parameters(full_url)
                    if param_results:
                        results['parameter_fuzzing'][endpoint] = param_results
                
                # Rate limiting test
                rate_limit = self._test_rate_limiting(full_url)
                if rate_limit:
                    results['rate_limiting'][endpoint] = rate_limit
            
            # Authentication bypass tests
            results['authentication_tests'] = self._test_auth_bypass(base_url)
            
            self.logger.info(f"API fuzzing completed. Found {len(results['discovered_endpoints'])} endpoints")
            return results
            
        except Exception as e:
            self.logger.error(f"API fuzzing error: {str(e)}")
            return {}
    
    def _discover_api_endpoints(self, base_url: str) -> List[str]:
        """Discover API endpoints through various methods"""
        endpoints = set()
        
        # Common API paths
        common_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
            '/rest/', '/graphql', '/swagger/', '/openapi.json',
            '/api-docs', '/docs/', '/documentation/',
            '/users/', '/user/', '/admin/', '/auth/',
            '/login/', '/register/', '/profile/', '/settings/',
            '/products/', '/orders/', '/payments/', '/search/'
        ]
        
        self.logger.info("Discovering API endpoints...")
        for path in common_paths:
            try:
                url = urljoin(base_url, path)
                resp = requests.get(url, timeout=5)
                if resp.status_code not in [404, 502, 503]:
                    endpoints.add(path)
            except:
                continue
        
        # Try to find endpoints from JavaScript files
        try:
            resp = requests.get(base_url, timeout=10)
            js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text)
            
            for js_url in js_urls[:5]:  # Limit to first 5 JS files
                full_js_url = urljoin(base_url, js_url)
                try:
                    js_resp = requests.get(full_js_url, timeout=5)
                    # Look for API endpoints in JS
                    api_patterns = re.findall(r'["\'](/api/[^"\']*)["\']', js_resp.text)
                    endpoints.update(api_patterns)
                except:
                    continue
        except:
            pass
            
        return list(endpoints)
    
    def _fuzz_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Fuzz common parameters"""
        common_params = [
            'id', 'user_id', 'username', 'email', 'token', 'key',
            'page', 'limit', 'offset', 'search', 'query', 'filter',
            'sort', 'order', 'category', 'type', 'format', 'callback'
        ]
        
        interesting_responses = []
        
        for param in common_params:
            test_values = ['1', 'admin', 'test', '../', 'null', '0', '-1']
            
            for value in test_values:
                try:
                    resp = requests.get(url, params={param: value}, timeout=5)
                    
                    # Check for interesting status codes or content changes
                    if resp.status_code in [200, 400, 422, 500] and len(resp.content) > 100:
                        interesting_responses.append({
                            'parameter': param,
                            'value': value,
                            'status_code': resp.status_code,
                            'content_length': len(resp.content)
                        })
                        break  # Found interesting response, move to next param
                except:
                    continue
                    
        return interesting_responses
    
    def _test_rate_limiting(self, url: str) -> Optional[Dict[str, Any]]:
        """Test for rate limiting"""
        try:
            response_times = []
            status_codes = []
            
            for i in range(10):  # Make 10 rapid requests
                start_time = time.time()
                resp = requests.get(url, timeout=5)
                response_time = time.time() - start_time
                
                response_times.append(response_time)
                status_codes.append(resp.status_code)
                
                # Check for rate limiting status codes
                if resp.status_code in [429, 503]:
                    return {
                        'rate_limited': True,
                        'status_code': resp.status_code,
                        'request_number': i + 1,
                        'retry_after': resp.headers.get('Retry-After')
                    }
                    
            # Check if response times increased significantly
            if len(response_times) > 5:
                avg_first_half = sum(response_times[:5]) / 5
                avg_second_half = sum(response_times[5:]) / len(response_times[5:])
                
                if avg_second_half > avg_first_half * 2:  # 2x slower
                    return {
                        'potential_rate_limiting': True,
                        'avg_response_time_increase': avg_second_half / avg_first_half
                    }
                    
        except Exception:
            pass
            
        return None
    
    def _test_auth_bypass(self, base_url: str) -> Dict[str, Any]:
        """Test common authentication bypass techniques"""
        bypass_tests = {
            'headers': [
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Real-IP': '127.0.0.1'},
                {'X-Originating-IP': '127.0.0.1'},
                {'X-Remote-IP': '127.0.0.1'},
                {'X-Client-IP': '127.0.0.1'},
                {'X-Original-URL': '/admin'},
                {'X-Rewrite-URL': '/admin'},
            ],
            'parameters': [
                {'admin': 'true'},
                {'debug': '1'},
                {'test': '1'},
                {'role': 'admin'},
                {'privilege': 'admin'}
            ]
        }
        
        results = {}
        protected_endpoints = ['/admin/', '/api/admin/', '/dashboard/', '/profile/']
        
        for endpoint in protected_endpoints:
            url = urljoin(base_url, endpoint)
            endpoint_results = []
            
            try:
                # Baseline request
                baseline = requests.get(url, timeout=5)
                baseline_status = baseline.status_code
                
                # Test header bypasses
                for headers in bypass_tests['headers']:
                    try:
                        resp = requests.get(url, headers=headers, timeout=5)
                        if resp.status_code != baseline_status and resp.status_code == 200:
                            endpoint_results.append({
                                'type': 'header_bypass',
                                'method': headers,
                                'status_code': resp.status_code
                            })
                    except:
                        continue
                
                # Test parameter bypasses
                for params in bypass_tests['parameters']:
                    try:
                        resp = requests.get(url, params=params, timeout=5)
                        if resp.status_code != baseline_status and resp.status_code == 200:
                            endpoint_results.append({
                                'type': 'parameter_bypass',
                                'method': params,
                                'status_code': resp.status_code
                            })
                    except:
                        continue
                        
                if endpoint_results:
                    results[endpoint] = endpoint_results
                    
            except:
                continue
                
        return results
    
    def _analyze_security_headers(self, url: str) -> Dict[str, Any]:
        """Analyze security headers"""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            security_headers = {
                'x_frame_options': response.headers.get('X-Frame-Options'),
                'x_content_type_options': response.headers.get('X-Content-Type-Options'),
                'strict_transport_security': response.headers.get('Strict-Transport-Security'),
                'content_security_policy': response.headers.get('Content-Security-Policy'),
                'missing_headers': []
            }
            
            # Check for missing security headers
            required_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options', 
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            for header in required_headers:
                if header not in response.headers:
                    security_headers['missing_headers'].append(header)
            
            return security_headers
            
        except Exception as e:
            self.logger.error(f"Error analyzing security headers: {str(e)}")
            return {}
    
    def _sanitize_url(self, url: str) -> str:
        """Sanitize URL for filename"""
        return re.sub(r'[^\w\-_\.]', '_', url)
    
    def _brute_force_dirs(self, url: str) -> List[Dict[str, Any]]:
        """Brute force directories and common files with concurrency control and rate limiting"""
        try:
            self.logger.info(f"Starting directory brute force for {url}")
            
            # Load directory wordlist with comprehensive error handling
            wordlist_path = self.config.get('dir_wordlist', '/usr/share/wordlists/dirb/common.txt')
            
            # Create a basic directory/file wordlist as fallback
            basic_dirs = [
                # Common directories
                'admin', 'administrator', 'login', 'uploads', 'images', 'img', 'css', 'js',
                'api', 'config', 'backup', 'backups', 'tmp', 'temp', 'test', 'dev',
                'phpmyadmin', 'wp-admin', 'wp-content', 'wp-includes', 'dashboard', 'panel',
                'control', 'cpanel', 'webmail', 'mail', 'ftp', 'ssh', 'logs', 'log',
                'database', 'db', 'files', 'documents', 'downloads', 'media', 'assets',
                'private', 'secret', 'hidden', 'secure', 'protected', 'include', 'inc',
                
                # Common files
                'robots.txt', 'sitemap.xml', 'favicon.ico', 'crossdomain.xml',
                '.htaccess', '.htpasswd', 'web.config', 'readme.txt', 'README.md',
                'install.php', 'setup.php', 'config.php', 'wp-config.php',
                'phpinfo.php', 'info.php', 'test.php', 'index.bak',
                'backup.sql', 'database.sql', 'dump.sql', '.env', '.git',
                
                # Admin panels and login pages
                'admin.php', 'login.php', 'signin.php', 'auth.php',
                'manager', 'administrator.php', 'moderator.php'
            ]
            
            # Attempt to load custom wordlist with proper error handling
            if not wordlist_path or not os.path.exists(wordlist_path):
                if wordlist_path:
                    self.logger.warning(f"Directory wordlist not found: {wordlist_path}, skipping directory brute force")
                    self.logger.info("To enable directory brute force, specify a valid wordlist")
                    return []  # Skip directory brute force entirely if no wordlist
                else:
                    self.logger.info("No directory wordlist specified, using built-in wordlist")
                    self.logger.info(f"Using built-in directory wordlist ({len(basic_dirs)} entries)")
                    wordlist = basic_dirs
            else:
                try:
                    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        if wordlist:
                            # Limit wordlist size for performance
                            max_words = self.config.get('max_words', 5000)
                            if len(wordlist) > max_words:
                                self.logger.info(f"Limiting wordlist from {len(wordlist)} to {max_words} entries")
                                wordlist = wordlist[:max_words]
                            self.logger.info(f"Loaded directory wordlist from {wordlist_path} ({len(wordlist)} entries)")
                        else:
                            self.logger.warning(f"Directory wordlist is empty: {wordlist_path}, skipping directory brute force")
                            return []  # Skip if wordlist is empty
                except (IOError, OSError, PermissionError) as e:
                    self.logger.error(f"Cannot read directory wordlist '{wordlist_path}': {str(e)}, skipping directory brute force")
                    return []  # Skip directory brute force on file errors
                except Exception as e:
                    self.logger.error(f"Unexpected error loading directory wordlist '{wordlist_path}': {str(e)}, skipping directory brute force")
                    return []  # Skip directory brute force on unexpected errors
            
            # Configuration
            timeout = min(self.config.get('timeout', 5), 10)  # Max 10 seconds
            rate_limit = self.config.get('rate_limit', 0)  # Seconds between requests
            max_threads = self.config.get('threads', 10)  # Default 10 threads
            max_threads = min(max_threads, 50)  # Cap at 50 threads
            
            # Interesting status codes to save
            interesting_codes = {
                200: 'OK',
                201: 'Created', 
                202: 'Accepted',
                204: 'No Content',
                301: 'Moved Permanently',
                302: 'Found',
                303: 'See Other',
                307: 'Temporary Redirect',
                308: 'Permanent Redirect',
                401: 'Unauthorized',
                403: 'Forbidden',
                405: 'Method Not Allowed',
                500: 'Internal Server Error',
                503: 'Service Unavailable'
            }
            
            self.logger.info(f"Using {max_threads} threads with {rate_limit}s rate limit")
            
            found_directories = []
            processed_count = 0
            
            def test_directory(path):
                """Test a single directory/file path"""
                nonlocal processed_count
                
                try:
                    # Rate limiting
                    if rate_limit > 0:
                        time.sleep(rate_limit)
                    
                    # Construct full URL
                    if not path.startswith('/'):
                        path = '/' + path
                    test_url = url.rstrip('/') + path
                    
                    # Use HEAD request for faster scanning (fallback to GET if needed)
                    try:
                        response = requests.head(
                            test_url,
                            timeout=timeout,
                            allow_redirects=False,
                            headers={
                                'User-Agent': self.config.get('user_agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
                            }
                        )
                        
                        # Some servers return 405 for HEAD but allow GET
                        if response.status_code == 405:
                            response = requests.get(
                                test_url,
                                timeout=timeout,
                                allow_redirects=False,
                                headers={
                                    'User-Agent': self.config.get('user_agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
                                }
                            )
                            
                    except requests.exceptions.RequestException:
                        # Fallback to GET request
                        response = requests.get(
                            test_url,
                            timeout=timeout,
                            allow_redirects=False,
                            headers={
                                'User-Agent': self.config.get('user_agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
                            }
                        )
                    
                    processed_count += 1
                    if processed_count % 100 == 0:
                        self.logger.info(f"Processed {processed_count}/{len(wordlist)} paths...")
                    
                    # Check for interesting status codes
                    if response.status_code in interesting_codes:
                        directory_info = {
                            'path': path,
                            'url': test_url,
                            'status_code': response.status_code,
                            'status_text': interesting_codes.get(response.status_code, 'Unknown'),
                            'size': response.headers.get('Content-Length', 'unknown'),
                            'content_type': response.headers.get('Content-Type', 'unknown'),
                            'server': response.headers.get('Server', 'unknown')
                        }
                        
                        # Add redirect information
                        if response.status_code in [301, 302, 303, 307, 308]:
                            directory_info['location'] = response.headers.get('Location', 'unknown')
                        
                        self.logger.info(f"Found: {test_url} [{response.status_code} {interesting_codes.get(response.status_code, '')}]")
                        return directory_info
                    
                    return None
                    
                except requests.exceptions.Timeout:
                    self.logger.debug(f"Timeout testing {test_url}")
                    return None
                except requests.exceptions.ConnectionError:
                    self.logger.debug(f"Connection error testing {test_url}")
                    return None
                except Exception as e:
                    self.logger.debug(f"Error testing {test_url}: {str(e)}")
                    return None
            
            # Use ThreadPoolExecutor for concurrent requests
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = [executor.submit(test_directory, path) for path in wordlist]
                
                for future in futures:
                    try:
                        result = future.result(timeout=timeout + 5)  # Give extra time for completion
                        if result:
                            found_directories.append(result)
                    except Exception as e:
                        self.logger.debug(f"Thread execution error: {str(e)}")
            
            # Save directory brute force results
            if found_directories:
                output_file = self.web_dir / f'directories_{self._sanitize_url(url)}.txt'
                with open(output_file, 'w') as f:
                    f.write(f"Directory brute force results for {url}\n")
                    f.write(f"Threads: {max_threads}, Rate limit: {rate_limit}s\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for dir_info in sorted(found_directories, key=lambda x: x['status_code']):
                        f.write(f"[{dir_info['status_code']}] {dir_info['url']} ({dir_info['status_text']})\n")
                        
                        if dir_info.get('content_type') != 'unknown':
                            f.write(f"    Content-Type: {dir_info['content_type']}\n")
                        if dir_info.get('size') != 'unknown':
                            f.write(f"    Size: {dir_info['size']} bytes\n")
                        if dir_info.get('server') != 'unknown':
                            f.write(f"    Server: {dir_info['server']}\n")
                        if dir_info.get('location'):
                            f.write(f"    Location: {dir_info['location']}\n")
                        f.write("\n")
                
                self.logger.info(f"Directory brute force found {len(found_directories)} accessible paths")
                
                # Log summary by status code
                status_summary = {}
                for item in found_directories:
                    code = item['status_code']
                    status_summary[code] = status_summary.get(code, 0) + 1
                
                summary_text = ', '.join([f"{code}: {count}" for code, count in sorted(status_summary.items())])
                self.logger.info(f"Status code summary: {summary_text}")
                
            else:
                self.logger.info("No accessible directories found")
            
            return found_directories
            
        except Exception as e:
            self.logger.error(f"Error during directory brute force: {str(e)}")
            return []

    def _enhanced_directory_discovery(self, url: str) -> List[Dict[str, Any]]:
        """Enhanced directory discovery using multiple tools (gobuster, ffuf, feroxbuster)"""
        self.logger.info(f"Starting enhanced directory discovery for {url}")
        
        discovered_paths = []
        
        # Try gobuster first (if available)
        gobuster_results = self._run_gobuster(url)
        discovered_paths.extend(gobuster_results)
        
        # Try ffuf as alternative (if available)
        if not gobuster_results:
            ffuf_results = self._run_ffuf(url)
            discovered_paths.extend(ffuf_results)
        
        # Try feroxbuster for recursive discovery (if available)
        ferox_results = self._run_feroxbuster(url)
        discovered_paths.extend(ferox_results)
        
        # Deduplicate results
        unique_paths = list(set(discovered_paths))
        
        self.logger.info(f"Enhanced directory discovery found {len(unique_paths)} unique paths")
        return unique_paths

    def _run_gobuster(self, url: str) -> List[Dict[str, Any]]:
        """Run gobuster for directory discovery"""
        try:
            if not check_tool_installed('gobuster'):
                self.logger.warning("Gobuster not available")
                return []
            
            self.logger.info(f"Running gobuster directory scan on {url}")
            
            # Get wordlist path
            wordlist_path = self.config.get('dir_wordlist', '/usr/share/wordlists/dirb/common.txt')
            
            # Fallback wordlists
            fallback_wordlists = [
                '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/seclists/Discovery/Web-Content/common.txt',
                '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'
            ]
            
            # Find available wordlist
            if not os.path.exists(wordlist_path):
                for fallback in fallback_wordlists:
                    if os.path.exists(fallback):
                        wordlist_path = fallback
                        break
                else:
                    self.logger.warning("No wordlist found for gobuster")
                    return []
            
            output_file = self.web_dir / f'gobuster_{self._sanitize_url(url)}.txt'
            
            cmd = [
                'gobuster', 'dir',
                '-u', url,
                '-w', wordlist_path,
                '-o', str(output_file),
                '-t', '50',  # 50 threads
                '-x', 'php,html,txt,js,css,bak,old,backup',  # Common extensions
                '--wildcard',
                '--no-error',
                '--quiet'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse results
            discovered_paths = []
            if output_file.exists():
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip() and not line.startswith('='):
                            # Extract path from gobuster output
                            parts = line.strip().split()
                            if parts:
                                path = parts[0]
                                discovered_paths.append({
                                    'path': path,
                                    'status': parts[1] if len(parts) > 1 else 'unknown',
                                    'size': parts[2] if len(parts) > 2 else 'unknown',
                                    'tool': 'gobuster'
                                })
            
            self.logger.info(f"Gobuster found {len(discovered_paths)} directories/files")
            return discovered_paths
            
        except subprocess.CalledProcessError:
            self.logger.warning("Gobuster not available")
            return []
        except Exception as e:
            self.logger.error(f"Error running gobuster: {str(e)}")
            return []

    def _run_ffuf(self, url: str) -> List[Dict[str, Any]]:
        """Run ffuf for directory discovery"""
        try:
            if not check_tool_installed('ffuf'):
                self.logger.warning("Ffuf not available")
                return []
            
            self.logger.info(f"Running ffuf directory scan on {url}")
            
            # Get wordlist path
            wordlist_path = self.config.get('dir_wordlist', '/usr/share/wordlists/dirb/common.txt')
            
            if not os.path.exists(wordlist_path):
                self.logger.warning("No wordlist found for ffuf")
                return []
            
            output_file = self.web_dir / f'ffuf_{self._sanitize_url(url)}.json'
            
            cmd = [
                'ffuf',
                '-u', f"{url}/FUZZ",
                '-w', wordlist_path,
                '-o', str(output_file),
                '-of', 'json',
                '-t', '50',  # 50 threads
                '-mc', '200,204,301,302,307,401,403',  # Match status codes
                '-fs', '0',  # Filter size 0
                '-silent'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse JSON results
            discovered_paths = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        for result in data.get('results', []):
                            discovered_paths.append({
                                'path': f"/{result['input']['FUZZ']}",
                                'status': result['status'],
                                'size': result['length'],
                                'words': result['words'],
                                'tool': 'ffuf'
                            })
                except json.JSONDecodeError:
                    self.logger.warning("Could not parse ffuf JSON output")
            
            self.logger.info(f"Ffuf found {len(discovered_paths)} directories/files")
            return discovered_paths
            
        except subprocess.CalledProcessError:
            self.logger.warning("Ffuf not available")
            return []
        except Exception as e:
            self.logger.error(f"Error running ffuf: {str(e)}")
            return []

    def _run_feroxbuster(self, url: str) -> List[Dict[str, Any]]:
        """Run feroxbuster for recursive directory discovery"""
        try:
            if not check_tool_installed('feroxbuster'):
                self.logger.warning("Feroxbuster not available")
                return []
            
            self.logger.info(f"Running feroxbuster recursive scan on {url}")
            
            # Get wordlist path
            wordlist_path = self.config.get('dir_wordlist', '/usr/share/wordlists/dirb/common.txt')
            
            if not os.path.exists(wordlist_path):
                self.logger.warning("No wordlist found for feroxbuster")
                return []
            
            output_file = self.web_dir / f'feroxbuster_{self._sanitize_url(url)}.txt'
            
            cmd = [
                'feroxbuster',
                '-u', url,
                '-w', wordlist_path,
                '-o', str(output_file),
                '-t', '50',  # 50 threads
                '-d', '3',   # Depth of 3
                '-x', 'php,html,txt,js,css,bak,old,backup',  # Extensions
                '--silent',
                '--no-recursion'  # Control recursion manually
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            # Parse results
            discovered_paths = []
            if output_file.exists():
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip() and 'HTTP' in line:
                            # Parse feroxbuster output format
                            parts = line.strip().split()
                            if len(parts) >= 4:
                                status = parts[0]
                                size = parts[1]
                                path = parts[-1].replace(url, '')
                                discovered_paths.append({
                                    'path': path,
                                    'status': status,
                                    'size': size,
                                    'tool': 'feroxbuster'
                                })
            
            self.logger.info(f"Feroxbuster found {len(discovered_paths)} directories/files")
            return discovered_paths
            
        except subprocess.CalledProcessError:
            self.logger.warning("Feroxbuster not available")
            return []
        except Exception as e:
            self.logger.error(f"Error running feroxbuster: {str(e)}")
            return []
    
    def _save_web_results(self, target: str, results: Dict[str, Any]) -> None:
        """Save web scanning results"""
        json_file = self.web_dir / f'{target}_web_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Web scan results saved to {json_file}")
    
    def is_wordpress(self, target: str) -> bool:
        """Check if target is running WordPress"""
        try:
            urls = self._get_web_urls(target)
            
            for url in urls[:1]:  # Check only first URL
                response = requests.get(url, timeout=10)
                content = response.text.lower()
                
                # Check for WordPress indicators
                wp_indicators = ['wp-content', 'wp-includes', 'wordpress']
                
                for indicator in wp_indicators:
                    if indicator in content:
                        return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking for WordPress: {str(e)}")
            return False
