"""
API Scanner
REST API and web service analysis
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse

import requests

from ...core.exceptions import ScanError


class APIScanner:
    """REST API and web service scanner"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        
        # Create API output directory
        self.api_dir = output_dir / 'api'
        self.api_dir.mkdir(exist_ok=True)
        
    def scan_apis(self, target: str) -> Dict[str, Any]:
        """Run comprehensive API scanning"""
        self.logger.info(f"Starting API scan for {target}")
        
        results = {
            'target': target,
            'api_discovery': {},
            'endpoint_analysis': {},
            'security_testing': {},
            'documentation_discovery': {},
            'schema_analysis': {}
        }
        
        try:
            # Prepare base URL
            base_url = self._prepare_base_url(target)
            
            # API discovery and analysis
            self._discover_api_endpoints(base_url, results)
            
            # Documentation discovery
            self._discover_api_documentation(base_url, results)
            
            # Security analysis
            self._analyze_api_security(base_url, results)
            
            # Schema analysis
            self._analyze_api_schemas(base_url, results)
            
            # Save results
            self._save_api_results(target, results)
            
        except Exception as e:
            self.logger.error(f"API scan failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _prepare_base_url(self, target: str) -> str:
        """Prepare base URL for API scanning"""
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
    
    def _discover_api_endpoints(self, base_url: str, results: Dict[str, Any]) -> None:
        """Discover API endpoints"""
        self.logger.info(f"Discovering API endpoints for {base_url}")
        
        discovery_results = {
            'common_paths': {},
            'discovered_endpoints': [],
            'api_versions': [],
            'interesting_files': []
        }
        
        try:
            # Common API paths to check
            api_paths = [
                '/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3',
                '/rest', '/restapi', '/api/rest',
                '/graphql', '/api/graphql',
                '/swagger', '/api/swagger', '/swagger-ui',
                '/docs', '/api/docs', '/api-docs',
                '/openapi.json', '/swagger.json', '/api.json',
                '/health', '/status', '/ping', '/info', '/version',
                '/users', '/user', '/admin', '/auth', '/login', '/register',
                '/products', '/orders', '/payments', '/search',
                '/upload', '/download', '/files'
            ]
            
            # Test each path
            for path in api_paths:
                try:
                    url = urljoin(base_url, path)
                    response = requests.get(url, timeout=10, allow_redirects=True)
                    
                    path_info = {
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                        'content_length': len(response.content),
                        'response_time': response.elapsed.total_seconds()
                    }
                    
                    # Check for interesting responses
                    if response.status_code in [200, 201, 202, 401, 403]:
                        path_info['interesting'] = True
                        
                        # Analyze response content
                        content_analysis = self._analyze_response_content(response)
                        path_info.update(content_analysis)
                        
                        discovery_results['discovered_endpoints'].append({
                            'path': path,
                            'url': url,
                            **path_info
                        })
                    
                    discovery_results['common_paths'][path] = path_info
                    
                    # Rate limiting
                    time.sleep(0.1)
                    
                except requests.exceptions.RequestException as e:
                    discovery_results['common_paths'][path] = {
                        'error': str(e),
                        'status_code': 0
                    }
                except Exception as e:
                    self.logger.debug(f"Error testing path {path}: {str(e)}")
            
            # Discover endpoints from JavaScript files
            js_endpoints = self._discover_endpoints_from_js(base_url)
            discovery_results['discovered_endpoints'].extend(js_endpoints)
            
            # Discover endpoints from robots.txt and sitemap
            additional_endpoints = self._discover_endpoints_from_files(base_url)
            discovery_results['discovered_endpoints'].extend(additional_endpoints)
            
        except Exception as e:
            self.logger.error(f"API endpoint discovery error: {str(e)}")
            discovery_results['error'] = str(e)
        
        results['api_discovery'] = discovery_results
        
        endpoint_count = len(discovery_results.get('discovered_endpoints', []))
        self.logger.info(f"API discovery found {endpoint_count} potential endpoints")
    
    def _analyze_response_content(self, response: requests.Response) -> Dict[str, Any]:
        """Analyze response content for API characteristics"""
        analysis = {}
        
        try:
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Check if it's JSON
            if 'application/json' in content_type or 'json' in content_type:
                analysis['format'] = 'json'
                
                try:
                    json_data = response.json()
                    analysis['json_structure'] = self._analyze_json_structure(json_data)
                except:
                    analysis['json_valid'] = False
            
            # Check if it's XML
            elif 'xml' in content_type:
                analysis['format'] = 'xml'
            
            # Check if it's HTML (likely documentation)
            elif 'text/html' in content_type:
                analysis['format'] = 'html'
                
                # Look for API documentation indicators
                content = response.text.lower()
                doc_indicators = ['swagger', 'openapi', 'api documentation', 'rest api', 'graphql']
                
                for indicator in doc_indicators:
                    if indicator in content:
                        analysis['documentation_type'] = indicator
                        break
            
            # Check response headers for API indicators
            api_headers = {}
            for header, value in response.headers.items():
                if any(keyword in header.lower() for keyword in ['api', 'cors', 'rate', 'limit']):
                    api_headers[header] = value
            
            if api_headers:
                analysis['api_headers'] = api_headers
            
            # Check for authentication requirements
            if response.status_code == 401:
                analysis['requires_auth'] = True
                auth_header = response.headers.get('WWW-Authenticate', '')
                if auth_header:
                    analysis['auth_method'] = auth_header
            
        except Exception as e:
            analysis['analysis_error'] = str(e)
        
        return analysis
    
    def _analyze_json_structure(self, json_data: Any) -> Dict[str, Any]:
        """Analyze JSON structure"""
        structure = {}
        
        try:
            if isinstance(json_data, dict):
                structure['type'] = 'object'
                structure['keys'] = list(json_data.keys())[:10]  # Limit keys
                structure['key_count'] = len(json_data.keys())
                
                # Look for common API patterns
                if 'data' in json_data:
                    structure['has_data_wrapper'] = True
                if 'error' in json_data or 'errors' in json_data:
                    structure['has_error_field'] = True
                if 'status' in json_data:
                    structure['has_status_field'] = True
                
            elif isinstance(json_data, list):
                structure['type'] = 'array'
                structure['length'] = len(json_data)
                
                if json_data and isinstance(json_data[0], dict):
                    structure['item_type'] = 'object'
                    structure['sample_keys'] = list(json_data[0].keys())[:5]
            
            else:
                structure['type'] = type(json_data).__name__
        
        except Exception as e:
            structure['error'] = str(e)
        
        return structure
    
    def _discover_endpoints_from_js(self, base_url: str) -> List[Dict[str, Any]]:
        """Discover API endpoints from JavaScript files"""
        endpoints = []
        
        try:
            # Get main page to find JS files
            response = requests.get(base_url, timeout=10)
            
            # Simple regex to find JS file references
            import re
            js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', response.text)
            
            for js_file in js_files[:5]:  # Limit to 5 JS files
                try:
                    js_url = urljoin(base_url, js_file)
                    js_response = requests.get(js_url, timeout=10)
                    
                    # Look for API endpoint patterns
                    api_patterns = [
                        r'["\']/(api/[^"\']*)["\']',
                        r'["\']/(v\d+/[^"\']*)["\']',
                        r'["\']/(rest/[^"\']*)["\']'
                    ]
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, js_response.text)
                        for match in matches:
                            endpoints.append({
                                'path': f'/{match}',
                                'source': 'javascript',
                                'js_file': js_file
                            })
                
                except Exception as e:
                    self.logger.debug(f"Error analyzing JS file {js_file}: {str(e)}")
        
        except Exception as e:
            self.logger.debug(f"Error discovering endpoints from JS: {str(e)}")
        
        return endpoints
    
    def _discover_endpoints_from_files(self, base_url: str) -> List[Dict[str, Any]]:
        """Discover endpoints from robots.txt and sitemap"""
        endpoints = []
        
        # Check robots.txt
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = requests.get(robots_url, timeout=10)
            
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if '/api' in path or '/v' in path:
                            endpoints.append({
                                'path': path,
                                'source': 'robots.txt'
                            })
        except:
            pass
        
        # Check sitemap.xml
        try:
            sitemap_url = urljoin(base_url, '/sitemap.xml')
            response = requests.get(sitemap_url, timeout=10)
            
            if response.status_code == 200:
                import re
                urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                
                for url in urls:
                    parsed_url = urlparse(url)
                    path = parsed_url.path
                    if '/api' in path or '/v' in path:
                        endpoints.append({
                            'path': path,
                            'source': 'sitemap.xml'
                        })
        except:
            pass
        
        return endpoints
    
    def _discover_api_documentation(self, base_url: str, results: Dict[str, Any]) -> None:
        """Discover API documentation"""
        self.logger.info(f"Discovering API documentation for {base_url}")
        
        doc_results = {
            'swagger_ui': {},
            'openapi_specs': {},
            'documentation_pages': []
        }
        
        try:
            # Common documentation paths
            doc_paths = [
                '/swagger-ui', '/swagger-ui.html', '/swagger-ui/',
                '/api/swagger-ui', '/api/swagger-ui.html',
                '/docs', '/api/docs', '/api-docs', '/documentation',
                '/redoc', '/api/redoc',
                '/openapi.json', '/swagger.json', '/api.json',
                '/openapi.yaml', '/swagger.yaml', '/api.yaml',
                '/v1/swagger.json', '/v2/swagger.json',
                '/api/v1/swagger.json', '/api/v2/swagger.json'
            ]
            
            for path in doc_paths:
                try:
                    url = urljoin(base_url, path)
                    response = requests.get(url, timeout=10)
                    
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '').lower()
                        
                        doc_info = {
                            'url': url,
                            'status_code': response.status_code,
                            'content_type': content_type,
                            'content_length': len(response.content)
                        }
                        
                        # Analyze documentation type
                        if 'json' in content_type:
                            try:
                                spec_data = response.json()
                                if 'swagger' in spec_data or 'openapi' in spec_data:
                                    doc_info['spec_type'] = 'openapi'
                                    doc_info['spec_version'] = spec_data.get('swagger') or spec_data.get('openapi')
                                    
                                    # Extract basic info
                                    if 'info' in spec_data:
                                        doc_info['api_info'] = spec_data['info']
                                    
                                    # Count endpoints
                                    if 'paths' in spec_data:
                                        doc_info['endpoint_count'] = len(spec_data['paths'])
                                    
                                    doc_results['openapi_specs'][path] = doc_info
                            except:
                                pass
                        
                        elif 'html' in content_type:
                            # Check for Swagger UI or other documentation
                            content = response.text.lower()
                            
                            if 'swagger' in content:
                                doc_info['doc_type'] = 'swagger-ui'
                            elif 'redoc' in content:
                                doc_info['doc_type'] = 'redoc'
                            elif 'api' in content and 'documentation' in content:
                                doc_info['doc_type'] = 'api-docs'
                            
                            doc_results['documentation_pages'].append(doc_info)
                
                except Exception as e:
                    self.logger.debug(f"Error checking documentation path {path}: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"API documentation discovery error: {str(e)}")
            doc_results['error'] = str(e)
        
        results['documentation_discovery'] = doc_results
        
        doc_count = len(doc_results.get('documentation_pages', [])) + len(doc_results.get('openapi_specs', {}))
        if doc_count > 0:
            self.logger.info(f"Found {doc_count} API documentation sources")
    
    def _analyze_api_security(self, base_url: str, results: Dict[str, Any]) -> None:
        """Analyze API security"""
        self.logger.info(f"Analyzing API security for {base_url}")
        
        security_results = {
            'cors_analysis': {},
            'authentication_tests': {},
            'rate_limiting': {},
            'security_headers': {},
            'common_vulnerabilities': {}
        }
        
        try:
            # CORS analysis
            cors_result = self._test_cors_configuration(base_url)
            security_results['cors_analysis'] = cors_result
            
            # Authentication bypass tests
            auth_result = self._test_authentication_bypass(base_url)
            security_results['authentication_tests'] = auth_result
            
            # Rate limiting tests
            rate_limit_result = self._test_rate_limiting(base_url)
            security_results['rate_limiting'] = rate_limit_result
            
            # Security headers analysis
            headers_result = self._analyze_security_headers(base_url)
            security_results['security_headers'] = headers_result
            
            # Common vulnerability tests
            vuln_result = self._test_common_vulnerabilities(base_url)
            security_results['common_vulnerabilities'] = vuln_result
            
        except Exception as e:
            self.logger.error(f"API security analysis error: {str(e)}")
            security_results['error'] = str(e)
        
        results['security_testing'] = security_results
    
    def _test_cors_configuration(self, base_url: str) -> Dict[str, Any]:
        """Test CORS configuration"""
        cors_results = {
            'vulnerable_origins': [],
            'wildcard_origin': False,
            'credentials_allowed': False
        }
        
        try:
            api_url = urljoin(base_url, '/api')
            
            # Test with evil origin
            headers = {'Origin': 'https://evil.com'}
            response = requests.options(api_url, headers=headers, timeout=10)
            
            cors_headers = {}
            for header, value in response.headers.items():
                if 'access-control' in header.lower():
                    cors_headers[header] = value
            
            # Check for vulnerable CORS configuration
            origin_header = response.headers.get('Access-Control-Allow-Origin', '')
            
            if origin_header == '*':
                cors_results['wildcard_origin'] = True
                cors_results['vulnerable_origins'].append('*')
            elif 'evil.com' in origin_header:
                cors_results['vulnerable_origins'].append('evil.com')
            
            if response.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true':
                cors_results['credentials_allowed'] = True
            
            cors_results['cors_headers'] = cors_headers
            
        except Exception as e:
            cors_results['error'] = str(e)
        
        return cors_results
    
    def _test_authentication_bypass(self, base_url: str) -> Dict[str, Any]:
        """Test authentication bypass techniques"""
        auth_results = {
            'bypass_attempts': [],
            'accessible_endpoints': []
        }
        
        bypass_techniques = [
            {'headers': {'X-Forwarded-For': '127.0.0.1'}, 'name': 'X-Forwarded-For bypass'},
            {'headers': {'X-Real-IP': '127.0.0.1'}, 'name': 'X-Real-IP bypass'},
            {'headers': {'X-Original-URL': '/admin'}, 'name': 'X-Original-URL bypass'},
            {'params': {'admin': 'true'}, 'name': 'Admin parameter bypass'},
            {'params': {'debug': '1'}, 'name': 'Debug parameter bypass'}
        ]
        
        protected_endpoints = ['/api/admin', '/api/users', '/admin', '/api/config']
        
        for endpoint in protected_endpoints:
            url = urljoin(base_url, endpoint)
            
            # Baseline request
            try:
                baseline = requests.get(url, timeout=10)
                baseline_status = baseline.status_code
                
                for technique in bypass_techniques:
                    try:
                        headers = technique.get('headers', {})
                        params = technique.get('params', {})
                        
                        response = requests.get(url, headers=headers, params=params, timeout=10)
                        
                        if response.status_code != baseline_status and response.status_code == 200:
                            auth_results['bypass_attempts'].append({
                                'endpoint': endpoint,
                                'technique': technique['name'],
                                'status_code': response.status_code,
                                'bypassed': True
                            })
                    except:
                        continue
            except:
                continue
        
        return auth_results
    
    def _test_rate_limiting(self, base_url: str) -> Dict[str, Any]:
        """Test rate limiting"""
        rate_limit_results = {
            'rate_limited': False,
            'requests_before_limit': 0,
            'rate_limit_headers': {}
        }
        
        try:
            api_url = urljoin(base_url, '/api')
            
            for i in range(20):  # Test with 20 requests
                response = requests.get(api_url, timeout=5)
                
                # Check for rate limiting status codes
                if response.status_code in [429, 503]:
                    rate_limit_results['rate_limited'] = True
                    rate_limit_results['requests_before_limit'] = i
                    
                    # Extract rate limiting headers
                    for header, value in response.headers.items():
                        if any(keyword in header.lower() for keyword in ['rate', 'limit', 'retry']):
                            rate_limit_results['rate_limit_headers'][header] = value
                    
                    break
                
                time.sleep(0.1)  # Small delay between requests
        
        except Exception as e:
            rate_limit_results['error'] = str(e)
        
        return rate_limit_results
    
    def _analyze_security_headers(self, base_url: str) -> Dict[str, Any]:
        """Analyze security headers"""
        try:
            response = requests.get(base_url, timeout=10)
            
            security_headers = {
                'x_frame_options': response.headers.get('X-Frame-Options'),
                'x_content_type_options': response.headers.get('X-Content-Type-Options'),
                'strict_transport_security': response.headers.get('Strict-Transport-Security'),
                'content_security_policy': response.headers.get('Content-Security-Policy'),
                'x_xss_protection': response.headers.get('X-XSS-Protection'),
                'missing_headers': []
            }
            
            # Check for missing security headers
            required_headers = [
                'X-Frame-Options', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Content-Security-Policy'
            ]
            
            for header in required_headers:
                if header not in response.headers:
                    security_headers['missing_headers'].append(header)
            
            return security_headers
            
        except Exception as e:
            return {'error': str(e)}
    
    def _test_common_vulnerabilities(self, base_url: str) -> Dict[str, Any]:
        """Test for common API vulnerabilities"""
        vuln_results = {
            'sql_injection_tests': [],
            'xss_tests': [],
            'path_traversal_tests': []
        }
        
        try:
            # Simple SQL injection tests
            sql_payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users; --"]
            
            for payload in sql_payloads:
                try:
                    url = urljoin(base_url, f"/api/users?id={payload}")
                    response = requests.get(url, timeout=10)
                    
                    # Look for SQL error indicators
                    error_indicators = ['sql', 'mysql', 'postgres', 'oracle', 'syntax error']
                    
                    if any(indicator in response.text.lower() for indicator in error_indicators):
                        vuln_results['sql_injection_tests'].append({
                            'payload': payload,
                            'vulnerable': True,
                            'response_length': len(response.content)
                        })
                except:
                    continue
            
            # Simple XSS tests
            xss_payloads = ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"]
            
            for payload in xss_payloads:
                try:
                    url = urljoin(base_url, f"/api/search?q={payload}")
                    response = requests.get(url, timeout=10)
                    
                    if payload in response.text:
                        vuln_results['xss_tests'].append({
                            'payload': payload,
                            'reflected': True
                        })
                except:
                    continue
        
        except Exception as e:
            vuln_results['error'] = str(e)
        
        return vuln_results
    
    def _analyze_api_schemas(self, base_url: str, results: Dict[str, Any]) -> None:
        """Analyze API schemas from discovered specs"""
        self.logger.info(f"Analyzing API schemas for {base_url}")
        
        schema_results = {
            'endpoints_analyzed': 0,
            'parameters_found': [],
            'data_models': [],
            'security_schemes': []
        }
        
        try:
            # Get OpenAPI specs from discovery results
            openapi_specs = results.get('documentation_discovery', {}).get('openapi_specs', {})
            
            for spec_path, spec_info in openapi_specs.items():
                if 'spec_type' in spec_info:
                    # Try to get the full spec
                    try:
                        spec_url = spec_info['url']
                        response = requests.get(spec_url, timeout=10)
                        
                        if response.status_code == 200:
                            spec_data = response.json()
                            
                            # Analyze paths and parameters
                            if 'paths' in spec_data:
                                schema_results['endpoints_analyzed'] = len(spec_data['paths'])
                                
                                # Extract parameters
                                for path, methods in spec_data['paths'].items():
                                    for method, details in methods.items():
                                        if isinstance(details, dict) and 'parameters' in details:
                                            for param in details['parameters']:
                                                schema_results['parameters_found'].append({
                                                    'path': path,
                                                    'method': method,
                                                    'parameter': param.get('name'),
                                                    'type': param.get('type'),
                                                    'required': param.get('required', False)
                                                })
                            
                            # Extract data models
                            if 'definitions' in spec_data:
                                schema_results['data_models'] = list(spec_data['definitions'].keys())
                            elif 'components' in spec_data and 'schemas' in spec_data['components']:
                                schema_results['data_models'] = list(spec_data['components']['schemas'].keys())
                            
                            # Extract security schemes
                            if 'securityDefinitions' in spec_data:
                                schema_results['security_schemes'] = list(spec_data['securityDefinitions'].keys())
                            elif 'components' in spec_data and 'securitySchemes' in spec_data['components']:
                                schema_results['security_schemes'] = list(spec_data['components']['securitySchemes'].keys())
                    
                    except Exception as e:
                        self.logger.debug(f"Error analyzing spec {spec_path}: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"API schema analysis error: {str(e)}")
            schema_results['error'] = str(e)
        
        results['schema_analysis'] = schema_results
        
        if schema_results['endpoints_analyzed'] > 0:
            self.logger.info(f"Analyzed {schema_results['endpoints_analyzed']} API endpoints from schemas")
    
    def _save_api_results(self, target: str, results: Dict[str, Any]) -> None:
        """Save API analysis results"""
        sanitized_target = target.replace(':', '_').replace('/', '_')
        
        # Save JSON results
        json_file = self.api_dir / f'{sanitized_target}_api_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"API results saved to {json_file}")
        
        # Create human-readable summary
        txt_file = self.api_dir / f'{sanitized_target}_api_summary.txt'
        
        with open(txt_file, 'w') as f:
            f.write(f"API Analysis Summary for {target}\n")
            f.write("=" * 50 + "\n\n")
            
            # API Discovery
            discovery = results.get('api_discovery', {})
            if discovery:
                endpoints = discovery.get('discovered_endpoints', [])
                f.write(f"API Discovery:\n")
                f.write(f"  Discovered Endpoints: {len(endpoints)}\n")
                
                if endpoints:
                    f.write("  Notable Endpoints:\n")
                    for endpoint in endpoints[:10]:  # Limit to 10
                        f.write(f"    {endpoint.get('path', 'N/A')} [{endpoint.get('status_code', 'N/A')}]\n")
                f.write("\n")
            
            # Documentation
            docs = results.get('documentation_discovery', {})
            if docs:
                openapi_specs = docs.get('openapi_specs', {})
                doc_pages = docs.get('documentation_pages', [])
                
                f.write("API Documentation:\n")
                f.write(f"  OpenAPI Specs: {len(openapi_specs)}\n")
                f.write(f"  Documentation Pages: {len(doc_pages)}\n")
                
                for spec_path, spec_info in openapi_specs.items():
                    f.write(f"    {spec_path} - {spec_info.get('spec_version', 'Unknown version')}\n")
                f.write("\n")
            
            # Security Analysis
            security = results.get('security_testing', {})
            if security:
                f.write("Security Analysis:\n")
                
                cors = security.get('cors_analysis', {})
                if cors.get('wildcard_origin'):
                    f.write("  ⚠️  CORS: Wildcard origin allowed (security risk)\n")
                elif cors.get('vulnerable_origins'):
                    f.write(f"  ⚠️  CORS: Vulnerable origins: {', '.join(cors['vulnerable_origins'])}\n")
                else:
                    f.write("  ✓ CORS: Configuration appears secure\n")
                
                rate_limiting = security.get('rate_limiting', {})
                if rate_limiting.get('rate_limited'):
                    f.write("  ✓ Rate Limiting: Enabled\n")
                else:
                    f.write("  ⚠️  Rate Limiting: Not detected\n")
                
                auth_bypass = security.get('authentication_tests', {})
                bypass_attempts = auth_bypass.get('bypass_attempts', [])
                if bypass_attempts:
                    f.write(f"  ⚠️  Auth Bypass: {len(bypass_attempts)} potential bypasses found\n")
                else:
                    f.write("  ✓ Auth Bypass: No bypasses detected\n")
                
                f.write("\n")
            
            # Schema Analysis
            schema = results.get('schema_analysis', {})
            if schema:
                f.write("Schema Analysis:\n")
                f.write(f"  Endpoints Analyzed: {schema.get('endpoints_analyzed', 0)}\n")
                f.write(f"  Parameters Found: {len(schema.get('parameters_found', []))}\n")
                f.write(f"  Data Models: {len(schema.get('data_models', []))}\n")
                f.write(f"  Security Schemes: {', '.join(schema.get('security_schemes', []))}\n")
        
        self.logger.info(f"API summary saved to {txt_file}")
