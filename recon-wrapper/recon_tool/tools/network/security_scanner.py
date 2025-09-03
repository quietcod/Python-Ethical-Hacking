"""
Security Scanner
SSL/TLS Security Analysis, Certificate Transparency, and Vulnerability Detection
"""

import json
import logging
import re
import socket
import ssl
import subprocess
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

import requests

from ...core.exceptions import NetworkError, ScanError
from ...core.utils import is_port_open


class SecurityScanner:
    """SSL/TLS Security Analysis and Certificate Transparency Scanner"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        self.results = {}
        
    def analyze_ssl_tls(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Comprehensive SSL/TLS analysis"""
        self.logger.info(f"Analyzing SSL/TLS for {target}:{port}")
        
        ssl_info = {
            'target': target,
            'port': port,
            'certificate': None,
            'cipher_suites': [],
            'protocols': [],
            'vulnerabilities': [],
            'security_headers': {},
            'certificate_chain': [],
            'transparency_logs': []
        }
        
        try:
            # Get SSL certificate information
            ssl_info['certificate'] = self._get_certificate_info(target, port)
            
            # Test supported SSL/TLS protocols
            ssl_info['protocols'] = self._test_ssl_protocols(target, port)
            
            # Get cipher suites
            ssl_info['cipher_suites'] = self._get_cipher_suites(target, port)
            
            # Check for common vulnerabilities
            ssl_info['vulnerabilities'] = self._check_ssl_vulnerabilities(target, port)
            
            # Get security headers
            ssl_info['security_headers'] = self._check_security_headers(target, port)
            
            # Get certificate chain
            ssl_info['certificate_chain'] = self._get_certificate_chain(target, port)
            
            # Query Certificate Transparency logs
            if ssl_info['certificate']:
                ssl_info['transparency_logs'] = self._query_certificate_transparency(ssl_info['certificate'])
            
            # Save results
            self._save_ssl_results(target, ssl_info)
            self.results[f"{target}:{port}"] = ssl_info
            
        except Exception as e:
            self.logger.error(f"SSL/TLS analysis failed for {target}:{port}: {str(e)}")
            ssl_info['error'] = str(e)
            
        return ssl_info
        
    def _get_certificate_info(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Extract detailed certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Get basic certificate info that's always available
                    basic_cert = ssock.getpeercert()
                    
                    cert_info = {
                        'subject': dict(x[0] for x in basic_cert.get('subject', [])),
                        'issuer': dict(x[0] for x in basic_cert.get('issuer', [])),
                        'serial_number': basic_cert.get('serialNumber'),
                        'not_before': basic_cert.get('notBefore'),
                        'not_after': basic_cert.get('notAfter'),
                        'signature_algorithm': None,
                        'public_key_algorithm': None,
                        'public_key_size': None,
                        'san': [name[1] for name in basic_cert.get('subjectAltName', [])],
                        'sha256_fingerprint': None,
                        'sha1_fingerprint': None,
                        'pem': None
                    }
                    
                    # Calculate basic fingerprint
                    try:
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert_info['sha256_fingerprint'] = hashlib.sha256(cert_der).hexdigest()
                        cert_info['sha1_fingerprint'] = hashlib.sha1(cert_der).hexdigest()
                    except Exception:
                        pass
                        
                    return cert_info
                    
        except Exception as e:
            self.logger.error(f"Failed to get certificate info: {str(e)}")
            return None
            
    def _test_ssl_protocols(self, target: str, port: int) -> List[Dict[str, Any]]:
        """Test supported SSL/TLS protocol versions"""
        protocols = []
        protocol_versions = [
            ('SSLv2', ssl.PROTOCOL_SSLv2 if hasattr(ssl, 'PROTOCOL_SSLv2') else None),
            ('SSLv3', ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None),
            ('TLSv1.3', ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None)
        ]
        
        for name, protocol in protocol_versions:
            if protocol is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((target, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        protocols.append({
                            'name': name,
                            'supported': True,
                            'cipher': ssock.cipher()
                        })
            except Exception:
                protocols.append({
                    'name': name,
                    'supported': False,
                    'cipher': None
                })
                
        return protocols
        
    def _get_cipher_suites(self, target: str, port: int) -> List[Dict[str, Any]]:
        """Get supported cipher suites"""
        cipher_suites = []
        
        try:
            # Test with different SSL contexts to get cipher information
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_suites.append({
                            'name': cipher_info[0],
                            'protocol': cipher_info[1],
                            'key_length': cipher_info[2]
                        })
                        
        except Exception as e:
            self.logger.error(f"Failed to get cipher suites: {str(e)}")
            
        return cipher_suites
        
    def _check_ssl_vulnerabilities(self, target: str, port: int) -> List[Dict[str, Any]]:
        """Check for common SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        # Check for weak protocols
        protocols = self._test_ssl_protocols(target, port)
        for proto in protocols:
            if proto['supported']:
                if proto['name'] in ['SSLv2', 'SSLv3', 'TLSv1.0']:
                    vulnerabilities.append({
                        'type': 'weak_protocol',
                        'name': f"Weak Protocol: {proto['name']}",
                        'severity': 'high' if proto['name'] in ['SSLv2', 'SSLv3'] else 'medium',
                        'description': f"Server supports deprecated protocol {proto['name']}"
                    })
                    
        # Check certificate validity
        cert_info = self._get_certificate_info(target, port)
        if cert_info:
            try:
                if cert_info.get('not_after'):
                    expiry = datetime.fromisoformat(cert_info['not_after'].replace('Z', '+00:00'))
                    if expiry < datetime.now():
                        vulnerabilities.append({
                            'type': 'expired_certificate',
                            'name': 'Expired Certificate',
                            'severity': 'high',
                            'description': f"Certificate expired on {cert_info['not_after']}"
                        })
                    elif (expiry - datetime.now()).days < 30:
                        vulnerabilities.append({
                            'type': 'expiring_certificate',
                            'name': 'Certificate Expiring Soon',
                            'severity': 'medium',
                            'description': f"Certificate expires on {cert_info['not_after']}"
                        })
            except Exception:
                pass
                
        return vulnerabilities
        
    def _check_security_headers(self, target: str, port: int) -> Dict[str, Any]:
        """Check HTTP security headers"""
        headers = {}
        
        try:
            # Try HTTPS first
            url = f"https://{target}:{port}" if port != 443 else f"https://{target}"
            response = requests.get(url, timeout=10, verify=False, allow_redirects=False)
            
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Permissions-Policy',
                'Expect-CT'
            ]
            
            for header in security_headers:
                value = response.headers.get(header)
                headers[header] = {
                    'present': value is not None,
                    'value': value
                }
                
        except Exception as e:
            self.logger.error(f"Failed to check security headers: {str(e)}")
            
        return headers
        
    def _get_certificate_chain(self, target: str, port: int) -> List[Dict[str, Any]]:
        """Get complete certificate chain"""
        chain = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Fallback to basic certificate info
                    try:
                        basic_cert = ssock.getpeercert()
                        chain.append({
                            'subject': dict(x[0] for x in basic_cert.get('subject', [])),
                            'issuer': dict(x[0] for x in basic_cert.get('issuer', [])),
                            'serial_number': basic_cert.get('serialNumber'),
                            'fingerprint': 'unavailable'
                        })
                    except Exception:
                        chain.append({
                            'subject': 'Certificate info unavailable',
                            'issuer': 'Certificate info unavailable'
                        })
                            
        except Exception as e:
            self.logger.error(f"Failed to get certificate chain: {str(e)}")
            
        return chain
        
    def _query_certificate_transparency(self, cert_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Query Certificate Transparency logs"""
        ct_logs = []
        
        # Check if Certificate Transparency is enabled
        if not self.config.get('cert_transparency', True):
            self.logger.info("Certificate Transparency queries disabled")
            return ct_logs
        
        if not cert_info or not cert_info.get('sha256_fingerprint'):
            return ct_logs
            
        try:
            # Query crt.sh for certificate transparency logs
            fingerprint = cert_info['sha256_fingerprint']
            url = f"https://crt.sh/?q={fingerprint}&output=json"
            
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for entry in data[:10]:  # Limit to first 10 entries
                        ct_logs.append({
                            'id': entry.get('id'),
                            'logged_at': entry.get('entry_timestamp'),
                            'not_before': entry.get('not_before'),
                            'not_after': entry.get('not_after'),
                            'common_name': entry.get('common_name'),
                            'issuer_name': entry.get('issuer_name')
                        })
                        
        except Exception as e:
            self.logger.error(f"Failed to query Certificate Transparency logs: {str(e)}")
            
        return ct_logs
        
    def _save_ssl_results(self, target: str, ssl_info: Dict[str, Any]) -> None:
        """Save SSL/TLS analysis results"""
        try:
            output_file = self.output_dir / f"ssl_analysis_{target.replace('.', '_')}.json"
            with open(output_file, 'w') as f:
                json.dump(ssl_info, f, indent=2, default=str)
            self.logger.info(f"SSL analysis results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to save SSL results: {str(e)}")
            
    def scan_target(self, target: str) -> Dict[str, Any]:
        """Run complete security scan on target"""
        self.logger.info(f"Running security scan on {target}")
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'ssl_analysis': {},
            'open_ports': []
        }
        
        # Get SSL/TLS ports from configuration
        ssl_ports = self.config.get('ports', [443, 8443, 9443, 8080, 8008, 8888])
        timeout = self.config.get('timeout', 30)
        
        for port in ssl_ports:
            if is_port_open(target, port, timeout=timeout):
                results['open_ports'].append(port)
                ssl_result = self.analyze_ssl_tls(target, port)
                results['ssl_analysis'][f"port_{port}"] = ssl_result
                
        return results
    
    def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Enhanced vulnerability scanning with multiple tools"""
        try:
            self.logger.info(f"Starting vulnerability scan for: {target}")
            
            results = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'nmap_vulners': {},
                'ssl_vulnerabilities': {},
                'web_vulnerabilities': {},
                'service_vulnerabilities': {},
                'cve_analysis': {}
            }
            
            # Nmap vulnerability scripts
            nmap_vuln_results = self._run_nmap_vulners(target)
            if nmap_vuln_results:
                results['nmap_vulners'] = nmap_vuln_results
            
            # SSL/TLS vulnerability analysis
            ssl_vulns = self._analyze_ssl_vulnerabilities(target)
            if ssl_vulns:
                results['ssl_vulnerabilities'] = ssl_vulns
            
            # Web application vulnerability checks
            web_vulns = self._check_web_vulnerabilities(target)
            if web_vulns:
                results['web_vulnerabilities'] = web_vulns
            
            # Service-specific vulnerability checks
            service_vulns = self._check_service_vulnerabilities(target)
            if service_vulns:
                results['service_vulnerabilities'] = service_vulns
            
            self.logger.info(f"Vulnerability scan completed for {target}")
            return results
            
        except Exception as e:
            self.logger.error(f"Vulnerability scan error: {str(e)}")
            raise ScanError(f"Vulnerability scan failed: {str(e)}", scan_type="vulnerability", target=target)
    
    def _run_nmap_vulners(self, target: str) -> Dict[str, Any]:
        """Run Nmap with vulnerability detection scripts"""
        try:
            vuln_scripts = [
                '--script=vuln',
                '--script=vulners',
                '--script=vulscan',
                '--script=exploit'
            ]
            
            results = {}
            
            for script in vuln_scripts:
                try:
                    cmd = f"nmap -sV {script} --script-args vulners.shodan-api-key='' {target}"
                    result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
                    
                    if result.stdout:
                        script_name = script.split('=')[1] if '=' in script else script
                        results[script_name] = self._parse_nmap_vuln_output(result.stdout)
                        
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Nmap vulnerability script {script} timed out")
                except Exception as e:
                    self.logger.debug(f"Script {script} failed: {str(e)}")
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Nmap vulnerability scan error: {str(e)}")
            return {}
    
    def _parse_nmap_vuln_output(self, output: str) -> Dict[str, Any]:
        """Parse Nmap vulnerability scan output"""
        # Look for CVE patterns
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, output)
        
        # Look for vulnerability descriptions
        vuln_lines = []
        for line in output.split('\n'):
            if any(keyword in line.lower() for keyword in ['vulnerable', 'exploit', 'cve-', 'risk']):
                vuln_lines.append(line.strip())
        
        return {
            'cves': list(set(cves)),
            'vulnerability_details': vuln_lines[:20]  # Limit output
        }
    
    def _analyze_ssl_vulnerabilities(self, target: str) -> Dict[str, Any]:
        """Advanced SSL/TLS vulnerability analysis"""
        try:
            ssl_ports = [443, 8443, 9443, 8080, 8008]
            results = {}
            
            for port in ssl_ports:
                if is_port_open(target, port):
                    port_results = {}
                    
                    # Check for common SSL vulnerabilities
                    vuln_checks = {
                        'heartbleed': self._check_heartbleed(target, port),
                        'poodle': self._check_poodle(target, port),
                        'beast': self._check_beast(target, port),
                        'drown': self._check_drown(target, port),
                        'weak_ciphers': self._check_weak_ciphers(target, port),
                        'certificate_issues': self._check_certificate_issues(target, port)
                    }
                    
                    # Filter out empty results
                    port_results = {k: v for k, v in vuln_checks.items() if v}
                    
                    if port_results:
                        results[f'port_{port}'] = port_results
                        
            return results
            
        except Exception as e:
            self.logger.error(f"SSL vulnerability analysis error: {str(e)}")
            return {}
    
    def _check_heartbleed(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Check for Heartbleed vulnerability using Nmap"""
        try:
            cmd = f"nmap -p {port} --script ssl-heartbleed {target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            if 'VULNERABLE' in result.stdout:
                return {
                    'vulnerable': True,
                    'cve': 'CVE-2014-0160',
                    'severity': 'HIGH',
                    'description': 'Heartbleed vulnerability detected'
                }
        except Exception:
            pass
        return None
    
    def _check_poodle(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Check for POODLE vulnerability"""
        try:
            cmd = f"nmap -p {port} --script ssl-poodle {target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            if 'VULNERABLE' in result.stdout:
                return {
                    'vulnerable': True,
                    'cve': 'CVE-2014-3566',
                    'severity': 'MEDIUM',
                    'description': 'POODLE vulnerability detected'
                }
        except Exception:
            pass
        return None
    
    def _check_beast(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Check for BEAST vulnerability"""
        try:
            cmd = f"nmap -p {port} --script ssl-enum-ciphers {target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            # Look for CBC ciphers with TLS 1.0
            if 'TLSv1.0' in result.stdout and 'CBC' in result.stdout:
                return {
                    'vulnerable': True,
                    'cve': 'CVE-2011-3389',
                    'severity': 'MEDIUM',
                    'description': 'BEAST vulnerability - CBC cipher with TLS 1.0'
                }
        except Exception:
            pass
        return None
    
    def _check_drown(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Check for DROWN vulnerability"""
        try:
            cmd = f"nmap -p {port} --script ssl-dh-params {target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            if 'SSLv2' in result.stdout:
                return {
                    'vulnerable': True,
                    'cve': 'CVE-2016-0800',
                    'severity': 'HIGH',
                    'description': 'DROWN vulnerability - SSLv2 enabled'
                }
        except Exception:
            pass
        return None
    
    def _check_weak_ciphers(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Check for weak SSL/TLS ciphers"""
        try:
            cmd = f"nmap -p {port} --script ssl-enum-ciphers {target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            weak_ciphers = []
            weak_keywords = ['NULL', 'EXPORT', 'RC4', 'DES', 'MD5', 'weak']
            
            for line in result.stdout.split('\n'):
                for keyword in weak_keywords:
                    if keyword in line.upper():
                        weak_ciphers.append(line.strip())
                        
            if weak_ciphers:
                return {
                    'weak_ciphers_found': True,
                    'severity': 'MEDIUM',
                    'ciphers': weak_ciphers[:10],  # Limit output
                    'description': 'Weak or insecure ciphers detected'
                }
        except Exception:
            pass
        return None
    
    def _check_certificate_issues(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Check for SSL certificate issues"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    issues = []
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        issues.append(f"Certificate expires in {days_until_expiry} days")
                    
                    # Check for self-signed
                    if cert.get('issuer') == cert.get('subject'):
                        issues.append("Self-signed certificate")
                    
                    if issues:
                        return {
                            'certificate_issues': True,
                            'issues': issues,
                            'severity': 'MEDIUM',
                            'certificate_info': {
                                'subject': cert.get('subject'),
                                'issuer': cert.get('issuer'),
                                'expiry': cert.get('notAfter')
                            }
                        }
                        
        except Exception as e:
            self.logger.debug(f"Certificate check error: {str(e)}")
        return None
    
    def _check_web_vulnerabilities(self, target: str) -> Dict[str, Any]:
        """Check for common web application vulnerabilities"""
        try:
            results = {}
            
            # Check if target responds to HTTP/HTTPS
            protocols = []
            if is_port_open(target, 80):
                protocols.append('http')
            if is_port_open(target, 443):
                protocols.append('https')
                
            for protocol in protocols:
                base_url = f"{protocol}://{target}"
                
                # SQL Injection basic check
                sqli_check = self._basic_sqli_check(base_url)
                if sqli_check:
                    results['sql_injection'] = sqli_check
                
                # XSS basic check
                xss_check = self._basic_xss_check(base_url)
                if xss_check:
                    results['xss'] = xss_check
                
                # Directory traversal check
                lfi_check = self._basic_lfi_check(base_url)
                if lfi_check:
                    results['directory_traversal'] = lfi_check
                
                # Command injection check
                cmd_check = self._basic_command_injection_check(base_url)
                if cmd_check:
                    results['command_injection'] = cmd_check
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Web vulnerability check error: {str(e)}")
            return {}
    
    def _basic_sqli_check(self, base_url: str) -> Optional[Dict[str, Any]]:
        """Basic SQL injection detection"""
        try:
            payloads = ["'", "1'OR'1'='1", "admin'--", "' UNION SELECT NULL--"]
            
            for payload in payloads:
                test_urls = [
                    f"{base_url}/?id={payload}",
                    f"{base_url}/login?username={payload}&password=test",
                    f"{base_url}/search?q={payload}"
                ]
                
                for url in test_urls:
                    try:
                        resp = requests.get(url, timeout=5)
                        
                        # Look for SQL error messages
                        error_patterns = [
                            r'mysql_fetch_array',
                            r'ORA-\d{5}',
                            r'Microsoft.*ODBC.*SQL',
                            r'PostgreSQL.*ERROR',
                            r'Warning.*mysql_.*',
                            r'SQL syntax.*MySQL',
                            r'sqlite3\.OperationalError'
                        ]
                        
                        for pattern in error_patterns:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                return {
                                    'potential_sqli': True,
                                    'url': url,
                                    'payload': payload,
                                    'pattern_matched': pattern,
                                    'severity': 'HIGH'
                                }
                                
                    except Exception:
                        continue
                        
        except Exception:
            pass
        return None
    
    def _basic_xss_check(self, base_url: str) -> Optional[Dict[str, Any]]:
        """Basic XSS detection"""
        try:
            payloads = [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>"
            ]
            
            for payload in payloads:
                test_urls = [
                    f"{base_url}/?search={payload}",
                    f"{base_url}/?q={payload}",
                    f"{base_url}/?name={payload}"
                ]
                
                for url in test_urls:
                    try:
                        resp = requests.get(url, timeout=5)
                        
                        if payload in resp.text:
                            return {
                                'potential_xss': True,
                                'url': url,
                                'payload': payload,
                                'reflected': True,
                                'severity': 'MEDIUM'
                            }
                            
                    except Exception:
                        continue
                        
        except Exception:
            pass
        return None
    
    def _basic_lfi_check(self, base_url: str) -> Optional[Dict[str, Any]]:
        """Basic Local File Inclusion detection"""
        try:
            payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd"
            ]
            
            for payload in payloads:
                test_urls = [
                    f"{base_url}/?file={payload}",
                    f"{base_url}/?page={payload}",
                    f"{base_url}/?include={payload}"
                ]
                
                for url in test_urls:
                    try:
                        resp = requests.get(url, timeout=5)
                        
                        # Look for signs of file inclusion
                        if any(pattern in resp.text for pattern in ['root:x:', 'daemon:', 'bin:', '127.0.0.1']):
                            return {
                                'potential_lfi': True,
                                'url': url,
                                'payload': payload,
                                'severity': 'HIGH'
                            }
                            
                    except Exception:
                        continue
                        
        except Exception:
            pass
        return None
    
    def _basic_command_injection_check(self, base_url: str) -> Optional[Dict[str, Any]]:
        """Basic command injection detection"""
        try:
            payloads = [
                "; ls",
                "| whoami",
                "&& dir",
                "`id`"
            ]
            
            for payload in payloads:
                test_urls = [
                    f"{base_url}/?cmd={payload}",
                    f"{base_url}/?exec={payload}",
                    f"{base_url}/?system={payload}"
                ]
                
                for url in test_urls:
                    try:
                        resp = requests.get(url, timeout=5)
                        
                        # Look for command output patterns
                        cmd_patterns = [
                            r'uid=\d+.*gid=\d+',  # id command output
                            r'total \d+',         # ls command output
                            r'Volume.*Serial',    # dir command output
                            r'root.*bin.*sbin'    # whoami/ls output
                        ]
                        
                        for pattern in cmd_patterns:
                            if re.search(pattern, resp.text):
                                return {
                                    'potential_command_injection': True,
                                    'url': url,
                                    'payload': payload,
                                    'pattern_matched': pattern,
                                    'severity': 'HIGH'
                                }
                                
                    except Exception:
                        continue
                        
        except Exception:
            pass
        return None
    
    def _check_service_vulnerabilities(self, target: str) -> Dict[str, Any]:
        """Check for service-specific vulnerabilities"""
        try:
            results = {}
            
            # Check common vulnerable services
            vulnerable_services = {
                21: 'FTP',
                22: 'SSH', 
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                993: 'IMAPS',
                995: 'POP3S',
                1433: 'MSSQL',
                3306: 'MySQL',
                5432: 'PostgreSQL',
                6379: 'Redis'
            }
            
            for port, service in vulnerable_services.items():
                if is_port_open(target, port):
                    service_vulns = self._check_specific_service(target, port, service)
                    if service_vulns:
                        results[f'{service}_port_{port}'] = service_vulns
                        
            return results
            
        except Exception as e:
            self.logger.error(f"Service vulnerability check error: {str(e)}")
            return {}
    
    def _check_specific_service(self, target: str, port: int, service: str) -> Optional[List[Dict[str, Any]]]:
        """Check vulnerabilities for specific services"""
        try:
            vulnerabilities = []
            
            if service == 'SSH':
                # Check for weak SSH configuration
                ssh_issues = self._check_ssh_vulnerabilities(target, port)
                if ssh_issues:
                    vulnerabilities.extend(ssh_issues)
                    
            elif service == 'FTP':
                # Check for anonymous FTP
                ftp_issues = self._check_ftp_vulnerabilities(target, port)
                if ftp_issues:
                    vulnerabilities.extend(ftp_issues)
                    
            elif service in ['MySQL', 'MSSQL', 'PostgreSQL']:
                # Check for database vulnerabilities
                db_issues = self._check_database_vulnerabilities(target, port, service)
                if db_issues:
                    vulnerabilities.extend(db_issues)
                    
            return vulnerabilities if vulnerabilities else None
            
        except Exception:
            return None
    
    def _check_ssh_vulnerabilities(self, target: str, port: int) -> List[Dict[str, Any]]:
        """Check SSH-specific vulnerabilities"""
        try:
            issues = []
            
            # Use Nmap SSH scripts
            ssh_scripts = [
                '--script=ssh2-enum-algos',
                '--script=ssh-hostkey',
                '--script=ssh-auth-methods'
            ]
            
            for script in ssh_scripts:
                try:
                    cmd = f"nmap -p {port} {script} {target}"
                    result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
                    
                    # Look for weak algorithms
                    if 'weak' in result.stdout.lower() or 'deprecated' in result.stdout.lower():
                        issues.append({
                            'issue': 'Weak SSH algorithms detected',
                            'severity': 'MEDIUM',
                            'details': result.stdout[:200]
                        })
                        
                except Exception:
                    continue
                    
            return issues
            
        except Exception:
            return []
    
    def _check_ftp_vulnerabilities(self, target: str, port: int) -> List[Dict[str, Any]]:
        """Check FTP-specific vulnerabilities"""
        try:
            issues = []
            
            # Check for anonymous FTP
            try:
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=10)
                
                try:
                    ftp.login('anonymous', 'test@test.com')
                    issues.append({
                        'issue': 'Anonymous FTP access enabled',
                        'severity': 'MEDIUM',
                        'details': 'Anonymous login successful'
                    })
                    ftp.quit()
                except:
                    pass
                    
            except Exception:
                pass
                
            return issues
            
        except Exception:
            return []
    
    def _check_database_vulnerabilities(self, target: str, port: int, service: str) -> List[Dict[str, Any]]:
        """Check database-specific vulnerabilities"""
        try:
            issues = []
            
            # Use Nmap database scripts
            if service == 'MySQL':
                cmd = f"nmap -p {port} --script=mysql-info,mysql-empty-password {target}"
            elif service == 'MSSQL':
                cmd = f"nmap -p {port} --script=ms-sql-info,ms-sql-empty-password {target}"
            elif service == 'PostgreSQL':
                cmd = f"nmap -p {port} --script=pgsql-brute {target}"
            else:
                return []
                
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
                
                # Look for security issues
                if 'empty password' in result.stdout.lower():
                    issues.append({
                        'issue': 'Empty/default password detected',
                        'severity': 'HIGH',
                        'service': service
                    })
                    
                if 'root' in result.stdout.lower() and 'access' in result.stdout.lower():
                    issues.append({
                        'issue': 'Root access detected',
                        'severity': 'HIGH',
                        'service': service
                    })
                    
            except Exception:
                pass
                
            return issues
            
        except Exception:
            return []
