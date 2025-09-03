"""
SSL Scanner
SSL/TLS certificate analysis and security assessment
"""

import json
import logging
import socket
import ssl
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from ...core.exceptions import ScanError


class SSLScanner:
    """SSL/TLS scanner for certificate analysis and security assessment"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        
        # Create SSL output directory
        self.ssl_dir = output_dir / 'ssl'
        self.ssl_dir.mkdir(exist_ok=True)
        
    def scan(self, target: str) -> Dict[str, Any]:
        """Run comprehensive SSL/TLS analysis"""
        self.logger.info(f"Starting SSL/TLS analysis for {target}")
        
        results = {
            'target': target,
            'certificate_info': {},
            'vulnerabilities': [],
            'cipher_suites': {},
            'protocol_support': {}
        }
        
        try:
            # Certificate analysis
            cert_info = self._analyze_certificate(target)
            results['certificate_info'] = cert_info
            
            # Vulnerability assessment
            vulnerabilities = self._assess_ssl_vulnerabilities(cert_info)
            results['vulnerabilities'] = vulnerabilities
            
            # Protocol support analysis
            protocol_support = self._check_protocol_support(target)
            results['protocol_support'] = protocol_support
            
            # Cipher suite analysis
            cipher_suites = self._analyze_cipher_suites(target)
            results['cipher_suites'] = cipher_suites
            
            # Save results
            self._save_ssl_results(target, results)
            
        except Exception as e:
            self.logger.error(f"SSL scan failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_certificate(self, target: str) -> Dict[str, Any]:
        """Analyze SSL certificate details"""
        try:
            self.logger.info(f"Analyzing SSL certificate for {target}")
            
            # Parse target to get hostname and port
            if ':' in target:
                hostname, port = target.split(':', 1)
                port = int(port)
            else:
                hostname = target
                port = 443
            
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
            
            # Parse certificate information
            cert_info = {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'serial_number': cert.get('serialNumber'),
                'not_before': cert.get('notBefore'),
                'not_after': cert.get('notAfter'),
                'version': cert.get('version'),
                'signature_algorithm': cert.get('signatureAlgorithm'),
                'subject_alt_names': [],
                'is_expired': self._is_cert_expired(cert.get('notAfter')),
                'is_self_signed': self._is_self_signed(cert),
                'days_until_expiry': self._days_until_expiry(cert.get('notAfter')),
                'key_size': self._get_key_size(cert_der) if cert_der else None,
                'fingerprint_sha1': self._get_fingerprint(cert_der, 'sha1') if cert_der else None,
                'fingerprint_sha256': self._get_fingerprint(cert_der, 'sha256') if cert_der else None
            }
            
            # Extract Subject Alternative Names
            if 'subjectAltName' in cert:
                cert_info['subject_alt_names'] = [name[1] for name in cert['subjectAltName']]
            
            return cert_info
            
        except socket.timeout:
            self.logger.error(f"Connection timeout to {target}")
            return {'error': 'Connection timeout'}
        except ssl.SSLError as e:
            self.logger.error(f"SSL error connecting to {target}: {str(e)}")
            return {'error': f'SSL error: {str(e)}'}
        except ConnectionRefusedError:
            self.logger.error(f"Connection refused to {target}")
            return {'error': 'Connection refused'}
        except Exception as e:
            self.logger.error(f"Error analyzing certificate: {str(e)}")
            return {'error': str(e)}
    
    def _is_cert_expired(self, not_after: str) -> bool:
        """Check if certificate is expired"""
        if not not_after:
            return True
            
        try:
            cert_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            return datetime.now() > cert_date
        except ValueError:
            # Try alternative date format
            try:
                cert_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y GMT')
                return datetime.now() > cert_date
            except ValueError:
                self.logger.warning(f"Unable to parse certificate date: {not_after}")
                return False
    
    def _days_until_expiry(self, not_after: str) -> int:
        """Calculate days until certificate expiry"""
        if not not_after:
            return -1
            
        try:
            cert_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            delta = cert_date - datetime.now()
            return delta.days
        except ValueError:
            try:
                cert_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y GMT')
                delta = cert_date - datetime.now()
                return delta.days
            except ValueError:
                return -1
    
    def _is_self_signed(self, cert: Dict[str, Any]) -> bool:
        """Check if certificate is self-signed"""
        try:
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            return subject == issuer
        except Exception:
            return False
    
    def _get_key_size(self, cert_der: bytes) -> int:
        """Extract public key size from certificate"""
        try:
            # This would require additional cryptography libraries
            # For now, return a placeholder
            return None
        except Exception:
            return None
    
    def _get_fingerprint(self, cert_der: bytes, algorithm: str) -> str:
        """Calculate certificate fingerprint"""
        try:
            import hashlib
            
            if algorithm.lower() == 'sha1':
                return hashlib.sha1(cert_der).hexdigest()
            elif algorithm.lower() == 'sha256':
                return hashlib.sha256(cert_der).hexdigest()
            else:
                return None
        except Exception:
            return None
    
    def _check_protocol_support(self, target: str) -> Dict[str, Any]:
        """Check SSL/TLS protocol support"""
        try:
            # Parse target
            if ':' in target:
                hostname, port = target.split(':', 1)
                port = int(port)
            else:
                hostname = target
                port = 443
            
            protocols = {
                'SSLv2': ssl.PROTOCOL_SSLv23,  # Will be rejected by modern systems
                'SSLv3': ssl.PROTOCOL_SSLv23,
                'TLSv1.0': ssl.PROTOCOL_TLSv1,
                'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
                'TLSv1.2': ssl.PROTOCOL_TLSv1_2
            }
            
            # Add TLSv1.3 if available
            if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
                protocols['TLSv1.3'] = ssl.PROTOCOL_TLSv1_3
            
            protocol_support = {}
            
            for protocol_name, protocol_const in protocols.items():
                try:
                    context = ssl.SSLContext(protocol_const)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            protocol_support[protocol_name] = {
                                'supported': True,
                                'cipher': ssock.cipher()[0] if ssock.cipher() else None
                            }
                            
                except (ssl.SSLError, ConnectionError, OSError):
                    protocol_support[protocol_name] = {'supported': False}
                except Exception as e:
                    protocol_support[protocol_name] = {
                        'supported': False,
                        'error': str(e)
                    }
            
            return protocol_support
            
        except Exception as e:
            self.logger.error(f"Error checking protocol support: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_cipher_suites(self, target: str) -> Dict[str, Any]:
        """Analyze supported cipher suites"""
        try:
            # Parse target
            if ':' in target:
                hostname, port = target.split(':', 1)
                port = int(port)
            else:
                hostname = target
                port = 443
            
            # Get cipher information from current connection
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            cipher_info = {}
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_info = {
                            'current_cipher': cipher[0],
                            'protocol_version': cipher[1],
                            'key_bits': cipher[2]
                        }
                    
                    # Get shared ciphers (available in current context)
                    shared_ciphers = ssock.shared_ciphers()
                    if shared_ciphers:
                        cipher_info['shared_ciphers'] = [
                            {
                                'name': cipher[0],
                                'protocol': cipher[1],
                                'key_bits': cipher[2]
                            }
                            for cipher in shared_ciphers[:10]  # Limit to 10
                        ]
            
            return cipher_info
            
        except Exception as e:
            self.logger.error(f"Error analyzing cipher suites: {str(e)}")
            return {'error': str(e)}
    
    def _assess_ssl_vulnerabilities(self, cert_info: Dict[str, Any]) -> list:
        """Assess SSL/TLS vulnerabilities based on certificate info"""
        vulnerabilities = []
        
        # Check certificate expiry
        if cert_info.get('is_expired'):
            vulnerabilities.append({
                'type': 'expired_certificate',
                'severity': 'critical',
                'description': 'SSL certificate has expired',
                'recommendation': 'Renew the SSL certificate immediately'
            })
        
        # Check certificate expiry warning (30 days)
        days_until_expiry = cert_info.get('days_until_expiry', 0)
        if 0 < days_until_expiry <= 30:
            vulnerabilities.append({
                'type': 'certificate_expiring_soon',
                'severity': 'medium',
                'description': f'SSL certificate expires in {days_until_expiry} days',
                'recommendation': 'Renew the SSL certificate soon'
            })
        
        # Check for self-signed certificate
        if cert_info.get('is_self_signed'):
            vulnerabilities.append({
                'type': 'self_signed_certificate',
                'severity': 'medium',
                'description': 'Certificate is self-signed',
                'recommendation': 'Use a certificate from a trusted CA'
            })
        
        # Check for weak signature algorithm
        sig_algorithm = cert_info.get('signature_algorithm', '').lower()
        if 'sha1' in sig_algorithm:
            vulnerabilities.append({
                'type': 'weak_signature_algorithm',
                'severity': 'medium',
                'description': 'Certificate uses weak SHA-1 signature algorithm',
                'recommendation': 'Use a certificate with SHA-256 or stronger'
            })
        
        # Check certificate version
        version = cert_info.get('version')
        if version and version < 3:
            vulnerabilities.append({
                'type': 'old_certificate_version',
                'severity': 'low',
                'description': f'Certificate uses old version {version}',
                'recommendation': 'Use X.509 v3 certificates'
            })
        
        return vulnerabilities
    
    def _save_ssl_results(self, target: str, results: Dict[str, Any]) -> None:
        """Save SSL analysis results"""
        sanitized_target = target.replace(':', '_').replace('/', '_')
        json_file = self.ssl_dir / f'{sanitized_target}_ssl_results.json'
        
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"SSL analysis results saved to {json_file}")
        
        # Create human-readable summary
        txt_file = self.ssl_dir / f'{sanitized_target}_ssl_summary.txt'
        
        with open(txt_file, 'w') as f:
            f.write(f"SSL/TLS Analysis Summary for {target}\n")
            f.write("=" * 50 + "\n\n")
            
            # Certificate information
            cert_info = results.get('certificate_info', {})
            if cert_info and 'error' not in cert_info:
                f.write("Certificate Information:\n")
                f.write(f"  Subject: {cert_info.get('subject', {}).get('commonName', 'N/A')}\n")
                f.write(f"  Issuer: {cert_info.get('issuer', {}).get('organizationName', 'N/A')}\n")
                f.write(f"  Valid From: {cert_info.get('not_before', 'N/A')}\n")
                f.write(f"  Valid To: {cert_info.get('not_after', 'N/A')}\n")
                f.write(f"  Days Until Expiry: {cert_info.get('days_until_expiry', 'N/A')}\n")
                f.write(f"  Self-Signed: {cert_info.get('is_self_signed', 'Unknown')}\n")
                
                if cert_info.get('subject_alt_names'):
                    f.write(f"  Subject Alt Names: {', '.join(cert_info['subject_alt_names'])}\n")
                
                f.write("\n")
            
            # Vulnerabilities
            vulnerabilities = results.get('vulnerabilities', [])
            if vulnerabilities:
                f.write("Security Issues:\n")
                for vuln in vulnerabilities:
                    f.write(f"  [{vuln.get('severity', 'unknown').upper()}] {vuln.get('description', 'N/A')}\n")
                    f.write(f"    Recommendation: {vuln.get('recommendation', 'N/A')}\n")
                f.write("\n")
            
            # Protocol support
            protocols = results.get('protocol_support', {})
            if protocols:
                f.write("Protocol Support:\n")
                for protocol, info in protocols.items():
                    status = "Supported" if info.get('supported') else "Not Supported"
                    f.write(f"  {protocol}: {status}\n")
                f.write("\n")
            
            # Current cipher
            cipher_info = results.get('cipher_suites', {})
            if cipher_info and 'current_cipher' in cipher_info:
                f.write("Current Connection:\n")
                f.write(f"  Cipher: {cipher_info['current_cipher']}\n")
                f.write(f"  Protocol: {cipher_info['protocol_version']}\n")
                f.write(f"  Key Size: {cipher_info['key_bits']} bits\n")
        
        self.logger.info(f"SSL summary saved to {txt_file}")
