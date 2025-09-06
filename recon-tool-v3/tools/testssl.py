#!/usr/bin/env python3
"""
Testssl SSL/TLS Security Scanner - Optimized for Comprehensive Security Assessment
Deep SSL/TLS vulnerability analysis, compliance checking, and security audit
Specialized for: Complete security assessment, CVE detection, compliance validation
"""

import json
import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class TestsslScanner(BaseTool):
    """Optimized Testssl for comprehensive SSL/TLS security assessment and compliance"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "testssl.sh"
        self.specialization = "comprehensive_ssl_security"
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute comprehensive testssl security assessment with vulnerability focus"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting TestsslScanner COMPREHENSIVE security assessment against {target}")
            
            if not self.verify_installation():
                return self._create_error_result("testssl.sh not installed")
            
            # Comprehensive security-focused command
            cmd = ['testssl.sh', '--jsonfile-pretty', '-', '--quiet', target]
            
            # Default to comprehensive security scans
            security_mode = scan_params.get('security_mode', 'comprehensive')
            if security_mode == 'comprehensive':
                cmd.extend(['--vulnerable', '--protocols', '--ciphers', '--server-defaults'])
            elif security_mode == 'compliance':
                cmd.extend(['--protocols', '--server-defaults', '--ciphers', '--pfs'])
            elif security_mode == 'vulnerability_only':
                cmd.extend(['--vulnerable'])
            
            # Add compliance checks if requested
            if scan_params.get('compliance_check'):
                cmd.append('--grade')
            
            # Execute with walrus operator - longer timeout for comprehensive analysis
            if (result := self.execute_command(cmd, timeout=600)).returncode not in [0, 1]:
                return self._create_error_result(f"Testssl comprehensive scan failed: {result.stderr}")
            
            # Parse and build results - focused on security assessment
            ssl_results = self._parse_security_focused_output(result.stdout, target)
            self.save_raw_output(result.stdout, target, 'json')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            vuln_count = len(ssl_results.get('vulnerabilities', []))
            critical_issues = len([v for v in ssl_results.get('vulnerabilities', []) if v.get('severity') in ['CRITICAL', 'HIGH']])
            
            self.logger.info(f"✅ TestsslScanner COMPREHENSIVE completed in {duration:.1f}s - {vuln_count} vulnerabilities, {critical_issues} critical/high")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'testssl_comprehensive_security',
                'specialization': 'vulnerability_assessment',
                'duration': duration,
                'ssl_results': ssl_results,
                'summary': {
                    'total_vulnerabilities': vuln_count,
                    'critical_issues': critical_issues,
                    'compliance_grade': ssl_results.get('compliance', {}).get('grade', 'Unknown'),
                    'security_recommendations': len(ssl_results.get('recommendations', []))
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ TestsslScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_security_focused_output(self, output: str, target: str) -> Dict:
        """Parse testssl JSON output focused on security vulnerabilities and compliance"""
        ssl_results = {
            'target': target,
            'vulnerabilities': [],
            'compliance': {},
            'security_protocols': [],
            'weak_ciphers': [],
            'recommendations': [],
            'scan_focus': 'security_assessment'
        }
        
        try:
            # testssl.sh outputs multiple JSON objects, parse each line for security issues
            for line in output.strip().split('\n'):
                if line.strip():
                    try:
                        if data := json.loads(line):
                            test_id = data.get('id', '')
                            severity = data.get('severity', '')
                            finding = data.get('finding', '')
                            cve = data.get('cve', '')
                            
                            # Focus on security vulnerabilities
                            if severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
                                ssl_results['vulnerabilities'].append({
                                    'test_id': test_id,
                                    'finding': finding,
                                    'severity': severity,
                                    'cve': cve,
                                    'category': self._categorize_vulnerability(test_id),
                                    'remediation': self._get_remediation_advice(test_id)
                                })
                            
                            # Security-relevant protocol analysis
                            elif 'protocol' in test_id.lower() and severity in ['OK', 'WARN', 'MEDIUM', 'HIGH']:
                                ssl_results['security_protocols'].append({
                                    'protocol': test_id,
                                    'status': finding,
                                    'security_impact': severity,
                                    'recommendation': self._get_protocol_recommendation(test_id, severity)
                                })
                            
                            # Weak cipher identification
                            elif 'cipher' in test_id.lower() and severity in ['MEDIUM', 'HIGH', 'CRITICAL']:
                                ssl_results['weak_ciphers'].append({
                                    'cipher': test_id,
                                    'weakness': finding,
                                    'severity': severity
                                })
                            
                            # Compliance and grading
                            elif 'grade' in test_id.lower() or 'compliance' in test_id.lower():
                                ssl_results['compliance'][test_id] = {
                                    'grade': finding,
                                    'details': severity
                                }
                    except json.JSONDecodeError:
                        continue
        except Exception:
            # Fallback to text parsing for security issues
            ssl_results = self._parse_security_text_output(output, target)
        
        # Generate security recommendations
        ssl_results['recommendations'] = self._generate_security_recommendations(ssl_results)
        
        return ssl_results
    
    def _categorize_vulnerability(self, test_id: str) -> str:
        """Categorize vulnerability type for better reporting"""
        if any(term in test_id.lower() for term in ['heartbleed', 'poodle', 'beast', 'crime']):
            return 'protocol_vulnerability'
        elif 'cipher' in test_id.lower():
            return 'cipher_weakness'
        elif 'cert' in test_id.lower():
            return 'certificate_issue'
        else:
            return 'configuration_weakness'
    
    def _get_remediation_advice(self, test_id: str) -> str:
        """Provide specific remediation advice for vulnerabilities"""
        remediation_map = {
            'heartbleed': 'Update OpenSSL to version 1.0.1g or later',
            'poodle': 'Disable SSLv3 and TLSv1.0 protocols',
            'beast': 'Enable TLS 1.1+ and disable cipher block chaining',
            'weak_cipher': 'Remove weak ciphers from server configuration'
        }
        
        for vuln_type, advice in remediation_map.items():
            if vuln_type in test_id.lower():
                return advice
        return 'Review SSL/TLS configuration and apply security best practices'
    
    def _get_protocol_recommendation(self, protocol: str, severity: str) -> str:
        """Get protocol-specific security recommendations"""
        if 'sslv' in protocol.lower():
            return 'Disable SSLv2/SSLv3 - deprecated and insecure'
        elif 'tlsv1.0' in protocol.lower() or 'tlsv1.1' in protocol.lower():
            return 'Consider disabling TLS 1.0/1.1 for enhanced security'
        elif severity in ['HIGH', 'MEDIUM']:
            return 'Review protocol configuration for security issues'
        return 'Protocol configuration acceptable'
    
    def _generate_security_recommendations(self, ssl_results: Dict) -> List[str]:
        """Generate actionable security recommendations based on findings"""
        recommendations = []
        
        # Protocol recommendations
        if any('ssl' in p.get('protocol', '').lower() for p in ssl_results.get('security_protocols', [])):
            recommendations.append('Disable legacy SSL protocols (SSLv2, SSLv3)')
        
        # Cipher recommendations
        if ssl_results.get('weak_ciphers'):
            recommendations.append('Remove weak ciphers from server configuration')
        
        # High/Critical vulnerability recommendations
        critical_vulns = [v for v in ssl_results.get('vulnerabilities', []) if v.get('severity') in ['CRITICAL', 'HIGH']]
        if critical_vulns:
            recommendations.append(f'Address {len(critical_vulns)} critical/high severity vulnerabilities immediately')
        
        return recommendations
    
    def _parse_security_text_output(self, output: str, target: str) -> Dict:
        """Fallback text parsing focused on security issues"""
        ssl_results = {
            'target': target,
            'vulnerabilities': [],
            'security_protocols': [],
            'recommendations': []
        }
        
        for line in output.split('\n'):
            if any(term in line.upper() for term in ['VULNERABLE', 'CRITICAL', 'HIGH RISK']):
                ssl_results['vulnerabilities'].append({
                    'finding': line.strip(),
                    'severity': 'HIGH' if 'VULNERABLE' in line.upper() else 'MEDIUM',
                    'category': 'detected_from_text'
                })
            elif any(proto in line for proto in ['SSLv', 'TLSv']):
                ssl_results['security_protocols'].append({
                    'protocol': line.strip(),
                    'status': 'detected'
                })
        
        return ssl_results
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'testssl_comprehensive_security',
            'ssl_results': {},
            'summary': {'total_vulnerabilities': 0}
        }
